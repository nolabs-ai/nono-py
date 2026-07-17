"""Regression test for the pre-Landlock-V4 proxy_only() exec deadlock.

On kernels without Landlock ABI V4 (< 6.7), proxy_only() enforcement falls back
to a seccomp USER_NOTIF filter. nono >= 0.67 traps sendmsg in that filter, which
once deadlocked sandboxed_exec(): the child handed the notify fd to the parent
via an SCM_RIGHTS sendmsg that the filter itself trapped, and the parent could
not service the trap because the fd was stuck inside it. The child wedged before
execve() and only SIGKILL recovered it (WAIT_KILLABLE_RECV). See the fix that
switched the handoff to write-fd-number + pidfd_getfd.

This test forces the fallback path on any kernel by clamping the Landlock ABI
probe to V2 with an LD_PRELOAD shim (the landlock crate probes via glibc's
syscall() wrapper, so it is interposable), then drives the exact deadlock
condition -- proxy_only() with timeout_secs=None -- in a subprocess with a
wall-clock timeout. The regression manifests as the subprocess hanging.
"""

import os
import shutil
import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="proxy_only seccomp fallback and the ABI shim are Linux-only",
)

# LD_PRELOAD shim: clamp the Landlock ABI version probe
# (landlock_create_ruleset(NULL, 0, VERSION)) to V2, emulating a 6.1 kernel.
_SHIM_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/syscall.h>
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#define LANDLOCK_CREATE_RULESET_VERSION (1UL << 0)
static long (*real_syscall)(long, long, long, long, long, long, long) = 0;
long syscall(long nr, ...) {
    long a[6];
    va_list ap; va_start(ap, nr);
    for (int i = 0; i < 6; i++) a[i] = va_arg(ap, long);
    va_end(ap);
    if (nr == SYS_landlock_create_ruleset && a[0] == 0 && a[1] == 0
        && (unsigned long)a[2] == LANDLOCK_CREATE_RULESET_VERSION) {
        const char *v = getenv("FAKE_LANDLOCK_ABI");
        return v ? atol(v) : 2;
    }
    if (!real_syscall)
        real_syscall = (long (*)(long, long, long, long, long, long, long))
            dlsym(RTLD_NEXT, "syscall");
    return real_syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
}
"""

# Driver run under the shim: force the fallback, then run the deadlock scenario.
# Prints structured PREV4: lines the test parses. Uses timeout_secs=None on
# purpose -- that is the worst case, which hangs forever if the bug is present.
_DRIVER_PY = textwrap.dedent(
    """
    import ctypes, sys
    import nono_py as nono

    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, None, 0, 1)  # same probe the landlock crate uses
    print(f"PREV4:ABI={abi}", flush=True)

    proxy = nono.start_proxy(nono.ProxyConfig(allowed_hosts=["example.com"]))
    caps = nono.CapabilitySet()
    caps.allow_path("/", nono.AccessMode.READ)  # enough to exec the interpreter
    caps.proxy_only(proxy)

    # Child makes a trapped connect() to a non-proxy port: the supervisor must
    # be pumped for the child to proceed at all, and the destination must be
    # denied (loopback but wrong port).
    child = [sys.executable, "-c",
             "import socket\\n"
             "try:\\n"
             "    socket.socket().connect(('127.0.0.1', 9))\\n"
             "    print('CONNECTED')\\n"
             "except PermissionError:\\n"
             "    print('DENIED_EACCES')\\n"
             "except OSError as e:\\n"
             "    print('OSERR', e.errno)\\n"]
    try:
        r = nono.sandboxed_exec(caps, child, timeout_secs=None)
        print(f"PREV4:RESULT exit={r.exit_code} out={r.stdout!r} err={r.stderr[:200]!r}",
              flush=True)
    except RuntimeError as e:
        msg = str(e)
        if "pidfd_getfd" in msg or "CAP_SYS_PTRACE" in msg:
            # Handoff blocked by container seccomp -- fast, clean error, NOT a
            # hang. Acceptable outcome for this regression test.
            print("PREV4:RESULT pidfd_blocked", flush=True)
        else:
            print(f"PREV4:RESULT runtimeerror {msg!r}", flush=True)
    finally:
        proxy.shutdown()
    """
)

# Give the child real time to build nono, start the proxy, fork+handshake, and
# run -- while still being far below a "hang". The deadlock never returns.
_WALLCLOCK_TIMEOUT_S = 60


@pytest.fixture(scope="module")
def _abi_shim(tmp_path_factory) -> str:
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler available to build the ABI shim")
    d = tmp_path_factory.mktemp("prev4")
    src = d / "fake_abi.c"
    src.write_text(_SHIM_C)
    so = d / "fake_abi.so"
    proc = subprocess.run(  # noqa: S603
        [cc, "-shared", "-fPIC", "-o", str(so), str(src), "-ldl"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"could not build ABI shim: {proc.stderr}")
    return str(so)


def test_proxy_only_exec_does_not_deadlock_on_pre_v4(_abi_shim, tmp_path) -> None:
    """proxy_only() + sandboxed_exec() must complete on the seccomp fallback path.

    Before the fd-handoff fix this hung forever (child wedged in the trapped
    sendmsg handshake before execve). The pass condition is simply: the call
    returns within the wall-clock budget, the ABI clamp was in effect, and the
    supervisor mediated the child (denied) -- or, in a container that blocks
    pidfd_getfd, it failed fast rather than hanging.
    """
    driver = tmp_path / "driver.py"
    driver.write_text(_DRIVER_PY)

    env = dict(os.environ)
    env["LD_PRELOAD"] = _abi_shim

    try:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, str(driver)],
            env=env,
            capture_output=True,
            text=True,
            timeout=_WALLCLOCK_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            "DEADLOCK REGRESSION: proxy_only() sandboxed_exec() did not return "
            f"within {_WALLCLOCK_TIMEOUT_S}s on the pre-V4 seccomp fallback path"
        )

    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("PREV4:")]
    combined = proc.stdout + "\n" + proc.stderr

    abi_line = next((ln for ln in lines if ln.startswith("PREV4:ABI=")), None)
    assert abi_line is not None, f"driver produced no ABI line; output:\n{combined}"
    if abi_line != "PREV4:ABI=2":
        pytest.skip(f"ABI shim not in effect ({abi_line}); cannot exercise fallback")

    result = next((ln for ln in lines if ln.startswith("PREV4:RESULT")), None)
    assert result is not None, f"driver produced no RESULT; output:\n{combined}"

    # A container that gates pidfd_getfd behind CAP_SYS_PTRACE fails fast with a
    # clean error -- not the deadlock, so it satisfies this regression.
    if "pidfd_blocked" in result:
        return

    # Otherwise the supervisor must have mediated the child and denied the
    # non-proxy destination. "CONNECTED" would mean the policy was bypassed.
    assert "DENIED_EACCES" in combined, (
        f"expected the trapped connect to be denied; got:\n{combined}"
    )
    assert "CONNECTED" not in combined, f"proxy_only allowed a denied dest:\n{combined}"
