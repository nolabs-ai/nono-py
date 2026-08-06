"""Regression test for the pre-Landlock-V4 proxy_only() exec deadlock.

On kernels without Landlock ABI V4 (< 6.7), proxy_only() enforcement falls back
to a seccomp USER_NOTIF filter. nono >= 0.67 traps sendmsg in that filter, which
once deadlocked sandboxed_exec(): the child handed the notify fd to the parent
via an SCM_RIGHTS sendmsg that the filter itself trapped. The current handoff
uses a short CLONE_FILES bootstrap, detaches the child's fd table, and completes
an ownership barrier without pidfd_getfd.

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
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
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
    if (nr == SYS_pidfd_open || nr == SYS_pidfd_getfd) {
        static const char marker[] = "PREV4:PIDFD_SYSCALL\n";
        write(2, marker, sizeof(marker) - 1);
        errno = EPERM;
        return -1;
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
    import ctypes, os, socket, sys
    import nono_py as nono

    def fd_snapshot():
        snapshot = {}
        for name in os.listdir("/proc/self/fd"):
            try:
                fd = int(name)
                snapshot[fd] = os.readlink(f"/proc/self/fd/{name}")
            except (FileNotFoundError, OSError, ValueError):
                # The descriptor used by listdir() is normally gone before
                # readlink(), and unrelated runtime threads may close their
                # own descriptors while the snapshot is being collected.
                pass
        return snapshot

    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, None, 0, 1)  # same probe the landlock crate uses
    print(f"PREV4:ABI={abi}", flush=True)

    proxy = nono.start_proxy(nono.ProxyConfig(allowed_hosts=["example.com"]))
    caps = nono.CapabilitySet()
    caps.allow_path("/", nono.AccessMode.READ)  # enough to exec the interpreter
    caps.proxy_only(proxy)
    parent_fds_before = fd_snapshot()

    # The target reports inherited descriptors before opening a socket, then
    # exercises both sides of the proxy-only policy. The proxy port is allowed;
    # another loopback port is denied. Both connect() calls are trapped.
    child = [sys.executable, "-c",
             "import os, socket\\n"
             "leaks = []\\n"
             "for name in os.listdir('/proc/self/fd'):\\n"
             "    try:\\n"
             "        target = os.readlink('/proc/self/fd/' + name)\\n"
             "    except OSError:\\n"
             "        continue\\n"
             "    if 'seccomp notify' in target or target.startswith('socket:'):\\n"
             "        leaks.append((name, target))\\n"
             "print('HYGIENE', leaks)\\n"
             "allowed = socket.socket()\\n"
             "allowed.settimeout(3)\\n"
             f"allowed.connect(('127.0.0.1', {proxy.port}))\\n"
             "allowed.close()\\n"
             "print('PROXY_CONNECTED')\\n"
             "try:\\n"
             "    socket.socket().connect(('127.0.0.1', 9))\\n"
             "    print('DIRECT_CONNECTED')\\n"
             "except PermissionError:\\n"
             "    print('DENIED_EACCES')\\n"
             "except OSError as e:\\n"
             "    print('OSERR', e.errno)\\n"]
    try:
        r = nono.sandboxed_exec(caps, child, timeout_secs=None)
        print(f"PREV4:RESULT exit={r.exit_code} out={r.stdout!r} err={r.stderr[:200]!r}",
              flush=True)

        # Exercise the low-fd edge: preserve then close all parent stdio while
        # preparing/launching another child. Bootstrap descriptors must not be
        # confused with fd 0/1/2, and the parent slots must return closed.
        saved_stdio = [os.dup(fd) for fd in (0, 1, 2)]
        try:
            for fd in (0, 1, 2):
                os.close(fd)
            closed_stdio_result = nono.sandboxed_exec(
                caps,
                [sys.executable, "-c", "print('CLOSED_STDIO_OK')"],
                timeout_secs=10,
            )
            stdio_was_closed = all(
                not os.path.exists(f"/proc/self/fd/{fd}") for fd in (0, 1, 2)
            )
        finally:
            for fd, saved in zip((0, 1, 2), saved_stdio, strict=True):
                os.dup2(saved, fd)
                os.close(saved)
        print(
            "PREV4:CLOSED_STDIO="
            f"exit={closed_stdio_result.exit_code} "
            f"out={closed_stdio_result.stdout!r} restored={stdio_was_closed}",
            flush=True,
        )

        timeout_result = nono.sandboxed_exec(
            caps,
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_secs=0.2,
        )
        print(f"PREV4:TIMEOUT=exit={timeout_result.exit_code}", flush=True)

        parent_fds_after = fd_snapshot()
        leaked = {
            fd: target for fd, target in parent_fds_after.items()
            if parent_fds_before.get(fd) != target
            and ('seccomp notify' in target or target.startswith('socket:'))
        }
        print(f"PREV4:PARENT_LEAKS={leaked!r}", flush=True)
    except RuntimeError as e:
        print(f"PREV4:RESULT runtimeerror {str(e)!r}", flush=True)
    finally:
        proxy.shutdown()
    """
)

_CHURN_DRIVER_PY = textwrap.dedent(
    """
    import concurrent.futures, ctypes, os, signal, socket, sys, threading, time
    import nono_py as nono

    def fd_snapshot():
        snapshot = {}
        for name in os.listdir("/proc/self/fd"):
            try:
                fd = int(name)
                snapshot[fd] = os.readlink(f"/proc/self/fd/{name}")
            except (FileNotFoundError, OSError, ValueError):
                pass
        return snapshot

    def fd_identity(fd):
        stat = os.fstat(fd)
        return (stat.st_dev, stat.st_ino, stat.st_mode, stat.st_rdev)

    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, None, 0, 1)
    print(f"PREV4:ABI={abi}", flush=True)

    scratch = sys.argv[1]
    worker_count = 4
    proxy = nono.start_proxy(nono.ProxyConfig(allowed_hosts=["example.com"]))
    parent_fds_before = fd_snapshot()
    stdio_before = [fd_identity(fd) for fd in (0, 1, 2)]
    stop = threading.Event()
    signal_count = 0

    def on_signal(_signum, _frame):
        global signal_count
        signal_count += 1

    signal.signal(signal.SIGUSR1, on_signal)

    def churn():
        while not stop.is_set():
            fd = os.open("/dev/null", os.O_RDONLY)
            os.close(fd)
            left, right = socket.socketpair()
            left.close()
            right.close()
            os.kill(os.getpid(), signal.SIGUSR1)
            time.sleep(0.001)

    churn_thread = threading.Thread(target=churn, name="fd-churn", daemon=True)
    churn_thread.start()

    target = (
        "import glob, os, sys, time\\n"
        "scratch, worker, total = sys.argv[1], sys.argv[2], int(sys.argv[3])\\n"
        "open(os.path.join(scratch, 'target-' + worker), 'w').close()\\n"
        "deadline = time.monotonic() + 10\\n"
        "while len(glob.glob(os.path.join(scratch, 'target-*'))) < total:\\n"
        "    if time.monotonic() >= deadline:\\n"
        "        print('TARGET_SERIALIZED_TIMEOUT', worker)\\n"
        "        raise SystemExit(2)\\n"
        "    time.sleep(0.01)\\n"
        "print('TARGET_CONCURRENT', worker)\\n"
    )

    def launch(worker):
        caps = nono.CapabilitySet()
        caps.allow_path("/", nono.AccessMode.READ)
        caps.allow_path(scratch, nono.AccessMode.READ_WRITE)
        caps.proxy_only(proxy)
        return nono.sandboxed_exec(
            caps,
            [sys.executable, "-c", target, scratch, str(worker), str(worker_count)],
            timeout_secs=15,
        )

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
            results = list(pool.map(launch, range(worker_count)))
    finally:
        stop.set()
        churn_thread.join(timeout=5)

    stdio_after = [fd_identity(fd) for fd in (0, 1, 2)]
    parent_fds_after = fd_snapshot()
    leaks = {
        fd: target for fd, target in parent_fds_after.items()
        if parent_fds_before.get(fd) != target
        and ('seccomp notify' in target or target.startswith('socket:'))
    }
    summaries = [(r.exit_code, r.stdout.decode(errors='replace').strip()) for r in results]
    print(f"PREV4:CONCURRENT={summaries!r}", flush=True)
    print(f"PREV4:STDIO_INTACT={stdio_before == stdio_after}", flush=True)
    print(f"PREV4:PARENT_LEAKS={leaks!r}", flush=True)
    print(f"PREV4:SIGNALS={signal_count}", flush=True)
    proxy.shutdown()
    """
)

_FAILURE_DRIVER_PY = textwrap.dedent(
    """
    import ctypes, os, sys
    import nono_py as nono

    def fd_snapshot():
        snapshot = {}
        for name in os.listdir("/proc/self/fd"):
            try:
                fd = int(name)
                snapshot[fd] = os.readlink(f"/proc/self/fd/{name}")
            except (FileNotFoundError, OSError, ValueError):
                pass
        return snapshot

    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, None, 0, 1)
    print(f"PREV4:ABI={abi}", flush=True)

    proxy = nono.start_proxy(nono.ProxyConfig(allowed_hosts=["example.com"]))
    caps = nono.CapabilitySet()
    caps.allow_path("/", nono.AccessMode.READ)
    caps.proxy_only(proxy)
    parent_fds_before = fd_snapshot()
    phases = (
        "before_listener",
        "after_listener",
        "after_fd_report",
        "after_unshare",
        "after_detached",
        "after_ack",
    )
    outcomes = []
    hook_active = True
    try:
        for phase in phases:
            for attempt in range(2):
                os.environ["NONO_PY_TEST_CLONE_FILES_FAULT"] = phase
                try:
                    result = nono.sandboxed_exec(
                        caps,
                        [sys.executable, "-c", "print('EXECUTED')"],
                        timeout_secs=10,
                    )
                except RuntimeError as error:
                    outcomes.append((phase, attempt, "error", str(error)))
                else:
                    output = result.stdout.decode(errors="replace")
                    outcomes.append((phase, attempt, f"exit={result.exit_code}", output))
                    if result.exit_code == 0 or "EXECUTED" in output:
                        hook_active = False
                        break
            if not hook_active:
                break
    finally:
        os.environ.pop("NONO_PY_TEST_CLONE_FILES_FAULT", None)

    parent_fds_after = fd_snapshot()
    leaks = {
        fd: target for fd, target in parent_fds_after.items()
        if parent_fds_before.get(fd) != target
        and ('seccomp notify' in target or target.startswith('socket:'))
    }
    print(f"PREV4:DEBUG_HOOK={hook_active}", flush=True)
    print(f"PREV4:FAILURES={outcomes!r}", flush=True)
    print(f"PREV4:PARENT_LEAKS={leaks!r}", flush=True)
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
    supervisor mediated the child (denied), without requiring pidfd_getfd.
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

    assert "pidfd_getfd" not in combined
    assert "CAP_SYS_PTRACE" not in combined
    assert "PREV4:PIDFD_SYSCALL" not in combined

    # The supervisor must mediate both decisions. The proxy listener is
    # reachable, while a direct connection is denied.
    assert "PROXY_CONNECTED" in combined, (
        f"expected the trapped proxy connect to succeed; got:\n{combined}"
    )
    assert "DENIED_EACCES" in combined, (
        f"expected the trapped connect to be denied; got:\n{combined}"
    )
    assert "DIRECT_CONNECTED" not in combined, (
        f"proxy_only allowed a denied destination:\n{combined}"
    )
    assert "HYGIENE []" in combined, f"bootstrap fd reached the target:\n{combined}"
    assert "PREV4:CLOSED_STDIO=exit=0" in combined, combined
    assert "CLOSED_STDIO_OK" in combined, combined
    assert "restored=True" in combined, combined
    assert "PREV4:TIMEOUT=exit=124" in combined, combined
    assert "PREV4:PARENT_LEAKS={}" in combined, f"bootstrap fd leaked in the parent:\n{combined}"


def test_pre_v4_bootstraps_survive_fd_churn_and_signals(_abi_shim, tmp_path) -> None:
    """Concurrent shared-table windows stay safe and release before target wait."""
    driver = tmp_path / "churn_driver.py"
    driver.write_text(_CHURN_DRIVER_PY)
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    env = dict(os.environ)
    env["LD_PRELOAD"] = _abi_shim

    try:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, str(driver), str(scratch)],
            env=env,
            capture_output=True,
            text=True,
            timeout=_WALLCLOCK_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            "concurrent pre-V4 bootstraps did not complete under fd/signal churn "
            f"within {_WALLCLOCK_TIMEOUT_S}s"
        )

    combined = proc.stdout + "\n" + proc.stderr
    if "PREV4:ABI=2" not in combined:
        pytest.skip(f"ABI shim not in effect; cannot exercise fallback:\n{combined}")

    assert proc.returncode == 0, combined
    assert "TARGET_SERIALIZED_TIMEOUT" not in combined, combined
    assert combined.count("TARGET_CONCURRENT") == 4, combined
    assert "PREV4:STDIO_INTACT=True" in combined, combined
    assert "PREV4:PARENT_LEAKS={}" in combined, combined

    signal_line = next(
        (line for line in proc.stdout.splitlines() if line.startswith("PREV4:SIGNALS=")),
        None,
    )
    assert signal_line is not None, combined
    assert int(signal_line.partition("=")[2]) > 0, combined


def test_pre_v4_bootstrap_failures_do_not_leak_listeners(_abi_shim, tmp_path) -> None:
    """Every debug fault phase fails closed and releases bootstrap descriptors."""
    driver = tmp_path / "failure_driver.py"
    driver.write_text(_FAILURE_DRIVER_PY)

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
            f"pre-V4 bootstrap fault cleanup did not complete within {_WALLCLOCK_TIMEOUT_S}s"
        )

    combined = proc.stdout + "\n" + proc.stderr
    if "PREV4:ABI=2" not in combined:
        pytest.skip(f"ABI shim not in effect; cannot exercise fallback:\n{combined}")
    if "PREV4:DEBUG_HOOK=False" in combined:
        pytest.skip("bootstrap fault injection is available only in debug/test builds")

    assert proc.returncode == 0, combined
    assert "EXECUTED" not in combined, combined
    assert "exit=0" not in combined, combined
    assert "PREV4:DEBUG_HOOK=True" in combined, combined
    assert "PREV4:PARENT_LEAKS={}" in combined, combined
    for phase in (
        "before_listener",
        "after_listener",
        "after_fd_report",
        "after_unshare",
        "after_detached",
        "after_ack",
    ):
        assert combined.count(f"('{phase}',") == 2, combined
