"""Tests for sandboxed_exec function."""

import contextlib
import errno
import os
import pwd
import shutil
import signal
import subprocess
import sys
import time

import pytest
from conftest import add_system_paths

from nono_py import (
    AccessMode,
    CapabilitySet,
    ExecResult,
    ProxyConfig,
    SandboxState,
    sandboxed_exec,
    start_proxy,
)

# errno values that indicate a sandbox (Landlock/seccomp) denial, as opposed to
# an unrelated failure such as ECONNREFUSED or a routing error.
_DENIAL_ERRNOS = (errno.EACCES, errno.EPERM)


def process_exists(pid: int) -> bool:
    """Return True if pid currently exists."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def clear_dangerous_loader_env(monkeypatch):
    """Remove loader env vars so inherit_env tests are not host-dependent."""
    for key in list(os.environ):
        if key.startswith(("LD_", "DYLD_")) or key in {"LIBPATH", "SHLIB_PATH"}:
            monkeypatch.delenv(key, raising=False)


# --- Unprivileged privilege-drop testing via user namespaces ----------------
#
# A real uid/gid drop needs privilege, so these behaviours used to be testable
# only as root. But an unprivileged user namespace that maps a subuid/subgid
# range lets us drive the genuine drop path in ordinary CI: inside the namespace
# the caller becomes "root" (mapped to the real user) and can hand the child a
# distinct uid taken from the mapped range. Two rules make it work:
#   * the namespace parent runs the CURRENT interpreter (sys.executable) so it
#     can still import nono_py from the venv, and
#   * the dropped child must exec a WORLD-READABLE system binary — the venv
#     interpreter lives under $HOME and is unreadable once the uid is dropped.

_CHILD_PY = "/usr/bin/python3"  # world-readable; safe to exec as the dropped uid
_DROP_ID = 4000  # distinct from both inner-root (0) and the real caller uid
_UNSHARE = shutil.which("unshare")


def _subid_range(path: str, name: str, numeric_id: int) -> tuple[int, int] | None:
    """Parse an /etc/subuid|subgid line for this user; return (start, count)."""
    with contextlib.suppress(OSError), open(path) as f:
        for line in f:
            owner, _, rest = line.strip().partition(":")
            start_s, _, count_s = rest.partition(":")
            if owner in (name, str(numeric_id)) and start_s and count_s:
                return int(start_s), int(count_s)
    return None


def _userns_map_args() -> list[str] | None:
    """Build unshare args mapping inner-0 -> caller and a subid range -> inner 1.., or None."""
    uid, gid = os.getuid(), os.getgid()
    name = pwd.getpwuid(uid).pw_name
    su = _subid_range("/etc/subuid", name, uid)
    sg = _subid_range("/etc/subgid", name, gid)
    if su is None or sg is None:
        return None
    (su_start, su_count), (sg_start, sg_count) = su, sg
    # The drop target must fall inside the mapped range (inner ids 1..count-1).
    if su_count <= _DROP_ID or sg_count <= _DROP_ID:
        return None
    return [
        "--user",
        f"--map-users=0:{uid}:1",
        f"--map-users=1:{su_start}:{su_count - 1}",
        f"--map-groups=0:{gid}:1",
        f"--map-groups=1:{sg_start}:{sg_count - 1}",
    ]


def _run_in_userns(script: str) -> subprocess.CompletedProcess:
    """Run `script` with the current interpreter inside a range-mapped user namespace."""
    args = _userns_map_args()
    assert _UNSHARE is not None and args is not None  # gated by the skipif below
    env = dict(os.environ, NONO_DROP_ID=str(_DROP_ID), NONO_CHILD_PY=_CHILD_PY)
    return subprocess.run(  # noqa: S603
        [_UNSHARE, *args, sys.executable, "-c", script],
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )


def _can_drop_in_userns() -> bool:
    """True if this host can really drop to a non-zero uid/gid in an unprivileged userns."""
    if not sys.platform.startswith("linux"):
        return False
    if _UNSHARE is None or not os.path.exists(_CHILD_PY):
        return False
    args = _userns_map_args()
    if args is None:
        return False
    probe = f"import os; os.setgroups([]); os.setgid({_DROP_ID}); os.setuid({_DROP_ID})"
    try:
        proc = subprocess.run(  # noqa: S603
            [_UNSHARE, *args, _CHILD_PY, "-c", probe],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


# Evaluated once at collection time; cheap and side-effect-free.
_CAN_DROP_IN_USERNS = _can_drop_in_userns()

# Shared setup for the in-userns child scripts: build a CapabilitySet that lets a
# world-readable system python run, plus a world-enterable working directory.
_USERNS_PRELUDE = """
import os, sys, tempfile
from nono_py import AccessMode, CapabilitySet, sandboxed_exec

DROP_ID = int(os.environ["NONO_DROP_ID"])
CHILD_PY = os.environ["NONO_CHILD_PY"]

work = tempfile.mkdtemp()
os.chmod(work, 0o777)  # the dropped uid must be able to enter its cwd
caps = CapabilitySet()
for _p in ("/usr", "/bin", "/lib", "/lib64", "/etc", "/proc", "/dev"):
    if os.path.exists(_p):
        try:
            caps.allow_path(_p, AccessMode.READ)
        except Exception:
            pass
caps.allow_path(work, AccessMode.READ_WRITE)
"""


class TestExecResult:
    """Tests for ExecResult type."""

    def test_repr(self, temp_dir):
        """ExecResult has a useful repr."""
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        result = sandboxed_exec(caps, ["echo", "hello"], cwd=str(temp_dir))
        assert "ExecResult" in repr(result)
        assert "exit_code=0" in repr(result)


class TestSandboxedExec:
    """Tests for sandboxed_exec function."""

    @pytest.fixture
    def base_caps(self, temp_dir):
        """Create a capability set with system paths and a working directory."""
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        return caps

    def test_simple_echo(self, base_caps, temp_dir):
        """Execute a simple echo command."""
        result = sandboxed_exec(base_caps, ["echo", "hello world"], cwd=str(temp_dir))
        assert isinstance(result, ExecResult)
        assert result.exit_code == 0
        assert result.stdout == b"hello world\n"
        assert result.stderr == b""

    def test_exit_code(self, base_caps, temp_dir):
        """Non-zero exit codes are captured."""
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "raise SystemExit(42)"],
            cwd=str(temp_dir),
        )
        assert result.exit_code == 42

    def test_stderr_capture(self, base_caps, temp_dir):
        """stderr is captured separately from stdout."""
        result = sandboxed_exec(
            base_caps,
            [
                sys.executable,
                "-c",
                "import sys; print('out'); print('err', file=sys.stderr)",
            ],
            cwd=str(temp_dir),
        )
        assert result.exit_code == 0
        assert b"out\n" in result.stdout
        assert b"err\n" in result.stderr

    def test_cwd(self, base_caps, temp_dir):
        """Working directory is respected."""
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "import os; print(os.getcwd())"],
            cwd=str(temp_dir),
        )
        assert result.exit_code == 0
        # On macOS /tmp -> /private/tmp, so check the canonical path
        output_path = result.stdout.decode().strip()
        assert os.path.realpath(output_path) == os.path.realpath(str(temp_dir))

    def test_env_override(self, base_caps, temp_dir):
        """Explicit environment variables are applied."""
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "import os; print(os.environ['MY_VAR'])"],
            cwd=str(temp_dir),
            env=[("MY_VAR", "test_value")],
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == b"test_value"

    def test_parent_environment_is_not_inherited_by_default(self, base_caps, temp_dir, monkeypatch):
        """Parent environment variables should not leak into the child."""
        monkeypatch.setenv("NONO_TEST_PARENT_SECRET", "secret-value")

        result = sandboxed_exec(
            base_caps,
            [
                sys.executable,
                "-c",
                ("import os\nprint(os.environ.get('NONO_TEST_PARENT_SECRET', 'MISSING'))\n"),
            ],
            cwd=str(temp_dir),
        )

        assert result.exit_code == 0
        assert result.stdout.strip() == b"MISSING"

    def test_parent_environment_inheritance_is_explicit(self, base_caps, temp_dir, monkeypatch):
        """Parent env inheritance requires inherit_env=True."""
        clear_dangerous_loader_env(monkeypatch)
        monkeypatch.setenv("NONO_TEST_PARENT_VALUE", "inherited-value")

        result = sandboxed_exec(
            base_caps,
            [
                sys.executable,
                "-c",
                "import os; print(os.environ['NONO_TEST_PARENT_VALUE'])",
            ],
            cwd=str(temp_dir),
            inherit_env=True,
        )

        assert result.exit_code == 0
        assert result.stdout.strip() == b"inherited-value"

    def test_loader_env_vars_are_rejected(self, base_caps, temp_dir):
        """Dynamic-loader env vars are blocked even when explicit."""
        with pytest.raises(ValueError, match="LD_PRELOAD"):
            sandboxed_exec(
                base_caps,
                ["echo", "ignored"],
                cwd=str(temp_dir),
                env=[("LD_PRELOAD", "blocked-loader.so")],
            )

    def test_inherited_loader_env_vars_are_rejected(self, base_caps, temp_dir, monkeypatch):
        """inherit_env=True fails closed on dangerous parent loader state."""
        clear_dangerous_loader_env(monkeypatch)
        monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "blocked-inject.dylib")

        with pytest.raises(ValueError, match="DYLD_INSERT_LIBRARIES"):
            sandboxed_exec(
                base_caps,
                ["echo", "ignored"],
                cwd=str(temp_dir),
                inherit_env=True,
            )

    def test_sandbox_blocks_access(self, temp_dir):
        """Sandbox prevents access to paths not in the capability set."""
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)

        result = sandboxed_exec(
            caps,
            ["cat", "/etc/passwd"],
            cwd=str(temp_dir),
        )
        assert result.exit_code != 0

    def test_parent_file_descriptors_are_not_inherited(self, base_caps, temp_dir):
        """Parent-open fds should not survive into the sandboxed exec child."""
        secret_path = temp_dir / "parent-only.txt"
        secret_path.write_text("fd-leak")

        fd = os.open(secret_path, os.O_RDONLY)
        assert fd > 2
        os.set_inheritable(fd, True)
        try:
            result = sandboxed_exec(
                base_caps,
                [
                    sys.executable,
                    "-c",
                    (
                        "import errno, os\n"
                        f"fd = {fd}\n"
                        "try:\n"
                        "    os.read(fd, 1)\n"
                        "except OSError as e:\n"
                        "    if e.errno == errno.EBADF:\n"
                        "        print('FD_CLOSED')\n"
                        "    else:\n"
                        "        print(f'FD_ERROR:{e.errno}')\n"
                        "else:\n"
                        "    print('FD_LEAKED')\n"
                    ),
                ],
                cwd=str(temp_dir),
            )
        finally:
            os.close(fd)

        assert result.exit_code == 0
        assert b"FD_CLOSED" in result.stdout
        assert b"FD_LEAKED" not in result.stdout

    def test_write_file_in_sandbox(self, base_caps, temp_dir):
        """Can write files to allowed paths."""
        result = sandboxed_exec(
            base_caps,
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path\n"
                    "Path('test.txt').write_text('sandboxed\\n')\n"
                    "print(Path('test.txt').read_text(), end='')\n"
                ),
            ],
            cwd=str(temp_dir),
        )
        assert result.exit_code == 0
        assert b"sandboxed" in result.stdout

    def test_timeout(self, base_caps, temp_dir):
        """Timeout kills long-running commands."""
        result = sandboxed_exec(
            base_caps,
            ["sleep", "60"],
            cwd=str(temp_dir),
            timeout_secs=0.5,
        )
        assert result.exit_code == 124  # Standard timeout exit code

    def test_timeout_kills_forked_descendants(self, base_caps, temp_dir):
        """Timeout kills the sandboxed command's process group."""
        pid_file = temp_dir / "child-pids.txt"

        started_at = time.monotonic()
        result = sandboxed_exec(
            base_caps,
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path\n"
                    "import subprocess\n"
                    "children = [subprocess.Popen(['sleep', '60']) for _ in range(2)]\n"
                    f"Path({str(pid_file)!r}).write_text("
                    "'\\n'.join(str(child.pid) for child in children) + '\\n')\n"
                    "for child in children:\n"
                    "    child.wait()\n"
                ),
            ],
            cwd=str(temp_dir),
            timeout_secs=0.5,
        )
        elapsed = time.monotonic() - started_at

        assert result.exit_code == 124
        assert elapsed < 5.0

        child_pids = [int(line) for line in pid_file.read_text().splitlines()]
        assert len(child_pids) == 2

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if all(not process_exists(pid) for pid in child_pids):
                break
            time.sleep(0.05)

        assert all(not process_exists(pid) for pid in child_pids)

    def test_empty_command_raises(self, base_caps):
        """Empty command list raises ValueError."""
        with pytest.raises(ValueError, match="command must not be empty"):
            sandboxed_exec(base_caps, [])

    def test_negative_timeout_raises(self, base_caps, temp_dir):
        """Negative timeout raises ValueError instead of panicking."""
        with pytest.raises(ValueError, match="timeout_secs must be non-negative"):
            sandboxed_exec(
                base_caps,
                ["echo", "hello"],
                cwd=str(temp_dir),
                timeout_secs=-1.0,
            )

    def test_zero_max_processes_raises(self, base_caps, temp_dir):
        """max_processes must be positive."""
        with pytest.raises(ValueError, match="max_processes must be positive"):
            sandboxed_exec(
                base_caps,
                ["echo", "hello"],
                cwd=str(temp_dir),
                max_processes=0,
            )

    def test_repeated_calls(self, base_caps, temp_dir):
        """Multiple calls work - parent process stays unsandboxed."""
        for i in range(3):
            result = sandboxed_exec(
                base_caps,
                ["echo", str(i)],
                cwd=str(temp_dir),
            )
            assert result.exit_code == 0
            assert result.stdout.strip() == str(i).encode()

    def test_command_not_found(self, base_caps, temp_dir):
        """Non-existent commands raise RuntimeError."""
        with pytest.raises(RuntimeError, match="Program not found in PATH"):
            sandboxed_exec(
                base_caps,
                ["nonexistent_command_xyz"],
                cwd=str(temp_dir),
            )


class TestSandboxedExecResourceLimits:
    """Resource-limit caps applied via setrlimit before exec."""

    @pytest.fixture
    def base_caps(self, temp_dir):
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        return caps

    def test_max_cpu_seconds_kills_runaway(self, base_caps, temp_dir):
        """A CPU-bound loop is terminated by the CPU cap, not our timeout path."""
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "x = 0\nwhile True:\n    x += 1"],
            cwd=str(temp_dir),
            max_cpu_seconds=1,
            timeout_secs=30.0,
        )
        # The cap terminates the child by signal. Because soft == hard the kernel
        # delivers SIGKILL; some kernels/timing deliver SIGXCPU first. Either way
        # it is a signal death, and NOT our timeout path (which returns 124, and
        # would only fire at 30s — far beyond the ~1s CPU cap).
        assert result.exit_code in (-signal.SIGKILL, -signal.SIGXCPU), result.exit_code

    def test_max_file_size_bytes_blocks_large_write(self, base_caps, temp_dir):
        """Writing past RLIMIT_FSIZE fails instead of filling the disk."""
        target = temp_dir / "big.bin"
        prog = (
            "import sys\n"
            "with open(sys.argv[1], 'wb') as f:\n"
            "    f.write(b'x' * 1_000_000)\n"
            "    f.flush()\n"
            "print('WROTE')\n"
        )
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", prog, str(target)],
            cwd=str(temp_dir),
            max_file_size_bytes=4096,
            timeout_secs=15.0,
        )
        assert result.exit_code != 0
        assert b"WROTE" not in result.stdout
        # The file must not have grown past the cap.
        if target.exists():
            assert target.stat().st_size <= 1_000_000

    def test_max_file_size_zero_is_allowed_without_writes(self, base_caps, temp_dir):
        """A zero file-size cap is a valid 'no writes' policy, not an error."""
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "print('ok')"],
            cwd=str(temp_dir),
            max_file_size_bytes=0,
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == b"ok"

    def test_max_open_files_enforced(self, base_caps, temp_dir):
        """The child cannot exceed the RLIMIT_NOFILE cap."""
        readable = temp_dir / "readme.txt"
        readable.write_text("hello")
        # 200 is safely below macOS's default RLIMIT_NOFILE of 256 so the
        # uncapped run succeeds, while the explicit cap of 96 still blocks it.
        target = 200
        prog = (
            f"import sys\n"
            f"held = []\n"
            f"try:\n"
            f"    for _ in range({target}):\n"
            f"        held.append(open(sys.argv[1]))\n"
            f"    print('OPENED_ALL', len(held))\n"
            f"except OSError:\n"
            f"    print('BLOCKED', len(held))\n"
        )
        capped = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", prog, str(readable)],
            cwd=str(temp_dir),
            max_open_files=96,
            timeout_secs=15.0,
        )
        assert capped.exit_code == 0
        assert b"BLOCKED" in capped.stdout

        uncapped = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", prog, str(readable)],
            cwd=str(temp_dir),
            timeout_secs=15.0,
        )
        assert uncapped.exit_code == 0
        assert b"OPENED_ALL" in uncapped.stdout

    def test_max_open_files_too_low_fails_closed(self, base_caps, temp_dir):
        """A NOFILE cap below what the sandbox needs to install fails closed:
        the child aborts before exec rather than running unsandboxed."""
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "print('RAN')"],
            cwd=str(temp_dir),
            max_open_files=3,
            timeout_secs=15.0,
        )
        assert result.exit_code != 0
        assert b"RAN" not in result.stdout

    def test_zero_max_cpu_seconds_raises(self, base_caps, temp_dir):
        with pytest.raises(ValueError, match="max_cpu_seconds must be positive"):
            sandboxed_exec(base_caps, ["echo", "hi"], cwd=str(temp_dir), max_cpu_seconds=0)

    def test_zero_max_open_files_raises(self, base_caps, temp_dir):
        with pytest.raises(ValueError, match="max_open_files must be positive"):
            sandboxed_exec(base_caps, ["echo", "hi"], cwd=str(temp_dir), max_open_files=0)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="uid/gid drop is exercised on Linux here",
)
class TestSandboxedExecPrivilegeDrop:
    """uid=/gid= drop the child to a distinct identity (TS30 mitigation)."""

    @pytest.fixture
    def base_caps(self, temp_dir):
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        return caps

    def test_uid_drop_requires_privilege(self, base_caps, temp_dir):
        """Unprivileged callers cannot drop to another uid: fail closed (126)."""
        if os.getuid() == 0:
            pytest.skip("running as root; see test_uid_drop_as_root")
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "import os; print(os.getuid())"],
            cwd=str(temp_dir),
            uid=12345,
            gid=12345,
        )
        assert result.exit_code == 126
        assert b"drop privileges" in result.stderr

    def test_uid_drop_as_root(self, base_caps, temp_dir):
        """A privileged caller drops the child to the requested uid/gid."""
        if os.getuid() != 0:
            pytest.skip("requires root")
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "import os; print(f'{os.getuid()},{os.getgid()}')"],
            cwd=str(temp_dir),
            uid=4000,
            gid=4000,
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == b"4000,4000"

    def test_zero_uid_rejected(self, base_caps, temp_dir):
        """uid=0 is a no-op drop and almost certainly a mistake: rejected."""
        with pytest.raises(ValueError, match="uid must be non-zero"):
            sandboxed_exec(base_caps, ["echo", "hi"], cwd=str(temp_dir), uid=0)

    def test_zero_gid_rejected(self, base_caps, temp_dir):
        """gid=0 is a no-op drop and almost certainly a mistake: rejected."""
        with pytest.raises(ValueError, match="gid must be non-zero"):
            sandboxed_exec(base_caps, ["echo", "hi"], cwd=str(temp_dir), gid=0)

    def test_uid_without_gid_defaults_gid_to_uid(self, base_caps, temp_dir):
        """uid without gid must not retain the parent's gid: gid defaults to uid."""
        if os.getuid() != 0:
            pytest.skip("requires root")
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "import os; print(f'{os.getuid()},{os.getgid()}')"],
            cwd=str(temp_dir),
            uid=4000,
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == b"4000,4000"


@pytest.mark.skipif(
    not _CAN_DROP_IN_USERNS,
    reason="needs an unprivileged user namespace able to map a subuid/subgid range",
)
class TestSandboxedExecPrivilegeDropUnprivileged:
    """Exercise a REAL privilege drop without root, inside a range-mapped user namespace.

    See the _run_in_userns helper above for how the namespace is set up. Each
    embedded child program runs as the dropped uid and asserts the security
    properties the drop is meant to guarantee — the assertions no existing test
    reaches, because they need a genuine drop rather than a matching-getuid check.
    """

    def test_real_drop_blocks_signals_and_climb_back(self):
        """Distinct uid: the child cannot signal its parent and cannot climb back to root."""
        script = (
            _USERNS_PRELUDE
            + """
prog = "\\n".join([
    "import os, sys",
    "assert os.getuid() == %d, ('uid not dropped', os.getuid())" % DROP_ID,
    # The parent is inner-root (uid 0); a distinct-uid child must not be able to
    # signal it — this is the child->parent signal vector the feature closes.
    "try:",
    "    os.kill(os.getppid(), 0); print('SIGNAL_ALLOWED'); sys.exit(3)",
    "except PermissionError:",
    "    pass",
    # The saved-set-uid must be gone: the child cannot regain the parent's uid.
    "try:",
    "    os.setuid(0); print('CLIMBED_BACK'); sys.exit(4)",
    "except PermissionError:",
    "    pass",
    "print('CHILD_OK')",
])
r = sandboxed_exec(caps, [CHILD_PY, "-c", prog], cwd=work, uid=DROP_ID)
if r.exit_code != 0 or r.stdout.strip() != b"CHILD_OK":
    sys.stderr.write("PARENT_FAIL exit=%r out=%r err=%r" % (r.exit_code, r.stdout, r.stderr))
    sys.exit(1)
print("PARENT_OK")
"""
        )
        proc = _run_in_userns(script)
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert b"PARENT_OK" in proc.stdout

    def test_gid_defaults_to_uid_and_supp_groups_cleared(self):
        """uid without gid: gid defaults to uid, and supplementary groups are cleared."""
        script = (
            _USERNS_PRELUDE
            + """
prog = "\\n".join([
    "import os",
    "assert os.getuid() == %d, ('uid not dropped', os.getuid())" % DROP_ID,
    "assert os.getgid() == %d, ('gid not defaulted to uid', os.getgid())" % DROP_ID,
    "assert set(os.getgroups()) - {%d} == set(), ('supp groups not cleared', os.getgroups())"
    % DROP_ID,
    "print('CHILD_OK')",
])
r = sandboxed_exec(caps, [CHILD_PY, "-c", prog], cwd=work, uid=DROP_ID)  # gid omitted
if r.exit_code != 0 or r.stdout.strip() != b"CHILD_OK":
    sys.stderr.write("PARENT_FAIL exit=%r out=%r err=%r" % (r.exit_code, r.stdout, r.stderr))
    sys.exit(1)
print("PARENT_OK")
"""
        )
        proc = _run_in_userns(script)
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert b"PARENT_OK" in proc.stdout


class TestSandboxedExecEnforcementMode:
    """enforcement_mode pins the OS mechanism for subprocess sandboxing."""

    @pytest.fixture
    def base_caps(self, temp_dir):
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        return caps

    def _assert_mode_enforces(self, base_caps, temp_dir, mode):
        # A permitted command runs under the chosen mode...
        ran = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "print(21 * 2)"],
            cwd=str(temp_dir),
            enforcement_mode=mode,
        )
        assert ran.exit_code == 0, ran.stderr
        assert ran.stdout.strip() == b"42"
        # ...and the mode must still SANDBOX: a read outside the allow-list is
        # denied. This guards against a future refactor making a mode a no-op
        # (fail-open) — which "it runs and exits 0" alone would not catch.
        denied = sandboxed_exec(
            base_caps,
            ["cat", "/etc/passwd"],
            cwd=str(temp_dir),
            enforcement_mode=mode,
        )
        assert denied.exit_code != 0
        assert b"root:" not in denied.stdout

    def test_auto_mode_enforces(self, base_caps, temp_dir):
        self._assert_mode_enforces(base_caps, temp_dir, "auto")

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="seccomp is Linux-only")
    def test_seccomp_mode_enforces(self, base_caps, temp_dir):
        self._assert_mode_enforces(base_caps, temp_dir, "seccomp")

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="landlock is Linux-only")
    def test_landlock_mode_enforces(self, base_caps, temp_dir):
        self._assert_mode_enforces(base_caps, temp_dir, "landlock")

    def test_invalid_mode_raises(self, base_caps, temp_dir):
        with pytest.raises(ValueError, match="enforcement_mode must be"):
            sandboxed_exec(
                base_caps,
                ["echo", "x"],
                cwd=str(temp_dir),
                enforcement_mode="bogus",
            )

    @pytest.mark.skipif(sys.platform.startswith("linux"), reason="Linux supports landlock/seccomp")
    @pytest.mark.parametrize("mode", ["landlock", "seccomp"])
    def test_linux_only_modes_rejected_on_macos(self, base_caps, temp_dir, mode):
        """landlock and seccomp are rejected on non-Linux even though they parse as valid tokens."""
        with pytest.raises(ValueError, match="only available on Linux"):
            sandboxed_exec(
                base_caps,
                ["echo", "x"],
                cwd=str(temp_dir),
                enforcement_mode=mode,
            )

    @pytest.mark.parametrize("mode", ["AUTO", "Auto", " auto", "seccomp ", "landlock\n"])
    def test_mode_matching_is_strict(self, base_caps, temp_dir, mode):
        """enforcement_mode is matched exactly (no case-folding / trimming).

        Pins the current contract so a future "be lenient" change is a conscious,
        tested decision rather than a silent one.
        """
        with pytest.raises(ValueError, match="enforcement_mode must be"):
            sandboxed_exec(
                base_caps,
                ["echo", "x"],
                cwd=str(temp_dir),
                enforcement_mode=mode,
            )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="landlock is Linux-only")
class TestSandboxedExecLandlockProxyOnlyRejected:
    """enforcement_mode='landlock' cannot service NetworkMode::ProxyOnly.

    Proxy-only enforcement relies on the seccomp-notify supervisor (which
    checks the destination IP) alongside Landlock's NetPort rule (which only
    checks the port). Only the 'auto' and 'seccomp' paths install that
    supervisor, so 'landlock' must reject proxy_only() up front instead of
    silently under-enforcing (port-only, no IP check).
    """

    @pytest.fixture
    def proxy(self):
        p = start_proxy(ProxyConfig(allowed_hosts=["example.com"]))
        yield p
        p.shutdown()

    def test_landlock_mode_rejects_proxy_only(self, temp_dir, proxy):
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        caps.proxy_only(proxy)

        with pytest.raises(ValueError, match="enforcement_mode='landlock' cannot enforce"):
            sandboxed_exec(
                caps,
                ["echo", "x"],
                cwd=str(temp_dir),
                enforcement_mode="landlock",
            )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="seccomp is Linux-only")
class TestSandboxedExecSeccompBaseline:
    """Explicit seccomp mode opts into the staged static network baseline."""

    @pytest.fixture
    def base_caps(self, temp_dir):
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        return caps

    def test_plain_block_denies_udp_and_io_uring(self, base_caps, temp_dir):
        base_caps.block_network()
        prog = (
            "import ctypes, socket\n"
            "try:\n"
            "    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "    print('UDP_OPEN')\n"
            "except OSError as e:\n"
            "    print('UDP_BLOCKED', e.errno)\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "result = libc.syscall(425, 1, None)\n"
            "print('IO_URING', result, ctypes.get_errno())\n"
        )
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", prog],
            cwd=str(temp_dir),
            timeout_secs=15.0,
            enforcement_mode="seccomp",
        )
        assert result.exit_code == 0, result.stderr
        assert b"UDP_BLOCKED 1" in result.stdout
        assert b"UDP_OPEN" not in result.stdout
        assert b"IO_URING -1 1" in result.stdout


def _landlock_has_network() -> bool:
    """True if the running kernel enforces Landlock TCP port rules (ABI V4+)."""
    import nono_py

    if not sys.platform.startswith("linux"):
        return False
    try:
        return bool(nono_py.detect_abi().has_network)
    except Exception:
        return False


# A child probe that connects to a (port, expecting either success or a sandbox
# denial) and prints an unambiguous, errno-tagged result so the test can tell a
# Landlock/seccomp denial apart from ECONNREFUSED or a routing failure.
_CONNECT_PROBE = (
    "import socket, sys\n"
    "def probe(p):\n"
    "    try:\n"
    "        socket.create_connection(('127.0.0.1', p), timeout=5).close()\n"
    "        return 'OK'\n"
    "    except OSError as e:\n"
    "        return 'ERR:%d' % (e.errno or 0)\n"
    "print(' '.join(probe(int(a)) for a in sys.argv[1:]))\n"
)


def _open_listener():
    """Open an unsandboxed loopback listener; return (socket, port)."""
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock, sock.getsockname()[1]


def _assert_denied(token: bytes):
    """Assert a probe token reports a sandbox denial (EACCES/EPERM), not e.g.
    ECONNREFUSED — which would let a removed-enforcement regression pass."""
    assert token.startswith(b"ERR:"), f"expected a denial, got {token!r}"
    code = int(token.split(b":")[1])
    assert code in _DENIAL_ERRNOS, f"expected EACCES/EPERM denial, got errno {code}"


@pytest.mark.skipif(
    not _landlock_has_network(),
    reason="per-port TCP filtering needs Landlock ABI V4+ (kernel >= 6.7)",
)
class TestSandboxedExecPortFiltering:
    """allow_bind_port / allow_localhost_port / allow_tcp_connect_port (items 3, 8)."""

    @pytest.fixture
    def base_caps(self, temp_dir):
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        return caps

    def test_allow_bind_port_permits_listen(self, base_caps, temp_dir):
        """A server may bind its allowed port while outbound stays blocked."""
        base_caps.block_network()
        base_caps.allow_bind_port(8080)
        prog = (
            "import socket\n"
            "s = socket.socket()\n"
            "s.bind(('127.0.0.1', 8080))\n"
            "s.listen(1)\n"
            "print('BIND_OK')\n"
        )
        result = sandboxed_exec(
            base_caps, [sys.executable, "-c", prog], cwd=str(temp_dir), timeout_secs=15.0
        )
        assert result.exit_code == 0, result.stderr
        assert result.stdout.strip() == b"BIND_OK"

    def test_bind_denied_on_other_port(self, base_caps, temp_dir):
        """Binding a port that was not allowed fails with a sandbox denial."""
        base_caps.block_network()
        base_caps.allow_bind_port(8080)
        prog = (
            "import socket\n"
            "s = socket.socket()\n"
            "try:\n"
            "    s.bind(('127.0.0.1', 9090))\n"
            "    s.listen(1)\n"
            "    print('BIND_OK')\n"
            "except OSError as e:\n"
            "    print('ERR:%d' % (e.errno or 0))\n"
        )
        result = sandboxed_exec(
            base_caps, [sys.executable, "-c", prog], cwd=str(temp_dir), timeout_secs=15.0
        )
        assert result.exit_code == 0, result.stderr
        _assert_denied(result.stdout.strip())

    def test_outbound_blocked_while_bind_allowed(self, base_caps, temp_dir):
        """allow_bind_port does not open outbound egress.

        Targets an unsandboxed loopback listener the child could otherwise
        reach, and asserts a specific EACCES/EPERM denial — so a removed
        enforcement would flip the result to a successful connect, not silently
        pass on an ECONNREFUSED/timeout as the old 1.1.1.1 probe could.
        """
        listener, port = _open_listener()
        try:
            base_caps.block_network()
            base_caps.allow_bind_port(8080)  # bind only; no connect grant
            result = sandboxed_exec(
                base_caps,
                [sys.executable, "-c", _CONNECT_PROBE, str(port)],
                cwd=str(temp_dir),
                timeout_secs=15.0,
            )
            assert result.exit_code == 0, result.stderr
            _assert_denied(result.stdout.strip())
        finally:
            listener.close()

    def test_allow_localhost_port_connect(self, base_caps, temp_dir):
        """A permitted localhost port is reachable; an unlisted one is denied."""
        listener_ok, allowed_port = _open_listener()
        listener_blocked, blocked_port = _open_listener()
        try:
            base_caps.block_network()
            base_caps.allow_localhost_port(allowed_port)
            result = sandboxed_exec(
                base_caps,
                [sys.executable, "-c", _CONNECT_PROBE, str(allowed_port), str(blocked_port)],
                cwd=str(temp_dir),
                timeout_secs=15.0,
            )
            assert result.exit_code == 0, result.stderr
            allowed_tok, blocked_tok = result.stdout.split()
            assert allowed_tok == b"OK"
            _assert_denied(blocked_tok)
        finally:
            listener_ok.close()
            listener_blocked.close()

    def test_allow_tcp_connect_port_connect(self, base_caps, temp_dir):
        """allow_tcp_connect_port permits only the listed port; others denied."""
        listener_ok, allowed_port = _open_listener()
        listener_blocked, blocked_port = _open_listener()
        try:
            base_caps.block_network()
            base_caps.allow_tcp_connect_port(allowed_port)
            result = sandboxed_exec(
                base_caps,
                [sys.executable, "-c", _CONNECT_PROBE, str(allowed_port), str(blocked_port)],
                cwd=str(temp_dir),
                timeout_secs=15.0,
            )
            assert result.exit_code == 0, result.stderr
            allowed_tok, blocked_tok = result.stdout.split()
            assert allowed_tok == b"OK"
            _assert_denied(blocked_tok)
        finally:
            listener_ok.close()
            listener_blocked.close()

    def test_udp_egress_is_not_blocked(self, base_caps, temp_dir):
        """KNOWN GAP: Landlock filters TCP only, so UDP egress is NOT blocked by
        block_network()+allow_bind_port. Pins the current behaviour so a doc/impl
        claiming "all egress blocked" cannot land unchallenged; update when the
        crate gains UDP filtering."""
        base_caps.block_network()
        base_caps.allow_bind_port(8080)
        prog = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "try:\n"
            "    s.sendto(b'x', ('1.1.1.1', 53))\n"
            "    print('UDP_SENT')\n"
            "except OSError as e:\n"
            "    print('UDP_BLOCKED', e.errno)\n"
        )
        result = sandboxed_exec(
            base_caps, [sys.executable, "-c", prog], cwd=str(temp_dir), timeout_secs=15.0
        )
        assert result.exit_code == 0, result.stderr
        # Documents today's reality: UDP is not filtered by Landlock.
        assert result.stdout.strip() == b"UDP_SENT"

    def test_seccomp_mode_blocks_udp_with_port_exceptions(self, base_caps, temp_dir):
        """Explicit seccomp mode closes the compatibility-mode UDP gap."""
        base_caps.block_network()
        base_caps.allow_bind_port(8080)
        prog = (
            "import socket\n"
            "try:\n"
            "    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "    print('UDP_OPEN')\n"
            "except OSError as e:\n"
            "    print('UDP_BLOCKED', e.errno)\n"
        )
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", prog],
            cwd=str(temp_dir),
            timeout_secs=15.0,
            enforcement_mode="seccomp",
        )
        assert result.exit_code == 0, result.stderr
        assert result.stdout.strip() == b"UDP_BLOCKED 1"

    def test_localhost_port_zero_fails_closed(self, base_caps, temp_dir):
        """The port-0 localhost wildcard is rejected on Linux with block-net:
        the sandbox fails closed at apply rather than granting a wildcard."""
        base_caps.block_network()
        base_caps.allow_localhost_port(0)
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "print('RAN')"],
            cwd=str(temp_dir),
            timeout_secs=15.0,
        )
        assert result.exit_code != 0
        assert b"RAN" not in result.stdout


@pytest.mark.skipif(
    _landlock_has_network(),
    reason="fail-closed path only exists on Landlock ABI < V4 (kernel < 6.7)",
)
class TestPortFilteringFailClosedPreV4:
    """On kernels without Landlock net filtering (e.g. the 6.1 target), a port
    allowlist combined with block_network() must fail closed at apply time, not
    silently run unenforced. Skipped on V4+ where the crate seccomp fallback for
    this is not yet implemented."""

    @pytest.fixture
    def base_caps(self, temp_dir):
        caps = CapabilitySet()
        add_system_paths(caps)
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        return caps

    def test_block_plus_bind_port_fails_closed(self, base_caps, temp_dir):
        base_caps.block_network()
        base_caps.allow_bind_port(8080)
        result = sandboxed_exec(
            base_caps,
            [sys.executable, "-c", "print('RAN')"],
            cwd=str(temp_dir),
            timeout_secs=15.0,
        )
        # The child aborts before exec rather than running unenforced.
        assert result.exit_code != 0
        assert b"RAN" not in result.stdout
        assert b"sandbox apply failed" in result.stderr


class TestCapabilitySetPortMethods:
    """The port methods are callable regardless of kernel enforcement support."""

    def test_methods_exist_and_accept_ports(self):
        caps = CapabilitySet()
        caps.block_network()
        caps.allow_localhost_port(5000)
        caps.allow_tcp_connect_port(443)
        caps.allow_bind_port(8080)
        # summary should render without error
        assert isinstance(caps.summary(), str)

    @pytest.mark.parametrize(
        "setup",
        [
            lambda c: c.allow_localhost_port(5000),
            lambda c: c.allow_tcp_connect_port(443),
            lambda c: c.allow_bind_port(8080),
        ],
    )
    def test_sandboxstate_rejects_port_allowlists(self, setup):
        """SandboxState cannot serialize per-port allowlists, so from_caps fails
        closed (raises) rather than silently dropping them — which, in allow-all
        mode, would widen the restored sandbox to fully open. Guards against that
        silent widening until the crate serializes the port vectors."""
        caps = CapabilitySet()
        caps.block_network()
        setup(caps)
        with pytest.raises(ValueError, match="per-port TCP allowlist"):
            SandboxState.from_caps(caps)

    def test_sandboxstate_still_works_without_port_rules(self):
        """A capability set with no port allowlist round-trips as before."""
        caps = CapabilitySet()
        caps.block_network()
        restored = SandboxState.from_json(SandboxState.from_caps(caps).to_json()).to_caps()
        assert restored.is_network_blocked
