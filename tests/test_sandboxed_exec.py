"""Tests for sandboxed_exec function."""

import os
import signal
import sys
import time

import pytest
from conftest import add_system_paths

from nono_py import AccessMode, CapabilitySet, ExecResult, sandboxed_exec


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
        prog = (
            "import sys\n"
            "held = []\n"
            "try:\n"
            "    for _ in range(1000):\n"
            "        held.append(open(sys.argv[1]))\n"
            "    print('OPENED_ALL', len(held))\n"
            "except OSError:\n"
            "    print('BLOCKED', len(held))\n"
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
