"""Tests for sandboxed_exec function."""

import os
import sys

import pytest
from conftest import add_system_paths

from nono_py import AccessMode, CapabilitySet, ExecResult, sandboxed_exec


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

    def test_parent_environment_is_not_inherited_by_default(
        self, base_caps, temp_dir, monkeypatch
    ):
        """Parent environment variables should not leak into the child."""
        monkeypatch.setenv("NONO_TEST_PARENT_SECRET", "secret-value")

        result = sandboxed_exec(
            base_caps,
            [
                sys.executable,
                "-c",
                (
                    "import os\n"
                    "print(os.environ.get('NONO_TEST_PARENT_SECRET', 'MISSING'))\n"
                ),
            ],
            cwd=str(temp_dir),
        )

        assert result.exit_code == 0
        assert result.stdout.strip() == b"MISSING"

    def test_parent_environment_inheritance_is_explicit(
        self, base_caps, temp_dir, monkeypatch
    ):
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

    def test_inherited_loader_env_vars_are_rejected(
        self, base_caps, temp_dir, monkeypatch
    ):
        """inherit_env=True fails closed on dangerous parent loader state."""
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
