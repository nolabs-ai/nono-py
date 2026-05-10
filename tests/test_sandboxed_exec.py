"""Tests for sandboxed_exec function."""

import os

import pytest
from conftest import add_system_paths

from nono_py import AccessMode, CapabilitySet, ExecResult, sandboxed_exec


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
            ["bash", "-c", "exit 42"],
            cwd=str(temp_dir),
        )
        assert result.exit_code == 42

    def test_stderr_capture(self, base_caps, temp_dir):
        """stderr is captured separately from stdout."""
        result = sandboxed_exec(
            base_caps,
            ["bash", "-c", "echo out; echo err >&2"],
            cwd=str(temp_dir),
        )
        assert result.exit_code == 0
        assert b"out\n" in result.stdout
        assert b"err\n" in result.stderr

    def test_cwd(self, base_caps, temp_dir):
        """Working directory is respected."""
        # Use bash built-in pwd rather than /bin/pwd, which is blocked by
        # Seatbelt's file-read-metadata restriction on stat(".").
        result = sandboxed_exec(
            base_caps,
            ["bash", "-c", "pwd"],
            cwd=str(temp_dir),
        )
        assert result.exit_code == 0
        # On macOS /tmp -> /private/tmp, so check the canonical path
        output_path = result.stdout.decode().strip()
        assert os.path.realpath(output_path) == os.path.realpath(str(temp_dir))

    def test_env_override(self, base_caps, temp_dir):
        """Environment variable overrides are applied."""
        result = sandboxed_exec(
            base_caps,
            ["bash", "-c", "echo $MY_VAR"],
            cwd=str(temp_dir),
            env=[("MY_VAR", "test_value")],
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == b"test_value"

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

    def test_write_file_in_sandbox(self, base_caps, temp_dir):
        """Can write files to allowed paths."""
        result = sandboxed_exec(
            base_caps,
            ["bash", "-c", "echo 'sandboxed' > test.txt && cat test.txt"],
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
