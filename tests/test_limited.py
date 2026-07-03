"""Tests for nono_py.limited — the CLI-driver for resource-limited runs.

The flag-translation, memory-formatting, argv-building, and binary-discovery
logic is tested deterministically without needing the ``nono`` binary. The
end-to-end enforcement test is skipped unless a ``nono`` binary is present on a
Linux host with working cgroup v2 delegation.
"""

from __future__ import annotations

import shutil
import sys

import pytest  # ty:ignore[unresolved-import]
from utils import add_system_paths

from nono_py import AccessMode, CapabilitySet, limited


class TestFormatMemory:
    """Normalization of the memory argument into a nono size string."""

    def test_none_is_none(self) -> None:
        assert limited._format_memory(None) is None

    def test_int_is_rendered_as_bytes(self) -> None:
        # nono parses a bare number as bytes.
        assert limited._format_memory(1048576) == "1048576"

    def test_str_passes_through(self) -> None:
        assert limited._format_memory("512M") == "512M"

    def test_str_is_stripped(self) -> None:
        assert limited._format_memory("  1Gi  ") == "1Gi"

    def test_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            limited._format_memory(0)

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError):
            limited._format_memory(-1)

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            limited._format_memory("   ")

    def test_bool_raises(self) -> None:
        # bool is an int subclass; a True/False memory limit is a bug, not 1/0.
        with pytest.raises(TypeError):
            limited._format_memory(True)


class TestCapsToFlags:
    """Translation of a CapabilitySet into nono run flags."""

    def test_empty_set_has_no_flags(self) -> None:
        assert limited.caps_to_flags(CapabilitySet()) == []

    def test_dir_read_write(self, temp_dir) -> None:
        caps = CapabilitySet()
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        resolved = caps.fs_capabilities()[0].resolved
        assert limited.caps_to_flags(caps) == ["--allow", resolved]

    def test_dir_read_only(self, temp_dir) -> None:
        caps = CapabilitySet()
        caps.allow_path(str(temp_dir), AccessMode.READ)
        resolved = caps.fs_capabilities()[0].resolved
        assert limited.caps_to_flags(caps) == ["--read", resolved]

    def test_dir_write_only(self, temp_dir) -> None:
        caps = CapabilitySet()
        caps.allow_path(str(temp_dir), AccessMode.WRITE)
        resolved = caps.fs_capabilities()[0].resolved
        assert limited.caps_to_flags(caps) == ["--write", resolved]

    def test_file_read_write(self, temp_file) -> None:
        caps = CapabilitySet()
        caps.allow_file(str(temp_file), AccessMode.READ_WRITE)
        resolved = caps.fs_capabilities()[0].resolved
        assert limited.caps_to_flags(caps) == ["--allow-file", resolved]

    def test_file_read_only(self, temp_file) -> None:
        caps = CapabilitySet()
        caps.allow_file(str(temp_file), AccessMode.READ)
        resolved = caps.fs_capabilities()[0].resolved
        assert limited.caps_to_flags(caps) == ["--read-file", resolved]

    def test_file_write_only(self, temp_file) -> None:
        caps = CapabilitySet()
        caps.allow_file(str(temp_file), AccessMode.WRITE)
        resolved = caps.fs_capabilities()[0].resolved
        assert limited.caps_to_flags(caps) == ["--write-file", resolved]

    def test_block_network_appends_flag(self, temp_dir) -> None:
        caps = CapabilitySet()
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        caps.block_network()
        assert limited.caps_to_flags(caps)[-1] == "--block-net"


class TestBuildArgv:
    """Assembly of the full nono run command line."""

    def _caps(self, temp_dir) -> CapabilitySet:
        caps = CapabilitySet()
        caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)
        return caps

    def test_structure(self, temp_dir) -> None:
        argv = limited.build_argv(
            self._caps(temp_dir),
            ["echo", "hi"],
            memory="256M",
            nono_bin=sys.executable,
        )
        assert argv[0] == shutil.which(sys.executable)
        assert argv[1] == "run"
        assert argv[argv.index("--memory") + 1] == "256M"
        sep = argv.index("--")
        assert argv[sep + 1 :] == ["echo", "hi"]

    def test_int_memory_is_bytes(self, temp_dir) -> None:
        argv = limited.build_argv(
            self._caps(temp_dir), ["true"], memory=2097152, nono_bin=sys.executable
        )
        assert argv[argv.index("--memory") + 1] == "2097152"

    def test_no_memory_omits_flag(self, temp_dir) -> None:
        argv = limited.build_argv(self._caps(temp_dir), ["true"], nono_bin=sys.executable)
        assert "--memory" not in argv

    def test_empty_command_raises(self, temp_dir) -> None:
        with pytest.raises(ValueError):
            limited.build_argv(self._caps(temp_dir), [], nono_bin=sys.executable)

    def test_flags_precede_separator(self, temp_dir) -> None:
        caps = self._caps(temp_dir)
        caps.block_network()
        argv = limited.build_argv(caps, ["prog"], memory="64M", nono_bin=sys.executable)
        sep = argv.index("--")
        assert "--block-net" in argv[:sep]
        assert "--memory" in argv[:sep]


class TestFindNonoBinary:
    """Binary discovery precedence: explicit, then NONO_BIN, then PATH."""

    def test_explicit_absolute_path(self) -> None:
        assert limited.find_nono_binary(sys.executable) == shutil.which(sys.executable)

    def test_explicit_missing_raises(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            limited.find_nono_binary(tmp_path / "definitely-not-here")

    def test_env_var_used(self, monkeypatch) -> None:
        monkeypatch.setenv("NONO_BIN", sys.executable)
        assert limited.find_nono_binary() == shutil.which(sys.executable)

    def test_missing_everywhere_raises(self, monkeypatch) -> None:
        monkeypatch.delenv("NONO_BIN", raising=False)
        monkeypatch.setenv("PATH", "")
        with pytest.raises(FileNotFoundError):
            limited.find_nono_binary()


@pytest.mark.skipif(sys.platform != "linux", reason="cgroup memory limiting is Linux-only")
def test_end_to_end_run_under_cap(temp_dir) -> None:
    """A trivial command runs to completion under a generous memory cap.

    Skips if the host can't actually enforce (no cgroup v2 delegation): nono
    fails closed there, and that failure is about the environment, not the code.
    """
    try:
        limited.find_nono_binary()
    except FileNotFoundError:
        pytest.skip("nono binary not available in this environment")

    caps = CapabilitySet()
    add_system_paths(caps)
    caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)

    result = limited.run(caps, ["true"], memory="128M", cwd=str(temp_dir))

    stderr = (result.stderr or "") if isinstance(result.stderr, str) else ""
    if not result.ok and ("cgroup" in stderr.lower() or "resource" in stderr.lower()):
        pytest.skip(f"resource enforcement unavailable here: {stderr!r}")
    assert result.ok, stderr
