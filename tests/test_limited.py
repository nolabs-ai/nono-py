"""Tests for nono_py.limited — the CLI-driver for resource-limited runs.

The flag-translation, memory-formatting, argv-building, and binary-discovery
logic is tested deterministically without needing the ``nono`` binary. The
end-to-end enforcement tests are skipped unless a ``--memory``-capable ``nono``
binary is present on a Linux host with working cgroup v2 delegation.
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

    def test_rw_dir_with_comma_raises(self, tmp_path) -> None:
        # nono's --allow flag splits on commas, so a read+write directory whose
        # path contains one would be silently mis-granted. Fail loudly instead.
        comma_dir = tmp_path / "has,comma"
        comma_dir.mkdir()
        caps = CapabilitySet()
        caps.allow_path(str(comma_dir), AccessMode.READ_WRITE)
        with pytest.raises(ValueError, match="comma"):
            limited.caps_to_flags(caps)

    def test_read_only_dir_with_comma_is_fine(self, tmp_path) -> None:
        # Only --allow carries the comma delimiter; --read/--write do not, so a
        # read-only grant on the same path must not raise.
        comma_dir = tmp_path / "has,comma"
        comma_dir.mkdir()
        caps = CapabilitySet()
        caps.allow_path(str(comma_dir), AccessMode.READ)
        resolved = caps.fs_capabilities()[0].resolved
        assert limited.caps_to_flags(caps) == ["--read", resolved]


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


def _require_nono() -> None:
    """Skip if there is no nono binary to drive."""
    try:
        limited.find_nono_binary()
    except FileNotFoundError:
        pytest.skip("nono binary not available in this environment")


def _skip_if_cannot_enforce(stderr: str) -> None:
    """Skip on nono's markers for a host or binary that cannot enforce --memory.

    Fail-closed enforcement errors all carry a literal "resource:" prefix.
    Matching the bare word would be wrong: nono prints a "resources memory=..."
    capability banner on stderr for every --memory run, which would turn
    unrelated failures into skips. Binaries that predate resource limiting
    reject the flag itself.
    """
    if "unexpected argument '--memory'" in stderr:
        pytest.skip("nono binary predates resource limiting (no --memory flag)")
    if "resource:" in stderr:
        pytest.skip(f"resource enforcement unavailable here: {stderr!r}")


@pytest.mark.skipif(sys.platform != "linux", reason="cgroup memory limiting is Linux-only")
def test_end_to_end_run_under_cap(temp_dir) -> None:
    """A trivial command runs to completion under a generous memory cap.

    Skips wherever the cap cannot be enforced: nono fails closed there, and
    that failure is about the environment, not this code.
    """
    _require_nono()

    caps = CapabilitySet()
    add_system_paths(caps)
    caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)

    result = limited.run(caps, ["true"], memory="128M", cwd=str(temp_dir), timeout=120)

    stderr = result.stderr if isinstance(result.stderr, str) else ""
    if not result.ok:
        _skip_if_cannot_enforce(stderr)
    assert result.ok, f"expected a clean exit, got returncode={result.returncode} stderr={stderr!r}"


@pytest.mark.skipif(sys.platform != "linux", reason="cgroup memory limiting is Linux-only")
def test_end_to_end_oom_kill_over_cap(temp_dir) -> None:
    """A command that allocates far past its cap is OOM-killed (exit 137).

    Counterpart to test_end_to_end_run_under_cap: that test proves a compliant
    command is unaffected by its cap, this one proves the cap actually kills.
    """
    _require_nono()

    caps = CapabilitySet()
    add_system_paths(caps)
    caps.allow_path(str(temp_dir), AccessMode.READ_WRITE)

    # bytearray(n) zero-fills, so all 256 MiB really get committed against the
    # 32M cap (nono disables swap) and the kernel must kill the tree. Bounded
    # on purpose: were the cap silently unenforced, this exits 0 and fails
    # below, whereas an unbounded hog would balloon until a host-level OOM
    # kill forged the expected 137. The timeout only guards a hung supervisor
    # — the kill itself is near-instant.
    hog = "a = bytearray(256 * 1024 * 1024)"
    result = limited.run(
        caps, [sys.executable, "-c", hog], memory="32M", cwd=str(temp_dir), timeout=120
    )

    stderr = result.stderr if isinstance(result.stderr, str) else ""
    if not result.oom_killed and not result.ok:
        # Exit 137 already answers the question; a kill that worked must never
        # be reported as "enforcement unavailable".
        _skip_if_cannot_enforce(stderr)
    assert result.oom_killed, (
        f"expected the hog to be OOM-killed (exit {limited.OOM_EXIT_CODE}), got "
        f"returncode={result.returncode} stdout={result.stdout!r} stderr={stderr!r}"
    )
