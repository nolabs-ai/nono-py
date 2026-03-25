"""Tests for CapabilitySet class."""

import os
import tempfile

import pytest

from nono_py import AccessMode, CapabilitySet


class TestCapabilitySetCreation:
    """Tests for CapabilitySet creation."""

    def test_new_empty(self) -> None:
        """Test creating an empty capability set."""
        caps = CapabilitySet()
        assert caps.fs_capabilities() == []
        assert not caps.is_network_blocked

    def test_repr(self) -> None:
        """Test string representation."""
        caps = CapabilitySet()
        assert "CapabilitySet" in repr(caps)
        assert "fs=0" in repr(caps)
        assert "network=allowed" in repr(caps)


class TestCapabilitySetPaths:
    """Tests for path-related methods."""

    def test_allow_path_valid_directory(self) -> None:
        """Test allowing access to a valid directory."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)

        fs_caps = caps.fs_capabilities()
        assert len(fs_caps) == 1
        assert fs_caps[0].access == AccessMode.READ
        assert not fs_caps[0].is_file

    def test_allow_path_nonexistent_raises(self) -> None:
        """Test that allowing a nonexistent path raises FileNotFoundError."""
        caps = CapabilitySet()
        with pytest.raises(FileNotFoundError):
            caps.allow_path("/nonexistent/path/that/does/not/exist", AccessMode.READ)

    def test_allow_file_valid_file(self) -> None:
        """Test allowing access to a valid file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            caps = CapabilitySet()
            caps.allow_file(temp_path, AccessMode.READ_WRITE)

            fs_caps = caps.fs_capabilities()
            assert len(fs_caps) == 1
            assert fs_caps[0].access == AccessMode.READ_WRITE
            assert fs_caps[0].is_file
        finally:
            os.unlink(temp_path)

    def test_allow_file_nonexistent_raises(self) -> None:
        """Test that allowing a nonexistent file raises FileNotFoundError."""
        caps = CapabilitySet()
        with pytest.raises(FileNotFoundError):
            caps.allow_file("/nonexistent/file.txt", AccessMode.READ)

    def test_allow_file_on_directory_raises(self) -> None:
        """Test that allow_file on a directory raises ValueError."""
        caps = CapabilitySet()
        with pytest.raises(ValueError):
            caps.allow_file("/tmp", AccessMode.READ)

    def test_allow_path_on_file_raises(self) -> None:
        """Test that allow_path on a file raises ValueError."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            caps = CapabilitySet()
            with pytest.raises(ValueError):
                caps.allow_path(temp_path, AccessMode.READ)
        finally:
            os.unlink(temp_path)

    def test_path_covered(self) -> None:
        """Test path_covered method."""
        # Use a temp directory to avoid symlink issues (e.g., /tmp -> /private/tmp on macOS)
        with tempfile.TemporaryDirectory() as tmpdir:
            caps = CapabilitySet()
            caps.allow_path(tmpdir, AccessMode.READ)

            # Get the resolved path from the capability
            resolved = caps.fs_capabilities()[0].resolved

            # The resolved path itself should be covered
            assert caps.path_covered(resolved)
            # A subdirectory should be covered
            assert caps.path_covered(os.path.join(resolved, "subdir"))
            # An unrelated path should not be covered
            assert not caps.path_covered("/var")

    def test_multiple_paths(self) -> None:
        """Test adding multiple paths."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)
        caps.allow_path("/var", AccessMode.WRITE)

        assert len(caps.fs_capabilities()) == 2


class TestCapabilitySetNetwork:
    """Tests for network-related methods."""

    def test_network_not_blocked_by_default(self) -> None:
        """Test that network is allowed by default."""
        caps = CapabilitySet()
        assert not caps.is_network_blocked

    def test_block_network(self) -> None:
        """Test blocking network access."""
        caps = CapabilitySet()
        caps.block_network()
        assert caps.is_network_blocked

    def test_repr_shows_blocked_network(self) -> None:
        """Test repr shows network status."""
        caps = CapabilitySet()
        caps.block_network()
        assert "network=blocked" in repr(caps)


class TestCapabilitySetDeduplicate:
    """Tests for deduplicate method."""

    def test_deduplicate_removes_duplicates(self) -> None:
        """Test that deduplicate removes duplicate paths."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)
        caps.allow_path("/tmp", AccessMode.WRITE)

        assert len(caps.fs_capabilities()) == 2

        caps.deduplicate()

        # After dedup, should have one entry with highest access
        assert len(caps.fs_capabilities()) == 1


class TestCapabilitySetSummary:
    """Tests for summary method."""

    def test_summary_empty(self) -> None:
        """Test summary of empty capability set."""
        caps = CapabilitySet()
        summary = caps.summary()
        assert isinstance(summary, str)

    def test_summary_with_paths(self) -> None:
        """Test summary includes path info."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)
        summary = caps.summary()
        assert "tmp" in summary.lower() or "/tmp" in summary


class TestCapabilitySetPlatformRule:
    """Tests for platform-specific rules."""

    def test_platform_rule_invalid_raises(self) -> None:
        """Test that invalid platform rules raise ValueError."""
        caps = CapabilitySet()
        # An invalid/dangerous rule should be rejected
        with pytest.raises(ValueError):
            caps.platform_rule('(allow file-read* (subpath "/"))')
