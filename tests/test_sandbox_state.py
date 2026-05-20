"""Tests for SandboxState class."""

import json
import os
import tempfile

import pytest  # ty:ignore[unresolved-import]  # noqa: F401

from nono_py import AccessMode, CapabilitySet, SandboxState


class TestSandboxStateCreation:
    """Tests for SandboxState creation."""

    def test_from_caps_empty(self) -> None:
        """Test creating state from empty capability set."""
        caps = CapabilitySet()
        state = SandboxState.from_caps(caps)
        assert not state.net_blocked

    def test_from_caps_with_network_blocked(self) -> None:
        """Test creating state from caps with network blocked."""
        caps = CapabilitySet()
        caps.block_network()
        state = SandboxState.from_caps(caps)
        assert state.net_blocked

    def test_repr(self) -> None:
        """Test string representation."""
        caps = CapabilitySet()
        state = SandboxState.from_caps(caps)
        assert "SandboxState" in repr(state)


class TestSandboxStateSerialization:
    """Tests for JSON serialization."""

    def test_to_json_empty(self) -> None:
        """Test serializing empty state to JSON."""
        caps = CapabilitySet()
        state = SandboxState.from_caps(caps)
        json_str = state.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_to_json_with_paths(self) -> None:
        """Test serializing state with paths."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108
        state = SandboxState.from_caps(caps)
        json_str = state.to_json()

        parsed = json.loads(json_str)
        assert "fs" in parsed
        assert len(parsed["fs"]) == 1

    def test_from_json_valid(self) -> None:
        """Test deserializing valid JSON."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108
        caps.block_network()
        original_state = SandboxState.from_caps(caps)
        json_str = original_state.to_json()

        restored_state = SandboxState.from_json(json_str)
        assert restored_state.net_blocked == original_state.net_blocked

    def test_from_json_invalid_raises(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError):
            SandboxState.from_json("not valid json")

    def test_from_json_empty_object(self) -> None:
        """Test deserializing empty object."""
        # Empty object should work with defaults
        with pytest.raises(ValueError):
            SandboxState.from_json("{}")


class TestSandboxStateRoundTrip:
    """Tests for round-trip serialization."""

    def test_roundtrip_empty(self) -> None:
        """Test round-trip with empty caps."""
        caps = CapabilitySet()
        state = SandboxState.from_caps(caps)
        json_str = state.to_json()
        restored = SandboxState.from_json(json_str)
        restored_caps = restored.to_caps()

        assert restored_caps.is_network_blocked == caps.is_network_blocked
        assert len(restored_caps.fs_capabilities()) == len(caps.fs_capabilities())

    def test_roundtrip_with_paths(self) -> None:
        """Test round-trip with paths (paths must still exist)."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ_WRITE)  # noqa: S108
        caps.block_network()

        state = SandboxState.from_caps(caps)
        json_str = state.to_json()
        restored = SandboxState.from_json(json_str)
        restored_caps = restored.to_caps()

        assert restored_caps.is_network_blocked
        assert len(restored_caps.fs_capabilities()) == 1

    def test_to_caps_missing_path_raises(self) -> None:
        """Test that to_caps raises if path no longer exists."""
        # Create a temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        # Create state with the temp file
        caps = CapabilitySet()
        caps.allow_file(temp_path, AccessMode.READ)
        state = SandboxState.from_caps(caps)
        json_str = state.to_json()

        # Delete the file
        os.unlink(temp_path)

        # Restore state and try to convert to caps
        restored = SandboxState.from_json(json_str)
        with pytest.raises(FileNotFoundError):
            restored.to_caps()
