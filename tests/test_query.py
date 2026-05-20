"""Tests for QueryContext class."""

import os
import tempfile

import pytest  # ty:ignore[unresolved-import]  # noqa: F401

from nono_py import AccessMode, CapabilitySet, QueryContext


class TestQueryContextCreation:
    """Tests for QueryContext creation."""

    def test_create_from_caps(self) -> None:
        """Test creating a query context from capabilities."""
        caps = CapabilitySet()
        ctx = QueryContext(caps)
        assert ctx is not None


class TestQueryContextPathQueries:
    """Tests for path queries."""

    def test_query_allowed_path(self) -> None:
        """Test querying an allowed path."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108
        ctx = QueryContext(caps)

        result = ctx.query_path("/tmp/somefile", AccessMode.READ)  # noqa: S108
        assert result["status"] == "allowed"
        assert result["reason"] == "granted_path"
        assert "granted_path" in result

    def test_query_denied_path(self) -> None:
        """Test querying a denied path."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108
        ctx = QueryContext(caps)

        result = ctx.query_path("/var/log/test", AccessMode.READ)
        assert result["status"] == "denied"
        assert result["reason"] == "path_not_granted"

    def test_query_insufficient_access(self) -> None:
        """Test querying with insufficient access level."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108
        ctx = QueryContext(caps)

        result = ctx.query_path("/tmp/somefile", AccessMode.WRITE)  # noqa: S108
        assert result["status"] == "denied"
        assert result["reason"] == "insufficient_access"
        assert "granted" in result
        assert "requested" in result

    def test_query_read_write_covers_read(self) -> None:
        """Test that READ_WRITE access covers READ requests."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ_WRITE)  # noqa: S108
        ctx = QueryContext(caps)

        result = ctx.query_path("/tmp/file", AccessMode.READ)  # noqa: S108
        assert result["status"] == "allowed"

    def test_query_read_write_covers_write(self) -> None:
        """Test that READ_WRITE access covers WRITE requests."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ_WRITE)  # noqa: S108
        ctx = QueryContext(caps)

        result = ctx.query_path("/tmp/file", AccessMode.WRITE)  # noqa: S108
        assert result["status"] == "allowed"

    def test_query_file_capability(self) -> None:
        """Test querying against a file capability."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            caps = CapabilitySet()
            caps.allow_file(temp_path, AccessMode.READ)
            ctx = QueryContext(caps)

            # The exact file should be allowed
            result = ctx.query_path(temp_path, AccessMode.READ)
            assert result["status"] == "allowed"

            # Parent directory should not be covered by file capability
            parent = os.path.dirname(temp_path)
            sibling = os.path.join(parent, "other_file.txt")
            result = ctx.query_path(sibling, AccessMode.READ)
            assert result["status"] == "denied"
        finally:
            os.unlink(temp_path)


class TestQueryContextNetworkQueries:
    """Tests for network queries."""

    def test_query_network_allowed_by_default(self) -> None:
        """Test that network is allowed by default."""
        caps = CapabilitySet()
        ctx = QueryContext(caps)

        result = ctx.query_network()
        assert result["status"] == "allowed"
        assert result["reason"] == "network_allowed"

    def test_query_network_blocked(self) -> None:
        """Test querying blocked network."""
        caps = CapabilitySet()
        caps.block_network()
        ctx = QueryContext(caps)

        result = ctx.query_network()
        assert result["status"] == "denied"
        assert result["reason"] == "network_blocked"


class TestQueryContextIsolation:
    """Tests for query context isolation."""

    def test_context_reflects_caps_at_creation_time(self) -> None:
        """Test that context reflects caps as they were when created."""
        caps = CapabilitySet()
        caps.allow_path("/tmp", AccessMode.READ)  # noqa: S108
        ctx = QueryContext(caps)

        # Modify caps after creating context
        caps.allow_path("/var", AccessMode.READ)

        # Context should still only know about /tmp
        result = ctx.query_path("/var/test", AccessMode.READ)
        # Note: This depends on whether QueryContext clones or references caps
        # Based on the Rust code, it clones, so /var should be denied
        assert result["status"] == "denied"
