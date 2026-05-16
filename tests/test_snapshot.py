"""Tests for snapshot/undo types: ExclusionConfig and SessionMetadata.

SnapshotManager baseline/incremental/restore, ContentHash, Change, and
FileState are covered by test_smoke.py and test_integration_snapshot.py.
This file focuses on the type-level behaviour of ExclusionConfig and
SessionMetadata which have no unit-level coverage elsewhere.
"""

import json

import pytest  # ty:ignore[unresolved-import]  # noqa: F401

from nono_py import (
    ExclusionConfig,
    SessionMetadata,
)


class TestExclusionConfig:
    """Tests for ExclusionConfig defaults and property access."""

    def test_defaults(self) -> None:
        cfg = ExclusionConfig()
        assert cfg.use_gitignore is True
        assert cfg.exclude_patterns == []
        assert cfg.exclude_globs == []
        assert cfg.force_include == []

    def test_custom_values(self) -> None:
        cfg = ExclusionConfig(
            use_gitignore=False,
            exclude_patterns=["node_modules", "__pycache__"],
            exclude_globs=["*.pyc"],
            force_include=["important.dat"],
        )
        assert cfg.use_gitignore is False
        assert cfg.exclude_patterns == ["node_modules", "__pycache__"]
        assert cfg.exclude_globs == ["*.pyc"]
        assert cfg.force_include == ["important.dat"]

    def test_repr(self) -> None:
        cfg = ExclusionConfig(exclude_patterns=["a", "b"])
        r = repr(cfg)
        assert "ExclusionConfig" in r
        assert "patterns=2" in r


class TestSessionMetadata:
    """Tests for SessionMetadata construction, setters, and serialization."""

    def test_construction(self) -> None:
        meta = SessionMetadata(
            session_id="test-123",
            command=["python", "main.py"],
            tracked_paths=["/workspace"],
        )
        assert meta.session_id == "test-123"
        assert meta.command == ["python", "main.py"]
        assert meta.tracked_paths == ["/workspace"]
        assert meta.snapshot_count == 0
        assert meta.exit_code is None
        assert meta.ended is None

    def test_started_auto_populated(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        assert meta.started is not None
        assert len(meta.started) > 0

    def test_setters(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        meta.ended = "2026-01-01T00:01:00Z"
        assert meta.ended == "2026-01-01T00:01:00Z"

        meta.snapshot_count = 5
        assert meta.snapshot_count == 5

        meta.exit_code = 42
        assert meta.exit_code == 42

    def test_exit_code_nullable(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        meta.exit_code = 1
        assert meta.exit_code == 1
        meta.exit_code = None
        assert meta.exit_code is None

    def test_merkle_roots_empty(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        assert meta.merkle_roots == []

    def test_network_events_empty(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        assert meta.network_events == []

    def test_set_network_events(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        events = [
            {
                "timestamp_unix_ms": 1700000000000,
                "mode": "connect",
                "decision": "allow",
                "target": "example.com",
                "port": 443,
                "method": None,
                "path": None,
                "status": None,
                "reason": None,
            }
        ]
        meta.set_network_events(events)
        result = meta.network_events
        assert len(result) == 1
        assert result[0]["target"] == "example.com"

    def test_to_json_roundtrip(self) -> None:
        meta = SessionMetadata(
            session_id="test-rt",
            command=["python", "main.py"],
            tracked_paths=["/workspace"],
        )
        meta.exit_code = 0
        meta.snapshot_count = 2

        json_str = meta.to_json()
        parsed = json.loads(json_str)
        assert parsed["session_id"] == "test-rt"
        assert parsed["exit_code"] == 0
        assert parsed["snapshot_count"] == 2

        restored = SessionMetadata.from_json(json_str)
        assert restored.session_id == "test-rt"
        assert restored.exit_code == 0
        assert restored.snapshot_count == 2

    def test_from_json_invalid_raises(self) -> None:
        with pytest.raises((ValueError, Exception)):
            SessionMetadata.from_json("not valid json")

    def test_executable_identity_none_by_default(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        assert meta.executable_identity is None

    def test_audit_event_count(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        assert meta.audit_event_count == 0

    def test_audit_integrity_none_by_default(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        assert meta.audit_integrity is None

    def test_audit_attestation_none_by_default(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        assert meta.audit_attestation is None

    def test_repr(self) -> None:
        meta = SessionMetadata(session_id="s", command=["echo"], tracked_paths=["/tmp"])
        r = repr(meta)
        assert "SessionMetadata" in r
        assert "s" in r
