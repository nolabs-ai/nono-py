"""Tests for the audit module: event builders and approval helpers.

AlphaRecorder, iter_session, tail_session, and verify_log are covered
by test_smoke.py and test_integration_audit.py. This file focuses on
the builder functions and approval decision helpers which have no
coverage elsewhere.
"""

import pytest  # ty:ignore[unresolved-import]  # noqa: F401

from nono_py.audit import (
    approval_denied,
    approval_granted,
    approval_timeout,
    capability_decision,
    network,
    session_ended,
    session_started,
    url_open,
)


class TestEventBuilders:
    """Tests for event builder functions."""

    def test_session_started(self) -> None:
        event = session_started(started="2026-01-01T00:00:00Z", command=["python", "main.py"])
        assert event["type"] == "session_started"
        assert event["started"] == "2026-01-01T00:00:00Z"
        assert event["command"] == ["python", "main.py"]

    def test_session_started_copies_command(self) -> None:
        cmd = ["python", "main.py"]
        event = session_started(started="2026-01-01T00:00:00Z", command=cmd)
        cmd.append("--flag")
        assert len(event["command"]) == 2

    def test_session_ended(self) -> None:
        event = session_ended(ended="2026-01-01T00:01:00Z", exit_code=0)
        assert event["type"] == "session_ended"
        assert event["ended"] == "2026-01-01T00:01:00Z"
        assert event["exit_code"] == 0

    def test_session_ended_nonzero(self) -> None:
        event = session_ended(ended="2026-01-01T00:01:00Z", exit_code=1)
        assert event["exit_code"] == 1

    def test_network_event(self) -> None:
        event = network(
            timestamp_unix_ms=1700000000000,
            mode="connect",
            decision="allow",
            target="api.example.com",
            port=443,
        )
        assert event["type"] == "network"
        assert event["event"]["mode"] == "connect"
        assert event["event"]["decision"] == "allow"
        assert event["event"]["target"] == "api.example.com"
        assert event["event"]["port"] == 443
        assert event["event"]["method"] is None

    def test_network_event_with_reverse_fields(self) -> None:
        event = network(
            timestamp_unix_ms=1700000000000,
            mode="reverse",
            decision="allow",
            target="api.example.com",
            method="POST",
            path="/v1/chat",
            status=200,
        )
        assert event["event"]["method"] == "POST"
        assert event["event"]["path"] == "/v1/chat"
        assert event["event"]["status"] == 200

    def test_network_event_deny_with_reason(self) -> None:
        event = network(
            timestamp_unix_ms=1700000000000,
            mode="connect",
            decision="deny",
            target="evil.com",
            reason="host not in allowlist",
        )
        assert event["event"]["decision"] == "deny"
        assert event["event"]["reason"] == "host not in allowlist"

    def test_url_open_success(self) -> None:
        event = url_open(
            url="https://example.com",
            child_pid=1234,
            session_id="abc",
            success=True,
        )
        assert event["type"] == "url_open"
        assert event["request"]["url"] == "https://example.com"
        assert event["success"] is True
        assert event["error"] is None
        assert len(event["request"]["request_id"]) == 32

    def test_url_open_failure(self) -> None:
        event = url_open(
            url="https://example.com",
            child_pid=1234,
            session_id="abc",
            success=False,
            error="blocked",
        )
        assert event["success"] is False
        assert event["error"] == "blocked"

    def test_url_open_custom_request_id(self) -> None:
        event = url_open(
            url="https://example.com",
            child_pid=1,
            session_id="s",
            success=True,
            request_id="custom-id",
        )
        assert event["request"]["request_id"] == "custom-id"

    def test_capability_decision_granted(self) -> None:
        event = capability_decision(
            timestamp="2026-01-01T00:00:00Z",
            path="/tmp/foo",
            access="Read",
            child_pid=1234,
            session_id="abc",
            decision=approval_granted(),
            backend="always-allow",
            duration_ms=5,
        )
        assert event["type"] == "capability_decision"
        path = event["entry"]["request"].get("path")
        assert path == "/tmp/foo"
        assert event["entry"]["decision"] == "Granted"
        assert event["entry"]["duration_ms"] == 5

    def test_capability_decision_denied(self) -> None:
        event = capability_decision(
            timestamp="2026-01-01T00:00:00Z",
            path="/etc/passwd",
            access="Write",
            child_pid=1,
            session_id="s",
            decision=approval_denied("not allowed"),
            backend="policy",
            duration_ms=0,
        )
        assert event["entry"]["decision"] == {"Denied": {"reason": "not allowed"}}

    def test_capability_decision_timeout(self) -> None:
        event = capability_decision(
            timestamp="2026-01-01T00:00:00Z",
            path="/tmp",
            access="Read",
            child_pid=1,
            session_id="s",
            decision=approval_timeout(),
            backend="interactive",
            duration_ms=30000,
        )
        assert event["entry"]["decision"] == "Timeout"

    def test_capability_decision_default_request_id(self) -> None:
        event = capability_decision(
            timestamp="t",
            path="/tmp",
            access="Read",
            child_pid=1,
            session_id="s",
            decision=approval_granted(),
            backend="b",
            duration_ms=0,
        )
        request_id = event["entry"]["request"].get("request_id")
        assert request_id is not None
        assert len(request_id) == 32


class TestApprovalHelpers:
    """Tests for approval decision helpers."""

    def test_approval_granted(self) -> None:
        assert approval_granted() == "Granted"

    def test_approval_timeout(self) -> None:
        assert approval_timeout() == "Timeout"

    def test_approval_denied(self) -> None:
        result = approval_denied("forbidden")
        assert result == {"Denied": {"reason": "forbidden"}}
