"""Tests for the audit module: event builders and approval helpers.

AlphaRecorder, iter_session, tail_session, and verify_log are covered
by test_smoke.py and test_integration_audit.py. This file focuses on
the builder functions and approval decision helpers which have no
coverage elsewhere.
"""

import json
from pathlib import Path
from typing import Any

import pytest  # ty:ignore[unresolved-import]  # noqa: F401
from pydantic import ValidationError

from nono_py.audit import (
    AlphaRecorder,
    VerificationError,
    approval_denied,
    approval_granted,
    approval_timeout,
    build_inclusion_proof,
    build_ledger_record,
    capability_decision,
    compute_session_digest,
    network,
    session_ended,
    session_started,
    url_open,
    validate_ledger_session_id,
    verify_inclusion_proof,
    verify_session_in_ledger,
)

_AUDIT_VECTOR_PATH = Path(__file__).parent / "fixtures" / "audit_alpha_vectors.json"


def _audit_vectors() -> dict[str, Any]:
    return json.loads(_AUDIT_VECTOR_PATH.read_text(encoding="utf-8"))


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

    def test_session_started_redaction_policy_omits_empty_fields(self) -> None:
        event = session_started(
            started="2026-01-01T00:00:00Z",
            command=["curl"],
            redaction_policy={
                "added_flags": ["--private-token"],
                "removed_query_keys": ["state"],
            },
        )
        assert event["redaction_policy"] == {
            "added_flags": ["--private-token"],
            "removed_query_keys": ["state"],
        }

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

    def test_network_event_current_rust_fields(self) -> None:
        event = network(
            timestamp_unix_ms=1700000000000,
            mode="connect_intercept",
            decision="deny",
            target="api.example.com",
            route_id="openai",
            auth_mechanism="phantom_header",
            auth_outcome="failed",
            managed_credential_active=True,
            injection_mode="header",
            denial_category="authentication_failed",
            port=443,
        )
        inner = event["event"]
        assert inner["mode"] == "connect_intercept"
        assert inner["route_id"] == "openai"
        assert inner["auth_mechanism"] == "phantom_header"
        assert inner["auth_outcome"] == "failed"
        assert inner["managed_credential_active"] is True
        assert inner["injection_mode"] == "header"
        assert inner["denial_category"] == "authentication_failed"

    def test_network_event_omits_rust_skip_none_fields(self) -> None:
        event = network(
            timestamp_unix_ms=1700000000000,
            mode="connect",
            decision="allow",
            target="api.example.com",
        )
        inner = event["event"]
        assert "route_id" not in inner
        assert "auth_mechanism" not in inner
        assert "denial_category" not in inner
        assert inner["port"] is None

    def test_network_rejects_invalid_mode(self) -> None:
        with pytest.raises(ValidationError):
            network(
                timestamp_unix_ms=1700000000000,
                mode="raw",
                decision="allow",
                target="api.example.com",
            )

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
            path="/tmp/foo",  # noqa: S108
            access="Read",
            child_pid=1234,
            session_id="abc",
            decision=approval_granted(),
            backend="always-allow",
            duration_ms=5,
        )
        assert event["type"] == "capability_decision"
        path = event["entry"]["request"].get("path")
        assert path == "/tmp/foo"  # noqa: S108
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
            path="/tmp",  # noqa: S108
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
            path="/tmp",  # noqa: S108
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

    def test_capability_decision_rejects_invalid_access(self) -> None:
        with pytest.raises(ValidationError):
            capability_decision(
                timestamp="t",
                path="/tmp",  # noqa: S108
                access="Execute",
                child_pid=1,
                session_id="s",
                decision=approval_granted(),
                backend="b",
                duration_ms=0,
            )

    def test_recorder_accepts_manual_capability_request_without_reason(self) -> None:
        event = {
            "type": "capability_decision",
            "entry": {
                "timestamp": "t",
                "request": {
                    "request_id": "r",
                    "path": "/tmp",  # noqa: S108
                    "access": "Read",
                    "child_pid": 1,
                    "session_id": "s",
                },
                "decision": "Granted",
                "backend": "b",
                "duration_ms": 0,
            },
        }

        record = AlphaRecorder().record(event)

        request = record["event"]["entry"]["request"]
        assert request["reason"] is None


class TestApprovalHelpers:
    """Tests for approval decision helpers."""

    def test_approval_granted(self) -> None:
        assert approval_granted() == "Granted"

    def test_approval_timeout(self) -> None:
        assert approval_timeout() == "Timeout"

    def test_approval_denied(self) -> None:
        result = approval_denied("forbidden")
        assert result == {"Denied": {"reason": "forbidden"}}


class TestInclusionProofs:
    """Tests for alpha Merkle inclusion proofs."""

    def test_inclusion_proof_round_trips_each_leaf(self) -> None:
        leaves = [
            "01" * 32,
            "02" * 32,
            "03" * 32,
            "04" * 32,
            "05" * 32,
        ]

        roots = set()
        for index, leaf in enumerate(leaves):
            proof = build_inclusion_proof(leaves, index)
            roots.add(proof["merkle_root"])
            assert proof["leaf_hash"] == leaf
            assert verify_inclusion_proof(proof) is True

        assert len(roots) == 1

    def test_inclusion_proof_rejects_tampered_leaf(self) -> None:
        proof = build_inclusion_proof(["01" * 32, "02" * 32, "03" * 32], 1)
        proof["leaf_hash"] = "09" * 32

        assert verify_inclusion_proof(proof) is False

    def test_inclusion_proof_checks_expected_root(self) -> None:
        proof = build_inclusion_proof(["01" * 32, "02" * 32, "03" * 32], 1)

        assert verify_inclusion_proof(proof, expected_root=proof["merkle_root"]) is True
        assert verify_inclusion_proof(proof, expected_root="0a" * 32) is False

    def test_self_consistent_proof_fails_against_trusted_root(self) -> None:
        # Internally consistent but rooted in itself — must not verify
        # against the real root.
        real = build_inclusion_proof(["01" * 32, "02" * 32], 0)
        forged = {
            "leaf_index": 0,
            "leaf_count": 1,
            "leaf_hash": "ab" * 32,
            "merkle_root": "ab" * 32,
            "siblings": [],
        }

        assert verify_inclusion_proof(forged) is True
        assert verify_inclusion_proof(forged, expected_root=real["merkle_root"]) is False


def _sample_metadata(session_id: str = "20260421-200000-11111") -> dict[str, object]:
    return {
        "session_id": session_id,
        "started": "2026-04-21T20:00:00Z",
        "ended": "2026-04-21T20:00:01Z",
        "command": ["/bin/pwd"],
        "executable_identity": None,
        "tracked_paths": ["/tmp/work"],  # noqa: S108
        "snapshot_count": 0,
        "exit_code": 0,
        "merkle_roots": [],
        "network_events": [],
        "audit_event_count": 2,
        "audit_integrity": None,
        "audit_attestation": None,
    }


class TestLedger:
    """Tests for alpha audit ledger helpers."""

    def test_session_digest_changes_when_protected_field_changes(self) -> None:
        base = _sample_metadata()
        base_digest = compute_session_digest(base)
        changed = dict(base)
        changed["audit_event_count"] = 3

        assert compute_session_digest(changed) != base_digest

    def test_ledger_record_verifies(self, tmp_path) -> None:
        metadata = _sample_metadata()
        record = build_ledger_record(metadata, sequence=0, previous_chain=None)
        ledger = tmp_path / "ledger.ndjson"
        ledger.write_text(json.dumps(record, separators=(",", ":")) + "\n")

        result = verify_session_in_ledger(ledger, metadata)

        assert result["entry_count"] == 1
        assert result["session_found"] is True
        assert result["session_digest_matches"] is True
        assert result["ledger_chain_verified"] is True
        assert result["ledger_head"] == record["chain_hash"]

    def test_missing_ledger_reports_not_found(self, tmp_path) -> None:
        result = verify_session_in_ledger(tmp_path / "missing.ndjson", _sample_metadata())

        assert result["entry_count"] == 0
        assert result["session_found"] is False
        assert result["ledger_chain_verified"] is False

    def test_ledger_rejects_malformed_session_id(self) -> None:
        with pytest.raises(Exception, match="invalid audit session id"):
            validate_ledger_session_id("real-token\\|real-key")

    def test_ledger_detects_tampered_chain(self, tmp_path) -> None:
        metadata = _sample_metadata()
        record = build_ledger_record(metadata, sequence=0, previous_chain=None)
        record["chain_hash"] = "aa" * 32
        ledger = tmp_path / "ledger.ndjson"
        ledger.write_text(json.dumps(record, separators=(",", ":")) + "\n")

        with pytest.raises(Exception, match="chain hash"):
            verify_session_in_ledger(ledger, metadata)

    def test_ledger_rejects_invalid_json_line(self, tmp_path) -> None:
        ledger = tmp_path / "ledger.ndjson"
        ledger.write_text("{not json\n")

        with pytest.raises(VerificationError, match="not valid JSON"):
            verify_session_in_ledger(ledger, _sample_metadata())

    def test_ledger_reports_physical_line_after_blank_lines(self, tmp_path) -> None:
        ledger = tmp_path / "ledger.ndjson"
        ledger.write_text("\n\n{not json\n")

        with pytest.raises(VerificationError, match="line 3 is not valid JSON"):
            verify_session_in_ledger(ledger, _sample_metadata())

    def test_ledger_rejects_record_missing_fields(self, tmp_path) -> None:
        record = build_ledger_record(_sample_metadata(), sequence=0, previous_chain=None)
        del record["session_id"]
        ledger = tmp_path / "ledger.ndjson"
        ledger.write_text(json.dumps(record) + "\n")

        with pytest.raises(VerificationError, match="missing fields: session_id"):
            verify_session_in_ledger(ledger, _sample_metadata())

    def test_ledger_rejects_non_object_record(self, tmp_path) -> None:
        ledger = tmp_path / "ledger.ndjson"
        ledger.write_text("[1, 2, 3]\n")

        with pytest.raises(VerificationError, match="not a JSON object"):
            verify_session_in_ledger(ledger, _sample_metadata())

    def test_ledger_chain_errors_report_physical_line(self, tmp_path) -> None:
        record = build_ledger_record(_sample_metadata(), sequence=0, previous_chain=None)
        record["chain_hash"] = "aa" * 32
        ledger = tmp_path / "ledger.ndjson"
        ledger.write_text("\n" + json.dumps(record, separators=(",", ":")) + "\n")

        with pytest.raises(VerificationError, match="chain hash mismatch at line 2"):
            verify_session_in_ledger(ledger, _sample_metadata())

    def test_session_digest_rejects_missing_protected_field(self) -> None:
        metadata = _sample_metadata()
        del metadata["audit_event_count"]

        with pytest.raises(Exception, match="missing protected digest fields: audit_event_count"):
            compute_session_digest(metadata)


class TestRustGoldenVectors:
    """Pin the wire format to vectors generated by the Rust core."""

    def test_session_digest_matches_rust(self) -> None:
        vectors = _audit_vectors()
        assert (
            compute_session_digest(vectors["session_metadata"])
            == vectors["ledger"]["session_digest"]
        )

    def test_ledger_chain_hash_matches_rust(self) -> None:
        vectors = _audit_vectors()
        ledger = vectors["ledger"]
        record = build_ledger_record(
            vectors["session_metadata"],
            sequence=ledger["sequence"],
            previous_chain=ledger["previous_chain"],
        )
        assert record == ledger["record"]

    def test_ledger_verification_matches_rust_vector(self, tmp_path: Path) -> None:
        vectors = _audit_vectors()
        ledger = tmp_path / "ledger.ndjson"
        ledger.write_text(
            json.dumps(vectors["ledger"]["record"], separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        result = verify_session_in_ledger(ledger, vectors["session_metadata"])

        assert result["entry_count"] == 1
        assert result["session_found"] is True
        assert result["session_digest_matches"] is True
        assert result["ledger_chain_verified"] is True
        assert result["ledger_head"] == vectors["ledger"]["record"]["chain_hash"]

    def test_inclusion_proof_matches_rust(self) -> None:
        vectors = _audit_vectors()
        proof_vector = vectors["inclusion_proof"]
        assert (
            build_inclusion_proof(proof_vector["leaf_hashes"], proof_vector["leaf_index"])
            == proof_vector["proof"]
        )

    def test_rust_built_proof_verifies(self) -> None:
        vectors = _audit_vectors()
        assert verify_inclusion_proof(vectors["inclusion_proof"]["proof"]) is True
