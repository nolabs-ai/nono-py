"""Integration tests for the audit module: AlphaRecorder, iter/tail session, verify_log."""

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from nono_py.audit import (
    AUDIT_EVENTS_FILENAME,
    AlphaRecorder,
    VerificationError,
    approval_granted,
    capability_decision,
    iter_session,
    network,
    session_ended,
    session_started,
    tail_session,
    url_open,
    verify_log,
)


def _audit_file(session_dir: Path) -> Path:
    return session_dir / AUDIT_EVENTS_FILENAME


@pytest.mark.integration
class TestAlphaRecorder:
    def test_sequence_advances(self) -> None:
        """sequence increments and chain_head is a 64-char hex after each record."""
        recorder = AlphaRecorder()
        assert recorder.sequence == 0
        assert recorder.chain_head is None

        recorder.record(session_started(started="2024-01-01T00:00:00Z", command=["a"]))
        assert recorder.sequence == 1
        assert recorder.chain_head is not None
        assert len(recorder.chain_head) == 64

        recorder.record(session_ended(ended="2024-01-01T00:00:01Z", exit_code=0))
        recorder.record(session_ended(ended="2024-01-01T00:00:02Z", exit_code=1))
        assert recorder.sequence == 3

    def test_prev_chain_links_records(self) -> None:
        """Each record's prev_chain matches the previous record's chain_hash."""
        recorder = AlphaRecorder()
        r0 = recorder.record(session_started(started="2024-01-01T00:00:00Z", command=["a"]))
        r1 = recorder.record(session_ended(ended="2024-01-01T00:00:01Z", exit_code=0))
        assert r0["prev_chain"] is None
        assert r1["prev_chain"] == r0["chain_hash"]


@pytest.mark.integration
class TestIterSession:
    def test_full_session_roundtrip(self, session_dir: Path) -> None:
        """Write three records, read them back in order, verify integrity."""
        recorder = AlphaRecorder()
        with _audit_file(session_dir).open("w") as fh:
            recorder.write(fh, session_started(started="2024-01-01T00:00:00Z", command=["pytest"]))
            recorder.write(
                fh,
                capability_decision(
                    timestamp="2024-01-01T00:00:00.001Z",
                    path="/tmp/file.txt",  # noqa: S108
                    access="Read",
                    child_pid=1234,
                    session_id="test-session",
                    decision=approval_granted(),
                    backend="inline",
                    duration_ms=1,
                ),
            )
            recorder.write(fh, session_ended(ended="2024-01-01T00:00:01Z", exit_code=0))

        records = list(iter_session(session_dir))
        assert len(records) == 3
        assert records[0]["event"]["type"] == "session_started"
        assert records[1]["event"]["type"] == "capability_decision"
        assert records[2]["event"]["type"] == "session_ended"
        assert records[0]["sequence"] == 0
        assert records[2]["sequence"] == 2

        result = verify_log(session_dir)
        assert result["records_verified"] is True
        assert result["event_count"] == 3

    def test_all_event_types(self, session_dir: Path) -> None:
        """All five event variants pass verification and are readable."""
        recorder = AlphaRecorder()
        with _audit_file(session_dir).open("w") as fh:
            recorder.write(fh, session_started(started="2024-01-01T00:00:00Z", command=["test"]))
            recorder.write(
                fh,
                capability_decision(
                    timestamp="2024-01-01T00:00:00.001Z",
                    path="/tmp/f.txt",  # noqa: S108
                    access="Read",
                    child_pid=42,
                    session_id="s1",
                    decision=approval_granted(),
                    backend="inline",
                    duration_ms=0,
                ),
            )
            recorder.write(
                fh,
                url_open(
                    url="https://example.com",
                    child_pid=42,
                    session_id="s1",
                    success=True,
                ),
            )
            recorder.write(
                fh,
                network(
                    timestamp_unix_ms=1_000_000,
                    mode="connect",
                    decision="allow",
                    target="example.com",
                    port=443,
                ),
            )
            recorder.write(fh, session_ended(ended="2024-01-01T00:00:01Z", exit_code=0))

        result = verify_log(session_dir)
        assert result["event_count"] == 5
        assert result["records_verified"] is True

        records = list(iter_session(session_dir))
        assert len(records) == 5


@pytest.mark.integration
class TestVerifyLog:
    def test_empty_log(self, session_dir: Path) -> None:
        """An empty NDJSON file verifies successfully with event_count=0."""
        _audit_file(session_dir).write_text("")
        result = verify_log(session_dir)
        assert result["event_count"] == 0
        assert result["records_verified"] is True
        assert result["computed_chain_head"] is None

    def test_stored_summary_cross_check(self, session_dir: Path) -> None:
        """Computed chain_head and merkle_root match when passed as stored summary."""
        recorder = AlphaRecorder()
        with _audit_file(session_dir).open("w") as fh:
            recorder.write(fh, session_started(started="2024-01-01T00:00:00Z", command=["test"]))
            recorder.write(fh, session_ended(ended="2024-01-01T00:00:01Z", exit_code=0))

        first = verify_log(session_dir)
        stored: dict[str, Any] = {
            "hash_algorithm": "sha256",
            "event_count": first["event_count"],
            "chain_head": first["computed_chain_head"],
            "merkle_root": first["computed_merkle_root"],
        }
        second = verify_log(session_dir, stored=stored)
        assert second["event_count_matches"] is True
        assert second["records_verified"] is True

    def test_detects_tampered_sequence(self, session_dir: Path) -> None:
        """A corrupt sequence field raises VerificationError."""
        recorder = AlphaRecorder()
        with _audit_file(session_dir).open("w") as fh:
            recorder.write(fh, session_started(started="2024-01-01T00:00:00Z", command=["test"]))
        data = json.loads(_audit_file(session_dir).read_text())
        data["sequence"] = 999
        _audit_file(session_dir).write_text(json.dumps(data, separators=(",", ":")) + "\n")
        with pytest.raises(VerificationError, match="sequence"):
            verify_log(session_dir)

    def test_detects_tampered_chain_hash(self, session_dir: Path) -> None:
        """A corrupt chain_hash raises VerificationError."""
        recorder = AlphaRecorder()
        with _audit_file(session_dir).open("w") as fh:
            recorder.write(fh, session_started(started="2024-01-01T00:00:00Z", command=["test"]))
        data = json.loads(_audit_file(session_dir).read_text())
        data["chain_hash"] = "a" * 64
        _audit_file(session_dir).write_text(json.dumps(data, separators=(",", ":")) + "\n")
        with pytest.raises(VerificationError, match="chain hash"):
            verify_log(session_dir)


@pytest.mark.integration
class TestTailSession:
    def test_reads_existing_records_then_stops(self, session_dir: Path) -> None:
        """tail_session yields pre-written records before the stop_event fires."""
        recorder = AlphaRecorder()
        with _audit_file(session_dir).open("w") as fh:
            recorder.write(fh, session_started(started="2024-01-01T00:00:00Z", command=["test"]))
            recorder.write(fh, session_ended(ended="2024-01-01T00:00:01Z", exit_code=0))

        stop = threading.Event()
        collected: list[dict[str, Any]] = []

        def _run() -> None:
            for rec in tail_session(session_dir, poll_interval_s=0.05, stop_event=stop):
                collected.append(rec)

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        deadline = time.monotonic() + 2.0
        while len(collected) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        stop.set()
        t.join(timeout=2.0)

        assert len(collected) == 2
        assert collected[0]["event"]["type"] == "session_started"
        assert collected[1]["event"]["type"] == "session_ended"
