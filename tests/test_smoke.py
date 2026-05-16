"""Smoke tests: one per subsystem, confirming APIs are reachable."""

import json

import pytest
from utils import add_system_paths

from nono_py import (
    AccessMode,
    CapabilitySet,
    QueryContext,
    SandboxState,
    SessionMetadata,
    SnapshotManager,
    SnapshotManifest,
    sandboxed_exec,
)
from nono_py.audit import (
    AUDIT_EVENTS_FILENAME,
    AlphaRecorder,
    iter_session,
    session_started,
    verify_log,
)


@pytest.mark.smoke
def test_capability_set_smoke(tmp_path) -> None:
    """CapabilitySet creation and summary return a non-empty string."""
    caps = CapabilitySet()
    caps.allow_path(str(tmp_path), AccessMode.READ)
    summary = caps.summary()
    assert isinstance(summary, str)
    assert len(summary) > 0


@pytest.mark.smoke
def test_sandbox_state_smoke(tmp_path) -> None:
    """SandboxState round-trips through JSON without error."""
    caps = CapabilitySet()
    caps.allow_path(str(tmp_path), AccessMode.READ)
    state = SandboxState.from_caps(caps)
    json_str = state.to_json()
    restored = SandboxState.from_json(json_str)
    assert isinstance(json_str, str)
    assert isinstance(restored, SandboxState)


@pytest.mark.smoke
@pytest.mark.usefixtures("require_sandboxed_exec")
def test_sandboxed_exec_smoke(tmp_path) -> None:
    """sandboxed_exec runs a trivial command and exits 0."""
    caps = CapabilitySet()
    add_system_paths(caps)
    caps.allow_path(str(tmp_path), AccessMode.READ_WRITE)
    result = sandboxed_exec(caps, ["echo", "smoke"], cwd=str(tmp_path))
    assert result.exit_code == 0
    assert b"smoke" in result.stdout


@pytest.mark.smoke
def test_query_context_smoke(tmp_path) -> None:
    """QueryContext.query_network() returns a dict with a 'status' key."""
    caps = CapabilitySet()
    caps.allow_path(str(tmp_path), AccessMode.READ)
    qc = QueryContext(caps)
    result = qc.query_network()
    assert "status" in result


@pytest.mark.smoke
def test_alpha_recorder_smoke() -> None:
    """AlphaRecorder.record() returns a dict with all four hash envelope fields."""
    recorder = AlphaRecorder()
    event = session_started(started="2024-01-01T00:00:00Z", command=["test"])
    rec = recorder.record(event)
    for field in ("sequence", "prev_chain", "leaf_hash", "chain_hash"):
        assert field in rec
    assert rec["sequence"] == 0
    assert rec["prev_chain"] is None
    assert len(rec["leaf_hash"]) == 64
    assert len(rec["chain_hash"]) == 64


@pytest.mark.smoke
def test_iter_session_smoke(tmp_path) -> None:
    """iter_session yields a record that was written to the NDJSON file."""
    session = tmp_path / "session"
    session.mkdir()
    audit_file = session / AUDIT_EVENTS_FILENAME
    recorder = AlphaRecorder()
    with audit_file.open("w") as fh:
        recorder.write(fh, session_started(started="2024-01-01T00:00:00Z", command=["smoke"]))
    records = list(iter_session(session))
    assert len(records) == 1
    assert records[0]["event"]["type"] == "session_started"


@pytest.mark.smoke
def test_verify_log_smoke(tmp_path) -> None:
    """AlphaRecorder → NDJSON file → verify_log passes integrity check."""
    session = tmp_path / "session"
    session.mkdir()
    audit_file = session / AUDIT_EVENTS_FILENAME
    recorder = AlphaRecorder()
    with audit_file.open("w") as fh:
        recorder.write(fh, session_started(started="2024-01-01T00:00:00Z", command=["smoke"]))
    result = verify_log(session)
    assert result["records_verified"] is True
    assert result["event_count"] == 1


@pytest.mark.smoke
def test_snapshot_manager_smoke(tmp_path) -> None:
    """SnapshotManager.create_baseline() returns a SnapshotManifest."""
    session = tmp_path / "session"
    session.mkdir()
    tracked = tmp_path / "tracked"
    tracked.mkdir()
    (tracked / "seed.txt").write_text("seed")
    mgr = SnapshotManager(str(session), [str(tracked)])
    manifest = mgr.create_baseline()
    assert isinstance(manifest, SnapshotManifest)
    assert manifest.number == 0


@pytest.mark.smoke
def test_session_metadata_smoke() -> None:
    """SessionMetadata round-trips session_id through to_json/from_json."""
    meta = SessionMetadata(
        session_id="smoke-session-id",
        command=["echo", "smoke"],
        tracked_paths=["/tmp"],
    )
    json_str = meta.to_json()
    parsed = json.loads(json_str)
    assert parsed["session_id"] == "smoke-session-id"
    restored = SessionMetadata.from_json(json_str)
    assert restored.session_id == "smoke-session-id"
