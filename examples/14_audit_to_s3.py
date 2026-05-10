#!/usr/bin/env python3
"""Stream nono audit events to an S3-compatible sink, with verification.

This example covers, in one file:

* The proxy network audit stream
  (``ProxyHandle.drain_audit_events()``).

* The supervisor's on-disk audit log (``audit-events.ndjson``) — the
  tamper-evident record of session lifecycle, capability decisions
  (filesystem auth), URL opens, network events, and the executed
  command itself.

* End-of-run alpha-scheme integrity verification of the on-disk log
  (chain hash, leaf hashes, Merkle root) via
  :func:`nono_py.audit.verify_log`.

Both streams are gzipped as JSON Lines and written to the configured
S3 endpoint. Each line is tagged with its source so downstream
consumers can demultiplex without inspecting field shape::

    {"source": "proxy",      "event":  <NetworkAuditEvent>}
    {"source": "supervisor", "record": <ndjson record>}

Sink modes
----------

Choose exactly one:

* **Real S3**: set ``NONO_S3_BUCKET`` (and optionally
  ``NONO_S3_ENDPOINT_URL`` for non-AWS endpoints like MinIO,
  ``NONO_S3_REGION``, plus the standard boto3 credential env vars).

* **Offline**: set ``NONO_S3_FAKE=1``. Uses an in-process sink that
  records every ``put_object`` in memory. No external setup.

In both cases ``NONO_S3_KEY_PREFIX`` is required so the example never
writes under a hidden default location.

Supervisor stream
-----------------

* ``NONO_AUDIT_SESSION_DIR`` set: the example tails that directory's
  ``audit-events.ndjson`` live and ships records as they are written.
  Use this when you have already run a ``nono`` CLI session.

* Unset: the example synthesises a minimal alpha-scheme audit log into
  a temp directory in the foreground (one record per supported event
  type, including a ``session_started`` with the executed command and
  a ``capability_decision`` for filesystem auth). The synthesised log
  is also passed to :func:`nono_py.audit.verify_log` to demonstrate
  the verifier round-trip.

Examples
--------

Offline (no infrastructure required)::

    NONO_S3_FAKE=1 \\
    NONO_S3_KEY_PREFIX=demo \\
    uv run python examples/14_audit_to_s3.py

MinIO::

    NONO_S3_ENDPOINT_URL=http://127.0.0.1:9000 \\
    NONO_S3_BUCKET=nono-audit-demo \\
    NONO_S3_KEY_PREFIX=nono/examples/14 \\
    NONO_S3_REGION=us-east-1 \\
    AWS_ACCESS_KEY_ID=minioadmin \\
    AWS_SECRET_ACCESS_KEY=minioadmin \\
    uv run python examples/14_audit_to_s3.py

Real AWS S3 (ambient credentials via env / ``~/.aws/credentials``)::

    NONO_S3_BUCKET=my-audit-bucket \\
    NONO_S3_KEY_PREFIX=nono/prod \\
    uv run python examples/14_audit_to_s3.py

Tail an existing CLI session as well::

    NONO_AUDIT_SESSION_DIR=~/.nono/audit/sessions/<id> \\
    NONO_S3_FAKE=1 NONO_S3_KEY_PREFIX=demo \\
    uv run python examples/14_audit_to_s3.py

Real-S3 modes require ``boto3`` (``uv pip install boto3``); the
offline mode does not.
"""

import gzip
import io
import json
import os
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from proxy_demo_support import PROXY_DEMO_CHILD_CODE, build_proxy_child_caps

from nono_py import (
    ProxyConfig,
    ProxyHandle,
    audit,
    is_supported,
    sandboxed_exec,
    start_proxy,
)


class S3AuditDrainer:
    """Background drainer that flushes tagged audit records to S3.

    Records are pushed in via :meth:`ingest` and flushed as gzipped
    JSON Lines. The drainer also runs its own poll loop pulling from
    the proxy's audit ring buffer.

    The sink must expose a ``put_object(Bucket, Key, Body, ContentType,
    ContentEncoding)`` method compatible with the boto3 S3 client.
    """

    def __init__(
        self,
        proxy: ProxyHandle,
        bucket: str,
        key_prefix: str,
        *,
        poll_interval_s: float,
        flush_every_n: int,
        flush_every_s: float,
        s3_client: Any,
    ) -> None:
        self._proxy = proxy
        self._bucket = bucket
        self._key_prefix = key_prefix.rstrip("/")
        self._poll = poll_interval_s
        self._flush_n = flush_every_n
        self._flush_s = flush_every_s
        self._s3 = s3_client
        self._buf: list[dict[str, Any]] = []
        self._buf_lock = threading.Lock()
        self._last_flush = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="nono-audit-drain", daemon=True
        )
        self._keys_written: list[str] = []

    @property
    def keys_written(self) -> list[str]:
        with self._buf_lock:
            return list(self._keys_written)

    def ingest(self, record: dict[str, Any]) -> None:
        with self._buf_lock:
            self._buf.append(record)

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._thread.join(timeout)
        try:
            self._drain_proxy()
            self._flush()
        except Exception as exc:  # noqa: BLE001
            print(
                f"[nono-audit-drain] final-flush error: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._drain_proxy()
                if self._should_flush():
                    self._flush()
            except Exception as exc:  # noqa: BLE001 — keep the thread alive
                # A silent drainer thread is the worst failure mode for an
                # audit pipeline. Surface to stderr and keep going so a
                # transient sink failure doesn't drop the whole stream.
                print(
                    f"[nono-audit-drain] flush error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
            self._stop.wait(self._poll)

    def _drain_proxy(self) -> None:
        for event in self._proxy.drain_audit_events():
            self.ingest({"source": "proxy", "event": event})

    def _should_flush(self) -> bool:
        with self._buf_lock:
            count = len(self._buf)
        if count == 0:
            return False
        return (
            count >= self._flush_n
            or (time.monotonic() - self._last_flush) >= self._flush_s
        )

    def _flush(self) -> None:
        with self._buf_lock:
            if not self._buf:
                self._last_flush = time.monotonic()
                return
            batch, self._buf = self._buf, []
        body = io.BytesIO()
        with gzip.GzipFile(fileobj=body, mode="wb") as gz:
            for record in batch:
                gz.write((json.dumps(record, separators=(",", ":")) + "\n").encode())
        ts_ms = int(time.time() * 1000)
        key = f"{self._key_prefix}/{ts_ms}-{uuid.uuid4().hex}.jsonl.gz"
        self._s3.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=body.getvalue(),
            ContentType="application/x-ndjson",
            ContentEncoding="gzip",
        )
        with self._buf_lock:
            self._keys_written.append(key)
        self._last_flush = time.monotonic()


class _SupervisorLogTailer:
    """Tail an ``audit-events.ndjson`` file and forward records to a drainer."""

    def __init__(
        self,
        session_dir: Path,
        drainer: S3AuditDrainer,
        *,
        poll_interval_s: float,
    ) -> None:
        self._session_dir = session_dir
        self._drainer = drainer
        self._poll = poll_interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="nono-audit-tail", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._thread.join(timeout)

    def _run(self) -> None:
        for record in audit.tail_session(
            self._session_dir,
            poll_interval_s=self._poll,
            stop_event=self._stop,
        ):
            self._drainer.ingest({"source": "supervisor", "record": record})


class _FakeS3Sink:
    """In-memory ``put_object`` recorder for offline runs (NONO_S3_FAKE=1)."""

    def __init__(self) -> None:
        self.objects: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        ContentType: str,
        ContentEncoding: str,
    ) -> dict[str, Any]:
        with self._lock:
            self.objects.append(
                {
                    "Bucket": Bucket,
                    "Key": Key,
                    "Body": bytes(Body),
                    "ContentType": ContentType,
                    "ContentEncoding": ContentEncoding,
                }
            )
        return {"ETag": f'"{uuid.uuid4().hex}"'}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        with self._lock:
            for obj in self.objects:
                if obj["Bucket"] == Bucket and obj["Key"] == Key:
                    body = obj["Body"]
                    return {
                        "Body": io.BytesIO(body),
                        "ContentEncoding": obj["ContentEncoding"],
                        "ContentType": obj["ContentType"],
                    }
        raise KeyError(f"s3://{Bucket}/{Key}")


def _synthesise_session_log(session_dir: Path, command: list[str]) -> None:
    """Write a minimal but algorithm-valid ``audit-events.ndjson``.

    Uses :class:`nono_py.audit.AlphaRecorder` and the per-variant
    builder helpers, so the example doubles as a usage demo for the
    audit primitives.

    Produces one record per supported event type — exercises command
    auditing, capability decisions, URL opens, network events, and
    session lifecycle without needing a real nono CLI session. Records
    are written progressively so the tailer demonstrates live streaming.
    """
    pid = 4242
    session_id = "sess-demo"

    events: list[audit.AuditEvent] = [
        audit.session_started(started="2026-04-28T00:00:00Z", command=command),
        audit.capability_decision(
            timestamp="2026-04-28T00:00:01Z",
            path="/etc/passwd",
            access="Read",
            child_pid=pid,
            session_id=session_id,
            decision=audit.approval_denied("policy: outside grant"),
            backend="PolicyApproval",
            duration_ms=2,
            reason="demo: agent attempted to read system file",
        ),
        audit.url_open(
            url="https://example.com/oauth/callback",
            child_pid=pid,
            session_id=session_id,
            success=True,
        ),
        audit.network(
            timestamp_unix_ms=int(time.time() * 1000),
            mode="connect",
            decision="deny",
            target="evil.example",
            port=443,
            reason="host evil.example is not in the allowlist",
        ),
        audit.session_ended(ended="2026-04-28T00:00:02Z", exit_code=0),
    ]

    def _write() -> None:
        path = session_dir / audit.AUDIT_EVENTS_FILENAME
        recorder = audit.AlphaRecorder()
        with path.open("w", encoding="utf-8") as fh:
            for ev in events:
                recorder.write(fh, ev)
                # Stagger so the tailer sees them as appends, not bulk read.
                time.sleep(0.15)

    threading.Thread(target=_write, name="nono-synth-log", daemon=True).start()


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"error: {name} is required", file=sys.stderr)
        sys.exit(2)
    return value


def _optional_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw else default


def _optional_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def _build_real_s3_client(
    endpoint_url: Optional[str], region: Optional[str]
) -> Any:
    try:
        import boto3
    except ImportError:
        print(
            "error: boto3 is not installed. Run 'uv pip install boto3' "
            "or set NONO_S3_FAKE=1 for offline mode.",
            file=sys.stderr,
        )
        sys.exit(2)

    kwargs: dict[str, Any] = {}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    if region:
        kwargs["region_name"] = region
    return boto3.client("s3", **kwargs)


def _format_record(record: dict[str, Any]) -> str:
    src = record.get("source", "?")
    if src == "proxy":
        e = record.get("event", {})
        port = f":{e['port']}" if e.get("port") is not None else ""
        method = f"{e['method']} " if e.get("method") else ""
        path = e.get("path") or ""
        status = f" status={e['status']}" if e.get("status") is not None else ""
        reason = f" reason={e['reason']!r}" if e.get("reason") else ""
        return (
            f"[proxy] [{e.get('decision','?')}] {e.get('mode','?')} "
            f"{method}{e.get('target','?')}{port}{path}{status}{reason}"
        )
    if src == "supervisor":
        rec = record.get("record", {})
        ev = rec.get("event", {})
        kind = ev.get("type", "?")
        detail = ""
        if kind == "session_started":
            detail = f" command={ev.get('command')}"
        elif kind == "session_ended":
            detail = f" exit_code={ev.get('exit_code')}"
        elif kind == "capability_decision":
            entry = ev.get("entry", {})
            req = entry.get("request", {})
            decision = entry.get("decision")
            decision_str = (
                "Granted"
                if decision == "Granted"
                else "Timeout"
                if decision == "Timeout"
                else next(iter(decision)) if isinstance(decision, dict) else "?"
            )
            detail = f" {decision_str} {req.get('access')} {req.get('path')}"
        elif kind == "url_open":
            detail = f" {ev.get('request', {}).get('url')}"
        elif kind == "network":
            inner = ev.get("event", {})
            detail = (
                f" [{inner.get('decision')}] {inner.get('mode')} "
                f"{inner.get('target')}:{inner.get('port')}"
            )
        return f"[supervisor seq={rec.get('sequence','?')}] {kind}{detail}"
    return f"[{src}] {record}"


def main() -> None:
    if not is_supported():
        print("Sandboxing not supported on this platform")
        sys.exit(1)

    fake_mode = os.environ.get("NONO_S3_FAKE", "").lower() in {"1", "true", "yes"}
    key_prefix = _require_env("NONO_S3_KEY_PREFIX")

    if fake_mode:
        bucket = os.environ.get("NONO_S3_BUCKET") or "nono-fake-sink"
        s3: Any = _FakeS3Sink()
        target_label = "FakeS3Sink (in-memory)"
    else:
        bucket = _require_env("NONO_S3_BUCKET")
        endpoint_url = os.environ.get("NONO_S3_ENDPOINT_URL") or None
        region = os.environ.get("NONO_S3_REGION") or None
        s3 = _build_real_s3_client(endpoint_url, region)
        target_label = endpoint_url or "AWS S3"

    poll = _optional_float("NONO_S3_POLL_S", 0.5)
    flush_n = _optional_int("NONO_S3_FLUSH_N", 100)
    flush_s = _optional_float("NONO_S3_FLUSH_S", 2.0)
    session_dir_raw = os.environ.get("NONO_AUDIT_SESSION_DIR") or None
    real_session = bool(session_dir_raw)
    session_dir = (
        Path(session_dir_raw).expanduser()
        if session_dir_raw
        else None
    )

    print("1. Starting proxy (allowed: example.com)")
    proxy = start_proxy(ProxyConfig(allowed_hosts=["example.com"]))
    print(f"   Listening on 127.0.0.1:{proxy.port}\n")

    print(f"2. Starting audit drainer -> s3://{bucket}/{key_prefix}  ({target_label})")
    print(f"   poll={poll}s  flush_every_n={flush_n}  flush_every_s={flush_s}s")

    # Decide where the supervisor log lives. Either the user pointed us at
    # one (real CLI session), or we synthesise one for the demo.
    synth_dir: Optional[tempfile.TemporaryDirectory] = None
    if not session_dir:
        synth_dir = tempfile.TemporaryDirectory(prefix="nono-synth-session-")
        session_dir = Path(synth_dir.name)
        print(
            f"   synthesising supervisor log at {session_dir}/"
            f"{audit.AUDIT_EVENTS_FILENAME}\n"
            "   (set NONO_AUDIT_SESSION_DIR to tail a real CLI session instead)"
        )
    else:
        print(f"   tailing supervisor log at {session_dir}/audit-events.ndjson")
    print()

    drainer = S3AuditDrainer(
        proxy,
        bucket=bucket,
        key_prefix=key_prefix,
        poll_interval_s=poll,
        flush_every_n=flush_n,
        flush_every_s=flush_s,
        s3_client=s3,
    )
    drainer.start()

    tailer = _SupervisorLogTailer(session_dir, drainer, poll_interval_s=poll)
    tailer.start()

    if not real_session:
        # Drive the synth writer in a background thread; staggered appends
        # exercise the tailer's live-follow path.
        _synthesise_session_log(
            session_dir,
            command=[sys.executable, "-c", "<demo-agent>"],
        )

    try:
        print("3. Running sandboxed child through the proxy")
        with tempfile.TemporaryDirectory() as workdir:
            caps = build_proxy_child_caps(workdir)
            env = list(proxy.env_vars().items()) + list(
                proxy.credential_env_vars().items()
            )
            result = sandboxed_exec(
                caps,
                [sys.executable, "-c", PROXY_DEMO_CHILD_CODE],
                cwd=workdir,
                env=env,
                timeout_secs=10.0,
            )
            print(f"   exit_code: {result.exit_code}")
            if result.exit_code != 0:
                stderr_text = (
                    result.stderr.decode("utf-8", errors="replace")
                    if isinstance(result.stderr, (bytes, bytearray))
                    else str(result.stderr)
                )
                if stderr_text.strip():
                    print(f"   stderr:\n{stderr_text.rstrip()}")
            print()

        print("4. Waiting for supervisor log + flush tick")
        # 5 synth records * 0.15s = 0.75s + flush window. Pad generously.
        time.sleep(max(flush_s + 1.0, 2.0))
    finally:
        print("\n5. Stopping drainer + tailer (final drain + flush)")
        tailer.stop()
        drainer.stop()
        proxy.shutdown()
        print("   Proxy shut down.\n")

    keys = drainer.keys_written
    print(f"6. S3 objects written: {len(keys)}")
    for key in keys:
        if isinstance(s3, _FakeS3Sink):
            obj = s3.get_object(Bucket=bucket, Key=key)
            body_bytes = obj["Body"].read()
        else:
            obj = s3.get_object(Bucket=bucket, Key=key)
            body_bytes = obj["Body"].read()
        payload = gzip.decompress(body_bytes).decode()
        records = [json.loads(line) for line in payload.splitlines() if line]
        encoding = obj.get("ContentEncoding", "")
        print(f"   s3://{bucket}/{key}")
        print(f"     encoding={encoding} records={len(records)}")
        for record in records:
            print(f"       {_format_record(record)}")

    print("\n7. Verifying on-disk audit log integrity (alpha scheme)")
    try:
        result = audit.verify_log(session_dir)
    except audit.VerificationError as e:
        print(f"   FAILED: {e}")
        sys.exit(3)
    print(f"   event_count = {result['event_count']}")
    print(f"   chain_head  = {result['computed_chain_head']}")
    print(f"   merkle_root = {result['computed_merkle_root']}")
    print(f"   records_verified = {result['records_verified']}")
    if result["stored_event_count"] is not None:
        print(
            "   stored summary: "
            f"event_count_matches={result['event_count_matches']}"
        )

    if synth_dir is not None:
        synth_dir.cleanup()

    print("\nComplete.")


if __name__ == "__main__":
    main()
