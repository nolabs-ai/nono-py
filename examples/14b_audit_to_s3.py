#!/usr/bin/env python3
"""Stream nono audit events to a real S3-compatible endpoint.

Companion to ``14_audit_to_s3.py``. That example uses an in-memory
``FakeS3Client`` so it runs without credentials; this one targets a real
endpoint via boto3. Works against AWS S3, MinIO, or anything else that
speaks the S3 API.

Two audit sources are demonstrated:

* **Proxy events** — drained from ``ProxyHandle.drain_audit_events()``.
  Network CONNECT / reverse / external decisions made by nono's HTTPS
  proxy. Always available.

* **Supervisor on-disk audit log** — tailed from
  ``<session_dir>/audit-events.ndjson``. The trusted supervisor (the
  nono CLI) writes a tamper-evident NDJSON log per session containing
  ``session_started``, ``session_ended``, ``capability_decision``,
  ``url_open``, and ``network`` records, each carrying a sequence
  number, leaf hash, and chain hash. Enabled when
  ``NONO_AUDIT_SESSION_DIR`` is set.

Each gzipped JSONL line shipped to S3 is tagged with its source so
downstream consumers can demultiplex:

    {"source": "proxy",      "event":  <NetworkAuditEvent dict>}
    {"source": "supervisor", "record": <ndjson record dict>}

All configuration comes from environment variables — no defaults.

Required:
    NONO_S3_BUCKET             Target bucket (must already exist).
    NONO_S3_KEY_PREFIX         Object key prefix, e.g. ``nono/prod``.

Optional:
    NONO_S3_ENDPOINT_URL       Override for non-AWS endpoints (e.g.
                               ``http://127.0.0.1:9000`` for MinIO).
    NONO_S3_REGION             Region name. Defaults to boto3 resolution.
    NONO_S3_POLL_S             Drainer poll interval (float seconds).
    NONO_S3_FLUSH_N            Flush after this many buffered events.
    NONO_S3_FLUSH_S            Flush after this many seconds since last flush.
    NONO_AUDIT_SESSION_DIR     Path to a session directory containing
                               ``audit-events.ndjson``. When set, the
                               example also tails the supervisor log
                               and ships its records into the same
                               batches.

Credentials follow the standard boto3 chain: ``AWS_ACCESS_KEY_ID`` /
``AWS_SECRET_ACCESS_KEY`` env vars, ``~/.aws/credentials``, instance
metadata, etc.

Example — MinIO, proxy events only:

    export NONO_S3_ENDPOINT_URL=http://127.0.0.1:9000
    export NONO_S3_BUCKET=nono-audit-demo
    export NONO_S3_KEY_PREFIX=nono/examples/14b
    export AWS_ACCESS_KEY_ID=minioadmin
    export AWS_SECRET_ACCESS_KEY=minioadmin
    export AWS_DEFAULT_REGION=us-east-1
    uv run python examples/14b_audit_to_s3_live.py

Example — adding the supervisor log: run a nono CLI session that
writes an ``audit-events.ndjson`` file (see the nono CLI docs for the
exact invocation), then point this script at the resulting session
directory:

    export NONO_AUDIT_SESSION_DIR=/path/to/session/dir
    uv run python examples/14b_audit_to_s3_live.py

Requires ``boto3`` in the environment (``uv pip install boto3``).
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

    Records are pushed in via :meth:`ingest` (one per event) and
    flushed as gzipped JSON Lines. The drainer also runs its own
    poll loop pulling from the proxy's audit ring buffer.

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
        """Push one tagged record into the buffer."""
        with self._buf_lock:
            self._buf.append(record)

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._thread.join(timeout)
        self._drain_proxy()
        self._flush()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._drain_proxy()
            if self._should_flush():
                self._flush()
            self._stop.wait(self._poll)

    def _drain_proxy(self) -> None:
        for event in self._proxy.drain_audit_events():
            self.ingest({"source": "proxy", "event": event})

    def _should_flush(self) -> bool:
        with self._buf_lock:
            if not self._buf:
                return False
            count = len(self._buf)
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
    """Tail a supervisor ``audit-events.ndjson`` and push records to a drainer."""

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


def _build_s3_client(endpoint_url: Optional[str], region: Optional[str]) -> Any:
    try:
        import boto3
    except ImportError:
        print(
            "error: boto3 is not installed. Run: uv pip install boto3",
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
        method = e.get("method") or ""
        path = e.get("path") or ""
        status = f" status={e['status']}" if e.get("status") is not None else ""
        reason = f" reason={e['reason']!r}" if e.get("reason") else ""
        return (
            f"[proxy] [{e.get('decision','?')}] {e.get('mode','?')} "
            f"{method} {e.get('target','?')}{port}{path}{status}{reason}"
        )
    if src == "supervisor":
        rec = record.get("record", {})
        ev = rec.get("event", {})
        return f"[supervisor seq={rec.get('sequence','?')}] type={ev.get('type','?')}"
    return f"[{src}] {record}"


def main() -> None:
    if not is_supported():
        print("Sandboxing not supported on this platform")
        sys.exit(1)

    bucket = _require_env("NONO_S3_BUCKET")
    key_prefix = _require_env("NONO_S3_KEY_PREFIX")
    endpoint_url = os.environ.get("NONO_S3_ENDPOINT_URL") or None
    region = os.environ.get("NONO_S3_REGION") or None
    poll = _optional_float("NONO_S3_POLL_S", 0.5)
    flush_n = _optional_int("NONO_S3_FLUSH_N", 100)
    flush_s = _optional_float("NONO_S3_FLUSH_S", 2.0)
    session_dir_raw = os.environ.get("NONO_AUDIT_SESSION_DIR") or None
    session_dir = Path(session_dir_raw).expanduser() if session_dir_raw else None

    s3 = _build_s3_client(endpoint_url, region)

    print("1. Starting proxy (allowed: example.com)")
    proxy = start_proxy(ProxyConfig(allowed_hosts=["example.com"]))
    print(f"   Listening on 127.0.0.1:{proxy.port}\n")

    target = endpoint_url or "AWS S3"
    print(f"2. Starting audit drainer -> s3://{bucket}/{key_prefix}  ({target})")
    print(f"   poll={poll}s  flush_every_n={flush_n}  flush_every_s={flush_s}s")
    if session_dir:
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

    tailer: Optional[_SupervisorLogTailer] = None
    if session_dir:
        tailer = _SupervisorLogTailer(session_dir, drainer, poll_interval_s=poll)
        tailer.start()

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

        print("4. Waiting for a time-based flush tick")
        time.sleep(max(flush_s + 0.5, 1.0))
    finally:
        print("\n5. Stopping drainer + tailer (final drain + flush)")
        if tailer:
            tailer.stop()
        drainer.stop()
        proxy.shutdown()
        print("   Proxy shut down.\n")

    keys = drainer.keys_written
    print(f"6. S3 objects written: {len(keys)}")
    for key in keys:
        obj = s3.get_object(Bucket=bucket, Key=key)
        payload = gzip.decompress(obj["Body"].read()).decode()
        records = [json.loads(line) for line in payload.splitlines() if line]
        encoding = obj.get("ContentEncoding", "")
        print(f"   s3://{bucket}/{key}")
        print(f"     encoding={encoding} records={len(records)}")
        for record in records:
            print(f"       {_format_record(record)}")

    print("\nComplete.")


if __name__ == "__main__":
    main()
