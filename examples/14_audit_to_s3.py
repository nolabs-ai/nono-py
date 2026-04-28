#!/usr/bin/env python3
"""Stream proxy audit events to an S3-compatible sink.

Demonstrates the drain-and-ship pattern: a background thread periodically
calls `ProxyHandle.drain_audit_events()`, buffers events, and flushes them
as gzipped JSON Lines objects to an S3 bucket.

nono-py does not ship an S3 sink itself — this file shows one way to wire
up the mechanism. All tunables (poll interval, batch size, flush cadence,
key layout) are explicit constructor arguments with no hidden defaults.

To run this example without AWS credentials it uses a small in-memory
`FakeS3Client` that records `put_object` calls. Swap it for
`boto3.client("s3")` to ship to real S3:

    import boto3
    drainer = S3AuditDrainer(
        proxy,
        bucket="my-audit-bucket",
        key_prefix="nono/prod",
        poll_interval_s=1.0,
        flush_every_n=500,
        flush_every_s=30.0,
        s3_client=boto3.client("s3"),
    )

Manual testing:

    uv run python examples/14_audit_to_s3.py
"""

import gzip
import io
import json
import sys
import tempfile
import threading
import time
import uuid
from typing import Any

from proxy_demo_support import PROXY_DEMO_CHILD_CODE, build_proxy_child_caps

from nono_py import (
    ProxyConfig,
    ProxyHandle,
    is_supported,
    sandboxed_exec,
    start_proxy,
)
from nono_py._nono_py import NetworkAuditEvent


class S3AuditDrainer:
    """Background drainer that flushes audit events to an S3-compatible sink.

    The sink must expose a `put_object(Bucket, Key, Body, ContentType,
    ContentEncoding)` method compatible with the boto3 S3 client.
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
        self._buf: list[NetworkAuditEvent] = []
        self._buf_lock = threading.Lock()
        self._last_flush = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="nono-audit-drain", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._thread.join(timeout)
        self._drain_once()
        self._flush()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._drain_once()
            if self._should_flush():
                self._flush()
            self._stop.wait(self._poll)

    def _drain_once(self) -> None:
        events = self._proxy.drain_audit_events()
        if not events:
            return
        with self._buf_lock:
            self._buf.extend(events)

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
            for event in batch:
                gz.write((json.dumps(event, separators=(",", ":")) + "\n").encode())
        ts_ms = int(time.time() * 1000)
        key = f"{self._key_prefix}/{ts_ms}-{uuid.uuid4().hex}.jsonl.gz"
        self._s3.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=body.getvalue(),
            ContentType="application/x-ndjson",
            ContentEncoding="gzip",
        )
        self._last_flush = time.monotonic()


class FakeS3Client:
    """In-memory stand-in for `boto3.client('s3')` so the example runs offline."""

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
                    "Body": Body,
                    "ContentType": ContentType,
                    "ContentEncoding": ContentEncoding,
                }
            )
        return {"ETag": f'"{uuid.uuid4().hex}"'}


def main() -> None:
    if not is_supported():
        print("Sandboxing not supported on this platform")
        sys.exit(1)

    print("1. Starting proxy (allowed: example.com)")
    proxy = start_proxy(ProxyConfig(allowed_hosts=["example.com"]))
    print(f"   Listening on 127.0.0.1:{proxy.port}\n")

    s3 = FakeS3Client()
    drainer = S3AuditDrainer(
        proxy,
        bucket="nono-audit-demo",
        key_prefix="nono/examples/14",
        poll_interval_s=0.5,
        flush_every_n=100,
        flush_every_s=2.0,
        s3_client=s3,
    )

    print("2. Starting audit drainer")
    print("   poll=0.5s  flush_every_n=100  flush_every_s=2.0s\n")
    drainer.start()

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
            print(f"   exit_code: {result.exit_code}\n")

        # Give the background thread time to flush on its timer. In real
        # deployments you would typically rely on stop() to do the final
        # flush; we sleep here just to exercise the time-based path.
        print("4. Waiting for a time-based flush tick")
        time.sleep(2.5)
    finally:
        # Stop the drainer BEFORE shutting down the proxy so the final
        # drain_audit_events() call still succeeds.
        print("\n5. Stopping drainer (final drain + flush)")
        drainer.stop()
        proxy.shutdown()
        print("   Proxy shut down.\n")

    print(f"6. S3 objects written: {len(s3.objects)}")
    for obj in s3.objects:
        payload = gzip.decompress(obj["Body"]).decode()
        events = [json.loads(line) for line in payload.splitlines() if line]
        print(f"   s3://{obj['Bucket']}/{obj['Key']}")
        print(f"     encoding={obj['ContentEncoding']} events={len(events)}")
        for event in events:
            decision = event.get("decision", "?")
            mode = event.get("mode", "?")
            target = event.get("target", "?")
            print(f"       [{decision}] {mode} -> {target}")

    print("\nComplete.")


if __name__ == "__main__":
    main()
