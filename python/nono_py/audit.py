"""Reader for the supervisor's append-only audit log.

The nono CLI's trusted supervisor writes one ``audit-events.ndjson`` file
per session into the session directory (typically
``~/.nono/audit/sessions/<session_id>/``). Each line is a JSON record:

    {
      "sequence":    <u64>,                 # monotonic, starts at 0
      "prev_chain":  <hex64>|null,          # chain hash of previous record
      "leaf_hash":   <hex64>,               # SHA-256 of canonical event_json
      "chain_hash":  <hex64>,               # rolling chain commitment
      "event_json":  <str>|null,            # canonical bytes used to derive leaf_hash
      "event": {
        "type": "session_started" | "session_ended"
              | "capability_decision" | "url_open" | "network",
        ...variant-specific fields
      }
    }

This module surfaces those records as Python dicts. It does not verify
the chain or merkle root — those checks belong to the supervisor (CLI).

Functions
---------
iter_session(session_dir)
    Iterate every record currently in ``audit-events.ndjson`` and stop
    at EOF. Use for completed sessions.

tail_session(session_dir, *, poll_interval_s, stop_event)
    Iterate every record in the file, then keep yielding new records as
    they are appended. Use for live sessions feeding a sink. The caller
    drives termination via ``stop_event``.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Union

_TAIL_READ_CHUNK = 65536

PathLike = Union[str, Path]

AUDIT_EVENTS_FILENAME = "audit-events.ndjson"

EVENT_TYPES = frozenset(
    {
        "session_started",
        "session_ended",
        "capability_decision",
        "url_open",
        "network",
    }
)


def _audit_path(session_dir: PathLike) -> Path:
    return Path(session_dir) / AUDIT_EVENTS_FILENAME


def iter_session(session_dir: PathLike) -> Iterator[Dict[str, Any]]:
    """Yield every record currently in the session's audit log, then stop.

    Raises:
        FileNotFoundError: if the audit-events.ndjson file does not exist.
        json.JSONDecodeError: if a line is malformed (caller may catch).
    """
    path = _audit_path(session_dir)
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def tail_session(
    session_dir: PathLike,
    *,
    poll_interval_s: float,
    stop_event: Optional[threading.Event] = None,
) -> Iterator[Dict[str, Any]]:
    """Yield existing records, then follow the file for new appends.

    Behaves like ``tail -F``: tolerates the file not yet existing
    (waits for it), and yields each freshly appended record as it lands.
    Termination is driven entirely by the caller via ``stop_event``.

    Args:
        session_dir: Directory containing ``audit-events.ndjson``.
        poll_interval_s: Sleep between polls when at EOF.
        stop_event: Event the caller sets to stop iteration. If None,
            iteration continues until the process exits.

    Yields:
        Parsed record dicts (same shape as ``iter_session``).
    """
    path = _audit_path(session_dir)
    stop = stop_event if stop_event is not None else threading.Event()

    while not path.exists():
        if stop.wait(poll_interval_s):
            return

    fh = path.open("r", encoding="utf-8")
    open_inode = os.fstat(fh.fileno()).st_ino
    try:
        buf = ""
        while not stop.is_set():
            chunk = fh.read(_TAIL_READ_CHUNK)
            if chunk:
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    yield json.loads(line)
                continue

            if stop.wait(poll_interval_s):
                return

            try:
                disk_stat = path.stat()
            except FileNotFoundError:
                # Rotated/moved between reads — wait for it to come back.
                continue

            rotated = (
                disk_stat.st_ino != open_inode
                or fh.tell() > disk_stat.st_size
            )
            if rotated:
                fh.close()
                fh = path.open("r", encoding="utf-8")
                open_inode = os.fstat(fh.fileno()).st_ino
                buf = ""
    finally:
        fh.close()


__all__ = [
    "AUDIT_EVENTS_FILENAME",
    "EVENT_TYPES",
    "iter_session",
    "tail_session",
]
