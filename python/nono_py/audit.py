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

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

_TAIL_READ_CHUNK = 65536

# Per-domain prefixes for the alpha audit scheme. Must match the upstream
# constants in nono-cli/src/audit_integrity.rs verbatim — keep in sync.
EVENT_DOMAIN_ALPHA = b"nono.audit.event.alpha\n"
CHAIN_DOMAIN_ALPHA = b"nono.audit.chain.alpha\n"
MERKLE_DOMAIN_ALPHA = b"nono.audit.merkle.alpha\n"

HASH_ALGORITHM_ALPHA = "sha256"
MERKLE_SCHEME_ALPHA = "alpha"

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

            rotated = disk_stat.st_ino != open_inode or fh.tell() > disk_stat.st_size
            if rotated:
                fh.close()
                fh = path.open("r", encoding="utf-8")
                open_inode = os.fstat(fh.fileno()).st_ino
                buf = ""
    finally:
        fh.close()


class VerificationError(Exception):
    """Raised when an audit log fails alpha-scheme integrity checks."""


def _hash_event_alpha(event_bytes: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(EVENT_DOMAIN_ALPHA)
    h.update(event_bytes)
    return h.digest()


def _hash_chain_alpha(previous: Optional[bytes], leaf: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(CHAIN_DOMAIN_ALPHA)
    h.update(previous if previous is not None else b"\x00" * 32)
    h.update(leaf)
    return h.digest()


def _merkle_root_alpha(leaves: List[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = list(leaves)
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            if i + 1 == len(level):
                # Odd remainder is promoted unchanged (matches upstream).
                nxt.append(left)
                continue
            right = level[i + 1]
            h = hashlib.sha256()
            h.update(MERKLE_DOMAIN_ALPHA)
            h.update(left)
            h.update(right)
            nxt.append(h.digest())
        level = nxt
    return level[0]


def _hex_to_bytes(hex_str: str) -> bytes:
    try:
        b = bytes.fromhex(hex_str)
    except ValueError as e:
        raise VerificationError(f"invalid hex: {hex_str!r}") from e
    if len(b) != 32:
        raise VerificationError(f"expected 32-byte SHA-256, got {len(b)} bytes from {hex_str!r}")
    return b


def verify_log(
    session_dir: PathLike,
    *,
    stored: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify the alpha-scheme integrity of a session's audit log.

    Walks ``audit-events.ndjson`` line by line, recomputing each
    record's leaf hash and chain hash and confirming the sequence
    monotonically increases from 0. If a stored
    :class:`AuditIntegritySummary` is supplied (or one is found at
    ``session_dir/session.json``), also confirms the final chain head,
    Merkle root, and event count match.

    Args:
        session_dir: Directory containing ``audit-events.ndjson``.
        stored: Optional precomputed integrity summary to cross-check
            against. Shape::

                {"hash_algorithm": "sha256",
                 "event_count":   <int>,
                 "chain_head":    "<hex64>",
                 "merkle_root":   "<hex64>"}

            If omitted, this function attempts to read
            ``session.json`` from the same directory and use its
            ``audit_integrity`` field (if present).

    Returns:
        A dict mirroring upstream's ``AuditVerificationResult``::

            {"hash_algorithm":         "sha256",
             "merkle_scheme":          "alpha",
             "event_count":            <int>,
             "computed_chain_head":    "<hex64>" | None,
             "computed_merkle_root":   "<hex64>" | None,
             "stored_event_count":     <int>    | None,
             "stored_chain_head":      "<hex64>" | None,
             "stored_merkle_root":     "<hex64>" | None,
             "event_count_matches":    bool,
             "records_verified":       bool,
             "missing_canonical_event_json": bool}

    Raises:
        FileNotFoundError: if ``audit-events.ndjson`` is absent.
        VerificationError: on any per-record sequence/prev_chain/leaf/
            chain mismatch, on stored chain-head or Merkle-root mismatch,
            or on canonical event_json mismatch.
    """
    path = _audit_path(session_dir)

    # Auto-discover stored summary if not provided.
    if stored is None:
        sj = Path(session_dir) / "session.json"
        if sj.exists():
            try:
                with sj.open("r", encoding="utf-8") as fh:
                    meta = json.load(fh)
                stored = meta.get("audit_integrity") or None
            except (OSError, json.JSONDecodeError):
                stored = None

    previous_chain: Optional[bytes] = None
    leaf_hashes: List[bytes] = []
    computed_chain_head: Optional[bytes] = None
    missing_canonical_event_json = False

    with path.open("r", encoding="utf-8") as fh:
        for index, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                raise VerificationError(f"line {index}: malformed JSON: {e}") from e

            expected_seq = len(leaf_hashes)
            seq = record.get("sequence")
            if seq != expected_seq:
                raise VerificationError(
                    f"line {index}: sequence mismatch (expected {expected_seq}, got {seq})"
                )

            rec_prev = record.get("prev_chain")
            rec_prev_bytes = _hex_to_bytes(rec_prev) if rec_prev is not None else None
            if rec_prev_bytes != previous_chain:
                raise VerificationError(f"line {index}: prev_chain mismatch")

            event = record.get("event")
            if event is None:
                raise VerificationError(f"line {index}: missing event payload")

            event_json_str = record.get("event_json")
            if event_json_str is not None:
                try:
                    reparsed = json.loads(event_json_str)
                except json.JSONDecodeError as e:
                    raise VerificationError(
                        f"line {index}: malformed canonical event_json: {e}"
                    ) from e
                if reparsed != event:
                    raise VerificationError(
                        f"line {index}: canonical event_json does not match event"
                    )
                event_bytes = event_json_str.encode("utf-8")
            else:
                missing_canonical_event_json = True
                # Best-effort canonicalisation. This will not match upstream
                # serde_json output exactly for nested fields with non-ASCII
                # or floats, but we only reach this branch when event_json
                # is absent — in which case the leaf hash cannot be
                # authoritatively verified.
                event_bytes = json.dumps(event, separators=(",", ":"), sort_keys=False).encode(
                    "utf-8"
                )

            leaf_hash = _hash_event_alpha(event_bytes)
            rec_leaf = _hex_to_bytes(record["leaf_hash"])
            if rec_leaf != leaf_hash:
                raise VerificationError(f"line {index}: leaf hash mismatch")

            chain_hash = _hash_chain_alpha(previous_chain, leaf_hash)
            rec_chain = _hex_to_bytes(record["chain_hash"])
            if rec_chain != chain_hash:
                raise VerificationError(f"line {index}: chain hash mismatch")

            previous_chain = chain_hash
            computed_chain_head = chain_hash
            leaf_hashes.append(leaf_hash)

    if stored is not None and leaf_hashes and missing_canonical_event_json:
        raise VerificationError(
            "alpha audit log is missing canonical event_json bytes "
            "but a stored integrity summary was supplied"
        )

    computed_merkle_root = _merkle_root_alpha(leaf_hashes) if leaf_hashes else None

    stored_event_count = stored.get("event_count") if stored else None
    stored_chain_head_hex = stored.get("chain_head") if stored else None
    stored_merkle_root_hex = stored.get("merkle_root") if stored else None

    event_count = len(leaf_hashes)
    event_count_matches = (
        stored_event_count == event_count if stored_event_count is not None else True
    )

    if stored_chain_head_hex is not None:
        stored_head = _hex_to_bytes(stored_chain_head_hex)
        if stored_head != computed_chain_head:
            raise VerificationError("stored chain head does not match computed chain head")

    if stored_merkle_root_hex is not None:
        stored_root = _hex_to_bytes(stored_merkle_root_hex)
        if stored_root != computed_merkle_root:
            raise VerificationError("stored Merkle root does not match computed Merkle root")

    return {
        "hash_algorithm": HASH_ALGORITHM_ALPHA,
        "merkle_scheme": MERKLE_SCHEME_ALPHA,
        "event_count": event_count,
        "computed_chain_head": computed_chain_head.hex() if computed_chain_head else None,
        "computed_merkle_root": computed_merkle_root.hex() if computed_merkle_root else None,
        "stored_event_count": stored_event_count,
        "stored_chain_head": stored_chain_head_hex,
        "stored_merkle_root": stored_merkle_root_hex,
        "event_count_matches": event_count_matches,
        "records_verified": True,
        "missing_canonical_event_json": missing_canonical_event_json,
    }


__all__ = [
    "AUDIT_EVENTS_FILENAME",
    "EVENT_TYPES",
    "EVENT_DOMAIN_ALPHA",
    "CHAIN_DOMAIN_ALPHA",
    "MERKLE_DOMAIN_ALPHA",
    "HASH_ALGORITHM_ALPHA",
    "MERKLE_SCHEME_ALPHA",
    "VerificationError",
    "iter_session",
    "tail_session",
    "verify_log",
]
