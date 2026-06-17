"""Reader, verifier, and primitives for the supervisor's audit log.

The nono CLI's trusted supervisor writes one ``audit-events.ndjson`` file
per session into the session directory (typically
``~/.nono/audit/sessions/<session_id>/``). Each line is an alpha-scheme
record::

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

This module exposes:

Reading
-------
- :func:`iter_session` — read every record currently in the file, then stop.
- :func:`tail_session` — read existing then follow appends, with inode-
  based rotation handling.

Verification
------------
- :func:`verify_log` — alpha-scheme integrity check (per-record sequence
  + prev_chain + leaf hash + chain hash; final Merkle root + chain head
  cross-check against an optional stored summary).
- :func:`build_inclusion_proof` / :func:`verify_inclusion_proof` —
  Merkle inclusion proofs for individual audit event leaves.
- :func:`compute_session_digest`, :func:`build_ledger_record`,
  :func:`iter_ledger`, :func:`verify_session_in_ledger`, and
  :func:`validate_ledger_session_id` — the append-only cross-session
  ledger (``ledger.ndjson``), hash-chained per record.
- :class:`VerificationError` — raised on mismatch.

Construction (Pydantic models + builder primitives)
---------------------------------------------------
- Pydantic models for each event variant
  (:class:`SessionStartedEvent`, :class:`SessionEndedEvent`,
  :class:`CapabilityDecisionEvent`, :class:`UrlOpenEvent`,
  :class:`NetworkEvent`) and the on-disk record envelope
  (:class:`AuditEventRecord`).
- Builder funcs (:func:`session_started`, :func:`session_ended`,
  :func:`capability_decision`, :func:`url_open`, :func:`network`,
  plus :func:`approval_granted` / :func:`approval_denied` /
  :func:`approval_timeout` for the inner ``ApprovalDecision`` shape)
  return validated dicts without making the caller remember the
  field schema.
- :class:`AlphaRecorder` — stateful builder that wraps event payloads
  in fully hashed records, advancing sequence and chain hash for the
  caller. Use this when synthesising or replaying a log.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import (
    IO,
    Annotated,
    Any,
    Literal,
    TypeAlias,
    TypedDict,
    cast,
)

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter

_TAIL_READ_CHUNK = 65536

# Per-domain prefixes for the alpha audit scheme. Must match the upstream
# constants in nono-cli/src/audit_integrity.rs verbatim — keep in sync.
EVENT_DOMAIN_ALPHA = b"nono.audit.event.alpha\n"
CHAIN_DOMAIN_ALPHA = b"nono.audit.chain.alpha\n"
MERKLE_DOMAIN_ALPHA = b"nono.audit.merkle.alpha\n"
SESSION_DIGEST_DOMAIN_ALPHA = b"nono.audit.session-digest.alpha\n"
LEDGER_CHAIN_DOMAIN_ALPHA = b"nono.audit.ledger.chain.alpha\n"

HASH_ALGORITHM_ALPHA = "sha256"
MERKLE_SCHEME_ALPHA = "alpha"

PathLike = str | Path

AUDIT_EVENTS_FILENAME = "audit-events.ndjson"
AUDIT_LEDGER_FILENAME = "ledger.ndjson"
AUDIT_ATTESTATION_BUNDLE_FILENAME = "audit-attestation.bundle"
AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA = "https://nono.sh/attestation/audit-session/alpha"
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

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


def iter_session(session_dir: PathLike) -> Iterator[dict[str, Any]]:
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
    stop_event: threading.Event | None = None,
) -> Iterator[dict[str, Any]]:
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


def _hash_chain_alpha(previous: bytes | None, leaf: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(CHAIN_DOMAIN_ALPHA)
    h.update(previous if previous is not None else b"\x00" * 32)
    h.update(leaf)
    return h.digest()


def _merkle_root_alpha(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
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


HashInput: TypeAlias = str | bytes


class AuditProofNodeDict(TypedDict):
    """JSON shape for one sibling in an alpha audit inclusion proof."""

    direction: Literal["left", "right"]
    hash: str


class AuditInclusionProofDict(TypedDict):
    """JSON shape returned by :func:`build_inclusion_proof`."""

    leaf_index: int
    leaf_count: int
    leaf_hash: str
    merkle_root: str
    siblings: list[AuditProofNodeDict]


class AuditVerificationResultDict(TypedDict):
    """JSON shape returned by :func:`verify_log`."""

    hash_algorithm: str
    merkle_scheme: str
    event_count: int
    computed_chain_head: str | None
    computed_merkle_root: str | None
    stored_event_count: int | None
    stored_chain_head: str | None
    stored_merkle_root: str | None
    event_count_matches: bool
    records_verified: bool
    missing_canonical_event_json: bool


class LedgerRecordDict(TypedDict):
    """JSON shape for one append-only alpha ledger entry."""

    sequence: int
    prev_chain: str | None
    session_id: str
    session_digest: str
    completed_at: str
    chain_hash: str


class LedgerVerificationResultDict(TypedDict):
    """JSON shape returned by :func:`verify_session_in_ledger`."""

    hash_algorithm: str
    entry_count: int
    session_digest: str
    session_found: bool
    session_digest_matches: bool
    ledger_chain_verified: bool
    ledger_head: str | None


class AuditAttestationSummaryDict(TypedDict):
    """Signed attestation metadata stored on session metadata."""

    predicate_type: str
    key_id: str
    public_key: str
    bundle_filename: str


class AuditAttestationVerificationResultDict(TypedDict):
    """JSON shape returned by audit-attestation verification."""

    present: bool
    predicate_type: str | None
    key_id: str | None
    key_id_matches: bool
    signature_verified: bool
    merkle_root_matches: bool
    session_id_matches: bool
    expected_public_key_matches: bool | None
    verification_error: str | None


class _AttestationModel(BaseModel):  # type: ignore[misc, unused-ignore]
    model_config = ConfigDict(extra="ignore", strict=True, populate_by_name=True)


class _DsseSignatureModel(_AttestationModel):
    sig: str
    keyid: str | None = None


class _DsseEnvelopeModel(_AttestationModel):
    payload_type: str = Field(alias="payloadType")
    payload: str
    signatures: list[_DsseSignatureModel]


class _PublicKeyMaterialModel(_AttestationModel):
    hint: str | None = None


class _VerificationMaterialModel(_AttestationModel):
    public_key: _PublicKeyMaterialModel = Field(alias="publicKey")
    tlog_entries: list[Any] = Field(default_factory=list, alias="tlogEntries")
    timestamp_verification_data: dict[str, Any] = Field(
        default_factory=dict,
        alias="timestampVerificationData",
    )


class _SigstoreDsseBundleModel(_AttestationModel):
    media_type: str = Field(alias="mediaType")
    verification_material: _VerificationMaterialModel = Field(alias="verificationMaterial")
    dsse_envelope: _DsseEnvelopeModel = Field(alias="dsseEnvelope")


def _hash_input_to_bytes(value: HashInput) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise VerificationError(f"expected 32-byte SHA-256, got {len(value)} bytes")
        return value
    return _hex_to_bytes(value)


def build_inclusion_proof(
    leaf_hashes: list[HashInput],
    leaf_index: int,
) -> AuditInclusionProofDict:
    """Build an alpha Merkle inclusion proof for one audit leaf.

    Args:
        leaf_hashes: Ordered audit leaf hashes as 32-byte values or hex strings.
        leaf_index: Zero-based index of the leaf to prove.

    Returns:
        A JSON-serializable proof dict compatible with the Rust core API.
    """
    leaves = [_hash_input_to_bytes(value) for value in leaf_hashes]
    if not leaves:
        raise VerificationError("cannot build an audit inclusion proof for an empty log")
    if leaf_index < 0 or leaf_index >= len(leaves):
        raise VerificationError(
            f"audit inclusion proof leaf index {leaf_index} is out of range for "
            f"{len(leaves)} leaves"
        )

    siblings: list[AuditProofNodeDict] = []
    index = leaf_index
    level = list(leaves)
    while len(level) > 1:
        sibling_index = index + 1 if index % 2 == 0 else index - 1
        if sibling_index < len(level):
            siblings.append(
                {
                    "direction": "left" if sibling_index < index else "right",
                    "hash": level[sibling_index].hex(),
                }
            )

        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            if i + 1 == len(level):
                nxt.append(left)
                continue
            h = hashlib.sha256()
            h.update(MERKLE_DOMAIN_ALPHA)
            h.update(left)
            h.update(level[i + 1])
            nxt.append(h.digest())
        index //= 2
        level = nxt

    return {
        "leaf_index": leaf_index,
        "leaf_count": len(leaves),
        "leaf_hash": leaves[leaf_index].hex(),
        "merkle_root": level[0].hex(),
        "siblings": siblings,
    }


def verify_inclusion_proof(
    proof: dict[str, Any],
    *,
    expected_root: HashInput | None = None,
) -> bool:
    """Verify an alpha Merkle inclusion proof.

    Without ``expected_root``, this checks internal consistency only:
    every value verified against (``leaf_hash``, ``leaf_count``,
    ``merkle_root``) comes from ``proof`` itself, so ``True`` means
    "this proof commits this leaf to this root" — not that the root is
    the real one. Callers must compare ``proof["merkle_root"]`` (and
    ``leaf_count``) against a trusted integrity summary, or pass the
    trusted root as ``expected_root`` to have that comparison done here.
    """
    try:
        trusted_root = _hash_input_to_bytes(expected_root) if expected_root is not None else None
        leaf_count = int(proof["leaf_count"])
        leaf_index = int(proof["leaf_index"])
        if leaf_count <= 0 or leaf_index < 0 or leaf_index >= leaf_count:
            return False
        computed = _hex_to_bytes(proof["leaf_hash"])
        merkle_root = _hex_to_bytes(proof["merkle_root"])
        siblings = iter(proof.get("siblings", []))

        index = leaf_index
        width = leaf_count
        while width > 1:
            if index % 2 == 0:
                expected_direction = "right" if index + 1 < width else None
            else:
                expected_direction = "left"

            if expected_direction is not None:
                try:
                    node = next(siblings)
                except StopIteration:
                    return False
                if node.get("direction") != expected_direction:
                    return False
                sibling = _hex_to_bytes(node["hash"])
                h = hashlib.sha256()
                h.update(MERKLE_DOMAIN_ALPHA)
                if expected_direction == "left":
                    h.update(sibling)
                    h.update(computed)
                else:
                    h.update(computed)
                    h.update(sibling)
                computed = h.digest()

            index //= 2
            width = (width + 1) // 2

        try:
            next(siblings)
            return False
        except StopIteration:
            if trusted_root is not None and computed != trusted_root:
                return False
            return computed == merkle_root
    except (KeyError, TypeError, ValueError, VerificationError):
        return False


def _metadata_to_dict(metadata: Mapping[str, Any] | Any) -> dict[str, Any]:
    if isinstance(metadata, Mapping):
        return dict(metadata)
    to_json = getattr(metadata, "to_json", None)
    if callable(to_json):
        return dict(json.loads(to_json()))
    raise TypeError("metadata must be a mapping or expose to_json()")


def _json_compact(value: Mapping[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64_decode_flexible(value: str) -> bytes:
    compact = "".join(value.split()).rstrip("=")
    compact = compact.replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except ValueError as e:
        raise VerificationError(f"invalid base64: {value!r}") from e


def _pae(payload_type: str, payload: bytes) -> bytes:
    payload_type_bytes = payload_type.encode("utf-8")
    header = b"DSSEv1 %d " % len(payload_type_bytes)
    header += payload_type_bytes
    header += b" %d " % len(payload)
    return header + payload


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Return DSSE Pre-Authentication Encoding bytes for a payload."""
    return _pae(payload_type, payload)


def _load_public_key_der(value: bytes | str) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if isinstance(value, bytes):
        stripped = value.lstrip()
        if stripped.startswith(b"-----BEGIN PUBLIC KEY-----"):
            public_key = serialization.load_pem_public_key(stripped)
            der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            der = value

        public_key = serialization.load_der_public_key(der)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise VerificationError("expected public key must be an ECDSA P-256 public key")
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise VerificationError("expected public key must use the P-256 curve")
        return der

    text = value.strip()
    if text.startswith("-----BEGIN PUBLIC KEY-----"):
        return _load_public_key_der(text.encode("utf-8"))
    return _load_public_key_der(_b64_decode_flexible(text))


def _load_p256_private_key(private_key_pem: bytes | str, password: bytes | None) -> Any:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key_bytes = (
        private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    )
    if key_bytes.lstrip().startswith(b"-----BEGIN"):
        private_key = serialization.load_pem_private_key(key_bytes, password=password)
    else:
        private_key = serialization.load_der_private_key(key_bytes, password=password)

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise VerificationError("audit attestation signing key must be an ECDSA P-256 private key")
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise VerificationError("audit attestation signing key must use the P-256 curve")
    return private_key


def _verify_p256_signature(public_key_der: bytes, pae_bytes: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    public_key = serialization.load_der_public_key(public_key_der)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise VerificationError("audit attestation public key must be an ECDSA P-256 public key")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise VerificationError("audit attestation public key must use the P-256 curve")
    try:
        public_key.verify(signature, pae_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise VerificationError("ECDSA signature verification failed") from e


def _decode_attestation_statement(bundle: _SigstoreDsseBundleModel) -> dict[str, Any]:
    envelope = bundle.dsse_envelope
    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE:
        raise VerificationError(
            "unexpected DSSE payloadType: "
            f"expected {IN_TOTO_PAYLOAD_TYPE}, got {envelope.payload_type}"
        )
    payload = _b64_decode_flexible(envelope.payload)
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise VerificationError(f"invalid DSSE in-toto statement payload: {e}") from e
    if not isinstance(statement, dict):
        raise VerificationError("DSSE payload is not an in-toto statement object")
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        raise VerificationError(
            "unexpected in-toto statement type: "
            f"expected {IN_TOTO_STATEMENT_TYPE}, got {statement.get('_type')}"
        )
    return statement


def _parse_attestation_bundle(bundle: Mapping[str, Any] | str | bytes) -> _SigstoreDsseBundleModel:
    if isinstance(bundle, bytes):
        bundle = bundle.decode("utf-8")
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except json.JSONDecodeError as e:
            raise VerificationError(f"invalid audit attestation bundle JSON: {e}") from e
    validated: _SigstoreDsseBundleModel = _SigstoreDsseBundleModel.model_validate(bundle)
    return validated


def _audit_attestation_summary(
    metadata: Mapping[str, Any] | Any,
) -> AuditAttestationSummaryDict | None:
    summary = _metadata_to_dict(metadata).get("audit_attestation")
    if summary is None:
        return None
    if not isinstance(summary, Mapping):
        raise VerificationError("audit_attestation metadata must be an object")
    return {
        "predicate_type": str(summary["predicate_type"]),
        "key_id": str(summary["key_id"]),
        "public_key": str(summary["public_key"]),
        "bundle_filename": str(summary["bundle_filename"]),
    }


def _audit_integrity_summary(metadata: Mapping[str, Any] | Any) -> Mapping[str, Any] | None:
    integrity = _metadata_to_dict(metadata).get("audit_integrity")
    if integrity is None:
        return None
    if not isinstance(integrity, Mapping):
        raise VerificationError("audit_integrity metadata must be an object")
    return integrity


def _attestation_failure(
    summary: AuditAttestationSummaryDict,
    expected_public_key_matches: bool | None,
    verification_error: str,
) -> AuditAttestationVerificationResultDict:
    return {
        "present": True,
        "predicate_type": summary["predicate_type"],
        "key_id": summary["key_id"],
        "key_id_matches": False,
        "signature_verified": False,
        "merkle_root_matches": False,
        "session_id_matches": False,
        "expected_public_key_matches": expected_public_key_matches,
        "verification_error": verification_error,
    }


def sign_audit_attestation_bundle(
    metadata: Mapping[str, Any] | Any,
    private_key_pem: bytes | str,
    *,
    key_id: str | None = None,
    password: bytes | None = None,
    redaction_policy: Mapping[str, Any] | None = None,
) -> tuple[str, AuditAttestationSummaryDict]:
    """Build and sign an alpha audit-attestation DSSE bundle.

    The private key must be an ECDSA P-256 key in PEM or DER form. The
    returned bundle is Sigstore bundle v0.3 JSON; the returned summary is the
    metadata shape stored under ``session["audit_attestation"]``.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    meta = _metadata_to_dict(metadata)
    integrity = _audit_integrity_summary(meta)
    if integrity is None:
        raise VerificationError("audit attestation requires audit integrity to be enabled")

    private_key = _load_p256_private_key(private_key_pem, password)
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    computed_key_id = hashlib.sha256(public_key_der).hexdigest()
    if key_id is not None and key_id != computed_key_id:
        raise VerificationError(
            "audit attestation key_id must be the SHA-256 hex digest of the SPKI public key"
        )
    signer_key_id = computed_key_id

    predicate = {
        "version": 1,
        "session_id": meta["session_id"],
        "started": meta["started"],
        "ended": meta["ended"],
        "command": list(meta["command"]),
        "redaction_policy": dict(redaction_policy) if redaction_policy is not None else None,
        "audit_log": {
            "hash_algorithm": integrity["hash_algorithm"],
            "event_count": integrity["event_count"],
            "chain_head": _hash_hex(integrity["chain_head"]),
            "merkle_root": _hash_hex(integrity["merkle_root"]),
        },
        "signer": {
            "kind": "keyed",
            "key_id": signer_key_id,
        },
    }
    statement = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": f"audit-session:{meta['session_id']}",
                "digest": {"sha256": _hash_hex(integrity["merkle_root"])},
            }
        ],
        "predicateType": AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA,
        "predicate": predicate,
    }
    payload = _json_compact(statement).encode("utf-8")
    signature = private_key.sign(_pae(IN_TOTO_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "publicKey": {"hint": computed_key_id},
            "tlogEntries": [],
            "timestampVerificationData": {},
        },
        "dsseEnvelope": {
            "payloadType": IN_TOTO_PAYLOAD_TYPE,
            "payload": _b64url_encode(payload),
            "signatures": [{"sig": _b64url_encode(signature)}],
        },
    }
    summary: AuditAttestationSummaryDict = {
        "predicate_type": AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA,
        "key_id": signer_key_id,
        "public_key": base64.b64encode(public_key_der).decode("ascii"),
        "bundle_filename": AUDIT_ATTESTATION_BUNDLE_FILENAME,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False), summary


def write_audit_attestation(
    session_dir: PathLike,
    metadata: Mapping[str, Any] | Any,
    private_key_pem: bytes | str,
    *,
    key_id: str | None = None,
    password: bytes | None = None,
    redaction_policy: Mapping[str, Any] | None = None,
) -> AuditAttestationSummaryDict:
    """Sign an audit attestation and write the bundle into ``session_dir``."""
    bundle_json, summary = sign_audit_attestation_bundle(
        metadata,
        private_key_pem,
        key_id=key_id,
        password=password,
        redaction_policy=redaction_policy,
    )
    path = Path(session_dir) / summary["bundle_filename"]
    path.write_text(bundle_json, encoding="utf-8")
    return summary


def verify_audit_attestation_bundle(
    bundle: Mapping[str, Any] | str | bytes,
    metadata: Mapping[str, Any] | Any,
    *,
    expected_public_key: bytes | str | None = None,
) -> AuditAttestationVerificationResultDict:
    """Verify a keyed alpha audit-attestation DSSE bundle.

    Supplying ``expected_public_key`` is what gives the result an external
    trust anchor. Without it, verification proves the bundle, metadata
    summary, and embedded public key are internally self-consistent, but an
    attacker who can rewrite the session directory can replace all three.
    """
    expected_public_key_supplied = expected_public_key is not None
    expected_public_key_matches: bool | None = None
    summary = _audit_attestation_summary(metadata)
    if summary is None:
        return {
            "present": False,
            "predicate_type": None,
            "key_id": None,
            "key_id_matches": False,
            "signature_verified": False,
            "merkle_root_matches": False,
            "session_id_matches": False,
            "expected_public_key_matches": False if expected_public_key_supplied else None,
            "verification_error": (
                "session has no audit attestation to verify against provided public key"
                if expected_public_key_supplied
                else None
            ),
        }

    integrity = _audit_integrity_summary(metadata)
    if integrity is None:
        return _attestation_failure(
            summary,
            expected_public_key_matches,
            "session has audit attestation metadata but no audit integrity summary",
        )

    try:
        parsed = _parse_attestation_bundle(bundle)
        statement = _decode_attestation_statement(parsed)
        predicate_type = str(statement.get("predicateType"))
        if predicate_type != AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA:
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "wrong bundle type: "
                f"expected {AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA}, got {predicate_type}",
            )
        predicate = statement.get("predicate")
        if not isinstance(predicate, Mapping):
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation predicate is not an object",
            )
        signer = predicate.get("signer")
        if not isinstance(signer, Mapping) or signer.get("kind") != "keyed":
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation must be keyed",
            )
        signer_key_id = signer.get("key_id") or parsed.verification_material.public_key.hint

        public_key_der = _b64_decode_flexible(summary["public_key"])
        recomputed_key_id = hashlib.sha256(public_key_der).hexdigest()
        if recomputed_key_id != summary["key_id"]:
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation metadata key mismatch: "
                f"expected {summary['key_id']}, got {recomputed_key_id}",
            )
        if signer_key_id != summary["key_id"]:
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation signer key mismatch: "
                f"expected {summary['key_id']}, got {signer_key_id}",
            )
        if expected_public_key is not None:
            expected_public_key_matches = (
                _load_public_key_der(expected_public_key) == public_key_der
            )
            if not expected_public_key_matches:
                return _attestation_failure(
                    summary,
                    False,
                    "provided public key does not match the attested signer key",
                )

        envelope = parsed.dsse_envelope
        if not envelope.signatures:
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation DSSE envelope has no signatures",
            )
        payload = _b64_decode_flexible(envelope.payload)
        signature = _b64_decode_flexible(envelope.signatures[0].sig)
        _verify_p256_signature(
            public_key_der,
            _pae(envelope.payload_type, payload),
            signature,
        )

        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not subjects:
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation statement has no subjects",
            )
        first_subject = subjects[0]
        digest = first_subject.get("digest") if isinstance(first_subject, Mapping) else None
        attested_root = digest.get("sha256") if isinstance(digest, Mapping) else None
        if attested_root != _hash_hex(integrity["merkle_root"]):
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation Merkle root does not match session integrity summary",
            )
        meta = _metadata_to_dict(metadata)
        if predicate.get("session_id") != meta["session_id"]:
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation session_id mismatch: "
                f"expected {meta['session_id']}, got {predicate.get('session_id')}",
            )

        audit_log = predicate.get("audit_log")
        if not isinstance(audit_log, Mapping):
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation predicate missing audit_log",
            )
        for field in ("hash_algorithm", "event_count", "chain_head"):
            expected = _hash_hex(integrity[field]) if field == "chain_head" else integrity[field]
            if audit_log.get(field) != expected:
                return _attestation_failure(
                    summary,
                    expected_public_key_matches,
                    f"audit attestation {field} does not match session integrity summary",
                )
        if predicate.get("started") != meta["started"] or predicate.get("ended") != meta["ended"]:
            return _attestation_failure(
                summary,
                expected_public_key_matches,
                "audit attestation timestamps do not match session metadata",
            )
    except (KeyError, TypeError, ValueError, VerificationError) as e:
        return _attestation_failure(summary, expected_public_key_matches, str(e))

    return {
        "present": True,
        "predicate_type": AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA,
        "key_id": summary["key_id"],
        "key_id_matches": True,
        "signature_verified": True,
        "merkle_root_matches": True,
        "session_id_matches": True,
        "expected_public_key_matches": expected_public_key_matches,
        "verification_error": None,
    }


def verify_audit_attestation(
    session_dir: PathLike,
    metadata: Mapping[str, Any] | Any,
    *,
    expected_public_key: bytes | str | None = None,
) -> AuditAttestationVerificationResultDict:
    """Load and verify the audit-attestation bundle referenced by metadata."""
    summary = _audit_attestation_summary(metadata)
    if summary is None:
        return verify_audit_attestation_bundle(
            b"{}",
            metadata,
            expected_public_key=expected_public_key,
        )

    bundle_path = Path(session_dir) / summary["bundle_filename"]
    if not bundle_path.exists():
        return _attestation_failure(
            summary,
            None,
            f"missing audit attestation bundle: {bundle_path}",
        )
    try:
        bundle_json = bundle_path.read_text(encoding="utf-8")
    except OSError as e:
        return _attestation_failure(
            summary,
            None,
            f"failed to read audit attestation bundle: {e}",
        )
    return verify_audit_attestation_bundle(
        bundle_json,
        metadata,
        expected_public_key=expected_public_key,
    )


def _hash_hex(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _path_bytes(path: Any) -> list[int]:
    return list(os.fsencode(str(path)))


def _executable_identity_payload(identity: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if identity is None:
        return None
    return {
        "resolved_path": _path_bytes(identity["resolved_path"]),
        "sha256": _hash_hex(identity["sha256"]),
    }


def _audit_integrity_payload(summary: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if summary is None:
        return None
    return {
        "hash_algorithm": summary["hash_algorithm"],
        "event_count": summary["event_count"],
        "chain_head": _hash_hex(summary["chain_head"]),
        "merkle_root": _hash_hex(summary["merkle_root"]),
    }


def _audit_attestation_payload(summary: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if summary is None:
        return None
    return {
        "predicate_type": summary["predicate_type"],
        "key_id": summary["key_id"],
        "public_key": summary["public_key"],
        "bundle_filename": summary["bundle_filename"],
    }


def _network_event_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "timestamp_unix_ms": event["timestamp_unix_ms"],
        "mode": event["mode"],
        "decision": event["decision"],
    }
    for key in (
        "route_id",
        "auth_mechanism",
        "auth_outcome",
        "managed_credential_active",
        "injection_mode",
        "denial_category",
    ):
        if event.get(key) is not None:
            wire[key] = event[key]
    wire.update(
        {
            "target": event["target"],
            "port": event.get("port"),
            "method": event.get("method"),
            "path": event.get("path"),
            "status": event.get("status"),
            "reason": event.get("reason"),
        }
    )
    return wire


# Every field committed by the session digest. All keys must be present in the
# metadata (None is fine for the optional ones) — silently defaulting a missing
# protected field would produce a digest that does not cover the real data.
_SESSION_DIGEST_KEYS = (
    "session_id",
    "started",
    "ended",
    "command",
    "executable_identity",
    "tracked_paths",
    "snapshot_count",
    "exit_code",
    "merkle_roots",
    "network_events",
    "audit_event_count",
    "audit_integrity",
    "audit_attestation",
)


def _session_digest_payload(metadata: Mapping[str, Any] | Any) -> dict[str, Any]:
    meta = _metadata_to_dict(metadata)
    missing = [key for key in _SESSION_DIGEST_KEYS if key not in meta]
    if missing:
        raise VerificationError(
            "session metadata is missing protected digest fields: " + ", ".join(missing)
        )
    return {
        "session_id": meta["session_id"],
        "started": meta["started"],
        "ended": meta["ended"],
        "command": list(meta["command"]),
        "executable_identity": _executable_identity_payload(meta["executable_identity"]),
        "tracked_paths": [_path_bytes(path) for path in meta["tracked_paths"]],
        "snapshot_count": meta["snapshot_count"],
        "exit_code": meta["exit_code"],
        "merkle_roots": [_hash_hex(root) for root in meta["merkle_roots"]],
        "network_events": [_network_event_payload(event) for event in meta["network_events"]],
        "audit_event_count": meta["audit_event_count"],
        "audit_integrity": _audit_integrity_payload(meta["audit_integrity"]),
        "audit_attestation": _audit_attestation_payload(meta["audit_attestation"]),
    }


def compute_session_digest(metadata: Mapping[str, Any] | Any) -> str:
    """Compute the alpha audit-ledger digest for session metadata.

    Every protected field must be present in ``metadata`` (optional ones may
    be ``None``); a missing field raises :class:`VerificationError` rather
    than silently hashing a default value.
    """
    payload = _session_digest_payload(metadata)
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    h = hashlib.sha256()
    h.update(SESSION_DIGEST_DOMAIN_ALPHA)
    h.update(payload_bytes)
    return h.hexdigest()


def _hash_ledger_link(
    previous: str | None,
    sequence: int,
    session_id: str,
    session_digest: str,
    completed_at: str,
) -> str:
    payload = {
        "sequence": sequence,
        "session_id": session_id,
        "session_digest": session_digest,
        "completed_at": completed_at,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    h = hashlib.sha256()
    h.update(LEDGER_CHAIN_DOMAIN_ALPHA)
    h.update(_hex_to_bytes(previous) if previous is not None else b"\x00" * 32)
    h.update(payload_bytes)
    return h.hexdigest()


def validate_ledger_session_id(session_id: str) -> None:
    valid = (
        bool(session_id)
        and len(session_id) <= 64
        and all(ch.isascii() and (ch.isalnum() or ch in "-_") for ch in session_id)
    )
    if not valid:
        raise VerificationError(f"invalid audit session id: {session_id}")


def build_ledger_record(
    metadata: Mapping[str, Any] | Any,
    *,
    sequence: int,
    previous_chain: str | None,
) -> LedgerRecordDict:
    """Build one alpha ledger record for `metadata`."""
    meta = _metadata_to_dict(metadata)
    session_id = str(meta["session_id"])
    validate_ledger_session_id(session_id)
    session_digest = compute_session_digest(meta)
    completed_at = meta.get("ended") or meta["started"]
    chain_hash = _hash_ledger_link(
        previous_chain,
        sequence,
        session_id,
        session_digest,
        completed_at,
    )
    return {
        "sequence": sequence,
        "prev_chain": previous_chain,
        "session_id": session_id,
        "session_digest": session_digest,
        "completed_at": completed_at,
        "chain_hash": chain_hash,
    }


def iter_ledger(ledger_path: PathLike) -> Iterator[LedgerRecordDict]:
    """Yield parsed records from a ledger NDJSON file.

    Raises:
        FileNotFoundError: if the ledger file does not exist.
        json.JSONDecodeError: if a line is malformed (caller may catch).
    """
    with Path(ledger_path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


_LEDGER_RECORD_KEYS = (
    "sequence",
    "prev_chain",
    "session_id",
    "session_digest",
    "completed_at",
    "chain_hash",
)


def _checked_ledger_records(path: Path) -> Iterator[tuple[int, LedgerRecordDict]]:
    """Like :func:`iter_ledger`, but malformed records raise VerificationError."""
    with path.open("r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                raise VerificationError(
                    f"audit ledger record at line {line_number} is not valid JSON"
                ) from e
            if not isinstance(record, dict):
                raise VerificationError(
                    f"audit ledger record at line {line_number} is not a JSON object"
                )
            missing = [key for key in _LEDGER_RECORD_KEYS if key not in record]
            if missing:
                raise VerificationError(
                    f"audit ledger record at line {line_number} is missing fields: "
                    + ", ".join(missing)
                )
            yield line_number, cast(LedgerRecordDict, record)


def verify_session_in_ledger(
    ledger_path: PathLike,
    metadata: Mapping[str, Any] | Any,
) -> LedgerVerificationResultDict:
    """Verify an alpha audit ledger and check whether it contains `metadata`.

    Raises:
        VerificationError: if a ledger record is malformed or the hash
            chain does not verify.
    """
    path = Path(ledger_path)
    expected_digest = compute_session_digest(metadata)
    if not path.exists():
        return {
            "hash_algorithm": HASH_ALGORITHM_ALPHA,
            "entry_count": 0,
            "session_digest": expected_digest,
            "session_found": False,
            "session_digest_matches": False,
            "ledger_chain_verified": False,
            "ledger_head": None,
        }

    meta = _metadata_to_dict(metadata)
    previous_chain: str | None = None
    entry_count = 0
    ledger_head: str | None = None
    session_found = False
    session_digest_matches = False

    for line_number, record in _checked_ledger_records(path):
        if record.get("sequence") != entry_count:
            raise VerificationError(f"audit ledger sequence mismatch at line {line_number}")
        if record.get("prev_chain") != previous_chain:
            raise VerificationError(f"audit ledger prev_chain mismatch at line {line_number}")
        chain_hash = _hash_ledger_link(
            previous_chain,
            record["sequence"],
            record["session_id"],
            record["session_digest"],
            record["completed_at"],
        )
        if chain_hash != record.get("chain_hash"):
            raise VerificationError(f"audit ledger chain hash mismatch at line {line_number}")

        if record["session_id"] == meta["session_id"]:
            session_found = True
            session_digest_matches = record["session_digest"] == expected_digest

        previous_chain = record["chain_hash"]
        ledger_head = record["chain_hash"]
        entry_count += 1

    return {
        "hash_algorithm": HASH_ALGORITHM_ALPHA,
        "entry_count": entry_count,
        "session_digest": expected_digest,
        "session_found": session_found,
        "session_digest_matches": session_digest_matches,
        "ledger_chain_verified": True,
        "ledger_head": ledger_head,
    }


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
    stored: Mapping[str, Any] | None = None,
) -> AuditVerificationResultDict:
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

    previous_chain: bytes | None = None
    leaf_hashes: list[bytes] = []
    computed_chain_head: bytes | None = None
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


# ---------------------------------------------------------------------------
# Event payload types and builders (alpha scheme)
# ---------------------------------------------------------------------------
#
# These mirror the Rust enum `AuditEventPayload` in
# nono-cli/src/audit_integrity.rs (serde tag = "type", snake_case). All
# top-level ``type`` discriminators are required; variant-specific fields
# follow upstream nullability.


class _AuditModel(BaseModel):  # type: ignore[misc, unused-ignore]
    """Strict Pydantic base for audit payloads shared with the Rust wire format."""

    model_config = ConfigDict(extra="forbid", strict=True)

    def to_wire(self) -> dict[str, Any]:
        """Return the plain dict shape written to NDJSON and expected by old callers."""
        return cast(dict[str, Any], self.model_dump(mode="json"))  # type: ignore[redundant-cast, unused-ignore]


HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]


class CapabilityRequestPayload(_AuditModel):
    """Payload of a capability request from the sandboxed child."""

    request_id: str
    path: str
    access: Literal["Read", "Write", "ReadWrite"]
    reason: str | None = None
    child_pid: int
    session_id: str


class _ApprovalDeniedInner(_AuditModel):
    reason: str


class _ApprovalDeniedPayload(_AuditModel):
    Denied: _ApprovalDeniedInner


# ApprovalDecision is a serde-tagged enum: "Granted" | {"Denied": ...} | "Timeout".
ApprovalDecision = Literal["Granted", "Timeout"] | dict[str, Any]
_ApprovalDecisionModelInput = Literal["Granted", "Timeout"] | _ApprovalDeniedPayload


class AuditEntryPayload(_AuditModel):
    """One supervisor capability decision."""

    timestamp: str
    request: CapabilityRequestPayload
    decision: _ApprovalDecisionModelInput
    backend: str
    duration_ms: int


class UrlOpenRequestPayload(_AuditModel):
    """Payload of a request to open a URL via the supervisor."""

    request_id: str
    url: str
    child_pid: int
    session_id: str


class NetworkAuditEventPayload(_AuditModel):
    """Inner shape of a ``network`` event's ``event`` field."""

    timestamp_unix_ms: int
    mode: Literal["connect", "connect_intercept", "reverse", "external"]
    decision: Literal["allow", "deny"]
    route_id: str | None = None
    auth_mechanism: (
        Literal[
            "proxy_authorization",
            "phantom_header",
            "phantom_path",
            "phantom_query",
        ]
        | None
    ) = None
    auth_outcome: Literal["succeeded", "failed"] | None = None
    managed_credential_active: bool | None = None
    injection_mode: (
        Literal[
            "header",
            "url_path",
            "query_param",
            "basic_auth",
            "oauth2",
        ]
        | None
    ) = None
    denial_category: (
        Literal[
            "authentication_failed",
            "endpoint_policy",
            "managed_credential_unavailable",
            "host_denied",
            "intercept_handshake_failed",
            "upstream_connect_failed",
            "connect_bypasses_l7",
            "external_proxy_rejected",
        ]
        | None
    ) = None
    target: str
    port: int | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    reason: str | None = None

    def to_wire(self) -> dict[str, Any]:
        wire = super().to_wire()
        for key in (
            "route_id",
            "auth_mechanism",
            "auth_outcome",
            "managed_credential_active",
            "injection_mode",
            "denial_category",
        ):
            if wire.get(key) is None:
                wire.pop(key, None)
        return wire


class ScrubPolicyDiffPayload(_AuditModel):
    added_flags: list[str] = Field(default_factory=list)
    removed_flags: list[str] = Field(default_factory=list)
    added_headers: list[str] = Field(default_factory=list)
    removed_headers: list[str] = Field(default_factory=list)
    added_query_keys: list[str] = Field(default_factory=list)
    removed_query_keys: list[str] = Field(default_factory=list)

    def to_wire(self) -> dict[str, Any]:
        return {key: value for key, value in super().to_wire().items() if value}


class SessionStartedEvent(_AuditModel):
    type: Literal["session_started"]
    started: str
    command: list[str]
    redaction_policy: ScrubPolicyDiffPayload | None = None

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {
            "type": self.type,
            "started": self.started,
            "command": list(self.command),
        }
        if self.redaction_policy is not None:
            wire["redaction_policy"] = self.redaction_policy.to_wire()
        return wire


class SessionEndedEvent(_AuditModel):
    type: Literal["session_ended"]
    ended: str
    exit_code: int


class CapabilityDecisionEvent(_AuditModel):
    type: Literal["capability_decision"]
    entry: AuditEntryPayload


class UrlOpenEvent(_AuditModel):
    type: Literal["url_open"]
    request: UrlOpenRequestPayload
    success: bool
    error: str | None = None


class NetworkEvent(_AuditModel):
    type: Literal["network"]
    event: NetworkAuditEventPayload

    def to_wire(self) -> dict[str, Any]:
        return {"type": self.type, "event": self.event.to_wire()}


AuditEvent = Annotated[
    SessionStartedEvent | SessionEndedEvent | CapabilityDecisionEvent | UrlOpenEvent | NetworkEvent,
    Field(discriminator="type"),
]


class AuditEventRecord(_AuditModel):
    """One line of ``audit-events.ndjson``."""

    sequence: int
    prev_chain: HexDigest | None = None
    leaf_hash: HexDigest
    chain_hash: HexDigest
    event_json: str | None = None
    event: AuditEvent

    def to_wire(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "prev_chain": self.prev_chain,
            "leaf_hash": self.leaf_hash,
            "chain_hash": self.chain_hash,
            "event_json": self.event_json,
            "event": self.event.to_wire(),
        }


_AUDIT_EVENT_ADAPTER: TypeAdapter[AuditEvent] = TypeAdapter(AuditEvent)
_APPROVAL_DECISION_ADAPTER: TypeAdapter[_ApprovalDecisionModelInput] = TypeAdapter(
    _ApprovalDecisionModelInput
)


def _validate_event(event: AuditEvent | dict[str, Any]) -> AuditEvent:
    return cast(  # type: ignore[redundant-cast, unused-ignore]
        AuditEvent,
        _AUDIT_EVENT_ADAPTER.validate_python(event),
    )


def _validate_approval_decision(decision: ApprovalDecision) -> _ApprovalDecisionModelInput:
    return cast(  # type: ignore[redundant-cast, unused-ignore]
        _ApprovalDecisionModelInput,
        _APPROVAL_DECISION_ADAPTER.validate_python(decision),
    )


def session_started(
    *,
    started: str,
    command: list[str],
    redaction_policy: dict[str, Any] | ScrubPolicyDiffPayload | None = None,
) -> dict[str, Any]:
    """Build a ``session_started`` event payload."""
    policy = (
        ScrubPolicyDiffPayload.model_validate(redaction_policy)
        if isinstance(redaction_policy, dict)
        else redaction_policy
    )
    return SessionStartedEvent(
        type="session_started",
        started=started,
        command=list(command),
        redaction_policy=policy,
    ).to_wire()


def session_ended(*, ended: str, exit_code: int) -> dict[str, Any]:
    """Build a ``session_ended`` event payload."""
    return SessionEndedEvent(type="session_ended", ended=ended, exit_code=exit_code).to_wire()


def approval_granted() -> ApprovalDecision:
    return "Granted"


def approval_timeout() -> ApprovalDecision:
    return "Timeout"


def approval_denied(reason: str) -> dict[str, Any]:
    return _ApprovalDeniedPayload(Denied=_ApprovalDeniedInner(reason=reason)).to_wire()


def capability_decision(
    *,
    timestamp: str,
    path: str,
    access: Literal["Read", "Write", "ReadWrite"],
    child_pid: int,
    session_id: str,
    decision: ApprovalDecision,
    backend: str,
    duration_ms: int,
    request_id: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Build a ``capability_decision`` event payload.

    ``request_id`` defaults to a fresh UUID4 hex if omitted.
    """
    return CapabilityDecisionEvent(
        type="capability_decision",
        entry=AuditEntryPayload(
            timestamp=timestamp,
            request=CapabilityRequestPayload(
                request_id=request_id or uuid.uuid4().hex,
                path=path,
                access=access,
                reason=reason,
                child_pid=child_pid,
                session_id=session_id,
            ),
            decision=_validate_approval_decision(decision),
            backend=backend,
            duration_ms=duration_ms,
        ),
    ).to_wire()


def url_open(
    *,
    url: str,
    child_pid: int,
    session_id: str,
    success: bool,
    error: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Build a ``url_open`` event payload."""
    return UrlOpenEvent(
        type="url_open",
        request=UrlOpenRequestPayload(
            request_id=request_id or uuid.uuid4().hex,
            url=url,
            child_pid=child_pid,
            session_id=session_id,
        ),
        success=success,
        error=error,
    ).to_wire()


def network(
    *,
    timestamp_unix_ms: int,
    mode: Literal["connect", "connect_intercept", "reverse", "external"],
    decision: Literal["allow", "deny"],
    target: str,
    route_id: str | None = None,
    auth_mechanism: Literal[
        "proxy_authorization",
        "phantom_header",
        "phantom_path",
        "phantom_query",
    ]
    | None = None,
    auth_outcome: Literal["succeeded", "failed"] | None = None,
    managed_credential_active: bool | None = None,
    injection_mode: Literal[
        "header",
        "url_path",
        "query_param",
        "basic_auth",
        "oauth2",
    ]
    | None = None,
    denial_category: Literal[
        "authentication_failed",
        "endpoint_policy",
        "managed_credential_unavailable",
        "host_denied",
        "intercept_handshake_failed",
        "upstream_connect_failed",
        "connect_bypasses_l7",
        "external_proxy_rejected",
    ]
    | None = None,
    port: int | None = None,
    method: str | None = None,
    path: str | None = None,
    status: int | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Build a ``network`` event payload."""
    return NetworkEvent(
        type="network",
        event=NetworkAuditEventPayload(
            timestamp_unix_ms=timestamp_unix_ms,
            mode=mode,
            decision=decision,
            route_id=route_id,
            auth_mechanism=auth_mechanism,
            auth_outcome=auth_outcome,
            managed_credential_active=managed_credential_active,
            injection_mode=injection_mode,
            denial_category=denial_category,
            target=target,
            port=port,
            method=method,
            path=path,
            status=status,
            reason=reason,
        ),
    ).to_wire()


# ---------------------------------------------------------------------------
# Recorder: produces alpha-scheme records with sequence + chain hashing
# ---------------------------------------------------------------------------


class AlphaRecorder:
    """Stateful builder for alpha-scheme audit records.

    Wraps :class:`AuditEvent` payloads in fully hashed records, advancing
    sequence number and chain hash on each call. Mirrors the upstream
    ``AuditRecorder`` semantics in ``nono-cli/src/audit_integrity.rs`` —
    use this when synthesising or replaying a log without the CLI.

    Thread safety: an internal :class:`threading.Lock` serialises
    ``record()`` / ``write()`` / property reads, so a single recorder
    instance can be shared across threads without corrupting the
    sequence number or chain hash. Note that when multiple threads
    share a file handle in :meth:`write`, the lock guarantees only that
    each record's hashing + serialisation + ``fh.write`` + ``fh.flush``
    runs as one critical section — interleaving with writes that bypass
    the recorder is still the caller's problem.
    """

    def __init__(self) -> None:
        self._next_seq = 0
        self._prev_chain: bytes | None = None
        self._lock = threading.Lock()

    @property
    def sequence(self) -> int:
        """Sequence number that will be assigned to the next record."""
        with self._lock:
            return self._next_seq

    @property
    def chain_head(self) -> str | None:
        """Hex-encoded chain head after the last record, or None if empty."""
        with self._lock:
            return self._prev_chain.hex() if self._prev_chain is not None else None

    def _build_record_locked(self, event: AuditEvent | dict[str, Any]) -> dict[str, Any]:
        validated_event = _validate_event(event)
        wire_event = validated_event.to_wire()
        event_json = json.dumps(wire_event, separators=(",", ":"))
        leaf = _hash_event_alpha(event_json.encode("utf-8"))
        chain = _hash_chain_alpha(self._prev_chain, leaf)
        rec = AuditEventRecord(
            sequence=self._next_seq,
            prev_chain=self._prev_chain.hex() if self._prev_chain else None,
            leaf_hash=leaf.hex(),
            chain_hash=chain.hex(),
            event_json=event_json,
            event=validated_event,
        ).to_wire()
        self._next_seq += 1
        self._prev_chain = chain
        return rec

    def record(self, event: AuditEvent | dict[str, Any]) -> dict[str, Any]:
        """Return one fully-hashed alpha record for ``event``.

        Canonical event JSON is stored on the record so that downstream
        :func:`verify_log` can rehash without ambiguity.
        """
        with self._lock:
            return self._build_record_locked(event)

    def write(self, fh: IO[str], event: AuditEvent | dict[str, Any]) -> dict[str, Any]:
        """Build a record, append one JSONL line to ``fh``, flush, return it.

        The build + ``fh.write`` + ``fh.flush`` runs under the recorder's
        lock so a single shared file handle stays consistent across
        concurrent writers.
        """
        with self._lock:
            rec = self._build_record_locked(event)
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            fh.flush()
            return rec


__all__ = [
    "AUDIT_EVENTS_FILENAME",
    "AUDIT_LEDGER_FILENAME",
    "AUDIT_ATTESTATION_BUNDLE_FILENAME",
    "AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA",
    "IN_TOTO_PAYLOAD_TYPE",
    "IN_TOTO_STATEMENT_TYPE",
    "EVENT_TYPES",
    "EVENT_DOMAIN_ALPHA",
    "CHAIN_DOMAIN_ALPHA",
    "MERKLE_DOMAIN_ALPHA",
    "SESSION_DIGEST_DOMAIN_ALPHA",
    "LEDGER_CHAIN_DOMAIN_ALPHA",
    "HASH_ALGORITHM_ALPHA",
    "MERKLE_SCHEME_ALPHA",
    "VerificationError",
    "AuditInclusionProofDict",
    "AuditProofNodeDict",
    "AuditVerificationResultDict",
    "LedgerRecordDict",
    "LedgerVerificationResultDict",
    "AuditAttestationSummaryDict",
    "AuditAttestationVerificationResultDict",
    "iter_session",
    "tail_session",
    "verify_log",
    "build_inclusion_proof",
    "verify_inclusion_proof",
    "build_ledger_record",
    "compute_session_digest",
    "dsse_pae",
    "iter_ledger",
    "sign_audit_attestation_bundle",
    "validate_ledger_session_id",
    "verify_audit_attestation",
    "verify_audit_attestation_bundle",
    "verify_session_in_ledger",
    "write_audit_attestation",
    # Event payload types
    "ApprovalDecision",
    "AuditEntryPayload",
    "AuditEvent",
    "AuditEventRecord",
    "CapabilityDecisionEvent",
    "CapabilityRequestPayload",
    "NetworkAuditEventPayload",
    "NetworkEvent",
    "ScrubPolicyDiffPayload",
    "SessionEndedEvent",
    "SessionStartedEvent",
    "UrlOpenEvent",
    "UrlOpenRequestPayload",
    # Builders
    "approval_denied",
    "approval_granted",
    "approval_timeout",
    "capability_decision",
    "network",
    "session_ended",
    "session_started",
    "url_open",
    # Recorder
    "AlphaRecorder",
]
