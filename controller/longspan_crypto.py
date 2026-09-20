"""Shared hashing helpers for the Longspan workflow."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
from datetime import date, datetime, time
from typing import Any


def digest_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=_canonical_json_default,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def hash_capability_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_capability_hash(token: str, stored_hash: str) -> bool:
    if not token or not stored_hash:
        return False
    return hmac.compare_digest(hash_capability_token(token), stored_hash)


def issue_capability_token() -> tuple[str, str]:
    token = secrets.token_hex(16)
    return token, hash_capability_token(token)


def sign_payload(payload_digest: str, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        payload_digest.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_payload_signature(payload_digest: str, signature: str, secret: str) -> bool:
    if not payload_digest or not signature or not secret:
        return False
    expected = sign_payload(payload_digest, secret)
    return hmac.compare_digest(expected, signature)


def deep_copy_evidence(evidence: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
    return tuple(copy.deepcopy(item) for item in evidence)


def _canonical_json_default(value: object) -> str:
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    raise TypeError(f"unsupported evidence value: {type(value).__name__}")


def canonical_evidence_document(evidence: tuple[dict[str, Any], ...]) -> str:
    return json.dumps(
        {"evidence": list(evidence)},
        sort_keys=True,
        separators=(",", ":"),
        default=_canonical_json_default,
    )


def canonical_evidence_digest(evidence: tuple[dict[str, Any], ...]) -> str:
    return digest_payload({"evidence": list(evidence)})


def compute_ledger_entry_hash(
    *,
    child_id: str,
    attempt_number: int,
    event_type: str,
    producer_role: str,
    payload_digest: str,
    previous_entry_hash: str | None,
    mac_key: str | None = None,
) -> str:
    base = digest_payload(
        {
            "child_id": child_id,
            "attempt_number": attempt_number,
            "event_type": event_type,
            "producer_role": producer_role,
            "payload_digest": payload_digest,
            "previous_entry_hash": previous_entry_hash,
        }
    )
    if mac_key:
        return sign_payload(f"top_delivery:ledger_entry:v1:{base}", mac_key)
    return base


def verify_ledger_entry_hash(
    *,
    child_id: str,
    attempt_number: int,
    event_type: str,
    producer_role: str,
    payload_digest: str,
    previous_entry_hash: str | None,
    entry_hash: str,
    mac_key: str | None = None,
) -> bool:
    expected = compute_ledger_entry_hash(
        child_id=child_id,
        attempt_number=attempt_number,
        event_type=event_type,
        producer_role=producer_role,
        payload_digest=payload_digest,
        previous_entry_hash=previous_entry_hash,
        mac_key=mac_key,
    )
    return hmac.compare_digest(expected, entry_hash)
