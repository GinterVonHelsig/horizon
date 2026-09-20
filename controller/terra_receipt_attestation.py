"""External Ed25519 attestation for Terra review receipts.

The database continues to derive its own receipt digest and ledger-MAC
signature.  This second signature is produced only by the out-of-band Terra
authority and is verified from a separately pinned public-key file.  A
workflow caller can therefore not self-authorize by choosing a database hash
or by supplying a caller-controlled signing secret.
"""

from __future__ import annotations

import json
import hashlib
import re
from typing import Any, Protocol

from authority_pins import CURRENT_TERRA_RECEIPT_KEY_VERSION
from comms01_authority_secrets import terra_receipt_verification_key
from exceptions import AuthorizationFailureError
from operator_asymmetric import sign_message, verify_message_signature


_SIGNATURE_PREFIX = re.compile(
    r"^v([1-9][0-9]*):([^:]+)(?::([0-9a-f]{64}):([^:]+))?$"
)
_REQUIRED_FIELDS = (
    "child_id",
    "attempt_number",
    "reviewer",
    "decision",
    "evidence_chain_head",
    "run_id",
    "task_id",
    "reviewed_sha",
    "fence_token",
    "controller_epoch",
    "tree_sha",
    "source_digest",
    "request_digest",
    "migration_head",
    "authority_version",
    "evidence_digest",
    "result_digest",
)


class TerraReceiptSigner(Protocol):
    """Out-of-band signer interface; private key material stays outside the controller."""

    def sign(self, receipt: dict[str, Any]) -> str:
        ...


def terra_receipt_signing_message(
    receipt: dict[str, Any], *, key_version: int = CURRENT_TERRA_RECEIPT_KEY_VERSION
) -> str:
    missing = [field for field in _REQUIRED_FIELDS if receipt.get(field) is None]
    if missing:
        raise AuthorizationFailureError(
            "Terra receipt attestation is missing: " + ", ".join(missing)
        )
    ordered = {field: receipt[field] for field in _REQUIRED_FIELDS}
    ordered["attempt_number"] = int(ordered["attempt_number"])
    ordered["fence_token"] = int(ordered["fence_token"])
    ordered["controller_epoch"] = int(ordered["controller_epoch"])
    ordered["authority_version"] = int(ordered["authority_version"])
    ordered["key_version"] = int(key_version)
    return json.dumps(ordered, sort_keys=True, separators=(",", ":"))


def terra_receipt_database_digest(receipt: dict[str, Any]) -> str:
    """Match PostgreSQL ``jsonb_build_object(...)::text`` digest bytes."""
    missing = [field for field in _REQUIRED_FIELDS if receipt.get(field) is None]
    if missing:
        raise AuthorizationFailureError(
            "Terra receipt database digest is missing: " + ", ".join(missing)
        )
    # PostgreSQL JSONB orders object keys by key length and then bytewise key
    # value. This is intentionally distinct from the compact signature message.
    ordered = {
        field: receipt[field]
        for field in sorted(_REQUIRED_FIELDS, key=lambda field: (len(field), field))
    }
    encoded = json.dumps(
        ordered, ensure_ascii=False, separators=(", ", ": ")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sign_terra_receipt(
    receipt: dict[str, Any],
    private_key_b64: str,
    *,
    key_version: int = CURRENT_TERRA_RECEIPT_KEY_VERSION,
) -> str:
    if int(key_version) != CURRENT_TERRA_RECEIPT_KEY_VERSION:
        raise AuthorizationFailureError("Terra receipt signing key version is not current")
    message = terra_receipt_signing_message(receipt, key_version=key_version)
    return f"v{int(key_version)}:{sign_message(message, private_key_b64)}"


def verify_terra_receipt_signature(
    receipt: dict[str, Any], signature: str | None
) -> bool:
    if not signature:
        return False
    match = _SIGNATURE_PREFIX.fullmatch(signature)
    if match is None:
        return False
    key_version = int(match.group(1))
    if key_version != CURRENT_TERRA_RECEIPT_KEY_VERSION:
        return False
    try:
        message = terra_receipt_signing_message(receipt, key_version=key_version)
        public_key = terra_receipt_verification_key(key_version=key_version)
    except (AuthorizationFailureError, TypeError, ValueError):
        return False
    return verify_message_signature(message, match.group(2), public_key)


def terra_receipt_signature_components(
    signature: str | None,
) -> tuple[str, str, str] | None:
    """Return the external signature, gateway MAC, and attestation binding.

    The external Ed25519 signature is deliberately extended only after the
    authority service has returned a database-derived gateway MAC and a
    one-shot attestation id.  Consumers that admit a stored receipt must
    validate all three components; validating only the Ed25519 prefix would
    leave the database witness and its binding unaudited.
    """
    if not isinstance(signature, str):
        return None
    match = _SIGNATURE_PREFIX.fullmatch(signature)
    if match is None or match.group(3) is None or match.group(4) is None:
        return None
    gateway_mac = match.group(3)
    attestation_id = match.group(4)
    if not re.fullmatch(r"[0-9a-f]{64}", gateway_mac):
        return None
    if not re.fullmatch(r"[0-9a-f]{32}", attestation_id):
        return None
    return f"v{match.group(1)}:{match.group(2)}", gateway_mac, attestation_id
