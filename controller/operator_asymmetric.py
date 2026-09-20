"""Ed25519 asymmetric operator approval signatures (verify-only on controller)."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from exceptions import AuthorizationFailureError


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def generate_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes_raw()
    public_bytes = public_key.public_bytes_raw()
    return _b64_encode(private_bytes), _b64_encode(public_bytes)


def parse_public_keys(raw: str) -> dict[int, str]:
    if not raw.strip():
        raise AuthorizationFailureError("operator public keys are not configured")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthorizationFailureError("operator public keys JSON is invalid") from exc
    if not isinstance(payload, dict) or not payload:
        raise AuthorizationFailureError("operator public keys must be a non-empty object")
    parsed: dict[int, str] = {}
    for key, value in payload.items():
        version = int(key)
        if version < 1:
            raise AuthorizationFailureError("operator public key version must be positive")
        if not isinstance(value, str) or not value.strip():
            raise AuthorizationFailureError("operator public key material is required")
        parsed[version] = value.strip()
    return parsed


def operator_public_key_for_version(public_keys: dict[int, str], key_version: int) -> str:
    if key_version not in public_keys:
        raise AuthorizationFailureError(
            f"operator public key version {key_version} is not configured"
        )
    return public_keys[key_version]


def sign_message(message: str, private_key_b64: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(_b64_decode(private_key_b64))
    signature = private_key.sign(message.encode("utf-8"))
    return _b64_encode(signature)


def verify_message_signature(
    message: str,
    signature_b64: str,
    public_key_b64: str,
) -> bool:
    if not message or not signature_b64 or not public_key_b64:
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_b64_decode(public_key_b64))
        public_key.verify(_b64_decode(signature_b64), message.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def challenge_signing_message(payload: dict[str, Any]) -> str:
    """Canonical message bound for operator approval signatures."""
    ordered = {
        "approval_id": payload["approval_id"],
        "operator_identity": payload["operator_identity"],
        "action_type": payload["action_type"],
        "action_digest": payload["action_digest"],
        "run_id": payload["run_id"],
        "nonce": payload["nonce"],
        "expires_at": payload["expires_at"],
        "key_version": int(payload["key_version"]),
        "controller_epoch": int(payload["controller_epoch"]),
        "config_version": int(payload["config_version"]),
        "challenge_epoch": int(payload["challenge_epoch"]),
    }
    return json.dumps(ordered, sort_keys=True, separators=(",", ":"))
