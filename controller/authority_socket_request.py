"""Bounded socket request envelope for authority service operations."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from exceptions import AuthorizationFailureError

SOCKET_REQUEST_TTL_SECONDS = 300
SOCKET_NONCE_BYTES = 16


def build_socket_request_envelope() -> dict[str, str]:
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=SOCKET_REQUEST_TTL_SECONDS)
    ).isoformat()
    return {
        "socket_request_id": uuid.uuid4().hex,
        "socket_nonce": secrets.token_hex(SOCKET_NONCE_BYTES),
        "socket_expires_at": expires_at,
    }


def validate_socket_request_envelope(payload: dict[str, Any]) -> str:
    request_id = payload.get("socket_request_id")
    nonce = payload.get("socket_nonce")
    expires_at = payload.get("socket_expires_at")
    if not isinstance(request_id, str) or not request_id.strip():
        raise AuthorizationFailureError("authority socket request_id is required")
    if len(request_id) > 128:
        raise AuthorizationFailureError("authority socket request_id exceeds bound")
    if not isinstance(nonce, str) or not (SOCKET_NONCE_BYTES <= len(nonce) <= 128):
        raise AuthorizationFailureError("authority socket nonce is required")
    if not isinstance(expires_at, str) or not expires_at.strip():
        raise AuthorizationFailureError("authority socket expiry is required")
    try:
        expires = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError) as exc:
        raise AuthorizationFailureError(
            "authority socket request expiry is malformed"
        ) from exc
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        raise AuthorizationFailureError("authority socket request expired")
    if expires > datetime.now(timezone.utc) + timedelta(seconds=SOCKET_REQUEST_TTL_SECONDS + 5):
        raise AuthorizationFailureError("authority socket request TTL exceeds bound")
    return request_id


def bind_socket_response(
    *,
    request: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, Any]:
    bound = dict(response)
    for field in ("socket_request_id", "socket_nonce", "socket_expires_at"):
        bound[field] = request[field]
    return bound
