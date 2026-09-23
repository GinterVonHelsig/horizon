"""Authority-socket-only signing material; never import from workflow paths."""

from __future__ import annotations

from authority_pins import AUTHORITY_WRITE_SIGNING_SECRET_PATH
from exceptions import AuthorizationFailureError
from pinned_trust import read_pinned_bytes


def authority_write_signing_secret() -> str:
    try:
        secret = read_pinned_bytes(
            AUTHORITY_WRITE_SIGNING_SECRET_PATH, require_root_owner=True,
        ).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise AuthorizationFailureError(
            "authority write signing secret trust anchor is unreadable"
        ) from exc
    if not secret:
        raise AuthorizationFailureError("authority write signing secret trust anchor is empty")
    return secret
