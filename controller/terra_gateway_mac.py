"""Authority-held Terra gateway MAC key loaded from pinned trust material."""

from __future__ import annotations

from pathlib import Path

from authority_pins import TERRA_GATEWAY_MAC_KEY_PATH
from exceptions import AuthorizationFailureError
from pinned_trust import read_pinned_bytes


def terra_gateway_mac_key() -> str | None:
    path = Path(TERRA_GATEWAY_MAC_KEY_PATH)
    if not path.is_file():
        return None
    secret = read_pinned_bytes(
        TERRA_GATEWAY_MAC_KEY_PATH,
        require_root_owner=True,
    ).decode("utf-8").strip()
    return secret or None


def require_terra_gateway_mac_key() -> str:
    key = terra_gateway_mac_key()
    if not key:
        raise AuthorizationFailureError(
            "Terra gateway MAC key is unavailable from authority boundary"
        )
    return key


__all__ = ["require_terra_gateway_mac_key", "terra_gateway_mac_key"]
