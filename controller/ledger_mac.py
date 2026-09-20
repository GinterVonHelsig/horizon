"""Authority-held ledger MAC key loaded from pinned trust material only."""

from __future__ import annotations

from pathlib import Path

from authority_pins import LEDGER_MAC_KEY_PATH
from exceptions import AuthorizationFailureError
from pinned_trust import read_pinned_bytes

# Legacy env names retained only so runtime can reject them if present.
FORBIDDEN_LEDGER_MAC_ENVS = (
    "COMMS01_LEDGER_MAC_SECRET",
    "COMMS01_LEDGER_MAC_KEY_FILE",
)


def ledger_mac_key() -> str | None:
    import os

    for env_name in FORBIDDEN_LEDGER_MAC_ENVS:
        if os.environ.get(env_name):
            raise AuthorizationFailureError(
                f"workflow must not supply ledger MAC via {env_name}; use pinned authority material"
            )
    if not Path(LEDGER_MAC_KEY_PATH).is_file():
        return None
    secret = read_pinned_bytes(
        LEDGER_MAC_KEY_PATH,
        require_root_owner=True,
    ).decode("utf-8").strip()
    if not secret:
        return None
    return secret


def require_ledger_mac_key() -> str:
    key = ledger_mac_key()
    if not key:
        raise AuthorizationFailureError("ledger MAC key is unavailable from authority boundary")
    return key
