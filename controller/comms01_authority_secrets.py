"""Controller-visible authority configuration (verification keys only)."""

from __future__ import annotations

import json
import os
from authority_pins import (
    CURRENT_OPERATOR_KEY_VERSION,
    CURRENT_TERRA_RECEIPT_KEY_VERSION,
    OPERATOR_PUBLIC_KEYS_PATH,
    TERRA_RECEIPT_PUBLIC_KEYS_PATH,
)
from exceptions import AuthorizationFailureError
from operator_asymmetric import operator_public_key_for_version, parse_public_keys
from pinned_trust import read_pinned_bytes

FORBIDDEN_WORKFLOW_SECRET_ENVS = (
    "COMMS01_AUTHORITY_WRITE_CREDENTIAL",
    "COMMS01_AUTHORITY_WRITE_CREDENTIAL_FILE",
    "COMMS01_AUTHORITY_WRITE_SIGNING_SECRET",
    "COMMS01_AUTHORITY_WRITE_SIGNING_SECRET_FILE",
    "COMMS01_OPERATOR_SIGNING_KEY",
    "COMMS01_OPERATOR_SIGNING_KEY_FILE",
    "COMMS01_BOOTSTRAP_OPERATOR_TOKEN",
    "COMMS01_OPERATOR_PUBLIC_KEYS",
    "COMMS01_OPERATOR_PUBLIC_KEYS_FILE",
    "COMMS01_AUTHORITY_SOCKET",
    # Terra receipt signing material belongs to an out-of-band signer; the
    # controller must reject attempts to inject it through its environment.
    "COMMS01_TERRA_RECEIPT_SIGNING_KEY",
    "COMMS01_TERRA_RECEIPT_SIGNING_KEY_FILE",
)


def operator_public_keys() -> dict[int, str]:
    try:
        raw = read_pinned_bytes(
            OPERATOR_PUBLIC_KEYS_PATH,
            require_root_owner=True,
        ).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise AuthorizationFailureError(
            "operator public keys trust anchor is unreadable"
        ) from exc
    if not raw:
        raise AuthorizationFailureError("operator public keys trust anchor is empty")
    return parse_public_keys(raw)


def operator_verification_key(*, key_version: int | None = None) -> str:
    version = CURRENT_OPERATOR_KEY_VERSION if key_version is None else key_version
    if version != CURRENT_OPERATOR_KEY_VERSION:
        raise AuthorizationFailureError(
            f"operator key version {version} is not the current pinned version"
        )
    return operator_public_key_for_version(operator_public_keys(), version)


def terra_receipt_public_keys() -> dict[int, str]:
    try:
        raw = read_pinned_bytes(
            TERRA_RECEIPT_PUBLIC_KEYS_PATH,
            require_root_owner=True,
        ).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise AuthorizationFailureError(
            "Terra receipt public keys trust anchor is unreadable"
        ) from exc
    if not raw:
        raise AuthorizationFailureError("Terra receipt public keys trust anchor is empty")
    return parse_public_keys(raw)


def terra_receipt_verification_key(*, key_version: int | None = None) -> str:
    version = (
        CURRENT_TERRA_RECEIPT_KEY_VERSION
        if key_version is None
        else int(key_version)
    )
    if version != CURRENT_TERRA_RECEIPT_KEY_VERSION:
        raise AuthorizationFailureError(
            f"Terra receipt key version {version} is not the current pinned version"
        )
    return operator_public_key_for_version(terra_receipt_public_keys(), version)


def workflow_may_not_access_authority_secrets() -> None:
    """Fail closed when workflow code attempts to load authority signing material."""
    for env_name in FORBIDDEN_WORKFLOW_SECRET_ENVS:
        if os.environ.get(env_name):
            raise AuthorizationFailureError(
                f"workflow path must not access authority secret env {env_name}"
            )
