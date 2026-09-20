"""Pinned Comms-01 workflow database target (no caller URL substitution)."""

from __future__ import annotations

from urllib.parse import urlsplit

from authority_pins import WORKFLOW_DATABASE_TARGET_PATH, WORKFLOW_DATABASE_ROLE
from comms01_scope import (
    assert_database_url,
    assert_effective_libpq_target,
    is_disposable_test_database,
)
from disposable_capability import load_signed_disposable_capability
from exceptions import AuthorizationFailureError, ScopeBoundaryViolationError
from pinned_trust import read_json_file


def load_workflow_database_target() -> dict[str, str | int]:
    payload = read_json_file(
        WORKFLOW_DATABASE_TARGET_PATH,
        strict_owner=True,
        require_root_owner=True,
    )
    required = (
        "database_url",
        "database_name",
        "database_role",
        "database_endpoint",
        "database_port",
    )
    missing = [field for field in required if not payload.get(field)]
    if missing:
        raise AuthorizationFailureError(
            f"workflow database target missing fields: {', '.join(missing)}"
        )
    if str(payload["database_role"]) != WORKFLOW_DATABASE_ROLE:
        raise AuthorizationFailureError(
            "workflow database target role must be the workflow LOGIN principal"
        )
    try:
        database_port = int(payload["database_port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorizationFailureError("workflow database target port is invalid") from exc
    if not 1 <= database_port <= 65535:
        raise AuthorizationFailureError("workflow database target port is outside valid range")
    target: dict[str, str | int] = {
        "database_url": str(payload["database_url"]),
        "database_name": str(payload["database_name"]),
        "database_role": str(payload["database_role"]),
        "database_endpoint": str(payload["database_endpoint"]),
        "database_port": database_port,
        "controller_service": str(payload.get("controller_service") or "top-delivery-controller"),
    }
    parsed = urlsplit(target["database_url"])
    if parsed.port != database_port:
        raise AuthorizationFailureError(
            "workflow database target URL/port does not match pinned database_port"
        )
    assert_effective_libpq_target(target["database_url"])
    if parsed.path.lstrip("/") != target["database_name"]:
        raise AuthorizationFailureError("workflow database target URL/database name mismatch")
    if (parsed.username or "") != target["database_role"]:
        raise AuthorizationFailureError("workflow database target URL/role mismatch")
    if target["database_endpoint"] not in {"local", "localhost", "127.0.0.1", "::1"}:
        if (parsed.hostname or "").lower() != target["database_endpoint"].lower():
            raise AuthorizationFailureError("workflow database target endpoint mismatch")
    return target


def resolve_workflow_database_url(caller_url: str | None) -> str:
    """Resolve the immutable workflow target; disposable harness URLs require capability."""
    if caller_url is None:
        return load_workflow_database_target()["database_url"]
    assert_database_url(caller_url)
    if is_disposable_test_database(caller_url):
        database_name = urlsplit(caller_url).path.lstrip("/")
        capability = load_signed_disposable_capability()
        if capability is None:
            raise AuthorizationFailureError(
                "disposable workflow target requires a verified signed capability"
            )
        if capability.database_name != database_name:
            raise AuthorizationFailureError("disposable workflow target capability mismatch")
        return caller_url
    target = load_workflow_database_target()
    pinned = target["database_url"]
    parsed_caller = urlsplit(caller_url)
    parsed_pinned = urlsplit(pinned)
    if (
        parsed_caller.path.lstrip("/") != target["database_name"]
        or (parsed_caller.hostname or "") != (parsed_pinned.hostname or "")
        or (parsed_caller.username or "") != (parsed_pinned.username or "")
    ):
        raise ScopeBoundaryViolationError(
            "caller database URL does not match pinned Comms-01 workflow target"
        )
    if caller_url != pinned:
        raise ScopeBoundaryViolationError(
            "non-disposable controller connections must use the pinned workflow database target"
        )
    return pinned
