"""Fixed Comms-01 attestation file loading and verification."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from authority_pins import (
    AUTHORITY_DATABASE_ROLE,
    COMMS01_DATABASE_ENDPOINTS,
    COMMS01_DATABASE_PORT,
    COMMS01_ATTESTATION_PATH,
    WORKFLOW_DATABASE_ROLE,
)
from exceptions import ScopeBoundaryViolationError
from pinned_trust import read_json_file

COMMS01_SCOPE = "comms-01"
ENVIRONMENT_MARKER = "isolated-top-delivery"
COMMS01_DATABASE_NAME = "top_delivery_control_p1"
COMMS01_WORKFLOW_ROLE = WORKFLOW_DATABASE_ROLE
COMMS01_AUTHORITY_ROLE = AUTHORITY_DATABASE_ROLE
COMMS01_CONTROLLER_SERVICE = "top-delivery-controller"


@dataclass(frozen=True)
class Comms01Attestation:
    scope: str
    environment_marker: str
    host_fingerprint: str
    database_name: str
    database_role: str  # legacy single-role field; prefer workflow/authority fields
    workflow_database_role: str
    authority_database_role: str
    controller_service: str
    database_endpoint: str
    database_port: int
    authority_service: str


def _host_scope_prefix() -> str:
    return f"comms01-{socket.gethostname()}"


def _runtime_host_fingerprint() -> str:
    return _host_scope_prefix()


def _attestation_host_matches(attestation_fingerprint: str, runtime_fingerprint: str) -> bool:
    if attestation_fingerprint == runtime_fingerprint:
        return True
    prefix = _host_scope_prefix()
    # Legacy attestations may pin an optional uid suffix after the host prefix.
    return attestation_fingerprint.startswith(f"{prefix}-")


def load_comms01_attestation(*, strict_owner: bool = True) -> Comms01Attestation:
    payload = read_json_file(
        COMMS01_ATTESTATION_PATH,
        strict_owner=strict_owner,
        require_root_owner=strict_owner,
    )
    required = (
        "scope",
        "environment_marker",
        "host_fingerprint",
        "database_name",
        "controller_service",
        "database_port",
    )
    missing = [field for field in required if not payload.get(field)]
    if missing:
        raise ScopeBoundaryViolationError(
            f"attestation file is missing required fields: {', '.join(missing)}"
        )
    workflow_role = str(
        payload.get("workflow_database_role")
        or payload.get("database_role")
        or WORKFLOW_DATABASE_ROLE
    )
    authority_role = str(
        payload.get("authority_database_role") or AUTHORITY_DATABASE_ROLE
    )
    # Legacy single database_role may name either principal; never require both at once.
    legacy_role = str(payload.get("database_role") or workflow_role)
    endpoint = str(payload.get("database_endpoint") or "local")
    try:
        database_port = int(payload["database_port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ScopeBoundaryViolationError(
            "attestation database_port must be an integer"
        ) from exc
    if not 1 <= database_port <= 65535:
        raise ScopeBoundaryViolationError("attestation database_port is invalid")
    if database_port != COMMS01_DATABASE_PORT:
        raise ScopeBoundaryViolationError(
            "attestation database_port is not the pinned Comms-01 port"
        )
    authority_service = str(
        payload.get("authority_service") or "top-delivery-authority-service"
    )
    return Comms01Attestation(
        scope=str(payload["scope"]),
        environment_marker=str(payload["environment_marker"]),
        host_fingerprint=str(payload["host_fingerprint"]),
        database_name=str(payload["database_name"]),
        database_role=legacy_role,
        workflow_database_role=workflow_role,
        authority_database_role=authority_role,
        controller_service=str(payload["controller_service"]),
        database_endpoint=endpoint,
        database_port=database_port,
        authority_service=authority_service,
    )


def assert_attestation_matches_runtime(attestation: Comms01Attestation) -> None:
    from authority_test_seam import allowed_test_owner_uids

    if attestation.scope != COMMS01_SCOPE:
        raise ScopeBoundaryViolationError("attestation scope mismatch")
    if attestation.environment_marker != ENVIRONMENT_MARKER:
        raise ScopeBoundaryViolationError("attestation environment marker mismatch")
    if attestation.database_name != COMMS01_DATABASE_NAME:
        raise ScopeBoundaryViolationError("attestation database is not the pinned Comms-01 control database")
    if attestation.workflow_database_role != COMMS01_WORKFLOW_ROLE:
        raise ScopeBoundaryViolationError("attestation workflow role is not the pinned Comms-01 role")
    if attestation.authority_database_role != COMMS01_AUTHORITY_ROLE:
        raise ScopeBoundaryViolationError("attestation authority role is not the pinned Comms-01 role")
    if attestation.controller_service != COMMS01_CONTROLLER_SERVICE:
        raise ScopeBoundaryViolationError("attestation controller service is not the pinned Comms-01 service")
    if attestation.database_endpoint.lower() not in COMMS01_DATABASE_ENDPOINTS:
        raise ScopeBoundaryViolationError("attestation database endpoint is outside the Comms-01 allowlist")
    runtime_fingerprint = _runtime_host_fingerprint()
    if _attestation_host_matches(attestation.host_fingerprint, runtime_fingerprint):
        return
    if attestation.host_fingerprint == "comms01-isolated-top-delivery-local" and allowed_test_owner_uids():
        return
    raise ScopeBoundaryViolationError(
        f"attestation host fingerprint mismatch: expected {runtime_fingerprint!r}, got {attestation.host_fingerprint!r}"
    )


def assert_runtime_database_binding(
    attestation: Comms01Attestation,
    *,
    actual_database: str,
    actual_role: str,
    database_url: str,
    expected_role: str | None = None,
) -> None:
    url_database = urlsplit(database_url).path.lstrip("/")
    if url_database != actual_database:
        raise ScopeBoundaryViolationError("database URL does not match connected database")
    if actual_database != attestation.database_name:
        raise ScopeBoundaryViolationError("connected database does not match attestation")
    role = expected_role or attestation.workflow_database_role
    if actual_role != role:
        raise ScopeBoundaryViolationError(
            f"connected database role {actual_role!r} does not match expected {role!r}"
        )


def assert_endpoint_binding(attestation: Comms01Attestation, database_url: str) -> None:
    parsed = urlsplit(database_url)
    try:
        url_port = parsed.port
    except ValueError as exc:
        raise ScopeBoundaryViolationError("database URL contains an invalid port") from exc
    query = parse_qs(parsed.query, keep_blank_values=True)
    routing_counts: dict[str, int] = {}
    for key, values in query.items():
        lowered = key.lower()
        if lowered in {"host", "port"}:
            routing_counts[lowered] = routing_counts.get(lowered, 0) + len(values)
    if any(count > 1 for count in routing_counts.values()):
        raise ScopeBoundaryViolationError(
            "database URL contains duplicate host/port overrides"
        )
    query_port_values = [
        value
        for key, values in query.items()
        if key.lower() == "port"
        for value in values
    ]
    try:
        query_port = int(query_port_values[0]) if query_port_values else None
    except ValueError as exc:
        raise ScopeBoundaryViolationError(
            "database URL contains an invalid port override"
        ) from exc
    effective_port = query_port if query_port is not None else url_port
    if effective_port is None:
        raise ScopeBoundaryViolationError(
            "database URL must explicitly bind the PostgreSQL port"
        )
    if effective_port != attestation.database_port:
        raise ScopeBoundaryViolationError(
            f"database URL port {effective_port!r} does not match pinned port {attestation.database_port!r}"
        )
    host = parsed.hostname or ""
    # local / Unix socket URLs are represented as endpoint "local"
    if attestation.database_endpoint.lower() in COMMS01_DATABASE_ENDPOINTS:
        if host not in {"", "localhost", "127.0.0.1", "::1"}:
            raise ScopeBoundaryViolationError(
                f"database endpoint host {host!r} is not the pinned local endpoint"
            )
        return
    if host != attestation.database_endpoint and database_url != attestation.database_endpoint:
        raise ScopeBoundaryViolationError(
            "database endpoint does not match pinned attestation endpoint"
        )
