"""Executable Comms-01 scope and boundary enforcement."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from authority_pins import (
    ADMIN_DATABASE_ROLES,
    AUTHORITY_DATABASE_ROLE,
    COMMS01_DATABASE_PORT,
    MIGRATION_DATABASE_ROLE,
    WORKFLOW_DATABASE_ROLE,
)
from attestation import (
    COMMS01_SCOPE,
    ENVIRONMENT_MARKER,
    Comms01Attestation,
    assert_attestation_matches_runtime,
    assert_runtime_database_binding,
    load_comms01_attestation,
    COMMS01_DATABASE_ENDPOINTS,
)
from authority_test_seam import allowed_test_owner_uids
from disposable_capability import load_signed_disposable_capability
from exceptions import AuthorizationFailureError, ScopeBoundaryViolationError

ALLOWED_CONTROLLER_SERVICES = frozenset(
    {
        "top-delivery-controller",
        "top-delivery-supervisor",
        "top-delivery-signal-adapter",
        "top-delivery-hermes",
        "top-delivery-signal-daemon",
        "top-delivery-worker",
    }
)
ALLOWED_DATABASE_NAME = "top_delivery_control_p1"
DISPOSABLE_DB_PREFIXES = ("td_test_", "td_downgrade_")
ALLOWED_DISPOSABLE_ROLES = frozenset(
    {
        "postgres",
        WORKFLOW_DATABASE_ROLE,
        AUTHORITY_DATABASE_ROLE,
    }
)
FORBIDDEN_DB_MARKERS = frozenset(
    {
        "trading",
        "ledger",
        "broker",
        "production",
        "auth",
        "oanda",
        "alpaca",
        "postgres-01",
    }
)
FORBIDDEN_HOST_MARKERS = frozenset(
    {
        "postgres-01",
        "trading",
        "production",
        "broker",
        "home/trading",
    }
)
BROKER_ENDPOINT_MARKERS = frozenset(
    {
        "oanda",
        "alpaca",
        "broker",
        "api-fxtrade",
        "paper-api",
    }
)

# libpq accepts connection-target parameters in the URI query string. The
# parsed URI hostname is not authoritative unless these overrides are absent;
# otherwise postgresql:///db?host=remote can bypass a host check.
LIBPQ_TARGET_OVERRIDE_KEYS = frozenset(
    {"host", "hostaddr", "port", "service", "dbname", "user"}
)
LIBPQ_TARGET_ENV_KEYS = (
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGDATABASE",
    "PGUSER",
)
PINNED_LOCAL_SOCKET_PATH = "/var/run/postgresql"


def strict_libpq_query(database_url: str) -> dict[str, list[str]]:
    """Parse libpq overrides once and reject duplicate routing parameters."""
    parsed = urlsplit(database_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    routing_counts: dict[str, int] = {}
    for key, values in query.items():
        lowered = key.lower()
        if lowered in {"host", "port"}:
            routing_counts[lowered] = routing_counts.get(lowered, 0) + len(values)
    duplicates = sorted(
        key for key, count in routing_counts.items() if count != 1
    )
    if duplicates:
        raise ScopeBoundaryViolationError(
            "database URL contains duplicate libpq routing parameter(s): "
            + ", ".join(duplicates)
        )
    if parsed.hostname and any(key.lower() == "host" for key in query):
        raise ScopeBoundaryViolationError(
            "database URL must not combine an authority host with a libpq host override"
        )
    if parsed.port is not None and any(key.lower() == "port" for key in query):
        raise ScopeBoundaryViolationError(
            "database URL must not combine an authority port with a libpq port override"
        )
    return query


def assert_effective_libpq_target(
    database_url: str,
    *,
    allow_pinned_unix_socket: bool = False,
    pinned_port: int | None = None,
) -> None:
    parsed = urlsplit(database_url)
    parsed_host = (parsed.hostname or "").lower()
    if "," in parsed_host:
        raise AuthorizationFailureError(
            "database URL contains a multi-host libpq authority"
        )
    inherited = [key for key in LIBPQ_TARGET_ENV_KEYS if key in os.environ]
    if inherited:
        raise AuthorizationFailureError(
            "database connection has unpinned libpq target environment: "
            + ", ".join(inherited)
        )
    query = strict_libpq_query(database_url)
    overrides = sorted(key for key in query if key.lower() in LIBPQ_TARGET_OVERRIDE_KEYS)
    if overrides:
        socket_host = query.get("host") == [PINNED_LOCAL_SOCKET_PATH]
        socket_port = query.get("port") == [str(pinned_port)] if pinned_port is not None else False
        if not (
            allow_pinned_unix_socket
            and not parsed_host
            and set(overrides) <= {"host", "port"}
            and socket_host
            and socket_port
        ):
            raise AuthorizationFailureError(
                "database URL contains unpinned libpq target override(s): "
                + ", ".join(overrides)
            )


@dataclass(frozen=True)
class Comms01Identity:
    scope: str
    environment_marker: str
    host_fingerprint: str
    database_name: str
    database_role: str
    controller_service: str


def _attestation_identity() -> Comms01Attestation:
    attestation = load_comms01_attestation()
    assert_attestation_matches_runtime(attestation)
    return attestation


def default_identity() -> Comms01Identity:
    attestation = _attestation_identity()
    return Comms01Identity(
        scope=attestation.scope,
        environment_marker=attestation.environment_marker,
        host_fingerprint=attestation.host_fingerprint,
        database_name=attestation.database_name,
        database_role=attestation.database_role,
        controller_service=attestation.controller_service,
    )


def _fail(reason: str) -> None:
    raise ScopeBoundaryViolationError(reason)


def verify_connection_identity(
    *,
    database_url: str,
    connection: Any | None = None,
    expected_role: str | None = None,
    expected_service: str | None = None,
    allow_disposable_inspection: bool = False,
) -> tuple[str, str]:
    """Verify current_database/current_user after connection; do not trust URL labels alone.

    expected_role selects the immutable principal for this process:
    workflow vs authority. A single attestation cannot require both at once.
    """
    assert_database_url(database_url)
    from attestation import assert_endpoint_binding

    database_name = urlsplit(database_url).path.lstrip("/")
    if connection is None:
        import psycopg2

        conn = psycopg2.connect(database_url)
        close_after = True
    else:
        conn = connection
        close_after = False
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT current_database(), current_user, "
                "inet_server_addr()::text, inet_server_port()"
            )
            row = cur.fetchone()
    finally:
        if close_after:
            conn.close()
    if row is None:
        _fail("could not resolve database connection identity")
    actual_database, actual_role = row[0], row[1]
    # PostgreSQL renders inet values with a CIDR suffix (for example
    # ``127.0.0.1/32``).  Compare the address, not its display mask.
    actual_server_address = str(row[2] or "").split("/", 1)[0].lower()
    actual_server_port = row[3]
    if actual_database != database_name:
        _fail(
            f"database identity mismatch: URL targets {database_name!r}, connected to {actual_database!r}"
        )
    attestation = _attestation_identity()
    assert_endpoint_binding(attestation, database_url)
    pinned_endpoint = attestation.database_endpoint.lower()
    disposable = is_disposable_test_database(database_url)
    url_host = (urlsplit(database_url).hostname or "").lower()
    unix_socket_target = not url_host
    if pinned_endpoint in {"local", "localhost", "127.0.0.1", "::1"}:
        if actual_server_address == "" and not (disposable and unix_socket_target):
            _fail("connected PostgreSQL server did not report a local address")
        if actual_server_address not in {"", "127.0.0.1", "::1"}:
            _fail(
                "connected PostgreSQL server address is outside the pinned local Comms-01 endpoint"
            )
    elif str(actual_server_address or "").lower() != pinned_endpoint:
        _fail(
            f"connected PostgreSQL server address {actual_server_address!r} "
            f"does not match pinned endpoint {attestation.database_endpoint!r}"
        )
    if (actual_server_port is None or int(actual_server_port) <= 0) and not (
        disposable and unix_socket_target
    ):
        _fail("connected PostgreSQL server did not report a valid port")
    if actual_server_port is not None and int(actual_server_port) != attestation.database_port:
        _fail(
            f"connected PostgreSQL server port {actual_server_port!r} does not match "
            f"pinned port {attestation.database_port!r}"
        )
    if expected_service is not None:
        assert_service_name(expected_service)
    harness = load_signed_disposable_capability()
    role_needed = expected_role or attestation.workflow_database_role
    if disposable:
        if harness is None:
            _fail("disposable database requires an installed signed disposable capability")
        allowed = {
            harness.database_role,
            WORKFLOW_DATABASE_ROLE,
            AUTHORITY_DATABASE_ROLE,
            "postgres",
            *ALLOWED_DISPOSABLE_ROLES,
        }
        root_inspection_allowed = (
            allow_disposable_inspection
            and actual_role == "root"
            and harness is not None
            and harness.operation
            in {
                "create_database",
                "drop_database",
                "migration_downgrade",
                "disposable_downgrade",
            }
        )
        if actual_role not in allowed and not root_inspection_allowed:
            _fail(f"disposable database role mismatch: connected as {actual_role!r}")
        if expected_role is not None and actual_role != expected_role:
            # Migration inspection may use an administrator connection, but a
            # runtime controller or authority connection must prove its exact
            # pinned LOGIN principal even on a disposable database. Database
            # naming alone is never a superuser/role-separation exception.
            inspection_allowed = (
                allow_disposable_inspection
                and actual_role in {"postgres", "root"}
                and harness is not None
                and harness.operation in {
                    "create_database",
                    "drop_database",
                    "migration_downgrade",
                    "disposable_downgrade",
                }
            )
            if not inspection_allowed:
                _fail(
                    f"disposable runtime role mismatch: expected {expected_role!r}, connected as {actual_role!r}"
                )
    else:
        assert_runtime_database_binding(
            attestation,
            actual_database=actual_database,
            actual_role=actual_role,
            database_url=database_url,
            expected_role=role_needed,
        )
    if not disposable and actual_database != attestation.database_name:
        _fail(
            f"canonical database mismatch: expected {attestation.database_name!r}, connected to {actual_database!r}"
        )
    return actual_database, actual_role


def assert_scope_label(scope: str) -> None:
    if scope != COMMS01_SCOPE:
        _fail(f"scope must be {COMMS01_SCOPE!r}, got {scope!r}")


def _live_service_units_from_cgroup() -> list[str]:
    try:
        cgroup = Path("/proc/self/cgroup").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    return re.findall(r"(?:^|/)([^/\n]+\.service)(?:/|$)", cgroup)


ENTRYPOINT_DELEGATE_UNIT_PREFIX = "top-delivery-entrypoint@"


def _entrypoint_delegate_unit_matches(service_name: str, cgroup_unit: str) -> bool:
    """True when ``cgroup_unit`` is an attested entrypoint delegate for ``service_name``."""
    unit = cgroup_unit.strip().lower()
    prefix = ENTRYPOINT_DELEGATE_UNIT_PREFIX
    if not unit.startswith(prefix):
        return False
    instance = unit[len(prefix):]
    if instance.endswith(".service"):
        instance = instance[:-8]
    return instance == service_name.strip().lower()


def _allowed_comms01_services(attestation: Comms01Attestation) -> frozenset[str]:
    return frozenset(
        {
            *ALLOWED_CONTROLLER_SERVICES,
            attestation.controller_service.strip().lower(),
            attestation.authority_service.strip().lower(),
        }
    )


def resolve_live_comms01_service_name() -> str:
    """Return the attested Comms-01 service name for the current live process."""
    attestation = _attestation_identity()
    allowed = _allowed_comms01_services(attestation)
    normalized_units = {
        unit.strip().lower() for unit in _live_service_units_from_cgroup()
    }
    for unit in normalized_units:
        name = unit.removesuffix(".service")
        if name in allowed:
            return name
        for candidate in sorted(allowed):
            if _entrypoint_delegate_unit_matches(candidate, unit):
                return candidate
    if not normalized_units:
        if "pytest" in sys.modules and allowed_test_owner_uids():
            return attestation.controller_service.strip().lower()
        _fail("live Comms-01 service unit could not be resolved")
    _fail(
        "live process service is outside Comms-01 boundary: "
        + ", ".join(sorted(normalized_units))
    )


def assert_service_name(service_name: str) -> None:
    normalized = service_name.strip().lower()
    attestation = _attestation_identity()
    allowed = _allowed_comms01_services(attestation)
    if normalized not in allowed:
        _fail(f"service {service_name!r} is outside Comms-01 controller boundary")
    if normalized not in {
        attestation.controller_service.strip().lower(),
        attestation.authority_service.strip().lower(),
        *ALLOWED_CONTROLLER_SERVICES,
    }:
        _fail("controller service attestation mismatch")
    # A caller-supplied label is not sufficient positive identity.  When the
    # process is launched by systemd, bind the requested role to the actual
    # cgroup unit.  The isolated pytest harness has no service unit and is
    # intentionally allowed to exercise the same code path.
    service_units = _live_service_units_from_cgroup()
    normalized_units = {unit.strip().lower() for unit in service_units}
    if service_units and f"{normalized}.service" not in normalized_units:
        if not any(
            _entrypoint_delegate_unit_matches(normalized, unit) for unit in normalized_units
        ):
            _fail(
                f"live process service does not match Comms-01 service {service_name!r}"
            )
    if not service_units:
        # A missing cgroup unit is acceptable only in a signed disposable
        # pytest harness with the explicit in-process test seam. A signed
        # disposable capability must never relax live service identity.
        if "pytest" not in sys.modules or not allowed_test_owner_uids():
            _fail("live Comms-01 service unit could not be resolved")


def assert_database_url(database_url: str) -> str:
    attestation = _attestation_identity()
    assert_effective_libpq_target(
        database_url,
        allow_pinned_unix_socket=True,
        pinned_port=attestation.database_port,
    )
    parsed = urlsplit(database_url)
    try:
        url_port = parsed.port
    except ValueError as exc:
        raise ScopeBoundaryViolationError(
            "database URL contains an invalid port"
        ) from exc
    query = strict_libpq_query(database_url)
    query_port_values = query.get("port", [])
    if len(query_port_values) > 1:
        _fail("database URL contains multiple port overrides")
    query_port = None
    if query_port_values:
        try:
            query_port = int(query_port_values[0])
        except ValueError as exc:
            raise ScopeBoundaryViolationError("database URL contains an invalid port override") from exc
    effective_port = query_port if query_port is not None else url_port
    if effective_port is None:
        _fail("database URL must explicitly bind the pinned PostgreSQL port")
    if effective_port != attestation.database_port:
        _fail(
            f"database URL port {effective_port!r} does not match pinned port "
            f"{attestation.database_port!r}"
        )
    if parsed.scheme not in {"postgresql", "postgresql+psycopg2"}:
        _fail("database URL must be PostgreSQL for Comms-01 controller")
    database = parsed.path.lstrip("/")
    host = (parsed.hostname or "").lower()
    database_lower = database.lower()
    userinfo = f"{parsed.username or ''}:{parsed.password or ''}".lower()
    for marker in FORBIDDEN_DB_MARKERS:
        if marker in host:
            _fail(f"forbidden production-like host marker: {marker}")
        if marker in database_lower and not (
            database == ALLOWED_DATABASE_NAME
            or any(database.startswith(prefix) for prefix in DISPOSABLE_DB_PREFIXES)
        ):
            _fail(f"forbidden production-like database marker: {marker}")
    for marker in BROKER_ENDPOINT_MARKERS:
        if marker in host or marker in userinfo:
            _fail(f"broker-like credential or host marker forbidden: {marker}")
    # Reject unmarked remote hosts that only look like the control DB by name.
    if database == ALLOWED_DATABASE_NAME and not host:
        _fail("canonical Comms-01 database URL must include an explicit pinned host")
    if database == ALLOWED_DATABASE_NAME and host not in {"localhost", "127.0.0.1", "::1"}:
        attestation = _attestation_identity()
        if attestation.database_endpoint == "local":
            _fail(f"non-local host {host!r} is not pinned for Comms-01 control database")
        if host != attestation.database_endpoint.lower():
            _fail(f"host {host!r} does not match pinned database endpoint")
    if is_disposable_test_database(database_url) and host not in {"", "localhost", "127.0.0.1", "::1"}:
        _fail("disposable Comms-01 validation databases must use a local endpoint")
    if is_disposable_test_database(database_url) and not host:
        if query.get("host") != [PINNED_LOCAL_SOCKET_PATH] or query_port != attestation.database_port:
            _fail("disposable database URL must use the pinned local socket and port")
    if not (
        database == ALLOWED_DATABASE_NAME
        or any(database.startswith(prefix) for prefix in DISPOSABLE_DB_PREFIXES)
    ):
        _fail(
            f"database {database!r} is not the Comms-01 control database or a disposable test database"
        )
    return database_url


def assert_host_fingerprint(host_fingerprint: str | None = None) -> None:
    attestation = _attestation_identity()
    actual = host_fingerprint or attestation.host_fingerprint
    if actual != attestation.host_fingerprint:
        _fail(f"host fingerprint mismatch: expected {attestation.host_fingerprint!r}, got {actual!r}")
    lowered = actual.lower()
    for marker in FORBIDDEN_HOST_MARKERS:
        if marker in lowered:
            _fail(f"forbidden host marker in fingerprint: {marker}")


def verified_local_host_fingerprint() -> str:
    """Return the host identity after attestation/runtime verification."""
    return _attestation_identity().host_fingerprint


def assert_environment_marker(marker: str | None = None) -> None:
    attestation = _attestation_identity()
    actual = marker or attestation.environment_marker
    if actual != ENVIRONMENT_MARKER:
        _fail(f"environment marker must be {ENVIRONMENT_MARKER!r}")


def reject_broker_endpoint(endpoint: str) -> None:
    lowered = endpoint.lower()
    for marker in BROKER_ENDPOINT_MARKERS:
        if marker in lowered:
            _fail(f"broker endpoint {endpoint!r} is forbidden in Comms-01 scope")


def reject_network_mutation(config: dict[str, Any]) -> None:
    for key in ("enable_network", "network_mutations", "iptables", "firewall", "route"):
        if config.get(key):
            _fail(f"network mutation via {key!r} is forbidden in Comms-01 scope")
    for endpoint in config.get("endpoints", []) or []:
        if isinstance(endpoint, str):
            reject_broker_endpoint(endpoint)


def assert_comms01_entrypoint(
    *,
    scope: str | None = None,
    database_url: str | None = None,
    service_name: str | None = None,
    host_fingerprint: str | None = None,
    environment_marker: str | None = None,
    extra_config: dict[str, Any] | None = None,
) -> Comms01Identity:
    """Fail closed before any Comms-01 side effect."""
    identity = default_identity()
    assert_environment_marker(environment_marker)
    assert_host_fingerprint(host_fingerprint)
    if scope is not None:
        assert_scope_label(scope)
    if database_url is not None:
        assert_database_url(database_url)
    if service_name is not None:
        assert_service_name(service_name)
    if extra_config:
        reject_network_mutation(extra_config)
    return identity


def is_disposable_test_database(database_url: str) -> bool:
    database = urlsplit(database_url).path.lstrip("/")
    return any(database.startswith(prefix) for prefix in DISPOSABLE_DB_PREFIXES)


def disposable_database_token(database_url: str) -> str:
    database = urlsplit(database_url).path.lstrip("/")
    if not is_disposable_test_database(database_url):
        _fail("database is not a verified disposable test database")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", database):
        _fail("invalid disposable database identifier")
    return database


def assert_admin_database_url(
    admin_url: str, *, allow_control_database: bool = False
) -> str:
    parsed = urlsplit(admin_url)
    database = parsed.path.lstrip("/")
    disposable = is_disposable_test_database(admin_url)
    capability = None
    try:
        attestation = _attestation_identity()
    except ScopeBoundaryViolationError:
        # A disposable Alembic child is deliberately a separate process and
        # cannot inherit the pytest-only host-fingerprint seam.  The exception
        # path is admitted only with an independently signed, root-installed
        # capability whose operation is bound to this target; a caller-chosen
        # td_test_* name is never sufficient to suppress attestation.
        capability = load_signed_disposable_capability()
        if (
            not disposable
            or capability is None
            or capability.operation not in {
            "create_database",
            "drop_database",
            "migration_downgrade",
            "disposable_downgrade",
            }
        ):
            raise
        if capability.database_name != database:
            raise AuthorizationFailureError(
                "signed disposable capability does not bind the administrative database target"
            )
        capability_roles = {parsed.username or ""}
        if capability.operation in {
            "migration_downgrade",
            "disposable_downgrade",
        }:
            # The signed witness authorizes the migration principal that will
            # be SET ROLE inside env.py; the outer URL remains the approved
            # administrative transport (root/postgres).
            capability_roles.add(MIGRATION_DATABASE_ROLE)
        if capability.database_role not in capability_roles:
            raise AuthorizationFailureError(
                "signed disposable capability does not bind the administrative database role"
            )
        if capability.database_port != COMMS01_DATABASE_PORT:
            raise AuthorizationFailureError(
                "signed disposable capability does not bind the pinned Comms-01 port"
            )
        attestation = None
    assert_effective_libpq_target(
        admin_url,
        allow_pinned_unix_socket=True,
        pinned_port=(
            attestation.database_port
            if attestation is not None
            else capability.database_port
        ),
    )
    if parsed.scheme not in {"postgresql", "postgresql+psycopg2"}:
        raise AuthorizationFailureError("admin database URL must be PostgreSQL")
    if parsed.username not in ADMIN_DATABASE_ROLES:
        raise AuthorizationFailureError(
            "admin database URL must use an approved local harness administrator role"
        )
    allowed_admin_databases = {"postgres", "template1"}
    if allow_control_database:
        allowed_admin_databases.add(ALLOWED_DATABASE_NAME)
    if database not in allowed_admin_databases and not disposable:
        raise AuthorizationFailureError(
            "admin database URL must target postgres/template1, the explicitly authorized control database, or a disposable harness database"
        )
    host = (parsed.hostname or "").lower()
    try:
        url_port = parsed.port
    except ValueError as exc:
        raise AuthorizationFailureError("admin database URL contains an invalid port") from exc
    query = strict_libpq_query(admin_url)
    query_port_values = query.get("port", [])
    if len(query_port_values) > 1:
        raise AuthorizationFailureError("admin database URL contains multiple port overrides")
    try:
        query_port = int(query_port_values[0]) if query_port_values else None
    except ValueError as exc:
        raise AuthorizationFailureError("admin database URL contains an invalid port override") from exc
    effective_port = query_port if query_port is not None else url_port
    for marker in FORBIDDEN_DB_MARKERS:
        if marker in host:
            raise AuthorizationFailureError(f"forbidden admin host marker: {marker}")
    # Administrative connections are used to create/drop disposable harness
    # databases. A disposable name never relaxes the endpoint pin. An empty
    # authority is accepted only when libpq is explicitly pinned to the local
    # socket and the attested port; the default socket/PGPORT must not decide
    # where destructive DDL runs.
    if host not in {"", "localhost", "127.0.0.1", "::1"}:
        raise AuthorizationFailureError(
            "admin database URL must use the pinned local Comms-01 endpoint"
        )
    pinned_endpoint = (
        attestation.database_endpoint.lower()
        if attestation is not None
        else capability.database_endpoint.lower()
    )
    if pinned_endpoint not in COMMS01_DATABASE_ENDPOINTS:
        raise AuthorizationFailureError(
            "admin database endpoint is not the pinned local Comms-01 endpoint"
        )
    pinned_port = attestation.database_port if attestation else capability.database_port
    if effective_port != pinned_port:
        raise AuthorizationFailureError(
            f"admin database URL port {effective_port!r} does not match pinned port "
            f"{pinned_port!r}"
        )
    if not host and (
        query.get("host") != [PINNED_LOCAL_SOCKET_PATH]
        or query_port != pinned_port
    ):
        raise AuthorizationFailureError(
            "admin database URL must explicitly pin the local PostgreSQL socket and port"
        )
    return admin_url


def verify_admin_connection_identity(admin_url: str, connection: Any) -> tuple[str, str]:
    """Verify the connected administrative identity before any database DDL."""
    assert_admin_database_url(admin_url)
    parsed = urlsplit(admin_url)
    expected_database = parsed.path.lstrip("/")
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT current_database(), session_user, current_user,
                   inet_server_addr()::text, inet_server_port(),
                   current_setting('port'), r.rolsuper, r.rolcreatedb
            FROM pg_roles AS r
            WHERE r.rolname = current_user
            """
        )
        row = cur.fetchone()
    if row is None:
        raise AuthorizationFailureError("could not resolve administrative PostgreSQL identity")
    (
        actual_database,
        session_role,
        actual_role,
        server_address,
        server_port,
        configured_port,
        is_superuser,
        can_create_db,
    ) = row
    attestation = _attestation_identity()
    if actual_database != expected_database:
        raise AuthorizationFailureError(
            f"administrative database identity mismatch: expected {expected_database!r}, got {actual_database!r}"
        )
    expected_role = parsed.username
    if not expected_role:
        raise AuthorizationFailureError(
            "administrative PostgreSQL URL must pin an explicit login role"
        )
    if session_role != expected_role or actual_role != expected_role:
        raise AuthorizationFailureError(
            "administrative PostgreSQL login/current role does not match the pinned URL role"
        )
    if expected_role not in ADMIN_DATABASE_ROLES:
        raise AuthorizationFailureError(
            f"administrative PostgreSQL role {expected_role!r} is not an approved local harness administrator"
        )
    if not actual_role or not (bool(is_superuser) or bool(can_create_db)):
        raise AuthorizationFailureError(
            f"administrative PostgreSQL role {actual_role!r} lacks database administration authority"
        )
    if int(configured_port) != attestation.database_port:
        raise AuthorizationFailureError(
            f"configured PostgreSQL port {configured_port!r} does not match pinned port "
            f"{attestation.database_port!r}"
        )
    if server_port is not None and int(server_port) != attestation.database_port:
        raise AuthorizationFailureError(
            f"effective PostgreSQL port {server_port!r} does not match pinned port "
            f"{attestation.database_port!r}"
        )
    if server_port is None and parsed.hostname:
        raise AuthorizationFailureError(
            "TCP administrative connection did not report an effective server port"
        )
    actual_address = str(server_address or "").split("/", 1)[0].lower()
    if parsed.hostname:
        if actual_address not in {"127.0.0.1", "::1"}:
            raise AuthorizationFailureError(
                f"connected administrative address {actual_address!r} is not loopback"
            )
    elif actual_address:
        raise AuthorizationFailureError(
            f"pinned Unix-socket administrative connection reported address {actual_address!r}"
        )
    return str(actual_database), str(actual_role)
