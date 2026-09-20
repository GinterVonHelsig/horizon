"""Alembic migration environment for the TOP-DELIVERY control database."""

from __future__ import annotations

import os
from logging.config import fileConfig
from urllib.parse import parse_qs, urlsplit

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from authority_pins import (
    ADMIN_DATABASE_ROLES,
    MIGRATION_SOURCE_PROVENANCE_PATH,
    MIGRATION_DATABASE_ROLE,
    effective_migration_capability_role,
)
from migration_catalog import recovery_schema_relation_names, recovery_schema_routine_names
from migration_source_anchor import verify_migration_source_anchor
from migration_target import requested_revision

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None

# Tables whose populated rows are authority, execution, or review evidence.
# Keep this list in Python so the downgrade guard can probe intermediate
# revisions without querying relations that do not exist yet.
_PROTECTED_TABLES_BY_TARGET = {
    "006_longspan_authority": (
        "longspan_authority_history",
        "longspan_operator_challenges",
        "longspan_authority_receipts",
        "longspan_experiments",
        "longspan_evidence_ledger",
        "longspan_execution_audits",
        "longspan_execution_results",
        "longspan_execution_evidence",
        "longspan_auditor_receipts",
        "longspan_terra_receipts",
        "longspan_terra_receipt_attestations",
        "longspan_ledger_legacy_attestations",
        "longspan_mac_material",
        "longspan_mac_key_history",
    ),
    "005_longspan_hardening": (
        "longspan_authority_config",
        "longspan_authority_history",
        "longspan_operator_challenges",
        "longspan_authority_receipts",
        "longspan_experiments",
        "longspan_evidence_ledger",
        "longspan_execution_audits",
        "longspan_execution_results",
        "longspan_execution_evidence",
        "longspan_auditor_receipts",
        "longspan_terra_receipts",
        "longspan_terra_receipt_attestations",
        "longspan_ledger_legacy_attestations",
        "longspan_mac_material",
        "longspan_mac_key_history",
    ),
    "004_longspan_workflow": (
        "longspan_children",
        "longspan_plans",
        "longspan_execution_results",
        "longspan_auditor_receipts",
        "longspan_terra_receipts",
        "longspan_experiments",
        "longspan_evidence_ledger",
        "longspan_authority_config",
        "longspan_authority_history",
        "longspan_operator_challenges",
        "longspan_authority_receipts",
        "longspan_terra_receipt_attestations",
        "longspan_execution_audits",
        "longspan_execution_evidence",
        "longspan_ledger_legacy_attestations",
        "longspan_mac_material",
        "longspan_mac_key_history",
    ),
    # 007 is an explicit canonical downgrade target. Its migration module
    # performs additional database-side checks, but env.py must first admit
    # the exact reachable target so those checks can execute. The current 008
    # head is intentionally not admitted as a downgrade target until a future
    # child migration exists and its protected-table set is reviewed.
    "007_longspan_authority_hardening": (
        "longspan_authority_config",
        "longspan_authority_history",
        "longspan_operator_challenges",
        "longspan_authority_receipts",
        "longspan_experiments",
        "longspan_terra_receipt_attestations",
        "longspan_execution_audits",
        "longspan_execution_results",
        "longspan_execution_evidence",
        "longspan_auditor_receipts",
        "longspan_evidence_ledger",
        "longspan_terra_receipts",
        "longspan_ledger_legacy_attestations",
        "longspan_mac_material",
        "longspan_mac_key_history",
    ),
}

# A multi-step Alembic downgrade executes every inverse revision between the
# current head and the requested target. Verify every source body up front;
# checking only the requested target would leave intermediate destructive SQL
# outside the root-owned provenance boundary.
_DOWNGRADE_SOURCE_PATHS = {
    "007_longspan_authority_hardening": (
        "013_cleanup_expired_attempt",
        "014_horizon_project_ledger",
        "012_claim_parent_scope_fix",
        "011_goal_claim_fence_token_fix",
        "010_goal_claim_parent_task",
        "009_goal_schedule_task",
        "008_longspan_authority_repair",
        "007_longspan_authority_hardening",
    ),
    "006_longspan_authority": (
        "013_cleanup_expired_attempt",
        "014_horizon_project_ledger",
        "012_claim_parent_scope_fix",
        "011_goal_claim_fence_token_fix",
        "010_goal_claim_parent_task",
        "009_goal_schedule_task",
        "008_longspan_authority_repair",
        "007_longspan_authority_hardening",
        "006_longspan_authority",
    ),
    "005_longspan_hardening": (
        "013_cleanup_expired_attempt",
        "014_horizon_project_ledger",
        "012_claim_parent_scope_fix",
        "011_goal_claim_fence_token_fix",
        "010_goal_claim_parent_task",
        "009_goal_schedule_task",
        "008_longspan_authority_repair",
        "007_longspan_authority_hardening",
        "006_longspan_authority",
        "005_longspan_hardening",
    ),
    "004_longspan_workflow": (
        "013_cleanup_expired_attempt",
        "014_horizon_project_ledger",
        "012_claim_parent_scope_fix",
        "011_goal_claim_fence_token_fix",
        "010_goal_claim_parent_task",
        "009_goal_schedule_task",
        "008_longspan_authority_repair",
        "007_longspan_authority_hardening",
        "006_longspan_authority",
        "005_longspan_hardening",
        "004_longspan_workflow",
    ),
}

# Verify the complete canonical upgrade chain before any administrative
# connection checks or migration DDL.  A target-only check would allow a
# caller to dispatch a tampered intermediate revision while still ending at a
# trusted 008 head.
_UPGRADE_SOURCE_PATHS = {
    "004_longspan_workflow": (
        "004_longspan_workflow",
    ),
    "005_longspan_hardening": (
        "004_longspan_workflow",
        "005_longspan_hardening",
    ),
    "006_longspan_authority": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
    ),
    "007_longspan_authority_hardening": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
    ),
    "008_longspan_authority_repair": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
    ),
    "009_goal_schedule_task": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
    ),
    "010_goal_claim_parent_task": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
    ),
    "011_goal_claim_fence_token_fix": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
    ),
    "012_claim_parent_scope_fix": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
    ),
    "013_cleanup_expired_attempt": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
        "013_cleanup_expired_attempt",
    ),
    "014_horizon_project_ledger": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
        "013_cleanup_expired_attempt",
        "014_horizon_project_ledger",
    ),
    "015_subworkflow_handoff": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
        "013_cleanup_expired_attempt",
        "014_horizon_project_ledger",
        "015_subworkflow_handoff",
    ),
    "016_horizon_prereq_corr": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
        "013_cleanup_expired_attempt",
        "014_horizon_project_ledger",
        "015_subworkflow_handoff",
        "016_horizon_prereq_corr",
    ),
    "020_horizon_prereq_corr_live": (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
        "013_cleanup_expired_attempt",
        "014_requeue_blocked_parent_task",
        "015_recover_executor_contract_failure",
        "016_recover_exhausted_executor_contract_once",
        "017_parent_rollback_routine",
        "018_horizon_project_ledger_live",
        "019_subworkflow_handoff_live",
        "020_horizon_prereq_corr_live",
    ),
}

_UPGRADE_SOURCE_PATHS["021_goal_completion"] = _UPGRADE_SOURCE_PATHS["020_horizon_prereq_corr_live"] + ("021_goal_completion",)
_UPGRADE_SOURCE_PATHS["017_goal_completion_disposable"] = _UPGRADE_SOURCE_PATHS["016_horizon_prereq_corr"] + ("021_goal_completion", "017_goal_completion_disposable")

if set(_DOWNGRADE_SOURCE_PATHS) != set(_PROTECTED_TABLES_BY_TARGET):
    raise RuntimeError(
        "downgrade admission and protected-table maps must cover the same targets"
    )


def get_url() -> str:
    return os.environ.get(
        "TOP_DELIVERY_DATABASE_URL",
        config.get_main_option("sqlalchemy.url"),
    )


def _is_downgrade_command() -> bool:
    import sys

    if "downgrade" in sys.argv:
        return True
    cmd = getattr(config.cmd_opts, "cmd", None)
    if isinstance(cmd, (list, tuple)) and cmd:
        first = cmd[0]
        name = getattr(first, "__name__", str(first))
        return name == "downgrade"
    return False


def _requested_revision(command: str) -> str | None:
    """Return the raw Alembic target so the transport gate sees it too."""
    return requested_revision(command, config)


def _guard_upgrade(connection) -> None:
    """Verify the pinned administrative transport before any upgrade DDL."""
    raw_target = _requested_revision("upgrade")
    target = "021_goal_completion" if raw_target == "head" else raw_target
    if target not in {
        '021_goal_completion',
        '017_goal_completion_disposable',
        '004_longspan_workflow',
        '005_longspan_hardening',
        '006_longspan_authority',
        '007_longspan_authority_hardening',
        '008_longspan_authority_repair',
        '009_goal_schedule_task',
        '010_goal_claim_parent_task',
        '011_goal_claim_fence_token_fix',
        '012_claim_parent_scope_fix',
        '013_cleanup_expired_attempt',
        '014_horizon_project_ledger',
        '015_subworkflow_handoff',
        '016_horizon_prereq_corr',
        '014_requeue_blocked_parent_task',
        '015_recover_executor_contract_failure',
        '016_recover_exhausted_executor_contract_once',
        '017_parent_rollback_routine',
        '018_horizon_project_ledger_live',
        '019_subworkflow_handoff_live',
        '020_horizon_prereq_corr_live',
    }:
        raise RuntimeError(
            "upgrade blocked: target must be a full canonical migration revision"
        )
    for source_revision in _UPGRADE_SOURCE_PATHS[target]:
        verify_migration_source_anchor(
            source_revision,
            anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH,
        )
    from comms01_scope import (
        ALLOWED_DATABASE_NAME,
        DISPOSABLE_DB_PREFIXES,
        PINNED_LOCAL_SOCKET_PATH,
        assert_admin_database_url,
    )

    admin_url = get_url()
    assert_admin_database_url(admin_url, allow_control_database=True)
    parsed = urlsplit(admin_url)
    expected_database = parsed.path.lstrip("/")
    expected_role = parsed.username
    if not (
        expected_database == ALLOWED_DATABASE_NAME
        or any(expected_database.startswith(prefix) for prefix in DISPOSABLE_DB_PREFIXES)
    ):
        raise RuntimeError(
            "upgrade blocked: database is outside the Comms-01 control boundary"
        )
    row = connection.execute(
        text(
            """
            SELECT current_database(), current_user, session_user,
                   r.rolsuper, r.rolcreatedb,
                   inet_server_addr()::text, inet_server_port(),
                   current_setting('port')
            FROM pg_roles AS r
            WHERE r.rolname = current_user
            """
        )
    ).one_or_none()
    if row is None:
        raise RuntimeError("upgrade blocked: administrative PostgreSQL identity is unavailable")
    database_name, current_role, session_role, is_superuser, can_create_db, address, port, configured_port = row
    if (
        database_name != expected_database
        or current_role not in ADMIN_DATABASE_ROLES
        or session_role != expected_role
        or expected_role not in ADMIN_DATABASE_ROLES
        or not (bool(is_superuser) or bool(can_create_db))
    ):
        raise RuntimeError(
            "upgrade blocked: connected identity is not the pinned administrative transport"
        )
    query = parse_qs(parsed.query, keep_blank_values=True)
    query_ports = query.get("port", [])
    expected_port = int(query_ports[0]) if query_ports else parsed.port
    if (
        expected_port is None
        or configured_port is None
        or not str(configured_port).isdigit()
        or int(configured_port) != int(expected_port)
    ):
        raise RuntimeError(
            "upgrade blocked: PostgreSQL configured port does not match the explicitly pinned URL port"
        )
    pinned_socket = (
        not parsed.hostname
        and query.get("host") == [PINNED_LOCAL_SOCKET_PATH]
    )
    if port is None:
        if not pinned_socket:
            raise RuntimeError(
                "upgrade blocked: TCP PostgreSQL connection did not report an effective server port"
            )
    elif int(port) != int(expected_port):
        raise RuntimeError(
            "upgrade blocked: PostgreSQL server port does not match the explicitly pinned URL port"
        )
    if address is None and not pinned_socket:
        raise RuntimeError(
            "upgrade blocked: PostgreSQL connection did not prove its endpoint"
        )
    if address and str(address).split("/", 1)[0] not in {"127.0.0.1", "::1"}:
        raise RuntimeError("upgrade blocked: PostgreSQL server address is outside Comms-01")
    _verify_alembic_version_bootstrap(connection)
    if target == "008_longspan_authority_repair":
        # 008 may adopt an archive parked by an earlier downgrade. Validate
        # the private namespace while the pinned administrator still has
        # transport authority, before SET ROLE and before adoption DDL.
        _prepare_recovery_schema(connection)
    elif target == "007_longspan_authority_hardening":
        # A direct 007 upgrade must validate an already-planted recovery
        # namespace, but a clean disposable target does not need one.  Never
        # create or repair it from this migration path.
        recovery_exists = connection.execute(
            text("SELECT to_regnamespace('top_delivery_recovery')")
        ).scalar()
        if recovery_exists is not None:
            _prepare_recovery_schema(connection)
    # Only the separately provisioned NOLOGIN migration role may execute
    # revision DDL. The transport administrator is merely the out-of-band
    # identity that enters this role; a superuser must never be accepted as
    # the effective migration principal.
    connection.execute(text(f"SET ROLE {MIGRATION_DATABASE_ROLE}"))
    effective = connection.execute(
        text("SELECT current_user, session_user")
    ).one()
    if effective[0] != MIGRATION_DATABASE_ROLE or effective[1] != expected_role:
        raise RuntimeError(
            "upgrade blocked: PostgreSQL session did not enter the pinned migration role"
        )


def _prepare_recovery_schema(connection) -> None:
    """Validate the operator-created private archive namespace without DDL."""
    allowed_relations = set(recovery_schema_relation_names())
    allowed_routines = set(recovery_schema_routine_names())
    schema_row = connection.execute(
        text(
            """
            SELECT r.rolname,
                   EXISTS (
                       SELECT 1
                       FROM aclexplode(
                           COALESCE(n.nspacl, acldefault('n', n.nspowner))
                       ) AS acl
                       WHERE acl.grantee = 0
                         AND acl.privilege_type IN ('USAGE', 'CREATE')
                   ) AS public_access
            FROM pg_namespace AS n
            JOIN pg_roles AS r ON r.oid = n.nspowner
            WHERE n.nspname = 'top_delivery_recovery'
            """
        )
    ).one_or_none()
    if schema_row is None:
        raise RuntimeError(
            "migration blocked: top_delivery_recovery is absent; run the explicit "
            "migration_bootstrap step as the pinned PostgreSQL administrator"
        )
    owner, public_access = schema_row
    if owner != MIGRATION_DATABASE_ROLE or bool(public_access):
        raise RuntimeError(
            "downgrade blocked: existing recovery schema has an unexpected owner or PUBLIC ACL"
        )
    relation_rows = connection.execute(
        text(
            """
            SELECT c.relname, r.rolname
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            JOIN pg_roles AS r ON r.oid = c.relowner
            WHERE n.nspname = 'top_delivery_recovery'
              -- Index ACLs are not independently grantable relation
              -- privileges and some PostgreSQL versions expose their
              -- relacl catalog value as a non-1D array. Check only grantable
              -- relation kinds here; indexes remain covered by the owning
              -- table/relation inventory above.
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S', 'i', 'I')
            ORDER BY c.relname
            """
        )
    ).all()
    unexpected = [name for name, _owner in relation_rows if name not in allowed_relations]
    if unexpected or any(owner_name != MIGRATION_DATABASE_ROLE for _, owner_name in relation_rows):
        raise RuntimeError(
            "downgrade blocked: recovery schema contains unexpected or wrongly owned objects"
        )
    unsafe_relation_acl = connection.execute(
        text(
            """
            SELECT c.relname
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = 'top_delivery_recovery'
              -- Index ACLs are not independently grantable relation
              -- privileges; exclude their catalog relacl representation.
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
              AND c.relacl IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM aclexplode(c.relacl) AS acl
                  WHERE acl.grantee <> c.relowner
              )
            """
        )
    ).scalars().all()
    if unsafe_relation_acl:
        raise RuntimeError(
            "downgrade blocked: recovery schema relation has a non-owner ACL"
        )
    function_rows = connection.execute(
        text(
            """
            SELECT p.oid::regprocedure::text, p.proname, r.rolname,
                   CASE
                       -- PostgreSQL's NULL proacl means the default
                       -- function ACL, which includes PUBLIC EXECUTE.
                       WHEN p.proacl IS NULL THEN TRUE
                       ELSE EXISTS (
                           SELECT 1
                           FROM aclexplode(p.proacl) AS acl
                           WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
                       )
                   END AS public_execute
            FROM pg_proc AS p
            JOIN pg_namespace AS n ON n.oid = p.pronamespace
            JOIN pg_roles AS r ON r.oid = p.proowner
            WHERE n.nspname = 'top_delivery_recovery'
            """
        )
    ).all()
    if (
        any(name not in allowed_routines for _, name, _, _ in function_rows)
        or any(owner_name != MIGRATION_DATABASE_ROLE for _, _, owner_name, _ in function_rows)
        or any(public_execute for _, _, _, public_execute in function_rows)
    ):
        raise RuntimeError(
            "downgrade blocked: recovery schema contains unexpected, wrongly owned, or public functions"
        )


def _verify_alembic_version_bootstrap(connection) -> None:
    """Verify metadata ownership; never repair it inside Alembic."""

    row = connection.execute(
        text(
            """
            SELECT pg_get_userbyid(c.relowner),
                   c.relacl IS NOT NULL
                       AND EXISTS (
                           SELECT 1
                           FROM aclexplode(c.relacl) AS acl
                           WHERE acl.grantee NOT IN (
                                     c.relowner,
                                     (SELECT oid FROM pg_roles
                                      WHERE rolname = 'top_delivery_workflow'),
                                     (SELECT oid FROM pg_roles
                                      WHERE rolname = 'top_delivery_authority')
                                 )
                              OR (
                                  acl.grantee IN (
                                      (SELECT oid FROM pg_roles
                                       WHERE rolname = 'top_delivery_workflow'),
                                      (SELECT oid FROM pg_roles
                                       WHERE rolname = 'top_delivery_authority')
                                  )
                                  AND acl.privilege_type <> 'SELECT'
                              )
                       )
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = 'alembic_version'
            """
        )
    ).one_or_none()
    if row is None:
        return
    if row[0] != MIGRATION_DATABASE_ROLE or bool(row[1]):
        raise RuntimeError(
            "migration blocked: alembic_version ownership or ACL is not the "
            "operator-provisioned migration contract"
        )


def _verify_downgrade_transport(connection, capability) -> None:
    """Bind a signed downgrade witness to this exact PostgreSQL endpoint."""
    from authority_pins import COMMS01_DATABASE_ENDPOINTS, COMMS01_DATABASE_PORT
    from comms01_scope import (
        PINNED_LOCAL_SOCKET_PATH,
        assert_admin_database_url,
        strict_libpq_query,
    )

    admin_url = get_url()
    assert_admin_database_url(admin_url, allow_control_database=True)
    parsed = urlsplit(admin_url)
    query = strict_libpq_query(admin_url)
    query_host = (query.get("host") or [""])[0].lower()
    configured_host = (parsed.hostname or "").lower()
    socket_target = not configured_host and query_host == PINNED_LOCAL_SOCKET_PATH
    configured_port = parsed.port
    if configured_port is None and query.get("port"):
        configured_port = int(query["port"][0])
    if configured_port != COMMS01_DATABASE_PORT:
        raise RuntimeError(
            "downgrade blocked: administrative URL port is not the pinned Comms-01 port"
        )
    if not configured_host and not socket_target:
        raise RuntimeError(
            "downgrade blocked: administrative URL does not pin the local PostgreSQL socket"
        )
    if configured_host and configured_host not in COMMS01_DATABASE_ENDPOINTS:
        raise RuntimeError(
            "downgrade blocked: administrative URL endpoint is outside Comms-01"
        )
    if capability.database_endpoint not in COMMS01_DATABASE_ENDPOINTS:
        raise RuntimeError(
            "downgrade blocked: signed capability endpoint is outside Comms-01"
        )
    server_address, server_port, configured_server_port = connection.execute(
        text(
            "SELECT inet_server_addr()::text, inet_server_port(), "
            "current_setting('port')"
        )
    ).one()
    actual_address = str(server_address or "").split("/", 1)[0].lower()
    actual_port = int(server_port or configured_server_port)
    if actual_port != COMMS01_DATABASE_PORT or actual_port != int(capability.database_port):
        raise RuntimeError(
            "downgrade blocked: connected PostgreSQL port does not match the signed capability"
        )
    local_endpoints = {"local", "localhost", "127.0.0.1", "::1"}
    if actual_address:
        if capability.database_endpoint in local_endpoints:
            if actual_address not in {"127.0.0.1", "::1", "localhost"}:
                raise RuntimeError(
                    "downgrade blocked: connected PostgreSQL address is outside Comms-01"
                )
        elif actual_address != capability.database_endpoint:
            raise RuntimeError(
                "downgrade blocked: connected PostgreSQL address differs from capability"
            )
    elif query_host != PINNED_LOCAL_SOCKET_PATH:
        raise RuntimeError(
            "downgrade blocked: PostgreSQL did not report an address for a non-socket target"
        )
    if configured_host in local_endpoints and capability.database_endpoint not in local_endpoints:
        raise RuntimeError(
            "downgrade blocked: URL and signed capability endpoints disagree"
        )


def _guard_downgrade(connection) -> None:
    """Fail closed for every downgrade path, including raw Alembic."""
    raw_target = _requested_revision("downgrade")
    downgrade_source_path = _DOWNGRADE_SOURCE_PATHS.get(raw_target)
    if downgrade_source_path is None:
        raise RuntimeError(
            "downgrade blocked: target must be a permitted full canonical migration revision"
        )
    # Verify every historical source that Alembic will dispatch before any
    # database query, capability lookup, or DDL.
    for source_revision in downgrade_source_path:
        verify_migration_source_anchor(
            source_revision,
            anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH,
        )
    from disposable_capability import (
        DOWNGRADE_CAPABILITY_OPERATIONS,
        require_disposable_capability,
    )
    row = connection.execute(
        text("SELECT current_database(), current_user, session_user")
    ).one()
    database_name, database_role, session_role = row[0], row[1], row[2]
    initial_database_role = str(database_role)
    if not (
        str(database_name).startswith("td_test_")
        or str(database_name).startswith("td_downgrade_")
    ):
        raise RuntimeError(
            f"downgrade blocked: database {database_name!r} is not disposable"
        )
    if not raw_target:
        raise RuntimeError(
            "downgrade blocked: explicit canonical target is unavailable"
        )
    target = raw_target
    if raw_target in {"base", "head"} or (raw_target and raw_target.startswith("-")):
        raise RuntimeError(
            "downgrade blocked: target must be a full canonical migration revision"
        )
    if raw_target and raw_target.isdigit():
        raise RuntimeError(
            "downgrade blocked: numeric migration target is not canonical"
        )
    if target not in set(_PROTECTED_TABLES_BY_TARGET):
        raise RuntimeError(
            "downgrade blocked: target must be a permitted full canonical migration revision"
        )
    # Verify the signed capability before consuming its nonce. Every later
    # guard uses this one bound witness; a caller cannot pass the early checks
    # and then swap in a different capability object.
    # Peer-authenticated root is an administrative transport identity, not a
    # migration principal. After the signed capability is validated against
    # the out-of-band migration role, constrain this transaction to that role
    # before any migration SQL runs. The SQL guards therefore never authorize
    # root or a superuser directly.
    transport_admin = initial_database_role in ADMIN_DATABASE_ROLES
    effective_database_role = effective_migration_capability_role(initial_database_role)
    capability = require_disposable_capability(
        operation="migration_downgrade",
        database_name=str(database_name),
        database_role=effective_database_role,
        migration_revision=target,
        consume_nonce=False,
    )
    if capability is None:
        raise RuntimeError(
            "downgrade blocked: signed disposable capability witness is missing"
        )
    _verify_downgrade_transport(connection, capability)
    from disposable_capability import consume_verified_disposable_capability

    consume_verified_disposable_capability(capability)
    if transport_admin:
        # The capability witness is committed before Alembic invokes the
        # revision. A transaction-local role would therefore revert at that
        # commit and the revision-level witness would observe the transport
        # account instead of the approved migration principal. Ownership was
        # provisioned out of band; this path only verifies it.
        _verify_alembic_version_bootstrap(connection)
        # A full downgrade may carry the 008 provenance archive across the
        # historical 006 -> 005 boundary.  Verify its private recovery
        # namespace, which must have been provisioned out of band before the
        # migration; the migration role cannot create schemas by design.
        if target in {
            "004_longspan_workflow",
            "005_longspan_hardening",
            "006_longspan_authority",
            "007_longspan_authority_hardening",
        }:
            _prepare_recovery_schema(connection)
        # Session scope is safe here because this is a NullPool disposable
        # migration connection, which is closed after the run.
        connection.execute(text(f"SET ROLE {MIGRATION_DATABASE_ROLE}"))
        role_row = connection.execute(
            text("SELECT current_user, session_user")
        ).one()
        database_role, session_role = role_row[0], role_row[1]
    # Runtime migration roles are a fixed allow-list. Root is never an
    # accepted migration principal; it may only be the transport identity that
    # performs the already-signed disposable harness role transition above.
    approved_migration_principals = {MIGRATION_DATABASE_ROLE, "postgres"}
    def principal_is_approved(principal: str) -> bool:
        return principal in approved_migration_principals

    if not principal_is_approved(str(database_role)):
        raise RuntimeError(
            f"downgrade blocked: connected principal {database_role!r} is not an approved migration role"
        )
    if not principal_is_approved(str(session_role)) and not (
        transport_admin
        and str(session_role) == initial_database_role
        and str(database_role) == MIGRATION_DATABASE_ROLE
    ):
        raise RuntimeError(
            f"downgrade blocked: session principal {session_role!r} is not an approved migration role"
        )
    # Refuse a destructive rollback whenever the target would
    # remove populated authority/execution/review evidence.  Probe relations
    # one at a time because a stepwise downgrade can legitimately reach a
    # revision where later tables do not exist yet.
    for table_name in _PROTECTED_TABLES_BY_TARGET.get(target, ()):
        exists = connection.execute(
            text("SELECT to_regclass(:qualified_name)"),
            {"qualified_name": f"public.{table_name}"},
        ).scalar()
        if exists is None:
            continue
        populated = connection.execute(
            text(f"SELECT EXISTS (SELECT 1 FROM {table_name} LIMIT 1)")
        ).scalar()
        if populated:
            raise RuntimeError(
                f"downgrade blocked: populated Longspan evidence cannot be destroyed by {target}"
            )
    # Persist the verified capability on the database before the migration
    # guard runs.  The SQL guard consumes this row transactionally; a TEMP table
    # or a caller-settable GUC is not an authorization witness.
    connection.execute(
        text(
            """
            INSERT INTO top_delivery_downgrade_capabilities (
                nonce, operation, database_name, database_role,
                transport_database_role, controller_service,
                migration_revision, expires_at
            )
            VALUES (
                :nonce, :operation, :database_name, :database_role,
                :transport_database_role, :controller_service,
                :migration_revision, :expires_at
            )
            ON CONFLICT (nonce) DO NOTHING
            """
        ),
        {
            "nonce": capability.nonce,
            "operation": capability.operation,
            "database_name": str(database_name),
            "database_role": str(database_role),
            "transport_database_role": str(initial_database_role),
            "controller_service": capability.controller_service,
            "migration_revision": str(target or ""),
            "expires_at": capability.expires_at,
        },
    )
    witness = connection.execute(
        text(
            """
            SELECT operation, database_name, database_role,
                   transport_database_role, controller_service,
                   migration_revision,
                   expires_at = CAST(:expires_at AS timestamptz)
            FROM top_delivery_downgrade_capabilities
            WHERE nonce = :nonce
            """
        ),
        {
            "nonce": capability.nonce,
            "expires_at": capability.expires_at,
        },
    ).one_or_none()
    if witness is None or witness != (
        capability.operation,
        str(database_name),
        str(database_role),
        str(initial_database_role),
        capability.controller_service,
        str(target or ""),
        True,
    ):
        raise RuntimeError(
            "downgrade blocked: persisted capability witness does not match the verified request"
        )


def run_migrations_offline() -> None:
    if _is_downgrade_command():
        raise RuntimeError("offline downgrade is forbidden; require connected disposable identity")
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        if _is_downgrade_command():
            _guard_downgrade(connection)
            connection.commit()
        else:
            # This runs before Alembic opens its migration transaction and
            # before any revision-level DDL.  A migration module must never
            # be able to turn ambient root/postgres access into its own
            # authorization witness.
            _guard_upgrade(connection)
            connection.commit()
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
