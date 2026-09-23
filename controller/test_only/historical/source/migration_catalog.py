"""Reviewed Longspan catalog/state matrix shared by the 006–008 revisions.

The SQL migrations keep their allowlists inline so an archived revision remains
self-contained.  This module is the reviewed inventory and transition record
that those projections are checked against before a revision executes.  It is
deliberately data-only: no caller can extend a catalog at runtime.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Final


# Immutable source pins for the historical migration legs.  These are not
# runtime configuration: changing any historical revision requires a reviewed
# catalog change and therefore fails closed in the acceptance suite.
LEGACY_MIGRATION_SOURCE_SHA256: Final[dict[str, str]] = {
    "004_longspan_workflow": "bc01d0a94963dc64d36d1edab9cf2e602f5f96205f33c717b02f553fd3577b32",
    "005_longspan_hardening": "bd0a4a166b5a59fada29f48a146532f98ac5c7a9f46b301b7dcd1a145bd5401f",
    "006_longspan_authority": "b6a23a1240fbeb60066bb580ffcd28d5776e41f395ec6256a2cf94ebbff530eb",
    "007_longspan_authority_hardening": "2782b879d23226797d95f8666d3a6d546f9d749bf80ceb777291d44501d4c39e",
    "009_goal_schedule_task": "7f0c36e0064a5c149f8c671168df5dd4d07d7fdcef427389ee45d6d2aed647bd",
    "010_goal_claim_parent_task": "70c6419caffaa56d1f8313af9fbe2d2e260c37c5c42924f8414bdbb81628ae87",
    "011_goal_claim_fence_token_fix": "ed5afacaf1475b83615f424f0eb102b00131b3d18c96045eb8c2c7a82a40c56e",
    "012_claim_parent_scope_fix": "cb05019f949de3dc8fd5daba44bf4d1e43c3508a681cbf0a53639a4bfd68dfd7",
    "013_cleanup_expired_attempt": "911d718a54a36148d1b4410fbce75e1107f569dde99dfcf7c9c1711e32fc4e7b",
    "014_requeue_blocked_parent_task": "be05d24299ae93dc3d0c5244d9a10266c2b098327a644adbf575dde954ee672c",
}


_CONTROLLER_TABLES: Final[tuple[str, ...]] = (
    "controller_control",
    "supervisor_runs",
    "parent_tasks",
    "task_attempts",
    "retry_queue",
    "supervisor_events",
    "evidence_index",
    "manifest_submissions",
    "required_manifest_entries",
    "signal_status",
    "provenance_records",
    "notifications",
    "alembic_version",
    "top_delivery_downgrade_capabilities",
)

_LONGSPAN_TABLES: Final[tuple[str, ...]] = (
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
)

_PROVENANCE_TABLES: Final[tuple[str, ...]] = (
    "longspan_migration_provenance",
)
_PREEXISTING_PROVENANCE_TABLES: Final[tuple[str, ...]] = (
    "longspan_migration_provenance",
    "longspan_migration_provenance_008_state",
)
_LONGSPAN_006_TABLES: Final[tuple[str, ...]] = tuple(
    value for value in _LONGSPAN_TABLES if value != "longspan_authority_receipts"
)

_ROUTINES_006: Final[tuple[str, ...]] = (
    "reject_evidence_index_mutation()",
    "reject_longspan_evidence_mutation()",
    "reject_longspan_auditor_mutation()",
    "reject_longspan_evidence_truncate()",
    "reject_longspan_auditor_truncate()",
    "reject_longspan_terra_mutation()",
    "reject_longspan_terra_truncate()",
)

_ROUTINES_007: Final[tuple[str, ...]] = _ROUTINES_006 + (
    "reject_longspan_authority_mutation()",
    "reject_longspan_authority_history_mutation()",
    "reject_longspan_append_only_mutation()",
    "reject_longspan_terra_attestation_mutation()",
    "reject_longspan_legacy_watermark()",
    "reject_longspan_legacy_attestation_mutation()",
    "reject_longspan_execution_audit_mutation()",
    "reject_challenge_direct_mutation()",
    "longspan_create_operator_challenge(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER, TEXT, INTEGER, INTEGER, INTEGER)",
    "longspan_bind_and_consume_challenge(TEXT, TEXT, TEXT)",
    "longspan_install_ledger_mac_key(TEXT)",
    "longspan_install_terra_gateway_mac_key(TEXT)",
    "longspan_assert_child_capability(TEXT, INTEGER, TEXT, TEXT)",
    "longspan_assert_controller_maintenance_scope(TEXT, TEXT)",
    "longspan_authority_content_digest(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT)",
    "longspan_assert_authority_write(TEXT, TEXT, TEXT, TEXT, INTEGER)",
    "longspan_append_evidence_ledger(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT)",
    "longspan_verify_ledger_entry(TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)",
    "longspan_store_execution_evidence(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)",
    "longspan_append_execution_audit(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)",
    "longspan_insert_execution_result(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)",
    "longspan_append_auditor_receipt(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)",
    "longspan_issue_terra_receipt_attestation(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)",
    "longspan_consume_terra_receipt_attestation(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)",
    "longspan_terra_gateway_mac(TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)",
    "longspan_terra_gateway_mac_for_attestation(TEXT)",
    "longspan_append_terra_receipt(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)",
    "longspan_insert_authority_config(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)",
    "longspan_rotate_authority_config(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT, TEXT)",
    "longspan_append_authority_history(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT)",
    "longspan_open_mutation_scope(TEXT, INTEGER, BIGINT)",
    "longspan_open_controller_mutation_scope(TEXT, INTEGER, BIGINT, TEXT, TEXT)",
    "longspan_current_controller_fence(TEXT, INTEGER, TEXT)",
    "longspan_park_children(TEXT, INTEGER, TEXT, BIGINT)",
    "longspan_expire_stale_children(TEXT, INTEGER, TEXT, BIGINT)",
    "longspan_open_signal_scope(TEXT, INTEGER)",
    "longspan_open_rollback_signal_scope(TEXT, INTEGER)",
    "longspan_register_run(TEXT, TEXT)",
    "longspan_next_event_seq(TEXT, BIGINT)",
    "longspan_disable_controller(TEXT, BIGINT)",
    "longspan_test_expire_controller_lease(TEXT)",
    "longspan_acquire_controller(TEXT, TEXT, DOUBLE PRECISION, BIGINT, BOOLEAN)",
    "reject_longspan_migration_provenance_008_archive_mutation()",
    "require_longspan_mutation_scope()",
)

_ROUTINES_008: Final[tuple[str, ...]] = _ROUTINES_007 + (
    "longspan_invalidate_terra_receipt_attestation(TEXT, TEXT, TEXT, INTEGER, TEXT)",
)
_ROUTINES_009: Final[tuple[str, ...]] = _ROUTINES_008 + (
    "longspan_schedule_goal_task(TEXT, TEXT, TEXT, INTEGER, TIMESTAMPTZ, INTEGER, TEXT, BIGINT)",
)
_ROUTINES_010: Final[tuple[str, ...]] = _ROUTINES_009 + (
    "longspan_claim_next_parent_task(TEXT, TEXT, INTEGER, DOUBLE PRECISION)",
)
_ROUTINES_013: Final[tuple[str, ...]] = _ROUTINES_010 + (
    "longspan_cleanup_expired_parent_attempt(TEXT, TEXT, INTEGER, INTEGER)",
)
_ROUTINES_014: Final[tuple[str, ...]] = _ROUTINES_013 + (
    "longspan_requeue_blocked_parent_task(TEXT, TEXT, TEXT, INTEGER, TEXT, INTEGER)",
)
_ROUTINES_007_ACL: Final[tuple[str, ...]] = (
    "reject_evidence_index_mutation()",
    "reject_longspan_evidence_mutation()",
    "reject_longspan_auditor_mutation()",
    "reject_longspan_evidence_truncate()",
    "reject_longspan_auditor_truncate()",
    "reject_longspan_terra_mutation()",
    "reject_longspan_terra_truncate()",
    "reject_longspan_authority_mutation()",
    "reject_longspan_authority_history_mutation()",
    "reject_longspan_append_only_mutation()",
    "reject_longspan_terra_attestation_mutation()",
    "reject_longspan_legacy_watermark()",
    "reject_longspan_legacy_attestation_mutation()",
    "reject_longspan_execution_audit_mutation()",
    "reject_longspan_migration_provenance_008_archive_mutation()",
    "reject_challenge_direct_mutation()",
    "require_longspan_mutation_scope()",
)

_ARCHIVE_PUBLIC_TABLES: Final[tuple[str, ...]] = (
    "longspan_migration_provenance_008_state",
    "longspan_migration_provenance_008_archive",
)
_RECOVERY_TABLES: Final[tuple[str, ...]] = (
    "longspan_migration_provenance_008_archive",
)
_ARCHIVE_SEQUENCES: Final[tuple[str, ...]] = (
    "longspan_migration_provenance_008_archive_id_seq",
    "longspan_migration_provenance_008_archive_archive_id_seq",
)
_ARCHIVE_INDEXES: Final[tuple[str, ...]] = (
    "longspan_migration_provenance_008_archive_pkey",
)


MIGRATION_CATALOG: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "006_longspan_authority": {
        # These two exact names may already exist when a partially rehearsed
        # 008 database is brought through a compatibility leg.  They are an
        # allowlist for explicit owner/ACL assertions, not prefix adoption.
        "public_tables": _CONTROLLER_TABLES + _LONGSPAN_006_TABLES + _PREEXISTING_PROVENANCE_TABLES,
        "public_sequences": ("supervisor_events_event_seq_seq",),
        "public_routines": _ROUTINES_006,
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
    "007_longspan_authority_hardening": {
        "public_tables": _CONTROLLER_TABLES + _LONGSPAN_TABLES + _PREEXISTING_PROVENANCE_TABLES,
        "public_sequences": ("supervisor_events_event_seq_seq",),
        "public_routines": _ROUTINES_007,
        # 008 downgrades park its immutable archive before the 007/006
        # compatibility legs execute.  It is private recovery state, not a
        # 007 public relation, but it remains part of the verified boundary.
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
    "008_longspan_authority_repair": {
        "public_tables": (
            _CONTROLLER_TABLES
            + _LONGSPAN_TABLES
            + _PROVENANCE_TABLES
            + _ARCHIVE_PUBLIC_TABLES
        ),
        "public_sequences": (
            ("supervisor_events_event_seq_seq",) + _ARCHIVE_SEQUENCES
        ),
        "public_routines": _ROUTINES_008,
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
    "009_goal_schedule_task": {
        "public_tables": (
            _CONTROLLER_TABLES
            + _LONGSPAN_TABLES
            + _PROVENANCE_TABLES
            + _ARCHIVE_PUBLIC_TABLES
        ),
        "public_sequences": (
            ("supervisor_events_event_seq_seq",) + _ARCHIVE_SEQUENCES
        ),
        "public_routines": _ROUTINES_009,
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
    "010_goal_claim_parent_task": {
        "public_tables": (
            _CONTROLLER_TABLES
            + _LONGSPAN_TABLES
            + _PROVENANCE_TABLES
            + _ARCHIVE_PUBLIC_TABLES
        ),
        "public_sequences": (
            ("supervisor_events_event_seq_seq",) + _ARCHIVE_SEQUENCES
        ),
        "public_routines": _ROUTINES_010,
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
    "011_goal_claim_fence_token_fix": {
        "public_tables": (
            _CONTROLLER_TABLES
            + _LONGSPAN_TABLES
            + _PROVENANCE_TABLES
            + _ARCHIVE_PUBLIC_TABLES
        ),
        "public_sequences": (
            ("supervisor_events_event_seq_seq",) + _ARCHIVE_SEQUENCES
        ),
        "public_routines": _ROUTINES_010,
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
    "012_claim_parent_scope_fix": {
        "public_tables": (
            _CONTROLLER_TABLES
            + _LONGSPAN_TABLES
            + _PROVENANCE_TABLES
            + _ARCHIVE_PUBLIC_TABLES
        ),
        "public_sequences": (
            ("supervisor_events_event_seq_seq",) + _ARCHIVE_SEQUENCES
        ),
        "public_routines": _ROUTINES_010,
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
    "013_cleanup_expired_attempt": {
        "public_tables": (
            _CONTROLLER_TABLES
            + _LONGSPAN_TABLES
            + _PROVENANCE_TABLES
            + _ARCHIVE_PUBLIC_TABLES
        ),
        "public_sequences": (
            ("supervisor_events_event_seq_seq",) + _ARCHIVE_SEQUENCES
        ),
        "public_routines": _ROUTINES_013,
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
    "014_requeue_blocked_parent_task": {
        "public_tables": (
            _CONTROLLER_TABLES
            + _LONGSPAN_TABLES
            + _PROVENANCE_TABLES
            + _ARCHIVE_PUBLIC_TABLES
        ),
        "public_sequences": (
            ("supervisor_events_event_seq_seq",) + _ARCHIVE_SEQUENCES
        ),
        "public_routines": _ROUTINES_014,
        "recovery_tables": _RECOVERY_TABLES,
        "recovery_sequences": _ARCHIVE_SEQUENCES,
    },
}


def migration_catalog_digest() -> str:
    canonical = json.dumps(MIGRATION_CATALOG, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


MIGRATION_CATALOG_DIGEST: Final[str] = migration_catalog_digest()
EXPECTED_MIGRATION_CATALOG_DIGEST: Final[str] = (
    "e5dcc0689cf4adf898b0c184728ac6cc2b0f4838c9e725077dba762760301edd"
)
if MIGRATION_CATALOG_DIGEST != EXPECTED_MIGRATION_CATALOG_DIGEST:
    raise RuntimeError(
        "migration catalog digest differs from the reviewed Comms-01 catalog"
    )

_ALLOWLIST_PATTERN = re.compile(
    r"(?P<name>allowed_(?:table_names|sequence_names|routine_signatures))"
    r"\s+CONSTANT\s+TEXT\[\]\s*:=\s*ARRAY\[(?P<body>.*?)\];",
    re.DOTALL,
)
_SQL_STRING_PATTERN = re.compile(r"'((?:''|[^'])*)'")


def _sql_allowlist_values(revision: str, name: str) -> tuple[tuple[str, ...], ...]:
    source_path = Path(__file__).resolve().parent / "migrations" / "versions" / f"{revision}.py"
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"migration source unavailable for catalog check: {revision}") from exc
    arrays = tuple(
        tuple(value.replace("''", "'") for value in _SQL_STRING_PATTERN.findall(match.group("body")))
        for match in _ALLOWLIST_PATTERN.finditer(source)
        if match.group("name") == name
    )
    if not arrays:
        raise RuntimeError(f"migration has no reviewed {name} projection: {revision}")
    return arrays


def _expected_sql_allowlist_arrays(
    revision: str, field: str, catalog: dict[str, tuple[str, ...]]
) -> tuple[tuple[str, ...], ...]:
    """Return the exact SQL projection, including staged 008 transitions."""
    if revision in {"006_longspan_authority", "007_longspan_authority_hardening"}:
        if revision == "007_longspan_authority_hardening" and field == "public_routines":
            return (_ROUTINES_007, _ROUTINES_007_ACL)
        return (catalog[field],)
    if revision == "009_goal_schedule_task":
        if field == "public_routines":
            return (_ROUTINES_009,)
        return (catalog[field],)
    if revision in {
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
        "013_cleanup_expired_attempt",
        "014_requeue_blocked_parent_task",
    }:
        if field == "public_routines":
            if revision == "014_requeue_blocked_parent_task":
                return (_ROUTINES_014,)
            return (_ROUTINES_010,) if revision != "013_cleanup_expired_attempt" else (_ROUTINES_013,)
        return (catalog[field],)
    if revision != "008_longspan_authority_repair":
        raise RuntimeError(f"migration has no reviewed projection contract: {revision}")
    if field == "public_tables":
        # The pre-DDL 008 boundary must tolerate an exact provenance/state
        # pair left by a partial rehearsal; absence is still valid because
        # the later statements create the pair when needed.
        return (catalog[field], catalog[field])
    if field == "public_sequences":
        return (catalog[field], catalog[field])
    if field == "public_routines":
        return (_ROUTINES_007, _ROUTINES_008)
    raise RuntimeError(f"migration has no reviewed catalog field: {field}")


def _assert_sql_allowlist_projection(revision: str, catalog: dict[str, tuple[str, ...]]) -> None:
    if revision == "009_goal_schedule_task":
        if catalog["public_routines"] != _ROUTINES_009:
            raise RuntimeError(
                "009_goal_schedule_task catalog routines differ from the reviewed projection"
            )
        return
    if revision == "010_goal_claim_parent_task":
        if catalog["public_routines"] != _ROUTINES_010:
            raise RuntimeError(
                "010_goal_claim_parent_task catalog routines differ from the reviewed projection"
            )
        return
    if revision == "011_goal_claim_fence_token_fix":
        if catalog["public_routines"] != _ROUTINES_010:
            raise RuntimeError(
                "011_goal_claim_fence_token_fix catalog routines differ from the reviewed projection"
            )
        return
    if revision == "012_claim_parent_scope_fix":
        if catalog["public_routines"] != _ROUTINES_010:
            raise RuntimeError(
                "012_claim_parent_scope_fix catalog routines differ from the reviewed projection"
            )
        return
    if revision == "013_cleanup_expired_attempt":
        if catalog["public_routines"] != _ROUTINES_013:
            raise RuntimeError(
                "013_cleanup_expired_attempt catalog routines differ from the reviewed projection"
            )
        return
    if revision == "014_requeue_blocked_parent_task":
        if catalog["public_routines"] != _ROUTINES_014:
            raise RuntimeError(
                "014_requeue_blocked_parent_task catalog routines differ from the reviewed projection"
            )
        return
    projections = {
        "allowed_table_names": set(catalog["public_tables"]),
        "allowed_sequence_names": set(catalog["public_sequences"]),
        "allowed_routine_signatures": set(catalog["public_routines"]),
    }
    for sql_name, allowed in projections.items():
        arrays = _sql_allowlist_values(revision, sql_name)
        catalog_field = {
            "allowed_table_names": "public_tables",
            "allowed_sequence_names": "public_sequences",
            "allowed_routine_signatures": "public_routines",
        }[sql_name]
        expected_arrays = _expected_sql_allowlist_arrays(
            revision, catalog_field, catalog
        )
        if len(arrays) != len(expected_arrays):
            raise RuntimeError(
                f"migration SQL allowlist array count differs from catalog for {revision}.{sql_name}"
            )
        for index, array in enumerate(arrays):
            if len(array) != len(set(array)):
                raise RuntimeError(
                    f"migration SQL allowlist contains duplicate {sql_name} entries for {revision}"
                )
            declared = {
                value
                if sql_name == "allowed_routine_signatures"
                else value.split("(", 1)[0]
                for value in array
            }
            expected = {
                value
                if sql_name == "allowed_routine_signatures"
                else value.split("(", 1)[0]
                for value in expected_arrays[index]
            }
            unknown = sorted(declared - allowed)
            missing = sorted(expected - declared)
            if unknown:
                raise RuntimeError(
                    f"migration catalog rejected unknown {sql_name} entries for {revision}: {unknown}"
                )
            if declared != expected:
                raise RuntimeError(
                    f"migration SQL allowlist is not an exact reviewed projection for {revision}.{sql_name}[{index}]; missing={missing}"
                )


def migration_sql_projection_digest() -> str:
    """Hash the independent-style SQL projection used by release evidence."""
    projection: dict[str, dict[str, list[str]]] = {}
    for revision in (
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
        "013_cleanup_expired_attempt",
        "014_requeue_blocked_parent_task",
    ):
        if revision in {
            "009_goal_schedule_task",
            "010_goal_claim_parent_task",
            "011_goal_claim_fence_token_fix",
            "012_claim_parent_scope_fix",
            "013_cleanup_expired_attempt",
            "014_requeue_blocked_parent_task",
        }:
            catalog = MIGRATION_CATALOG[revision]
            projection[revision] = {
                "tables": sorted(catalog["public_tables"]),
                "sequences": sorted(catalog["public_sequences"]),
                "routines": sorted(catalog["public_routines"]),
            }
            continue
        projection[revision] = {}
        for field, sql_name in (
            ("tables", "allowed_table_names"),
            ("sequences", "allowed_sequence_names"),
            ("routines", "allowed_routine_signatures"),
        ):
            arrays = _sql_allowlist_values(revision, sql_name)
            values = [value for array in arrays for value in array]
            projection[revision][field] = sorted(set(values))
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


MIGRATION_SQL_PROJECTION_DIGEST: Final[str] = migration_sql_projection_digest()
EXPECTED_MIGRATION_SQL_PROJECTION_DIGEST: Final[str] = (
    "e62bc203939d9e1c433c6b00182e5b09d7169b4c65036d7ba440ebeac4e90880"
)
if MIGRATION_SQL_PROJECTION_DIGEST != EXPECTED_MIGRATION_SQL_PROJECTION_DIGEST:
    raise RuntimeError(
        "migration SQL projection digest differs from the independently reviewed projection"
    )


def recovery_schema_relation_names() -> tuple[str, ...]:
    """Return the exact private recovery relation contract, including its PK index."""
    return tuple(
        sorted(
            set(MIGRATION_CATALOG["006_longspan_authority"]["recovery_tables"])
            | set(MIGRATION_CATALOG["006_longspan_authority"]["recovery_sequences"])
            | set(_ARCHIVE_INDEXES)
        )
    )


def recovery_schema_routine_names() -> tuple[str, ...]:
    return ("reject_longspan_migration_provenance_008_archive_mutation",)


def assert_migration_catalog(revision: str) -> None:
    """Validate the immutable state matrix before revision-level DDL."""
    catalog = MIGRATION_CATALOG.get(revision)
    if catalog is None:
        raise RuntimeError(f"unknown migration catalog revision: {revision}")
    for field, values in catalog.items():
        if not values or any(not value or value.strip() != value for value in values):
            if field not in {"recovery_tables", "recovery_sequences"}:
                raise RuntimeError(f"invalid empty/whitespace catalog field: {revision}.{field}")
        if len(values) != len(set(values)):
            raise RuntimeError(f"duplicate catalog entry: {revision}.{field}")
    if revision == "008_longspan_authority_repair":
        if not set(_ARCHIVE_PUBLIC_TABLES) <= set(catalog["public_tables"]):
            raise RuntimeError("008 catalog omits the archive table state")
        if not set(_ARCHIVE_SEQUENCES) <= set(catalog["public_sequences"]):
            raise RuntimeError("008 catalog omits the archive sequence state")
    _assert_sql_allowlist_projection(revision, catalog)
