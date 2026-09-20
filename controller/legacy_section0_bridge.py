"""Deterministic bridge from legacy Section-0 data to the mainline schema.

The bridge is disposable-only. It never relabels an Alembic revision or
connects to the live Comms-01 database. Restore a read-only backup into a
``td_test_*`` source, create a fresh ``003_commit_order_and_invariants``
target, run this bridge, then apply verified mainline migrations 004-008.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import psycopg2
from psycopg2 import sql

from comms01_scope import LIBPQ_TARGET_ENV_KEYS, LIBPQ_TARGET_OVERRIDE_KEYS
from operator_asymmetric import sign_message, verify_message_signature
from artifact_signing import domain_separated_message

LEGACY_REVISION = "004_auditor_provenance"
BASELINE_REVISION = "003_commit_order_and_invariants"
DISPOSABLE_NAME = re.compile(r"^td_(?:test|downgrade)_[A-Za-z0-9_]+$")

# Explicit allowlist: roles, ACLs, Alembic metadata, functions, and triggers
# are rebuilt by the trusted mainline migrations rather than copied.
TABLES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("supervisor_runs", ("run_id",), ("run_id", "state", "updated_at")),
    (
        "controller_control",
        ("run_id",),
        (
            "run_id",
            "current_epoch",
            "owner",
            "lease_expires_at",
            "scheduling_enabled",
            "updated_at",
            "event_seq_counter",
        ),
    ),
    (
        "parent_tasks",
        ("task_id", "run_id"),
        (
            "task_id",
            "run_id",
            "objective",
            "state",
            "priority",
            "available_at",
            "attempt",
            "active_attempt_id",
            "updated_at",
        ),
    ),
    (
        "task_attempts",
        ("attempt_id", "task_id", "run_id"),
        (
            "attempt_id",
            "task_id",
            "run_id",
            "fence_token",
            "controller_epoch",
            "owner",
            "status",
            "heartbeat_at",
            "lease_expires_at",
            "created_at",
            "ended_at",
        ),
    ),
    (
        "retry_queue",
        ("retry_key",),
        (
            "retry_key",
            "run_id",
            "task_id",
            "available_at",
            "attempt",
            "reason",
            "state",
        ),
    ),
    (
        "supervisor_events",
        ("event_id",),
        (
            "event_id",
            "run_id",
            "controller_epoch",
            "event_type",
            "occurred_at",
            "detail_json",
            "event_seq",
        ),
    ),
    (
        "notifications",
        ("notification_key",),
        ("notification_key", "run_id", "event_type", "sent_at", "state"),
    ),
    (
        "evidence_index",
        ("evidence_id",),
        (
            "evidence_id",
            "run_id",
            "task_id",
            "attempt_id",
            "fence_token",
            "artifact_path",
            "sha256",
            "byte_count",
            "producer",
            "result",
            "created_at",
        ),
    ),
    (
        "required_manifest_entries",
        ("entry_id",),
        ("entry_id", "artifact_path", "expected_sha256", "producer"),
    ),
    (
        "manifest_submissions",
        ("submission_id",),
        (
            "submission_id",
            "run_id",
            "entry_id",
            "artifact_path",
            "sha256",
            "producer",
            "result",
            "created_at",
        ),
    ),
    (
        "signal_status",
        ("run_id",),
        ("run_id", "status_json", "readiness", "last_event_seq", "updated_at"),
    ),
    (
        "provenance_records",
        ("run_id",),
        (
            "run_id",
            "reviewed_sha",
            "commit_sha",
            "tree_sha",
            "build_sha",
            "activation_sha",
            "verified",
            "updated_at",
        ),
    ),
)

LEGACY_ONLY_COLUMNS = {"evidence_index": ("producer_role", "controller_epoch")}
# An empty legacy object is not silently discardable.  Adding an entry here is
# an explicit source-controlled schema disposition that must be reviewed with
# the bridge candidate; the empty set is intentional for the current 004 dump.
LEGACY_EMPTY_DISPOSITION_ALLOWLIST: frozenset[tuple[str, str | None]] = frozenset()
SCHEMA_DISPOSITION_VERSION = "legacy-004-empty-disposition-v1"
BRIDGE_DIGEST_SCOPE = (
    "bridge-selected-columns-v2;canonical-json-row-sort;"
    "json-value-coercion-v1;datetime-utc-isoformat;date-isoformat;"
    "decimal-string;bytes-hex;legacy-only-columns-retained-in-source-attestation"
)
SNAPSHOT_DIGEST_SCOPE = (
    "snapshot-all-public-base-columns-v1;canonical-json-row-sort;"
    "json-value-coercion-v1;datetime-utc-isoformat;date-isoformat;"
    "decimal-string;bytes-hex"
)
SCHEMA_FIELDS = (
    "data_type",
    "udt_name",
    "is_nullable",
    "datetime_precision",
    "numeric_precision",
    "numeric_scale",
    "character_maximum_length",
)
REVIEW_SIGNING_PRIVATE_KEY_PATH = Path("/etc/top-delivery/comms01-review-signing.key")
REVIEW_SIGNING_PUBLIC_KEY_PATH = Path("/etc/top-delivery/comms01-review-signing.pub")


def _read_pinned_key(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0:
        raise ValueError(f"review key is not a regular file: {path}")
    if path.stat().st_mode & 0o077:
        raise ValueError(f"review key permissions are too broad: {path}")
    return path.read_text(encoding="ascii").strip()


def _git_provenance() -> tuple[str, str]:
    repository = Path(__file__).resolve().parents[1]
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=repository, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("bridge candidate Git provenance is unavailable") from exc
    if len(commit) != 40 or len(tree) != 40:
        raise ValueError("bridge candidate Git provenance is malformed")
    return commit, tree


def _assert_disposable(url: str, label: str) -> str:
    parsed = urlsplit(url)
    name = parsed.path.lstrip("/")
    if not DISPOSABLE_NAME.fullmatch(name):
        raise ValueError(f"{label} must be a td_test_* or td_downgrade_* database")
    query = parse_qs(parsed.query, keep_blank_values=True)
    unknown_or_redirecting = sorted(
        key
        for key in query
        if key.lower() not in {"host", "port"}
        or key.lower() in LIBPQ_TARGET_OVERRIDE_KEYS - {"host", "port"}
    )
    if unknown_or_redirecting:
        raise ValueError(
            f"{label} contains forbidden libpq target parameter(s): "
            + ", ".join(unknown_or_redirecting)
        )
    if parsed.hostname and any(key in query for key in ("host", "port")):
        raise ValueError(
            f"{label} must not combine an authority host with a libpq host/port override"
        )
    inherited_target_settings = sorted(
        key for key in LIBPQ_TARGET_ENV_KEYS if os.environ.get(key)
    )
    if inherited_target_settings:
        raise ValueError(
            f"{label} cannot inherit libpq target environment: "
            + ", ".join(inherited_target_settings)
        )
    if len(query.get("host", [])) > 1 or len(query.get("port", [])) > 1:
        raise ValueError(f"{label} must not repeat host or port parameters")
    query_host = query.get("host", [None])[-1]
    if parsed.hostname is None:
        if query_host != "/var/run/postgresql":
            raise ValueError(
                f"{label} must specify loopback host or /var/run/postgresql socket"
            )
    elif parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(f"{label} must use the local PostgreSQL endpoint")
    requested_port = parsed.port
    if requested_port is None and query.get("port"):
        try:
            requested_port = int(query["port"][-1])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} must use PostgreSQL port 5432") from exc
    if requested_port != 5432:
        raise ValueError(f"{label} must use PostgreSQL port 5432")
    return name


def _connect_verified(url: str, label: str) -> tuple[str, Any, dict[str, Any]]:
    """Connect and prove that libpq did not redirect a disposable URL."""
    name = _assert_disposable(url, label)
    connection = psycopg2.connect(url)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET SESSION search_path TO public")
            cursor.execute("""
                SELECT current_database(), inet_server_addr()::text,
                       inet_server_port()
                """)
            actual_name, actual_address, actual_port = cursor.fetchone()
            cursor.execute("SELECT current_schema(), current_setting('search_path')")
            actual_schema, actual_search_path = cursor.fetchone()
        # The identity probe starts an implicit transaction.  End it so the
        # bridge can set the source snapshot isolation before its first data
        # query.
        connection.rollback()
        if actual_name != name:
            raise ValueError(
                f"{label} connected to unexpected database {actual_name!r}"
            )
        if actual_schema != "public" or actual_search_path != "public":
            raise ValueError(f"{label} search_path is not pinned to public")
        query_host = parse_qs(urlsplit(url).query, keep_blank_values=True).get(
            "host", [None]
        )[-1]
        if actual_address is None and query_host != "/var/run/postgresql":
            raise ValueError(f"{label} did not resolve to a pinned local endpoint")
        if actual_address not in (None, "127.0.0.1", "::1"):
            raise ValueError(
                f"{label} connected to non-local PostgreSQL address {actual_address!r}"
            )
        if actual_port is None and query_host != "/var/run/postgresql":
            raise ValueError(f"{label} did not expose the expected server port")
        if actual_port not in (None, 5432):
            raise ValueError(
                f"{label} connected to unexpected PostgreSQL port {actual_port}"
            )
        return (
            name,
            connection,
            {
                "current_database": actual_name,
                "inet_server_addr": actual_address,
                "inet_server_port": actual_port,
                "current_schema": actual_schema,
                "search_path": actual_search_path,
            },
        )
    except Exception:
        connection.close()
        raise


def _revision(connection) -> str:
    with connection.cursor() as cursor:
        cursor.execute("SELECT version_num FROM alembic_version")
        row = cursor.fetchone()
    if row is None:
        raise ValueError("database has no Alembic revision")
    return str(row[0])


def _available_columns(connection, table: str) -> set[str]:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = %s",
            (table,),
        )
        return {str(row[0]) for row in cursor.fetchall()}


def _column_metadata(connection, table: str) -> dict[str, dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT column_name, data_type, udt_name, is_nullable,
                   datetime_precision, numeric_precision, numeric_scale,
                   character_maximum_length
            FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = %s
            ORDER BY ordinal_position
            """,
            (table,),
        )
        return {
            str(row[0]): {
                field: row[index] for index, field in enumerate(SCHEMA_FIELDS, start=1)
            }
            for row in cursor.fetchall()
        }


def _primary_key_columns(connection, table: str) -> tuple[str, ...]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT a.attname
            FROM pg_index AS i
            JOIN pg_class AS c ON c.oid = i.indrelid
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS keys(attnum, position)
              ON TRUE
            JOIN pg_attribute AS a ON a.attrelid = c.oid AND a.attnum = keys.attnum
            WHERE n.nspname = 'public' AND c.relname = %s AND i.indisprimary
            ORDER BY keys.position
            """,
            (table,),
        )
        return tuple(str(row[0]) for row in cursor.fetchall())


def _base_tables(connection) -> list[str]:
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
            ORDER BY table_name
            """)
        return [str(row[0]) for row in cursor.fetchall()]


def _public_sequences(connection) -> list[str]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.relname
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'S'
            ORDER BY c.relname
            """
        )
        return [str(row[0]) for row in cursor.fetchall()]


def _target_pristine(connection) -> dict[str, Any]:
    """Prove that the 003 target has no unaccounted durable state."""
    tables = _base_tables(connection)
    non_empty_tables = [
        table
        for table in tables
        if table != "alembic_version" and _row_count(connection, table) != 0
    ]
    sequences: list[dict[str, Any]] = []
    non_pristine_sequences: list[str] = []
    for sequence_name in _public_sequences(connection):
        query = sql.SQL("SELECT last_value, is_called FROM public.{sequence}").format(
            sequence=sql.Identifier(sequence_name)
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            last_value, is_called = cursor.fetchone()
        item = {
            "sequence": sequence_name,
            "last_value": int(last_value),
            "is_called": bool(is_called),
        }
        sequences.append(item)
        if item["last_value"] != 1 or item["is_called"]:
            non_pristine_sequences.append(sequence_name)
    if non_empty_tables or non_pristine_sequences:
        raise ValueError(
            "target contains durable state before bridge: "
            f"tables={non_empty_tables}, sequences={non_pristine_sequences}"
        )
    return {
        "public_base_tables": tables,
        "non_empty_tables": non_empty_tables,
        "public_sequences": sequences,
        "pristine": True,
    }


def _source_relation_completeness(connection) -> dict[str, Any]:
    """Reject durable relations outside the explicitly audited public schema."""
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT nspname
            FROM pg_namespace
            WHERE nspname NOT IN ('public', 'information_schema')
              AND nspname NOT LIKE 'pg_%'
            ORDER BY nspname
            """
        )
        non_system_schemas = [str(row[0]) for row in cursor.fetchall()]
        cursor.execute(
            """
            SELECT c.relname, c.relkind::text
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relkind IN ('f', 'm')
            ORDER BY c.relname
            """
        )
        non_base_relations = [
            {"name": str(row[0]), "relkind": str(row[1])}
            for row in cursor.fetchall()
        ]
    if non_system_schemas or non_base_relations:
        raise ValueError(
            "source contains un-audited schemas or non-base relations: "
            f"schemas={non_system_schemas}, relations={non_base_relations}"
        )
    return {
        "allowed_schema": "public",
        "non_system_schemas": non_system_schemas,
        "non_base_relations": non_base_relations,
    }


def _row_count(connection, table: str) -> int:
    query = sql.SQL("SELECT count(*) FROM public.{table}").format(
        table=sql.Identifier(table)
    )
    with connection.cursor() as cursor:
        cursor.execute(query)
        return int(cursor.fetchone()[0])


def _column_digest(connection, table: str, column: str) -> str | None:
    key_columns = _primary_key_columns(connection, table)
    selected_columns = (*key_columns, column) if key_columns else (column,)
    query = sql.SQL("SELECT {columns} FROM public.{table}").format(
        columns=sql.SQL(", ").join(sql.Identifier(item) for item in selected_columns),
        table=sql.Identifier(table),
    )
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
    rows.sort(
        key=lambda row: json.dumps(
            [_json_value(value) for value in row],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    values = [_json_value(row[-1]) for row in rows]
    if not values:
        return None
    return hashlib.sha256(
        json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _schema_completeness(connection) -> dict[str, Any]:
    expected_tables = {table for table, _keys, _columns in TABLES}
    source_tables = _base_tables(connection)
    dropped_tables: list[dict[str, Any]] = []
    dropped_columns: list[dict[str, Any]] = []
    unexpected_rows: list[str] = []
    for table in source_tables:
        if table == "alembic_version" or table in expected_tables:
            continue
        count = _row_count(connection, table)
        metadata = _column_metadata(connection, table)
        disposition = (table, None)
        dropped_tables.append(
            {
                "table": table,
                "columns": sorted(metadata),
                "row_count": count,
                "disposition": (
                    "explicitly reviewed empty legacy object"
                    if disposition in LEGACY_EMPTY_DISPOSITION_ALLOWLIST
                    else "requires explicit legacy schema disposition"
                ),
                "disposition_version": SCHEMA_DISPOSITION_VERSION,
            }
        )
        if count or disposition not in LEGACY_EMPTY_DISPOSITION_ALLOWLIST:
            unexpected_rows.append(table)

    for table, _keys, columns in TABLES:
        metadata = _column_metadata(connection, table)
        expected_columns = set(columns) | set(LEGACY_ONLY_COLUMNS.get(table, ()))
        for column in sorted(set(metadata) - expected_columns):
            non_null_query = sql.SQL(
                "SELECT count(*) FROM public.{table} WHERE {column} IS NOT NULL"
            ).format(table=sql.Identifier(table), column=sql.Identifier(column))
            with connection.cursor() as cursor:
                cursor.execute(non_null_query)
                non_null_count = int(cursor.fetchone()[0])
            dropped_columns.append(
                {
                    "table": table,
                    "column": column,
                    "metadata": metadata[column],
                    "non_null_count": non_null_count,
                    "digest": _column_digest(connection, table, column),
                    "disposition": (
                        "explicitly reviewed empty legacy object"
                        if (table, column) in LEGACY_EMPTY_DISPOSITION_ALLOWLIST
                        else "requires explicit legacy schema disposition"
                    ),
                    "disposition_version": SCHEMA_DISPOSITION_VERSION,
                }
            )
            if (
                non_null_count
                or (table, column) not in LEGACY_EMPTY_DISPOSITION_ALLOWLIST
            ):
                unexpected_rows.append(f"{table}.{column}")
    if unexpected_rows:
        raise ValueError(
            "source contains unlisted durable data: "
            + ", ".join(sorted(unexpected_rows))
        )
    return {
        "source_tables": source_tables,
        "disposition_version": SCHEMA_DISPOSITION_VERSION,
        "approved_empty_objects": [
            {"table": table, "column": column}
            for table, column in sorted(LEGACY_EMPTY_DISPOSITION_ALLOWLIST)
        ],
        "dropped_empty_tables": dropped_tables,
        "dropped_empty_columns": dropped_columns,
    }


def _assert_column_compatibility(
    source, target, table: str, columns: tuple[str, ...]
) -> None:
    source_metadata = _column_metadata(source, table)
    target_metadata = _column_metadata(target, table)
    for column in columns:
        if column not in source_metadata or column not in target_metadata:
            continue
        if source_metadata[column] != target_metadata[column]:
            raise ValueError(
                f"bridge type mismatch for {table}.{column}: "
                f"source={source_metadata[column]} target={target_metadata[column]}"
            )


def _resynchronize_sequences(connection) -> list[dict[str, Any]]:
    """Advance disposable target sequences after explicit-key inserts."""
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT seq.relname, tbl.relname, att.attname
            FROM pg_class AS seq
            JOIN pg_namespace AS ns ON ns.oid = seq.relnamespace
            LEFT JOIN pg_depend AS dep
              ON dep.objid = seq.oid AND dep.deptype = 'a'
            LEFT JOIN pg_class AS tbl ON tbl.oid = dep.refobjid
            LEFT JOIN pg_attribute AS att
              ON att.attrelid = tbl.oid AND att.attnum = dep.refobjsubid
            WHERE ns.nspname = 'public' AND seq.relkind = 'S'
            ORDER BY seq.relname
            """)
        sequence_rows = cursor.fetchall()
    result: list[dict[str, Any]] = []
    for sequence_name, table_name, column_name in sequence_rows:
        if table_name and column_name:
            max_query = sql.SQL("SELECT max({column}) FROM public.{table}").format(
                column=sql.Identifier(column_name), table=sql.Identifier(table_name)
            )
            with connection.cursor() as cursor:
                cursor.execute(max_query)
                maximum = cursor.fetchone()[0]
        elif sequence_name == "supervisor_events_event_seq_seq":
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT last_value, is_called FROM public.supervisor_events_event_seq_seq"
                )
                last_value, is_called = cursor.fetchone()
                cursor.execute(
                    "SELECT seqstart FROM pg_sequence "
                    "WHERE seqrelid = 'public.supervisor_events_event_seq_seq'::regclass"
                )
                start_row = cursor.fetchone()
                cursor.execute(
                    "SELECT column_default FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = 'supervisor_events' "
                    "AND column_name = 'event_seq'"
                )
                default_row = cursor.fetchone()
                cursor.execute(
                    "SELECT pg_get_serial_sequence('public.supervisor_events', 'event_seq')"
                )
                serial_row = cursor.fetchone()
            start_value = start_row[0] if start_row else None
            column_default = default_row[0] if default_row else None
            serial_binding = serial_row[0] if serial_row else None
            if (
                column_default is not None
                or serial_binding is not None
                or bool(is_called)
                or start_value is None
                or int(last_value) != int(start_value)
            ):
                raise ValueError(
                    "legacy supervisor event sequence is bound or consumed; "
                    "cannot claim unused-after-003 disposition"
                )
            result.append(
                {
                    "sequence": sequence_name,
                    "owned_by": None,
                    "status": "unused-after-003",
                    "consumer": "controller-assigned-event-seq; runtime-nextval-forbidden",
                    "set_value": int(last_value),
                    "is_called": bool(is_called),
                    "start_value": int(start_value),
                    "column_default": column_default,
                    "serial_binding": serial_binding,
                    "disposition": "preserved; no nextval reconciliation for unbound legacy sequence",
                }
            )
            continue
        else:
            raise ValueError(
                "unowned sequence requires an explicit reviewed mapping: "
                + sequence_name
            )
        if maximum is None:
            set_value, is_called = 1, False
        else:
            set_value, is_called = int(maximum), True
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT setval(%s::regclass, %s, %s)",
                (f"public.{sequence_name}", set_value, is_called),
            )
        result.append(
            {
                "sequence": sequence_name,
                "owned_by": (
                    f"{table_name}.{column_name}"
                    if table_name and column_name
                    else None
                ),
                "set_value": set_value,
                "is_called": is_called,
                "status": "active-owned-sequence",
                "consumer": "database-default-nextval",
            }
        )
    return result


def _per_run_sequence_checks(connection) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT controls.run_id, controls.event_seq_counter,
                   COALESCE(MAX(events.event_seq), 0)
            FROM public.controller_control AS controls
            LEFT JOIN public.supervisor_events AS events
              ON events.run_id = controls.run_id
            GROUP BY controls.run_id, controls.event_seq_counter
            ORDER BY controls.run_id
            """
        )
        rows = cursor.fetchall()
    checks = [
        {
            "run_id": str(run_id),
            "event_seq_counter": int(counter),
            "max_event_seq": int(max_event_seq),
            "safe": int(counter) >= int(max_event_seq),
        }
        for run_id, counter, max_event_seq in rows
    ]
    unsafe = [check["run_id"] for check in checks if not check["safe"]]
    if unsafe:
        raise ValueError(
            "copied controller event counters trail copied events: "
            + ", ".join(unsafe)
        )
    return checks


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


def _digest(rows: Iterable[Mapping[str, Any]]) -> str:
    normalized = [
        {key: _json_value(value) for key, value in row.items()} for row in rows
    ]
    normalized.sort(
        key=lambda row: json.dumps(
            row, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    )
    payload = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_evidence_digest(evidence: Mapping[str, Any]) -> str:
    """Hash emitted evidence after removing only its self-referential field."""
    body = dict(evidence)
    body.pop("evidence_sha256", None)
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
    ).hexdigest()


def _shared_digest_cross_check(
    table_evidence: Iterable[Mapping[str, Any]],
    post_evidence: Iterable[Mapping[str, Any]],
) -> bool:
    """Compare the reduced bridge contract using explicit per-table lookups."""
    source_by_table: dict[str, str] = {}
    for item in table_evidence:
        table = str(item["table"])
        if table in source_by_table:
            raise ValueError(f"bridge digest cross-check has duplicate source table: {table}")
        source_by_table[table] = str(item["source_digest"])
    target_by_table: dict[str, str] = {}
    for item in post_evidence:
        table = str(item["table"])
        if table in target_by_table:
            raise ValueError(f"bridge digest cross-check has duplicate target table: {table}")
        target_by_table[table] = str(item["target_digest"])
    shared_tables = [
        table for table, _keys, _columns in TABLES if table != "evidence_index"
    ]
    missing_source = sorted(set(shared_tables) - set(source_by_table))
    missing_target = sorted(set(shared_tables) - set(target_by_table))
    if missing_source or missing_target:
        raise ValueError(
            "bridge digest cross-check is missing table evidence: "
            f"source={missing_source}, target={missing_target}"
        )
    return all(
        source_by_table[table] == target_by_table[table] for table in shared_tables
    )


def _read_rows(
    connection, table: str, columns: tuple[str, ...], keys: tuple[str, ...]
) -> list[dict[str, Any]]:
    query = sql.SQL("SELECT {columns} FROM public.{table} ORDER BY {keys}").format(
        columns=sql.SQL(", ").join(sql.Identifier(column) for column in columns),
        table=sql.Identifier(table),
        keys=sql.SQL(", ").join(sql.Identifier(key) for key in keys),
    )
    with connection.cursor() as cursor:
        cursor.execute(query)
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _insert_rows(
    connection, table: str, columns: tuple[str, ...], rows: list[dict[str, Any]]
) -> None:
    if not rows:
        return
    query = sql.SQL("INSERT INTO public.{table} ({columns}) VALUES ({values})").format(
        table=sql.Identifier(table),
        columns=sql.SQL(", ").join(sql.Identifier(column) for column in columns),
        values=sql.SQL(", ").join(sql.Placeholder() for _ in columns),
    )
    with connection.cursor() as cursor:
        for row in rows:
            cursor.execute(query, [row[column] for column in columns])


def _update_parent_attempt_ids(connection, rows: list[dict[str, Any]]) -> None:
    with connection.cursor() as cursor:
        for row in rows:
            if row["active_attempt_id"] is not None:
                cursor.execute(
                    "UPDATE public.parent_tasks SET active_attempt_id = %s WHERE task_id = %s AND run_id = %s",
                    (row["active_attempt_id"], row["task_id"], row["run_id"]),
                )


def bridge(
    source_url: str,
    target_url: str,
    evidence_path: Path,
    *,
    candidate_sha: str | None = None,
    tree_sha: str | None = None,
    signing_key_file: Path = REVIEW_SIGNING_PRIVATE_KEY_PATH,
    verify_key_file: Path = REVIEW_SIGNING_PUBLIC_KEY_PATH,
    include_legacy_raw: bool = False,
) -> dict[str, Any]:
    source_name, source, source_identity = _connect_verified(source_url, "source_url")
    target_name, target, target_identity = _connect_verified(target_url, "target_url")
    if source_name == target_name:
        source.close()
        target.close()
        raise ValueError("source and target must be different databases")
    try:
        with source, target:
            with source.cursor() as cursor:
                cursor.execute(
                    "SET SESSION CHARACTERISTICS AS TRANSACTION "
                    "ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                )
                cursor.execute(
                    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                )
                cursor.execute("SHOW transaction_isolation")
                isolation_level = str(cursor.fetchone()[0])
                cursor.execute("SHOW transaction_read_only")
                read_only = str(cursor.fetchone()[0])
            if isolation_level != "repeatable read" or read_only != "on":
                raise ValueError(
                    f"source snapshot is not repeatable-read/read-only: {isolation_level}/{read_only}"
                )
            with target.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                cursor.execute("SHOW transaction_isolation")
                target_isolation = str(cursor.fetchone()[0])
                if target_isolation != "serializable":
                    raise ValueError(
                        f"target transaction is not serializable: {target_isolation}"
                    )
                target_pristine = _target_pristine(target)
            source_revision = _revision(source)
            target_revision = _revision(target)
            if source_revision != LEGACY_REVISION:
                raise ValueError(
                    f"source must be exactly {LEGACY_REVISION}, got {source_revision}"
                )
            if target_revision != BASELINE_REVISION:
                raise ValueError(
                    f"target must be exactly {BASELINE_REVISION}, got {target_revision}"
                )

            source_rows: dict[str, list[dict[str, Any]]] = {}
            table_evidence: list[dict[str, Any]] = []
            legacy_attestations: list[dict[str, Any]] = []
            relation_completeness = _source_relation_completeness(source)
            completeness = _schema_completeness(source)
            for table, keys, columns in TABLES:
                source_columns = _available_columns(source, table)
                target_columns = _available_columns(target, table)
                missing_source = set(columns) - source_columns
                missing_target = set(columns) - target_columns
                if missing_source or missing_target:
                    raise ValueError(
                        f"bridge schema mismatch for {table}: source_missing={sorted(missing_source)} target_missing={sorted(missing_target)}"
                    )
                _assert_column_compatibility(source, target, table, columns)
                rows = _read_rows(source, table, columns, keys)
                source_rows[table] = rows
                old_columns = tuple(
                    column
                    for column in LEGACY_ONLY_COLUMNS.get(table, ())
                    if column in source_columns
                )
                old_rows = (
                    _read_rows(source, table, keys + old_columns, keys)
                    if old_columns
                    else []
                )
                legacy_attestations.append(
                    {
                        "table": table,
                        "columns": list(old_columns),
                        "row_count": len(old_rows),
                        "digest": _digest(old_rows) if old_rows else None,
                        "rows": (
                            [
                                {
                                    key: _json_value(value)
                                    for key, value in row.items()
                                }
                                for row in old_rows
                            ]
                            if include_legacy_raw
                            else []
                        ),
                        "raw_values_included": include_legacy_raw,
                        "disposition": "retained in source backup attestation; no mainline consumer",
                    }
                )
                table_evidence.append(
                    {
                        "table": table,
                        "keys": list(keys),
                        "columns": list(columns),
                        "source_row_count": len(rows),
                        "source_digest": _digest(rows),
                        "digest_scope": BRIDGE_DIGEST_SCOPE,
                    }
                )

            parent_rows = [
                dict(row, active_attempt_id=None) for row in source_rows["parent_tasks"]
            ]
            for table, _keys, columns in TABLES:
                _insert_rows(
                    target,
                    table,
                    columns,
                    parent_rows if table == "parent_tasks" else source_rows[table],
                )
            _update_parent_attempt_ids(target, source_rows["parent_tasks"])
            post_evidence: list[dict[str, Any]] = []
            for table, keys, columns in TABLES:
                rows = _read_rows(target, table, columns, keys)
                if rows != source_rows[table]:
                    raise ValueError(f"post-bridge data mismatch in {table}")
                post_evidence.append(
                    {
                        "table": table,
                        "target_row_count": len(rows),
                        "target_digest": _digest(rows),
                        "digest_scope": BRIDGE_DIGEST_SCOPE,
                    }
                )
            shared_column_copy_digests_match = _shared_digest_cross_check(
                table_evidence, post_evidence
            )
            if not shared_column_copy_digests_match:
                raise ValueError(
                    "bridge shared-column digest cross-check failed; refusing evidence"
                )
            per_run_sequence_checks = _per_run_sequence_checks(target)
            sequence_evidence = _resynchronize_sequences(target)
            target.commit()
    finally:
        source.close()
        target.close()

    if candidate_sha is None or tree_sha is None:
        candidate_sha, tree_sha = _git_provenance()
    evidence: dict[str, Any] = {
        "schema": "top-delivery/legacy-section0-bridge/v1",
        "status": "passed",
        "candidate_sha": candidate_sha,
        "tree_sha": tree_sha,
        "source": {
            "database_name": source_name,
            "revision": source_revision,
            "read_only_transaction": read_only == "on",
            "transaction_isolation": isolation_level,
            "connection": source_identity,
        },
        "target": {
            "database_name": target_name,
            "revision_before_mainline_upgrade": target_revision,
            "connection": target_identity,
            "transaction_isolation": target_isolation,
            "empty_before_copy": True,
            "pristine_before_copy": target_pristine,
        },
        "migration_policy": {
            "legacy_revision_copied": False,
            "revision_relabeled": False,
            "next_step": "run verified mainline migrations 004_longspan_workflow through 008_longspan_authority_repair",
        },
        "schema_completeness": completeness,
        "source_relation_completeness": relation_completeness,
        "tables": table_evidence,
        "post_bridge": post_evidence,
        "digest_cross_check": {
            "shared_column_copy_digests_match": shared_column_copy_digests_match,
            "bridge_scope": BRIDGE_DIGEST_SCOPE,
            "live_snapshot_scope": SNAPSHOT_DIGEST_SCOPE,
            "shared_column_tables": [
                table for table, _keys, _columns in TABLES if table != "evidence_index"
            ],
            "intentionally_non_comparable": {
                "evidence_index": {
                    "bridge_columns": list(
                        next(columns for table, _keys, columns in TABLES if table == "evidence_index")
                    ),
                    "legacy_only_columns": list(LEGACY_ONLY_COLUMNS["evidence_index"]),
                    "live_snapshot_includes_all_columns": True,
                    "disposition": (
                        "legacy-only columns are retained in the source backup attestation; "
                        "the mainline bridge copies only the reviewed shared contract"
                    ),
                }
            },
            "method": (
                "shared columns use the same canonical JSON row normalization and "
                "stable row ordering; full-snapshot digests are not compared to a "
                "reduced bridge contract"
            ),
        },
        "sequence_reconciliation": sequence_evidence,
        "per_run_sequence_checks": per_run_sequence_checks,
        "legacy_only_attestations": legacy_attestations,
        "legacy_raw_values_included": include_legacy_raw,
    }
    evidence["evidence_hash_scope"] = (
        "sha256(canonical UTF-8 JSON with sort_keys=true and compact separators "
        "after removing evidence_sha256)"
    )
    evidence["evidence_sha256"] = _canonical_evidence_digest(evidence)
    signing_key = _read_pinned_key(signing_key_file)
    verify_key = _read_pinned_key(verify_key_file)
    signature = sign_message(
        domain_separated_message(
            str(evidence["schema"]), str(evidence["evidence_sha256"])
        ),
        signing_key,
    )
    if not verify_message_signature(
        domain_separated_message(
            str(evidence["schema"]), str(evidence["evidence_sha256"])
        ),
        signature,
        verify_key,
    ):
        raise ValueError("bridge evidence signature failed pinned-key verification")
    evidence["signature_algorithm"] = (
        "Ed25519 over domain-separated evidence_sha256"
    )
    evidence["signature"] = signature
    evidence["verify_key_sha256"] = hashlib.sha256(
        verify_key.encode("ascii")
    ).hexdigest()
    encoded = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        evidence_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
    except Exception:
        try:
            evidence_path.unlink()
        except FileNotFoundError:
            pass
        raise
    if stat.S_IMODE(evidence_path.stat().st_mode) != 0o600:
        raise PermissionError("bridge evidence must be mode 0600")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--include-legacy-raw", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            bridge(
                args.source_url,
                args.target_url,
                args.evidence,
                include_legacy_raw=args.include_legacy_raw,
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
