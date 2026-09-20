#!/usr/bin/env python3
"""Capture a digest-only snapshot from the pinned live Comms-01 database host.

Run this on Comms-01 as the pinned read-only PostgreSQL operator. The output
contains no row values. It is written as an unsigned capture by the pinned
read-only PostgreSQL operator; the root-only Comms-01 signing step signs the
exact capture before transport.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_REPEATABLE_READ

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

from legacy_section0_bridge import SNAPSHOT_DIGEST_SCOPE, _revision  # noqa: E402
from verify_section0_rollback import _table_snapshot_from_connection  # noqa: E402


LIVE_SOCKET = "/var/run/postgresql"
LIVE_PORT = 5432
TRANSPORT_ROLE = "top_delivery_backup_transport"
BACKUP_ROLE = "top_delivery_backup_reader"
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-database-name", default="top_delivery_control_p1")
    parser.add_argument("--backup-output", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    connection = psycopg2.connect(
        dbname=args.expected_database_name,
        user=TRANSPORT_ROLE,
        host=LIVE_SOCKET,
        port=LIVE_PORT,
        options="-c search_path=public",
    )
    try:
        connection.set_session(
            isolation_level=ISOLATION_LEVEL_REPEATABLE_READ,
            readonly=True,
            autocommit=False,
        )
        with connection.cursor() as cursor:
            cursor.execute("SET ROLE top_delivery_backup_reader")
            cursor.execute("SET LOCAL default_transaction_read_only = on")
            cursor.execute("SELECT pg_export_snapshot()")
            snapshot_id = str(cursor.fetchone()[0])
            cursor.execute(
                "SELECT current_database(), session_user, current_user,"
                " inet_server_addr()::text, inet_server_port(),"
                " current_schema(), current_setting('search_path'),"
                " current_setting('transaction_isolation'),"
                " current_setting('transaction_read_only'),"
                " current_setting('default_transaction_read_only')"
            )
            (
                database_name,
                session_user,
                database_user,
                address,
                port,
                schema,
                search_path,
                transaction_isolation,
                transaction_read_only,
                default_transaction_read_only,
            ) = cursor.fetchone()
            revision = _revision(connection)
        if database_name != args.expected_database_name:
            raise RuntimeError("live snapshot connected to an unexpected database")
        if schema != "public" or search_path != "public":
            raise RuntimeError("live snapshot search_path is not pinned to public")
        if (
            session_user != TRANSPORT_ROLE
            or database_user != BACKUP_ROLE
            or transaction_isolation != "repeatable read"
            or transaction_read_only != "on"
            or default_transaction_read_only != "on"
        ):
            raise RuntimeError(
                "live snapshot role/transaction mode is not dedicated read-only"
            )
        if revision != "004_auditor_provenance":
            raise RuntimeError("live snapshot is not the accepted legacy revision")
        if args.backup_output is not None:
            args.backup_output.parent.mkdir(parents=True, exist_ok=True)
            previous_umask = os.umask(0o077)
            try:
                subprocess.run(
                    [
                        "pg_dump",
                        "--format=custom",
                        "--no-owner",
                        "--no-privileges",
                        f"--role={BACKUP_ROLE}",
                        f"--snapshot={snapshot_id}",
                        f"--file={args.backup_output}",
                    ],
                    check=True,
                    env={
                        key: value
                        for key, value in os.environ.items()
                        if not key.startswith("PG")
                    }
                    | {
                        "PGDATABASE": args.expected_database_name,
                        "PGUSER": TRANSPORT_ROLE,
                        "PGHOST": LIVE_SOCKET,
                        "PGPORT": str(LIVE_PORT),
                    },
                    # pg_dump connects as the peer-authenticated session user,
                    # then applies the same dedicated read-only role.
                    # The role is also checked below by the signed snapshot.
                )
            finally:
                os.umask(previous_umask)
            args.backup_output.chmod(0o600)
        snapshot = _table_snapshot_from_connection(connection)
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT max(event_seq), count(*) FROM public.supervisor_events"
            )
            max_event_seq, event_count = cursor.fetchone()
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
        sequence_name = "supervisor_events_event_seq_seq"
        sequence_state = snapshot["sequences"].get(sequence_name)
        if not isinstance(sequence_state, dict):
            raise RuntimeError("required supervisor event sequence is missing")
        column_default = default_row[0] if default_row else None
        serial_binding = serial_row[0] if serial_row else None
        active_sequence = bool(column_default or serial_binding)
        if active_sequence and int(sequence_state["last_value"]) < int(max_event_seq or 0):
            raise RuntimeError("active supervisor event sequence is behind table data")
        sequence_safety = {
            sequence_name: {
                "status": "active" if active_sequence else "unused-after-003",
                "safe_for_automatic_insert": active_sequence,
                "consumer": (
                    "controller-assigned-event-seq; runtime-nextval-forbidden"
                    if not active_sequence
                    else "database-default-nextval"
                ),
                "last_value": int(sequence_state["last_value"]),
                "is_called": bool(sequence_state["is_called"]),
                "max_event_seq": int(max_event_seq or 0),
                "event_row_count": int(event_count or 0),
                "column_default": column_default,
                "serial_binding": serial_binding,
                "reason": (
                    "legacy mainline 003 removed the global event_seq default; "
                    "controller assigns per-run event_seq values"
                    if not active_sequence
                    else "sequence is bound to the event_seq default"
                ),
            }
        }
    finally:
        connection.close()
    payload: dict[str, object] = {
        "schema": "top-delivery/section0-live-snapshot/v1",
        "status": "passed",
        "server_derived": True,
        "live_mutation": False,
        "snapshot_digest_scope": SNAPSHOT_DIGEST_SCOPE,
        "database_identity": {
            "current_database": database_name,
            "session_user": session_user,
            "current_user": database_user,
            "inet_server_addr": address,
            "inet_server_port": port,
            "current_schema": schema,
            "search_path": search_path,
            "revision": revision,
            "transaction_isolation": transaction_isolation,
            "transaction_read_only": transaction_read_only,
            "default_transaction_read_only": default_transaction_read_only,
            "backup_role": BACKUP_ROLE,
            "transport_role": TRANSPORT_ROLE,
            "exported_snapshot_id": snapshot_id,
        },
        "snapshot": snapshot,
        "sequence_safety": sequence_safety,
        "transport": "authenticated-ssh-from-pinned-Comms-01-host",
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
    except Exception:
        try:
            args.output.unlink()
        except FileNotFoundError:
            pass
        raise
    if stat.S_IMODE(args.output.stat().st_mode) != 0o600:
        raise RuntimeError("live snapshot must be mode 0600")
    print("live snapshot captured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
