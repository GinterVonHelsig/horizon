#!/usr/bin/env python3
"""Capture and sign the Comms-01 backup-reader role boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import psycopg2

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

ROLE = "top_delivery_backup_reader"
TRANSPORT_ROLE = "top_delivery_backup_transport"


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-database-name", default="top_delivery_control_p1")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    connection = psycopg2.connect(
        dbname=args.expected_database_name,
        user="postgres",
        host="/var/run/postgresql",
        port=5432,
        options="-c search_path=public",
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT current_database(), current_schema(), current_setting('search_path')"
            )
            database_name, schema, search_path = cursor.fetchone()
            role_rows = {}
            for role_name in (ROLE, TRANSPORT_ROLE):
                cursor.execute(
                    """
                    SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit
                    FROM pg_roles WHERE rolname = %s
                    """,
                    (role_name,),
                )
                role_row = cursor.fetchone()
                if role_row is None:
                    raise RuntimeError(f"required backup role is missing: {role_name}")
                role_rows[role_name] = role_row
            cursor.execute(
                """
                SELECT c.relname,
                       has_table_privilege(%s, format('public.%%I', c.relname), 'SELECT'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'INSERT'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'UPDATE'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'DELETE'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'SELECT'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'INSERT'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'UPDATE'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'DELETE'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'TRUNCATE'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'REFERENCES'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'TRIGGER'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'TRUNCATE'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'REFERENCES'),
                       has_table_privilege(%s, format('public.%%I', c.relname), 'TRIGGER')
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
                ORDER BY c.relname
                """,
                (
                    ROLE, ROLE, ROLE, ROLE,
                    TRANSPORT_ROLE, TRANSPORT_ROLE, TRANSPORT_ROLE, TRANSPORT_ROLE,
                    ROLE, ROLE, ROLE, TRANSPORT_ROLE, TRANSPORT_ROLE, TRANSPORT_ROLE,
                ),
            )
            tables = [
                {
                    "table": str(row[0]),
                    "select": bool(row[1]),
                    "insert": bool(row[2]),
                    "update": bool(row[3]),
                    "delete": bool(row[4]),
                    "transport_select": bool(row[5]),
                    "transport_insert": bool(row[6]),
                    "transport_update": bool(row[7]),
                    "transport_delete": bool(row[8]),
                    "truncate": bool(row[9]),
                    "references": bool(row[10]),
                    "trigger": bool(row[11]),
                    "transport_truncate": bool(row[12]),
                    "transport_references": bool(row[13]),
                    "transport_trigger": bool(row[14]),
                }
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """
                SELECT c.relname,
                       has_sequence_privilege(%s, format('public.%%I', c.relname), 'SELECT'),
                       has_sequence_privilege(%s, format('public.%%I', c.relname), 'USAGE'),
                       has_sequence_privilege(%s, format('public.%%I', c.relname), 'UPDATE'),
                       has_sequence_privilege(%s, format('public.%%I', c.relname), 'SELECT'),
                       has_sequence_privilege(%s, format('public.%%I', c.relname), 'USAGE'),
                       has_sequence_privilege(%s, format('public.%%I', c.relname), 'UPDATE')
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind = 'S'
                ORDER BY c.relname
                """,
                (ROLE, ROLE, ROLE, TRANSPORT_ROLE, TRANSPORT_ROLE, TRANSPORT_ROLE),
            )
            sequences = [
                {
                    "sequence": str(row[0]),
                    "select": bool(row[1]),
                    "usage": bool(row[2]),
                    "update": bool(row[3]),
                    "transport_select": bool(row[4]),
                    "transport_usage": bool(row[5]),
                    "transport_update": bool(row[6]),
                }
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """
                SELECT c.relname,
                       COALESCE(
                           array_agg(acl.privilege_type ORDER BY acl.privilege_type)
                               FILTER (WHERE acl.grantee = 0),
                           ARRAY[]::text[]
                       )
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                LEFT JOIN LATERAL aclexplode(c.relacl) AS acl ON TRUE
                WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
                GROUP BY c.relname
                ORDER BY c.relname
                """
            )
            public_table_privileges = [
                {"table": str(row[0]), "privileges": [str(item) for item in row[1]]}
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """
                SELECT c.relname,
                       COALESCE(
                           array_agg(acl.privilege_type ORDER BY acl.privilege_type)
                               FILTER (WHERE acl.grantee = 0),
                           ARRAY[]::text[]
                       )
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                LEFT JOIN LATERAL aclexplode(c.relacl) AS acl ON TRUE
                WHERE n.nspname = 'public' AND c.relkind = 'S'
                GROUP BY c.relname
                ORDER BY c.relname
                """
            )
            public_sequence_privileges = [
                {"sequence": str(row[0]), "privileges": [str(item) for item in row[1]]}
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """
                SELECT member.rolname, parent.rolname, m.admin_option
                FROM pg_auth_members AS m
                JOIN pg_roles AS member ON member.oid = m.member
                JOIN pg_roles AS parent ON parent.oid = m.roleid
                WHERE member.rolname IN (%s, %s)
                ORDER BY member.rolname, parent.rolname
                """,
                (ROLE, TRANSPORT_ROLE),
            )
            role_memberships = [
                {
                    "member": str(row[0]),
                    "parent": str(row[1]),
                    "admin_option": bool(row[2]),
                }
                for row in cursor.fetchall()
            ]
            cursor.execute(
                """
                SELECT r.rolname, count(*)
                FROM pg_attribute AS a
                JOIN pg_class AS c ON c.oid = a.attrelid
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                CROSS JOIN LATERAL aclexplode(a.attacl) AS acl
                JOIN pg_roles AS r ON r.oid = acl.grantee
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p')
                  AND a.attnum > 0
                  AND NOT a.attisdropped
                  AND r.rolname IN (%s, %s)
                GROUP BY r.rolname
                ORDER BY r.rolname
                """,
                (ROLE, TRANSPORT_ROLE),
            )
            column_privileges = {str(row[0]): int(row[1]) for row in cursor.fetchall()}
            cursor.execute(
                "SELECT has_schema_privilege(%s, 'public', 'USAGE'), "
                "has_schema_privilege(%s, 'public', 'CREATE'), "
                "has_schema_privilege(%s, 'public', 'USAGE'), "
                "has_schema_privilege(%s, 'public', 'CREATE')",
                (ROLE, ROLE, TRANSPORT_ROLE, TRANSPORT_ROLE),
            )
            schema_usage, schema_create, transport_schema_usage, transport_schema_create = cursor.fetchone()
            cursor.execute(
                "SELECT pg_has_role(%s, %s, 'member')",
                (TRANSPORT_ROLE, ROLE),
            )
            transport_member = bool(cursor.fetchone()[0])
    finally:
        connection.close()
    def role_facts(role_name: str) -> dict[str, object]:
        role_row = role_rows[role_name]
        return {
            "role": role_name,
            "can_login": bool(role_row[0]),
            "superuser": bool(role_row[1]),
            "create_database": bool(role_row[2]),
            "create_role": bool(role_row[3]),
            "inherit": bool(role_row[4]),
        }

    role = role_facts(ROLE)
    transport_role = role_facts(TRANSPORT_ROLE)
    body: dict[str, object] = {
        "schema": "top-delivery/comms01-backup-reader-grants/v1",
        "status": "passed",
        "live_mutation": False,
        "database_name": database_name,
        "current_schema": schema,
        "search_path": search_path,
        "role": role,
        "transport_role": transport_role,
        "transport_membership": {"member": ROLE, "is_member": transport_member},
        "schema_usage": bool(schema_usage),
        "schema_create": bool(schema_create),
        "transport_schema_usage": bool(transport_schema_usage),
        "transport_schema_create": bool(transport_schema_create),
        "tables": tables,
        "sequences": sequences,
        "public_table_privileges": public_table_privileges,
        "public_sequence_privileges": public_sequence_privileges,
        "role_memberships": role_memberships,
        "column_privileges": {
            ROLE: int(column_privileges.get(ROLE, 0)),
            TRANSPORT_ROLE: int(column_privileges.get(TRANSPORT_ROLE, 0)),
        },
        "writes_allowed": any(
            table[field]
            for table in tables
            for field in (
                "insert", "update", "delete",
                "truncate", "references", "trigger",
                "transport_insert", "transport_update", "transport_delete",
                "transport_truncate", "transport_references", "transport_trigger",
            )
        ) or any(
            sequence[field]
            for sequence in sequences
            for field in ("update", "transport_update")
        ),
    }
    if (
        database_name != args.expected_database_name
        or schema != "public"
        or search_path != "public"
        or role["can_login"]
        or role["superuser"]
        or role["create_database"]
        or role["create_role"]
        or not schema_usage
        or schema_create
        or not transport_role["can_login"]
        or transport_role["superuser"]
        or transport_role["create_database"]
        or transport_role["create_role"]
        or not transport_member
        or not transport_schema_usage
        or transport_schema_create
        or body["writes_allowed"]
        or body["column_privileges"][ROLE]
        or body["column_privileges"][TRANSPORT_ROLE]
        or any(item["privileges"] for item in public_table_privileges)
        or any(item["privileges"] for item in public_sequence_privileges)
        or {
            (item["member"], item["parent"], item["admin_option"])
            for item in role_memberships
        }
        != {(TRANSPORT_ROLE, ROLE, False)}
        or not all(table["select"] and table["transport_select"] for table in tables)
        or not all(
            not table[field]
            for table in tables
            for field in (
                "insert", "update", "delete", "truncate", "references", "trigger",
                "transport_insert", "transport_update", "transport_delete",
                "transport_truncate", "transport_references", "transport_trigger",
            )
        )
        or not all(
            not sequence[field]
            for sequence in sequences
            for field in ("update", "transport_update")
        )
    ):
        raise RuntimeError("backup reader role boundary is not least privilege")
    encoded = (json.dumps(body, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(encoded)
    if stat.S_IMODE(args.output.stat().st_mode) != 0o600:
        raise RuntimeError("role-grant artifact must be mode 0600")
    print(json.dumps({"status": "captured", "output_sha256": hashlib.sha256(encoded).hexdigest()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
