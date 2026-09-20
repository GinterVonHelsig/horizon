"""Out-of-band bootstrap for PostgreSQL migration namespaces.

This module is intentionally separate from Alembic ``env.py``.  A pinned
local PostgreSQL administrator runs it before a migration.  The migration
environment only verifies the resulting objects; it never creates a schema or
changes ownership as an implicit migration side effect.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from urllib.parse import urlsplit

import psycopg2
from psycopg2 import sql

from authority_pins import (
    ADMIN_DATABASE_ROLES,
    AUTHORITY_DATABASE_ROLE,
    MIGRATION_DATABASE_ROLE,
    WORKFLOW_DATABASE_ROLE,
)
from comms01_scope import (
    ALLOWED_DATABASE_NAME,
    assert_admin_database_url,
    is_disposable_test_database,
)
from exceptions import AuthorizationFailureError


LEGACY_ROUTINES_REQUIRING_OWNER_NORMALIZATION = (
    # Migration 001 creates this append-only trigger function before the
    # dedicated migration principal exists.  A restored 003 baseline can
    # therefore legitimately retain the transport/dump owner.  Normalize
    # this exact, catalogued routine during the explicit administrator
    # bootstrap so 006 can run entirely under top_delivery_migration.
    "reject_evidence_index_mutation()",
)


def normalize_legacy_routine_owners(cursor) -> list[dict[str, str | None]]:
    """Transfer only the reviewed legacy routine and attest the branch taken."""

    evidence: list[dict[str, str | None]] = []
    for routine_signature in LEGACY_ROUTINES_REQUIRING_OWNER_NORMALIZATION:
        cursor.execute(
            "SELECT to_regprocedure(%s), pg_get_userbyid(p.proowner) "
            "FROM pg_proc AS p "
            "WHERE p.oid = to_regprocedure(%s)",
            (routine_signature, routine_signature),
        )
        routine = cursor.fetchone()
        if routine is None or routine[0] is None:
            evidence.append(
                {
                    "signature": routine_signature,
                    "before_owner": None,
                    "after_owner": None,
                    "action": "absent",
                }
            )
            continue
        if str(routine[0]) != routine_signature:
            raise AuthorizationFailureError(
                "legacy routine catalog returned an unexpected signature"
            )
        before_owner = str(routine[1])
        if before_owner != MIGRATION_DATABASE_ROLE:
            routine_sql = sql.SQL("{}.{}()").format(
                sql.Identifier("public"),
                sql.Identifier("reject_evidence_index_mutation"),
            )
            cursor.execute(
                sql.SQL("ALTER FUNCTION {} OWNER TO {}").format(
                    routine_sql,
                    sql.Identifier(MIGRATION_DATABASE_ROLE),
                )
            )
            after_owner = MIGRATION_DATABASE_ROLE
            action = "normalized"
        else:
            after_owner = before_owner
            action = "already-normalized"
        evidence.append(
            {
                "signature": routine_signature,
                "before_owner": before_owner,
                "after_owner": after_owner,
                "action": action,
            }
        )
    return evidence


def bootstrap_migration_namespace(database_url: str) -> dict[str, object]:
    """Provision and verify the exact migration namespace on one target.

    The function accepts only the canonical Comms-01 control database or an
    explicitly disposable test/downgrade database.  It performs no data
    deletion and never grants runtime roles DDL authority.
    """

    assert_admin_database_url(database_url, allow_control_database=True)
    parsed = urlsplit(database_url)
    database_name = parsed.path.lstrip("/")
    if database_name != ALLOWED_DATABASE_NAME and not is_disposable_test_database(
        database_url
    ):
        raise AuthorizationFailureError(
            "migration bootstrap target is outside the Comms-01 control boundary"
        )
    expected_role = parsed.username
    if expected_role not in ADMIN_DATABASE_ROLES:
        raise AuthorizationFailureError(
            "migration bootstrap requires a pinned local administrator role"
        )

    with closing(psycopg2.connect(database_url)) as connection:
        connection.autocommit = True
        with connection.cursor() as identity_cursor:
            identity_cursor.execute(
                "SELECT current_database(), current_user, session_user"
            )
            actual_database, actual_role, session_role = identity_cursor.fetchone()
        if actual_database != database_name or actual_role != expected_role:
            raise AuthorizationFailureError(
                "migration bootstrap connected identity does not match the pinned URL"
            )
        if session_role != expected_role:
            raise AuthorizationFailureError(
                "migration bootstrap session identity does not match the pinned URL"
            )
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT rolname, rolsuper, rolcreatedb, rolcreaterole,
                       rolcanlogin, rolinherit
                FROM pg_roles
                WHERE rolname = %s
                """,
                (MIGRATION_DATABASE_ROLE,),
            )
            migration_role = cursor.fetchone()
            if migration_role is None:
                raise AuthorizationFailureError(
                    "migration bootstrap requires the pre-provisioned migration role"
                )
            if (
                migration_role[1]
                or migration_role[2]
                or migration_role[3]
                or migration_role[4]
                or migration_role[5]
            ):
                raise AuthorizationFailureError(
                    "migration bootstrap found an unsafe migration role"
                )
            for runtime_role in (WORKFLOW_DATABASE_ROLE, AUTHORITY_DATABASE_ROLE):
                cursor.execute(
                    "SELECT 1 FROM pg_roles WHERE rolname = %s", (runtime_role,)
                )
                if cursor.fetchone() is None:
                    raise AuthorizationFailureError(
                        f"migration bootstrap requires pre-provisioned role {runtime_role}"
                    )

            # A logical restore of the historical 003 baseline may preserve
            # the original owner of the 001 trigger function.  Transfer only
            # the exact reviewed legacy routine; do not discover or adopt
            # arbitrary functions.  This is explicit root/admin bootstrap,
            # before SET ROLE, so Alembic 006 remains owner-safe and no
            # migration principal needs superuser or CREATEROLE privilege.
            owner_evidence = normalize_legacy_routine_owners(cursor)

            # These are the only namespace/metadata ownership writes allowed
            # here. They are explicit operator bootstrap actions, not hidden
            # migration behavior.
            cursor.execute(
                sql.SQL(
                    "CREATE SCHEMA IF NOT EXISTS top_delivery_recovery AUTHORIZATION {}"
                ).format(sql.Identifier(MIGRATION_DATABASE_ROLE))
            )
            cursor.execute(
                sql.SQL("ALTER SCHEMA top_delivery_recovery OWNER TO {}").format(
                    sql.Identifier(MIGRATION_DATABASE_ROLE)
                )
            )
            cursor.execute(
                sql.SQL("REVOKE ALL ON SCHEMA top_delivery_recovery FROM PUBLIC, {}, {}")
                .format(
                    sql.Identifier(WORKFLOW_DATABASE_ROLE),
                    sql.Identifier(AUTHORITY_DATABASE_ROLE),
                )
            )
            cursor.execute(
                sql.SQL("GRANT USAGE ON SCHEMA top_delivery_recovery TO {}").format(
                    sql.Identifier(MIGRATION_DATABASE_ROLE)
                )
            )
            # Pre-create Alembic's metadata table under the migration owner so
            # Alembic never creates it while still connected as the transport
            # administrator. The shape is Alembic's standard version-table
            # contract and is intentionally limited to this metadata table.
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS public.alembic_version (
                    version_num VARCHAR(32) NOT NULL,
                    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
                )
                """
            )
            cursor.execute(
                sql.SQL("ALTER TABLE public.alembic_version OWNER TO {}").format(
                    sql.Identifier(MIGRATION_DATABASE_ROLE)
                )
            )
            cursor.execute(
                sql.SQL("REVOKE ALL ON TABLE public.alembic_version FROM PUBLIC, {}, {}")
                .format(
                    sql.Identifier(WORKFLOW_DATABASE_ROLE),
                    sql.Identifier(AUTHORITY_DATABASE_ROLE),
                )
            )
            cursor.execute(
                "SELECT to_regclass('public.alembic_version') IS NOT NULL"
            )
            if cursor.fetchone()[0]:
                cursor.execute(
                    sql.SQL("ALTER TABLE public.alembic_version OWNER TO {}").format(
                        sql.Identifier(MIGRATION_DATABASE_ROLE)
                    )
                )
                cursor.execute(
                    sql.SQL("REVOKE ALL ON TABLE public.alembic_version FROM PUBLIC, {}, {}")
                    .format(
                        sql.Identifier(WORKFLOW_DATABASE_ROLE),
                        sql.Identifier(AUTHORITY_DATABASE_ROLE),
                    )
                )
            return {"legacy_routine_owner_normalization": owner_evidence}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        required=True,
        help="explicit pinned local PostgreSQL administrator URL",
    )
    args = parser.parse_args()
    bootstrap_migration_namespace(args.database_url)
    print("migration bootstrap verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
