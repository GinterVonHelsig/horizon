"""Provision distinct PostgreSQL roles before migration 007 (test harness only)."""

from __future__ import annotations

import psycopg2

from authority_pins import (
    ATTACKER_DATABASE_ROLE,
    AUTHORITY_DATABASE_ROLE,
    MIGRATION_DATABASE_ROLE,
    WORKFLOW_DATABASE_ROLE,
)

WORKFLOW_PASSWORD = "td-workflow-test"
AUTHORITY_PASSWORD = "td-authority-test"
ATTACKER_PASSWORD = "td-attacker-test"

_REQUIRED_ROLES = (
    WORKFLOW_DATABASE_ROLE,
    AUTHORITY_DATABASE_ROLE,
    MIGRATION_DATABASE_ROLE,
    ATTACKER_DATABASE_ROLE,
)


def ensure_test_delivery_roles(
    admin_url: str = "postgresql://root@/postgres?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
) -> None:
    """Create cluster roles out-of-band before Alembic 007 runs (never from migration)."""
    with psycopg2.connect(admin_url) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                f"""
                DO $provision$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{WORKFLOW_DATABASE_ROLE}') THEN
                        CREATE ROLE {WORKFLOW_DATABASE_ROLE} LOGIN PASSWORD '{WORKFLOW_PASSWORD}'
                            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    ELSE
                        ALTER ROLE {WORKFLOW_DATABASE_ROLE} LOGIN PASSWORD '{WORKFLOW_PASSWORD}'
                            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{AUTHORITY_DATABASE_ROLE}') THEN
                        CREATE ROLE {AUTHORITY_DATABASE_ROLE} LOGIN PASSWORD '{AUTHORITY_PASSWORD}'
                            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    ELSE
                        ALTER ROLE {AUTHORITY_DATABASE_ROLE} LOGIN PASSWORD '{AUTHORITY_PASSWORD}'
                            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATION_DATABASE_ROLE}') THEN
                        CREATE ROLE {MIGRATION_DATABASE_ROLE} NOLOGIN
                            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    ELSE
                        ALTER ROLE {MIGRATION_DATABASE_ROLE} NOLOGIN
                            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ATTACKER_DATABASE_ROLE}') THEN
                        CREATE ROLE {ATTACKER_DATABASE_ROLE} LOGIN PASSWORD '{ATTACKER_PASSWORD}'
                            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    ELSE
                        ALTER ROLE {ATTACKER_DATABASE_ROLE} LOGIN PASSWORD '{ATTACKER_PASSWORD}'
                            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    END IF;
                    REVOKE {AUTHORITY_DATABASE_ROLE} FROM {WORKFLOW_DATABASE_ROLE};
                    REVOKE {WORKFLOW_DATABASE_ROLE} FROM {AUTHORITY_DATABASE_ROLE};
                    REVOKE {AUTHORITY_DATABASE_ROLE} FROM {ATTACKER_DATABASE_ROLE};
                    REVOKE {WORKFLOW_DATABASE_ROLE} FROM {ATTACKER_DATABASE_ROLE};
                    REVOKE {MIGRATION_DATABASE_ROLE} FROM {WORKFLOW_DATABASE_ROLE};
                    REVOKE {MIGRATION_DATABASE_ROLE} FROM {AUTHORITY_DATABASE_ROLE};
                    -- Older harnesses used wrapper roles.  Remove both
                    -- directions so the 007 transitive-membership audit does
                    -- not inherit stale privileges from a previous run.
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'td_workflow') THEN
                        REVOKE {WORKFLOW_DATABASE_ROLE}, {AUTHORITY_DATABASE_ROLE},
                            {MIGRATION_DATABASE_ROLE}, {ATTACKER_DATABASE_ROLE}
                            FROM td_workflow;
                        REVOKE td_workflow FROM {WORKFLOW_DATABASE_ROLE}, {AUTHORITY_DATABASE_ROLE},
                            {MIGRATION_DATABASE_ROLE}, {ATTACKER_DATABASE_ROLE};
                    END IF;
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'td_authority') THEN
                        REVOKE {WORKFLOW_DATABASE_ROLE}, {AUTHORITY_DATABASE_ROLE},
                            {MIGRATION_DATABASE_ROLE}, {ATTACKER_DATABASE_ROLE}
                            FROM td_authority;
                        REVOKE td_authority FROM {WORKFLOW_DATABASE_ROLE}, {AUTHORITY_DATABASE_ROLE},
                            {MIGRATION_DATABASE_ROLE}, {ATTACKER_DATABASE_ROLE};
                    END IF;
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'td_test_runner') THEN
                        REVOKE {WORKFLOW_DATABASE_ROLE}, {AUTHORITY_DATABASE_ROLE},
                            {MIGRATION_DATABASE_ROLE}, {ATTACKER_DATABASE_ROLE}
                            FROM td_test_runner;
                        REVOKE td_test_runner FROM {WORKFLOW_DATABASE_ROLE}, {AUTHORITY_DATABASE_ROLE},
                            {MIGRATION_DATABASE_ROLE}, {ATTACKER_DATABASE_ROLE};
                    END IF;
                END
                $provision$ LANGUAGE plpgsql;
                """
            )


def roles_are_provisioned(
    admin_url: str = "postgresql://root@/postgres?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
) -> bool:
    with psycopg2.connect(admin_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) FROM pg_roles
                WHERE rolname = ANY(%s)
                """,
                (list(_REQUIRED_ROLES),),
            )
            row = cur.fetchone()
            return row is not None and int(row[0]) == len(_REQUIRED_ROLES)
