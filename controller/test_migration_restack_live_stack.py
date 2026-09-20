"""Disposable proofs for live-stack migration graph reconciliation."""

from __future__ import annotations

import subprocess
import uuid

import psycopg2

from conftest import ADMIN_URL, _install_capability
from db import alembic_command, create_disposable_database, current_database_revision, drop_database
from migration_bootstrap import bootstrap_migration_namespace

LIVE_DB = "top_delivery_control_p1"
MIGRATION_ROLE = "top_delivery_migration"


def _normalize_clone_ownership(url: str) -> None:
    """Mirror live Comms-01 ownership after a schema-only clone drops ACLs."""
    with psycopg2.connect(url) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                f"""
                DO $normalize$
                DECLARE
                    rel record;
                    fn record;
                BEGIN
                    FOR rel IN
                        SELECT n.nspname, c.relname, c.relkind
                        FROM pg_class AS c
                        JOIN pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                          AND c.relkind IN ('r', 'S', 'v', 'm')
                    LOOP
                        EXECUTE format(
                            'ALTER %s %I.%I OWNER TO {MIGRATION_ROLE}',
                            CASE rel.relkind
                                WHEN 'r' THEN 'TABLE'
                                WHEN 'S' THEN 'SEQUENCE'
                                WHEN 'v' THEN 'VIEW'
                                WHEN 'm' THEN 'MATERIALIZED VIEW'
                            END,
                            rel.nspname,
                            rel.relname
                        );
                    END LOOP;
                    FOR fn IN
                        SELECT n.nspname,
                               p.proname,
                               pg_get_function_identity_arguments(p.oid) AS args
                        FROM pg_proc AS p
                        JOIN pg_namespace AS n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public'
                    LOOP
                        EXECUTE format(
                            'ALTER FUNCTION %I.%I(%s) OWNER TO {MIGRATION_ROLE}',
                            fn.nspname,
                            fn.proname,
                            fn.args
                        );
                    END LOOP;
                END
                $normalize$ LANGUAGE plpgsql;
                """
            )


def _clone_live_schema(name: str) -> str:
    subprocess.run(["sudo", "-u", "postgres", "createdb", "--encoding=UTF8", name], check=True)
    dump = subprocess.Popen(
        ["sudo", "-u", "postgres", "pg_dump", "--schema-only", "--no-owner", "--no-acl", LIVE_DB],
        stdout=subprocess.PIPE,
    )
    restore = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-d", name, "-q"],
        stdin=dump.stdout,
        capture_output=True,
        text=True,
    )
    dump.wait()
    if dump.returncode != 0 or restore.returncode != 0:
        raise RuntimeError(restore.stderr[-2000:])
    url = f"postgresql://root@/{name}?host=%2Fvar%2Frun%2Fpostgresql&port=5432"
    with psycopg2.connect(url) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f"GRANT USAGE, CREATE ON SCHEMA public TO {MIGRATION_ROLE}")
    bootstrap_migration_namespace(url)
    _normalize_clone_ownership(url)
    subprocess.run(
        [
            "sudo",
            "-u",
            "postgres",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            name,
            "-c",
            "SET ROLE top_delivery_migration; DELETE FROM alembic_version; "
            "INSERT INTO alembic_version (version_num) VALUES ('017_parent_rollback_routine');",
        ],
        check=True,
    )
    with psycopg2.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version_num FROM alembic_version")
            row = cur.fetchone()
            if row is None or row[0] != "017_parent_rollback_routine":
                raise RuntimeError(
                    f"clone must start at 017_parent_rollback_routine, got {row}"
                )
    return url


def test_upgrade_live_stack_from_017_clone() -> None:
    name = f"td_test_{uuid.uuid4().hex[:12]}_live017"
    url = _clone_live_schema(name)
    _install_capability(operation="create_database", database_name=name)
    try:
        alembic_command(url, "upgrade", "020_horizon_prereq_corr_live")
        assert current_database_revision(url) == "020_horizon_prereq_corr_live"
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT to_regclass('public.horizon_projects')")
                assert cur.fetchone()[0] is not None
                cur.execute("SELECT to_regclass('public.horizon_correlation_qa')")
                assert cur.fetchone()[0] is not None
    finally:
        _install_capability(operation="drop_database", database_name=name)
        drop_database(ADMIN_URL, name)


def test_disposable_horizon_branch_still_reaches_016() -> None:
    name = f"td_test_{uuid.uuid4().hex[:12]}_horizon"
    _install_capability(operation="create_database", database_name=name)
    url = create_disposable_database(ADMIN_URL, name)
    try:
        alembic_command(url, "upgrade", "016_horizon_prereq_corr")
        assert current_database_revision(url) == "016_horizon_prereq_corr"
    finally:
        _install_capability(operation="drop_database", database_name=name)
        drop_database(ADMIN_URL, name)
