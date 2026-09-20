"""Focused remediation tests for scope, authority, migration, and evidence."""

from __future__ import annotations

import os
import errno
import json
import copy
import hashlib
import inspect
import re
import stat
import shutil
import subprocess
import socket
import sys
import tempfile
import threading
import textwrap
import uuid
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import psycopg2
import pytest

from authority_socket import AuthorityWriteCredential
from authority_service_server import AuthorityServiceServer
from authority_socket_request import SOCKET_REQUEST_TTL_SECONDS, build_socket_request_envelope
from authority_pins import (
    AUTHORITY_DATABASE_ROLE,
    AUTHORITY_SERVICE_GID,
    AUTHORITY_SERVICE_UID,
    ATTACKER_DATABASE_ROLE,
    MIGRATION_DATABASE_ROLE,
)
from comms01_authority import Comms01AuthorityBoundary, ExternalOperatorApprovalReceipt
from comms01_scope import (
    ScopeBoundaryViolationError,
    assert_comms01_entrypoint,
    reject_broker_endpoint,
)
from db import (
    CANONICAL_ALEMBIC_HEAD,
    alembic_command,
    create_disposable_database,
    current_database_revision,
    drop_database,
    MIGRATION_SOURCE_PROVENANCE_ALGORITHM,
    MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION,
    migration_source_digest,
    resolve_canonical_revision,
    run_migrations,
)
from exceptions import (
    AuthorityServiceUnavailableError,
    AuthorizationFailureError,
    IntegrityFailureError,
    ProvenanceMismatchError,
    StaleFenceError,
)
from longspan import LongspanWorkflow, child_idempotency_key, default_inspector, default_plan_producer, default_task_handler
from longspan_crypto import (
    canonical_evidence_digest,
    compute_ledger_entry_hash,
    digest_payload,
    hash_capability_token,
    sign_payload,
)
from migration_target import requested_revision
from test_authority_helpers import sign_external_operator_receipt
from longspan_repository import LongspanRepository
from parent_controller import ParentController
from provenance import RunProvenanceTuple, capture_run_provenance, git_commit_sha, reject_provenance_drift
from repository import PostgresRepository
from terra_review import TerraReviewAuthority
from test_disposable_helpers import (
    TEST_SIGNING_KEY,
    TEST_VERIFY_KEY,
    install_create_capability,
    install_downgrade_capability,
    install_drop_capability,
)
from test_role_provision import ensure_test_delivery_roles
from test_longspan import (
    ADMIN_URL,
    OPERATOR_TOKEN,
    REVIEWED_SHA,
    TERRA_TOKEN,
    _provision_authority,
    _run_cycle,
    _seed_ready_parent,
    _workflow,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEWED_SHA = git_commit_sha(REPO_ROOT)


def _restore_route_fields(database_url: str) -> dict[str, object]:
    parsed = urlsplit(database_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    endpoint = parsed.hostname or unquote(query.get("host", [""])[0])
    port = parsed.port
    if port is None:
        port = int(query["port"][0])
    return {
        "database_name": parsed.path.lstrip("/"),
        "database_role": parsed.username,
        "database_endpoint": endpoint,
        "database_port": port,
    }


def _bind_restore_identity(
    database_url: str, restore_target: dict[str, object]
) -> dict[str, object]:
    from comms01_operation_entrypoints import _bind_restore_cluster_identity

    return _bind_restore_cluster_identity(database_url, restore_target)


def _restore_identity_digest_fields(
    restore_target: dict[str, object],
) -> dict[str, str]:
    return {
        "cluster_system_identifier": str(restore_target["cluster_system_identifier"]),
        "database_oid": str(restore_target["database_oid"]),
    }


def _create_test_database(name: str | None = None) -> tuple[str, str]:
    database_name = name or f"td_test_{uuid.uuid4().hex}"
    ensure_test_delivery_roles(ADMIN_URL)
    install_create_capability(database_name=database_name)
    return database_name, create_disposable_database(ADMIN_URL, database_name)


def _drop_test_database(database_name: str) -> None:
    install_drop_capability(database_name=database_name)
    drop_database(ADMIN_URL, database_name)


@contextmanager
def _isolated_role_graph_connection(*, include_workflow: bool = True):
    """Start a throwaway PostgreSQL cluster for migration role-graph tests.

    Role membership is cluster-global, so changing the shared Comms-01 test
    cluster is unsafe even when a finally block normally repairs it.  These
    tests exercise the real 007 SQL against a private ephemeral cluster
    instead.  No shared role catalog, database, or service is touched.
    """
    if os.geteuid() == 0:
        import pwd

        postgres = pwd.getpwnam("postgres")
        runuser = Path("/usr/sbin/runuser")
        if not runuser.is_file() or not os.access(runuser, os.X_OK):
            raise RuntimeError(f"role-graph harness requires pinned runuser: {runuser}")
        runner = [str(runuser), "-u", "postgres", "--"]
    else:
        runner = []

    # Use verified absolute binaries and a private Unix socket.  The role
    # graph tests must not open a TCP listener or probe/bind a host port.
    initdb_path = Path("/usr/lib/postgresql/17/bin/initdb")
    pg_ctl_path = Path("/usr/lib/postgresql/17/bin/pg_ctl")
    for binary in (initdb_path, pg_ctl_path):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f"role-graph harness requires pinned PostgreSQL binary: {binary}")
    initdb = str(initdb_path)
    pg_ctl = str(pg_ctl_path)
    cluster_dir = Path(tempfile.mkdtemp(prefix="top-delivery-role-graph-"))
    socket_dir = cluster_dir / "socket"
    socket_dir.mkdir()
    if os.geteuid() == 0:
        os.chown(cluster_dir, postgres.pw_uid, postgres.pw_gid)
        os.chown(socket_dir, postgres.pw_uid, postgres.pw_gid)
    data_dir = cluster_dir / "data"
    started = False
    try:
        subprocess.run(
            [*runner, initdb, "-D", str(data_dir), "--auth=trust", "--no-locale"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                *runner,
                pg_ctl,
                "-D",
                str(data_dir),
                "-o",
                f"-p 5432 -k {socket_dir} -h ''",
                "-w",
                "start",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        started = True
    except BaseException:
        subprocess.run(
            [*runner, pg_ctl, "-D", str(data_dir), "-m", "immediate", "-w", "stop"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        shutil.rmtree(cluster_dir, ignore_errors=True)
        raise
    conn = None
    admin_conn = None
    database_name = f"td_test_role_graph_{uuid.uuid4().hex}"
    try:
        admin_conn = psycopg2.connect(
            host=str(socket_dir), port=5432, dbname="postgres", user="postgres"
        )
        admin_conn.autocommit = True
        with admin_conn.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{database_name}"')
        admin_conn.close()
        admin_conn = None
        conn = psycopg2.connect(
            host=str(socket_dir), port=5432, dbname=database_name, user="postgres"
        )
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION pgcrypto")
            roles = [
                "top_delivery_authority",
                "top_delivery_attacker",
                "top_delivery_migration",
            ]
            if include_workflow:
                roles.insert(0, "top_delivery_workflow")
            for role in roles:
                login = "LOGIN" if role != "top_delivery_migration" else "NOLOGIN"
                cur.execute(
                    f"CREATE ROLE {role} {login} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT"
                )
            cur.execute(
                "GRANT USAGE, CREATE ON SCHEMA public TO top_delivery_migration"
            )
        yield conn
    finally:
        if conn is not None:
            conn.close()
        if admin_conn is not None:
            admin_conn.close()
        cleanup_errors: list[str] = []
        try:
            admin_conn = psycopg2.connect(
                host=str(socket_dir), port=5432, dbname="postgres", user="postgres"
            )
            admin_conn.autocommit = True
            with admin_conn.cursor() as cur:
                cur.execute(f'DROP DATABASE IF EXISTS "{database_name}"')
        except Exception as exc:  # pragma: no cover - cleanup failure path
            cleanup_errors.append(f"drop disposable role-graph database: {exc}")
        finally:
            if admin_conn is not None:
                admin_conn.close()
        if started:
            stop = subprocess.run(
                [*runner, pg_ctl, "-D", str(data_dir), "-m", "fast", "-w", "stop"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if stop.returncode != 0:
                cleanup_errors.append(
                    f"stop disposable role-graph cluster returned {stop.returncode}"
                )
        shutil.rmtree(cluster_dir, ignore_errors=False)
        if cluster_dir.exists():
            cleanup_errors.append("disposable role-graph cluster directory remains")
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))


def _run_007_upgrade_direct(connection) -> None:
    """Run only revision 007 under Alembic's operation context.

    The first 007 statement is the role/extension prerequisite.  Directly
    invoking the revision on the isolated cluster makes this test independent
    of the Comms-01 URL/attestation harness while still exercising the exact
    migration SQL and its pre-DDL boundary.
    """
    import importlib.util

    migration_path = REPO_ROOT / "controller/migrations/versions/007_longspan_authority_hardening.py"
    spec = importlib.util.spec_from_file_location("top_delivery_test_migration_007", migration_path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL

    dsn = connection.get_dsn_parameters()
    engine = create_engine(
        URL.create(
            "postgresql+psycopg2",
            username=dsn["user"],
            host=dsn["host"],
            port=int(dsn["port"]),
            database=dsn["dbname"],
        )
    )
    try:
        with engine.connect() as sql_connection:
            sql_connection.exec_driver_sql("SET ROLE top_delivery_migration")
            with Operations.context(MigrationContext.configure(sql_connection)):
                migration.upgrade()
    finally:
        engine.dispose()


def _run_008_downgrade_direct(connection, *, witness_rows=()) -> None:
    """Run the exact 008 downgrade SQL without env.py's capability guard.

    This deliberately exercises the migration-level archive-park witness on
    a private disposable target.  ``witness_rows`` are inserted in the same
    transaction as the migration so the test can prove that duplicate rows
    fail closed; callers can also commit a row before invoking this helper to
    prove that a prior transaction is not accepted as a witness.
    """
    import importlib.util

    migration_path = REPO_ROOT / "controller/migrations/versions/008_longspan_authority_repair.py"
    spec = importlib.util.spec_from_file_location("top_delivery_test_migration_008", migration_path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    import disposable_capability
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL

    dsn = connection.get_dsn_parameters()
    engine = create_engine(
        URL.create(
            "postgresql+psycopg2",
            username=dsn["user"],
            host=dsn["host"],
            port=int(dsn["port"]),
            database=dsn["dbname"],
        )
    )
    try:
        with engine.connect() as sql_connection:
            sql_connection.exec_driver_sql("SET ROLE top_delivery_migration")
            for row in witness_rows:
                sql_connection.exec_driver_sql(
                    """
                    INSERT INTO top_delivery_downgrade_capabilities
                        (nonce, operation, database_name, database_role,
                         transport_database_role, controller_service,
                         migration_revision, expires_at, consumed_at,
                         consumed_steps)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s,
                            COALESCE(%s, clock_timestamp()), %s)
                    """,
                    row,
                )
            original_guard = disposable_capability.require_connected_migration_downgrade
            disposable_capability.require_connected_migration_downgrade = (
                lambda **_kwargs: None
            )
            try:
                with Operations.context(MigrationContext.configure(sql_connection)):
                    migration.downgrade()
            finally:
                disposable_capability.require_connected_migration_downgrade = original_guard
    finally:
        engine.dispose()


def _authority_provision_attempt(workflow: LongspanWorkflow, run_id: str):
    boundary = Comms01AuthorityBoundary(workflow.repo, repo_root=REPO_ROOT)
    captured = capture_run_provenance(
        REPO_ROOT,
        reviewed_sha=REVIEWED_SHA,
        db_url=workflow.parent._repo.db_url,
    )
    controller_epoch = workflow.parent.controller_epoch(run_id)
    terra_hash = hash_capability_token(TERRA_TOKEN)
    operator_hash = hash_capability_token(OPERATOR_TOKEN)
    action_digest = digest_payload(
        {
            "action": "initial_provision",
            "run_id": run_id,
            "operator_identity": "operator@test",
            "reviewed_sha": REVIEWED_SHA,
            "tree_sha": captured.tree_sha,
            "source_digest": captured.source_digest,
            "controller_epoch": controller_epoch,
            "config_version": 1,
            "terra_auth_hash": terra_hash,
            "operator_auth_hash": operator_hash,
        }
    )
    challenge = boundary.issue_operator_2fa_challenge(
        run_id=run_id,
        action_type="initial_provision",
        action_digest=action_digest,
        operator_identity="operator@test",
        controller_epoch=controller_epoch,
        config_version=1,
        challenge_epoch=controller_epoch,
    )
    receipt = sign_external_operator_receipt(challenge)
    return boundary, captured, controller_epoch, receipt


def test_resolve_canonical_revision_rejects_partial() -> None:
    with pytest.raises(ValueError, match="partial revision"):
        resolve_canonical_revision("004")


def test_resolve_canonical_revision_rejects_relative() -> None:
    with pytest.raises(ValueError, match="relative"):
        resolve_canonical_revision("-1")


def test_migration_head_is_008() -> None:
    assert resolve_canonical_revision("head") == CANONICAL_ALEMBIC_HEAD


def test_migration_target_rejects_argv_parser_disagreement(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["alembic", "downgrade", "006_longspan_authority"])
    config = SimpleNamespace(
        cmd_opts=SimpleNamespace(revision="005_longspan_hardening", target=None)
    )
    with pytest.raises(ValueError, match="disagrees"):
        requested_revision("downgrade", config)
    config.cmd_opts.revision = "006_longspan_authority"
    assert requested_revision("downgrade", config) == "006_longspan_authority"


def test_migration_source_provenance_marker_matches_source() -> None:
    migration = (
        REPO_ROOT
        / "controller"
        / "migrations"
        / "versions"
        / f"{CANONICAL_ALEMBIC_HEAD}.py"
    ).read_text(encoding="utf-8")
    assert "MIGRATION_SOURCE_PROVENANCE_DIGEST = \"" in migration
    marker = migration.split("MIGRATION_SOURCE_PROVENANCE_DIGEST = \"", 1)[1].split(
        "\"", 1
    )[0]
    assert marker == migration_source_digest(CANONICAL_ALEMBIC_HEAD)


def test_008_external_source_anchor_rejects_missing_and_tampered_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """008 must fail before DDL when its out-of-band anchor is not trusted."""
    import importlib.util

    migration_path = (
        REPO_ROOT / "controller/migrations/versions/008_longspan_authority_repair.py"
    )
    spec = importlib.util.spec_from_file_location("test_migration_008_anchor", migration_path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    anchor = tmp_path / "migration-source.json"
    monkeypatch.setattr(migration, "MIGRATION_SOURCE_PROVENANCE_PATH", str(anchor))
    with pytest.raises(ScopeBoundaryViolationError, match="missing"):
        migration._assert_source_provenance()

    valid = {
        "algorithm": "sha256",
        "normalization_version": 1,
        "revision": "008_longspan_authority_repair",
        "source_digest": migration.MIGRATION_SOURCE_PROVENANCE_DIGEST,
    }
    anchor.write_text(json.dumps(valid), encoding="utf-8")
    anchor.chmod(0o600)
    for field, value in (
        ("algorithm", "sha512"),
        ("normalization_version", 2),
        ("revision", "007_longspan_authority_hardening"),
        ("source_digest", "0" * 64),
    ):
        tampered = dict(valid)
        tampered[field] = value
        anchor.write_text(json.dumps(tampered), encoding="utf-8")
        with pytest.raises(RuntimeError, match="pinned trust anchor"):
            migration._assert_source_provenance()

    if os.geteuid() == 0:
        os.chown(anchor, AUTHORITY_SERVICE_UID, 0)
        with pytest.raises(ScopeBoundaryViolationError, match="root-owned"):
            migration._assert_source_provenance()
        os.chown(anchor, 0, 0)
    anchor.chmod(0o644)
    with pytest.raises(ScopeBoundaryViolationError, match="permissions"):
        migration._assert_source_provenance()
    anchor.chmod(0o600)
    symlink = tmp_path / "migration-source-link.json"
    symlink.symlink_to(anchor)
    monkeypatch.setattr(migration, "MIGRATION_SOURCE_PROVENANCE_PATH", str(symlink))
    with pytest.raises(ScopeBoundaryViolationError, match="symlink"):
        migration._assert_source_provenance()


def test_008_downgrade_checks_source_anchor_before_capability_and_ddl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """008 downgrade verifies its root-owned source anchor before mutation."""
    import importlib.util

    migration_path = (
        REPO_ROOT / "controller/migrations/versions/008_longspan_authority_repair.py"
    )
    spec = importlib.util.spec_from_file_location("test_migration_008_downgrade_order", migration_path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    import disposable_capability

    calls: list[str] = []
    monkeypatch.setattr(migration, "_assert_source_provenance", lambda: calls.append("anchor"))
    monkeypatch.setattr(
        migration,
        "assert_migration_catalog",
        lambda _revision: calls.append("catalog"),
    )
    monkeypatch.setattr(
        disposable_capability,
        "require_connected_migration_downgrade",
        lambda **_kwargs: calls.append("capability"),
    )
    monkeypatch.setattr(migration.op, "execute", lambda _sql: calls.append("ddl"))

    migration.downgrade()

    assert calls[0] == "anchor"
    assert calls.index("anchor") < calls.index("capability") < calls.index("ddl")


@pytest.mark.parametrize(
    "revision",
    (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
    ),
)
def test_historical_upgrade_checks_source_anchor_before_mutation(
    revision: str,
) -> None:
    """Every historical upgrade verifies its exact source before catalog/DDL."""
    import ast

    source_path = REPO_ROOT / "controller/migrations/versions" / f"{revision}.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    upgrade = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "upgrade"
    )
    first = upgrade.body[0]
    assert isinstance(first, ast.Expr)
    assert isinstance(first.value, ast.Call)
    assert isinstance(first.value.func, ast.Name)
    assert first.value.func.id == "verify_migration_source_anchor"


def test_env_anchor_rejects_tampered_008_before_downgrade_ddl(
    tmp_path: Path,
) -> None:
    """The env-level verifier rejects 008 tampering before any DDL callback."""
    from migration_source_anchor import (
        CANONICAL_MIGRATION,
        normalized_source_digest,
        verify_migration_source_anchor,
    )

    source_path = (
        REPO_ROOT
        / "controller/migrations/versions/008_longspan_authority_repair.py"
    )
    source = source_path.read_bytes()
    anchor = tmp_path / "migration-source-anchor.json"
    anchor.write_text(
        json.dumps(
            {
                "algorithm": "sha256",
                "normalization_version": 1,
                "revision": CANONICAL_MIGRATION,
                "source_digest": normalized_source_digest(source),
            }
        ),
        encoding="utf-8",
    )
    anchor.chmod(0o600)
    tampered_path = tmp_path / "008-tampered.py"
    tampered_path.write_bytes(
        source.replace(
            b"    _assert_source_provenance()\n",
            b"",
            1,
        )
    )
    ddl_reached: list[str] = []

    def guarded_downgrade() -> None:
        verify_migration_source_anchor(
            CANONICAL_MIGRATION,
            source_path=tampered_path,
            anchor_path=anchor,
        )
        ddl_reached.append("ddl")

    with pytest.raises(ProvenanceMismatchError, match="root-owned trust anchor"):
        guarded_downgrade()
    assert ddl_reached == []


def test_env_guard_rejects_before_any_database_access() -> None:
    """The real env.py guard calls the independent verifier before SQL."""
    import ast

    env_source = (REPO_ROOT / "controller/migrations/env.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(env_source, filename="controller/migrations/env.py")
    guard = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_guard_downgrade"
    )
    calls: list[str] = []

    def verifier(*_args: object, **_kwargs: object) -> None:
        calls.append("anchor")
        raise ProvenanceMismatchError("tampered 008 source")

    namespace: dict[str, object] = {
        "__name__": "test_env_guard",
        "_requested_revision": lambda _command: "007_longspan_authority_hardening",
        "verify_migration_source_anchor": verifier,
        "MIGRATION_SOURCE_PROVENANCE_PATH": "/invalid/test-anchor.json",
        "_DOWNGRADE_SOURCE_PATHS": {
            "007_longspan_authority_hardening": (
                "008_longspan_authority_repair",
                "007_longspan_authority_hardening",
            )
        },
    }
    module = ast.Module(body=[guard], type_ignores=[])
    exec(compile(module, "controller/migrations/env.py", "exec"), namespace)

    class UnexpectedDatabaseAccess:
        def execute(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("database access occurred before source verification")

    with pytest.raises(ProvenanceMismatchError, match="tampered 008 source"):
        namespace["_guard_downgrade"](
            UnexpectedDatabaseAccess(),  # type: ignore[operator]
        )
    assert calls == ["anchor"]


def test_env_guard_verifies_every_intermediate_downgrade_source() -> None:
    """A multi-step downgrade cannot skip an unverified intermediate body."""
    import ast

    env_source = (REPO_ROOT / "controller/migrations/env.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(env_source, filename="controller/migrations/env.py")
    guard = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_guard_downgrade"
    )
    calls: list[str] = []

    def verifier(revision: str, **_kwargs: object) -> None:
        calls.append(revision)
        if revision == "007_longspan_authority_hardening":
            raise ProvenanceMismatchError("tampered intermediate source")

    namespace: dict[str, object] = {
        "__name__": "test_env_guard_path",
        "_requested_revision": lambda _command: "006_longspan_authority",
        "verify_migration_source_anchor": verifier,
        "MIGRATION_SOURCE_PROVENANCE_PATH": "/invalid/test-anchor.json",
        "_DOWNGRADE_SOURCE_PATHS": {
            "006_longspan_authority": (
                "008_longspan_authority_repair",
                "007_longspan_authority_hardening",
                "006_longspan_authority",
            )
        },
    }
    module = ast.Module(body=[guard], type_ignores=[])
    exec(compile(module, "controller/migrations/env.py", "exec"), namespace)
    with pytest.raises(ProvenanceMismatchError, match="tampered intermediate source"):
        namespace["_guard_downgrade"](object())  # type: ignore[operator]
    assert calls == [
        "008_longspan_authority_repair",
        "007_longspan_authority_hardening",
    ]


def test_env_guard_verifies_every_intermediate_upgrade_source() -> None:
    """A head upgrade cannot skip an untrusted historical migration body."""
    import ast

    env_source = (REPO_ROOT / "controller/migrations/env.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(env_source, filename="controller/migrations/env.py")
    guard = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_guard_upgrade"
    )
    calls: list[str] = []

    def verifier(revision: str, **_kwargs: object) -> None:
        calls.append(revision)
        if revision == "006_longspan_authority":
            raise ProvenanceMismatchError("tampered intermediate upgrade source")

    namespace: dict[str, object] = {
        "__name__": "test_env_upgrade_guard_path",
        "_requested_revision": lambda _command: "head",
        "verify_migration_source_anchor": verifier,
        "MIGRATION_SOURCE_PROVENANCE_PATH": "/invalid/test-anchor.json",
        "_UPGRADE_SOURCE_PATHS": {
            "008_longspan_authority_repair": (
                "004_longspan_workflow",
                "005_longspan_hardening",
                "006_longspan_authority",
                "007_longspan_authority_hardening",
                "008_longspan_authority_repair",
            )
        },
    }
    module = ast.Module(body=[guard], type_ignores=[])
    exec(compile(module, "controller/migrations/env.py", "exec"), namespace)
    with pytest.raises(
        ProvenanceMismatchError, match="tampered intermediate upgrade source"
    ):
        namespace["_guard_upgrade"](object())  # type: ignore[operator]
    assert calls == [
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
    ]


def test_control_database_downgrade_is_rejected_before_capability_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pinned Comms-01 database cannot enter the downgrade path."""
    import db as db_module

    parsed = urlsplit(ADMIN_URL)
    control_url = urlunsplit(
        parsed._replace(
            netloc="root@127.0.0.1:5432",
            path="/top_delivery_control_p1",
            query="",
        )
    )

    def unexpected_capability_lookup(**_kwargs: object) -> None:
        raise AssertionError("capability lookup occurred for the live control database")

    monkeypatch.setattr(
        db_module,
        "_require_disposable_harness_capability",
        unexpected_capability_lookup,
    )
    with pytest.raises(ValueError, match="only permitted on a verified disposable"):
        db_module.alembic_command(control_url, "downgrade", "006_longspan_authority")


def test_historical_downgrade_source_anchors_reject_tampering(
    tmp_path: Path,
) -> None:
    """Every destructive historical leg is bound to the external source map."""
    from migration_catalog import LEGACY_MIGRATION_SOURCE_SHA256
    from migration_source_anchor import verify_migration_source_anchor

    anchor = tmp_path / "migration-source-anchor.json"
    anchor.write_text(
        json.dumps(
            {
                "algorithm": "sha256",
                "normalization_version": 1,
                "revision": "008_longspan_authority_repair",
                "source_digest": migration_source_digest(CANONICAL_ALEMBIC_HEAD),
                "legacy_source_digests": dict(LEGACY_MIGRATION_SOURCE_SHA256),
            }
        ),
        encoding="utf-8",
    )
    anchor.chmod(0o600)
    for revision, expected_digest in LEGACY_MIGRATION_SOURCE_SHA256.items():
        source_path = (
            REPO_ROOT / "controller/migrations/versions" / f"{revision}.py"
        )
        verify_migration_source_anchor(
            revision, source_path=source_path, anchor_path=anchor
        )
        tampered_path = tmp_path / f"{revision}-tampered.py"
        tampered_path.write_bytes(source_path.read_bytes() + b"\n-- tampered\n")
        with pytest.raises(ProvenanceMismatchError, match="root-owned trust anchor"):
            verify_migration_source_anchor(
                revision, source_path=tampered_path, anchor_path=anchor
            )
        assert expected_digest == LEGACY_MIGRATION_SOURCE_SHA256[revision]


def test_historical_anchor_is_independent_of_catalog_edits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changing a source and the in-tree catalog cannot rewrite the root witness."""
    import hashlib

    from migration_catalog import LEGACY_MIGRATION_SOURCE_SHA256
    from migration_source_anchor import (
        PINNED_LEGACY_MIGRATION_SOURCE_SHA256,
        verify_migration_source_anchor,
    )

    revision = "006_longspan_authority"
    source_path = REPO_ROOT / "controller/migrations/versions" / f"{revision}.py"
    tampered_path = tmp_path / f"{revision}-tampered.py"
    tampered_source = source_path.read_bytes() + b"\n# catalog and source edited together\n"
    tampered_path.write_bytes(tampered_source)
    monkeypatch.setitem(
        LEGACY_MIGRATION_SOURCE_SHA256,
        revision,
        hashlib.sha256(tampered_source).hexdigest(),
    )
    anchor = tmp_path / "migration-source-anchor.json"
    anchor.write_text(
        json.dumps(
            {
                "algorithm": "sha256",
                "normalization_version": 1,
                "revision": CANONICAL_ALEMBIC_HEAD,
                "source_digest": migration_source_digest(CANONICAL_ALEMBIC_HEAD),
                "legacy_source_digests": dict(PINNED_LEGACY_MIGRATION_SOURCE_SHA256),
            }
        ),
        encoding="utf-8",
    )
    anchor.chmod(0o600)
    with pytest.raises(ProvenanceMismatchError, match="root-owned trust anchor"):
        verify_migration_source_anchor(
            revision, source_path=tampered_path, anchor_path=anchor
        )


def test_008_downgrade_guard_covers_all_sensitive_legacy_tables() -> None:
    """The direct 008 database guard must reject every authority secret table."""
    source = (
        REPO_ROOT / "controller/migrations/versions/008_longspan_authority_repair.py"
    ).read_text(encoding="utf-8")
    downgrade = source.split("def downgrade()", 1)[1]
    for table, phrase in (
        ("longspan_mac_material", "MAC material is populated"),
        ("longspan_mac_key_history", "MAC key history is populated"),
        (
            "longspan_ledger_legacy_attestations",
            "legacy ledger attestations are populated",
        ),
    ):
        assert f"to_regclass('public.{table}')" in downgrade
        assert f"FROM {table} LIMIT 1" in downgrade
        assert phrase in downgrade


def test_authority_writes_and_rollback_share_the_controller_row_fence() -> None:
    """Provision/rotation and rollback must serialize on the same row lock."""
    source = (
        REPO_ROOT / "controller/migrations/versions/008_longspan_authority_repair.py"
    ).read_text(encoding="utf-8")
    upgrade = source.split("def downgrade()", 1)[0]
    for routine in (
        "longspan_insert_authority_config",
        "longspan_rotate_authority_config",
        "longspan_append_authority_history",
    ):
        routine_source = upgrade.split(
            f"CREATE OR REPLACE FUNCTION {routine}", 1
        )[1]
        assert "FROM controller_control" in routine_source
        assert "WHERE controller_control.run_id = p_run_id" in routine_source
        assert "FOR UPDATE" in routine_source
        if routine == "longspan_append_authority_history":
            assert "authority history challenge is stale after controller fencing" in routine_source
            assert "FROM longspan_authority_config" in routine_source
            assert "authority history payload does not match persisted config" in routine_source
        else:
            assert "authority write challenge is stale after controller fencing" in routine_source
    rollback_source = (
        REPO_ROOT
        / "controller/migrations/versions/007_longspan_authority_hardening.py"
    ).read_text(encoding="utf-8").split("CREATE OR REPLACE FUNCTION longspan_disable_controller", 1)[1]
    assert "FROM controller_control" in rollback_source
    assert "FOR UPDATE" in rollback_source


def test_authority_history_rejects_expired_controller_fence(
    db_url: str, artifact_root: Path
) -> None:
    """A previously valid authority challenge cannot append after lease expiry."""
    from urllib.parse import quote, urlsplit

    from authority_pins import AUTHORITY_DATABASE_ROLE

    workflow = _workflow(db_url, artifact_root)
    run_id = "run-history-expired-fence"
    workflow.parent.register_run(run_id)
    _provision_authority(workflow, run_id)
    with workflow.repo.repo.transaction() as cur:
        cur.execute("SELECT longspan_test_expire_controller_lease(%s)", (run_id,))
    database_name = urlsplit(db_url).path.lstrip("/")
    auth_url = (
        f"postgresql://{AUTHORITY_DATABASE_ROLE}:{quote('td-authority-test')}@127.0.0.1/{database_name}"
    )
    try:
        with psycopg2.connect(auth_url) as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg2.Error, match="authority history lost controller fence"):
                    cur.execute(
                        """
                        SELECT longspan_append_authority_history(
                            %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        """,
                        (
                            "expired-history",
                            run_id,
                            1,
                            "terra",
                            "operator",
                            "reviewed",
                            "tree",
                            "source",
                            "approval",
                            "approval-id",
                            "operator@test",
                            1,
                            1,
                            "receipt",
                            "action",
                            "binding",
                        ),
                    )
                    conn.rollback()
    finally:
        workflow.close()


def test_pinned_source_manifest_ancestors_are_not_writable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The in-tree executable manifest trust path rejects writable ancestors."""
    import pinned_trust

    unsafe_root = tmp_path / "unsafe"
    unsafe_root.mkdir(mode=0o777)
    unsafe_root.chmod(0o777)
    nested = unsafe_root / "controller"
    nested.mkdir(mode=0o755)
    manifest = nested / "pinned-executables.json"
    manifest.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(pinned_trust, "_SOURCE_PINNED_EXECUTABLE_MANIFEST_PATH", manifest)
    with pytest.raises(ScopeBoundaryViolationError, match="unsafe ancestor"):
        pinned_trust._assert_secure_ancestors(manifest)


def test_release_and_target_anchors_reject_authority_service_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Release/target pins cannot be rewritten by the authority service UID."""
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the pinned owner boundary")
    anchor = tmp_path / "trusted-anchor.json"
    anchor.write_text("{}\n", encoding="utf-8")
    anchor.chmod(0o600)
    os.chown(anchor, AUTHORITY_SERVICE_UID, 0)

    import attestation
    import authority_socket_secrets
    import workflow_database_target
    import comms01_authority_secrets
    import ledger_mac
    import terra_gateway_mac

    monkeypatch.setattr(attestation, "COMMS01_ATTESTATION_PATH", str(anchor))
    monkeypatch.setattr(
        workflow_database_target, "WORKFLOW_DATABASE_TARGET_PATH", str(anchor)
    )
    import authority_service_server

    monkeypatch.setattr(
        authority_service_server,
        "AUTHORITY_SERVICE_DATABASE_TARGET_PATH",
        str(anchor),
    )
    monkeypatch.setattr(comms01_authority_secrets, "OPERATOR_PUBLIC_KEYS_PATH", str(anchor))
    monkeypatch.setattr(comms01_authority_secrets, "TERRA_RECEIPT_PUBLIC_KEYS_PATH", str(anchor))
    monkeypatch.setattr(authority_socket_secrets, "AUTHORITY_WRITE_SIGNING_SECRET_PATH", str(anchor))
    monkeypatch.setattr(ledger_mac, "LEDGER_MAC_KEY_PATH", str(anchor))
    monkeypatch.setattr(terra_gateway_mac, "TERRA_GATEWAY_MAC_KEY_PATH", str(anchor))
    for loader in (
        attestation.load_comms01_attestation,
        workflow_database_target.load_workflow_database_target,
        authority_service_server.load_authority_service_database_target,
        comms01_authority_secrets.operator_public_keys,
        comms01_authority_secrets.terra_receipt_public_keys,
        authority_socket_secrets.authority_write_signing_secret,
        ledger_mac.ledger_mac_key,
        terra_gateway_mac.terra_gateway_mac_key,
    ):
        with pytest.raises(ScopeBoundaryViolationError, match="root-owned"):
            loader()


def test_pinned_runtime_anchor_contract_is_root_owned_and_loadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every runtime anchor is root-owned and readable by its service principal."""
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the deployed anchor contract")
    import pinned_trust

    tmpfiles = (
        REPO_ROOT
        / "controller"
        / "deploy"
        / "top-delivery-trust-anchors.tmpfiles"
    ).read_text(encoding="utf-8")
    strict_paths = re.findall(
        r"^z /etc/top-delivery/(\S+) 0600 root root -$",
        tmpfiles,
        flags=re.MULTILINE,
    )
    group_paths = re.findall(
        r"^z /etc/top-delivery/(\S+) 0640 root 59901 -$",
        tmpfiles,
        flags=re.MULTILINE,
    )
    assert strict_paths and group_paths
    for index, filename in enumerate(strict_paths):
        anchor = tmp_path / f"anchor-{index}"
        anchor.write_text("{}\n", encoding="utf-8")
        anchor.chmod(0o600)
        os.chown(anchor, 0, 0)
        assert pinned_trust.verify_pinned_file_trust(
            str(anchor), require_root_owner=True
        ) == anchor
    service_root = Path(tempfile.mkdtemp(prefix="top-delivery-anchor-", dir="/tmp"))
    service_root.chmod(0o755)
    try:
        for index, filename in enumerate(group_paths):
            anchor = service_root / f"service-anchor-{index}"
            anchor.write_text("{}\n", encoding="utf-8")
            anchor.chmod(0o640)
            os.chown(anchor, 0, AUTHORITY_SERVICE_GID)
            monkeypatch.setattr(
                pinned_trust,
                "SERVICE_GROUP_READABLE_PATHS",
                frozenset({anchor.resolve()}),
            )
            assert pinned_trust.verify_pinned_file_trust(
                str(anchor), require_root_owner=True
            ) == anchor
            original_uid, original_gid = os.geteuid(), os.getegid()
            try:
                os.setegid(AUTHORITY_SERVICE_GID)
                os.seteuid(AUTHORITY_SERVICE_UID)
                assert anchor.read_text(encoding="utf-8") == "{}\n"
            finally:
                os.seteuid(original_uid)
                os.setegid(original_gid)
    finally:
        shutil.rmtree(service_root)


def test_pinned_trust_requires_root_owner_by_default(
    tmp_path: Path,
) -> None:
    """Callers must opt into an explicitly allowlisted service-owned path."""
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the owner contract")
    import pinned_trust

    anchor = tmp_path / "service-owned-anchor"
    anchor.write_text("{}\n", encoding="utf-8")
    anchor.chmod(0o600)
    os.chown(anchor, AUTHORITY_SERVICE_UID, 0)
    with pytest.raises(ScopeBoundaryViolationError, match="root-owned"):
        pinned_trust.verify_pinned_file_trust(str(anchor))
    with pytest.raises(ScopeBoundaryViolationError, match="root-owned"):
        pinned_trust.read_json_file(str(anchor))


def test_disposable_harness_capability_is_root_only_and_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mutation capability remains a root-only input, not a group secret."""
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the capability-file contract")
    import disposable_capability
    import pinned_trust

    private_root = Path(tempfile.mkdtemp(prefix="top-delivery-capability-", dir="/root"))
    try:
        capability_path = private_root / "comms01-disposable-harness.json"
        capability_path.write_text("{}\n", encoding="utf-8")
        capability_path.chmod(0o600)
        os.chown(capability_path, 0, 0)
        monkeypatch.setattr(
            disposable_capability,
            "DISPOSABLE_HARNESS_CAPABILITY_PATH",
            str(capability_path),
        )
        assert disposable_capability.read_capability_json_file(str(capability_path)) == {}
        tmpfiles = (
            REPO_ROOT
            / "controller/deploy/top-delivery-trust-anchors.tmpfiles"
        ).read_text(encoding="utf-8")
        assert (
            "z /etc/top-delivery/comms01-disposable-harness.json 0600 root root -"
            in tmpfiles
        )
        assert "comms01-disposable-harness.json 0640 root 59901" not in tmpfiles
        with pytest.raises(ScopeBoundaryViolationError, match="service-group read"):
            pinned_trust.verify_pinned_file_trust(
                str(capability_path),
                allow_service_group_read=True,
                require_root_owner=True,
            )
    finally:
        shutil.rmtree(private_root)


def test_unverified_trust_anchor_read_is_not_available(
    tmp_path: Path,
) -> None:
    import pinned_trust

    anchor = tmp_path / "anchor.json"
    anchor.write_text("{}\n", encoding="utf-8")
    anchor.chmod(0o600)
    with pytest.raises(ScopeBoundaryViolationError, match="unverified trust-anchor"):
        pinned_trust.read_json_file(str(anchor), strict_owner=False)


def test_read_json_file_reads_from_verified_descriptor_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A replacement after open cannot change the bytes being verified."""
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the pinned owner boundary")
    import pinned_trust

    anchor = tmp_path / "anchor.json"
    replacement = tmp_path / "replacement.json"
    anchor.write_text('{"value":"original"}\n', encoding="utf-8")
    replacement.write_text('{"value":"replacement"}\n', encoding="utf-8")
    anchor.chmod(0o600)
    replacement.chmod(0o600)
    os.chown(anchor, 0, 0)
    os.chown(replacement, 0, 0)
    real_open = pinned_trust.os.open
    replaced = False

    def open_and_replace(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal replaced
        fd = real_open(path, flags, *args, **kwargs)
        if not replaced and os.fspath(path) == os.fspath(anchor) and "dir_fd" not in kwargs:
            replaced = True
            os.replace(replacement, anchor)
        return fd

    monkeypatch.setattr(pinned_trust.os, "open", open_and_replace)
    assert pinned_trust.read_json_file(str(anchor)) == {"value": "original"}
    assert replaced


def test_disposable_capability_consumption_rejects_pinned_object_swap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A capability cannot be verified once and consumed after replacement."""
    import disposable_capability

    capability = disposable_capability.SignedDisposableCapability(
        operation="disposable_downgrade",
        database_name="td_test_swap",
        database_role="top_delivery_migration",
        controller_service="top-delivery-controller",
        nonce="nonce-a",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        migration_revision="006_longspan_authority",
        signature="signature-a",
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    replacement = capability.__class__(
        **{**capability.__dict__, "nonce": "nonce-b", "signature": "signature-b"}
    )
    monkeypatch.setattr(
        disposable_capability,
        "load_signed_disposable_capability",
        lambda: replacement,
    )
    with pytest.raises(AuthorizationFailureError, match="changed after verification"):
        disposable_capability.consume_verified_disposable_capability(capability)


def test_008_archive_park_uses_database_capability_ledger_not_temp_witness() -> None:
    source = (
        REPO_ROOT / "controller/migrations/versions/008_longspan_authority_repair.py"
    ).read_text(encoding="utf-8")
    park_source = source.split("DO $park_008_archive$", 1)[1].split(
        "$park_008_archive$ LANGUAGE plpgsql", 1
    )[0]
    assert "pg_temp.top_delivery_008_downgrade_witness" not in park_source
    assert "FROM top_delivery_downgrade_capabilities" in park_source
    assert "pg_current_xact_id()::xid" in park_source
    assert "age(xmin) = 0" in park_source
    assert "xmin::text = txid_current()::text" not in park_source


def test_008_archive_park_rejects_stale_and_duplicate_ledger_witnesses() -> None:
    """Only one capability consumed in the current transaction may park 008."""
    from sqlalchemy.exc import DBAPIError

    def witness_row(
        database_name: str,
        nonce: str,
        consumed_steps: list[str],
        *,
        database_clock: bool = False,
    ) -> tuple[object, ...]:
        now = datetime.now(timezone.utc)
        return (
            nonce,
            "disposable_downgrade",
            database_name,
            MIGRATION_DATABASE_ROLE,
            "root",
            "top-delivery-controller",
            "006_longspan_authority",
            now + timedelta(minutes=30),
            None if database_clock else now,
            consumed_steps,
        )

    for case in ("prior-committed", "duplicate-current"):
        name, url = _create_test_database(f"td_downgrade_witness_{uuid.uuid4().hex}")
        try:
            run_migrations(url)
            committed_row = witness_row(
                name,
                f"stale-{uuid.uuid4().hex}",
                ["008_longspan_authority_repair"],
            )
            if case == "prior-committed":
                with psycopg2.connect(url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO top_delivery_downgrade_capabilities
                                (nonce, operation, database_name, database_role,
                                 transport_database_role, controller_service,
                                 migration_revision, expires_at, consumed_at,
                                 consumed_steps)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, clock_timestamp()), %s)
                            """,
                            committed_row,
                        )
                rows = ()
                expected_error = "exact connected signed capability witness"
            else:
                rows = (
                    witness_row(
                        name,
                        f"fresh-{uuid.uuid4().hex}",
                        [],
                        database_clock=True,
                    ),
                    witness_row(
                        name,
                        f"duplicate-{uuid.uuid4().hex}",
                        ["008_longspan_authority_repair"],
                        database_clock=True,
                    ),
                )
                expected_error = "exactly one consumed capability witness"
            with psycopg2.connect(url) as admin_conn:
                with pytest.raises(
                    DBAPIError,
                    match=expected_error,
                ):
                    _run_008_downgrade_direct(admin_conn, witness_rows=rows)
            with psycopg2.connect(url) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT version_num FROM alembic_version")
                    assert cur.fetchone()[0] == CANONICAL_ALEMBIC_HEAD
                    cur.execute(
                        "SELECT to_regclass('public.longspan_migration_provenance_008_archive'), "
                        "to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive')"
                    )
                    public_archive, recovery_archive = cur.fetchone()
                    assert public_archive is None
                    assert recovery_archive is None
        finally:
            _drop_test_database(name)


def test_008_archive_park_rejects_hostile_recovery_namespace() -> None:
    """The migration must not park authority provenance in a PUBLIC schema."""
    from sqlalchemy.exc import DBAPIError

    name, url = _create_test_database(f"td_downgrade_hostile_recovery_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute("GRANT USAGE ON SCHEMA top_delivery_recovery TO PUBLIC")
            conn.commit()
        now = datetime.now(timezone.utc)
        witness = (
            f"hostile-{uuid.uuid4().hex}",
            "disposable_downgrade",
            name,
            MIGRATION_DATABASE_ROLE,
            "root",
            "top-delivery-controller",
            "007_longspan_authority_hardening",
            now + timedelta(minutes=30),
            None,
            [],
        )
        with psycopg2.connect(url) as conn:
            with pytest.raises(DBAPIError, match="recovery schema owner or PUBLIC ACL is unsafe"):
                _run_008_downgrade_direct(conn, witness_rows=(witness,))
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version_num FROM alembic_version")
                assert cur.fetchone()[0] == CANONICAL_ALEMBIC_HEAD
    finally:
        _drop_test_database(name)


def test_008_archive_park_rejects_third_role_archive_acl() -> None:
    """A non-runtime grant cannot be carried into the recovery schema."""
    from sqlalchemy.exc import DBAPIError

    name, url = _create_test_database(f"td_downgrade_third_role_acl_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE public.longspan_migration_provenance_008_archive (
                        archive_id BIGINT PRIMARY KEY,
                        revision TEXT NOT NULL,
                        source_digest TEXT NOT NULL,
                        algorithm TEXT NOT NULL,
                        normalization_version INTEGER NOT NULL,
                        applied_at TIMESTAMPTZ NOT NULL,
                        application_count BIGINT NOT NULL DEFAULT 1,
                        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                        provenance_table_preexisting BOOLEAN NOT NULL
                    )
                    """
                )
                cur.execute(
                    "ALTER TABLE public.longspan_migration_provenance_008_archive "
                    "OWNER TO top_delivery_migration"
                )
                cur.execute(
                    "GRANT SELECT ON TABLE public.longspan_migration_provenance_008_archive "
                    f"TO {ATTACKER_DATABASE_ROLE}"
                )
            conn.commit()
        now = datetime.now(timezone.utc)
        witness = (
            f"third-role-{uuid.uuid4().hex}",
            "disposable_downgrade",
            name,
            MIGRATION_DATABASE_ROLE,
            "root",
            "top-delivery-controller",
            "007_longspan_authority_hardening",
            now + timedelta(minutes=30),
            None,
            [],
        )
        with psycopg2.connect(url) as conn:
            with pytest.raises(DBAPIError, match="archive has an unexpected ACL"):
                _run_008_downgrade_direct(conn, witness_rows=(witness,))
    finally:
        _drop_test_database(name)


@pytest.mark.parametrize(
    ("default_statement", "expected_object_type"),
    (
        (
            "ALTER DEFAULT PRIVILEGES FOR ROLE top_delivery_migration "
            "IN SCHEMA public GRANT INSERT ON TABLES TO top_delivery_workflow",
            "r",
        ),
        (
            "ALTER DEFAULT PRIVILEGES FOR ROLE top_delivery_migration "
            "IN SCHEMA public GRANT USAGE ON SEQUENCES TO top_delivery_workflow",
            "S",
        ),
    ),
)
def test_008_archive_park_rejects_owner_default_acl(
    default_statement: str, expected_object_type: str
) -> None:
    """Owner-scoped table and sequence defaults cannot cross the park boundary."""
    name, url = _create_test_database(f"td_downgrade_008_default_acl_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(default_statement)
            conn.commit()
        install_downgrade_capability(
            database_name=name,
            migration_revision="005_longspan_hardening",
        )
        command_env = os.environ.copy()
        command_env["TOP_DELIVERY_DATABASE_URL"] = url
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(REPO_ROOT / "controller/alembic.ini"),
                "downgrade",
                "005_longspan_hardening",
            ],
            cwd=str(REPO_ROOT / "controller"),
            env=command_env,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert (
            "008 archive park blocked: unsafe public default ACL for role "
            f"top_delivery_migration and object type {expected_object_type}"
        ) in result.stderr
    finally:
        _drop_test_database(name)


def test_008_archive_park_ignores_unrelated_role_default_acl() -> None:
    """Defaults for another role cannot veto the archive owner's park."""
    name, url = _create_test_database(f"td_downgrade_008_unrelated_acl_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"ALTER DEFAULT PRIVILEGES FOR ROLE {ATTACKER_DATABASE_ROLE} "
                    "IN SCHEMA public GRANT INSERT ON TABLES TO top_delivery_workflow"
                )
            conn.commit()
        install_downgrade_capability(
            database_name=name,
            migration_revision="005_longspan_hardening",
        )
        alembic_command(url, "downgrade", "005_longspan_hardening")
        assert current_database_revision(url) == "005_longspan_hardening"
    finally:
        _drop_test_database(name)


def test_007_is_historical_and_008_is_static_forward_repair() -> None:
    historical = Path(
        "controller/migrations/versions/007_longspan_authority_hardening.py"
    ).read_text(encoding="utf-8")
    repair = Path(
        "controller/migrations/versions/008_longspan_authority_repair.py"
    ).read_text(encoding="utf-8")
    # 007 now explicitly preserves an archive left by a controlled 008->007
    # downgrade; it does not own or create the 008 revision itself.
    assert "longspan_migration_provenance_008_archive" in historical
    assert "008_longspan_authority_repair" not in historical
    assert "pg_get_functiondef" not in repair
    assert "information_schema" not in repair
    assert "EXECUTE rewritten_definition" not in repair
    assert "Restore the exact published 007 routine bodies" in repair
    assert "longspan_migration_provenance_008_archive" in repair


def test_008_repairs_an_existing_007_schema_with_explicit_contract() -> None:
    name, url = _create_test_database(f"td_test_007repair_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version_num FROM alembic_version")
                assert cur.fetchone()[0] == "007_longspan_authority_hardening"
                cur.execute(
                    "SELECT pg_get_functiondef(p.oid) "
                    "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'public' AND p.proname = %s",
                    ("longspan_store_execution_evidence",),
                )
                old_definition = cur.fetchone()[0]
                assert "pg_advisory_xact_lock" not in old_definition

        try:
            alembic_command(url, "upgrade", "008_longspan_authority_repair")
        except subprocess.CalledProcessError as exc:
            raise AssertionError(f"008 restore/re-upgrade failed: {exc.stderr}") from exc
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version_num FROM alembic_version")
                assert cur.fetchone()[0] == "008_longspan_authority_repair"
                cur.execute(
                    "SELECT pg_get_constraintdef(oid) "
                    "FROM pg_constraint "
                    "WHERE conrelid = 'longspan_terra_receipt_attestations'::regclass "
                    "AND conname = 'longspan_terra_receipt_attestations_migration_head_008_chk'"
                )
                constraint = cur.fetchone()[0]
                assert "007_longspan_authority_hardening" in constraint
                assert "008_longspan_authority_repair" in constraint
                for function_name in (
                    "longspan_store_execution_evidence",
                    "longspan_append_execution_audit",
                    "longspan_insert_execution_result",
                    "longspan_append_auditor_receipt",
                ):
                    cur.execute(
                        "SELECT pg_get_functiondef(p.oid) "
                        "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
                        "WHERE n.nspname = 'public' AND p.proname = %s",
                        (function_name,),
                    )
                    definition = cur.fetchone()[0]
                    assert "pg_advisory_xact_lock(8101, hashtext(p_child_id))" in definition
                cur.execute(
                    "SELECT pg_get_functiondef(p.oid) "
                    "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'public' AND p.proname = 'longspan_issue_terra_receipt_attestation'"
                )
                issue_definition = cur.fetchone()[0]
                assert "interval '5 minutes'" in issue_definition
    finally:
        _drop_test_database(name)


def test_008_adds_transport_sentinel_constraint_to_existing_007_database() -> None:
    """The forward head repairs 007 databases; editing 006 is insufficient."""
    name, url = _create_test_database(f"td_test_007sentinel_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                # Simulate a database created by the historical 006/007
                # release before the forward 008 repair added this constraint.
                cur.execute(
                    "ALTER TABLE top_delivery_downgrade_capabilities "
                    "DROP CONSTRAINT IF EXISTS downgrade_capability_transport_role_bound"
                )
                cur.execute(
                    """
                    INSERT INTO top_delivery_downgrade_capabilities
                        (nonce, operation, database_name, database_role,
                         transport_database_role, controller_service,
                         migration_revision, expires_at)
                    VALUES
                        (%s, 'migration_downgrade', %s, 'top_delivery_migration',
                         '__legacy_unbound__', 'top-delivery-controller',
                         '007_longspan_authority_hardening',
                         clock_timestamp() + interval '5 minutes')
                    """,
                    (f"legacy-{uuid.uuid4().hex}", name),
                )
                conn.commit()
        alembic_command(url, "upgrade", "008_longspan_authority_repair")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1
                    FROM pg_constraint
                    WHERE conrelid = 'top_delivery_downgrade_capabilities'::regclass
                      AND conname = 'downgrade_capability_transport_role_bound'
                    """
                )
                assert cur.fetchone() == (1,)
                with pytest.raises(psycopg2.Error, match="transport_role_bound"):
                    cur.execute(
                        """
                        INSERT INTO top_delivery_downgrade_capabilities
                            (nonce, operation, database_name, database_role,
                             transport_database_role, controller_service,
                             migration_revision, expires_at)
                        VALUES
                            (%s, 'migration_downgrade', %s, 'top_delivery_migration',
                             '__legacy_unbound__', 'top-delivery-controller',
                             '007_longspan_authority_hardening',
                             clock_timestamp() + interval '5 minutes')
                        """,
                        (f"new-legacy-{uuid.uuid4().hex}", name),
                    )
                conn.rollback()
    finally:
        _drop_test_database(name)


def test_migration_catalog_rejects_unknown_sql_allowlist_entries() -> None:
    from migration_catalog import MIGRATION_CATALOG, assert_migration_catalog

    for revision in MIGRATION_CATALOG:
        assert_migration_catalog(revision)


def test_migration_catalog_rejects_catalog_drift_and_duplicate_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import migration_catalog

    original = migration_catalog.MIGRATION_CATALOG
    drifted = copy.deepcopy(original)
    drifted["007_longspan_authority_hardening"]["public_routines"] = (
        *drifted["007_longspan_authority_hardening"]["public_routines"][:-1],
        "longspan_append_execution_audit(TEXT, TEXT, INTEGER)",
    )
    monkeypatch.setattr(migration_catalog, "MIGRATION_CATALOG", drifted)
    with pytest.raises(RuntimeError, match="unknown allowed_routine_signatures"):
        migration_catalog.assert_migration_catalog("007_longspan_authority_hardening")

    duplicate = copy.deepcopy(original)
    duplicate["006_longspan_authority"]["public_tables"] += (
        duplicate["006_longspan_authority"]["public_tables"][0],
    )
    monkeypatch.setattr(migration_catalog, "MIGRATION_CATALOG", duplicate)
    with pytest.raises(RuntimeError, match="duplicate catalog entry"):
        migration_catalog.assert_migration_catalog("006_longspan_authority")


def test_disposable_admin_attestation_bypass_requires_signed_target_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import comms01_scope
    from disposable_capability import SignedDisposableCapability

    def missing_attestation() -> object:
        raise ScopeBoundaryViolationError("test attestation unavailable")

    monkeypatch.setattr(comms01_scope, "_attestation_identity", missing_attestation)
    monkeypatch.setattr(comms01_scope, "load_signed_disposable_capability", lambda: None)
    with pytest.raises(ScopeBoundaryViolationError, match="test attestation unavailable"):
        comms01_scope.assert_admin_database_url(
            "postgresql://postgres@127.0.0.1:5432/td_test_unattested"
        )

    capability = SignedDisposableCapability(
        operation="migration_downgrade",
        database_name="td_test_other",
        database_role="top_delivery_migration",
        controller_service="top-delivery-controller",
        nonce="attestation-test",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        migration_revision="007_longspan_authority_hardening",
        signature="signed",
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    monkeypatch.setattr(
        comms01_scope, "load_signed_disposable_capability", lambda: capability
    )
    with pytest.raises(AuthorizationFailureError, match="does not bind"):
        comms01_scope.assert_admin_database_url(
            "postgresql://postgres@127.0.0.1:5432/td_test_unattested"
        )
    with pytest.raises(ScopeBoundaryViolationError, match="test attestation unavailable"):
        comms01_scope.assert_admin_database_url(
            "postgresql://postgres@127.0.0.1:5432/top_delivery_control_p1"
        )

    canonical_capability = SignedDisposableCapability(
        operation="create_database",
        database_name="top_delivery_control_p1",
        database_role="postgres",
        controller_service="top-delivery-controller",
        nonce="canonical-target-test",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        migration_revision=None,
        signature="signed",
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    monkeypatch.setattr(
        comms01_scope, "load_signed_disposable_capability", lambda: canonical_capability
    )
    with pytest.raises(ScopeBoundaryViolationError, match="test attestation unavailable"):
        comms01_scope.assert_admin_database_url(
            "postgresql://postgres@127.0.0.1:5432/top_delivery_control_p1",
            allow_control_database=True,
        )


def test_admin_control_database_url_is_attested_and_port_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import comms01_scope
    from attestation import Comms01Attestation

    attestation = Comms01Attestation(
        scope="comms-01",
        environment_marker="isolated-top-delivery",
        host_fingerprint="comms01-isolated-top-delivery-local",
        database_name="top_delivery_control_p1",
        database_role="top_delivery_workflow",
        workflow_database_role="top_delivery_workflow",
        authority_database_role="top_delivery_authority",
        controller_service="top-delivery-controller",
        database_endpoint="local",
        database_port=5432,
        authority_service="top-delivery-authority-service",
    )
    monkeypatch.setattr(comms01_scope, "_attestation_identity", lambda: attestation)
    assert comms01_scope.assert_admin_database_url(
        "postgresql://postgres@127.0.0.1:5432/top_delivery_control_p1",
        allow_control_database=True,
    )
    with pytest.raises(AuthorizationFailureError, match="postgres/template1"):
        comms01_scope.assert_admin_database_url(
            "postgresql://postgres@127.0.0.1:5432/top_delivery_control_p1"
        )


def test_008_to_006_parks_archive_and_reupgrades_without_public_residue() -> None:
    """The direct 008->006 path must preserve archive identity privately."""
    name, url = _create_test_database(f"td_downgrade_008_to_006_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        install_downgrade_capability(
            database_name=name, migration_revision="006_longspan_authority"
        )
        alembic_command(url, "downgrade", "006_longspan_authority")
        assert current_database_revision(url) == "006_longspan_authority"
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM top_delivery_recovery.longspan_migration_provenance_008_archive"
                )
                archive_count = int(cur.fetchone()[0])
                assert archive_count >= 1
                cur.execute(
                    "SELECT to_regclass('public.longspan_migration_provenance_008_archive'), "
                    "to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq'), "
                    "to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq')"
                )
                public_archive, canonical_sequence, legacy_sequence = cur.fetchone()
                assert public_archive is None
                assert canonical_sequence is not None
                assert legacy_sequence is None
                cur.execute(
                    "SELECT 1 FROM pg_constraint "
                    "WHERE conrelid = 'top_delivery_downgrade_capabilities'::regclass "
                    "AND conname = 'downgrade_capability_transport_role_bound'"
                )
                assert cur.fetchone() == (1,)

        install_create_capability(database_name=name)
        alembic_command(url, "upgrade", "head")
        assert current_database_revision(url) == CANONICAL_ALEMBIC_HEAD
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM public.longspan_migration_provenance_008_archive"
                )
                assert int(cur.fetchone()[0]) >= archive_count
                cur.execute(
                    "SELECT to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive'), "
                    "to_regclass('public.longspan_migration_provenance_008_archive')"
                )
                private_archive, public_archive = cur.fetchone()
                assert private_archive is None
                assert public_archive is not None
    finally:
        _drop_test_database(name)


def test_007_rejects_forbidden_role_membership_before_schema_mutation() -> None:
    """Role-graph rejection is tested on a private cluster, never shared state."""
    from sqlalchemy.exc import DBAPIError

    with _isolated_role_graph_connection() as conn:
        membership_cases = (
            ("direct authority grant", ("GRANT top_delivery_authority TO top_delivery_workflow",)),
            (
                "admin-option attacker grant",
                ("GRANT top_delivery_attacker TO top_delivery_workflow WITH ADMIN OPTION",),
            ),
            (
                "transitive attacker-to-authority grant",
                (
                    "GRANT top_delivery_attacker TO top_delivery_workflow",
                    "GRANT top_delivery_authority TO top_delivery_attacker",
                ),
            ),
        )
        for _case_name, grants in membership_cases:
            with conn.cursor() as cur:
                cur.execute("RESET ROLE")
                cur.execute(
                    "REVOKE top_delivery_authority FROM top_delivery_workflow, top_delivery_attacker"
                )
                cur.execute(
                    "REVOKE top_delivery_attacker FROM top_delivery_workflow"
                )
                for statement in grants:
                    cur.execute(statement)
            with pytest.raises(
                DBAPIError, match="forbidden direct or transitive membership"
            ):
                _run_007_upgrade_direct(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass('public.longspan_authority_config'), "
                    "to_regclass('public.longspan_children')"
                )
                assert cur.fetchone() == (None, None)


def test_008_downgrade_static_contract_is_byte_equivalent_and_rehearsed() -> None:
    historical = Path(
        "controller/migrations/versions/007_longspan_authority_hardening.py"
    ).read_text(encoding="utf-8")
    repair = Path(
        "controller/migrations/versions/008_longspan_authority_repair.py"
    ).read_text(encoding="utf-8").split("def downgrade()", 1)[1]

    def function_block(source: str, name: str) -> str:
        # Match the routine's actual dollar-quote tag rather than assuming
        # every historical function used `$$`. This keeps the equivalence
        # check tied to the complete published body and terminator.
        match = re.search(
            rf"(?ms)^\s*CREATE OR REPLACE FUNCTION {re.escape(name)}\(.*?"
            rf"AS (?P<tag>\$[A-Za-z0-9_]*\$).*?(?P=tag) LANGUAGE plpgsql SECURITY DEFINER"
            rf"(?:\s+SET search_path = pg_catalog, public;)?",
            source,
        )
        assert match is not None, f"missing static routine {name}"
        return textwrap.dedent(match.group(0)).strip()

    restored_routines = (
        "longspan_store_execution_evidence",
        "longspan_append_execution_audit",
        "longspan_insert_execution_result",
        "longspan_append_auditor_receipt",
        "longspan_issue_terra_receipt_attestation",
        "longspan_consume_terra_receipt_attestation",
        "longspan_terra_gateway_mac",
        "longspan_terra_gateway_mac_for_attestation",
        "longspan_append_terra_receipt",
        "longspan_insert_authority_config",
        "longspan_rotate_authority_config",
        "longspan_append_authority_history",
        "reject_longspan_terra_attestation_mutation",
    )
    for routine in restored_routines:
        assert function_block(historical, routine) == function_block(repair, routine)
    assert re.search(
        r"CREATE OR REPLACE FUNCTION\s+longspan_invalidate_terra_receipt_attestation\(\s*TEXT\s*\)",
        historical,
    ) is None

    name, url = _create_test_database(f"td_downgrade_008_cycle_{uuid.uuid4().hex}")
    fresh_name: str | None = None
    try:
        run_migrations(url)
        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        alembic_command(url, "downgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version_num FROM alembic_version")
                assert cur.fetchone()[0] == "007_longspan_authority_hardening"
                cur.execute(
                    "SELECT COUNT(*) FROM top_delivery_recovery.longspan_migration_provenance_008_archive "
                    "WHERE revision = '008_longspan_authority_repair'"
                )
                assert cur.fetchone()[0] == 1
                cur.execute(
                    "SELECT 1 FROM pg_constraint "
                    "WHERE conrelid = 'top_delivery_downgrade_capabilities'::regclass "
                    "AND conname = 'downgrade_capability_transport_role_bound'"
                )
                assert cur.fetchone() == (1,)
                cur.execute(
                        "SELECT p.oid::regprocedure::text FROM pg_proc AS p "
                    "JOIN pg_namespace AS n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'public' "
                    "AND p.proname = 'longspan_invalidate_terra_receipt_attestation'"
                )
                assert all(
                    signature != "longspan_invalidate_terra_receipt_attestation(text)"
                    for (signature,) in cur.fetchall()
                )
                cur.execute(
                    """
                    SELECT has_function_privilege(
                        'public',
                        'public.longspan_store_execution_evidence(text,text,integer,text,text,text)',
                        'EXECUTE'
                    )
                    """
                )
                assert cur.fetchone()[0] is False
                cur.execute(
                    """
                    SELECT has_function_privilege(
                        'top_delivery_workflow',
                        'public.longspan_store_execution_evidence(text,text,integer,text,text,text)',
                        'EXECUTE'
                    )
                    """
                )
                assert cur.fetchone()[0] is True
            with psycopg2.connect(url) as archive_conn:
                archive_conn.autocommit = True
                with archive_conn.cursor() as archive_cur:
                    with pytest.raises(psycopg2.Error, match="append-only"):
                        archive_cur.execute(
                            "UPDATE top_delivery_recovery.longspan_migration_provenance_008_archive "
                            "SET last_seen_at = clock_timestamp()"
                        )
                    archive_conn.rollback()
                    with pytest.raises(psycopg2.Error, match="append-only"):
                        archive_cur.execute(
                            "DELETE FROM top_delivery_recovery.longspan_migration_provenance_008_archive"
                        )

        def catalog_snapshot(database_url: str) -> tuple[object, ...]:
            with psycopg2.connect(database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT p.oid::regprocedure::text,
                               pg_get_functiondef(p.oid),
                               COALESCE(p.proacl::text, '')
                        FROM pg_proc AS p
                        JOIN pg_namespace AS n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public'
                          AND p.proname = ANY(%s)
                        ORDER BY 1
                        """,
                        (list(restored_routines),),
                    )
                    routines = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT conname, pg_get_constraintdef(oid)
                        FROM pg_constraint
                        WHERE conrelid = 'public.longspan_terra_receipt_attestations'::regclass
                        ORDER BY conname
                        """
                    )
                    constraints = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT tgname, pg_get_triggerdef(oid)
                        FROM pg_trigger
                        WHERE tgrelid = 'public.longspan_terra_receipt_attestations'::regclass
                          AND NOT tgisinternal
                        ORDER BY tgname
                        """
                    )
                    triggers = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT attname, format_type(atttypid, atttypmod), attnotnull
                        FROM pg_attribute
                        WHERE attrelid = 'public.longspan_terra_receipt_attestations'::regclass
                          AND attnum > 0 AND NOT attisdropped
                        ORDER BY attnum
                        """
                    )
                    columns = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT pg_get_userbyid(relowner), COALESCE(relacl::text, '')
                        FROM pg_class
                        WHERE oid = 'public.longspan_terra_receipt_attestations'::regclass
                        """
                    )
                    table_owner_acl = tuple(cur.fetchone())
                    cur.execute(
                        "SELECT to_regclass('public.longspan_migration_provenance')"
                    )
                    provenance_relation = cur.fetchone()[0]
            return (
                routines,
                constraints,
                triggers,
                columns,
                table_owner_acl,
                provenance_relation,
            )

        def full_schema_inventory(
            database_url: str, *, exclude_archive: bool
        ) -> tuple[tuple[object, ...], ...]:
            """Compare the whole public catalog, allowing only the archive table."""
            with psycopg2.connect(database_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT c.relname, c.relkind, pg_get_userbyid(c.relowner),
                               COALESCE(c.relacl::text, '')
                        FROM pg_class AS c
                        JOIN pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                        ORDER BY c.relname, c.relkind
                        """
                    )
                    relations = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod),
                               a.attnotnull, COALESCE(pg_get_expr(d.adbin, d.adrelid), '')
                        FROM pg_attribute AS a
                        JOIN pg_class AS c ON c.oid = a.attrelid
                        JOIN pg_namespace AS n ON n.oid = c.relnamespace
                        LEFT JOIN pg_attrdef AS d
                          ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                        WHERE n.nspname = 'public'
                          AND a.attnum > 0 AND NOT a.attisdropped
                        ORDER BY c.relname, a.attnum
                        """
                    )
                    columns = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT c.relname, i.relname, pg_get_indexdef(i.oid)
                        FROM pg_index AS x
                        JOIN pg_class AS c ON c.oid = x.indrelid
                        JOIN pg_class AS i ON i.oid = x.indexrelid
                        JOIN pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                        ORDER BY c.relname, i.relname
                        """
                    )
                    indexes = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT c.oid::regclass::text, conname, contype,
                               pg_get_constraintdef(pc.oid)
                        FROM pg_constraint AS pc
                        JOIN pg_class AS c ON c.oid = pc.conrelid
                        JOIN pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                        ORDER BY 1, 2
                        """
                    )
                    constraints = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT c.oid::regclass::text, tgname, pg_get_triggerdef(pt.oid)
                        FROM pg_trigger AS pt
                        JOIN pg_class AS c ON c.oid = pt.tgrelid
                        JOIN pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND NOT pt.tgisinternal
                        ORDER BY 1, 2
                        """
                    )
                    triggers = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT p.oid::regprocedure::text, pg_get_functiondef(p.oid),
                               pg_get_userbyid(p.proowner), COALESCE(p.proacl::text, '')
                        FROM pg_proc AS p
                        JOIN pg_namespace AS n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public'
                        ORDER BY 1
                        """
                    )
                    routines = tuple(cur.fetchall())
                    cur.execute(
                        """
                        SELECT d.defaclnamespace::regnamespace::text,
                               d.defaclobjtype, COALESCE(d.defaclacl::text, '')
                        FROM pg_default_acl AS d
                        WHERE d.defaclnamespace = 'public'::regnamespace
                        ORDER BY 1, 2
                        """
                    )
                    default_privileges = tuple(cur.fetchall())
            sections = (
                relations,
                columns,
                indexes,
                constraints,
                triggers,
                routines,
                default_privileges,
            )
            if not exclude_archive:
                return sections
            return tuple(
                tuple(
                    row
                    for row in section
                    if "longspan_migration_provenance_008_archive"
                    not in " ".join(str(value) for value in row)
                )
                for section in sections
            )

        downgraded_snapshot = catalog_snapshot(url)
        downgraded_schema = full_schema_inventory(url, exclude_archive=True)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive')"
                )
                assert cur.fetchone()[0] is not None
        fresh_name, fresh_url = _create_test_database(
            f"td_test_fresh_007_{uuid.uuid4().hex}"
        )
        alembic_command(fresh_url, "upgrade", "007_longspan_authority_hardening")
        assert current_database_revision(fresh_url) == "007_longspan_authority_hardening"
        with psycopg2.connect(fresh_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass('public.longspan_migration_provenance_008_archive')"
                )
                assert cur.fetchone()[0] is None
        fresh_snapshot = catalog_snapshot(fresh_url)
        assert downgraded_snapshot == fresh_snapshot
        fresh_schema = full_schema_inventory(fresh_url, exclude_archive=False)
        assert downgraded_schema == fresh_schema

        # Creating the fresh comparison database overwrites the isolated
        # capability file. Rebind the original administrative transport to
        # this exact target before the subprocess re-upgrade.
        install_create_capability(database_name=name)
        try:
            alembic_command(url, "upgrade", "008_longspan_authority_repair")
        except subprocess.CalledProcessError as exc:
            raise AssertionError(f"008 restore/re-upgrade failed: {exc.stderr}") from exc
        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        alembic_command(url, "downgrade", "007_longspan_authority_hardening")
        assert current_database_revision(url) == "007_longspan_authority_hardening"
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM top_delivery_recovery.longspan_migration_provenance_008_archive "
                    "WHERE revision = '008_longspan_authority_repair'"
                )
                assert cur.fetchone()[0] == 2
    finally:
        _drop_test_database(name)
        if fresh_name is not None:
            _drop_test_database(fresh_name)


def test_008_accepts_preexisting_provenance_pair_through_downgrade_reupgrade() -> None:
    """A partially rehearsed 007 database retains both provenance identities."""
    name, url = _create_test_database(f"td_downgrade_preprov_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE longspan_migration_provenance (
                        revision TEXT PRIMARY KEY,
                        source_digest TEXT NOT NULL,
                        algorithm TEXT NOT NULL,
                        normalization_version INTEGER NOT NULL,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
                    )
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_migration_provenance
                        (revision, source_digest, algorithm, normalization_version)
                    VALUES ('007_longspan_authority_hardening', %s, 'sha256', 1)
                    """,
                    ("0" * 64,),
                )
                cur.execute(
                    """
                    CREATE TABLE longspan_migration_provenance_008_state (
                        singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
                        provenance_table_preexisting BOOLEAN NOT NULL,
                        recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
                    )
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_migration_provenance_008_state
                        (singleton, provenance_table_preexisting)
                    VALUES (TRUE, TRUE)
                    """
                )
                cur.execute(
                    """
                    ALTER TABLE longspan_migration_provenance OWNER TO top_delivery_migration;
                    ALTER TABLE longspan_migration_provenance_008_state OWNER TO top_delivery_migration;
                    REVOKE ALL ON longspan_migration_provenance,
                        longspan_migration_provenance_008_state FROM PUBLIC;
                    """
                )
        alembic_command(url, "upgrade", "head")
        install_downgrade_capability(
            database_name=name, migration_revision="006_longspan_authority"
        )
        alembic_command(url, "downgrade", "006_longspan_authority")
        alembic_command(url, "upgrade", "head")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT source_digest, algorithm, normalization_version
                    FROM longspan_migration_provenance
                    WHERE revision = '007_longspan_authority_hardening'
                    """
                )
                assert cur.fetchone() == ("0" * 64, "sha256", 1)
                cur.execute(
                    """
                    SELECT source_digest, algorithm, normalization_version
                    FROM longspan_migration_provenance
                    WHERE revision = '008_longspan_authority_repair'
                    """
                )
                assert cur.fetchone() is not None
    finally:
        _drop_test_database(name)


def test_private_archive_restore_rehearsal_preserves_identity_and_sequences() -> None:
    name, url = _create_test_database(f"td_downgrade_private_{uuid.uuid4().hex}")
    try:
        run_migrations(url)

        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        alembic_command(url, "downgrade", "007_longspan_authority_hardening")

        def archive_state(
            schema: str,
        ) -> tuple[tuple[tuple[object, ...], ...], int, object, object]:
            with psycopg2.connect(url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"SELECT archive_id, revision, source_digest, algorithm, "
                        f"normalization_version FROM {schema}.longspan_migration_provenance_008_archive "
                        "ORDER BY archive_id"
                    )
                    archive_rows = tuple(cur.fetchall())
                    cur.execute(
                        f"SELECT COUNT(*) FROM {schema}.longspan_migration_provenance_008_archive"
                    )
                    count = cur.fetchone()[0]
                    cur.execute(
                        f"SELECT to_regclass('{schema}.longspan_migration_provenance_008_archive_archive_id_seq')"
                    )
                    legacy_sequence = cur.fetchone()[0]
                    cur.execute(
                        f"SELECT pg_get_serial_sequence('{schema}.longspan_migration_provenance_008_archive', 'archive_id')"
                    )
                    owned_sequence = cur.fetchone()[0]
            return archive_rows, count, legacy_sequence, owned_sequence

        original_rows, original_count, recovery_legacy, owned_sequence = archive_state(
            "top_delivery_recovery"
        )
        assert original_count >= 1
        assert original_count == len(original_rows)
        assert recovery_legacy is None
        assert owned_sequence == (
            "top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq"
        )

        install_downgrade_capability(
            database_name=name, migration_revision="005_longspan_hardening"
        )
        # Targeting 005 invokes the actual 006 -> 005 downgrade.  A target of
        # 006 only runs the 007 -> 006 compatibility downgrade and therefore
        # must not be used as evidence for the private recovery boundary.
        alembic_command(url, "downgrade", "005_longspan_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM top_delivery_recovery.longspan_migration_provenance_008_archive"
                )
                assert cur.fetchone()[0] == original_count
                cur.execute(
                    "SELECT pg_get_userbyid(c.relowner) FROM pg_class AS c "
                    "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'top_delivery_recovery' "
                    "AND c.relname = 'longspan_migration_provenance_008_archive'"
                )
                assert cur.fetchone()[0] == "top_delivery_migration"
                cur.execute(
                    "SELECT to_regclass('public.longspan_migration_provenance_008_archive')"
                )
                assert cur.fetchone()[0] is None

        alembic_command(url, "upgrade", "head")
        restored_rows, restored_count, public_legacy, owned_sequence = archive_state("public")
        original_by_id = {row[0]: row[1:] for row in original_rows}
        restored_by_id = {row[0]: row[1:] for row in restored_rows}
        assert all(
            restored_by_id[archive_id] == row
            for archive_id, row in original_by_id.items()
        )
        assert restored_count == original_count
        assert public_legacy is None
        assert owned_sequence == "public.longspan_migration_provenance_008_archive_id_seq"

        # Repeat the full path. The private namespace is now pre-existing and
        # empty; the second cycle must not collide, adopt an attacker object,
        # or lose the original archive identities.
        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        alembic_command(url, "downgrade", "007_longspan_authority_hardening")
        install_downgrade_capability(
            database_name=name, migration_revision="005_longspan_hardening"
        )
        alembic_command(url, "downgrade", "005_longspan_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM top_delivery_recovery.longspan_migration_provenance_008_archive"
                )
                # The second downgrade contributes exactly one new
                # provenance observation. A larger count would indicate
                # duplication or runaway archive growth.
                assert cur.fetchone()[0] == restored_count + 1
        alembic_command(url, "upgrade", "head")
        second_rows, second_count, public_legacy, owned_sequence = archive_state("public")
        second_by_id = {row[0]: row[1:] for row in second_rows}
        assert all(
            second_by_id[archive_id] == row
            for archive_id, row in original_by_id.items()
        )
        assert second_count == restored_count + 1
        assert public_legacy is None
        assert owned_sequence == "public.longspan_migration_provenance_008_archive_id_seq"
    finally:
        _drop_test_database(name)


def test_recovery_schema_rejects_preexisting_unexpected_owner_and_relation() -> None:
    name, url = _create_test_database(f"td_downgrade_recovery_guard_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        alembic_command(url, "downgrade", "007_longspan_authority_hardening")
        install_downgrade_capability(
            database_name=name, migration_revision="006_longspan_authority"
        )
        alembic_command(url, "downgrade", "006_longspan_authority")
        with psycopg2.connect(url) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "CREATE TABLE top_delivery_recovery.operator_planted (value TEXT)"
                )
        install_downgrade_capability(
            database_name=name, migration_revision="005_longspan_hardening"
        )
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "downgrade", "005_longspan_hardening")
    finally:
        _drop_test_database(name)


def test_recovery_schema_rejects_default_acl_private_routine() -> None:
    """NULL proacl means PUBLIC EXECUTE and must not pass recovery fencing."""
    name, url = _create_test_database(f"td_downgrade_recovery_routine_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        alembic_command(url, "downgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE FUNCTION top_delivery_recovery.planted_default()
                    RETURNS INTEGER
                    LANGUAGE SQL
                    AS $$ SELECT 1 $$
                    """
                )
        install_downgrade_capability(
            database_name=name, migration_revision="005_longspan_hardening"
        )
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "downgrade", "005_longspan_hardening")
    finally:
        _drop_test_database(name)


def test_upgrade_head_rejects_unexpected_recovery_relation() -> None:
    name, url = _create_test_database(f"td_downgrade_uprel_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        alembic_command(url, "downgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "CREATE TABLE top_delivery_recovery.upgrade_planted (value TEXT)"
                )
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "upgrade", "head")
    finally:
        _drop_test_database(name)


def test_upgrade_head_rejects_default_acl_private_routine() -> None:
    name, url = _create_test_database(f"td_downgrade_uproutine_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        alembic_command(url, "downgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE FUNCTION top_delivery_recovery.upgrade_planted()
                    RETURNS INTEGER
                    LANGUAGE SQL
                    AS $$ SELECT 1 $$
                    """
                )
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "upgrade", "head")
    finally:
        _drop_test_database(name)


def test_pinned_command_manifest_binds_hash_and_package_evidence() -> None:
    import comms01_operation_entrypoints as entrypoints

    assert set(entrypoints.PINNED_EXECUTABLE_METADATA) == {
        entrypoints.PINNED_PG_RESTORE_EXECUTABLE,
        entrypoints.PINNED_SYSTEMCTL_EXECUTABLE,
    }
    for executable, metadata in entrypoints.PINNED_EXECUTABLE_METADATA.items():
        assert len(metadata["sha256"]) == 64
        assert metadata["package"]
        assert metadata["package_version"]
        assert entrypoints.PINNED_EXECUTABLE_SHA256[executable] == metadata["sha256"]


def test_pinned_manifest_group_read_exception_cannot_touch_secret_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import pinned_trust

    manifest = tmp_path / "pinned-executables.json"
    manifest.write_text("{}", encoding="utf-8")
    secret = tmp_path / "signing-key"
    secret.write_text("private", encoding="utf-8")
    if os.geteuid() != 0:
        pytest.skip("file-owner trust branches require root in this harness")
    os.chown(manifest, 0, AUTHORITY_SERVICE_GID)
    os.chown(secret, 0, AUTHORITY_SERVICE_GID)
    manifest.chmod(0o640)
    secret.chmod(0o640)
    monkeypatch.setattr(
        pinned_trust, "_PINNED_EXECUTABLE_MANIFEST_PATH", manifest.resolve()
    )
    assert pinned_trust.verify_pinned_file_trust(
        str(manifest), allow_service_group_read=True
    ) == manifest
    manifest.chmod(0o644)
    assert pinned_trust.verify_pinned_file_trust(
        str(manifest), allow_service_group_read=True
    ) == manifest
    with pytest.raises(ScopeBoundaryViolationError):
        pinned_trust.verify_pinned_file_trust(str(manifest))
    with pytest.raises(ScopeBoundaryViolationError):
        pinned_trust.verify_pinned_file_trust(
            str(secret), allow_service_group_read=True
        )
    manifest.chmod(0o660)
    with pytest.raises(ScopeBoundaryViolationError):
        pinned_trust.verify_pinned_file_trust(
            str(manifest), allow_service_group_read=True
        )
    tmpfiles = (
        REPO_ROOT
        / "controller"
        / "deploy"
        / "top-delivery-pinned-executables.tmpfiles"
    ).read_text(encoding="utf-8")
    assert "0640 root topdelivery" in tmpfiles
    assert AUTHORITY_SERVICE_GID == 59901


def test_restore_fence_provisioning_is_out_of_band_and_private() -> None:
    tmpfiles = (
        REPO_ROOT / "controller" / "deploy" / "top-delivery-restore-fences.tmpfiles"
    ).read_text(encoding="utf-8")
    assert "d /var/lib/top-delivery 0700 root root -" in tmpfiles
    assert "d /var/lib/top-delivery/restore-fences 0700 root root -" in tmpfiles
    runbook = (
        REPO_ROOT / "controller" / "runbooks" / "pinned-executable-attestation.md"
    ).read_text(encoding="utf-8")
    assert "does not silently create one" in runbook


def test_all_pinned_trust_consumers_have_explicit_deployment_modes() -> None:
    tmpfiles = (
        REPO_ROOT
        / "controller"
        / "deploy"
        / "top-delivery-trust-anchors.tmpfiles"
    ).read_text(encoding="utf-8")
    expected = {
        "comms01-operator-keys.json": "0640 root 59901",
        "comms01-terra-receipt-keys.json": "0640 root 59901",
        "comms01-attestation.json": "0640 root 59901",
        "comms01-authority-db-target.json": "0640 root 59901",
        "comms01-workflow-db-target.json": "0640 root 59901",
        "comms01-disposable-harness.json": "0600 root root",
        "comms01-disposable-signing-key": "0600 root root",
        "comms01-disposable-verifier.pub": "0640 root 59901",
        "comms01-disposable-consumed-nonces.json": "0600 root root",
        "comms01-migration-source-provenance.json": "0600 root root",
        "comms01-authority-write-secret": "0640 root 59901",
        "comms01-ledger-mac.key": "0640 root 59901",
        "comms01-terra-gateway-mac.key": "0640 root 59901",
        "comms01-runner-envelope.pub": "0640 root 59901",
        "comms01-review-signing.key": "0600 root root",
        "comms01-review-signing.pub": "0600 root root",
    }
    for filename, owner_mode in expected.items():
        assert f"/etc/top-delivery/{filename} {owner_mode}" in tmpfiles
    assert "top-delivery-trust-anchors.tmpfiles" in (
        REPO_ROOT / "controller" / "runbooks" / "pinned-executable-attestation.md"
    ).read_text(encoding="utf-8")


def test_database_records_migration_source_provenance(db_url: str) -> None:
    """A disposable migrated target carries the exact in-tree source digest."""
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source_digest, algorithm, normalization_version "
                "FROM longspan_migration_provenance "
                "WHERE revision = %s",
                (CANONICAL_ALEMBIC_HEAD,),
            )
            row = cur.fetchone()
    assert row == (
        migration_source_digest(CANONICAL_ALEMBIC_HEAD),
        MIGRATION_SOURCE_PROVENANCE_ALGORITHM,
        MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION,
    )


def test_database_result_and_auditor_writers_share_child_advisory_lock(
    db_url: str,
) -> None:
    """Every SQL writer uses the same lock key as the Python transaction."""
    function_names = (
        "longspan_store_execution_evidence",
        "longspan_insert_execution_result",
        "longspan_append_execution_audit",
        "longspan_append_auditor_receipt",
    )
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            for function_name in function_names:
                cur.execute(
                    """
                    SELECT pg_get_functiondef(p.oid)
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public' AND p.proname = %s
                    """,
                    (function_name,),
                )
                definitions = [row[0] for row in cur.fetchall()]
                assert definitions, function_name
                assert all(
                    "pg_advisory_xact_lock(8101, hashtext(p_child_id))" in definition
                    for definition in definitions
                ), function_name


def test_database_run_and_child_advisory_lock_namespaces_are_distinct(
    db_url: str,
) -> None:
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            for function_name in (
                "longspan_insert_authority_config",
                "longspan_rotate_authority_config",
                "longspan_append_authority_history",
            ):
                cur.execute(
                    """
                    SELECT pg_get_functiondef(p.oid)
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public' AND p.proname = %s
                    """,
                    (function_name,),
                )
                definitions = [row[0] for row in cur.fetchall()]
                assert definitions, function_name
                assert all(
                    "pg_advisory_xact_lock(8102, hashtext(p_run_id))" in definition
                    for definition in definitions
                )
                assert all("8101" not in definition for definition in definitions)


def test_restore_target_lock_rejects_special_file_modes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_lock_mode",
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    fd = entrypoints._acquire_restore_target_lock(
        "postgresql://root@/td_test_lock_mode", target
    )
    os.close(fd)
    lock_path = root / entrypoints.RESTORE_TARGET_LOCK_NAME
    lock_path.chmod(0o4600)
    with pytest.raises(ScopeBoundaryViolationError, match="regular file"):
        entrypoints._acquire_restore_target_lock(
            "postgresql://root@/td_test_lock_mode", target
        )


def test_restore_uses_one_target_mutex_and_orders_body_after_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    identities = [
        {
            "database_name": f"td_test_lock_{index}",
            "cluster_system_identifier": str(100 + index),
            "database_oid": str(200 + index),
        }
        for index in range(8)
    ]
    for target in identities:
        fd = entrypoints._acquire_restore_target_lock(
            "postgresql:///ignored", target
        )
        os.close(fd)
    assert sorted(path.name for path in root.iterdir()) == [
        entrypoints.RESTORE_TARGET_LOCK_NAME
    ]

    events: list[str] = []
    monkeypatch.setattr(
        entrypoints,
        "is_disposable_test_database",
        lambda _database_url: True,
    )
    monkeypatch.setattr(
        entrypoints,
        "_bind_restore_cluster_identity",
        lambda _database_url, restore_target: dict(restore_target),
    )

    def fake_target_lock(_database_url: str, _restore_target: dict[str, object]) -> int:
        events.append("target-lock")
        return os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)

    def fake_restore_body(**_kwargs: object) -> str:
        events.append("restore-body")
        return "digest"

    monkeypatch.setattr(entrypoints, "_acquire_restore_target_lock", fake_target_lock)
    monkeypatch.setattr(
        entrypoints,
        "_restore_disposable_database_locked",
        fake_restore_body,
    )
    entrypoints.restore_disposable_database(
        database_url="postgresql:///td_test_lock_order",
        backup_path="/var/lib/top-delivery/backups/restore.dump",
        operator_approval_receipt=object(),
        restore_target=identities[0],
    )
    assert events == ["target-lock", "restore-body"]
    source = inspect.getsource(entrypoints.restore_disposable_database)
    assert source.index("_acquire_restore_target_lock") < source.index(
        "_restore_disposable_database_locked"
    )


def test_database_terra_receipt_digest_matches_live_jsonb(db_url: str) -> None:
    """Python's compatibility helper matches live PostgreSQL JSONB bytes."""
    from terra_receipt_attestation import terra_receipt_database_digest

    payload = {
        "child_id": "child",
        "attempt_number": 0,
        "reviewer": "terra-réview",
        "decision": "approved",
        "evidence_chain_head": "a" * 64,
        "run_id": "run",
        "task_id": "task",
        "reviewed_sha": "b" * 40,
        "fence_token": 1,
        "controller_epoch": 2,
        "tree_sha": "c" * 40,
        "source_digest": "d" * 64,
        "request_digest": "e" * 64,
        "migration_head": CANONICAL_ALEMBIC_HEAD,
        "authority_version": 1,
        "evidence_digest": "f" * 64,
        "result_digest": "0" * 64,
    }
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT encode(digest(convert_to(
                    jsonb_build_object(
                        'child_id', %s,
                        'attempt_number', %s,
                        'reviewer', %s,
                        'decision', %s,
                        'evidence_chain_head', %s,
                        'run_id', %s,
                        'task_id', %s,
                        'reviewed_sha', %s,
                        'fence_token', %s,
                        'controller_epoch', %s,
                        'tree_sha', %s,
                        'source_digest', %s,
                        'request_digest', %s,
                        'migration_head', %s,
                        'authority_version', %s,
                        'evidence_digest', %s,
                        'result_digest', %s
                    )::text, 'UTF8'
                ), 'sha256'), 'hex')
                """,
                tuple(
                    payload[field]
                    for field in (
                        "child_id",
                        "attempt_number",
                        "reviewer",
                        "decision",
                        "evidence_chain_head",
                        "run_id",
                        "task_id",
                        "reviewed_sha",
                        "fence_token",
                        "controller_epoch",
                        "tree_sha",
                        "source_digest",
                        "request_digest",
                        "migration_head",
                        "authority_version",
                        "evidence_digest",
                        "result_digest",
                    )
                ),
            )
            database_digest = cur.fetchone()[0]
    assert database_digest == terra_receipt_database_digest(payload)


def test_live_downgrade_rejected_without_capability() -> None:
    """A non-disposable/control target is rejected before any downgrade work."""
    with pytest.raises(
        ValueError,
        match="not the Comms-01 control database or a disposable test database",
    ):
        alembic_command(ADMIN_URL, "downgrade", "005_longspan_hardening")


def test_disposable_downgrade_rejected_without_capability() -> None:
    """A disposable target cannot downgrade merely because it is disposable."""
    name, url = _create_test_database(f"td_downgrade_nocap_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        with pytest.raises(
            AuthorizationFailureError,
            match="disposable capability operation mismatch",
        ):
            alembic_command(url, "downgrade", "005_longspan_hardening")
        assert current_database_revision(url) == CANONICAL_ALEMBIC_HEAD
    finally:
        _drop_test_database(name)


def test_downgrade_guards_require_approved_migration_principal() -> None:
    migration_006 = Path(
        "controller/migrations/versions/006_longspan_authority.py"
    ).read_text()
    migration_007 = Path(
        "controller/migrations/versions/007_longspan_authority_hardening.py"
    ).read_text()
    for source, revision in ((migration_006, "006"), (migration_007, "007")):
        assert "connected principal is not an approved migration role" in source
        assert "current_user NOT IN ('{MIGRATION_ROLE}', 'postgres')" in source
        assert "session_user NOT IN ('{MIGRATION_ROLE}', 'postgres')" not in source
        assert "current_user = 'root' AND capability_nonce IS NOT NULL" not in source
        assert "session_user = 'root'" not in source
        assert f"{revision} downgrade blocked: signed disposable capability sentinel" in source


def test_disposable_admin_target_is_still_loopback_pinned() -> None:
    from comms01_scope import assert_admin_database_url

    with pytest.raises(AuthorizationFailureError, match="local Comms-01 endpoint"):
        assert_admin_database_url(
            "postgresql://postgres@192.0.2.44/td_test_remote_name"
        )


def test_canonical_target_requires_explicit_host() -> None:
    from comms01_scope import assert_database_url

    with pytest.raises(
        ScopeBoundaryViolationError, match="explicitly bind the pinned PostgreSQL port"
    ):
        assert_database_url("postgresql:///top_delivery_control_p1")


def test_duplicate_libpq_routing_parameters_are_rejected() -> None:
    from comms01_scope import strict_libpq_query

    for database_url in (
        "postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_duplicate"
        "?host=127.0.0.1&host=localhost",
        "postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_duplicate"
        "?port=5432&port=5433",
        "postgresql:///td_test_duplicate?HOST=%2Fvar%2Frun%2Fpostgresql"
        "&host=%2Ftmp%2Fother&port=5432",
    ):
        with pytest.raises(ScopeBoundaryViolationError, match="duplicate"):
            strict_libpq_query(database_url)


def test_attestation_endpoint_binding_rejects_mixed_case_duplicates() -> None:
    from attestation import Comms01Attestation, assert_endpoint_binding

    attestation = Comms01Attestation(
        scope="comms-01",
        environment_marker="test",
        host_fingerprint="test-host",
        database_name="top_delivery_control_p1",
        database_role="top_delivery_workflow",
        workflow_database_role="top_delivery_workflow",
        authority_database_role="top_delivery_authority",
        controller_service="top-delivery-controller",
        database_endpoint="local",
        database_port=5432,
        authority_service="top-delivery-authority",
    )
    with pytest.raises(ScopeBoundaryViolationError, match="duplicate"):
        assert_endpoint_binding(
            attestation,
            "postgresql:///top_delivery_control_p1"
            "?HOST=%2Fvar%2Frun%2Fpostgresql&host=%2Ftmp%2Fother&port=5432",
        )


def test_comms01_operation_contract_pins_side_effect_targets() -> None:
    from comms01_operation_policy import assert_comms01_operation

    assert_comms01_operation(
        operation="backup",
        database_url="postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_contract",
        backup_path="/var/lib/top-delivery/backups/contract.dump",
    )
    assert_comms01_operation(
        operation="service-status",
        service_name="top-delivery-controller",
    )
    with pytest.raises(ScopeBoundaryViolationError, match="locally attested"):
        assert_comms01_operation(
            operation="service-status",
            service_name="top-delivery-controller",
            host_fingerprint="wrong-comms01-host",
        )
    with pytest.raises(ScopeBoundaryViolationError, match="backup target"):
        assert_comms01_operation(
            operation="backup",
            database_url="postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_contract",
            backup_path="/home/trading/backup.dump",
        )
    with pytest.raises(AuthorizationFailureError, match="signed external 2FA"):
        assert_comms01_operation(operation="authority-rotate")
    with pytest.raises(AuthorizationFailureError, match="signed external 2FA"):
        assert_comms01_operation(
            operation="authority-rotate",
            rotation_target={"run_id": "run"},
        )
    with pytest.raises(Exception, match="release authority"):
        assert_comms01_operation(operation="deploy")


def test_restore_fence_uses_canonical_target_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_canonical",
        "database_role": "top_delivery_workflow",
        "database_endpoint": "127.0.0.1",
        "database_port": 5432,
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    first = entrypoints._restore_fence_path(
        "postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_canonical",
        target,
    )
    equivalent_route = (
        "postgresql://top_delivery_workflow@127.0.0.1/td_test_canonical"
        "?port=5432&application_name=restore"
    )
    second = entrypoints._restore_fence_path(equivalent_route, target)
    assert first == second
    assert first == entrypoints._restore_fence_path(
        "postgresql://postgres@/td_test_canonical?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
        {
            **target,
            "database_role": "postgres",
            "database_endpoint": "/var/run/postgresql",
        },
    )
    assert first != entrypoints._restore_fence_path(
        equivalent_route,
        {**target, "database_name": "td_test_other"},
    )


def test_restore_fence_rejects_stored_cluster_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_canonical",
        "database_role": "top_delivery_workflow",
        "database_endpoint": "127.0.0.1",
        "database_port": 5432,
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    fence_path = Path(entrypoints._restore_fence_path("ignored", target))
    fence_path.write_text(
        "partial_restore_fence\n"
        "database_name=td_test_canonical\n"
        "cluster_system_identifier=222\n"
        "database_oid=12345\n"
        "database_url_sha256=" + hashlib.sha256(b"ignored").hexdigest() + "\n"
        "backup_path_sha256=" + hashlib.sha256(b"backup").hexdigest() + "\n"
        "reason=test\n"
        "created_at=1.0\n",
        encoding="utf-8",
    )
    fence_path.chmod(0o600)
    fd = os.open(fence_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(ProvenanceMismatchError, match="identity"):
            entrypoints._assert_restore_fence_matches_target(fd, target)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "bad_line",
    (
        "unknown_field=value\n",
        "database_name=duplicate\n",
        "database_url_sha256=not-a-digest\n",
        "created_at=nan\n",
        "reason=control\x01character\n",
    ),
)
def test_restore_fence_rejects_ambiguous_or_untrusted_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bad_line: str
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_canonical",
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    fence_path = Path(entrypoints._restore_fence_path("ignored", target))
    fence_path.write_text(
        "partial_restore_fence\n"
        "database_name=td_test_canonical\n"
        "cluster_system_identifier=111\n"
        "database_oid=12345\n"
        "database_url_sha256=" + "0" * 64 + "\n"
        "backup_path_sha256=" + "1" * 64 + "\n"
        + bad_line,
        encoding="utf-8",
    )
    fence_path.chmod(0o600)
    fd = os.open(fence_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(ScopeBoundaryViolationError):
            entrypoints._assert_restore_fence_matches_target(fd, target)
    finally:
        os.close(fd)


def test_restore_failure_rotation_preserves_first_and_latest_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_failure_rotation",
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    fence_path = str(root / "target.fence")
    for index in range(entrypoints.MAX_RESTORE_FAILURE_RECORDS + 8):
        entrypoints._write_restore_failure_evidence(
            fence_path=fence_path,
            restore_target=target,
            reason=f"failure-{index}",
            diagnostics=f"diagnostic-{index}",
        )
    records = sorted(root.glob("target.fence.failure-*"))
    assert len(records) == entrypoints.MAX_RESTORE_FAILURE_RECORDS
    contents = [record.read_text(encoding="utf-8") for record in records]
    assert any("reason=failure-0" in content for content in contents)
    assert any("reason=failure-39" in content for content in contents)
    rotation_state = (root / "target.fence.rotation-state").read_text(
        encoding="utf-8"
    )
    assert "dropped_occurrences=8" in rotation_state
    assert (root / ".restore-failure-rotation.lock").is_file()


def test_restore_failure_evidence_is_retained_after_verified_clear(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_failure_cleanup",
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    fence_path = str(root / "target.fence")
    entrypoints._write_restore_failure_evidence(
        fence_path=fence_path,
        restore_target=target,
        reason="failure",
        diagnostics="diagnostic",
    )
    assert list(root.glob("target.fence.failure-*"))
    assert (root / ".restore-failure-rotation.lock").is_file()
    temporary = root / "target.fence.rotation-state.tmp-abandoned"
    temporary.write_text("incomplete\n", encoding="utf-8")
    temporary.chmod(0o600)
    state = root / "target.fence.rotation-state"
    state.write_text(
        "dropped_occurrences=0\nquarantined_occurrences=0\n",
        encoding="utf-8",
    )
    state.chmod(0o600)
    entrypoints._cleanup_restore_failure_artifacts(root, fence_path)
    assert list(root.glob("target.fence.failure-*"))
    assert not list(root.glob("target.fence.rotation-state.tmp-*"))
    assert (root / "target.fence.rotation-state").is_file()
    assert (root / ".restore-failure-rotation.lock").is_file()
    entrypoints._cleanup_restore_failure_artifacts(root, fence_path)
    assert (root / ".restore-failure-rotation.lock").is_file()


def test_restore_failure_malformed_rotation_state_is_quarantined_and_retained(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_malformed_rotation",
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    fence_path = str(root / "target.fence")
    (root / "target.fence.rotation-state").write_text(
        "not-a-valid-rotation-state\n", encoding="utf-8"
    )
    (root / "target.fence.rotation-state").chmod(0o600)
    entrypoints._write_restore_failure_evidence(
        fence_path=fence_path,
        restore_target=target,
        reason="failure",
        diagnostics="diagnostic",
    )
    assert (root / "target.fence.rotation-state").read_text(
        encoding="utf-8"
    ).startswith("dropped_occurrences=0")
    assert list(root.glob("target.fence.rotation-state.malformed-*"))
    for index in range(entrypoints.MAX_RESTORE_FAILURE_STATE_QUARANTINES + 4):
        (root / "target.fence.rotation-state").write_text(
            f"malformed-{index}\n", encoding="utf-8"
        )
        (root / "target.fence.rotation-state").chmod(0o600)
        entrypoints._write_restore_failure_evidence(
            fence_path=fence_path,
            restore_target=target,
            reason=f"failure-{index}",
            diagnostics=f"diagnostic-{index}",
        )
    quarantined = list(root.glob("target.fence.rotation-state.malformed-*"))
    assert len(quarantined) <= entrypoints.MAX_RESTORE_FAILURE_STATE_QUARANTINES
    state_text = (root / "target.fence.rotation-state").read_text(encoding="utf-8")
    assert "quarantined_occurrences=" in state_text
    counter_text = (root / "target.fence.rotation-quarantine-count").read_text(
        encoding="utf-8"
    )
    assert int(counter_text.split("=", 1)[1]) >= 1
    entrypoints._cleanup_restore_failure_artifacts(root, fence_path)
    assert list(root.glob("target.fence.rotation-state.malformed-*"))
    assert (root / "target.fence.rotation-state").is_file()
    assert (root / ".restore-failure-rotation.lock").is_file()


def test_restore_failure_rotation_and_cleanup_share_permanent_mutex(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_rotation_race",
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    fence_path = str(root / "target.fence")
    errors: list[BaseException] = []

    def write_failure(index: int) -> None:
        try:
            entrypoints._write_restore_failure_evidence(
                fence_path=fence_path,
                restore_target=target,
                reason=f"failure-{index}",
                diagnostics=f"diagnostic-{index}",
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    def clean_failure_artifacts() -> None:
        try:
            entrypoints._cleanup_restore_failure_artifacts(root, fence_path)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(write_failure, index) for index in range(20)
        ]
        futures.extend(executor.submit(clean_failure_artifacts) for _ in range(20))
        for future in futures:
            future.result()
    assert not errors
    assert len(list(root.glob("target.fence.failure-*"))) <= entrypoints.MAX_RESTORE_FAILURE_RECORDS
    assert (root / ".restore-failure-rotation.lock").is_file()


def test_restore_failure_rotation_rejects_untrusted_record_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    target = {
        "database_name": "td_test_hostile_failure",
        "cluster_system_identifier": "111",
        "database_oid": "12345",
    }
    fence_path = str(root / "target.fence")
    hostile = root / "target.fence.failure-hostile"
    hostile.symlink_to("/tmp")
    with pytest.raises(ScopeBoundaryViolationError, match="root-private regular"):
        entrypoints._write_restore_failure_evidence(
            fence_path=fence_path,
            restore_target=target,
            reason="failure",
            diagnostics="diagnostic",
        )
    assert hostile.is_symlink()
    assert (root / ".restore-failure-rotation.lock").is_file()


def test_restore_fence_clear_requires_authenticated_snapshot_recovery(
    db_url: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from comms01_authority import OperatorTwoFactorChallenge
    from comms01_operation_entrypoints import (
        _bind_restore_cluster_identity,
        _restore_fence_path,
        _write_restore_fence,
        clear_restore_fence_after_snapshot_recovery,
    )
    import comms01_operation_entrypoints as entrypoints
    import comms01_operation_policy as operation_policy

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    monkeypatch.setattr(operation_policy, "COMMS01_BACKUP_ROOTS", (str(root),))
    database_url = db_url
    snapshot_path = root / "recovery.dump"
    snapshot = b"verified disposable recovery snapshot"
    snapshot_path.write_bytes(snapshot)
    snapshot_digest = hashlib.sha256(snapshot).hexdigest()
    target = {
        "run_id": "run-fence-clear",
        "operator_identity": "operator@test",
        "reviewed_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "source_digest": "c" * 64,
        "controller_epoch": 4,
        "config_version": 2,
        "challenge_epoch": 9,
        "migration_head": CANONICAL_ALEMBIC_HEAD,
        "recovery_snapshot_migration_head": CANONICAL_ALEMBIC_HEAD,
        "recovery_snapshot_source_digest": migration_source_digest(
            CANONICAL_ALEMBIC_HEAD
        ),
        "recovery_snapshot_path": str(snapshot_path),
        "recovery_snapshot_digest": snapshot_digest,
        "recovery_snapshot_size": len(snapshot),
    }
    target.update(_restore_route_fields(database_url))
    target = _bind_restore_cluster_identity(database_url, target)
    action_digest = digest_payload(
        {
            "action": "clear_restore_fence",
            "run_id": target["run_id"],
            "operator_identity": target["operator_identity"],
            "reviewed_sha": target["reviewed_sha"],
            "tree_sha": target["tree_sha"],
            "source_digest": target["source_digest"],
            "controller_epoch": target["controller_epoch"],
            "config_version": target["config_version"],
            "challenge_epoch": target["challenge_epoch"],
            "database_url": database_url,
            "recovery_snapshot_path": str(snapshot_path),
            "recovery_snapshot_digest": snapshot_digest,
            "recovery_snapshot_size": len(snapshot),
            "migration_head": target["migration_head"],
            "recovery_snapshot_migration_head": target[
                "recovery_snapshot_migration_head"
            ],
            "recovery_snapshot_source_digest": target[
                "recovery_snapshot_source_digest"
            ],
            "database_name": target["database_name"],
            "database_role": target["database_role"],
            "database_endpoint": target["database_endpoint"],
            "database_port": target["database_port"],
            **_restore_identity_digest_fields(target),
        }
    )
    challenge = OperatorTwoFactorChallenge(
        approval_id="fence-clear-approval",
        operator_identity=target["operator_identity"],
        action_type="clear_restore_fence",
        action_digest=action_digest,
        run_id=target["run_id"],
        nonce="fence-clear-nonce",
        expires_at="2099-01-01T00:00:00+00:00",
        key_version=1,
        controller_epoch=target["controller_epoch"],
        config_version=target["config_version"],
        challenge_epoch=target["challenge_epoch"],
        challenge_digest="fence-clear-challenge",
    )
    receipt = sign_external_operator_receipt(challenge)
    fence_path = _restore_fence_path(database_url, target)
    _write_restore_fence(database_url, str(snapshot_path), target, "test")
    assert Path(fence_path).exists()
    # A retry after an interrupted clearance must accept the same verified
    # clearance record rather than failing on O_EXCL.
    entrypoints._write_restore_fence_clearance(
        fence_path=fence_path,
        approval_id=receipt.approval_id,
        snapshot_digest=snapshot_digest,
        restore_target=target,
    )
    # The recovery proof must invoke the same fixed restore path, but this
    # unit test deliberately uses a textual fixture rather than a real custom
    # PostgreSQL dump.  Keep the database identity/head verification live and
    # stub only the pinned child result.
    monkeypatch.setattr(
        entrypoints,
        "_run_fixed_command",
        lambda **_kwargs: type("Result", (), {"returncode": 0})(),
    )
    assert (
        clear_restore_fence_after_snapshot_recovery(
            database_url=database_url,
            operator_approval_receipt=receipt,
            restore_target=target,
            recovery_snapshot_path=str(snapshot_path),
            recovery_snapshot_digest=snapshot_digest,
            recovery_snapshot_size=len(snapshot),
        )
        == snapshot_digest
    )
    assert not Path(fence_path).exists()
    clearance_files = list(root.glob("*.cleared-*"))
    assert clearance_files
    clearance = clearance_files[0].read_text(encoding="utf-8")
    assert "database_name=" in clearance
    assert "cluster_system_identifier=" in clearance
    assert "database_oid=" in clearance
    assert f"migration_head={CANONICAL_ALEMBIC_HEAD}" in clearance
    assert "restore_verified=1" in clearance


def test_comms01_backup_open_rejects_intermediate_symlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import comms01_operation_policy as operation_policy

    root = tmp_path / "backups"
    nested = root / "nested"
    nested.mkdir(parents=True)
    monkeypatch.setattr(operation_policy, "COMMS01_BACKUP_ROOTS", (str(root),))
    target = nested / "snapshot.dump"
    fd = operation_policy.open_pinned_backup_file(str(target), purpose="backup")
    try:
        os.write(fd, b"snapshot")
    finally:
        os.close(fd)
    assert target.read_bytes() == b"snapshot"

    link = root / "link"
    link.symlink_to(nested, target_is_directory=True)
    with pytest.raises(ScopeBoundaryViolationError, match="symlink"):
        operation_policy.open_pinned_backup_file(
            str(link / "rejected.dump"), purpose="backup"
        )


def test_comms01_restore_receipt_binds_backup_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from comms01_authority import OperatorTwoFactorChallenge
    from comms01_operation_entrypoints import authorize_restore, open_backup_target
    import comms01_operation_entrypoints as entrypoints
    import comms01_operation_policy as operation_policy

    root = tmp_path / "backups"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    monkeypatch.setattr(operation_policy, "COMMS01_BACKUP_ROOTS", (str(root),))
    database_url = "postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_restore"
    restore_target = {
        "run_id": "run-restore",
        "operator_identity": "operator@test",
        "reviewed_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "source_digest": "c" * 64,
        "controller_epoch": 4,
        "config_version": 2,
        "challenge_epoch": 9,
        "backup_path": str(root / "restore.dump"),
        "backup_digest": "d" * 64,
        "backup_size": 7,
        "migration_head": CANONICAL_ALEMBIC_HEAD,
    }
    restore_target.update(_restore_route_fields(database_url))
    restore_target.update(
        {
            "cluster_system_identifier": "7666378573161670785",
            "database_oid": "1",
        }
    )
    action_digest = digest_payload(
        {
            "action": "restore",
            "run_id": restore_target["run_id"],
            "operator_identity": restore_target["operator_identity"],
            "reviewed_sha": restore_target["reviewed_sha"],
            "tree_sha": restore_target["tree_sha"],
            "source_digest": restore_target["source_digest"],
            "controller_epoch": restore_target["controller_epoch"],
            "config_version": restore_target["config_version"],
            "challenge_epoch": restore_target["challenge_epoch"],
            "database_url": database_url,
            "backup_path": str(root / "restore.dump"),
            "backup_digest": restore_target["backup_digest"],
            "backup_size": restore_target["backup_size"],
            "migration_head": restore_target["migration_head"],
            "database_name": restore_target["database_name"],
            "database_role": restore_target["database_role"],
            "database_endpoint": restore_target["database_endpoint"],
            "database_port": restore_target["database_port"],
            **_restore_identity_digest_fields(restore_target),
        }
    )
    challenge = OperatorTwoFactorChallenge(
        approval_id="restore-approval",
        operator_identity=restore_target["operator_identity"],
        action_type="restore",
        action_digest=action_digest,
        run_id=restore_target["run_id"],
        nonce="restore-nonce",
        expires_at="2099-01-01T00:00:00+00:00",
        key_version=1,
        controller_epoch=restore_target["controller_epoch"],
        config_version=restore_target["config_version"],
        challenge_epoch=restore_target["challenge_epoch"],
        challenge_digest="restore-challenge",
    )
    receipt = sign_external_operator_receipt(challenge)
    authorize_restore(
        database_url=database_url,
        operator_approval_receipt=receipt,
        restore_target=restore_target,
    )
    with pytest.raises(AuthorizationFailureError, match="action digest|signature|binding"):
        authorize_restore(
            database_url=database_url,
            operator_approval_receipt=receipt,
            restore_target={**restore_target, "backup_path": str(root / "other.dump")},
        )
    fd = open_backup_target(
        database_url=database_url,
        backup_path=str(root / "backup.dump"),
        purpose="backup",
    )
    os.close(fd)
    from comms01_operation_entrypoints import authorize_service_action

    authorize_service_action(
        operation="service-status", service_name="top-delivery-controller"
    )


def test_comms01_side_effect_runners_are_the_only_fixed_adapters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from comms01_operation_entrypoints import (
        backup_bytes,
        restore_bytes,
        service_restart,
        service_status,
        _restore_fence_path,
    )
    from comms01_authority import OperatorTwoFactorChallenge
    import comms01_operation_entrypoints as entrypoints

    import comms01_operation_policy as operation_policy

    root = tmp_path / "backups"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    monkeypatch.setattr(operation_policy, "COMMS01_BACKUP_ROOTS", (str(root),))
    database_url = "postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_runner"
    backup_path = str(root / "runner.dump")
    payload = b"isolated-backup-bytes"
    backup_digest = backup_bytes(
        database_url=database_url, backup_path=backup_path, payload=payload
    )
    restore_target = {
        "run_id": "run-runner",
        "operator_identity": "operator@test",
        "reviewed_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "source_digest": "c" * 64,
        "controller_epoch": 4,
        "config_version": 2,
        "challenge_epoch": 9,
        "backup_path": backup_path,
        "backup_digest": backup_digest,
        "backup_size": len(payload),
        "migration_head": CANONICAL_ALEMBIC_HEAD,
    }
    restore_target.update(_restore_route_fields(database_url))
    restore_target.update(
        {
            "cluster_system_identifier": "7666378573161670785",
            "database_oid": "1",
        }
    )
    action_digest = digest_payload(
        {
            "action": "restore",
            "run_id": restore_target["run_id"],
            "operator_identity": restore_target["operator_identity"],
            "reviewed_sha": restore_target["reviewed_sha"],
            "tree_sha": restore_target["tree_sha"],
            "source_digest": restore_target["source_digest"],
            "controller_epoch": restore_target["controller_epoch"],
            "config_version": restore_target["config_version"],
            "challenge_epoch": restore_target["challenge_epoch"],
            "database_url": database_url,
            "backup_path": backup_path,
            "backup_digest": backup_digest,
            "backup_size": restore_target["backup_size"],
            "migration_head": restore_target["migration_head"],
            "database_name": restore_target["database_name"],
            "database_role": restore_target["database_role"],
            "database_endpoint": restore_target["database_endpoint"],
            "database_port": restore_target["database_port"],
            **_restore_identity_digest_fields(restore_target),
        }
    )
    challenge = OperatorTwoFactorChallenge(
        approval_id="runner-approval",
        operator_identity=restore_target["operator_identity"],
        action_type="restore",
        action_digest=action_digest,
        run_id=restore_target["run_id"],
        nonce="runner-nonce",
        expires_at="2099-01-01T00:00:00+00:00",
        key_version=1,
        controller_epoch=restore_target["controller_epoch"],
        config_version=restore_target["config_version"],
        challenge_epoch=restore_target["challenge_epoch"],
        challenge_digest="runner-challenge",
    )
    receipt = sign_external_operator_receipt(challenge)
    Path(backup_path).write_bytes(b"x" * len(payload))
    with pytest.raises(AuthorizationFailureError, match="digest"):
        restore_bytes(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )
    Path(backup_path).write_bytes(payload)
    restored, restored_digest = restore_bytes(
        database_url=database_url,
        backup_path=backup_path,
        operator_approval_receipt=receipt,
        restore_target=restore_target,
    )
    assert restored == payload
    assert restored_digest == backup_digest

    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_run(command, **kwargs):
        calls.append((tuple(command), kwargs))
        stdout = "active" if command[-1] == "top-delivery-controller" else ""
        return type("Result", (), {"returncode": 0, "stdout": stdout})()

    monkeypatch.setattr("comms01_operation_entrypoints.subprocess.run", fake_run)
    assert service_status(service_name="top-delivery-controller") == "active"
    service_restart(service_name="top-delivery-controller")
    assert calls[0][0][0].startswith("/proc/self/fd/")
    assert calls[0][0][1:] == (
        "is-active",
        "top-delivery-controller",
    )
    assert calls[1][0][0].startswith("/proc/self/fd/")
    assert calls[1][0][1:] == ("restart", "top-delivery-controller")
    for _command, kwargs in calls:
        assert kwargs["env"]["PATH"] == "/usr/bin:/bin"
        assert kwargs["env"]["LANG"] == "C"
        assert kwargs["timeout"] == 60.0
        assert kwargs["pass_fds"] == (
            int(_command[0].rsplit("/", 1)[1]),
        )

    executable_root = tmp_path / "trusted"
    executable_root.mkdir(mode=0o700)
    writable_executable = executable_root / "writable"
    writable_executable.write_bytes(b"#!/bin/sh\n")
    writable_executable.chmod(0o775)
    with pytest.raises(ScopeBoundaryViolationError, match="root-owned"):
        entrypoints._open_pinned_executable(str(writable_executable))
    symlink_root = tmp_path / "symlink-root"
    symlink_root.mkdir(mode=0o700)
    real_dir = tmp_path / "real-dir"
    real_dir.mkdir(mode=0o700)
    real_executable = real_dir / "tool"
    real_executable.write_bytes(b"#!/bin/sh\n")
    real_executable.chmod(0o755)
    monkeypatch.setitem(entrypoints.PINNED_EXECUTABLE_SHA256, "/usr/bin/systemctl", "0" * 64)
    with pytest.raises(ScopeBoundaryViolationError, match="digest"):
        entrypoints._open_pinned_executable("/usr/bin/systemctl")
    symlink_root.joinpath("link").symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(ScopeBoundaryViolationError):
        entrypoints._open_pinned_executable(str(symlink_root / "link" / "tool"))
    if os.geteuid() == 0:
        non_root_executable = executable_root / "non-root"
        non_root_executable.write_bytes(b"#!/bin/sh\n")
        non_root_executable.chmod(0o755)
        os.chown(non_root_executable, 65534, 65534)
        with pytest.raises(ScopeBoundaryViolationError, match="root-owned"):
            entrypoints._open_pinned_executable(str(non_root_executable))


def test_disposable_restore_runner_is_fixed_and_verifies_head(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from comms01_operation_entrypoints import (
        PartialRestoreError,
        PinnedCommandTimeoutError,
        _restore_fence_path,
        backup_bytes,
        restore_disposable_database,
    )
    import comms01_operation_entrypoints as entrypoints
    import comms01_operation_policy as operation_policy
    from comms01_authority import OperatorTwoFactorChallenge

    root = tmp_path / "backups"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    monkeypatch.setattr(operation_policy, "COMMS01_BACKUP_ROOTS", (str(root),))
    database_url = (
        "postgresql://top_delivery_workflow:td-workflow-test@/"
        "td_test_restore_consumer?host=%2Fvar%2Frun%2Fpostgresql&port=5432"
    )
    backup_path = str(root / "restore.dump")
    payload = b"disposable-restore-dump"
    backup_digest = backup_bytes(
        database_url=database_url, backup_path=backup_path, payload=payload
    )
    restore_target = {
        "run_id": "run-restore-consumer",
        "operator_identity": "operator@test",
        "reviewed_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "source_digest": "c" * 64,
        "controller_epoch": 4,
        "config_version": 2,
        "challenge_epoch": 9,
        "backup_path": backup_path,
        "backup_digest": backup_digest,
        "backup_size": len(payload),
        "migration_head": CANONICAL_ALEMBIC_HEAD,
    }
    restore_target.update(_restore_route_fields(database_url))
    restore_target.update(
        {
            "cluster_system_identifier": "7666378573161670785",
            "database_oid": "1",
        }
    )
    action_digest = digest_payload(
        {
            "action": "restore",
            "run_id": restore_target["run_id"],
            "operator_identity": restore_target["operator_identity"],
            "reviewed_sha": restore_target["reviewed_sha"],
            "tree_sha": restore_target["tree_sha"],
            "source_digest": restore_target["source_digest"],
            "controller_epoch": restore_target["controller_epoch"],
            "config_version": restore_target["config_version"],
            "challenge_epoch": restore_target["challenge_epoch"],
            "database_url": database_url,
            "backup_path": backup_path,
            "backup_digest": backup_digest,
            "backup_size": len(payload),
            "migration_head": CANONICAL_ALEMBIC_HEAD,
            "database_name": restore_target["database_name"],
            "database_role": restore_target["database_role"],
            "database_endpoint": restore_target["database_endpoint"],
            "database_port": restore_target["database_port"],
            **_restore_identity_digest_fields(restore_target),
        }
    )
    challenge = OperatorTwoFactorChallenge(
        approval_id="restore-consumer-approval",
        operator_identity=restore_target["operator_identity"],
        action_type="restore",
        action_digest=action_digest,
        run_id=restore_target["run_id"],
        nonce="restore-consumer-nonce",
        expires_at="2099-01-01T00:00:00+00:00",
        key_version=1,
        controller_epoch=restore_target["controller_epoch"],
        config_version=restore_target["config_version"],
        challenge_epoch=restore_target["challenge_epoch"],
        challenge_digest="restore-consumer-challenge",
    )
    receipt = sign_external_operator_receipt(challenge)

    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_restore(command, **kwargs):
        calls.append((tuple(command), kwargs))
        restore_fd = int(command[7].rsplit("/", 1)[1])
        os.lseek(restore_fd, 0, os.SEEK_SET)
        assert os.read(restore_fd, len(payload)) == payload
        return type("Result", (), {"returncode": 0})()

    class FakeCursor:
        def __init__(
            self,
            database: str = "td_test_restore_consumer",
            role: str = "top_delivery_workflow",
            port: int = 5432,
        ) -> None:
            self._result: tuple[str, ...] | None = None
            self._database = database
            self._role = role
            self._port = port

        def __enter__(self) -> "FakeCursor":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(
            self, statement: str, params: tuple[object, ...] | None = None
        ) -> None:
            if statement == (
                "SELECT current_database(), current_user, "
                "inet_server_addr()::text, inet_server_port()"
            ):
                self._result = (self._database, self._role, None, self._port)
            elif statement == (
                "SELECT current_database(), current_user, "
                "inet_server_addr()::text, inet_server_port(), current_setting('port')"
            ):
                self._result = (
                    self._database,
                    self._role,
                    None,
                    self._port,
                    self._port,
                )
            elif statement == (
                "SELECT current_database(), current_user, inet_server_addr()::text, "
                "inet_server_port(), current_setting('port'), "
                "current_setting('unix_socket_directories')"
            ):
                self._result = (
                    self._database,
                    self._role,
                    None,
                    self._port,
                    self._port,
                    "/var/run/postgresql",
                )
            elif statement == (
                "SELECT current_database(), current_user, "
                "system_identifier::text FROM pg_control_system()"
            ):
                self._result = (
                    self._database,
                    self._role,
                    "7666378573161670785",
                )
            elif statement == (
                "SELECT system_identifier::text FROM pg_control_system()"
            ):
                self._result = ("7666378573161670785",)
            elif statement == (
                "SELECT oid::text FROM pg_database WHERE datname = current_database()"
            ):
                self._result = ("1",)
            elif statement == "SELECT version_num FROM alembic_version":
                self._result = (CANONICAL_ALEMBIC_HEAD,)
            elif statement == (
                "SELECT source_digest, algorithm, normalization_version "
                "FROM longspan_migration_provenance "
                "WHERE revision = %s"
            ):
                assert params == (CANONICAL_ALEMBIC_HEAD,)
                self._result = (
                    migration_source_digest(CANONICAL_ALEMBIC_HEAD),
                    MIGRATION_SOURCE_PROVENANCE_ALGORITHM,
                    MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION,
                )
            else:
                raise AssertionError(f"unexpected restore verification SQL: {statement}")

        def fetchone(self) -> tuple[str, ...] | None:
            return self._result

    class FakeConnection:
        def __init__(self, database: str = "td_test_restore_consumer") -> None:
            self.closed = False
            self._database = database

        def __enter__(self) -> "FakeConnection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def cursor(self) -> FakeCursor:
            return FakeCursor(database=self._database)

        def close(self) -> None:
            self.closed = True

    import comms01_operation_entrypoints as entrypoints
    import comms01_scope

    # Exercise the real identity helper before mutating the named backup. The
    # restore consumes the already-streamed sealed descriptor, so a source
    # mutation after verification cannot change applied bytes.
    original_verify_target = entrypoints._verify_disposable_restore_target
    def mutate_after_target_verification(
        _target: str, _restore_target: dict[str, object]
    ) -> None:
        original_verify_target(_target, _restore_target)
        Path(backup_path).write_bytes(b"attacker-after-verification")

    monkeypatch.setattr(
        entrypoints,
        "_verify_disposable_restore_target",
        mutate_after_target_verification,
    )
    original_verify_identity = comms01_scope.verify_connection_identity
    monkeypatch.setattr(
        comms01_scope,
        "verify_connection_identity",
        lambda **_kwargs: ("td_test_restore_consumer", "top_delivery_workflow"),
    )
    monkeypatch.setattr("comms01_operation_entrypoints.subprocess.run", fake_restore)
    monkeypatch.setattr(psycopg2, "connect", lambda target: FakeConnection())

    original_restore_target = dict(restore_target)
    assert (
        restore_disposable_database(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )
        == backup_digest
    )
    assert restore_target == original_restore_target
    fenced_target = entrypoints._bind_restore_cluster_identity(
        database_url, restore_target
    )
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[0].startswith("/proc/self/fd/")
    assert command[1:7] == (
        "--exit-on-error",
        "--clean",
        "--if-exists",
        "--no-owner",
        "--dbname",
        "postgresql://top_delivery_workflow@/td_test_restore_consumer?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
    )
    assert command[7].startswith("/proc/self/fd/")
    assert kwargs["check"] is False
    assert int(command[0].rsplit("/", 1)[1]) in kwargs["pass_fds"]
    assert int(command[7].rsplit("/", 1)[1]) in kwargs["pass_fds"]
    assert kwargs["env"]["PGPASSFILE"].startswith("/proc/self/fd/")
    assert "PGPASSWORD" not in kwargs["env"]
    assert len(kwargs["pass_fds"]) == 3
    assert "td-workflow-test" not in command
    assert kwargs["timeout"] >= 60.0
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is not subprocess.DEVNULL

    # A failure before the sealed payload is opened must still leave the
    # durable in-progress fence behind; this is the crash-window regression
    # that prevents a later retry from assuming the target is clean.
    original_open_verified = entrypoints._open_verified_restore_fd
    original_failure_writer = entrypoints._write_restore_failure_evidence

    def fail_before_child(**_kwargs: object) -> tuple[int, str]:
        raise AuthorizationFailureError("simulated pre-child failure")

    monkeypatch.setattr(
        entrypoints, "_open_verified_restore_fd", fail_before_child
    )
    with pytest.raises(AuthorizationFailureError, match="simulated pre-child failure"):
        restore_disposable_database(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )
    pre_child_fence = Path(_restore_fence_path(database_url, fenced_target))
    assert pre_child_fence.is_file()
    pre_child_records = sorted(root.glob("*.failure-*"))
    assert any(
        "reason=restore authorization failure: AuthorizationFailureError"
        in record.read_text(encoding="utf-8")
        for record in pre_child_records
    )
    pre_child_fence.unlink()
    def fail_evidence_persistence(**_kwargs: object) -> None:
        raise RuntimeError("simulated evidence persistence failure")

    monkeypatch.setattr(
        entrypoints, "_write_restore_failure_evidence", fail_evidence_persistence
    )
    with pytest.raises(AuthorizationFailureError, match="simulated pre-child failure"):
        restore_disposable_database(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )
    evidence_failure_fence = Path(_restore_fence_path(database_url, fenced_target))
    assert evidence_failure_fence.is_file()
    evidence_failure_fence.unlink()
    monkeypatch.setattr(
        entrypoints, "_write_restore_failure_evidence", original_failure_writer
    )
    monkeypatch.setattr(
        entrypoints, "_open_verified_restore_fd", original_open_verified
    )

    class WrongConnection(FakeConnection):
        def __init__(self) -> None:
            super().__init__(database="td_test_wrong_target")

    monkeypatch.setattr(entrypoints, "_verify_disposable_restore_target", original_verify_target)
    monkeypatch.setattr(
        comms01_scope,
        "verify_connection_identity",
        original_verify_identity,
    )
    monkeypatch.setattr(psycopg2, "connect", lambda _target: WrongConnection())
    Path(backup_path).write_bytes(payload)
    with pytest.raises(
        (AuthorizationFailureError, ScopeBoundaryViolationError),
        match="wrong target|identity mismatch",
    ):
        restore_disposable_database(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )
    assert len(calls) == 1

    monkeypatch.setattr(psycopg2, "connect", lambda _target: FakeConnection())
    monkeypatch.setattr(
        entrypoints,
        "_verify_disposable_restore_target",
        lambda _target, _restore_target: None,
    )
    monkeypatch.setattr(
        entrypoints,
        "_verify_disposable_restore_state",
        lambda _target, _head, _restore_target: (_ for _ in ()).throw(
            AuthorizationFailureError("simulated post-restore verification failure")
        ),
    )
    monkeypatch.setattr(
        entrypoints,
        "_run_fixed_command",
        lambda **_kwargs: type("Result", (), {"returncode": 0})(),
    )
    Path(backup_path).write_bytes(payload)
    with pytest.raises(PartialRestoreError, match="target is fenced"):
        restore_disposable_database(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )
    post_restore_fence = Path(_restore_fence_path(database_url, fenced_target))
    assert post_restore_fence.is_file()
    post_restore_fence.unlink()
    monkeypatch.setattr(
        entrypoints,
        "_verify_disposable_restore_state",
        lambda _target, _head, _restore_target: None,
    )
    monkeypatch.setattr(
        entrypoints,
        "_run_fixed_command",
        lambda **_kwargs: (_ for _ in ()).throw(
            PinnedCommandTimeoutError("simulated timeout after clean")
        ),
    )
    Path(backup_path).write_bytes(payload)
    with pytest.raises(PartialRestoreError, match="snapshot recovery"):
        restore_disposable_database(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )
    fence_path = Path(_restore_fence_path(database_url, fenced_target))
    assert fence_path.is_file()
    with pytest.raises(PartialRestoreError, match="target is fenced"):
        restore_disposable_database(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )
    alternate_backup_path = str(root / "alternate.dump")
    Path(alternate_backup_path).write_bytes(payload)
    with pytest.raises(AuthorizationFailureError, match="action digest|signature|binding"):
        restore_disposable_database(
            database_url=database_url,
            backup_path=alternate_backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )

    with pytest.raises(ScopeBoundaryViolationError, match="disposable"):
        restore_disposable_database(
            database_url=database_url.replace("td_test_restore_consumer", "top_delivery_control_p1"),
            backup_path=backup_path,
            operator_approval_receipt=receipt,
            restore_target=restore_target,
        )


def test_disposable_restore_runner_live_pg_restore_proof(
    db_url: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exercise the real pg_dump/pg_restore path only on disposable databases."""
    from urllib.parse import urlsplit, urlunsplit

    from comms01_operation_entrypoints import (
        _create_restore_passfile_fd,
        _password_free_database_url,
        backup_bytes,
        restore_disposable_database,
    )
    import comms01_operation_entrypoints as entrypoints
    import comms01_operation_policy as operation_policy
    from comms01_authority import OperatorTwoFactorChallenge

    target_name, target_url = _create_test_database(
        f"td_test_restore_live_{uuid.uuid4().hex}"
    )
    run_migrations(target_url)
    root = tmp_path / "live-backups"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    monkeypatch.setattr(operation_policy, "COMMS01_BACKUP_ROOTS", (str(root),))
    source_name = urlsplit(db_url).path.lstrip("/")
    local_socket = "%2Fvar%2Frun%2Fpostgresql"
    source_admin_url = (
        f"postgresql://root@/{source_name}?host={local_socket}&port=5432"
    )
    target_admin_url = (
        f"postgresql://root@/{target_name}?host={local_socket}&port=5432"
    )
    from comms01_scope import verify_connection_identity

    wrong_database_url = target_admin_url.replace(target_name, f"{target_name}_wrong")
    with psycopg2.connect(target_admin_url) as actual_connection:
        with pytest.raises(
            (AuthorizationFailureError, ScopeBoundaryViolationError),
            match="database identity mismatch",
        ):
            verify_connection_identity(
                database_url=wrong_database_url,
                connection=actual_connection,
                expected_role="root",
            )

    # Prove the actual sealed PGPASSFILE path with a password-authenticated
    # disposable connection.  This is separate from the root/peer pg_restore
    # path so a passfile regression cannot hide behind peer authentication.
    workflow_url = urlunsplit(
        (
            "postgresql",
            "top_delivery_workflow:td-workflow-test@127.0.0.1:5432",
            f"/{target_name}",
            "",
            "",
        )
    )
    safe_workflow_url, workflow_password = _password_free_database_url(workflow_url)
    assert workflow_password == "td-workflow-test"
    passfile_fd = _create_restore_passfile_fd(workflow_url, workflow_password)
    try:
        assert stat.S_IMODE(os.fstat(passfile_fd).st_mode) == 0o600
        with psycopg2.connect(
            safe_workflow_url, passfile=f"/proc/self/fd/{passfile_fd}"
        ) as password_connection:
            assert verify_connection_identity(
                database_url=safe_workflow_url,
                connection=password_connection,
                expected_role="top_delivery_workflow",
            ) == (target_name, "top_delivery_workflow")
    finally:
        os.close(passfile_fd)
    dump_path = tmp_path / "source.dump"
    backup_path = str(root / "source.dump")
    try:
        subprocess.run(
            (
                "/usr/lib/postgresql/17/bin/pg_dump",
                "--format=custom",
                "--file",
                str(dump_path),
                "--dbname",
                source_admin_url,
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=60.0,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        payload = dump_path.read_bytes()
        backup_digest = backup_bytes(
            database_url=target_admin_url,
            backup_path=backup_path,
            payload=payload,
        )
        restore_target = {
            "run_id": "run-restore-live",
            "operator_identity": "operator@test",
            "reviewed_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "source_digest": "c" * 64,
            "controller_epoch": 4,
            "config_version": 2,
            "challenge_epoch": 9,
            "backup_path": backup_path,
            "backup_digest": backup_digest,
            "backup_size": len(payload),
            "migration_head": CANONICAL_ALEMBIC_HEAD,
        }
        restore_target.update(_restore_route_fields(target_admin_url))
        restore_target = _bind_restore_identity(target_admin_url, restore_target)
        action_digest = digest_payload(
            {
                "action": "restore",
                "run_id": restore_target["run_id"],
                "operator_identity": restore_target["operator_identity"],
                "reviewed_sha": restore_target["reviewed_sha"],
                "tree_sha": restore_target["tree_sha"],
                "source_digest": restore_target["source_digest"],
                "controller_epoch": restore_target["controller_epoch"],
                "config_version": restore_target["config_version"],
                "challenge_epoch": restore_target["challenge_epoch"],
                "database_url": target_admin_url,
                "backup_path": backup_path,
                "backup_digest": backup_digest,
                "backup_size": len(payload),
                "migration_head": CANONICAL_ALEMBIC_HEAD,
                "database_name": restore_target["database_name"],
                "database_role": restore_target["database_role"],
                "database_endpoint": restore_target["database_endpoint"],
                "database_port": restore_target["database_port"],
                **_restore_identity_digest_fields(restore_target),
            }
        )
        challenge = OperatorTwoFactorChallenge(
            approval_id="restore-live-approval",
            operator_identity=restore_target["operator_identity"],
            action_type="restore",
            action_digest=action_digest,
            run_id=restore_target["run_id"],
            nonce="restore-live-nonce",
            expires_at="2099-01-01T00:00:00+00:00",
            key_version=1,
            controller_epoch=restore_target["controller_epoch"],
            config_version=restore_target["config_version"],
            challenge_epoch=restore_target["challenge_epoch"],
            challenge_digest="restore-live-challenge",
        )
        receipt = sign_external_operator_receipt(challenge)
        assert (
            restore_disposable_database(
                database_url=target_admin_url,
                backup_path=backup_path,
                operator_approval_receipt=receipt,
                restore_target=restore_target,
            )
            == backup_digest
        )
    finally:
        _drop_test_database(target_name)


def test_disposable_restore_runner_live_password_pg_restore_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The actual pinned pg_restore child authenticates through PGPASSFILE."""
    from urllib.parse import urlsplit

    from comms01_authority import OperatorTwoFactorChallenge
    from comms01_operation_entrypoints import (
        _create_restore_passfile_fd,
        _password_free_database_url,
        backup_bytes,
        restore_disposable_database,
    )
    import comms01_operation_entrypoints as entrypoints
    import comms01_operation_policy as operation_policy

    target_name, admin_url = _create_test_database(
        f"td_test_restore_password_{uuid.uuid4().hex}"
    )
    run_migrations(admin_url)
    root = tmp_path / "password-backups"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    monkeypatch.setattr(operation_policy, "COMMS01_BACKUP_ROOTS", (str(root),))
    password_url = (
        f"postgresql://top_delivery_workflow:td-workflow-test@127.0.0.1:5432/{target_name}"
    )
    safe_url, password = _password_free_database_url(password_url)
    assert password == "td-workflow-test"
    try:
        # Create the probe as the disposable administrator, then transfer
        # ownership so the password-authenticated workflow role can dump,
        # drop and recreate it through pg_restore.
        with psycopg2.connect(admin_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "CREATE TABLE password_restore_probe (id INTEGER PRIMARY KEY, marker TEXT NOT NULL)"
                )
                cur.execute(
                    "ALTER TABLE password_restore_probe OWNER TO top_delivery_workflow"
                )
                cur.execute(
                    "GRANT USAGE, CREATE ON SCHEMA public TO top_delivery_workflow"
                )
                cur.execute(
                    "INSERT INTO password_restore_probe (id, marker) VALUES (1, 'before-restore')"
                )
            conn.commit()

        dump_path = tmp_path / "password-source.dump"
        dump_passfile_fd = _create_restore_passfile_fd(password_url, password)
        try:
            assert stat.S_IMODE(os.fstat(dump_passfile_fd).st_mode) == 0o600
            subprocess.run(
                (
                    "/usr/lib/postgresql/17/bin/pg_dump",
                    "--format=custom",
                    "--table=password_restore_probe",
                    "--file",
                    str(dump_path),
                    "--dbname",
                    safe_url,
                ),
                check=True,
                capture_output=True,
                text=True,
                timeout=60.0,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PGPASSFILE": f"/proc/self/fd/{dump_passfile_fd}",
                },
                pass_fds=(dump_passfile_fd,),
            )
        finally:
            os.close(dump_passfile_fd)

        payload = dump_path.read_bytes()
        backup_path = str(root / "password-source.dump")
        backup_digest = backup_bytes(
            database_url=password_url,
            backup_path=backup_path,
            payload=payload,
        )
        restore_target = {
            "run_id": "run-restore-password",
            "operator_identity": "operator@test",
            "reviewed_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "source_digest": "c" * 64,
            "controller_epoch": 4,
            "config_version": 2,
            "challenge_epoch": 9,
            "backup_path": backup_path,
            "backup_digest": backup_digest,
            "backup_size": len(payload),
            "migration_head": CANONICAL_ALEMBIC_HEAD,
        }
        restore_target.update(_restore_route_fields(password_url))
        restore_target = _bind_restore_identity(password_url, restore_target)
        action_digest = digest_payload(
            {
                "action": "restore",
                "run_id": restore_target["run_id"],
                "operator_identity": restore_target["operator_identity"],
                "reviewed_sha": restore_target["reviewed_sha"],
                "tree_sha": restore_target["tree_sha"],
                "source_digest": restore_target["source_digest"],
                "controller_epoch": restore_target["controller_epoch"],
                "config_version": restore_target["config_version"],
                "challenge_epoch": restore_target["challenge_epoch"],
                "database_url": password_url,
                "backup_path": backup_path,
                "backup_digest": backup_digest,
                "backup_size": len(payload),
                "migration_head": CANONICAL_ALEMBIC_HEAD,
                "database_name": restore_target["database_name"],
                "database_role": restore_target["database_role"],
                "database_endpoint": restore_target["database_endpoint"],
                "database_port": restore_target["database_port"],
                **_restore_identity_digest_fields(restore_target),
            }
        )
        challenge = OperatorTwoFactorChallenge(
            approval_id="restore-password-approval",
            operator_identity=restore_target["operator_identity"],
            action_type="restore",
            action_digest=action_digest,
            run_id=restore_target["run_id"],
            nonce="restore-password-nonce",
            expires_at="2099-01-01T00:00:00+00:00",
            key_version=1,
            controller_epoch=restore_target["controller_epoch"],
            config_version=restore_target["config_version"],
            challenge_epoch=restore_target["challenge_epoch"],
            challenge_digest="restore-password-challenge",
        )
        receipt = sign_external_operator_receipt(challenge)
        assert (
            restore_disposable_database(
                database_url=password_url,
                backup_path=backup_path,
                operator_approval_receipt=receipt,
                restore_target=restore_target,
            )
            == backup_digest
        )
        with psycopg2.connect(password_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT marker FROM password_restore_probe WHERE id = 1")
                assert cur.fetchone()[0] == "before-restore"
    finally:
        _drop_test_database(target_name)


def test_comms01_backup_runner_has_a_bounded_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from comms01_operation_entrypoints import backup_bytes
    import comms01_operation_entrypoints as entrypoints
    import comms01_operation_policy as operation_policy

    root = tmp_path / "backups"
    root.mkdir()
    monkeypatch.setattr(operation_policy, "COMMS01_BACKUP_ROOTS", (str(root),))
    monkeypatch.setattr(entrypoints, "MAX_RESTORE_BYTES", 4)
    with pytest.raises(ScopeBoundaryViolationError, match="bounded limit"):
        backup_bytes(
            database_url="postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_runner",
            backup_path=str(root / "oversized.dump"),
            payload=b"12345",
        )


def test_ledger_mac_is_domain_separated_from_generic_payload_signatures() -> None:
    payload = {
        "child_id": "child",
        "attempt_number": 1,
        "event_type": "executor_result",
        "producer_role": "executor",
        "payload_digest": "payload",
        "previous_entry_hash": None,
    }
    base_digest = digest_payload(payload)
    generic = sign_payload(base_digest, "mac-key")
    ledger = compute_ledger_entry_hash(**payload, mac_key="mac-key")
    assert ledger == sign_payload("top_delivery:ledger_entry:v1:" + base_digest, "mac-key")
    assert ledger != generic


def test_database_scope_trigger_uses_controller_domain_without_test_bypass(
    db_url: str,
) -> None:
    """Exercise controller scopes through the real workflow database role."""
    run_id = f"run-scope-domain-{uuid.uuid4().hex}"
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT current_setting('top_delivery.disposable_test_mutation', true)"
            )
            assert cur.fetchone()[0] in (None, "")
            cur.execute(
                "SELECT longspan_register_run(%s, %s)",
                (run_id, "active"),
            )
            conn.commit()
            cur.execute(
                "SELECT longspan_acquire_controller(%s, %s, %s, %s, %s)",
                (run_id, "scope-domain-test", 30.0, 0, False),
            )
            assert int(cur.fetchone()[0]) == 1
            conn.commit()


def test_multi_host_libpq_authority_is_rejected() -> None:
    from comms01_scope import assert_database_url

    with pytest.raises(AuthorizationFailureError, match="multi-host"):
        assert_database_url(
            "postgresql://top_delivery_workflow@127.0.0.1,192.0.2.44/td_test_multi"
        )


def test_libpq_query_target_overrides_are_rejected() -> None:
    from comms01_scope import assert_admin_database_url, assert_database_url

    with pytest.raises(AuthorizationFailureError, match="libpq target override"):
        assert_admin_database_url(
            "postgresql:///td_test_query_override?host=192.0.2.44"
        )
    with pytest.raises(AuthorizationFailureError, match="libpq target override"):
        assert_database_url(
            "postgresql://top_delivery_workflow@/td_test_query_override?hostaddr=192.0.2.44"
        )


def test_libpq_target_environment_overrides_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from comms01_scope import assert_database_url

    for key in (
        "PGHOST",
        "PGHOSTADDR",
        "PGPORT",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGDATABASE",
        "PGUSER",
    ):
        monkeypatch.setenv(key, "192.0.2.44")
        with pytest.raises(AuthorizationFailureError, match="libpq target environment"):
            assert_database_url("postgresql:///td_test_env_override")
        monkeypatch.delenv(key)


@pytest.mark.parametrize(
    "key,value",
    (
        ("host", "192.0.2.44"),
        ("hostaddr", "192.0.2.44"),
        ("port", "5433"),
        ("service", "untrusted-service"),
        ("dbname", "production_db"),
        ("user", "postgres"),
        ("HOSTADDR", "192.0.2.44"),
        ("host%61ddr", "192.0.2.44"),
    ),
)
def test_every_libpq_query_target_override_is_rejected(key: str, value: str) -> None:
    from comms01_scope import assert_database_url

    with pytest.raises(AuthorizationFailureError, match="libpq target override"):
        assert_database_url(
            f"postgresql://top_delivery_workflow@/td_test_query_override?{key}={value}"
        )


def test_migration_role_graph_check_has_one_source_of_truth() -> None:
    source = Path(
        "controller/migrations/versions/007_longspan_authority_hardening.py"
    ).read_text(encoding="utf-8")
    assert source.count("WITH RECURSIVE role_members(member_oid, role_oid)") == 1


def test_database_inspection_seam_is_not_normal_connection_option() -> None:
    import db

    assert "allow_disposable_inspection" not in inspect.signature(db.connect).parameters
    assert "explicit admin-only seam" in (db.connect_disposable_inspection.__doc__ or "")


def test_authority_service_requires_the_pinned_database_role() -> None:
    import authority_service_server
    import comms01_scope

    server = object.__new__(AuthorityServiceServer)
    server._db_url = "postgresql://top_delivery_authority@127.0.0.1/top_delivery_control_p1"
    server._repo = SimpleNamespace(_repo=SimpleNamespace(_conn=object()))
    server._target = {}
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            authority_service_server,
            "load_comms01_attestation",
            lambda: SimpleNamespace(),
        )
        monkeypatch.setattr(
            comms01_scope,
            "verify_connection_identity",
            lambda **_: ("top_delivery_control_p1", "postgres"),
        )
        with pytest.raises(AuthorizationFailureError, match="requires role"):
            server._verify_server_runtime()


def test_authority_service_disposable_capability_is_target_bound() -> None:
    import authority_service_server
    import comms01_scope

    server = object.__new__(AuthorityServiceServer)
    server._db_url = (
        "postgresql://top_delivery_authority@127.0.0.1:5432/td_test_actual"
    )
    server._repo = SimpleNamespace(_repo=SimpleNamespace(_conn=object()))
    server._target = {
        "database_name": "td_test_actual",
        "database_endpoint": "127.0.0.1",
        "database_port": 5432,
        "database_role": "top_delivery_authority",
        "authority_service": "top-delivery-authority-service",
    }
    wrong_target = SimpleNamespace(
        database_name="td_test_other",
        database_endpoint="127.0.0.1",
        database_port=5432,
        database_role=MIGRATION_DATABASE_ROLE,
    )
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            authority_service_server,
            "load_comms01_attestation",
            lambda: SimpleNamespace(),
        )
        monkeypatch.setattr(
            comms01_scope,
            "verify_connection_identity",
            lambda **_: ("td_test_actual", "top_delivery_authority"),
        )
        monkeypatch.setattr(
            comms01_scope,
            "is_disposable_test_database",
            lambda _url: True,
        )
        monkeypatch.setattr(
            authority_service_server,
            "load_signed_disposable_capability",
            lambda: wrong_target,
        )
        with pytest.raises(AuthorizationFailureError, match="does not match connected target"):
            server._verify_server_runtime()


def test_disposable_mutation_seam_is_capability_bound_and_transaction_local() -> None:
    import db

    name, url = _create_test_database(f"td_test_seam_local_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="007_longspan_authority_hardening"
    )
    conn = psycopg2.connect(url)
    try:
        with conn.cursor() as cur:
            db.authorize_disposable_test_mutation(conn, url, cursor=cur)
            cur.execute(
                "SELECT current_setting('top_delivery.disposable_test_mutation', true)"
            )
            assert cur.fetchone()[0] == "1"
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT current_setting('top_delivery.disposable_test_mutation', true)"
            )
            assert cur.fetchone()[0] in (None, "")
    finally:
        conn.close()
        _drop_test_database(name)


def test_disposable_mutation_seam_rejects_wrong_database_inside_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import disposable_capability
    import db

    name, url = _create_test_database(f"td_test_seam_target_{uuid.uuid4().hex}")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                disposable_capability,
                "load_signed_disposable_capability",
                lambda: SimpleNamespace(database_name="td_test_other_target"),
            )
            with psycopg2.connect(url) as conn:
                conn.autocommit = False
                with conn.cursor() as cur:
                    with pytest.raises(
                        AuthorizationFailureError,
                        match="signed capability for this database",
                    ):
                        db.authorize_disposable_test_mutation(conn, url, cursor=cur)
                    cur.execute(
                        "SELECT current_setting('top_delivery.disposable_test_mutation', true)"
                    )
                    assert cur.fetchone()[0] is None
    finally:
        _drop_test_database(name)


def test_disposable_mutation_authorization_is_not_established_at_connect_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import db
    import workflow_database_target

    name, url = _create_test_database(f"td_test_connect_seam_{uuid.uuid4().hex}")
    monkeypatch.setattr(workflow_database_target, "resolve_workflow_database_url", lambda _url: url)
    monkeypatch.setattr(db, "assert_comms01_entrypoint", lambda **_kwargs: None)
    monkeypatch.setattr(db, "validate_database_url", lambda value: value)
    monkeypatch.setattr(db, "verify_connection_identity", lambda **_kwargs: None)
    conn = db._connect(url, allow_disposable_inspection=True)
    try:
        assert conn.autocommit is False
        with conn.cursor() as cur:
            cur.execute(
                "SELECT current_setting('top_delivery.disposable_test_mutation', true)"
            )
            assert cur.fetchone()[0] is None
    finally:
        conn.close()
        _drop_test_database(name)


def test_repository_reauthorizes_transaction_local_disposable_seam() -> None:
    import repository

    name, url = _create_test_database(f"td_test_repo_seam_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="007_longspan_authority_hardening"
    )
    repo = repository.PostgresRepository.__new__(repository.PostgresRepository)
    repo.db_url = url
    repo._conn = psycopg2.connect(url)
    try:
        with repo.transaction() as cur:
            cur.execute(
                "SELECT current_setting('top_delivery.disposable_test_mutation', true)"
            )
            assert cur.fetchone()["current_setting"] == "1"
        with repo._conn.cursor() as cur:
            cur.execute(
                "SELECT current_setting('top_delivery.disposable_test_mutation', true)"
            )
            assert cur.fetchone()[0] in (None, "")
    finally:
        repo.close()
        _drop_test_database(name)


def test_006_archive_acl_allows_only_select_for_runtime_roles() -> None:
    source = Path(
        "controller/migrations/versions/006_longspan_authority.py"
    ).read_text(encoding="utf-8")
    assert "acl.privilege_type = 'SELECT'" in source
    assert "acl.grantee IN" in source
    assert "archive_has_unexpected_acl" in source
    assert "archive_has_unexpected_column_acl" in source
    assert "archive_has_unexpected_default_acl" in source


def test_008_archive_default_acl_contract_is_owner_scoped() -> None:
    source = Path(
        "controller/migrations/versions/008_longspan_authority_repair.py"
    ).read_text(encoding="utf-8")
    assert "defaults.defaclrole = archive_owner_oid" in source
    assert "defaults.defaclobjtype IN ('r', 'S')" in source
    assert "unsafe public default ACL for role %" in source


def test_client_advisory_lock_namespaces_match_migration_contract() -> None:
    source = Path("controller/longspan_repository.py").read_text(encoding="utf-8")
    assert source.count("pg_advisory_xact_lock(8101, hashtext(%s))") >= 2
    assert "pg_advisory_xact_lock(8102, hashtext(%s))" in source


def test_disposable_capability_requires_root_owner_even_for_trusted_service_uid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the trusted-service UID boundary")
    import disposable_capability

    capability_path = tmp_path / "capability.json"
    capability_path.write_text("{}\n", encoding="utf-8")
    capability_path.chmod(0o600)
    os.chown(capability_path, AUTHORITY_SERVICE_UID, 0)
    monkeypatch.setattr(
        disposable_capability, "DISPOSABLE_HARNESS_CAPABILITY_PATH", str(capability_path)
    )
    with pytest.raises(AuthorizationFailureError, match="trusted owner/path"):
        disposable_capability.read_capability_json_file(str(capability_path))


def test_migration_and_receipt_guards_are_explicitly_bound() -> None:
    env_source = Path("controller/migrations/env.py").read_text(encoding="utf-8")
    migration_source = Path(
        "controller/migrations/versions/007_longspan_authority_hardening.py"
    ).read_text(encoding="utf-8")
    assert "explicit canonical target is unavailable" in env_source
    assert "approved_migration_principals" in env_source
    assert "load_signed_disposable_capability" not in env_source
    assert "database_name=str(database_name)" in env_source
    assert "database_role=effective_database_role" in env_source
    assert "migration_revision=target" in env_source
    assert "database_name=str(database_name)" in env_source
    assert "migration_revision=target" in env_source
    assert "top_delivery:terra_receipt:v1:" in migration_source
    assert "stored_request_digest" in migration_source
    assert "stored_evidence_digest" in migration_source
    assert "stored_result_digest" in migration_source
    assert "controller_routine" not in migration_source
    assert "general controller scope table is not in the explicit controller allowlist" in migration_source
    assert "DROP TABLE IF EXISTS longspan_execution_audits" in migration_source
    assert "current_user = 'root' AND capability_nonce IS NOT NULL" not in migration_source
    assert "to_regclass(:qualified_name)" in env_source
    assert "007_longspan_authority_hardening" in env_source
    assert '"008_longspan_authority_repair"' in env_source
    assert env_source.index("target not in set(_PROTECTED_TABLES_BY_TARGET)") < env_source.index(
        "require_disposable_capability("
    )
    general_allowlist = migration_source.split(
        "AND TG_TABLE_NAME NOT IN (", 1
    )[1].split(") THEN", 1)[0]
    assert "'longspan_children'" not in general_allowlist
    assert "'longspan_plans'" not in general_allowlist
    assert "'longspan_execution_results'" not in general_allowlist


def test_populated_004_to_head_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    name, url = _create_test_database(f"td_downgrade_pop006_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "004_longspan_workflow")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO supervisor_runs (run_id, state) VALUES ('run-006', 'active')"
                )
                cur.execute(
                    """
                    INSERT INTO parent_tasks (task_id, run_id, objective, state)
                    VALUES ('task-006', 'run-006', 'migration', 'queued')
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_children
                        (child_id, task_id, run_id, parent_attempt_id, fence_token, state,
                         idempotency_key, request_digest, attempt_number, version)
                    VALUES ('child-006', 'task-006', 'run-006', 'attempt-006', 1, 'ready',
                            'idem-006', 'digest-006', 0, 0)
                    """
                )
                entry_hash = compute_ledger_entry_hash(
                    child_id="child-006",
                    attempt_number=0,
                    event_type="seed",
                    producer_role="parent",
                    payload_digest=digest_payload({"seed": True}),
                    previous_entry_hash=None,
                )
                cur.execute(
                    """
                    INSERT INTO longspan_evidence_ledger
                        (entry_id, child_id, attempt_number, event_type, producer_role,
                         payload_digest, previous_entry_hash, entry_hash)
                    VALUES ('entry-006', 'child-006', 0, 'seed', 'parent', %s, NULL, %s)
                    """,
                    (digest_payload({"seed": True}), entry_hash),
                )
                conn.commit()
        run_migrations(url)
        # The read path is still target-fenced; provide the same signed
        # disposable capability that an isolated migration inspection uses.
        install_downgrade_capability(
            database_name=name, migration_revision=CANONICAL_ALEMBIC_HEAD
        )
        assert current_database_revision(url) == CANONICAL_ALEMBIC_HEAD
    finally:
        _drop_test_database(name)


def test_legacy_unbound_transport_sentinel_is_rejected_for_new_capabilities() -> None:
    name, url = _create_test_database(f"td_test_sentinel_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg2.Error, match="transport_role_bound"):
                    cur.execute(
                        """
                        INSERT INTO top_delivery_downgrade_capabilities
                            (nonce, operation, database_name, database_role,
                             transport_database_role, controller_service,
                             migration_revision, expires_at)
                        VALUES
                            (%s, 'migration_downgrade', %s, 'top_delivery_migration',
                             '__legacy_unbound__', 'top-delivery-controller',
                             '007_longspan_authority_hardening',
                             clock_timestamp() + interval '5 minutes')
                        """,
                        (f"sentinel-{uuid.uuid4().hex}", name),
                    )
                conn.rollback()
    finally:
        _drop_test_database(name)


def test_006_downgrade_blocked_with_authority_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    name, url = _create_test_database(f"td_downgrade_006_{uuid.uuid4().hex}")
    install_downgrade_capability(database_name=name, migration_revision="005_longspan_hardening")
    server = None
    try:
        run_migrations(url)
        from test_authority_helpers import start_authority_service_for_url

        server = start_authority_service_for_url(url)
        workflow_url = (
            f"postgresql://top_delivery_workflow:td-workflow-test@127.0.0.1:5432/{name}"
        )
        # Authority-service startup may consume the shared test capability
        # while validating its disposable target. Re-issue the signed
        # capability at the workflow connection boundary.
        install_downgrade_capability(
            database_name=name, migration_revision="005_longspan_hardening"
        )
        workflow = _workflow(workflow_url, tmp_path)
        workflow.parent.register_run("run-auth")
        _provision_authority(workflow, "run-auth")
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "downgrade", "005_longspan_hardening")
        workflow.close()
    finally:
        if server is not None:
            server.close()
        _drop_test_database(name)


def test_downgrade_to_006_refuses_populated_007_evidence() -> None:
    name, url = _create_test_database(f"td_downgrade_007_pop_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="006_longspan_authority"
    )
    try:
        run_migrations(url)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO longspan_mac_material (material_id, mac_key) VALUES ('ledger', 'populated-test-key')"
                )
            conn.commit()
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "downgrade", "006_longspan_authority")
    finally:
        _drop_test_database(name)


def test_populated_008_downgrade_is_rejected_by_database_gate(tmp_path: Path) -> None:
    """A populated authority row must block an in-place 008 downgrade."""
    name, url = _create_test_database(f"td_downgrade_pop8_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        from test_authority_helpers import start_authority_service_for_url

        server = start_authority_service_for_url(url)
        workflow_url = (
            f"postgresql://top_delivery_workflow:td-workflow-test@127.0.0.1:5432/{name}"
        )
        try:
            workflow = _workflow(workflow_url, tmp_path)
            try:
                workflow.parent.register_run("populated-008-gate")
                _provision_authority(workflow, "populated-008-gate")
            finally:
                workflow.close()
        finally:
            server.close()
        install_downgrade_capability(
            database_name=name, migration_revision="006_longspan_authority"
        )
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "downgrade", "006_longspan_authority")
    finally:
        _drop_test_database(name)


def test_populated_008_rollback_contract_requires_restore_not_downgrade() -> None:
    runbook = (
        REPO_ROOT / "controller" / "migrations" / "longspan-008-populated-006-runbook.md"
    ).read_text(encoding="utf-8")
    lowered = runbook.lower()
    assert "restore-from-backup" in lowered
    assert "longspan_mac_material" in lowered
    assert "pitr" in lowered
    assert "in-place `008 → 006` downgrade is intentionally rejected" in lowered


def test_populated_006_evidence_upgrade_fails_without_backfill() -> None:
    name, url = _create_test_database(f"td_downgrade_006_legacy_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="006_longspan_authority"
    )
    try:
        run_migrations(url)
        install_downgrade_capability(
            database_name=name, migration_revision="006_longspan_authority"
        )
        alembic_command(url, "downgrade", "006_longspan_authority")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO supervisor_runs (run_id, state) VALUES ('legacy-run', 'active')"
                )
                cur.execute(
                    """
                    INSERT INTO parent_tasks (task_id, run_id, objective, state)
                    VALUES ('legacy-task', 'legacy-run', 'legacy evidence', 'queued')
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_children
                        (child_id, task_id, run_id, parent_attempt_id, fence_token, state,
                         idempotency_key, request_digest, attempt_number, version)
                    VALUES ('legacy-child', 'legacy-task', 'legacy-run', 'legacy-attempt', 1,
                            'executed', 'legacy-idem', 'legacy-request', 0, 0)
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_execution_audits
                        (audit_id, child_id, attempt_number, request_digest, result_digest,
                         validation_outcome, raw_result_ref)
                    VALUES ('legacy-audit', 'legacy-child', 0, 'legacy-request',
                            'legacy-result', 'passed', 'legacy-raw')
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_auditor_receipts
                        (receipt_id, child_id, attempt_number, verdict, reasons_json,
                         inspector_digest, receipt_digest)
                    VALUES ('legacy-receipt', 'legacy-child', 0, 'pass', '[]',
                            'legacy-inspector', 'legacy-receipt-digest')
                    """
                )
            conn.commit()
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "upgrade", "head")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*), MIN(audit_id) FROM longspan_execution_audits"
                )
                assert cur.fetchone() == (1, "legacy-audit")
                cur.execute(
                    "SELECT COUNT(*), MIN(receipt_id) FROM longspan_auditor_receipts"
                )
                assert cur.fetchone() == (1, "legacy-receipt")
    finally:
        _drop_test_database(name)


def test_006_legacy_execution_auditor_and_terra_contracts_accept_valid_rows() -> None:
    """The recorded 006 downgrade boundary remains executable, not just rejecting."""
    name, url = _create_test_database(f"td_downgrade_006_positive_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="006_longspan_authority"
    )
    try:
        run_migrations(url)
        alembic_command(url, "downgrade", "006_longspan_authority")
        executor_token = "legacy-executor-token"
        auditor_token = "legacy-auditor-token"
        terra_token = "legacy-terra-token"
        reviewed_sha = "a" * 40
        child_id = "legacy-positive-child"
        run_id = "legacy-positive-run"
        task_id = "legacy-positive-task"
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO supervisor_runs (run_id, state) VALUES (%s, 'active')",
                    (run_id,),
                )
                cur.execute(
                    """
                    INSERT INTO parent_tasks (task_id, run_id, objective, state)
                    VALUES (%s, %s, 'legacy positive contract', 'queued')
                    """,
                    (task_id, run_id),
                )
                cur.execute(
                    """
                    INSERT INTO longspan_children
                        (child_id, task_id, run_id, parent_attempt_id, fence_token, state,
                         idempotency_key, request_digest, attempt_number, version,
                         lease_expires_at, executor_capability_hash, auditor_capability_hash)
                    VALUES (%s, %s, %s, 'legacy-parent-attempt', 1, 'executing',
                            'legacy-positive-idem', 'legacy-positive-request', 0, 0,
                            clock_timestamp() + interval '10 minutes', %s, %s)
                    """,
                    (
                        child_id,
                        task_id,
                        run_id,
                        hash_capability_token(executor_token),
                        hash_capability_token(auditor_token),
                    ),
                )
                legacy_entry_hash = compute_ledger_entry_hash(
                    child_id=child_id,
                    attempt_number=0,
                    event_type="executor_result",
                    producer_role="executor",
                    payload_digest="legacy-positive-payload",
                    previous_entry_hash=None,
                )
                cur.execute(
                    """
                    INSERT INTO longspan_evidence_ledger
                        (entry_id, child_id, attempt_number, event_type, producer_role,
                         payload_digest, previous_entry_hash, entry_hash)
                    VALUES ('legacy-positive-ledger', %s, 0, 'executor_result', 'executor',
                            'legacy-positive-payload', NULL, %s)
                    """,
                    (child_id, legacy_entry_hash),
                )
                cur.execute(
                    """
                    SELECT longspan_append_execution_audit(
                        'legacy-positive-audit', %s, 0, 'legacy-positive-request',
                        'legacy-positive-result', 'passed', 'legacy-raw', %s
                    )
                    """,
                    (child_id, executor_token),
                )
                cur.execute(
                    "UPDATE longspan_children SET state = 'executed' WHERE child_id = %s",
                    (child_id,),
                )
                cur.execute(
                    """
                    SELECT longspan_append_auditor_receipt(
                        'legacy-positive-auditor', %s, 0, 'pass', '[]',
                        'legacy-inspector', 'legacy-auditor-receipt', %s
                    )
                    """,
                    (child_id, auditor_token),
                )
                cur.execute(
                    "UPDATE longspan_children SET state = 'terra_pending' WHERE child_id = %s",
                    (child_id,),
                )
                cur.execute(
                    """
                    INSERT INTO longspan_authority_config
                        (run_id, terra_auth_hash, operator_auth_hash, reviewed_sha)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        run_id,
                        hash_capability_token(terra_token),
                        hash_capability_token("legacy-operator"),
                        reviewed_sha,
                    ),
                )
                cur.execute("SELECT set_config('top_delivery.controller_epoch', '1', true)")
                cur.execute(
                    """
                    SELECT longspan_append_terra_receipt(
                        'legacy-positive-terra', %s, 0, 'terra-review', 'approved',
                        %s, 'legacy-receipt', %s, %s, %s, 1, 1, 'legacy-tree',
                        'legacy-source', 'legacy-positive-request', '006_longspan_authority',
                        1, 'legacy-evidence', 'legacy-positive-result', 'legacy-signature', %s
                    )
                    """,
                    (
                        child_id,
                        legacy_entry_hash,
                        run_id,
                        task_id,
                        reviewed_sha,
                        terra_token,
                    ),
                )
                cur.execute(
                    "SELECT COUNT(*) FROM longspan_terra_receipts WHERE child_id = %s",
                    (child_id,),
                )
                assert cur.fetchone()[0] == 1
            conn.commit()
    finally:
        _drop_test_database(name)


def test_007_to_006_restores_legacy_contracts_and_reupgrades() -> None:
    name, url = _create_test_database(f"td_downgrade_007_direct_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="006_longspan_authority"
    )
    try:
        run_migrations(url)
        alembic_command(url, "downgrade", "006_longspan_authority")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version_num FROM alembic_version")
                assert cur.fetchone()[0] == "006_longspan_authority"
                cur.execute(
                    """
                    SELECT p.pronargs, pg_get_function_identity_arguments(p.oid)
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public'
                      AND p.proname = 'longspan_append_auditor_receipt'
                    """
                )
                signatures = cur.fetchall()
                assert len(signatures) == 1
                assert signatures[0][0] == 8
                assert "p_evidence_digest" not in signatures[0][1]
                cur.execute(
                    """
                    SELECT has_function_privilege(
                        'top_delivery_workflow',
                        'public.longspan_append_auditor_receipt(text,text,integer,text,text,text,text,text)',
                        'EXECUTE'
                    )
                    """
                )
                assert cur.fetchone()[0] is False
                cur.execute(
                    """
                    SELECT p.pronargs, pg_get_function_result(p.oid),
                           pg_get_function_identity_arguments(p.oid)
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public'
                      AND p.proname = 'longspan_append_execution_audit'
                    """
                )
                execution_signatures = cur.fetchall()
                assert len(execution_signatures) == 1
                assert execution_signatures[0][0] == 8
                assert execution_signatures[0][1] == "void"
                assert "p_evidence_digest" not in execution_signatures[0][2]
                cur.execute(
                    """
                    SELECT has_function_privilege(
                        'top_delivery_workflow',
                        'public.longspan_append_execution_audit(text,text,integer,text,text,text,text,text)',
                        'EXECUTE'
                    )
                    """
                )
                assert cur.fetchone()[0] is False
                cur.execute(
                    """
                    SELECT p.pronargs, pg_get_function_result(p.oid)
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public'
                      AND p.proname = 'longspan_append_terra_receipt'
                    """
                )
                terra_signatures = cur.fetchall()
                assert len(terra_signatures) == 1
                assert terra_signatures[0][0] == 21
                assert terra_signatures[0][1] == "void"
                cur.execute(
                    """
                    SELECT has_function_privilege(
                        'top_delivery_workflow',
                        'public.longspan_append_terra_receipt(text,text,integer,text,text,text,text,text,text,text,bigint,integer,text,text,text,text,integer,text,text,text,text)',
                        'EXECUTE'
                    )
                    """
                )
                assert cur.fetchone()[0] is False
                cur.execute(
                    "SELECT to_regclass('public.longspan_execution_audits')"
                )
                assert cur.fetchone()[0] == "longspan_execution_audits"
        # The restored routines are callable at the 006 boundary and fail
        # closed on an unknown child rather than silently accepting a call.
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg2.Error):
                    cur.execute(
                        """
                        SELECT longspan_append_execution_audit(
                            %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        """,
                        ("audit-missing", "child-missing", 0, "request", "result", "ok", None, "token"),
                    )
                conn.rollback()
                with pytest.raises(psycopg2.Error):
                    cur.execute(
                        """
                        SELECT longspan_append_terra_receipt(
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        """,
                        (
                            "terra-missing", "child-missing", 0, "terra", "approved",
                            "head", "receipt", "run-missing", "task-missing", REVIEWED_SHA,
                            1, 1, "tree", "source", "request", "006_longspan_authority",
                            1, "evidence", "result", "signature", "token",
                        ),
                    )
                conn.rollback()
        install_downgrade_capability(
            database_name=name, migration_revision="005_longspan_hardening"
        )
        alembic_command(url, "downgrade", "005_longspan_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public'
                      AND p.proname = 'longspan_append_auditor_receipt'
                      AND p.pronargs = 8
                    """
                )
                assert cur.fetchone()[0] == 0
        alembic_command(url, "upgrade", "head")
        assert current_database_revision(url) == CANONICAL_ALEMBIC_HEAD
    finally:
        _drop_test_database(name)


def test_007_to_006_acl_matches_fresh_006_install() -> None:
    downgraded_name, downgraded_url = _create_test_database(
        f"td_downgrade_007_acl_{uuid.uuid4().hex}"
    )
    fresh_name, fresh_url = _create_test_database(
        f"td_downgrade_006_acl_{uuid.uuid4().hex}"
    )

    def acl_snapshot(url: str) -> tuple[list[tuple], list[tuple]]:
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT table_name, grantee, privilege_type
                    FROM information_schema.role_table_grants
                    WHERE table_schema = 'public'
                      AND grantee IN ('top_delivery_workflow', 'top_delivery_authority')
                    ORDER BY table_name, grantee, privilege_type
                    """
                )
                table_rows = cur.fetchall()
                cur.execute(
                    """
                    SELECT routine_name, grantee, privilege_type
                    FROM information_schema.routine_privileges
                    WHERE specific_schema = 'public'
                      AND grantee IN ('top_delivery_workflow', 'top_delivery_authority')
                    ORDER BY routine_name, grantee, privilege_type
                    """
                )
                routine_rows = cur.fetchall()
        return table_rows, routine_rows

    try:
        install_downgrade_capability(
            database_name=downgraded_name,
            migration_revision="006_longspan_authority",
        )
        run_migrations(downgraded_url)
        alembic_command(downgraded_url, "downgrade", "006_longspan_authority")
        # The downgrade capability is bound to the first database. Rebind the
        # administrative test transport before upgrading the independent
        # fresh-install comparison database.
        install_create_capability(database_name=fresh_name)
        alembic_command(fresh_url, "upgrade", "006_longspan_authority")
        assert acl_snapshot(downgraded_url) == acl_snapshot(fresh_url)
    finally:
        _drop_test_database(downgraded_name)
        _drop_test_database(fresh_name)


def test_006_downgrade_rejects_runtime_insert_acl_on_archive() -> None:
    """A runtime INSERT grant must fail before the 008 archive is parked."""
    name, url = _create_test_database(f"td_downgrade_006_insert_acl_{uuid.uuid4().hex}")
    try:
        # Start at the exact 006 schema so this test reaches the 006 guard
        # directly, without a preceding 007 compatibility downgrade changing
        # the archive ACL first.
        alembic_command(url, "upgrade", "006_longspan_authority")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "ALTER SCHEMA top_delivery_recovery OWNER TO top_delivery_migration"
                )
                cur.execute(
                    "REVOKE ALL ON SCHEMA top_delivery_recovery FROM PUBLIC, "
                    "top_delivery_workflow, top_delivery_authority"
                )
                cur.execute(
                    """
                    CREATE TABLE public.longspan_migration_provenance_008_archive (
                        archive_id BIGINT PRIMARY KEY,
                        revision TEXT NOT NULL,
                        source_digest TEXT NOT NULL,
                        algorithm TEXT NOT NULL,
                        normalization_version INTEGER NOT NULL,
                        applied_at TIMESTAMPTZ NOT NULL,
                        application_count BIGINT NOT NULL DEFAULT 1,
                        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                        provenance_table_preexisting BOOLEAN NOT NULL
                    )
                    """
                )
                cur.execute(
                    "ALTER TABLE public.longspan_migration_provenance_008_archive "
                    "OWNER TO top_delivery_migration"
                )
                cur.execute(
                    "GRANT INSERT ON TABLE public.longspan_migration_provenance_008_archive "
                    "TO top_delivery_workflow"
                )
                conn.commit()
        install_downgrade_capability(
            database_name=name,
            migration_revision="005_longspan_hardening",
        )
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            alembic_command(url, "downgrade", "005_longspan_hardening")
        assert "006 downgrade blocked: public provenance archive has an unexpected ACL" in (
            exc_info.value.stderr or ""
        )
    finally:
        _drop_test_database(name)


def test_006_downgrade_accepts_runtime_select_acl_on_archive() -> None:
    """The approved runtime SELECT-only ACL can cross the 006 -> 005 leg."""
    name, url = _create_test_database(f"td_downgrade_006_select_acl_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "006_longspan_authority")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "ALTER SCHEMA top_delivery_recovery OWNER TO top_delivery_migration"
                )
                cur.execute(
                    "REVOKE ALL ON SCHEMA top_delivery_recovery FROM PUBLIC, "
                    "top_delivery_workflow, top_delivery_authority"
                )
                cur.execute(
                    """
                    CREATE TABLE public.longspan_migration_provenance_008_archive (
                        archive_id BIGINT PRIMARY KEY,
                        revision TEXT NOT NULL,
                        source_digest TEXT NOT NULL,
                        algorithm TEXT NOT NULL,
                        normalization_version INTEGER NOT NULL,
                        applied_at TIMESTAMPTZ NOT NULL,
                        application_count BIGINT NOT NULL DEFAULT 1,
                        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                        provenance_table_preexisting BOOLEAN NOT NULL
                    )
                    """
                )
                cur.execute(
                    "ALTER TABLE public.longspan_migration_provenance_008_archive "
                    "OWNER TO top_delivery_migration"
                )
                cur.execute(
                    "GRANT SELECT ON TABLE public.longspan_migration_provenance_008_archive "
                    "TO top_delivery_workflow"
                )
            conn.commit()
        install_downgrade_capability(
            database_name=name,
            migration_revision="005_longspan_hardening",
        )
        alembic_command(url, "downgrade", "005_longspan_hardening")
        assert current_database_revision(url) == "005_longspan_hardening"
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass('public.longspan_migration_provenance_008_archive'), "
                    "to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive')"
                )
                public_archive, recovery_archive = cur.fetchone()
                assert public_archive is None
                assert recovery_archive is not None
    finally:
        _drop_test_database(name)


def _prepare_006_public_archive_with_acl(
    url: str,
    extra_statement: str,
) -> None:
    """Create the 006-bound archive and apply one deliberately unsafe ACL."""
    alembic_command(url, "upgrade", "006_longspan_authority")
    with psycopg2.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "ALTER SCHEMA top_delivery_recovery OWNER TO top_delivery_migration"
            )
            cur.execute(
                "REVOKE ALL ON SCHEMA top_delivery_recovery FROM PUBLIC, "
                "top_delivery_workflow, top_delivery_authority"
            )
            cur.execute(
                """
                CREATE TABLE public.longspan_migration_provenance_008_archive (
                    archive_id BIGINT PRIMARY KEY,
                    revision TEXT NOT NULL,
                    source_digest TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    normalization_version INTEGER NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL,
                    application_count BIGINT NOT NULL DEFAULT 1,
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
                    provenance_table_preexisting BOOLEAN NOT NULL
                )
                """
            )
            cur.execute(
                "ALTER TABLE public.longspan_migration_provenance_008_archive "
                "OWNER TO top_delivery_migration"
            )
            cur.execute(extra_statement)
        conn.commit()


def test_006_downgrade_rejects_runtime_column_insert_acl_on_archive() -> None:
    """A column-level INSERT grant must fail independently of relation ACLs."""
    name, url = _create_test_database(
        f"td_downgrade_006_column_acl_{uuid.uuid4().hex}"
    )
    try:
        _prepare_006_public_archive_with_acl(
            url,
            "GRANT INSERT (archive_id) ON TABLE "
            "public.longspan_migration_provenance_008_archive "
            "TO top_delivery_workflow",
        )
        install_downgrade_capability(
            database_name=name,
            migration_revision="005_longspan_hardening",
        )
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            alembic_command(url, "downgrade", "005_longspan_hardening")
        assert (
            "006 downgrade blocked: public provenance archive has an unexpected "
            "column ACL"
        ) in (exc_info.value.stderr or "")
    finally:
        _drop_test_database(name)


@pytest.mark.parametrize(
    ("extra_statement", "expected_object_type"),
    (
        (
            "ALTER DEFAULT PRIVILEGES FOR ROLE top_delivery_migration "
            "IN SCHEMA public GRANT INSERT ON TABLES TO top_delivery_workflow",
            "r",
        ),
        (
            "ALTER DEFAULT PRIVILEGES FOR ROLE top_delivery_migration "
            "IN SCHEMA public GRANT USAGE ON SEQUENCES TO top_delivery_workflow",
            "S",
        ),
    ),
)
def test_006_downgrade_rejects_runtime_default_insert_acl_on_archive(
    extra_statement: str, expected_object_type: str
) -> None:
    """Owner-scoped table and sequence defaults fail before the archive is moved."""
    name, url = _create_test_database(
        f"td_downgrade_006_default_acl_{uuid.uuid4().hex}"
    )
    try:
        _prepare_006_public_archive_with_acl(url, extra_statement)
        install_downgrade_capability(
            database_name=name,
            migration_revision="005_longspan_hardening",
        )
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            alembic_command(url, "downgrade", "005_longspan_hardening")
        assert (
            "006 downgrade blocked: public provenance archive has an unexpected "
            f"default ACL for role top_delivery_migration and object type {expected_object_type}"
        ) in (exc_info.value.stderr or "")
    finally:
        _drop_test_database(name)


def test_006_downgrade_ignores_unrelated_role_default_acl() -> None:
    """The 006 archive guard is scoped to defaults owned by the archive role."""
    name, url = _create_test_database(
        f"td_downgrade_006_unrelated_{uuid.uuid4().hex}"
    )
    try:
        _prepare_006_public_archive_with_acl(
            url,
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ATTACKER_DATABASE_ROLE} "
            "IN SCHEMA public GRANT INSERT ON TABLES TO top_delivery_workflow",
        )
        install_downgrade_capability(
            database_name=name,
            migration_revision="005_longspan_hardening",
        )
        alembic_command(url, "downgrade", "005_longspan_hardening")
        assert current_database_revision(url) == "005_longspan_hardening"
    finally:
        _drop_test_database(name)


def test_workflow_cannot_self_provision_authority(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    with pytest.raises(AuthorizationFailureError, match="Comms01AuthorityBoundary"):
        workflow.provision_authority(
            "run-1",
            terra_auth_token=TERRA_TOKEN,
            operator_auth_token=OPERATOR_TOKEN,
            reviewed_sha=REVIEWED_SHA,
        )
    workflow.close()


def test_executor_cannot_rotate_authority(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _provision_authority(workflow, "run-1")
    with pytest.raises(AuthorizationFailureError):
        workflow.repo.rotate_authority_config(
            run_id="run-1",
            terra_auth_hash=hash_capability_token("new-terra"),
            operator_auth_hash=hash_capability_token("new-operator"),
            reviewed_sha=REVIEWED_SHA,
            tree_sha="tree",
            source_digest="source",
            controller_epoch=workflow.parent.controller_epoch("run-1"),
            expected_config_version=1,
            approval_receipt_digest="digest",
            approval_id="approval-x",
            operator_identity="operator@test",
            write_credential=AuthorityWriteCredential(token="forged"),
            operator_challenge={
                "approval_id": "x",
                "run_id": "run-1",
                "action_type": "rotate_authority",
                "action_digest": "digest",
                "operator_identity": "operator@test",
                "nonce": "n",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "key_version": 2,
                "controller_epoch": workflow.parent.controller_epoch("run-1"),
                "config_version": 2,
                "challenge_digest": "cd",
                "write_credential": AuthorityWriteCredential(token="forged"),
            },
        )
    workflow.close()


def test_scope_rejects_broker_endpoint() -> None:
    with pytest.raises(ScopeBoundaryViolationError):
        reject_broker_endpoint("https://api-fxtrade.oanda.com")


def test_scope_rejects_production_database() -> None:
    with pytest.raises(ScopeBoundaryViolationError):
        assert_comms01_entrypoint(
            scope="comms-01",
            database_url="postgresql://u@postgres-01/top_delivery_control_p1",
        )


def test_controller_and_workflow_fences_cannot_cross(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-scope-fences")
    workflow.parent.schedule_task("run-scope-fences", "task-scope-fences", "scope")
    claimed = workflow.parent.claim_next("run-scope-fences", "worker")
    assert claimed is not None
    epoch = workflow.parent.controller_epoch("run-scope-fences")
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            """
            SELECT controller_fence_token
            FROM controller_control
            WHERE run_id = %s
            """,
            ("run-scope-fences",),
        )
        controller_fence = int(cur.fetchone()["controller_fence_token"])
        cur.execute(
            "SELECT fence_token FROM task_attempts WHERE task_id = %s",
            ("task-scope-fences",),
        )
        task_fence = int(cur.fetchone()["fence_token"])
    assert controller_fence != task_fence
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                "SELECT longspan_open_controller_mutation_scope(%s, %s, %s, %s)",
                (
                    "run-scope-fences",
                    epoch,
                    task_fence,
                    workflow.parent.controller_owner,
                ),
            )
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                "SELECT longspan_open_mutation_scope(%s, %s, %s)",
                ("run-scope-fences", epoch, controller_fence),
            )
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                "SELECT longspan_open_controller_mutation_scope(%s, %s, %s, %s)",
                (
                    "run-scope-fences",
                    epoch,
                    controller_fence,
                    "forged-controller-owner",
                ),
            )
    workflow.close()


def test_general_controller_scope_rejects_raw_task_mutation(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-controller-scope")
    workflow.parent.schedule_task("run-controller-scope", "task-controller-scope", "scope")
    claimed = workflow.parent.claim_next("run-controller-scope", "worker")
    assert claimed is not None
    epoch = workflow.parent.controller_epoch("run-controller-scope")
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                """
                SELECT controller_fence_token
                FROM controller_control
                WHERE run_id = %s
                """,
                ("run-controller-scope",),
            )
            controller_fence = int(cur.fetchone()["controller_fence_token"])
            cur.execute(
                "SELECT longspan_open_controller_mutation_scope(%s, %s, %s, %s, %s)",
                (
                    "run-controller-scope",
                    epoch,
                    controller_fence,
                    workflow.parent.controller_owner,
                    "general",
                ),
            )
            cur.execute("SELECT set_config('top_delivery.disposable_test_mutation', '0', true)")
            cur.execute(
                "UPDATE parent_tasks SET objective = 'forged' WHERE task_id = %s",
                (claimed.task_id,),
            )
    # A caller-settable GUC is not an authorization witness.  It must not
    # bypass the trigger when no database-generated signed scope exists.
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                "SELECT set_config('top_delivery.disposable_test_mutation', '0', true)"
            )
            cur.execute(
                "SELECT set_config('top_delivery.controller_routine', '1', true)"
            )
            cur.execute(
                "UPDATE parent_tasks SET objective = 'forged-guc' WHERE task_id = %s",
                (claimed.task_id,),
            )
    workflow.close()


def test_general_controller_scope_rejects_parent_task_insert(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-controller-insert-scope")
    epoch = workflow.parent.controller_epoch("run-controller-insert-scope")
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                """
                SELECT controller_fence_token
                FROM controller_control
                WHERE run_id = %s
                """,
                ("run-controller-insert-scope",),
            )
            controller_fence = int(cur.fetchone()["controller_fence_token"])
            cur.execute(
                "SELECT longspan_open_controller_mutation_scope(%s, %s, %s, %s, %s)",
                (
                    "run-controller-insert-scope",
                    epoch,
                    controller_fence,
                    workflow.parent.controller_owner,
                    "general",
                ),
            )
            cur.execute("SELECT set_config('top_delivery.disposable_test_mutation', '0', true)")
            cur.execute(
                """
                INSERT INTO parent_tasks
                    (task_id, run_id, objective, state, priority, available_at, attempt, updated_at)
                VALUES (%s, %s, %s, 'queued', 0, clock_timestamp(), 0, clock_timestamp())
                """,
                (
                    "task-controller-insert-scope",
                    "run-controller-insert-scope",
                    "forged insert",
                ),
            )
    workflow.close()


def test_schedule_goal_task_routine_inserts_queued_parent_task(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-schedule-goal-task")
    epoch = workflow.parent.controller_epoch("run-schedule-goal-task")
    payload = None
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            """
            SELECT controller_fence_token
            FROM controller_control
            WHERE run_id = %s
            """,
            ("run-schedule-goal-task",),
        )
        controller_fence = int(cur.fetchone()["controller_fence_token"])
        cur.execute(
            """
            SELECT longspan_schedule_goal_task(
                %s, %s, %s, %s, %s, %s, %s, %s
            ) AS result
            """,
            (
                "run-schedule-goal-task",
                "task-schedule-goal-task",
                "goal objective",
                3,
                None,
                epoch,
                workflow.parent.controller_owner,
                controller_fence,
            ),
        )
        payload = cur.fetchone()["result"]
        cur.execute(
            """
            SELECT task_id, run_id, objective, state, priority, attempt
            FROM parent_tasks
            WHERE task_id = %s
            """,
            ("task-schedule-goal-task",),
        )
        row = cur.fetchone()
    assert row is not None
    assert row["task_id"] == "task-schedule-goal-task"
    assert row["run_id"] == "run-schedule-goal-task"
    assert row["objective"] == "goal objective"
    assert row["state"] == "queued"
    assert int(row["attempt"]) == 0
    assert int(row["priority"]) == 3
    assert payload["created"] is True
    assert payload["state"] == "queued"
    workflow.close()


def test_workflow_cannot_open_controller_maintenance_scope(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-maintenance-scope")
    epoch = workflow.parent.controller_epoch("run-maintenance-scope")
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_open_controller_mutation_scope(
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    "run-maintenance-scope",
                    epoch,
                    1,
                    workflow.parent.controller_owner,
                    "park_children",
                ),
            )
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_open_controller_mutation_scope(
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    "run-maintenance-scope",
                    epoch,
                    1,
                    workflow.parent.controller_owner,
                    "expire_stale_children",
                ),
            )
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                "SELECT longspan_park_children(%s, %s, %s, %s)",
                ("run-maintenance-scope", epoch, "forged-owner", 1),
            )
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                "SELECT longspan_expire_stale_children(%s, %s, %s, %s)",
                ("run-maintenance-scope", epoch, workflow.parent.controller_owner, 999999),
            )
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            "SELECT longspan_current_controller_fence(%s, %s, %s)",
            ("run-maintenance-scope", epoch, workflow.parent.controller_owner),
        )
        current_fence = int(next(iter(cur.fetchone().values())))
        cur.execute(
            "SELECT longspan_park_children(%s, %s, %s, %s)",
            (
                "run-maintenance-scope",
                epoch,
                workflow.parent.controller_owner,
                current_fence,
            ),
        )
        assert int(next(iter(cur.fetchone().values()))) == 0
        cur.execute(
            "SELECT current_setting('top_delivery.mutation_scope_payload', true) AS payload, "
            "current_setting('top_delivery.mutation_scope_signature', true) AS signature"
        )
        scope_state = cur.fetchone()
        assert scope_state["payload"] == ""
        assert scope_state["signature"] == ""
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            "SELECT to_regprocedure(%s)",
            ("public.longspan_open_controller_mutation_scope(text,integer,bigint,text)",),
        )
        row = cur.fetchone()
        assert next(iter(row.values())) is None
        cur.execute(
            "SELECT to_regprocedure(%s) AS park_routine, to_regprocedure(%s) AS expire_routine",
            (
                "public.longspan_park_children(text,integer,text,bigint)",
                "public.longspan_expire_stale_children(text,integer,text,bigint)",
            ),
        )
        routines = cur.fetchone()
        assert routines["park_routine"] is not None
        assert routines["expire_routine"] is not None
    workflow.close()


def test_old_maintenance_request_fails_after_same_owner_fence_turnover(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    run_id = "run-maintenance-fence-turnover"
    workflow.parent.register_run(run_id)
    owner = workflow.parent.controller_owner
    old_epoch = workflow.parent.controller_epoch(run_id)
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            "SELECT longspan_current_controller_fence(%s, %s, %s)",
            (run_id, old_epoch, owner),
        )
        old_fence = int(next(iter(cur.fetchone().values())))
        cur.execute("SELECT longspan_test_expire_controller_lease(%s)", (run_id,))
    new_epoch = workflow.parent._repo.acquire_controller(
        run_id,
        owner,
        lease_seconds=workflow.parent.controller_lease_seconds,
        expected_epoch=old_epoch,
    )
    assert new_epoch == old_epoch + 1
    with pytest.raises(psycopg2.Error):
        with workflow.repo.repo.transaction() as cur:
            cur.execute(
                "SELECT longspan_park_children(%s, %s, %s, %s)",
                (run_id, old_epoch, owner, old_fence),
            )
    workflow.close()


def test_workflow_cannot_bind_write_credential(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    with pytest.raises(AuthorizationFailureError, match="cannot bind authority write credentials"):
        workflow.repo.bind_operator_write_credential(
            approval_id="approval-x",
            write_binding_digest="digest",
            write_credential_digest="cred",
        )
    workflow.close()


def test_workflow_cannot_spoof_authority_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COMMS01_AUTHORITY_SOCKET", "unix:///tmp/spoofed.sock")
    with pytest.raises(AuthorizationFailureError, match="must not access authority secret env"):
        from authority_write_gate import assert_workflow_cannot_access_authority_secrets

        assert_workflow_cannot_access_authority_secrets()


def test_workflow_cannot_issue_write_credentials_in_process() -> None:
    from authority_write_gate import assert_workflow_cannot_access_authority_secrets
    from authority_socket import AuthorityWriteCredential
    from longspan_repository import LongspanRepository

    assert_workflow_cannot_access_authority_secrets()
    credential = AuthorityWriteCredential(token="forged-token")
    assert credential.token
    with pytest.raises(AuthorizationFailureError, match="workflow/controller cannot write"):
        LongspanRepository.insert_authority_config(
            None,
            run_id="run-1",
            terra_auth_hash="x",
            operator_auth_hash="y",
            reviewed_sha="sha",
            tree_sha="tree",
            source_digest="source",
            controller_epoch=1,
            approval_receipt_digest="digest",
            approval_id="approval",
            operator_identity="operator@test",
            config_version=1,
            write_credential=credential,
            operator_challenge={},
        )


def test_workflow_cannot_insert_authority_without_credential(
    db_url: str, artifact_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    monkeypatch.delenv("COMMS01_AUTHORITY_WRITE_CREDENTIAL", raising=False)
    with pytest.raises(AuthorizationFailureError, match="workflow/controller cannot write"):
        workflow.repo.insert_authority_config(
            run_id="run-1",
            terra_auth_hash=hash_capability_token(TERRA_TOKEN),
            operator_auth_hash=hash_capability_token(OPERATOR_TOKEN),
            reviewed_sha=REVIEWED_SHA,
            tree_sha="tree",
            source_digest="source",
            controller_epoch=workflow.parent.controller_epoch("run-1"),
            approval_receipt_digest="digest",
            approval_id="approval-x",
            operator_identity="operator@test",
            config_version=1,
            write_credential=AuthorityWriteCredential(token=""),
            operator_challenge={
                "approval_id": "x",
                "run_id": "run-1",
                "action_type": "initial_provision",
                "action_digest": "digest",
                "operator_identity": "operator@test",
                "nonce": "n",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "key_version": 1,
                "controller_epoch": workflow.parent.controller_epoch("run-1"),
                "config_version": 1,
                "challenge_digest": "cd",
                "write_credential": AuthorityWriteCredential(token=""),
            },
        )
    workflow.close()


def test_evidence_mutation_after_dispatch_does_not_change_audit(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.record_evidence(
        "run-1", "evidence/a01.json", producer="test", result="pass"
    )
    workflow.parent.schedule_task("run-1", "task-1", "evidence tamper")
    mutated: list[dict[str, object]] = []

    class MutatingHandler:
        def __call__(self, context):
            evidence = list(context.verified_evidence)
            if evidence:
                evidence[0]["ok"] = False
                mutated.append(evidence[0])
            return default_task_handler(context)

    _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "tamper"}),
        task_handler=MutatingHandler(),
    )
    frozen = tuple(workflow.parent.evidence("run-1"))
    expected_digest = canonical_evidence_digest(frozen)
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            """
                SELECT ea.request_digest, ea.evidence_digest, ea.result_digest,
                       c.request_digest AS child_request_digest,
                       c.child_id, c.attempt_number
            FROM longspan_execution_audits ea
            JOIN longspan_children c ON c.child_id = ea.child_id
            WHERE c.task_id = 'task-1'
            """
        )
        row = cur.fetchone()
    assert row is not None
    assert mutated
    assert row["request_digest"] == row["child_request_digest"]
    assert row["evidence_digest"] == expected_digest
    assert '"ok": false' not in row["request_digest"]
    result = workflow.repo.get_execution_result(row["child_id"], int(row["attempt_number"]))
    assert row["result_digest"] == result["result_digest"]
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            """
                SELECT evidence_json, evidence_digest
                FROM longspan_execution_evidence
                WHERE child_id = %s AND attempt_number = %s
            """,
            (row["child_id"], int(row["attempt_number"])),
        )
        evidence_row = cur.fetchone()
    assert evidence_row is not None
    persisted_evidence = tuple(json.loads(evidence_row["evidence_json"])["evidence"])
    assert "ok" not in persisted_evidence[0]
    assert evidence_row["evidence_digest"] == canonical_evidence_digest(persisted_evidence)
    workflow.close()


def test_terra_final_failure_retires_issued_attestation(
    db_url: str,
    artifact_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any post-issuance finalization error retires the out-of-band witness."""
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-attestation-retire")
    _seed_ready_parent(workflow.parent, "run-attestation-retire", artifact_root)
    _provision_authority(workflow, "run-attestation-retire")
    workflow.parent.schedule_task(
        "run-attestation-retire", "task-attestation-retire", "retire witness"
    )
    import longspan_repository as repository_module

    issued: list[str] = []
    original_issue = repository_module.request_terra_receipt_attestation

    def capture_issue(**kwargs):
        result = original_issue(**kwargs)
        issued.append(result[0])
        return result

    monkeypatch.setattr(
        repository_module, "request_terra_receipt_attestation", capture_issue
    )

    original_transition = workflow.repo._transition_child

    def fail_transition(*args, **kwargs):
        if kwargs.get("new_state") == "terra_approved":
            raise PermissionError("injected final transition failure")
        return original_transition(*args, **kwargs)

    monkeypatch.setattr(workflow.repo, "_transition_child", fail_transition)
    with pytest.raises(Exception):
        _run_cycle(
            workflow,
            "run-attestation-retire",
            request_digest=digest_payload({"task": "attestation-retire"}),
        )
    assert issued
    from authority_repository import AuthorityRepository
    from test_authority_helpers import _authority_url_for_database

    authority_repo = AuthorityRepository.from_url(_authority_url_for_database(db_url))
    try:
        with pytest.raises(psycopg2.Error, match="attestation"):
            authority_repo.get_terra_receipt_gateway_mac(issued[0])
    finally:
        authority_repo.close()
        workflow.close()


def test_terra_rejected_resume_bumps_attempt(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "terra retry")
    _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "terra-retry"}),
        terra_decision="rejected",
    )
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            "SELECT state, attempt_number FROM longspan_children WHERE task_id = %s",
            ("task-1",),
        )
        child = cur.fetchone()
    assert child is not None
    assert child["state"] == "ready"
    assert int(child["attempt_number"]) == 1
    workflow.close()


def test_capture_run_provenance_requires_reviewed_sha(tmp_path: Path) -> None:
    with pytest.raises(ProvenanceMismatchError):
        capture_run_provenance(REPO_ROOT, reviewed_sha="0" * 40)


def test_legacy_partial_authority_blocks_007_upgrade() -> None:
    name, url = _create_test_database(f"td_downgrade_legacy_auth_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "005_longspan_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO supervisor_runs (run_id, state) VALUES ('legacy-run', 'active')"
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS longspan_authority_config (
                        run_id TEXT PRIMARY KEY REFERENCES supervisor_runs(run_id)
                    )
                    """
                )
                cur.execute(
                    "INSERT INTO longspan_authority_config (run_id) VALUES ('legacy-run')"
                )
                conn.commit()
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "upgrade", "007_longspan_authority_hardening")
    finally:
        _drop_test_database(name)


def test_unbound_terra_receipt_blocks_007_upgrade() -> None:
    name, url = _create_test_database(f"td_downgrade_unbound_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "005_longspan_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO supervisor_runs (run_id, state) VALUES ('run-r', 'active')"
                )
                cur.execute(
                    """
                    INSERT INTO parent_tasks (task_id, run_id, objective, state)
                    VALUES ('task-r', 'run-r', 'receipt', 'queued')
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_children
                        (child_id, task_id, run_id, parent_attempt_id, fence_token, state,
                         idempotency_key, request_digest, attempt_number, version)
                    VALUES ('child-r', 'task-r', 'run-r', 'attempt-r', 1, 'terra_pending',
                            'idem-r', 'digest-r', 0, 0)
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_terra_receipts
                        (receipt_id, child_id, attempt_number, reviewer, decision,
                         evidence_chain_head, receipt_digest)
                    VALUES ('receipt-r', 'child-r', 0, 'terra', 'approved', 'head', 'digest')
                    """
                )
                conn.commit()
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "upgrade", "007_longspan_authority_hardening")
    finally:
        _drop_test_database(name)


def test_challenge_replay_not_consumed_on_failed_authority_write(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    boundary, captured, controller_epoch, receipt = _authority_provision_attempt(
        workflow, "run-1"
    )
    boundary.initial_provision(
        run_id="run-1",
        terra_auth_token=TERRA_TOKEN,
        operator_auth_token=OPERATOR_TOKEN,
        reviewed_sha=REVIEWED_SHA,
        tree_sha=captured.tree_sha,
        source_digest=captured.source_digest,
        controller_epoch=controller_epoch,
        operator_identity="operator@test",
        operator_approval_receipt=receipt,
    )
    with pytest.raises(AuthorizationFailureError):
        boundary.initial_provision(
            run_id="run-1",
            terra_auth_token=TERRA_TOKEN,
            operator_auth_token=OPERATOR_TOKEN,
            reviewed_sha=REVIEWED_SHA,
            tree_sha=captured.tree_sha,
            source_digest=captured.source_digest,
            controller_epoch=controller_epoch,
            operator_identity="operator@test",
            operator_approval_receipt=receipt,
        )
    workflow.close()


def test_forged_operator_receipt_rejected(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    boundary, captured, controller_epoch, receipt = _authority_provision_attempt(
        workflow, "run-1"
    )
    forged = ExternalOperatorApprovalReceipt(
        approval_id=receipt.approval_id,
        operator_identity="other-operator",
        nonce=receipt.nonce,
        expires_at=receipt.expires_at,
        action_type=receipt.action_type,
        action_digest=receipt.action_digest,
        run_id=receipt.run_id,
        key_version=receipt.key_version,
        controller_epoch=receipt.controller_epoch,
        config_version=receipt.config_version,
        signature=receipt.signature,
    )
    with pytest.raises(AuthorizationFailureError, match="identity mismatch"):
        boundary.initial_provision(
            run_id="run-1",
            terra_auth_token=TERRA_TOKEN,
            operator_auth_token=OPERATOR_TOKEN,
            reviewed_sha=REVIEWED_SHA,
            tree_sha=captured.tree_sha,
            source_digest=captured.source_digest,
            controller_epoch=controller_epoch,
            operator_identity="operator@test",
            operator_approval_receipt=forged,
        )
    workflow.close()


def test_provenance_drift_rejected() -> None:
    captured = RunProvenanceTuple(
        reviewed_sha=REVIEWED_SHA,
        candidate_sha=REVIEWED_SHA,
        tree_sha="tree",
        source_digest="source",
        migration_head=CANONICAL_ALEMBIC_HEAD,
        migration_revision=CANONICAL_ALEMBIC_HEAD,
    )
    with pytest.raises(AuthorizationFailureError, match="tree_sha drift"):
        reject_provenance_drift(captured=captured, tree_sha="forged-tree")


def test_pre_authority_ledger_append_blocked(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    workflow.parent.schedule_task("run-1", "task-1", "pre-auth")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, _capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "pre-auth"}),
    )
    with pytest.raises(IntegrityFailureError):
        workflow.repo.append_ledger_entry(
            child_id=child["child_id"],
            attempt_number=0,
            event_type="seed",
            producer_role="parent",
            payload_digest=digest_payload({"seed": True}),
            controller_epoch=workflow.parent.controller_epoch("run-1"),
            run_id="run-1",
            fence_token=fence,
        )
    workflow.close()


def test_parent_ledger_uses_only_fenced_recovery_events(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    with pytest.raises(IntegrityFailureError, match="recovery contract"):
        workflow.repo.append_parent_ledger_entry(
            child_id="child-not-created",
            attempt_number=0,
            event_type="seed",
            payload_digest=digest_payload({"seed": True}),
            controller_epoch=1,
            run_id="run-1",
            parent_attempt_id="attempt-1",
            fence_token=1,
        )
    workflow.close()


def test_generic_child_transition_cannot_authorize_completion(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    with pytest.raises(AuthorizationFailureError, match="generic child state transitions"):
        workflow.repo.transition_child_state(
            child_id="child-not-created",
            expected_version=0,
            new_state="verified",
            controller_epoch=1,
            run_id="run-1",
            parent_attempt_id="attempt-1",
            fence_token=1,
            clear_capabilities=False,
        )
    workflow.close()


def test_stale_fence_raises_typed_error(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "stale fence")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "stale-fence"}),
    )
    with pytest.raises(StaleFenceError):
        workflow.manager.create_plan(
            child=child,
            capabilities=capabilities,
            parent_task=claimed,
            parent_attempt_id=attempt_id,
            fence_token=fence + 1,
            producer=default_plan_producer,
            controller_epoch=workflow.parent.controller_epoch("run-1"),
        )
    workflow.close()


def test_disposable_database_requires_signed_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "disposable_capability.load_signed_disposable_capability",
        lambda: None,
    )
    with pytest.raises(AuthorizationFailureError, match="signed disposable capability"):
        create_disposable_database(ADMIN_URL, f"td_test_{uuid.uuid4().hex}")


def test_disposable_capability_rejects_forged_and_private_as_public_signatures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from disposable_capability import (
        SignedDisposableCapability,
        build_capability_file_payload,
        verify_disposable_capability_signature,
    )
    from operator_asymmetric import generate_keypair

    body = {
        "operation": "migration_downgrade",
        "database_name": "td_test_capability_negative",
        "database_role": "postgres",
        "controller_service": "top-delivery-controller",
        "nonce": f"negative-{uuid.uuid4().hex}",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "migration_revision": "007_longspan_authority_hardening",
    }
    forged_signing_key, _forged_verify_key = generate_keypair()
    forged_payload = build_capability_file_payload(
        **body,
        signing_key=forged_signing_key,
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    forged = SignedDisposableCapability(**forged_payload)
    with pytest.raises(AuthorizationFailureError, match="signature is invalid"):
        verify_disposable_capability_signature(forged)

    legacy_payload = {
        **body,
        "database_endpoint": "127.0.0.1",
        "database_port": 5432,
        "signature": sign_payload(digest_payload(body), TEST_SIGNING_KEY),
    }
    legacy = SignedDisposableCapability(**legacy_payload)
    with pytest.raises(AuthorizationFailureError, match="signature is invalid"):
        verify_disposable_capability_signature(legacy)

    pinned_payload = build_capability_file_payload(
        **body,
        signing_key=TEST_SIGNING_KEY,
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    pinned = SignedDisposableCapability(**pinned_payload)
    import disposable_capability
    import pinned_trust

    verifier_path = tmp_path / "verifier.pub"
    verifier_path.write_text(TEST_SIGNING_KEY + "\n", encoding="ascii")
    verifier_path.chmod(0o600)
    monkeypatch.setattr(
        disposable_capability,
        "DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH",
        str(verifier_path),
    )
    monkeypatch.setattr(
        pinned_trust,
        "DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH",
        str(verifier_path),
    )
    with pytest.raises(AuthorizationFailureError, match="signature is invalid"):
        verify_disposable_capability_signature(pinned)


def test_disposable_capability_verifier_rejects_malformed_or_nonroot_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import disposable_capability
    import pinned_trust

    verifier_path = tmp_path / "verifier.pub"
    verifier_path.write_bytes(b"\xff\n")
    verifier_path.chmod(0o600)
    monkeypatch.setattr(
        disposable_capability,
        "DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH",
        str(verifier_path),
    )
    monkeypatch.setattr(
        pinned_trust,
        "DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH",
        str(verifier_path),
    )
    with pytest.raises(AuthorizationFailureError, match="valid ASCII"):
        disposable_capability._load_verification_key()

    verifier_path.write_text("AQ==\n", encoding="ascii")
    with pytest.raises(AuthorizationFailureError, match="Ed25519 public key"):
        disposable_capability._load_verification_key()

    verifier_path.write_text("\n", encoding="ascii")
    with pytest.raises(AuthorizationFailureError, match="verifier key is empty"):
        disposable_capability._load_verification_key()

    os.chown(verifier_path, AUTHORITY_SERVICE_UID, 0)
    verifier_path.write_text(TEST_VERIFY_KEY + "\n", encoding="ascii")
    verifier_path.chmod(0o600)
    with pytest.raises(ScopeBoundaryViolationError, match="root-owned"):
        disposable_capability._load_verification_key()


def test_disposable_nonce_store_is_pinned_and_malformed_state_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import disposable_capability

    nonce_path = tmp_path / "consumed-nonces.json"
    target = tmp_path / "nonce-target"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    nonce_path.symlink_to(target)
    monkeypatch.setattr(disposable_capability, "CONSUMED_NONCE_PATH", str(nonce_path))
    with pytest.raises(AuthorizationFailureError, match="safely openable"):
        disposable_capability._consume_nonce(
            "nonce-symlink", (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        )

    nonce_path.unlink()
    nonce_path.write_text("not-json\n", encoding="utf-8")
    nonce_path.chmod(0o600)
    with pytest.raises(AuthorizationFailureError, match="nonce store is malformed"):
        disposable_capability._consume_nonce(
            "nonce-malformed", (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        )


def test_disposable_nonce_store_never_evicts_unexpired_replay_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import disposable_capability

    nonce_path = tmp_path / "consumed-nonces.json"
    future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    nonce_path.write_text(
        json.dumps(
            {
                "old-live": {"consumed_at": datetime.now(timezone.utc).isoformat(), "expires_at": future},
                "new-live": {"consumed_at": datetime.now(timezone.utc).isoformat(), "expires_at": future},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    nonce_path.chmod(0o600)
    monkeypatch.setattr(disposable_capability, "CONSUMED_NONCE_PATH", str(nonce_path))
    monkeypatch.setattr(disposable_capability, "MAX_CONSUMED_NONCES", 2)

    with pytest.raises(AuthorizationFailureError, match="full of unexpired"):
        disposable_capability._consume_nonce("third-live", future)
    with pytest.raises(AuthorizationFailureError, match="already consumed"):
        disposable_capability._consume_nonce("old-live", future)


def test_downgrade_capability_requires_exact_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import disposable_capability

    monkeypatch.setattr(
        disposable_capability,
        "load_signed_disposable_capability",
        lambda: disposable_capability.SignedDisposableCapability(
            operation="migration_downgrade",
            database_name="td_test_revision",
            database_role="top_delivery_migration",
            controller_service="top-delivery-comms01",
            nonce="revision-nonce",
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            migration_revision=None,
            signature="test",
            database_endpoint="127.0.0.1",
            database_port=5432,
        ),
    )
    with pytest.raises(AuthorizationFailureError, match="migration revision mismatch"):
        disposable_capability.require_disposable_capability(
            operation="migration_downgrade",
            migration_revision="006_longspan_authority",
        )


def test_capability_file_rejects_wrong_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import disposable_capability

    capability_path = tmp_path / "capability.json"
    capability_path.write_text("{}\n", encoding="utf-8")
    capability_path.chmod(0o600)
    os.chown(capability_path, 65534, 0)
    monkeypatch.setattr(
        disposable_capability, "DISPOSABLE_HARNESS_CAPABILITY_PATH", str(capability_path)
    )
    with pytest.raises(AuthorizationFailureError, match="trusted owner/path"):
        disposable_capability.read_capability_json_file(str(capability_path))


def test_public_verifier_read_exception_is_path_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import pinned_trust

    other_path = tmp_path / "other-public-key"
    other_path.write_text(TEST_VERIFY_KEY + "\n", encoding="ascii")
    other_path.chmod(0o600)
    with pytest.raises(ScopeBoundaryViolationError, match="only for the pinned"):
        pinned_trust.verify_pinned_file_trust(
            str(other_path), allow_public_key_read=True
        )


def test_restore_clearance_conflict_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    fence_path = str(root / "target.fence")
    entrypoints._write_restore_fence_clearance(
        fence_path=fence_path,
        approval_id="approval-conflict",
        snapshot_digest="a" * 64,
    )
    clearance = next(root.glob("target.fence.cleared-*"))
    clearance.write_text(
        "partial_restore_fence_clearance\n"
        "approval_id_sha256=" + hashlib.sha256(b"approval-conflict").hexdigest() + "\n"
        "snapshot_digest=" + "b" * 64 + "\n"
        "cleared_at=1.0\n",
        encoding="utf-8",
    )
    clearance.chmod(0o600)
    with pytest.raises(ScopeBoundaryViolationError, match="does not match"):
        entrypoints._write_restore_fence_clearance(
            fence_path=fence_path,
            approval_id="approval-conflict",
            snapshot_digest="a" * 64,
        )


def test_restore_clearance_records_are_bounded_under_rotation_mutex(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import comms01_operation_entrypoints as entrypoints

    root = tmp_path / "fences"
    root.mkdir()
    root.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PINNED_RESTORE_FENCE_ROOT", str(root))
    fence_path = str(root / "target.fence")
    for index in range(entrypoints.MAX_RESTORE_CLEARANCE_RECORDS + 8):
        entrypoints._write_restore_fence_clearance(
            fence_path=fence_path,
            approval_id=f"approval-{index}",
            snapshot_digest=f"{index:064x}",
        )
    records = list(root.glob("target.fence.cleared-*"))
    assert len(records) == entrypoints.MAX_RESTORE_CLEARANCE_RECORDS
    assert (root / ".restore-failure-rotation.lock").is_file()


def test_migration_007_upgrade_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    name, url = _create_test_database(f"td_downgrade_007_idem_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "004_longspan_workflow")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO supervisor_runs (run_id, state) VALUES ('run-idem', 'active')
                    """
                )
                cur.execute(
                    """
                    INSERT INTO parent_tasks (task_id, run_id, objective, state)
                    VALUES ('task-idem', 'run-idem', 'idem', 'queued')
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_children
                        (child_id, task_id, run_id, parent_attempt_id, fence_token, state,
                         idempotency_key, request_digest, attempt_number, version,
                         lease_token_hash)
                    VALUES ('child-idem', 'task-idem', 'run-idem', 'attempt-idem', 1, 'ready',
                            'idem-idem', 'digest-idem', 0, 0, 'lease-hash')
                    """
                )
                conn.commit()
        alembic_command(url, "upgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT attempt_number, state FROM longspan_children WHERE child_id = 'child-idem'"
                )
                first = cur.fetchone()
                cur.execute(
                    "SELECT 1 FROM pg_proc WHERE proname = 'longspan_append_evidence_ledger'"
                )
                assert cur.fetchone() is not None
        alembic_command(url, "upgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT attempt_number, state FROM longspan_children WHERE child_id = 'child-idem'"
                )
                second = cur.fetchone()
                cur.execute("SELECT version_num FROM alembic_version")
                assert cur.fetchone()[0] == "007_longspan_authority_hardening"
        assert first == second

        # Simulate a partially rehearsed database carrying the historical
        # VOID-returning terra routine while Alembic still reports 006. The
        # 007 upgrade must replace that signature safely.
        terra_signature = """
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        """
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"DROP FUNCTION IF EXISTS longspan_append_terra_receipt({terra_signature})"
                )
                cur.execute(
                    f"""
                    CREATE FUNCTION longspan_append_terra_receipt({terra_signature})
                    RETURNS VOID AS $$ BEGIN RETURN; END; $$ LANGUAGE plpgsql
                    """
                )
                # Legacy objects are transferred to the dedicated
                # migration principal by the out-of-band database
                # bootstrap before a restricted Alembic run.  The
                # migration must not regain superuser/CREATEROLE power
                # merely to repair an object owned by the transport role.
                cur.execute(
                    f"ALTER FUNCTION longspan_append_terra_receipt({terra_signature}) "
                    "OWNER TO top_delivery_migration"
                )
                cur.execute(
                    "UPDATE alembic_version SET version_num = '006_longspan_authority'"
                )
            conn.commit()
        alembic_command(url, "upgrade", "007_longspan_authority_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT pg_get_function_result(p.oid)
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public'
                      AND p.proname = 'longspan_append_terra_receipt'
                    """
                )
                assert cur.fetchone()[0] == "text"
                cur.execute(
                    "SELECT to_regprocedure(%s), to_regprocedure(%s)",
                    (
                        "public.longspan_append_execution_audit(text,text,integer,text,text,text,text,text)",
                        "public.longspan_append_auditor_receipt(text,text,integer,text,text,text,text,text)",
                    ),
                )
                assert cur.fetchone() == (None, None)
                cur.execute(
                    "SELECT to_regprocedure(%s), to_regprocedure(%s)",
                    (
                        "public.longspan_append_execution_audit(text,text,integer,text,text,text,text,text)",
                        "public.longspan_append_auditor_receipt(text,text,integer,text,text,text,text,text)",
                    ),
                )
                assert cur.fetchone() == (None, None)
    finally:
        _drop_test_database(name)


def test_socket_request_ttl_and_replay_capacity_are_fail_closed() -> None:
    server = object.__new__(AuthorityServiceServer)
    server._seen_socket_requests = {}
    server._socket_request_owners = {}
    server._socket_peer_counts = {}
    server._socket_request_lock = threading.Lock()

    ttl_payload = build_socket_request_envelope()
    ttl_payload["socket_expires_at"] = (
        datetime.now(timezone.utc)
        + timedelta(seconds=SOCKET_REQUEST_TTL_SECONDS + 10)
    ).isoformat()
    with pytest.raises(AuthorizationFailureError, match="TTL exceeds"):
        server._consume_socket_request(ttl_payload, peer_identity=(1000, 1000))

    malformed_payload = build_socket_request_envelope()
    malformed_payload["socket_expires_at"] = "not-a-timestamp"
    with pytest.raises(AuthorizationFailureError, match="expiry is malformed"):
        server._consume_socket_request(malformed_payload, peer_identity=(1000, 1000))

    expired_payload = build_socket_request_envelope()
    expired_payload["socket_expires_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()
    with pytest.raises(AuthorizationFailureError, match="request expired"):
        server._consume_socket_request(expired_payload, peer_identity=(1000, 1000))

    now = datetime.now(timezone.utc)
    server._seen_socket_requests = {
        f"seen-{index}": now + timedelta(seconds=30)
        for index in range(server.SOCKET_REPLAY_CACHE_MAX)
    }
    with pytest.raises(AuthorizationFailureError, match="cache is full"):
        server._consume_socket_request(
            build_socket_request_envelope(), peer_identity=(1000, 1000)
        )


def test_socket_request_expiry_is_sampled_after_replay_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import authority_service_server as authority_server_module

    server = object.__new__(AuthorityServiceServer)
    server._seen_socket_requests = {}
    server._socket_request_owners = {}
    server._socket_peer_counts = {}

    class TrackingLock:
        entered = False

        def __enter__(self):
            self.entered = True
            return self

        def __exit__(self, *_args):
            return False

    lock = TrackingLock()
    server._socket_request_lock = lock
    real_datetime = authority_server_module.datetime
    expires_at = real_datetime.now(timezone.utc) + timedelta(seconds=30)
    payload = build_socket_request_envelope()
    payload["socket_expires_at"] = expires_at.isoformat()

    class ExpiredAfterLock:
        @classmethod
        def fromisoformat(cls, value: str):
            return real_datetime.fromisoformat(value)

        @classmethod
        def now(cls, tz):
            assert lock.entered
            return expires_at + timedelta(seconds=1)

    monkeypatch.setattr(authority_server_module, "datetime", ExpiredAfterLock)
    with pytest.raises(AuthorizationFailureError, match="request expired"):
        server._consume_socket_request(payload, peer_identity=(1000, 1000))
    assert payload["socket_request_id"] not in server._seen_socket_requests


def test_authority_server_bounds_partial_peer_before_serving_next_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial approved peer cannot hold the single accept loop forever."""
    import authority_service_server as authority_server_module

    class FakeConnection:
        def __init__(self, label: str) -> None:
            self.label = label
            self.timeouts: list[float] = []

        def __enter__(self) -> "FakeConnection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

    first = FakeConnection("partial")
    second = FakeConnection("next")

    class FakeListener:
        def __init__(self) -> None:
            self._connections = iter((first, second))

        def accept(self):
            try:
                return next(self._connections), None
            except StopIteration as exc:
                raise OSError("listener closed") from exc

    received = iter((socket.timeout("partial frame"), b"{}"))
    sent: list[bytes] = []
    monkeypatch.setattr(authority_server_module, "verify_authority_client_peer", lambda _conn: None)
    monkeypatch.setattr(authority_server_module, "peer_credentials", lambda _conn: (1, 1000, 1000))
    monkeypatch.setattr(
        authority_server_module,
        "recv_framed",
        lambda _conn, *, deadline=None: _next_frame(received),
    )
    monkeypatch.setattr(
        authority_server_module,
        "bind_socket_response",
        lambda request, response: response,
    )
    def fake_send(conn, payload, *, deadline=None):
        assert deadline is not None
        if conn is first:
            raise OSError("peer closed during response")
        sent.append(payload)

    monkeypatch.setattr(authority_server_module, "send_framed", fake_send)

    server = object.__new__(AuthorityServiceServer)
    server._consume_socket_request = lambda payload, *, peer_identity=None: payload
    server._handle = lambda _payload: {"status": "ok"}
    server._serve(FakeListener())

    assert first.timeouts == [authority_server_module.AUTHORITY_SOCKET_TIMEOUT_SECONDS]
    assert second.timeouts == [authority_server_module.AUTHORITY_SOCKET_TIMEOUT_SECONDS]
    assert len(sent) == 1


def test_authority_server_bounds_oversized_error_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A huge handler error is reduced without killing the accept loop."""
    import authority_service_server as authority_server_module

    class FakeConnection:
        def __init__(self) -> None:
            self.timeouts: list[float] = []

        def __enter__(self) -> "FakeConnection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, value: float) -> None:
            self.timeouts.append(value)

    connection = FakeConnection()

    class FakeListener:
        used = False

        def accept(self):
            if not self.used:
                self.used = True
                return connection, None
            raise OSError("listener closed")

    monkeypatch.setattr(authority_server_module, "verify_authority_client_peer", lambda _conn: None)
    monkeypatch.setattr(
        authority_server_module,
        "peer_credentials",
        lambda _conn: (1, 1000, 1000),
    )
    monkeypatch.setattr(
        authority_server_module,
        "recv_framed",
        lambda _conn, *, deadline=None: b"{}",
    )
    monkeypatch.setattr(
        authority_server_module,
        "bind_socket_response",
        lambda request, response: response,
    )
    sent: list[bytes] = []
    monkeypatch.setattr(
        authority_server_module,
        "send_framed",
        lambda _conn, payload, *, deadline=None: sent.append(payload),
    )
    server = object.__new__(AuthorityServiceServer)
    server._consume_socket_request = lambda payload, *, peer_identity=None: payload
    server._handle = lambda _payload: {"error": "x" * (authority_server_module.MAX_FRAME_BYTES * 2)}
    server._serve(FakeListener())
    assert connection.timeouts == [authority_server_module.AUTHORITY_SOCKET_TIMEOUT_SECONDS]
    assert len(sent) == 1
    assert len(sent[0]) <= authority_server_module.MAX_FRAME_BYTES


def _next_frame(values):
    value = next(values)
    if isinstance(value, BaseException):
        raise value
    return value


def test_authority_socket_framing_uses_absolute_deadline() -> None:
    import time

    from authority_socket_framing import recv_framed

    left, right = socket.socketpair()
    try:
        deadline = time.monotonic() + 0.08

        def drip_header() -> None:
            for value in b"\x00\x00\x00\x01":
                try:
                    time.sleep(0.04)
                    right.send(bytes((value,)))
                except OSError:
                    return

        sender = threading.Thread(target=drip_header)
        sender.start()
        started = time.monotonic()
        with pytest.raises(socket.timeout, match="deadline"):
            recv_framed(left, deadline=deadline)
        elapsed = time.monotonic() - started
        sender.join(timeout=1.0)
        assert elapsed < 0.3
    finally:
        left.close()
        right.close()


def test_socket_replay_quota_isolated_per_peer() -> None:
    server = object.__new__(AuthorityServiceServer)
    server._seen_socket_requests = {}
    server._socket_request_owners = {}
    server._socket_peer_counts = {}
    server._socket_request_lock = threading.Lock()
    peer_one = (101, 1001, 1001)
    peer_same_principal = (202, 1001, 1001)
    peer_two = (303, 1002, 1002)
    for _ in range(server.SOCKET_REPLAY_CACHE_MAX_PER_PEER):
        server._consume_socket_request(
            build_socket_request_envelope(), peer_identity=peer_same_principal
        )
    with pytest.raises(AuthorizationFailureError, match="quota is full for this peer"):
        server._consume_socket_request(
            build_socket_request_envelope(), peer_identity=peer_one
        )
    # A separate approved process is still able to issue a request; one noisy
    # peer cannot consume the whole global replay budget.
    server._consume_socket_request(
        build_socket_request_envelope(), peer_identity=peer_two
    )


def test_socket_replay_eviction_is_atomic_on_corrupt_owner() -> None:
    server = object.__new__(AuthorityServiceServer)
    server._seen_socket_requests = {
        "expired": datetime.now(timezone.utc) - timedelta(seconds=1)
    }
    server._socket_request_owners = {}
    server._socket_peer_counts = {}
    server._socket_request_lock = threading.Lock()
    with pytest.raises(AuthorizationFailureError, match="accounting is inconsistent"):
        server._consume_socket_request(
            build_socket_request_envelope(), peer_identity=(1000, 1000)
        )
    assert "expired" in server._seen_socket_requests


def test_socket_replay_eviction_rejects_insufficient_owner_quota_atomically() -> None:
    server = object.__new__(AuthorityServiceServer)
    expired_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    server._seen_socket_requests = {
        "expired-one": expired_at,
        "expired-two": expired_at,
    }
    server._socket_request_owners = {
        "expired-one": (1000, 1000),
        "expired-two": (1000, 1000),
    }
    server._socket_peer_counts = {(1000, 1000): 1}
    server._socket_request_lock = threading.Lock()
    with pytest.raises(AuthorizationFailureError, match="accounting is inconsistent"):
        server._consume_socket_request(
            build_socket_request_envelope(), peer_identity=(1000, 1000)
        )
    assert set(server._seen_socket_requests) == {"expired-one", "expired-two"}
    assert server._socket_request_owners == {
        "expired-one": (1000, 1000),
        "expired-two": (1000, 1000),
    }
    assert server._socket_peer_counts == {(1000, 1000): 1}

    server._seen_socket_requests = {
        "expired": datetime.now(timezone.utc) - timedelta(seconds=1)
    }
    server._socket_request_owners = {"expired": [1000, 1000]}
    server._socket_peer_counts = {}
    with pytest.raises(AuthorizationFailureError, match="accounting is inconsistent"):
        server._consume_socket_request(
            build_socket_request_envelope(), peer_identity=(1000, 1000)
        )
    assert server._socket_request_owners["expired"] == [1000, 1000]

    server._seen_socket_requests = {
        "expired": datetime.now(timezone.utc) - timedelta(seconds=1)
    }
    server._socket_request_owners = {"expired": (1000, 1000)}
    server._socket_peer_counts = {(1000, 1000): 0}
    with pytest.raises(AuthorizationFailureError, match="accounting is inconsistent"):
        server._consume_socket_request(
            build_socket_request_envelope(), peer_identity=(1000, 1000)
        )
    assert "expired" in server._seen_socket_requests


def test_006_downgrade_schema_equivalence_to_005(monkeypatch: pytest.MonkeyPatch) -> None:
    name, url = _create_test_database(f"td_downgrade_006_eq_{uuid.uuid4().hex}")
    install_downgrade_capability(database_name=name, migration_revision="005_longspan_hardening")
    try:
        alembic_command(url, "upgrade", "005_longspan_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                    ORDER BY table_name, ordinal_position
                    """
                )
                before = {row[0] for row in cur.fetchall()}
        alembic_command(url, "upgrade", "006_longspan_authority")
        alembic_command(url, "downgrade", "005_longspan_hardening")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                    ORDER BY table_name, ordinal_position
                    """
                )
                after = {row[0] for row in cur.fetchall()}
        assert before == after
        assert current_database_revision(url) == "005_longspan_hardening"
    finally:
        _drop_test_database(name)


def test_workflow_role_cannot_insert_authority_config(db_url: str) -> None:
    repository = PostgresRepository(db_url)
    repository.register_run("run-grant")
    repository.close()
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    """
                    INSERT INTO longspan_authority_config
                        (run_id, terra_auth_hash, operator_auth_hash, reviewed_sha,
                         tree_sha, source_digest, config_version, approval_receipt_digest)
                    VALUES ('run-grant', 'a', 'b', 'c', 'd', 'e', 1, 'f')
                    """
                )
                conn.commit()


def test_authority_role_can_read_receipt_witness_without_dml() -> None:
    """The authority witness lookup is read-only at the table ACL boundary."""
    name, url = _create_test_database(f"td_test_receipt_acl_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        from test_authority_helpers import _authority_url_for_database

        authority_url = _authority_url_for_database(url)
        with psycopg2.connect(authority_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT attestation_id FROM longspan_terra_receipt_attestations LIMIT 0"
                )
        with psycopg2.connect(authority_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT has_table_privilege(%s, %s, %s)",
                    (
                        AUTHORITY_DATABASE_ROLE,
                        "public.longspan_terra_receipt_attestations",
                        "SELECT",
                    ),
                )
                assert cur.fetchone()[0] is True
                for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                    cur.execute(
                        "SELECT has_table_privilege(%s, %s, %s)",
                        (
                            AUTHORITY_DATABASE_ROLE,
                            "public.longspan_terra_receipt_attestations",
                            privilege,
                        ),
                    )
                    assert cur.fetchone()[0] is False, privilege
                with pytest.raises(psycopg2.Error):
                    cur.execute(
                        "INSERT INTO longspan_terra_receipt_attestations (attestation_id) "
                        "VALUES ('authority-acl-negative')"
                    )
    finally:
        _drop_test_database(name)


def test_missing_authority_socket_parent_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Service absence is distinct from a tampered socket trust boundary."""
    import authority_service_client

    def missing_parent(_path: str):
        raise AuthorityServiceUnavailableError("authority socket parent directory is missing")

    monkeypatch.setattr(authority_service_client, "verify_authority_socket_path", missing_parent)
    with pytest.raises(AuthorityServiceUnavailableError):
        authority_service_client._request({"operation": "status"})


def test_wrong_authority_server_peer_is_not_retryable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A peer-auth failure remains authorization/integrity failure, not retry."""
    import authority_service_client

    socket_path = tmp_path / "authority.sock"
    socket_path.touch()

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, _path: str) -> None:
            return None

    monkeypatch.setattr(authority_service_client, "verify_authority_socket_path", lambda _path: socket_path)
    monkeypatch.setattr(authority_service_client.socket, "socket", lambda *_args: FakeSocket())
    monkeypatch.setattr(
        authority_service_client,
        "verify_authority_server_peer",
        lambda _sock: (_ for _ in ()).throw(
            AuthorizationFailureError("authority server peer UID is not authorized")
        ),
    )
    with pytest.raises(AuthorizationFailureError, match="peer UID"):
        authority_service_client._request({"operation": "status"})


def test_peer_credentials_separates_transport_and_peer_auth_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A closed socket is retryable; an unreadable peer identity is not."""
    import authority_service_client

    class FailingSocket:
        def __init__(self, error_number: int) -> None:
            self.error_number = error_number

        def getsockopt(self, *_args):
            raise OSError(self.error_number, "peer credential failure")

    with pytest.raises(AuthorityServiceUnavailableError):
        authority_service_client.peer_credentials(FailingSocket(errno.ENOTCONN))
    with pytest.raises(AuthorizationFailureError):
        authority_service_client.peer_credentials(FailingSocket(errno.EACCES))


def test_workflow_role_cannot_read_mac_material(db_url: str) -> None:
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    "SELECT material_id, mac_key FROM longspan_mac_material"
                )


def test_authority_mac_bootstrap_is_idempotent_and_rejects_rotation() -> None:
    name, url = _create_test_database(f"td_test_mac_bootstrap_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        from test_authority_helpers import _authority_url_for_database

        authority_url = _authority_url_for_database(url)
        with psycopg2.connect(authority_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT longspan_install_ledger_mac_key(%s)",
                    ("ledger-bootstrap",),
                )
                cur.execute(
                    "SELECT longspan_install_terra_gateway_mac_key(%s)",
                    ("gateway-bootstrap",),
                )
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT material_id, key_version FROM longspan_mac_material ORDER BY material_id"
                )
                first_material = cur.fetchall()
                cur.execute("SELECT count(*) FROM longspan_mac_key_history")
                first_history_count = cur.fetchone()[0]
        with psycopg2.connect(authority_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT longspan_install_ledger_mac_key(%s)",
                    ("ledger-bootstrap",),
                )
                cur.execute(
                    "SELECT longspan_install_terra_gateway_mac_key(%s)",
                    ("gateway-bootstrap",),
                )
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT material_id, key_version FROM longspan_mac_material ORDER BY material_id"
                )
                assert cur.fetchall() == first_material
                cur.execute("SELECT count(*) FROM longspan_mac_key_history")
                assert cur.fetchone()[0] == first_history_count
        with psycopg2.connect(authority_url) as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg2.Error, match="rotation requires"):
                    cur.execute(
                        "SELECT longspan_install_terra_gateway_mac_key(%s)",
                        ("unexpected-rotation",),
                    )
    finally:
        _drop_test_database(name)


def test_workflow_role_cannot_mutate_authority_history(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-hist")
    _provision_authority(workflow, "run-hist")
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    """
                    UPDATE longspan_authority_history
                    SET reviewed_sha = 'forged'
                    WHERE run_id = 'run-hist'
                    """
                )
                conn.commit()
    workflow.close()


def test_workflow_cannot_set_role_to_authority(db_url: str) -> None:
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user")
            assert cur.fetchone()[0] == "top_delivery_workflow"
            with pytest.raises(psycopg2.Error):
                cur.execute("SET ROLE top_delivery_authority")


def test_authority_version_only_update_rejected(db_url: str, artifact_root: Path) -> None:
    from urllib.parse import quote, urlsplit

    from authority_pins import AUTHORITY_DATABASE_ROLE

    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-ver")
    _provision_authority(workflow, "run-ver")
    name = urlsplit(db_url).path.lstrip("/")
    auth_url = (
        f"postgresql://{AUTHORITY_DATABASE_ROLE}:{quote('td-authority-test')}@127.0.0.1/{name}"
    )
    with psycopg2.connect(auth_url) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    """
                    UPDATE longspan_authority_config
                    SET config_version = config_version + 1
                    WHERE run_id = 'run-ver'
                    """
                )
                conn.commit()
    workflow.close()


def test_resume_retry_issues_fresh_idempotency_key(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "retry-key")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "retry-key"}),
    )
    original_key = child["idempotency_key"]
    workflow.repo.transition_child_state(
        child_id=child["child_id"],
        expected_version=int(child["version"]),
        new_state="retry_wait",
        controller_epoch=workflow.parent.controller_epoch("run-1"),
        run_id="run-1",
        parent_attempt_id=attempt_id,
        fence_token=fence,
        clear_capabilities=True,
        bump_attempt=False,
    )
    workflow.parent.retry_task("run-1", claimed.task_id, claimed.generation or "", "retry")
    reclaimed = workflow.parent.claim_next("run-1", "worker")
    assert reclaimed is not None
    new_attempt, new_fence = workflow.parent.resolve_parent_attempt(
        reclaimed.task_id, reclaimed.generation or ""
    )
    resumed, _caps = workflow.resume_retry_child(
        child_id=child["child_id"],
        parent_attempt_id=new_attempt,
        fence_token=new_fence,
    )
    assert resumed["idempotency_key"] != original_key
    assert int(resumed["attempt_number"]) >= 1
    workflow.close()


def test_enqueue_retry_requires_live_generation_and_advances_attempt(
    db_url: str, artifact_root: Path
) -> None:
    """The public retry enqueue cannot bypass the fenced retry transition."""
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-enqueue-retry")
    _seed_ready_parent(workflow.parent, "run-enqueue-retry", artifact_root)
    _provision_authority(workflow, "run-enqueue-retry")
    workflow.parent.schedule_task("run-enqueue-retry", "task-enqueue-retry", "retry")
    claimed = workflow.parent.claim_next("run-enqueue-retry", "worker")
    assert claimed is not None and claimed.generation

    retry_key = workflow.parent.enqueue_retry(
        "run-enqueue-retry",
        "task-enqueue-retry",
        "injected-failure",
        claimed.generation,
    )
    assert retry_key
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            "SELECT attempt, state, active_attempt_id FROM parent_tasks WHERE task_id = %s",
            ("task-enqueue-retry",),
        )
        parent = cur.fetchone()
        cur.execute(
            "SELECT retry_key, attempt FROM retry_queue WHERE retry_key = %s",
            (retry_key,),
        )
        queued = cur.fetchone()
    assert parent is not None
    assert int(parent["attempt"]) == int(claimed.attempt) + 1
    assert parent["state"] == "queued"
    assert parent["active_attempt_id"] is None
    assert queued is not None and int(queued["attempt"]) == int(claimed.attempt) + 1

    with pytest.raises(PermissionError, match="stale or unknown"):
        workflow.parent.enqueue_retry(
            "run-enqueue-retry",
            "task-enqueue-retry",
            "duplicate",
            claimed.generation,
        )
    workflow.close()


def test_enqueue_retry_limit_terminalizes_and_is_not_replayable(
    db_url: str, artifact_root: Path
) -> None:
    controller = ParentController(
        db_url,
        stale_after=10,
        controller_lease_seconds=5,
        artifact_root=artifact_root,
        max_retries=1,
    )
    controller.register_run("run-enqueue-limit")
    controller.schedule_task("run-enqueue-limit", "task-enqueue-limit", "bounded")
    first = controller.claim_next("run-enqueue-limit", "worker")
    assert first is not None and first.generation
    assert controller.enqueue_retry(
        "run-enqueue-limit", "task-enqueue-limit", "temporary", first.generation
    )
    second = controller.claim_next("run-enqueue-limit", "worker")
    assert second is not None and second.generation
    assert controller.enqueue_retry(
        "run-enqueue-limit", "task-enqueue-limit", "temporary", second.generation
    ) == ""
    final = controller.task("task-enqueue-limit")
    assert final.state == "failed"
    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT active_attempt_id FROM parent_tasks WHERE task_id = %s",
            ("task-enqueue-limit",),
        )
        assert cur.fetchone()["active_attempt_id"] is None
        cur.execute(
            "SELECT COUNT(*) AS count FROM retry_queue WHERE task_id = %s",
            ("task-enqueue-limit",),
        )
        retry_count = int(cur.fetchone()["count"])
        cur.execute(
            "SELECT COUNT(*) AS count FROM supervisor_events "
            "WHERE run_id = %s AND event_type = 'task_failed_retry_limit'",
            ("run-enqueue-limit",),
        )
        failure_events = int(cur.fetchone()["count"])
    assert retry_count == 1
    assert failure_events == 1
    with pytest.raises(PermissionError, match="stale"):
        controller.enqueue_retry(
            "run-enqueue-limit", "task-enqueue-limit", "replay", second.generation
        )
    controller.close()


def test_retry_budget_has_a_hard_upper_bound(db_url: str, artifact_root: Path) -> None:
    with pytest.raises(ValueError, match="max_retries must be <="):
        ParentController(db_url, artifact_root=artifact_root, max_retries=21)


def test_retry_budget_enforced_ceiling_terminalizes(
    db_url: str, artifact_root: Path
) -> None:
    controller = ParentController(
        db_url, artifact_root=artifact_root, max_retries=20
    )
    controller.register_run("run-retry-ceiling")
    controller.schedule_task("run-retry-ceiling", "task-retry-ceiling", "bounded")
    for index in range(20):
        claimed = controller.claim_next("run-retry-ceiling", "worker")
        assert claimed is not None and claimed.generation
        assert controller.enqueue_retry(
            "run-retry-ceiling",
            "task-retry-ceiling",
            f"temporary-{index}",
            claimed.generation,
        )
    claimed = controller.claim_next("run-retry-ceiling", "worker")
    assert claimed is not None and claimed.generation
    assert (
        controller.enqueue_retry(
            "run-retry-ceiling",
            "task-retry-ceiling",
            "final",
            claimed.generation,
        )
        == ""
    )
    assert controller.task("task-retry-ceiling").state == "failed"
    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT COUNT(*) AS count FROM retry_queue WHERE task_id = %s",
            ("task-retry-ceiling",),
        )
        assert int(cur.fetchone()["count"]) == 20
        cur.execute(
            "SELECT COUNT(*) AS count FROM supervisor_events "
            "WHERE run_id = %s AND event_type = 'task_failed_retry_limit'",
            ("run-retry-ceiling",),
        )
        assert int(cur.fetchone()["count"]) == 1
    controller.close()


def test_retry_budget_is_bound_at_repository_boundaries(
    db_url: str, artifact_root: Path
) -> None:
    controller = ParentController(db_url, artifact_root=artifact_root)
    with pytest.raises(ValueError, match="max_retries must be <="):
        controller._repo.retry_task(
            run_id="run-boundary",
            task_id="task-boundary",
            attempt_id="attempt-boundary",
            fence_token=1,
            controller_epoch=1,
            reason="test",
            delay_seconds=0,
            max_retries=21,
        )
    with pytest.raises(ValueError, match="max_retries must be <="):
        controller._repo.tick_stale("run-boundary", 1, max_retries=21)
    with pytest.raises(ValueError, match="max_retries must be <="):
        controller._repo.idempotent_cleanup(
            "attempt-boundary",
            run_id="run-boundary",
            controller_epoch=1,
            max_retries=21,
        )
    longspan_repo = LongspanRepository(controller._repo)
    with pytest.raises(ValueError, match="max_retries must be <="):
        longspan_repo.atomic_recover_permission_and_requeue(
            child_id="child-boundary",
            expected_version=0,
            controller_epoch=1,
            run_id="run-boundary",
            task_id="task-boundary",
            parent_attempt_id="attempt-boundary",
            fence_token=1,
            reason="test",
            max_retries=21,
        )
    controller.close()


def test_raw_alembic_downgrade_rejects_replayed_capability() -> None:
    name, url = _create_test_database(f"td_downgrade_replay_{uuid.uuid4().hex}")
    install_downgrade_capability(database_name=name, migration_revision="006_longspan_authority")
    try:
        alembic_command(url, "upgrade", "head")
        alembic_command(url, "downgrade", "006_longspan_authority")
        with pytest.raises((AuthorizationFailureError, subprocess.CalledProcessError)):
            alembic_command(url, "downgrade", "005_longspan_hardening")
    finally:
        _drop_test_database(name)


def test_downgrade_capability_target_cannot_authorize_a_different_leg() -> None:
    """A capability for 006 cannot authorize an Alembic target of 005."""
    name, url = _create_test_database(f"td_downgrade_target_binding_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="006_longspan_authority"
    )
    try:
        alembic_command(url, "upgrade", "head")
        with pytest.raises((AuthorizationFailureError, subprocess.CalledProcessError)):
            alembic_command(url, "downgrade", "005_longspan_hardening")
        assert current_database_revision(url) == CANONICAL_ALEMBIC_HEAD
    finally:
        _drop_test_database(name)


def test_legacy_migrations_match_base_lineage_hashes() -> None:
    from migration_catalog import LEGACY_MIGRATION_SOURCE_SHA256

    root = Path(__file__).resolve().parents[1]
    for revision, expected_sha in LEGACY_MIGRATION_SOURCE_SHA256.items():
        path = root / "controller/migrations/versions" / f"{revision}.py"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha, revision
        source = path.read_text(encoding="utf-8")
        assert "require_connected_migration_downgrade" in source, revision
        assert "TOP_DELIVERY_ALLOW_" not in source, revision
    migration_006 = (
        root / "controller/migrations/versions/006_longspan_authority.py"
    ).read_text(encoding="utf-8")
    assert "terra receipt run provenance exists" in migration_006
    assert "terra receipt task provenance exists" in migration_006
    assert "terra receipt reviewed-SHA provenance exists" in migration_006


def test_upgrade_rejects_postgres_maintenance_database_before_ddl() -> None:
    """Canonical upgrades cannot target postgres/template1 maintenance DBs."""
    parsed = urlsplit(ADMIN_URL)
    for database_name in ("postgres", "template1"):
        maintenance_url = urlunsplit(parsed._replace(path=f"/{database_name}"))
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            alembic_command(maintenance_url, "upgrade", "head")
    maintenance_url = urlunsplit(parsed._replace(path="/postgres"))
    with psycopg2.connect(maintenance_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.longspan_children')")
            assert cur.fetchone() == (None,)


def test_005_downgrade_rejects_populated_experiment_provenance() -> None:
    name, url = _create_test_database(f"td_downgrade_experiment_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="005_longspan_hardening"
    )
    try:
        # Seed the populated experiment at 006, before 007 installs the
        # runtime mutation triggers. This is an isolated fixture setup, not a
        # production write path.
        alembic_command(url, "upgrade", "006_longspan_authority")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO supervisor_runs (run_id, state) VALUES ('run-experiment', 'active')"
                )
                cur.execute(
                    """
                    INSERT INTO longspan_experiments
                        (experiment_id, run_id, hypothesis, baseline, scope,
                         predicted_benefit, rollback_plan, classification, state,
                         protected_targets_json,
                         operator_approval_digest, auditor_receipt_id)
                    VALUES ('experiment-protected', 'run-experiment', 'hypothesis',
                            'baseline', 'comms-01', 'benefit', 'restore', 'workflow',
                            'accepted', '[\"comms-01\"]', 'operator-digest', 'audit-1')
                    """
                )
                conn.commit()
        alembic_command(url, "upgrade", "head")
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "downgrade", "005_longspan_hardening")
        assert current_database_revision(url) == "008_longspan_authority_repair"
    finally:
        _drop_test_database(name)


def test_007_downgrade_rejects_populated_experiment_provenance() -> None:
    """The 008 -> 007 leg also protects experiment provenance."""
    name, url = _create_test_database(f"td_downgrade_007_experiment_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "006_longspan_authority")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO supervisor_runs (run_id, state) VALUES ('run-experiment-007', 'active')"
                )
                cur.execute(
                    """
                    INSERT INTO longspan_experiments
                        (experiment_id, run_id, hypothesis, baseline, scope,
                         predicted_benefit, rollback_plan, classification, state,
                         protected_targets_json,
                         operator_approval_digest, auditor_receipt_id)
                    VALUES ('experiment-protected-007', 'run-experiment-007',
                            'hypothesis', 'baseline', 'comms-01', 'benefit',
                            'restore', 'workflow', 'accepted', '[\"comms-01\"]',
                            'operator-digest', 'audit-007')
                    """
                )
                conn.commit()
        alembic_command(url, "upgrade", "head")
        install_downgrade_capability(
            database_name=name, migration_revision="007_longspan_authority_hardening"
        )
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "downgrade", "007_longspan_authority_hardening")
        assert current_database_revision(url) == CANONICAL_ALEMBIC_HEAD
    finally:
        _drop_test_database(name)


def test_upgrade_007_rejects_untrusted_existing_recovery_namespace() -> None:
    name, url = _create_test_database(f"td_test_007_recovery_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "006_longspan_authority")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "CREATE TABLE top_delivery_recovery.unexpected_object (id INTEGER)"
                )
                conn.commit()
        with pytest.raises(subprocess.CalledProcessError):
            alembic_command(url, "upgrade", "007_longspan_authority_hardening")
        assert current_database_revision(url) == "006_longspan_authority"
    finally:
        _drop_test_database(name)


def test_workflow_cannot_direct_insert_audits_or_receipts(db_url: str) -> None:
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            for statement in (
                """
                INSERT INTO longspan_execution_results
                    (result_id, child_id, attempt_number, outcome, result_digest, artifact_refs_json)
                VALUES ('er1', 'missing', 0, 'success', 'digest', '[]')
                """,
                """
                INSERT INTO longspan_execution_audits
                    (audit_id, child_id, attempt_number, request_digest, result_digest,
                     validation_outcome)
                VALUES ('a1', 'missing', 0, 'r', 'r', 'ok')
                """,
                """
                INSERT INTO longspan_execution_evidence
                    (evidence_id, child_id, attempt_number, evidence_json, evidence_digest)
                VALUES ('ee1', 'missing', 0, '{"evidence":[]}', 'digest')
                """,
                """
                INSERT INTO longspan_auditor_receipts
                    (receipt_id, child_id, attempt_number, verdict, reasons_json,
                     inspector_digest, receipt_digest)
                VALUES ('ar1', 'missing', 0, 'pass', '[]', 'i', 'd')
                """,
                """
                INSERT INTO longspan_terra_receipts
                    (receipt_id, child_id, attempt_number, reviewer, decision,
                     evidence_chain_head, receipt_digest, run_id, task_id, reviewed_sha)
                VALUES ('tr1', 'missing', 0, 'terra', 'approved', 'h', 'd', 'run', 'task', 'sha')
                """,
                """
                INSERT INTO longspan_evidence_ledger
                    (entry_id, child_id, attempt_number, sequence_number, event_type,
                     producer_role, payload_digest, entry_hash)
                VALUES ('e1', 'missing', 0, 1, 'x', 'executor', 'p', 'h')
                """,
                """
                INSERT INTO longspan_operator_challenges
                    (approval_id, run_id, action_type, action_digest, operator_identity,
                     nonce, expires_at, key_version, challenge_digest)
                VALUES ('c1', 'run', 'x', 'd', 'op', 'n', now() + interval '1 minute', 1, 'cd')
                """,
            ):
                with pytest.raises(psycopg2.Error):
                    cur.execute(statement)
                    conn.commit()
                conn.rollback()


def test_env_flag_alone_cannot_authorize_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    name, url = _create_test_database(f"td_downgrade_env_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "head")
        for flag in (
            "TOP_DELIVERY_ALLOW_LONGSPAN_DOWNGRADE",
            "TOP_DELIVERY_ALLOW_SCHEMA_DOWNGRADE",
            "TOP_DELIVERY_ALLOW_AUTHORITY_DOWNGRADE",
            "TOP_DELIVERY_ALLOW_EVIDENCE_DOWNGRADE",
        ):
            monkeypatch.setenv(flag, "1")
        # Capability still names create/drop operation from fixture churn; force mismatch.
        install_create_capability(database_name=name)
        with pytest.raises((AuthorizationFailureError, subprocess.CalledProcessError, ValueError)):
            alembic_command(url, "downgrade", "006_longspan_authority")
    finally:
        _drop_test_database(name)


def test_ledger_mac_env_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from ledger_mac import ledger_mac_key

    monkeypatch.setenv("COMMS01_LEDGER_MAC_SECRET", "forged")
    with pytest.raises(AuthorizationFailureError, match="must not supply ledger MAC"):
        ledger_mac_key()


def test_production_cannot_enable_authority_test_seam(monkeypatch: pytest.MonkeyPatch) -> None:
    import authority_test_seam as seam

    monkeypatch.setattr(seam, "_caller_is_test", lambda: False)
    with pytest.raises(RuntimeError, match="unreachable from production"):
        seam.inject_test_owner_uids(frozenset({1}))
    with pytest.raises(RuntimeError, match="unreachable from production"):
        seam.inject_test_peer_uids(frozenset({1}))


def test_assert_database_url_rejects_brokerish_host() -> None:
    from comms01_scope import assert_database_url

    with pytest.raises(ScopeBoundaryViolationError):
        assert_database_url("postgresql://broker-user:secret@api-fxtrade.example/top_delivery_control_p1")
    with pytest.raises(ScopeBoundaryViolationError):
        assert_database_url("postgresql://u@postgres-01/top_delivery_control_p1")


def test_007_has_no_all_tables_grant() -> None:
    import re

    text = (
        Path(__file__).resolve().parents[1]
        / "controller/migrations/versions/007_longspan_authority_hardening.py"
    ).read_text(encoding="utf-8")
    assert re.search(r"GRANT\s+[^;]*\bON ALL TABLES\b", text) is None
    assert "GRANT INSERT ON longspan_execution_audits TO {WORKFLOW_ROLE}" not in text
    assert "GRANT INSERT ON longspan_auditor_receipts TO {WORKFLOW_ROLE}" not in text
    assert "GRANT INSERT ON longspan_terra_receipts TO {WORKFLOW_ROLE}" not in text
    assert "GRANT INSERT ON longspan_authority_config TO {AUTHORITY_ROLE}" not in text
    assert "GRANT INSERT ON longspan_authority_history TO {AUTHORITY_ROLE}" not in text
    assert "LOGIN PASSWORD" not in text
    assert "td-workflow-change-me" not in text
    assert "td-authority-change-me" not in text
    assert re.search(r"CREATE\s+ROLE\s+.*LOGIN", text, re.IGNORECASE) is None
    assert "longspan_append_execution_audit" in text
    assert "longspan_store_execution_evidence" in text
    assert "longspan_append_auditor_receipt" in text
    assert "longspan_append_terra_receipt" in text
    assert "longspan_insert_authority_config" in text
    assert "longspan_rotate_authority_config" in text


def test_007_upgrade_fails_without_preprovisioned_roles() -> None:
    """Missing-role rejection is isolated from the shared cluster catalog."""
    from sqlalchemy.exc import DBAPIError

    with _isolated_role_graph_connection(include_workflow=False) as conn:
        with conn.cursor() as cur:
            cur.execute("SET ROLE top_delivery_migration")
        with pytest.raises(DBAPIError, match="required role .* is absent"):
            _run_007_upgrade_direct(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.longspan_authority_config')")
            assert cur.fetchone() == (None,)


def test_authority_role_cannot_direct_insert_authority_config(
    db_url: str, artifact_root: Path
) -> None:
    from urllib.parse import quote, urlsplit

    from authority_pins import AUTHORITY_DATABASE_ROLE

    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-auth-dml")
    _provision_authority(workflow, "run-auth-dml")
    name = urlsplit(db_url).path.lstrip("/")
    auth_url = (
        f"postgresql://{AUTHORITY_DATABASE_ROLE}:{quote('td-authority-test')}@127.0.0.1/{name}"
    )
    with psycopg2.connect(auth_url) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    """
                    INSERT INTO longspan_authority_config
                        (run_id, terra_auth_hash, operator_auth_hash, reviewed_sha,
                         tree_sha, source_digest, config_version, approval_receipt_digest)
                    VALUES ('run-auth-dml', 'a', 'b', 'c', 'd', 'e', 2, 'f')
                    """
                )
                conn.commit()
    workflow.close()


def test_authority_routine_requires_consumed_bound_challenge(db_url: str) -> None:
    """A valid authority DB role cannot call the write routine with free payloads."""
    from urllib.parse import quote, urlsplit

    from authority_pins import AUTHORITY_DATABASE_ROLE

    database_name = urlsplit(db_url).path.lstrip("/")
    auth_url = (
        f"postgresql://{AUTHORITY_DATABASE_ROLE}:{quote('td-authority-test')}@127.0.0.1/{database_name}"
    )
    with psycopg2.connect(auth_url) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    """
                    SELECT * FROM longspan_insert_authority_config(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        "run-direct",
                        "terra",
                        "operator",
                        "reviewed",
                        "tree",
                        "source",
                        1,
                        "action",
                        "missing-approval",
                        "action",
                        "binding",
                    ),
                )
                conn.rollback()
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    """
                    SELECT longspan_create_operator_challenge(
                        %s, %s, %s, %s, %s, %s, now() + interval '1 minute', %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        "approval-direct",
                        "run-direct",
                        "rotate_authority",
                        "action",
                        "operator",
                        "nonce",
                        1,
                        "challenge",
                        1,
                        1,
                        1,
                    ),
                )
                conn.rollback()


def test_superuser_cannot_bypass_authority_challenge(db_url: str) -> None:
    """Schema ownership must not turn a superuser session into an operator approval."""
    from urllib.parse import urlsplit

    database_name = urlsplit(db_url).path.lstrip("/")
    with psycopg2.connect(f"postgresql:///{database_name}") as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    """
                    SELECT * FROM longspan_insert_authority_config(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        "run-superuser",
                        "terra",
                        "operator",
                        "reviewed",
                        "tree",
                        "source",
                        1,
                        "action",
                        "missing-approval",
                        "action",
                        "binding",
                    ),
                )
                conn.rollback()


def test_authority_role_cannot_direct_insert_authority_history(
    db_url: str, artifact_root: Path
) -> None:
    from urllib.parse import quote, urlsplit

    from authority_pins import AUTHORITY_DATABASE_ROLE

    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-hist-dml")
    _provision_authority(workflow, "run-hist-dml")
    name = urlsplit(db_url).path.lstrip("/")
    auth_url = (
        f"postgresql://{AUTHORITY_DATABASE_ROLE}:{quote('td-authority-test')}@127.0.0.1/{name}"
    )
    with psycopg2.connect(auth_url) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error):
                cur.execute(
                    """
                    INSERT INTO longspan_authority_history
                        (history_id, run_id, config_version, terra_auth_hash, operator_auth_hash,
                         reviewed_sha, tree_sha, source_digest, approval_receipt_digest)
                    VALUES ('hist-1', 'run-hist-dml', 2, 'a', 'b', 'c', 'd', 'e', 'f')
                    """
                )
                conn.commit()
    workflow.close()


def test_authority_cannot_set_role_to_workflow(db_url: str) -> None:
    from urllib.parse import quote, urlsplit

    from authority_pins import AUTHORITY_DATABASE_ROLE, WORKFLOW_DATABASE_ROLE

    name = urlsplit(db_url).path.lstrip("/")
    auth_url = (
        f"postgresql://{AUTHORITY_DATABASE_ROLE}:{quote('td-authority-test')}@127.0.0.1/{name}"
    )
    with psycopg2.connect(auth_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user")
            assert cur.fetchone()[0] == AUTHORITY_DATABASE_ROLE
            with pytest.raises(psycopg2.Error):
                cur.execute(f"SET ROLE {WORKFLOW_DATABASE_ROLE}")


def test_caller_cannot_redirect_workflow_database_target(db_url: str) -> None:
    from workflow_database_target import resolve_workflow_database_url

    with pytest.raises(ScopeBoundaryViolationError):
        resolve_workflow_database_url(
            "postgresql://top_delivery_workflow:wrong@127.0.0.1/other_database"
        )
    assert resolve_workflow_database_url(db_url) == db_url


def test_disposable_workflow_target_rejects_wildcard_capability(db_url: str) -> None:
    from disposable_capability import build_capability_file_payload, write_test_capability_file
    from authority_pins import DISPOSABLE_HARNESS_CAPABILITY_PATH
    from test_disposable_helpers import TEST_SIGNING_KEY

    payload = build_capability_file_payload(
        operation="create_database",
        database_name="*",
        database_role="postgres",
        controller_service="top-delivery-controller",
        nonce=f"wildcard-{uuid.uuid4().hex}",
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        signing_key=TEST_SIGNING_KEY,
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    write_test_capability_file(DISPOSABLE_HARNESS_CAPABILITY_PATH, payload)
    from workflow_database_target import resolve_workflow_database_url

    with pytest.raises(AuthorizationFailureError, match="capability mismatch"):
        resolve_workflow_database_url(db_url)

    with pytest.raises(AuthorizationFailureError, match="database name mismatch"):
        create_disposable_database(ADMIN_URL, f"td_test_{uuid.uuid4().hex}")


def test_disposable_database_capability_nonce_is_consumed_before_replay() -> None:
    name = f"td_test_nonce_{uuid.uuid4().hex}"
    install_create_capability(database_name=name)
    url = create_disposable_database(ADMIN_URL, name)
    try:
        with pytest.raises(AuthorizationFailureError, match="nonce already consumed"):
            create_disposable_database(ADMIN_URL, name)
    finally:
        install_drop_capability(database_name=name)
        drop_database(ADMIN_URL, name)


def test_create_capability_cannot_replace_existing_database() -> None:
    name = f"td_test_existing_{uuid.uuid4().hex}"
    install_create_capability(database_name=name)
    url = create_disposable_database(ADMIN_URL, name)
    try:
        install_create_capability(database_name=name)
        with pytest.raises(AuthorizationFailureError, match="already exists"):
            create_disposable_database(ADMIN_URL, name)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_database()")
                assert cur.fetchone()[0] == name
    finally:
        install_drop_capability(database_name=name)
        drop_database(ADMIN_URL, name)


def test_database_url_rejects_unapproved_pinned_port() -> None:
    from comms01_scope import assert_database_url

    with pytest.raises(ScopeBoundaryViolationError, match="pinned port"):
        assert_database_url(
            "postgresql://top_delivery_workflow@127.0.0.1:5433/"
            "top_delivery_control_p1"
        )
