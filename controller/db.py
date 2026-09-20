"""PostgreSQL connection helpers and migration runner."""

from __future__ import annotations

import os
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import psycopg2
import psycopg2.extras
from alembic.config import Config
from alembic.script import ScriptDirectory
from psycopg2.extensions import connection as PgConnection

from comms01_scope import (
    ALLOWED_DATABASE_NAME,
    ALLOWED_DISPOSABLE_ROLES,
    assert_admin_database_url,
    assert_comms01_entrypoint,
    assert_database_url,
    assert_effective_libpq_target,
    disposable_database_token,
    is_disposable_test_database,
    resolve_live_comms01_service_name,
    verify_admin_connection_identity,
    verify_connection_identity,
)
from authority_pins import (
    AUTHORITY_DATABASE_ROLE,
    AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
    MIGRATION_DATABASE_ROLE,
    WORKFLOW_DATABASE_ROLE,
    effective_migration_capability_role,
)
from exceptions import AuthorizationFailureError, ProvenanceMismatchError, ScopeBoundaryViolationError
from migration_source_anchor import normalized_source_digest
from pinned_trust import read_json_file

CONTROLLER_DIR = Path(__file__).resolve().parent
DEFAULT_DB_NAME = ALLOWED_DATABASE_NAME
CANONICAL_ALEMBIC_HEAD = "012_claim_parent_scope_fix"
MIGRATION_SOURCE_PROVENANCE_ALGORITHM = "sha256"
MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION = 1
FORBIDDEN_DB_MARKERS = (
    "trading",
    "ledger",
    "broker",
    "production",
    "auth",
)
RELATIVE_REVISION_PATTERN = re.compile(r"^[\-+:@]|@|\+|\-|\^")
AUTHORITY_DESTRUCTIVE_REVISIONS = frozenset(
    {
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
    }
)
FORBIDDEN_DOWNGRADE_REVISIONS = frozenset(
    {
        "base",
        "001_initial",
        "002_event_sequence",
        "003_commit_order_and_invariants",
    }
)
DOWNGRADE_ENV_FLAG = "TOP_DELIVERY_ALLOW_SCHEMA_DOWNGRADE"
AUTHORITY_DOWNGRADE_ENV_FLAG = "TOP_DELIVERY_ALLOW_AUTHORITY_DOWNGRADE"
ALEMBIC_TIMEOUT_SECONDS = 300.0
MAX_ALEMBIC_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_ALEMBIC_OUTPUT_TAIL_BYTES = 8192


def _limit_alembic_child_output() -> None:
    """Hard-limit each Alembic child's diagnostic file before it starts."""
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_ALEMBIC_OUTPUT_BYTES, MAX_ALEMBIC_OUTPUT_BYTES),
    )


def _kill_alembic_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the whole migration process group and wait with a bound."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)


def validate_database_url(url: str) -> str:
    """Reject connection strings that target forbidden production databases."""
    try:
        assert_database_url(url)
    except ScopeBoundaryViolationError as exc:
        raise ValueError(str(exc)) from exc
    return url


def _connect(
    db_url: str, *, allow_disposable_inspection: bool
) -> PgConnection:
    from workflow_database_target import resolve_workflow_database_url

    resolved = resolve_workflow_database_url(db_url)
    live_service = resolve_live_comms01_service_name()
    assert_comms01_entrypoint(
        scope="comms-01",
        database_url=resolved,
        service_name=live_service,
    )
    validate_database_url(resolved)
    conn = psycopg2.connect(resolved)
    conn.autocommit = True
    verify_connection_identity(
        database_url=resolved,
        connection=conn,
        expected_role=WORKFLOW_DATABASE_ROLE,
        expected_service=live_service,
        allow_disposable_inspection=allow_disposable_inspection,
    )
    # Raw clock/lease manipulation is needed by failure-injection tests, but
    # only after the signed disposable inspection capability has authorized
    # this exact target. Authorization is deliberately established by the
    # repository transaction that performs the mutation, never at connect
    # time: connecting must not leave an implicit transaction or reusable
    # mutation flag behind.
    conn.autocommit = False
    return conn


def authorize_disposable_test_mutation(
    conn: PgConnection,
    db_url: str,
    *,
    cursor: Any | None = None,
) -> None:
    """Open the transaction-local failure-injection seam for one exact target."""
    if not is_disposable_test_database(db_url):
        return
    from disposable_capability import load_signed_disposable_capability

    capability = load_signed_disposable_capability()
    database_name = urlsplit(db_url).path.lstrip("/")
    if capability is None or capability.database_name != database_name:
        raise AuthorizationFailureError(
            "disposable mutation seam requires a signed capability for this database"
        )
    if cursor is None:
        with conn.cursor() as owned_cursor:
            owned_cursor.execute(
                "SELECT set_config('top_delivery.disposable_test_mutation', '1', true)"
            )
    else:
        cursor.execute("SELECT set_config('top_delivery.disposable_test_mutation', '1', true)")


def connect(db_url: str) -> PgConnection:
    """Connect as the pinned workflow principal for normal controller work."""
    return _connect(db_url, allow_disposable_inspection=False)


def connect_disposable_inspection(db_url: str) -> PgConnection:
    """Inspect a disposable database through the explicit admin-only seam.

    This path is intentionally separate from ``connect`` so a normal workflow
    connection cannot opt into administrator identity exceptions by passing a
    boolean flag.  It is read-only at the application layer and is restricted
    to the disposable database naming contract before the connection is made.
    """
    if not is_disposable_test_database(db_url):
        raise AuthorizationFailureError(
            "disposable inspection requires a td_test_ or td_downgrade_ database"
        )
    return _connect(db_url, allow_disposable_inspection=True)


def resolve_authority_database_url(caller_url: str) -> str:
    """Resolve the authority service's immutable target; never use a caller URL blindly."""
    target = read_json_file(
        AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
        strict_owner=True,
        require_root_owner=True,
    )
    required = (
        "database_url",
        "database_name",
        "database_role",
        "database_endpoint",
        "database_port",
    )
    missing = [field for field in required if not target.get(field)]
    if missing:
        raise AuthorizationFailureError(
            f"authority database target missing fields: {', '.join(missing)}"
        )
    if str(target["database_role"]) != AUTHORITY_DATABASE_ROLE:
        raise AuthorizationFailureError("authority database target role is not pinned")
    pinned = str(target["database_url"])
    assert_effective_libpq_target(pinned)
    if caller_url != pinned:
        raise ScopeBoundaryViolationError(
            "authority connections must use the pinned Comms-01 authority target"
        )
    parsed = urlsplit(pinned)
    try:
        database_port = int(target["database_port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorizationFailureError("authority database target port is invalid") from exc
    if parsed.port != database_port:
        raise AuthorizationFailureError(
            "authority database target URL/port does not match pinned database_port"
        )
    if parsed.path.lstrip("/") != str(target["database_name"]):
        raise AuthorizationFailureError("authority database target URL/name mismatch")
    if parsed.username != AUTHORITY_DATABASE_ROLE:
        raise AuthorizationFailureError("authority database target URL/role mismatch")
    endpoint = str(target["database_endpoint"])
    if endpoint not in {"local", "localhost", "127.0.0.1", "::1"}:
        if (parsed.hostname or "").lower() != endpoint.lower():
            raise AuthorizationFailureError("authority database target endpoint mismatch")
    return pinned


def connect_authority(db_url: str) -> PgConnection:
    """Connect only as the pinned authority principal, independently of workflow routing."""
    resolved = resolve_authority_database_url(db_url)
    validate_database_url(resolved)
    conn = psycopg2.connect(resolved)
    conn.autocommit = True
    verify_connection_identity(
        database_url=resolved,
        connection=conn,
        expected_role=AUTHORITY_DATABASE_ROLE,
        expected_service="top-delivery-authority-service",
    )
    conn.autocommit = False
    return conn


def _alembic_config() -> Config:
    config = Config(str(CONTROLLER_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(CONTROLLER_DIR / "migrations"))
    return config


def _alembic_script() -> ScriptDirectory:
    return ScriptDirectory.from_config(_alembic_config())


def resolve_canonical_revision(revision: str) -> str:
    """Resolve and require a canonical full Alembic revision identifier."""
    if not revision:
        raise ValueError("revision is required")
    if revision in {"head", "heads"}:
        head = _alembic_script().get_current_head()
        if head is None:
            raise ValueError("no Alembic head is configured")
        return head
    if RELATIVE_REVISION_PATTERN.search(revision):
        raise ValueError(
            f"relative or branch-relative revision {revision!r} is forbidden; "
            "use a canonical full revision identifier"
        )
    if revision in FORBIDDEN_DOWNGRADE_REVISIONS:
        return revision
    script = _alembic_script()
    resolved = script.get_revision(revision)
    if resolved is None:
        raise ValueError(f"unknown Alembic revision: {revision}")
    canonical = resolved.revision
    if canonical != revision:
        raise ValueError(
            f"partial revision alias {revision!r} is forbidden; use {canonical!r}"
        )
    return canonical


def migration_source_digest(revision: str) -> str:
    """Hash the exact in-tree migration source with its self-marker normalized.

    The canonical migration records this digest in PostgreSQL when it is applied.  The
    marker assignment itself is replaced before hashing so the recorded value
    is stable and cannot be changed merely by updating the marker to the value
    calculated from the rest of the file.
    """
    canonical = resolve_canonical_revision(revision)
    if canonical != CANONICAL_ALEMBIC_HEAD:
        raise ProvenanceMismatchError(
            f"migration source provenance is only defined for {CANONICAL_ALEMBIC_HEAD}"
        )
    migration_path = (
        CONTROLLER_DIR / "migrations" / "versions" / f"{canonical}.py"
    )
    try:
        source = migration_path.read_bytes()
    except OSError as exc:
        raise ProvenanceMismatchError(
            f"migration source is unavailable: {migration_path}"
        ) from exc
    return normalized_source_digest(source)


def assert_migration_source_provenance(cursor: Any, revision: str) -> None:
    """Require the database's canonical migration source marker to match code."""
    canonical = resolve_canonical_revision(revision)
    expected_digest = migration_source_digest(canonical)
    try:
        cursor.execute(
            "SELECT source_digest, algorithm, normalization_version "
            "FROM longspan_migration_provenance "
            "WHERE revision = %s",
            (canonical,),
        )
        row = cursor.fetchone()
    except Exception as exc:
        if exc.__class__.__name__ == "UndefinedTable":
            raise ProvenanceMismatchError(
                "canonical database is missing migration source provenance"
            ) from exc
        raise
    if (
        row is None
        or row[0] != expected_digest
        or row[1] != MIGRATION_SOURCE_PROVENANCE_ALGORITHM
        or row[2] != MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION
    ):
        raise ProvenanceMismatchError(
            "canonical database migration source provenance does not match this release"
        )


def verify_disposable_database_identity(
    db_url: str,
    *,
    operation: str = "schema_downgrade",
    migration_revision: str | None = None,
) -> None:
    validate_database_url(db_url)
    disposable_database_token(db_url)
    database_name = urlsplit(db_url).path.lstrip("/")
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database(), current_user")
            row = cur.fetchone()
    finally:
        conn.close()
    if row is None:
        raise ValueError("could not resolve disposable database identity")
    actual_database, actual_role = row[0], row[1]
    if actual_database != database_name:
        raise ValueError(
            f"database identity mismatch: URL targets {database_name!r}, connected to {actual_database!r}"
        )
    if not any(actual_database.startswith(prefix) for prefix in ("td_test_", "td_downgrade_")):
        raise ValueError("disposable downgrade requires a td_test_ or td_downgrade_ database")
    capability_role = effective_migration_capability_role(str(actual_role))
    if actual_role not in ALLOWED_DISPOSABLE_ROLES and actual_role != "root":
        raise ValueError(
            f"database role {actual_role!r} is not allowlisted for disposable downgrade"
        )
    # Use the same complete capability contract for every connected role,
    # including peer-auth root.  The old root-only branch checked only a
    # subset of the binding and could disagree with Alembic's guard.
    _require_disposable_harness_capability(
        operation=operation,
        database_name=str(actual_database),
        database_role=capability_role,
        migration_revision=migration_revision,
        consume_nonce=False,
    )


def assert_disposable_database_for_downgrade(db_url: str, revision: str) -> None:
    validate_database_url(db_url)
    if not is_disposable_test_database(db_url):
        raise ValueError(
            "schema downgrade is only permitted on a verified disposable test database"
        )
    verify_disposable_database_identity(
        db_url,
        operation="schema_downgrade",
        migration_revision=revision,
    )
    database_name = urlsplit(db_url).path.lstrip("/")
    _require_disposable_harness_capability(
        operation="schema_downgrade",
        database_name=database_name,
        migration_revision=revision,
    )


def assert_forward_only_upgrade(revision: str, db_url: str | None = None) -> str:
    canonical = resolve_canonical_revision(revision)
    if db_url is not None and is_disposable_test_database(db_url):
        return canonical
    head = resolve_canonical_revision("head")
    if canonical not in {head, "head", "heads"}:
        raise ValueError(
            f"normal migration entry points may only upgrade to head {head!r}"
        )
    return canonical


def assert_downgrade_allowed(db_url: str, revision: str) -> str:
    canonical = resolve_canonical_revision(revision)
    assert_disposable_database_for_downgrade(db_url, canonical)
    if canonical in FORBIDDEN_DOWNGRADE_REVISIONS:
        raise ValueError(f"downgrade to {canonical} is forbidden")
    database_name = urlsplit(db_url).path.lstrip("/")
    if canonical in AUTHORITY_DESTRUCTIVE_REVISIONS:
        _require_disposable_harness_capability(
            operation="authority_downgrade",
            database_name=database_name,
            migration_revision=canonical,
        )
        _require_disposable_harness_capability(
            operation="evidence_downgrade",
            database_name=database_name,
            migration_revision=canonical,
        )
    return canonical


def run_migrations(db_url: str) -> None:
    if is_disposable_test_database(db_url):
        alembic_command(db_url, "upgrade", "016_horizon_prereq_corr")
    else:
        alembic_command(db_url, "upgrade", "020_horizon_prereq_corr_live")


ALLOWED_ALEMBIC_COMMANDS = frozenset({"upgrade", "downgrade"})


def alembic_command(db_url: str, command: str, revision: str) -> None:
    if command not in ALLOWED_ALEMBIC_COMMANDS:
        raise ValueError(f"unsupported alembic command: {command}")
    if command == "upgrade":
        target = assert_forward_only_upgrade(revision, db_url)
    else:
        target = assert_downgrade_allowed(db_url, revision)
    validate_database_url(db_url)
    env = os.environ.copy()
    env["TOP_DELIVERY_DATABASE_URL"] = db_url
    try:
        command_args = [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(CONTROLLER_DIR / "alembic.ini"),
            command,
            target,
        ]
        with tempfile.TemporaryFile() as stdout_sink, tempfile.TemporaryFile() as stderr_sink:
            def bounded_excerpt(sink) -> str:
                sink.flush()
                sink.seek(0, os.SEEK_END)
                size = sink.tell()
                if size <= MAX_ALEMBIC_OUTPUT_TAIL_BYTES:
                    sink.seek(0, os.SEEK_SET)
                    return sink.read().decode("utf-8", errors="replace")
                head_bytes = MAX_ALEMBIC_OUTPUT_TAIL_BYTES // 2
                tail_bytes = MAX_ALEMBIC_OUTPUT_TAIL_BYTES - head_bytes
                sink.seek(0, os.SEEK_SET)
                head = sink.read(head_bytes).decode("utf-8", errors="replace")
                sink.seek(max(0, size - tail_bytes), os.SEEK_SET)
                tail = sink.read(tail_bytes).decode("utf-8", errors="replace")
                return head + "\n...[alembic diagnostic excerpt truncated]...\n" + tail

            def output_size_exceeded() -> bool:
                return (
                    os.fstat(stdout_sink.fileno()).st_size > MAX_ALEMBIC_OUTPUT_BYTES
                    or os.fstat(stderr_sink.fileno()).st_size > MAX_ALEMBIC_OUTPUT_BYTES
                )

            process = subprocess.Popen(
                command_args,
                cwd=str(CONTROLLER_DIR),
                env=env,
                stdout=stdout_sink,
                stderr=stderr_sink,
                text=False,
                start_new_session=True,
                preexec_fn=_limit_alembic_child_output,
            )
            deadline = time.monotonic() + ALEMBIC_TIMEOUT_SECONDS
            while process.poll() is None:
                if output_size_exceeded():
                    _kill_alembic_process_group(process)
                    stdout_text = bounded_excerpt(stdout_sink)
                    stderr_text = bounded_excerpt(stderr_sink)
                    raise subprocess.CalledProcessError(
                        -9,
                        command_args,
                        output=stdout_text,
                        stderr=(
                            "alembic output exceeded the bounded diagnostic limit\n"
                            + stderr_text
                        )[-MAX_ALEMBIC_OUTPUT_TAIL_BYTES:],
                    )
                if time.monotonic() >= deadline:
                    _kill_alembic_process_group(process)
                    stdout_text = bounded_excerpt(stdout_sink)
                    stderr_text = bounded_excerpt(stderr_sink)
                    raise subprocess.TimeoutExpired(
                        command_args,
                        ALEMBIC_TIMEOUT_SECONDS,
                        output=stdout_text,
                        stderr=stderr_text,
                    )
                time.sleep(0.05)
            # The child may have exited between the last poll and the output
            # check.  Enforce the same bound on the completed process too.
            if output_size_exceeded():
                stdout_text = bounded_excerpt(stdout_sink)
                stderr_text = bounded_excerpt(stderr_sink)
                raise subprocess.CalledProcessError(
                    process.returncode or -1,
                    command_args,
                    output=stdout_text,
                    stderr=(
                        "alembic output exceeded the bounded diagnostic limit\n"
                        + stderr_text
                    )[-MAX_ALEMBIC_OUTPUT_TAIL_BYTES:],
                )
            stdout_text = bounded_excerpt(stdout_sink)
            stderr_text = bounded_excerpt(stderr_sink)
            result_returncode = process.returncode
            if result_returncode != 0:
                details = (stderr_text or stdout_text).strip()
                raise subprocess.CalledProcessError(
                    result_returncode,
                    command_args,
                    output=stdout_text,
                    stderr=details or stdout_text,
                )
    except OSError as exc:
        raise RuntimeError("Alembic migration subprocess could not be started or terminated") from exc


def current_database_revision(db_url: str, *, connection_mode: str = "workflow") -> str | None:
    if connection_mode == "authority":
        conn = connect_authority(db_url)
    elif connection_mode == "workflow":
        if is_disposable_test_database(db_url):
            conn = connect_disposable_inspection(db_url)
        else:
            conn = connect(db_url)
    else:
        raise ValueError(f"unknown database connection mode: {connection_mode}")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT version_num FROM alembic_version")
            row = cur.fetchone()
            if row and row[0] == CANONICAL_ALEMBIC_HEAD:
                assert_migration_source_provenance(cur, row[0])
            return row[0] if row else None
    finally:
        conn.close()


def _require_disposable_harness_capability(
    *,
    operation: str,
    database_name: str | None = None,
    database_role: str | None = None,
    migration_revision: str | None = None,
    consume_nonce: bool = False,
) -> Any:
    from disposable_capability import require_disposable_capability

    return require_disposable_capability(
        operation=operation,
        database_name=database_name,
        database_role=database_role,
        migration_revision=migration_revision,
        consume_nonce=consume_nonce,
    )


def create_disposable_database(admin_url: str, name: str) -> str:
    assert_admin_database_url(admin_url)
    admin_role = urlsplit(admin_url).username
    if not admin_role:
        raise AuthorizationFailureError(
            "administrative PostgreSQL URL must pin an explicit login role"
        )
    capability = _require_disposable_harness_capability(
        operation="create_database",
        database_name=name,
        database_role=admin_role,
        consume_nonce=True,
    )
    if not re.fullmatch(r"td_(test|downgrade)_[A-Za-z0-9_]+", name):
        raise AuthorizationFailureError(
            "disposable database name must match td_test_* or td_downgrade_*"
        )
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("invalid disposable database identifier")
    admin = psycopg2.connect(admin_url)
    admin.autocommit = True
    try:
        _database_name, actual_role = verify_admin_connection_identity(admin_url, admin)
        if actual_role != capability.database_role:
            raise AuthorizationFailureError(
                "authenticated administrative role does not match the signed capability"
            )
        with admin.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            if cur.fetchone() is not None:
                raise AuthorizationFailureError(
                    "disposable database already exists; use a distinct drop_database "
                    "capability before recreating it"
                )
            cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        admin.close()
    parsed_admin = urlsplit(admin_url)
    disposable_url = urlunsplit(
        (
            parsed_admin.scheme,
            parsed_admin.netloc,
            f"/{name}",
            parsed_admin.query,
            parsed_admin.fragment,
        )
    )
    # The production migration requires pgcrypto as an out-of-band prerequisite.
    # Install it only in this explicitly disposable test database; never in the
    # canonical Comms-01 or trading database.
    disposable = psycopg2.connect(disposable_url)
    disposable.autocommit = True
    try:
        with disposable.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            # The migration principal is provisioned out-of-band and must be
            # the only identity that can create migration objects.  PostgreSQL
            # 15+ does not grant CREATE on the public schema to arbitrary
            # roles in a newly-created database, so establish this explicit
            # disposable-harness prerequisite before env.py enters the role.
            cur.execute(
                f"GRANT USAGE, CREATE ON SCHEMA public TO {MIGRATION_DATABASE_ROLE}"
            )
        # Disposable databases must use the same explicit out-of-band
        # namespace bootstrap as Comms-01. Alembic env.py only verifies these
        # objects; it no longer creates schemas or repairs metadata ownership.
        from migration_bootstrap import bootstrap_migration_namespace

        bootstrap_migration_namespace(disposable_url)
    finally:
        disposable.close()
    return disposable_url


def drop_database(admin_url: str, name: str) -> None:
    assert_admin_database_url(admin_url)
    admin_role = urlsplit(admin_url).username
    if not admin_role:
        raise AuthorizationFailureError(
            "administrative PostgreSQL URL must pin an explicit login role"
        )
    capability = _require_disposable_harness_capability(
        operation="drop_database",
        database_name=name,
        database_role=admin_role,
        consume_nonce=True,
    )
    if not re.fullmatch(r"td_(test|downgrade)_[A-Za-z0-9_]+", name):
        raise AuthorizationFailureError(
            "disposable database name must match td_test_* or td_downgrade_*"
        )
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("invalid disposable database identifier")
    admin = psycopg2.connect(admin_url)
    admin.autocommit = True
    try:
        _database_name, actual_role = verify_admin_connection_identity(admin_url, admin)
        if actual_role != capability.database_role:
            raise AuthorizationFailureError(
                "authenticated administrative role does not match the signed capability"
            )
        with admin.cursor() as cur:
            cur.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = %s AND pid <> pg_backend_pid()
                """,
                (name,),
            )
            cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
    finally:
        admin.close()


def row_to_dict(row: Any) -> dict[str, Any]:
    if row is None:
        return {}
    if isinstance(row, dict):
        return dict(row)
    return dict(row)
