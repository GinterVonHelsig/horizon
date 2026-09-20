from __future__ import annotations

import json
import fcntl
import os
import uuid
import subprocess
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import psycopg2
import pytest

from authority_pins import (
    ATTACKER_DATABASE_ROLE,
    AUTHORITY_SERVICE_GID,
    AUTHORITY_DATABASE_ROLE,
    AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
    AUTHORITY_SOCKET_PATH,
    COMMS01_ATTESTATION_PATH,
    DISPOSABLE_CAPABILITY_SIGNING_KEY_PATH,
    DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH,
    DISPOSABLE_HARNESS_CAPABILITY_PATH,
    LEDGER_MAC_KEY_PATH,
    MIGRATION_DATABASE_ROLE,
    MIGRATION_SOURCE_PROVENANCE_PATH,
    OPERATOR_PUBLIC_KEYS_PATH,
    TERRA_RECEIPT_PUBLIC_KEYS_PATH,
    TERRA_GATEWAY_MAC_KEY_PATH,
    WORKFLOW_DATABASE_ROLE,
    WORKFLOW_DATABASE_TARGET_PATH,
)
from psycopg2 import sql
from pinned_trust import SERVICE_GROUP_READABLE_PATHS
from authority_service_server import AuthorityServiceServer
from authority_socket_secrets import AUTHORITY_WRITE_SIGNING_SECRET_PATH
from db import create_disposable_database, drop_database, run_migrations
from disposable_capability import build_capability_file_payload, write_test_capability_file
from operator_asymmetric import generate_keypair
from provenance import git_commit_sha
from test_only.disposable_harness import enable_disposable_harness
from test_only.pinned_trust_session import (
    PINNED_TRUST_SESSION_PATHS,
    PinnedTrustRestoreError,
    begin_pinned_trust_session,
    restore_pinned_trust_files,
)
from test_disposable_helpers import TEST_SIGNING_KEY as _TEST_SIGNING_KEY
from test_disposable_helpers import TEST_VERIFY_KEY as _TEST_VERIFY_KEY
from test_role_provision import ensure_test_delivery_roles


ADMIN_URL = os.environ.get(
    "TOP_DELIVERY_PG_ADMIN_URL",
    "postgresql://root@/postgres?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
)

REPO_ROOT = Path(__file__).resolve().parents[1]
_OPERATOR_PRIVATE_KEY, _OPERATOR_PUBLIC_KEY = generate_keypair()
_TERRA_PRIVATE_KEY, _TERRA_PUBLIC_KEY = generate_keypair()
_TEST_LEDGER_MAC = "test-ledger-mac-secret"
_TEST_TERRA_GATEWAY_MAC = "test-terra-gateway-mac-secret"
_WORKFLOW_PASSWORD = "td-workflow-test"
_AUTHORITY_PASSWORD = "td-authority-test"

_TEST_ROLE_NAMES = (
    WORKFLOW_DATABASE_ROLE,
    AUTHORITY_DATABASE_ROLE,
    MIGRATION_DATABASE_ROLE,
    ATTACKER_DATABASE_ROLE,
)

# Never authorize MAC via env; pinned file only.
os.environ.pop("COMMS01_LEDGER_MAC_SECRET", None)
os.environ.pop("COMMS01_LEDGER_MAC_KEY_FILE", None)

from test_authority_helpers import configure_operator_signing_key, configure_terra_signing_key

configure_operator_signing_key(_OPERATOR_PRIVATE_KEY)
configure_terra_signing_key(_TERRA_PRIVATE_KEY)
enable_disposable_harness()

for legacy_env in (
    "COMMS01_AUTHORITY_WRITE_CREDENTIAL",
    "COMMS01_OPERATOR_VERIFICATION_KEY",
    "COMMS01_BOOTSTRAP_OPERATOR_TOKEN",
    "COMMS01_OPERATOR_PUBLIC_KEYS",
    "COMMS01_OPERATOR_PUBLIC_KEYS_FILE",
    "COMMS01_AUTHORITY_SOCKET",
    "COMMS01_HOST_FINGERPRINT",
    "TOP_DELIVERY_ENVIRONMENT",
    "COMMS01_DATABASE_ROLE",
    "COMMS01_DISPOSABLE_TEST_MODE",
    "TOP_DELIVERY_ALLOW_SCHEMA_DOWNGRADE",
    "TOP_DELIVERY_ALLOW_AUTHORITY_DOWNGRADE",
    "TOP_DELIVERY_ALLOW_EVIDENCE_DOWNGRADE",
    "TOP_DELIVERY_ALLOW_LONGSPAN_DOWNGRADE",
):
    os.environ.pop(legacy_env, None)


def _write_pinned_file(path: str, payload: str) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(payload, encoding="utf-8")
    if file_path in SERVICE_GROUP_READABLE_PATHS:
        # Keep disposable fixtures identical to the production trust boundary:
        # runtime-readable anchors are root-owned, authority-group-readable,
        # and exactly 0640. Private test-only keys remain 0600/root.
        os.chown(file_path, 0, AUTHORITY_SERVICE_GID)
        file_path.chmod(0o640)
    else:
        file_path.chmod(0o600)


def _snapshot_test_roles(admin_url: str) -> tuple[dict[str, tuple], list[tuple[str, str, bool]]]:
    """Capture cluster-global role state before disposable tests alter it."""

    with psycopg2.connect(admin_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT rolname, rolsuper, rolinherit, rolcreaterole,
                       rolcreatedb, rolcanlogin, rolreplication, rolbypassrls,
                       rolpassword
                FROM pg_authid
                WHERE rolname = ANY(%s)
                """,
                (list(_TEST_ROLE_NAMES),),
            )
            roles = {str(row[0]): tuple(row[1:]) for row in cur.fetchall()}
            cur.execute(
                """
                SELECT parent.rolname, member.rolname, membership.admin_option
                FROM pg_auth_members AS membership
                JOIN pg_roles AS parent ON parent.oid = membership.roleid
                JOIN pg_roles AS member ON member.oid = membership.member
                WHERE parent.rolname = ANY(%s) OR member.rolname = ANY(%s)
                """,
                (list(_TEST_ROLE_NAMES), list(_TEST_ROLE_NAMES)),
            )
            memberships = [
                (str(parent), str(member), bool(admin_option))
                for parent, member, admin_option in cur.fetchall()
            ]
    return roles, memberships


def _restore_test_roles(
    admin_url: str,
    snapshot: tuple[dict[str, tuple], list[tuple[str, str, bool]]],
) -> None:
    """Restore cluster-global role attributes and memberships after tests."""

    roles, memberships = snapshot
    with psycopg2.connect(admin_url) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            for role_name, values in roles.items():
                (
                    rolsuper,
                    rolinherit,
                    rolcreaterole,
                    rolcreatedb,
                    rolcanlogin,
                    rolreplication,
                    rolbypassrls,
                    rolpassword,
                ) = values
                attributes = [
                    "SUPERUSER" if rolsuper else "NOSUPERUSER",
                    "INHERIT" if rolinherit else "NOINHERIT",
                    "CREATEROLE" if rolcreaterole else "NOCREATEROLE",
                    "CREATEDB" if rolcreatedb else "NOCREATEDB",
                    "LOGIN" if rolcanlogin else "NOLOGIN",
                    "REPLICATION" if rolreplication else "NOREPLICATION",
                    "BYPASSRLS" if rolbypassrls else "NOBYPASSRLS",
                ]
                statement = sql.SQL("ALTER ROLE {} {} PASSWORD {}").format(
                    sql.Identifier(role_name),
                    sql.SQL(" ").join(sql.SQL(attribute) for attribute in attributes),
                    sql.Literal(rolpassword),
                )
                cur.execute(statement)

            cur.execute(
                """
                SELECT parent.rolname, member.rolname
                FROM pg_auth_members AS membership
                JOIN pg_roles AS parent ON parent.oid = membership.roleid
                JOIN pg_roles AS member ON member.oid = membership.member
                WHERE parent.rolname = ANY(%s) OR member.rolname = ANY(%s)
                """,
                (list(_TEST_ROLE_NAMES), list(_TEST_ROLE_NAMES)),
            )
            for parent, member in cur.fetchall():
                cur.execute(
                    sql.SQL("REVOKE {} FROM {}").format(
                        sql.Identifier(parent), sql.Identifier(member)
                    )
                )
            for parent, member, admin_option in memberships:
                grant = sql.SQL("GRANT {} TO {}").format(
                    sql.Identifier(parent), sql.Identifier(member)
                )
                if admin_option:
                    grant += sql.SQL(" WITH ADMIN OPTION")
                cur.execute(grant)


def _install_capability(
    *,
    operation: str,
    database_name: str = "*",
    database_role: str | None = None,
    migration_revision: str | None = None,
) -> None:
    if database_role is None:
        with psycopg2.connect(ADMIN_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_user")
                database_role = str(cur.fetchone()[0])
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = build_capability_file_payload(
        operation=operation,
        database_name=database_name,
        database_role=database_role,
        controller_service="top-delivery-controller",
        nonce=f"test-{operation}-{uuid.uuid4().hex}",
        expires_at=expires_at,
        signing_key=_TEST_SIGNING_KEY,
        migration_revision=migration_revision,
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    write_test_capability_file(DISPOSABLE_HARNESS_CAPABILITY_PATH, payload)


def _provision_role_users(admin_url: str, database_name: str) -> tuple[str, str]:
    """Create distinct LOGIN principals with no cross-membership."""
    base = admin_url.rsplit("/", 1)[0]
    admin_db_url = f"{base}/{database_name}"
    with psycopg2.connect(admin_db_url) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                f"""
                DO $users$
                BEGIN
                    ALTER ROLE {WORKFLOW_DATABASE_ROLE} LOGIN PASSWORD '{_WORKFLOW_PASSWORD}'
                        NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    ALTER ROLE {AUTHORITY_DATABASE_ROLE} LOGIN PASSWORD '{_AUTHORITY_PASSWORD}'
                        NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
                    REVOKE {AUTHORITY_DATABASE_ROLE} FROM {WORKFLOW_DATABASE_ROLE};
                    REVOKE {WORKFLOW_DATABASE_ROLE} FROM {AUTHORITY_DATABASE_ROLE};
                    GRANT CONNECT ON DATABASE "{database_name}" TO {WORKFLOW_DATABASE_ROLE};
                    GRANT CONNECT ON DATABASE "{database_name}" TO {AUTHORITY_DATABASE_ROLE};
                END
                $users$ LANGUAGE plpgsql;
                """
            )
    host = "127.0.0.1"
    wf_pw = quote(_WORKFLOW_PASSWORD, safe="")
    auth_pw = quote(_AUTHORITY_PASSWORD, safe="")
    workflow_url = f"postgresql://{WORKFLOW_DATABASE_ROLE}:{wf_pw}@{host}:5432/{database_name}"
    authority_url = f"postgresql://{AUTHORITY_DATABASE_ROLE}:{auth_pw}@{host}:5432/{database_name}"
    # The MAC bootstrap is an authority operation, not an admin/superuser
    # bypass. Keep the test fixture aligned with the production role boundary.
    with psycopg2.connect(authority_url) as authority_conn:
        with authority_conn.cursor() as authority_cur:
            authority_cur.execute(
                "SELECT longspan_install_ledger_mac_key(%s)",
                (_TEST_LEDGER_MAC,),
            )
            authority_cur.execute(
                "SELECT longspan_install_terra_gateway_mac_key(%s)",
                (_TEST_TERRA_GATEWAY_MAC,),
            )
    return workflow_url, authority_url


def _write_authority_service_target(authority_url: str, database_name: str) -> None:
    payload = {
        "database_url": authority_url,
        "database_name": database_name,
        "database_role": AUTHORITY_DATABASE_ROLE,
        "database_endpoint": "127.0.0.1",
        "database_port": 5432,
        "authority_service": "top-delivery-authority-service",
    }
    _write_pinned_file(
        AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


def _write_workflow_service_target(workflow_url: str, database_name: str) -> None:
    payload = {
        "database_url": workflow_url,
        "database_name": database_name,
        "database_role": WORKFLOW_DATABASE_ROLE,
        "database_endpoint": "127.0.0.1",
        "database_port": 5432,
        "controller_service": "top-delivery-controller",
    }
    _write_pinned_file(
        WORKFLOW_DATABASE_TARGET_PATH,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


@pytest.fixture(scope="session")
def serialize_disposable_trust_state() -> Iterator[None]:
    """Serialize sessions that mutate the fixed disposable trust anchors.

    The controller deliberately uses root-owned, fixed-path trust anchors in
    production.  The disposable harness replaces those files for each test
    session, so parallel pytest processes would otherwise race and produce
    false signature/attestation failures.  Holding the lock for the complete
    session lifetime makes accidental xdist or concurrent invocations safe by
    serialization; it does not weaken the production trust boundary.
    """

    lock_path = Path(
        os.environ.get(
            "TOP_DELIVERY_TEST_SESSION_LOCK",
            "/tmp/top-delivery-controller-test-session.lock",
        )
    )
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = lock_path.open("a+", encoding="utf-8")
    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


@pytest.fixture(scope="session", autouse=True)
def install_pinned_trust_anchors(
    serialize_disposable_trust_state: None,
) -> Iterator[None]:
    file_snapshot = begin_pinned_trust_session(
        PINNED_TRUST_SESSION_PATHS,
        COMMS01_ATTESTATION_PATH,
        os.environ,
    )
    role_snapshot = None
    file_restore_error: Exception | None = None
    role_restore_error: Exception | None = None
    try:
        role_snapshot = _snapshot_test_roles(ADMIN_URL)
        ensure_test_delivery_roles(ADMIN_URL)
        attestation = {
            "scope": "comms-01",
            "environment_marker": "isolated-top-delivery",
            "host_fingerprint": "comms01-isolated-top-delivery-local",
            "database_name": "top_delivery_control_p1",
            "database_role": WORKFLOW_DATABASE_ROLE,
            "workflow_database_role": WORKFLOW_DATABASE_ROLE,
            "authority_database_role": AUTHORITY_DATABASE_ROLE,
            "controller_service": "top-delivery-controller",
            "database_endpoint": "local",
            "database_port": 5432,
            "authority_service": "top-delivery-authority-service",
        }
        _write_pinned_file(
            COMMS01_ATTESTATION_PATH,
            json.dumps(attestation, indent=2, sort_keys=True) + "\n",
        )
        _write_pinned_file(
            MIGRATION_SOURCE_PROVENANCE_PATH,
            json.dumps(
                {
                    "algorithm": "sha256",
                    "normalization_version": 1,
                    "revision": "008_longspan_authority_repair",
                    "source_digest": "38ec94c702a8f85fd261d3539fd3899cb4955fff428c2282870aca2a13d92101",
                    "legacy_source_digests": {
                        "017_goal_completion_disposable": "b8fa1755241ac9089ca0c427f8663f77c9b61d025dfa016270b31c3b96d912e2",
                        "021_goal_completion": "acf255eb8b83f4f17a0c4aff1f3ecc3ca10bbc5323aefdaf58e5a74998e04a15",
                        "004_longspan_workflow": "bc01d0a94963dc64d36d1edab9cf2e602f5f96205f33c717b02f553fd3577b32",
                        "005_longspan_hardening": "bd0a4a166b5a59fada29f48a146532f98ac5c7a9f46b301b7dcd1a145bd5401f",
                        "006_longspan_authority": "b6a23a1240fbeb60066bb580ffcd28d5776e41f395ec6256a2cf94ebbff530eb",
                        "007_longspan_authority_hardening": "2782b879d23226797d95f8666d3a6d546f9d749bf80ceb777291d44501d4c39e",
                        "009_goal_schedule_task": "7f0c36e0064a5c149f8c671168df5dd4d07d7fdcef427389ee45d6d2aed647bd",
                        "010_goal_claim_parent_task": "70c6419caffaa56d1f8313af9fbe2d2e260c37c5c42924f8414bdbb81628ae87",
                        "011_goal_claim_fence_token_fix": "ed5afacaf1475b83615f424f0eb102b00131b3d18c96045eb8c2c7a82a40c56e",
                        "012_claim_parent_scope_fix": "cb05019f949de3dc8fd5daba44bf4d1e43c3508a681cbf0a53639a4bfd68dfd7",
                        "013_cleanup_expired_attempt": "911d718a54a36148d1b4410fbce75e1107f569dde99dfcf7c9c1711e32fc4e7b",
                        "014_horizon_project_ledger": "38bb8be3ba2283a18a1011fcbb1a5ca19c7b74d268a378219b4efaa1861891ca",
                        "015_subworkflow_handoff": "dfa9b35ec871ff0e667b9a3b851bd57a294e177be8fb4346f64ac6dbb17557ff",
                        "016_horizon_prereq_corr": "437b0d2d2387c9fd9ce95b0afb38d73c2ed80049d2532278166767f4c377d766",
                        "014_requeue_blocked_parent_task": "07b5a02e7ffb22e08b38947629396a96ab80235c9fd7bf0a7ce55c8955e6f73e",
                        "015_recover_executor_contract_failure": "19b9c2c5dd0ed8a349330baba6e5259b1ceb19dfe794430951bac035cbfa4cc5",
                        "016_recover_exhausted_executor_contract_once": "a17ab7da918d6c3a861e3177bca1200beac06597ab8da33894dd9896d5a4cef6",
                        "017_parent_rollback_routine": "30ae5700613aabc5f4c40788e78ad5290cacba2335aca9a474d3b61f6394e103",
                        "018_horizon_project_ledger_live": "9e30a586002a025529fe646cb7b731452aade698efc6a05805ad429cb2a0d0d6",
                        "019_subworkflow_handoff_live": "df4b1c4f6d580ccd78a28d602c4df336e975fdad017689513d982fbe2051e63b",
                        "020_horizon_prereq_corr_live": "16bd70bb01a4d3eea4d972e9806ca3fd4536d4c0914a0cdba88e0594ba087f9a",
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
        _write_pinned_file(
            OPERATOR_PUBLIC_KEYS_PATH,
            json.dumps({"1": _OPERATOR_PUBLIC_KEY}, indent=2, sort_keys=True) + "\n",
        )
        # Test-only key material is intentionally written to a separate trust
        # anchor so Terra receipt verification cannot accidentally reuse the
        # operator approval path in production.
        _write_pinned_file(
            TERRA_RECEIPT_PUBLIC_KEYS_PATH,
            json.dumps({"1": _TERRA_PUBLIC_KEY}, indent=2, sort_keys=True) + "\n",
        )
        _write_pinned_file(
            DISPOSABLE_CAPABILITY_SIGNING_KEY_PATH,
            _TEST_SIGNING_KEY + "\n",
        )
        _write_pinned_file(
            DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH,
            _TEST_VERIFY_KEY + "\n",
        )
        _write_pinned_file(LEDGER_MAC_KEY_PATH, _TEST_LEDGER_MAC + "\n")
        _write_pinned_file(
            TERRA_GATEWAY_MAC_KEY_PATH,
            _TEST_TERRA_GATEWAY_MAC + "\n",
        )
        _install_capability(operation="create_database")
        _write_pinned_file(
            AUTHORITY_WRITE_SIGNING_SECRET_PATH,
            "test-authority-write-signing-secret\n",
        )
        Path(AUTHORITY_SOCKET_PATH).parent.mkdir(parents=True, exist_ok=True)
        yield
    finally:
        try:
            restore_pinned_trust_files(file_snapshot)
        except Exception as exc:  # noqa: BLE001 — still restore roles
            file_restore_error = exc
        try:
            if role_snapshot is not None:
                _restore_test_roles(ADMIN_URL, role_snapshot)
        except Exception as exc:  # noqa: BLE001 — still raise file error
            role_restore_error = exc
        if file_restore_error is not None or role_restore_error is not None:
            raise PinnedTrustRestoreError(
                f"trust session restore failed file={file_restore_error!r} "
                f"roles={role_restore_error!r}"
            ) from (file_restore_error or role_restore_error)


@pytest.fixture()
def db_url(request) -> Iterator[str]:
    name = f"td_test_{uuid.uuid4().hex}"
    _install_capability(operation="create_database", database_name=name)
    url = create_disposable_database(ADMIN_URL, name)
    try:
        if getattr(request,"param",None)=="live-stack":
            from db import alembic_command
            alembic_command(url,"upgrade","021_goal_completion")
        else:
            run_migrations(url)
    except subprocess.CalledProcessError as exc:
        from harness_adapters.redaction import redact_text
        # Report the earliest boundary instead of repeating opaque subprocess
        # exit codes for every dependent test. Never expose connection secrets.
        diagnostic = redact_text(str(exc.stderr or exc.output or "migration failed"))
        if getattr(request,"param",None)=="live-stack" and "014_requeue_blocked_parent_task is already applied on live; do not re-apply" in diagnostic:
            from exceptions import MissingLiveMigrationBaselineError
            raise MissingLiveMigrationBaselineError("archived live 014 source is unavailable; fresh replay intentionally denied") from exc
        raise RuntimeError("disposable migration failed: " + diagnostic[-4096:]) from exc
    workflow_url, authority_url = _provision_role_users(ADMIN_URL, name)
    _write_workflow_service_target(workflow_url, name)
    _write_authority_service_target(authority_url, name)
    server = AuthorityServiceServer(repo_root=REPO_ROOT)
    server.start()
    try:
        yield workflow_url
    finally:
        server.close()
        socket_path = Path(AUTHORITY_SOCKET_PATH)
        if socket_path.exists():
            socket_path.unlink()
        _install_capability(operation="drop_database", database_name=name)
        drop_database(ADMIN_URL, name)


@pytest.fixture()
def artifact_root(tmp_path: Path) -> Path:
    root = tmp_path / "artifacts"
    root.mkdir()
    return root


@pytest.fixture()
def reviewed_sha() -> str:
    return git_commit_sha(REPO_ROOT)


@pytest.fixture()
def provenance_tuple(reviewed_sha: str) -> tuple[str, str]:
    from provenance import capture_run_provenance

    captured = capture_run_provenance(REPO_ROOT, reviewed_sha=reviewed_sha)
    return captured.tree_sha, captured.source_digest
