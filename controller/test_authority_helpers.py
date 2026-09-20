"""Test helpers for external operator approval (out-of-band 2FA simulation)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import quote, urlsplit

from authority_pins import (
    AUTHORITY_DATABASE_ROLE,
    AUTHORITY_SERVICE_GID,
    AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
    WORKFLOW_DATABASE_ROLE,
)
from authority_service_server import AuthorityServiceServer
from comms01_authority import ExternalOperatorApprovalReceipt, OperatorTwoFactorChallenge
from operator_asymmetric import challenge_signing_message, sign_message

REPO_ROOT = Path(__file__).resolve().parents[1]

_OPERATOR_PRIVATE_KEY: str | None = None
_TERRA_PRIVATE_KEY: str | None = None
_AUTHORITY_PASSWORD = "td-authority-test"


def configure_operator_signing_key(private_key: str) -> None:
    global _OPERATOR_PRIVATE_KEY
    _OPERATOR_PRIVATE_KEY = private_key


def operator_private_key_for_tests() -> str:
    if not _OPERATOR_PRIVATE_KEY:
        raise ValueError("test operator private key is not configured")
    return _OPERATOR_PRIVATE_KEY


def configure_terra_signing_key(private_key: str) -> None:
    global _TERRA_PRIVATE_KEY
    _TERRA_PRIVATE_KEY = private_key


def terra_private_key_for_tests() -> str:
    if not _TERRA_PRIVATE_KEY:
        raise ValueError("test Terra private key is not configured")
    return _TERRA_PRIVATE_KEY


def _authority_url_for_database(db_url: str) -> str:
    database_name = urlsplit(db_url).path.lstrip("/")
    auth_pw = quote(_AUTHORITY_PASSWORD, safe="")
    return f"postgresql://{AUTHORITY_DATABASE_ROLE}:{auth_pw}@127.0.0.1:5432/{database_name}"


def _write_authority_service_target(authority_url: str, database_name: str) -> None:
    payload = {
        "database_url": authority_url,
        "database_name": database_name,
        "database_role": AUTHORITY_DATABASE_ROLE,
        "database_endpoint": "127.0.0.1",
        "database_port": 5432,
        "authority_service": "top-delivery-authority-service",
    }
    path = Path(AUTHORITY_SERVICE_DATABASE_TARGET_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # This is a runtime-readable pinned target, so disposable tests must mirror
    # the production root:authority-service 0640 trust contract. Private
    # test-only keys remain root-only in conftest.py.
    os.chown(path, 0, AUTHORITY_SERVICE_GID)
    path.chmod(0o640)


def start_authority_service_for_url(db_url: str) -> AuthorityServiceServer:
    database_name = urlsplit(db_url).path.lstrip("/")
    # Ensure distinct authority LOGIN exists with password (migrations may have created it).
    import psycopg2

    admin = psycopg2.connect(db_url if urlsplit(db_url).username in {None, "postgres"} else f"postgresql:///{database_name}")
    # Prefer peer/admin on the disposable DB.
    admin.close()
    admin = psycopg2.connect(f"postgresql:///{database_name}")
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(
            f"""
            ALTER ROLE {AUTHORITY_DATABASE_ROLE} LOGIN PASSWORD '{_AUTHORITY_PASSWORD}'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            ALTER ROLE {WORKFLOW_DATABASE_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            REVOKE {AUTHORITY_DATABASE_ROLE} FROM {WORKFLOW_DATABASE_ROLE};
            REVOKE {WORKFLOW_DATABASE_ROLE} FROM {AUTHORITY_DATABASE_ROLE};
            GRANT CONNECT ON DATABASE "{database_name}" TO {AUTHORITY_DATABASE_ROLE};
            """
        )
    admin.close()
    authority_url = _authority_url_for_database(db_url)
    try:
        from ledger_mac import require_ledger_mac_key
        from terra_gateway_mac import require_terra_gateway_mac_key

        with psycopg2.connect(authority_url) as authority_conn:
            with authority_conn.cursor() as authority_cur:
                authority_cur.execute(
                    "SELECT longspan_install_ledger_mac_key(%s)",
                    (require_ledger_mac_key(),),
                )
                authority_cur.execute(
                    "SELECT longspan_install_terra_gateway_mac_key(%s)",
                    (require_terra_gateway_mac_key(),),
                )
    except Exception:
        pass
    _write_authority_service_target(authority_url, database_name)
    server = AuthorityServiceServer(repo_root=REPO_ROOT)
    server.start()
    return server


def sign_external_operator_receipt(
    challenge: OperatorTwoFactorChallenge,
    *,
    operator_private_key: str | None = None,
) -> ExternalOperatorApprovalReceipt:
    private_key = operator_private_key or _OPERATOR_PRIVATE_KEY
    if not private_key:
        raise ValueError("operator private key is required to sign external approval receipt")
    payload = {
        "approval_id": challenge.approval_id,
        "operator_identity": challenge.operator_identity,
        "action_type": challenge.action_type,
        "action_digest": challenge.action_digest,
        "run_id": challenge.run_id,
        "nonce": challenge.nonce,
        "expires_at": challenge.expires_at,
        "key_version": challenge.key_version,
        "controller_epoch": challenge.controller_epoch,
        "config_version": challenge.config_version,
        "challenge_epoch": challenge.challenge_epoch,
    }
    signing_message = challenge_signing_message(payload)
    return ExternalOperatorApprovalReceipt(
        approval_id=challenge.approval_id,
        operator_identity=challenge.operator_identity,
        nonce=challenge.nonce,
        expires_at=challenge.expires_at,
        action_type=challenge.action_type,
        action_digest=challenge.action_digest,
        run_id=challenge.run_id,
        key_version=challenge.key_version,
        controller_epoch=challenge.controller_epoch,
        config_version=challenge.config_version,
        signature=sign_message(signing_message, private_key),
    )
