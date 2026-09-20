"""Test helpers for disposable capability installation and authority service startup."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2

from authority_pins import DISPOSABLE_HARNESS_CAPABILITY_PATH, MIGRATION_DATABASE_ROLE
from disposable_capability import build_capability_file_payload, write_test_capability_file
from operator_asymmetric import generate_keypair

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_SIGNING_KEY, TEST_VERIFY_KEY = generate_keypair()


def _connected_admin_role() -> str:
    with psycopg2.connect("postgresql:///postgres") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user")
            return str(cur.fetchone()[0])


def install_create_capability(*, database_name: str) -> None:
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = build_capability_file_payload(
        operation="create_database",
        database_name=database_name,
        database_role=_connected_admin_role(),
        controller_service="top-delivery-controller",
        nonce=f"create-{uuid.uuid4().hex}",
        expires_at=expires_at,
        signing_key=TEST_SIGNING_KEY,
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    write_test_capability_file(DISPOSABLE_HARNESS_CAPABILITY_PATH, payload)


def install_drop_capability(*, database_name: str) -> None:
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = build_capability_file_payload(
        operation="drop_database",
        database_name=database_name,
        database_role=_connected_admin_role(),
        controller_service="top-delivery-controller",
        nonce=f"drop-{uuid.uuid4().hex}",
        expires_at=expires_at,
        signing_key=TEST_SIGNING_KEY,
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    write_test_capability_file(DISPOSABLE_HARNESS_CAPABILITY_PATH, payload)


def install_downgrade_capability(
    *,
    database_name: str,
    migration_revision: str | None = None,
    database_role: str | None = None,
) -> None:
    # Do not set environment flags; env.py derives them only after capability verify.
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    payload = build_capability_file_payload(
        operation="disposable_downgrade",
        database_name=database_name,
        database_role=database_role or MIGRATION_DATABASE_ROLE,
        controller_service="top-delivery-controller",
        nonce=f"downgrade-{uuid.uuid4().hex}",
        expires_at=expires_at,
        signing_key=TEST_SIGNING_KEY,
        migration_revision=migration_revision,
        database_endpoint="127.0.0.1",
        database_port=5432,
    )
    write_test_capability_file(DISPOSABLE_HARNESS_CAPABILITY_PATH, payload)
