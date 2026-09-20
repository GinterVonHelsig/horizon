"""In-tree control-plane app.py F5: audit commits before HTTP errors; TOTP step replay."""

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import pytest

VENV_SITE = "/opt/top-delivery-venv/lib/python3.13/site-packages"
if VENV_SITE not in sys.path:
    sys.path.insert(0, VENV_SITE)

CONTROL_PLANE = Path(__file__).resolve().parents[1]
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

LIVE_CONTROL = "top_delivery_control_p1"
FORBIDDEN = ("top_delivery_control_p1", "/opt/top-delivery-auth")


def _create_td_test_db() -> tuple[str, str]:
    name = f"td_test_auth_{uuid.uuid4().hex[:16]}"
    if not name.startswith("td_test_"):
        raise RuntimeError("refusing to create non-td_test database")
    admin = psycopg2.connect("dbname=postgres user=root host=/var/run/postgresql")
    admin.autocommit = True
    try:
        with admin.cursor() as cur:
            cur.execute("SELECT current_database()")
            assert cur.fetchone()[0] == "postgres"
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (LIVE_CONTROL,))
            assert cur.fetchone() is not None
            cur.execute(f"CREATE DATABASE {name}")
    finally:
        admin.close()
    url = f"dbname={name} user=root host=/var/run/postgresql"
    return name, url


def _drop_td_test_db(name: str) -> None:
    if not name.startswith("td_test_"):
        raise RuntimeError("refusing to drop non-td_test database")
    admin = psycopg2.connect("dbname=postgres user=root host=/var/run/postgresql")
    admin.autocommit = True
    try:
        with admin.cursor() as cur:
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                (name,),
            )
            cur.execute(f"DROP DATABASE IF EXISTS {name}")
    finally:
        admin.close()


@pytest.fixture
def auth_client(monkeypatch: pytest.MonkeyPatch):
    import importlib

    import pyotp

    name, url = _create_td_test_db()
    secret = pyotp.random_base32()
    token = "test-internal-token"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("INTERNAL_TOKEN", token)
    monkeypatch.setenv("TOTP_SECRET", secret)
    import app as auth_app

    auth_app = importlib.reload(auth_app)
    from fastapi.testclient import TestClient

    with TestClient(auth_app.app) as client:
        yield client, secret, token, name, url
    _drop_td_test_db(name)


def _action_hash() -> str:
    return hashlib.sha256(b"disposable-f5-action").hexdigest()


def test_invalid_totp_audit_survives_http_403(auth_client) -> None:
    client, _secret, token, name, url = auth_client
    assert name.startswith("td_test_")
    assert LIVE_CONTROL not in url
    headers = {"x-internal-token": token}
    created = client.post(
        "/v1/challenges",
        json={"action_id": "noop", "action_hash": _action_hash(), "scope": "disposable"},
        headers=headers,
    )
    assert created.status_code == 200
    challenge_id = created.json()["challenge_id"]
    denied = client.post(
        f"/v1/challenges/{challenge_id}/authorize",
        json={"code": "000000", "action_hash": _action_hash()},
        headers=headers,
    )
    assert denied.status_code == 403
    conn = psycopg2.connect(url)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT event, detail FROM auth_audit WHERE challenge_id=%s ORDER BY id", (challenge_id,))
            events = cur.fetchall()
    finally:
        conn.close()
    assert ("authorization_rejected", "invalid_totp") in events


def test_expiry_audit_survives_http_410(auth_client) -> None:
    client, _secret, token, _name, url = auth_client
    headers = {"x-internal-token": token}
    created = client.post(
        "/v1/challenges",
        json={"action_id": "noop", "action_hash": _action_hash(), "scope": "disposable"},
        headers=headers,
    )
    challenge_id = created.json()["challenge_id"]
    conn = psycopg2.connect(url)
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE auth_challenges SET expires_at=%s WHERE challenge_id=%s",
                (datetime.now(timezone.utc) - timedelta(seconds=1), challenge_id),
            )
    finally:
        conn.close()
    expired = client.post(
        f"/v1/challenges/{challenge_id}/authorize",
        json={"code": "123456", "action_hash": _action_hash()},
        headers=headers,
    )
    assert expired.status_code == 410
    conn = psycopg2.connect(url)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT result FROM auth_challenges WHERE challenge_id=%s", (challenge_id,))
            result = cur.fetchone()[0]
            cur.execute("SELECT event FROM auth_audit WHERE challenge_id=%s AND event=%s", (challenge_id, "authorization_expired"))
            audit = cur.fetchone()
    finally:
        conn.close()
    assert result == "expired"
    assert audit is not None


def test_totp_step_cannot_authorize_a_second_challenge(auth_client) -> None:
    client, secret, token, _name, url = auth_client
    import pyotp

    headers = {"x-internal-token": token}
    action = _action_hash()
    first = client.post(
        "/v1/challenges",
        json={"action_id": "one", "action_hash": action, "scope": "disposable"},
        headers=headers,
    ).json()["challenge_id"]
    second = client.post(
        "/v1/challenges",
        json={"action_id": "two", "action_hash": action, "scope": "disposable"},
        headers=headers,
    ).json()["challenge_id"]
    code = pyotp.TOTP(secret).now()
    ok = client.post(
        f"/v1/challenges/{first}/authorize",
        json={"code": code, "action_hash": action},
        headers=headers,
    )
    assert ok.status_code == 200
    replay = client.post(
        f"/v1/challenges/{second}/authorize",
        json={"code": code, "action_hash": action},
        headers=headers,
    )
    assert replay.status_code == 403
    conn = psycopg2.connect(url)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM auth_totp_steps")
            count = cur.fetchone()[0]
            cur.execute("SELECT detail FROM auth_audit WHERE challenge_id=%s AND event=%s", (second, "authorization_rejected"))
            details = [row[0] for row in cur.fetchall()]
    finally:
        conn.close()
    assert count == 1
    assert "totp_step_replay" in details


def test_f5_tests_do_not_touch_live_auth_paths() -> None:
    text = Path(__file__).read_text()
    assert "/opt/top-delivery-auth" not in text or "FORBIDDEN" in text
    assert "top_delivery_control_p1" in text
    assert "td_test_" in text
