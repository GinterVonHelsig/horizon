"""Action-bound authorization service for the isolated TOP-DELIVERY control plane."""
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timezone

import psycopg2
from psycopg2 import errors as pg_errors
import pyotp
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DB_URL = os.environ["DATABASE_URL"]
INTERNAL_TOKEN = os.environ["INTERNAL_TOKEN"]
TOTP_SECRET = os.environ["TOTP_SECRET"]
app = FastAPI(title="TOP-DELIVERY authorization", docs_url=None, redoc_url=None)


def db():
    return psycopg2.connect(DB_URL)


def require_token(token: str | None) -> None:
    if not token or not secrets.compare_digest(token, INTERNAL_TOKEN):
        raise HTTPException(status_code=401, detail="invalid internal token")


class ChallengeRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=200)
    action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: str = Field(min_length=1, max_length=200)


class AuthorizationRequest(BaseModel):
    code: str = Field(pattern=r"^[0-9]{6}$")
    action_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


@app.on_event("startup")
def init_db() -> None:
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_challenges (
              challenge_id text PRIMARY KEY,
              action_id text NOT NULL,
              action_hash text NOT NULL,
              scope text NOT NULL,
              created_at timestamptz NOT NULL,
              expires_at timestamptz NOT NULL,
              consumed_at timestamptz,
              result text
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_audit (
              id bigserial PRIMARY KEY,
              challenge_id text,
              event text NOT NULL,
              action_hash text,
              event_at timestamptz NOT NULL,
              detail text NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_totp_steps (
              totp_step bigint PRIMARY KEY,
              challenge_id text NOT NULL,
              consumed_at timestamptz NOT NULL
            )
            """
        )


@app.get("/healthz")
def healthz():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    return {"status": "healthy", "signal": "not_configured", "totp": "configured"}


@app.post("/v1/challenges")
def create_challenge(req: ChallengeRequest, x_internal_token: str | None = Header(default=None)):
    require_token(x_internal_token)
    now = datetime.now(timezone.utc)
    expires = now.replace(microsecond=0) + __import__("datetime").timedelta(seconds=60)
    challenge_id = secrets.token_urlsafe(24)
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO auth_challenges VALUES (%s,%s,%s,%s,%s,%s,NULL,NULL)",
            (challenge_id, req.action_id, req.action_hash, req.scope, now, expires),
        )
        cur.execute(
            "INSERT INTO auth_audit(challenge_id,event,action_hash,event_at,detail) VALUES (%s,%s,%s,%s,%s)",
            (challenge_id, "challenge_created", req.action_hash, now, "signal_not_configured"),
        )
    return {"challenge_id": challenge_id, "expires_at": expires.isoformat(), "notification": "signal_not_configured"}


@app.post("/v1/challenges/{challenge_id}/authorize")
def authorize(challenge_id: str, req: AuthorizationRequest, x_internal_token: str | None = Header(default=None)):
    require_token(x_internal_token)
    now = datetime.now(timezone.utc)
    totp = pyotp.TOTP(TOTP_SECRET)
    totp_step = int(now.timestamp()) // totp.interval
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT action_hash, expires_at, consumed_at FROM auth_challenges WHERE challenge_id=%s FOR UPDATE", (challenge_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="unknown challenge")
        action_hash, expires_at, consumed_at = row
        if consumed_at is not None:
            raise HTTPException(status_code=409, detail="challenge already consumed")
        if now >= expires_at:
            cur.execute("UPDATE auth_challenges SET result='expired' WHERE challenge_id=%s", (challenge_id,))
            cur.execute(
                "INSERT INTO auth_audit(challenge_id,event,action_hash,event_at,detail) VALUES (%s,%s,%s,%s,%s)",
                (challenge_id, "authorization_expired", action_hash, now, "expired"),
            )
            conn.commit()
            raise HTTPException(status_code=410, detail="challenge expired")
        if not secrets.compare_digest(action_hash, req.action_hash):
            raise HTTPException(status_code=403, detail="action hash mismatch")
        if not totp.verify(req.code, valid_window=0):
            cur.execute(
                "INSERT INTO auth_audit(challenge_id,event,action_hash,event_at,detail) VALUES (%s,%s,%s,%s,%s)",
                (challenge_id, "authorization_rejected", action_hash, now, "invalid_totp"),
            )
            conn.commit()
            raise HTTPException(status_code=403, detail="invalid code")
        try:
            cur.execute(
                "INSERT INTO auth_totp_steps(totp_step, challenge_id, consumed_at) VALUES (%s,%s,%s)",
                (totp_step, challenge_id, now),
            )
        except pg_errors.UniqueViolation:
            conn.rollback()
            with conn.cursor() as audit_cur:
                audit_cur.execute(
                    "INSERT INTO auth_audit(challenge_id,event,action_hash,event_at,detail) VALUES (%s,%s,%s,%s,%s)",
                    (challenge_id, "authorization_rejected", action_hash, now, "totp_step_replay"),
                )
            conn.commit()
            raise HTTPException(status_code=403, detail="invalid code")
        cur.execute("UPDATE auth_challenges SET consumed_at=%s,result='authorized' WHERE challenge_id=%s", (now, challenge_id))
        cur.execute("INSERT INTO auth_audit(challenge_id,event,action_hash,event_at,detail) VALUES (%s,%s,%s,%s,%s)", (challenge_id, "authorization_granted", action_hash, now, "totp"))
    return {"authorized": True, "challenge_id": challenge_id, "action_hash": hashlib.sha256(action_hash.encode()).hexdigest()}

