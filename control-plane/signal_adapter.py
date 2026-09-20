"""Authenticated Signal receive/send adapter for TOP-DELIVERY.

The adapter is deliberately a thin transport boundary.  It does not execute
shell commands, invoke a model, or write a production system.  Read-only
messages are passed byte-for-byte to the local controller socket.  The two
execution messages only create or consume an action-bound challenge through
the isolated authorization service and append a pending intent; no executor
is present in this process.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import sqlite3
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from authorization import (
    CHALLENGE_TTL_SECONDS,
    action_digest,
    canonical_action,
)
from signal_bridge import (
    BoundedRateLimiter,
    SignalBridge,
    SignalEnvelope,
    SignalIdentityPolicy,
)

LOGGER = logging.getLogger("top_delivery.signal_adapter")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SIX_DIGIT = re.compile(r"^\d{6}$")
_NEXT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
_EXECUTION_COMMANDS = frozenset({"next", "queue-next-prompt", "authorize"})
_SIGNAL_COMMANDS = (
    "status",
    "architecture-summary",
    "recommended",
    "active-runs",
    "latest-evidence",
    "next-step (read-only run next action)",
    "trading-summary [YYYY-MM-DD]",
    "artifact lookup (read-only evidence)",
    "next (2FA queue)",
    "authorize CODE",
    "commands",
)
AUTHORIZATION_MODE = "authorization"
READ_ONLY_MODE = "read-only"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _compact_fingerprint(value: str) -> str:
    return "".join(value.split()).lower()


def _error(code: str, **fields: Any) -> str:
    payload: dict[str, Any] = {"error": code}
    payload.update(fields)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _execution_error(
    code: str,
    *,
    message: str,
    next_action: str,
    **fields: Any,
) -> str:
    return _error(
        code,
        mode=AUTHORIZATION_MODE,
        message=message,
        next_action=next_action,
        **fields,
    )


def _authorization_service_error(code: str) -> str:
    guidance = {
        "challenge_unknown": (
            "No pending challenge matches that id.",
            "next",
        ),
        "challenge_expired": (
            "The challenge expired after 60 seconds. "
            "Send next to create a new challenge.",
            "next",
        ),
        "authorization_duplicate": (
            "This challenge was already authorized and cannot be reused.",
            "next",
        ),
        "action_hash_mismatch": (
            "The action digest does not match the pending challenge. "
            "Use the current challenge returned by next.",
            "next",
        ),
        "authorization_rejected": (
            "The six-digit code was rejected for this challenge.",
            "next",
        ),
        "authorization_service_unavailable": (
            "The authorization service is temporarily unavailable.",
            "retry authorize or next",
        ),
    }
    message, next_action = guidance.get(
        code,
        ("Authorization was rejected.", "next"),
    )
    return _execution_error(code, message=message, next_action=next_action)


class RpcError(RuntimeError):
    """The local signal-cli or authorization RPC returned an error."""


class AuthServiceError(RpcError):
    """The authorization service rejected a well-formed request."""

    def __init__(self, code: str, *, http_status: int | None = None) -> None:
        self.error_code = code
        self.http_status = http_status
        super().__init__(code)


class JsonRpcClient:
    """Small JSON-RPC client with no third-party runtime dependency."""

    def __init__(self, endpoint: str, *, timeout: float = 15.0) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self._next_id = 1

    def call(
        self, method: str, params: Mapping[str, Any], *, timeout: float | None = None
    ) -> Any:
        request_id = self._next_id
        self._next_id += 1
        request = urllib.request.Request(
            self.endpoint,
            data=_json_bytes(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": dict(params),
                }
            ),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout if timeout is None else timeout
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise RpcError(f"rpc {method} unavailable") from exc
        if not isinstance(payload, Mapping):
            raise RpcError(f"rpc {method} returned a malformed response")
        error = payload.get("error")
        if error is not None:
            if isinstance(error, Mapping):
                code = error.get("code", "unknown")
                message = str(error.get("message", "unknown error"))[:240]
                raise RpcError(f"rpc {method} returned an error ({code}): {message}")
            raise RpcError(f"rpc {method} returned an error")
        return payload.get("result")


class AuthClient:
    """REST client for the localhost-only action authorization API."""

    def __init__(self, base_url: str, internal_token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.internal_token = internal_token

    def call(self, method: str, params: Mapping[str, Any], **_kwargs: Any) -> Any:
        if not method.startswith("POST "):
            raise RpcError("unsupported authorization method")
        request = urllib.request.Request(
            self.base_url + method[5:],
            data=_json_bytes(params),
            headers={
                "Content-Type": "application/json",
                "X-Internal-Token": self.internal_token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10.0) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                body = json.loads(exc.read().decode("utf-8"))
                if isinstance(body, Mapping):
                    detail = str(body.get("detail", ""))
            except (OSError, ValueError, UnicodeDecodeError):
                detail = ""
            code = _authorization_error_code(exc.code, detail)
            raise AuthServiceError(code, http_status=exc.code) from exc
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise RpcError("authorization service unavailable") from exc
        if not isinstance(payload, Mapping):
            raise RpcError("authorization service returned malformed data")
        return payload


def _authorization_error_code(http_status: int, detail: str) -> str:
    lowered = detail.lower()
    if http_status == 404 or "unknown challenge" in lowered:
        return "challenge_unknown"
    if http_status == 410 or "expired" in lowered:
        return "challenge_expired"
    if http_status == 409 or "consumed" in lowered:
        return "authorization_duplicate"
    if http_status == 403 and "hash" in lowered:
        return "action_hash_mismatch"
    if http_status == 403 and "code" in lowered:
        return "authorization_rejected"
    if http_status == 403:
        return "authorization_rejected"
    return "authorization_rejected"


class ControllerSocketClient:
    """Adapter implementing the controller interface expected by SignalBridge."""

    def __init__(
        self,
        socket_path: str | Path,
        sender_id: str,
        *,
        transport_sender: str | None = None,
    ) -> None:
        self.socket_path = str(socket_path)
        self.sender_id = sender_id
        self.transport_sender = transport_sender or sender_id

    def handle_text(
        self, text: str, sender_id: str, *, is_group: bool = False
    ) -> str:
        if sender_id != self.transport_sender or is_group:
            raise PermissionError("controller sender rejected")
        request = {
            "text": text,
            "sender_id": self.sender_id,
            "is_group": False,
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(15.0)
            connection.connect(self.socket_path)
            connection.sendall(_json_bytes(request) + b"\n")
            chunks: list[bytes] = []
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        raw = b"".join(chunks).split(b"\n", 1)[0]
        response = json.loads(raw.decode("utf-8"))
        if not isinstance(response, Mapping) or response.get("ok") is not True:
            raise RuntimeError("controller socket rejected request")
        result = response.get("result")
        if not isinstance(result, str):
            raise RuntimeError("controller socket returned a non-text result")
        return result


class ActionQueue:
    """Durable append-only intent record for authorized, non-executing actions."""

    def __init__(self, db_path: str | Path) -> None:
        self._connection = sqlite3.connect(
            str(db_path), timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS pending_challenges (
                challenge_id TEXT PRIMARY KEY,
                action_json TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS authorization_sessions (
                operator_id TEXT NOT NULL,
                action_name TEXT NOT NULL,
                scope TEXT NOT NULL,
                granted_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                source_challenge_id TEXT NOT NULL,
                PRIMARY KEY(operator_id, action_name, scope)
            );
            CREATE TABLE IF NOT EXISTS authorized_actions (
                challenge_id TEXT PRIMARY KEY,
                action_json TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                authorized_at REAL NOT NULL,
                state TEXT NOT NULL CHECK (state = 'pending-parent')
            );
            CREATE TABLE IF NOT EXISTS adapter_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at REAL NOT NULL,
                event_type TEXT NOT NULL,
                message_id_digest TEXT,
                detail_json TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS adapter_events_no_update
            BEFORE UPDATE ON adapter_events
            BEGIN SELECT RAISE(ABORT, 'adapter events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS adapter_events_no_delete
            BEFORE DELETE ON adapter_events
            BEGIN SELECT RAISE(ABORT, 'adapter events are append-only'); END;
            """
        )

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()

    def event(
        self, event_type: str, *, message_id: str | None = None, **detail: Any
    ) -> None:
        self._connection.execute(
            "INSERT INTO adapter_events(occurred_at,event_type,message_id_digest,detail_json) VALUES(?,?,?,?)",
            (
                time.time(),
                event_type,
                self._digest(message_id) if message_id is not None else None,
                json.dumps(detail, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            ),
        )

    def remember_challenge(
        self, challenge_id: str, action: Mapping[str, Any], digest: str
    ) -> None:
        self._connection.execute(
            "INSERT OR IGNORE INTO pending_challenges(challenge_id,action_json,action_digest,created_at) VALUES(?,?,?,?)",
            (
                challenge_id,
                json.dumps(dict(action), ensure_ascii=True, sort_keys=True, separators=(",", ":")),
                digest,
                time.time(),
            ),
        )

    def latest_pending_challenge(
        self,
        now: float,
        *,
        ttl: float = CHALLENGE_TTL_SECONDS,
    ) -> tuple[str, str] | None:
        cutoff = now - ttl
        row = self._connection.execute(
            """
            SELECT challenge_id, action_digest
            FROM pending_challenges
            WHERE challenge_id NOT IN (SELECT challenge_id FROM authorized_actions)
              AND created_at > ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (cutoff,),
        ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1])

    def latest_pending_action(
        self,
        now: float,
        *,
        ttl: float = CHALLENGE_TTL_SECONDS,
    ) -> tuple[str, str, dict[str, Any]] | None:
        cutoff = now - ttl
        row = self._connection.execute(
            """
            SELECT challenge_id, action_digest, action_json
            FROM pending_challenges
            WHERE challenge_id NOT IN (SELECT challenge_id FROM authorized_actions)
              AND created_at > ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (cutoff,),
        ).fetchone()
        if row is None:
            return None
        try:
            action = json.loads(row[2])
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(action, dict):
            return None
        return str(row[0]), str(row[1]), action

    def action_for_challenge(self, challenge_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT action_json FROM pending_challenges WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            action = json.loads(row[0])
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        return action if isinstance(action, dict) else None

    def has_stale_pending_challenge(
        self,
        now: float,
        *,
        ttl: float = CHALLENGE_TTL_SECONDS,
    ) -> bool:
        cutoff = now - ttl
        row = self._connection.execute(
            """
            SELECT 1
            FROM pending_challenges
            WHERE challenge_id NOT IN (SELECT challenge_id FROM authorized_actions)
              AND created_at <= ?
            LIMIT 1
            """,
            (cutoff,),
        ).fetchone()
        return row is not None

    def pending_challenge_digest(self, challenge_id: str) -> str | None:
        row = self._connection.execute(
            "SELECT action_digest FROM pending_challenges WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row[0])

    def is_authorized(self, challenge_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM authorized_actions WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()
        return row is not None

    def authorize(
        self, challenge_id: str, action_digest_value: str, response: Mapping[str, Any]
    ) -> bool:
        row = self._connection.execute(
            "SELECT action_json,action_digest FROM pending_challenges WHERE challenge_id=?",
            (challenge_id,),
        ).fetchone()
        if row is None or row[1] != action_digest_value:
            return False
        created = self._connection.execute(
            "INSERT OR IGNORE INTO authorized_actions(challenge_id,action_json,action_digest,authorized_at,state) VALUES(?,?,?,?,?)",
            (challenge_id, row[0], row[1], time.time(), "pending-parent"),
        ).rowcount
        self.event(
            "action_authorized" if created else "action_authorization_duplicate",
            challenge_id=challenge_id,
            action_digest=action_digest_value,
            provider_receipt=bool(response.get("authorized")),
        )
        return created == 1

    def grant_session(
        self,
        operator_id: str,
        action_name: str,
        scope: str,
        source_challenge_id: str,
        now: float,
        *,
        ttl: float = _NEXT_SESSION_TTL_SECONDS,
    ) -> float:
        expires_at = now + ttl
        self._connection.execute(
            """
            INSERT OR REPLACE INTO authorization_sessions(
                operator_id, action_name, scope, granted_at, expires_at,
                source_challenge_id
            ) VALUES(?,?,?,?,?,?)
            """,
            (operator_id, action_name, scope, now, expires_at, source_challenge_id),
        )
        self.event(
            "authorization_session_granted",
            operator_id=operator_id,
            action_name=action_name,
            scope=scope,
            expires_at=expires_at,
            source_challenge_id=source_challenge_id,
        )
        return expires_at

    def active_session(
        self,
        operator_id: str,
        action_name: str,
        scope: str,
        now: float,
    ) -> float | None:
        row = self._connection.execute(
            """
            SELECT expires_at
            FROM authorization_sessions
            WHERE operator_id=? AND action_name=? AND scope=? AND expires_at>?
            """,
            (operator_id, action_name, scope, now),
        ).fetchone()
        return None if row is None else float(row[0])

    def authorize_from_session(
        self,
        operator_id: str,
        action: Mapping[str, Any],
        digest: str,
        message_id: str,
        now: float,
    ) -> tuple[bool, float | None]:
        action_name = str(action.get("action", ""))
        scope = str(action.get("target", ""))
        expires_at = self.active_session(operator_id, action_name, scope, now)
        if expires_at is None:
            return False, None
        challenge_id = "session-" + self._digest(
            f"{operator_id}|{message_id}|{digest}"
        )
        action_json = json.dumps(
            dict(action), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        created = self._connection.execute(
            """
            INSERT OR IGNORE INTO authorized_actions(
                challenge_id, action_json, action_digest, authorized_at, state
            ) VALUES(?,?,?,?,?)
            """,
            (challenge_id, action_json, digest, now, "pending-parent"),
        ).rowcount
        self.event(
            "action_authorized_by_session"
            if created
            else "action_session_duplicate",
            operator_id=operator_id,
            action_name=action_name,
            scope=scope,
            action_digest=digest,
            challenge_id=challenge_id,
            session_expires_at=expires_at,
        )
        return created == 1, expires_at

    def close(self) -> None:
        self._connection.close()


_TOP_DELIVERY_HEADER = "TOP-DELIVERY"
_HTML_TAG = re.compile(r"<[^>]+>")
_CREDENTIAL_HINT = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|private[_-]?key)\s*[:=]"
)
_MAX_DISPLAY_FIELD = 480
_MALFORMED_OUTBOUND = (
    f"{_TOP_DELIVERY_HEADER}\n"
    "Reply unavailable: response was not valid JSON.\n"
    "Next: retry the command or send status."
)
_UNRECOGNIZED_OUTBOUND = (
    f"{_TOP_DELIVERY_HEADER}\n"
    "Reply unavailable: response could not be rendered safely.\n"
    "Next: retry the command or send status."
)


def _sanitize_display_text(value: Any, *, maximum: int = _MAX_DISPLAY_FIELD) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    text = _HTML_TAG.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    if _CREDENTIAL_HINT.search(text):
        return "[redacted]"
    if len(text) > maximum:
        return text[: maximum - 3] + "..."
    return text


_RUN_TIMESTAMP_PREFIX = re.compile(r"^\d{8}T\d{6}Z[-_]", re.ASCII)
_RUN_WORDS = {
    "2fa": "2FA",
    "api": "API",
    "comms01": "Comms-01",
    "mfa": "MFA",
    "p1": "P1",
    "pmo": "PMO",
    "qa": "QA",
    "ui": "UI",
    "ux": "UX",
}


def _friendly_run_label(value: Any) -> str:
    raw = _sanitize_display_text(value)
    if not raw:
        return "unknown run"
    stripped = _RUN_TIMESTAMP_PREFIX.sub("", raw)
    words = [word for word in re.split(r"[-_]", stripped) if word]
    if not words:
        return "unknown run"
    display = [_RUN_WORDS.get(word.lower(), word.capitalize()) for word in words]
    return " ".join(display)


def _friendly_phase_label(value: Any) -> str:
    text = _sanitize_display_text(value)
    if not text:
        return "unknown"
    if text.upper() == text:
        return text
    return text.replace("_", " ").replace("-", " ").capitalize()


def _action_description(action: Any) -> str:
    if not isinstance(action, Mapping):
        return "the requested TOP-DELIVERY action"
    name = _sanitize_display_text(action.get("action"))
    descriptions = {
        "queue_next_prompt": "Queue the next approved TOP-DELIVERY prompt",
        "create_next_prompt": "Create the next approved TOP-DELIVERY prompt",
        "retry_queueable_child": "Retry the selected queueable child task",
        "reap_terminal_child": "Reap the selected completed child task",
    }
    return descriptions.get(name, name or "the requested TOP-DELIVERY action")


def _format_blockers(blockers: Any) -> list[str]:
    if not isinstance(blockers, list) or not blockers:
        return ["none"]
    cleaned = [
        _sanitize_display_text(item)
        for item in blockers
        if _sanitize_display_text(item)
    ]
    return cleaned or ["none"]


def _format_evidence_summary(payload: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    evidence = payload.get("evidence")
    if isinstance(evidence, list) and evidence:
        paths = [
            _sanitize_display_text(item.get("path"))
            for item in evidence
            if isinstance(item, Mapping) and _sanitize_display_text(item.get("path"))
        ]
        if paths:
            if len(paths) <= 3:
                lines.append(f"Evidence: {len(paths)} file(s)")
                lines.extend(f"  - {path}" for path in paths)
            else:
                lines.append(f"Evidence: {len(paths)} files")
        return lines
    evidence_paths = payload.get("evidence_paths")
    if isinstance(evidence_paths, list) and evidence_paths:
        paths = [
            _sanitize_display_text(item)
            for item in evidence_paths
            if _sanitize_display_text(item)
        ]
        if not paths:
            return lines
        if len(paths) <= 3:
            lines.append(f"Evidence paths: {len(paths)}")
            lines.extend(f"  - {path}" for path in paths)
        else:
            lines.append(f"Evidence paths: {len(paths)} files")
    return lines


def _format_read_only_status(payload: Mapping[str, Any]) -> str:
    lines = [_TOP_DELIVERY_HEADER, f"Mode: {READ_ONLY_MODE}"]
    runs = payload.get("runs")
    if isinstance(runs, list):
        lines.append(f"Status: {_sanitize_display_text(payload.get('status', 'active'))}")
        if not runs:
            lines.append("Active runs: none")
        else:
            lines.append(f"Active runs: {len(runs)}")
            for run in runs[:8]:
                if not isinstance(run, Mapping):
                    continue
                run_id = _friendly_run_label(run.get("run_id", "unknown"))
                phase = _friendly_phase_label(run.get("phase"))
                status = _sanitize_display_text(run.get("status")) or "unknown"
                blockers = _format_blockers(run.get("blockers"))
                blocker_text = blockers[0] if blockers == ["none"] else "; ".join(blockers)
                next_action = _friendly_next_action(run.get("next_action"))
                line = f"- {run_id} | phase {phase} | {status} | blockers: {blocker_text}"
                if next_action:
                    line += f" | next: {next_action}"
                lines.append(line)
            if len(runs) > 8:
                lines.append(f"  ... and {len(runs) - 8} more")
        next_action = _friendly_next_action(payload.get("next_action"))
        if next_action:
            lines.append(f"Next: {next_action}")
        return "\n".join(lines)

    run_id = _sanitize_display_text(payload.get("run_id"))
    if run_id:
        lines.append(f"Run: {_friendly_run_label(run_id)}")
    phase = _sanitize_display_text(payload.get("phase"))
    if phase:
        lines.append(f"Phase: {_friendly_phase_label(phase)}")
    status = _sanitize_display_text(payload.get("status"))
    if status:
        lines.append(f"Status: {status}")
    requested_date = _sanitize_display_text(payload.get("requested_date"))
    if requested_date:
        lines.append(f"Date: {requested_date}")
    blockers = _format_blockers(payload.get("blockers"))
    if blockers == ["none"]:
        lines.append("Blockers: none")
    else:
        lines.append("Blockers:")
        lines.extend(f"  - {item}" for item in blockers)
    artifact = payload.get("artifact")
    if isinstance(artifact, Mapping):
        path = _sanitize_display_text(artifact.get("path"))
        digest = _sanitize_display_text(artifact.get("sha256"))
        size = _sanitize_display_text(artifact.get("size"))
        if path:
            lines.append(f"Artifact: {path}")
        if digest:
            lines.append(f"SHA-256: {digest}")
        if size:
            lines.append(f"Size: {size} bytes")
    next_action = _friendly_next_action(payload.get("next_action"))
    if next_action:
        lines.append(f"Next: {next_action}")
    lines.extend(_format_evidence_summary(payload))
    return "\n".join(lines)


def _format_read_only_error(payload: Mapping[str, Any]) -> str:
    lines = [_TOP_DELIVERY_HEADER, f"Mode: {READ_ONLY_MODE}"]
    error = payload.get("error")
    if isinstance(error, Mapping):
        message = _sanitize_display_text(error.get("message"))
        code = _sanitize_display_text(error.get("code"))
        if message:
            lines.append(f"Error: {message}")
        elif code:
            lines.append(f"Error: {code}")
    elif isinstance(error, str) and error:
        lines.append(f"Error: {_sanitize_display_text(error)}")
    next_action = _friendly_next_action(payload.get("next_action"))
    if next_action:
        lines.append(f"Next: {next_action}")
    return "\n".join(lines)


def _authorization_command(payload: Mapping[str, Any]) -> str:
    """Return the simple operator command; binding stays internal."""

    return "authorize CODE"


def _friendly_next_action(value: Any) -> str:
    """Hide the retired queue command from all operator-facing output."""

    action = _sanitize_display_text(value)
    if action == "queue-next-prompt":
        return "next"
    if action.startswith("wait and retry queue-next-prompt"):
        return action.replace("queue-next-prompt", "next")
    return action


def _format_next_action(payload: Mapping[str, Any]) -> str:
    raw_action = payload.get("next_action")
    if isinstance(raw_action, str) and raw_action.strip().startswith("authorize"):
        return _authorization_command(payload)
    return _friendly_next_action(raw_action)


def _format_commands(payload: Mapping[str, Any]) -> str:
    commands = payload.get("commands")
    if not isinstance(commands, list):
        return _UNRECOGNIZED_OUTBOUND
    visible = [
        _sanitize_display_text(command)
        for command in commands
        if _sanitize_display_text(command)
    ]
    return "\n".join(
        (
            _TOP_DELIVERY_HEADER,
            f"Available commands: {', '.join(visible)}",
        )
    )


def _format_architecture_summary(payload: Mapping[str, Any]) -> str:
    document = payload.get("architecture_summary")
    if not isinstance(document, Mapping):
        return _UNRECOGNIZED_OUTBOUND
    lines = [
        _TOP_DELIVERY_HEADER,
        f"Architecture: {_sanitize_display_text(document.get('title'))}",
        f"As of: {_sanitize_display_text(document.get('as_of'))}",
        "",
        "Current reality:",
    ]
    reality = document.get("current_reality")
    if isinstance(reality, list):
        lines.extend(f"- {_sanitize_display_text(item)}" for item in reality)
    lines.extend(("", "Master project:"))
    tree = document.get("tree")
    if isinstance(tree, list):
        sections = [item for item in tree if isinstance(item, Mapping)]
        for section_index, section in enumerate(sections):
            section_last = section_index == len(sections) - 1
            section_prefix = "└─" if section_last else "├─"
            section_id = _sanitize_display_text(section.get("id"))
            name = _sanitize_display_text(section.get("name"))
            status = _sanitize_display_text(section.get("status"))
            lines.append(f"{section_prefix} {section_id}. {name} [{status}]")
            items = section.get("items")
            if not isinstance(items, list):
                continue
            child_prefix = "   " if section_last else "│  "
            children = [item for item in items if isinstance(item, Mapping)]
            for item_index, item in enumerate(children):
                item_prefix = "└─" if item_index == len(children) - 1 else "├─"
                item_name = _sanitize_display_text(item.get("name"))
                item_status = _sanitize_display_text(item.get("status"))
                lines.append(f"{child_prefix}{item_prefix} {item_name} [{item_status}]")
    lines.extend(("", "Next: recommended"))
    path = _sanitize_display_text(payload.get("architecture_path"))
    digest = _sanitize_display_text(payload.get("architecture_sha256"))
    if path:
        lines.append(f"Source: {path}")
    if digest:
        lines.append(f"Source SHA-256: {digest}")
    return "\n".join(lines)


def _format_recommended_order(payload: Mapping[str, Any]) -> str:
    order = payload.get("recommended_order")
    if not isinstance(order, list):
        return _UNRECOGNIZED_OUTBOUND
    lines = [_TOP_DELIVERY_HEADER, "Recommended next order:"]
    for index, item in enumerate(order, start=1):
        lines.append(f"{index}. {_sanitize_display_text(item)}")
    path = _sanitize_display_text(payload.get("architecture_path"))
    if path:
        lines.append(f"Source: {path}")
    return "\n".join(lines)


def _format_trading_summary(payload: Mapping[str, Any]) -> str:
    summary = payload.get("trading_summary")
    if not isinstance(summary, Mapping):
        return _format_read_only_status(payload)
    financial = summary.get("financial")
    operational = summary.get("operational")
    lines = [
        _TOP_DELIVERY_HEADER,
        f"Trading summary: {_sanitize_display_text(summary.get('date'))}",
        "",
        "Financial:",
    ]
    if isinstance(financial, Mapping):
        labels = (
            ("trusted_closed_pnl", "Trusted closed P&L"),
            ("evidence_backed_pnl", "Broker-evidence-backed P&L"),
            ("closed_trades", "Closed trade rows"),
            ("open_trades", "Open trade rows"),
            ("wins", "Wins"),
            ("losses", "Losses"),
            ("flat_results", "Flat/zero-result rows"),
            ("missing_broker_evidence", "Missing broker evidence"),
        )
        for key, label in labels:
            if key in financial:
                value = financial.get(key)
                if key.endswith("pnl"):
                    try:
                        value = f"${float(value):.2f}"
                    except (TypeError, ValueError):
                        value = _sanitize_display_text(value)
                lines.append(f"- {label}: {_sanitize_display_text(value)}")
    breakdown = summary.get("trade_breakdown")
    if isinstance(breakdown, list) and breakdown:
        lines.append("Trade breakdown:")
        for item in breakdown:
            if not isinstance(item, Mapping):
                continue
            lines.append(
                "- "
                + _sanitize_display_text(item.get("instrument"))
                + ": "
                + _sanitize_display_text(item.get("rows"))
                + " rows, P&L $"
                + _sanitize_display_text(item.get("pnl"))
            )
    failures = summary.get("failure_breakdown")
    if isinstance(failures, list) and failures:
        lines.append("Failure breakdown:")
        for item in failures:
            if isinstance(item, Mapping):
                lines.append(
                    "- "
                    + _sanitize_display_text(item.get("rows"))
                    + " rows: "
                    + _sanitize_display_text(item.get("reason"))
                )
    lines.append("")
    lines.append("Operational:")
    if isinstance(operational, Mapping):
        labels = (
            ("service_ok", "Service preflight"),
            ("all_strategies", "Strategy state"),
            ("broker_synchronization", "Broker synchronization"),
            ("accounting_high_severity", "Accounting high-severity issues"),
            ("order_intents_today", "Order intents today"),
            ("broker_events_today", "Broker events today"),
            ("open_rows", "Open database rows"),
            ("opportunity_blocks", "Opportunity blocks"),
            ("readiness_note", "Readiness note"),
        )
        for key, label in labels:
            if key in operational:
                lines.append(f"- {label}: {_sanitize_display_text(operational.get(key))}")
    verdict = _sanitize_display_text(summary.get("verdict"))
    if verdict:
        lines.extend(("", f"Verdict: {verdict}"))
    path = _sanitize_display_text(payload.get("summary_path"))
    if path:
        lines.append(f"Source: {path}")
    return "\n".join(lines)


def _format_authorization_challenge(payload: Mapping[str, Any]) -> str:
    action_details = payload.get("action_details")
    description = _sanitize_display_text(
        payload.get("action_description") or _action_description(action_details)
    )
    run_id = payload.get("run_id")
    phase = payload.get("phase")
    expires_at = _sanitize_display_text(payload.get("expires_at"))
    command = _authorization_command(payload)
    lines = [
        _TOP_DELIVERY_HEADER,
        "2FA authorization request",
        f"Action: {description}",
    ]
    if run_id:
        lines.append(f"Run: {_friendly_run_label(run_id)}")
    if phase:
        lines.append(f"Phase: {_friendly_phase_label(phase)}")
    purpose = _sanitize_display_text(payload.get("purpose"))
    if purpose:
        lines.append(f"Effect: {purpose}")
    if expires_at:
        lines.append(f"Expires: {expires_at}")
    lines.append(f"Reply exactly: {command}")
    return "\n".join(lines)


def _format_authorization_error(payload: Mapping[str, Any]) -> str:
    code = _sanitize_display_text(payload.get("error"))
    message = _sanitize_display_text(payload.get("message"))
    next_action = _format_next_action(payload)
    lines = [_TOP_DELIVERY_HEADER, f"Mode: {AUTHORIZATION_MODE}"]
    if message:
        lines.append(f"Error: {message}")
    elif code:
        lines.append(f"Error: {code.replace('_', ' ')}")
    if next_action:
        lines.append(f"Next: {next_action}")
    return "\n".join(lines)


def _format_pending_parent_success(payload: Mapping[str, Any]) -> str:
    action_details = payload.get("action_details")
    description = _sanitize_display_text(
        payload.get("action_description") or _action_description(action_details)
    )
    run_id = payload.get("run_id")
    phase = payload.get("phase")
    if isinstance(action_details, Mapping):
        run_id = run_id or action_details.get("run_id")
        phase = phase or action_details.get("phase")
    lines = [
        _TOP_DELIVERY_HEADER,
        "2FA authorization accepted",
        f"Action: {description}",
    ]
    if run_id:
        lines.append(f"Run: {_friendly_run_label(run_id)}")
    if phase:
        lines.append(f"Phase: {_friendly_phase_label(phase)}")
    authorization_method = _sanitize_display_text(payload.get("authorization_method"))
    if authorization_method == "seven-day-session":
        lines.append("Authorization: existing seven-day Comms-01 session")
    elif authorization_method == "2fa-code":
        lines.append("Authorization: six-digit 2FA code accepted")
    session_expires_at = _sanitize_display_text(payload.get("session_expires_at"))
    if session_expires_at:
        lines.append(f"Session expires: {session_expires_at}")
    if authorization_method == "seven-day-session":
        lines.append(
            "Permission: this action is recorded; the session applies only to low-risk next requests."
        )
    else:
        lines.append("Permission: recorded for this action only.")
    lines.append("Execution: not started; no prompt has run.")
    lines.append("No production, trading, broker, or ledger action was authorized.")
    lines.append("Next: status")
    return "\n".join(lines)


def format_signal_outbound(response: str) -> str:
    """Render internal controller/adapter JSON as concise Signal-safe plain text."""

    try:
        payload = json.loads(response)
    except (TypeError, ValueError):
        return _MALFORMED_OUTBOUND
    if not isinstance(payload, Mapping):
        return _UNRECOGNIZED_OUTBOUND

    if isinstance(payload.get("commands"), list):
        return _format_commands(payload)
    if isinstance(payload.get("architecture_summary"), Mapping):
        return _format_architecture_summary(payload)
    if isinstance(payload.get("recommended_order"), list):
        return _format_recommended_order(payload)
    if isinstance(payload.get("trading_summary"), Mapping):
        return _format_trading_summary(payload)

    mode = payload.get("mode")
    if mode == AUTHORIZATION_MODE:
        if payload.get("state") == "pending-parent":
            return _format_pending_parent_success(payload)
        if isinstance(payload.get("error"), str):
            return _format_authorization_error(payload)
        if payload.get("challenge_id"):
            return _format_authorization_challenge(payload)
        return _UNRECOGNIZED_OUTBOUND

    if mode == READ_ONLY_MODE or payload.get("status") == "error":
        if payload.get("error") is not None or payload.get("status") == "error":
            return _format_read_only_error(payload)
        return _format_read_only_status(payload)

    if isinstance(payload.get("error"), str):
        return _format_authorization_error(
            {**payload, "mode": AUTHORIZATION_MODE}
        )

    return _UNRECOGNIZED_OUTBOUND


class SignalAdapter:
    """Long-running receive loop with pinned identity and durable idempotency."""

    def __init__(
        self,
        *,
        rpc: JsonRpcClient,
        controller: ControllerSocketClient,
        state_db: str | Path,
        account: str,
        allowed_sender: str,
        pinned_fingerprint: str,
        operator_id: str,
        auth_rpc: AuthClient,
        send: Callable[[str], bool] | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.rpc = rpc
        self.auth_rpc = auth_rpc
        self.account = account
        self.allowed_sender = allowed_sender
        self.pinned_fingerprint = _compact_fingerprint(pinned_fingerprint)
        self.operator_id = operator_id
        self.now = now
        self.state = ActionQueue(state_db)
        self.controller = controller
        self.policy = SignalIdentityPolicy(
            approved_sender_id=allowed_sender,
            pinned_identity_fingerprint=self.pinned_fingerprint,
        )
        self.bridge = SignalBridge(
            controller,
            self.policy,
            state_db,
            max_messages=30,
            window_seconds=60.0,
        )
        self.execution_limiter = BoundedRateLimiter(5, 60.0)
        self._send = send or self._send_rpc

    def _send_rpc(self, message: str) -> bool:
        result = self.rpc.call(
            "send",
            {
                "account": self.account,
                "recipient": [self.allowed_sender],
                "message": message,
            },
            timeout=15.0,
        )
        if not isinstance(result, Mapping):
            return False
        results = result.get("results")
        if isinstance(results, list):
            return any(
                isinstance(item, Mapping)
                and (item.get("type") == "SUCCESS" or item.get("success") is True)
                for item in results
            )
        return result.get("type") == "SUCCESS" or result.get("success") is True

    def verify_identity(self) -> str:
        result = self.rpc.call("listIdentities", {"account": self.account})
        if not isinstance(result, list):
            raise RpcError("listIdentities returned malformed data")
        for identity in result:
            if not isinstance(identity, Mapping):
                continue
            if identity.get("number") != self.allowed_sender:
                continue
            observed = _compact_fingerprint(str(identity.get("fingerprint", "")))
            if observed != self.pinned_fingerprint:
                raise PermissionError("pinned Signal identity changed")
            trust = str(identity.get("trustLevel", "unknown"))
            if trust != "TRUSTED_VERIFIED":
                LOGGER.warning("pinned Signal identity is %s", trust)
            return trust
        raise PermissionError("allowlisted Signal identity is not present")

    @staticmethod
    def _data_envelope(raw: Any) -> SignalEnvelope | None:
        if not isinstance(raw, Mapping):
            return None
        envelope = raw.get("envelope", raw)
        if not isinstance(envelope, Mapping):
            return None
        data = envelope.get("dataMessage")
        if not isinstance(data, Mapping):
            return None
        text = data.get("message")
        if not isinstance(text, str) or not text:
            return None
        sender = envelope.get("sourceNumber") or envelope.get("source")
        if not isinstance(sender, str) or not sender:
            return None
        timestamp = data.get("timestamp") or envelope.get("timestamp")
        if not isinstance(timestamp, (int, float, str)):
            return None
        device = envelope.get("sourceDevice", 1)
        source_uuid = envelope.get("sourceUuid", sender)
        message_id = f"signal:{source_uuid}:{device}:{timestamp}"
        group = data.get("groupInfo") is not None or envelope.get("groupInfo") is not None
        return SignalEnvelope(
            message_id=message_id,
            sender_id=sender,
            # The transport envelope does not carry the safety number.  The
            # adapter replaces this marker only after listIdentities has
            # matched the pinned key in _authorized_envelope().
            identity_fingerprint="transport-unverified",
            text=text,
            is_group=bool(group),
        )

    def _authorized_envelope(self, envelope: SignalEnvelope) -> SignalEnvelope:
        return SignalEnvelope(
            message_id=envelope.message_id,
            sender_id=envelope.sender_id,
            identity_fingerprint=self.pinned_fingerprint,
            text=envelope.text.lstrip("/") if envelope.text.startswith("/") else envelope.text,
            is_group=envelope.is_group,
        )

    def _cached_response(self, message_id: str) -> str | None:
        row = self.state._connection.execute(
            "SELECT detail_json FROM adapter_events WHERE event_type='outbound_cached' AND message_id_digest=? ORDER BY event_id DESC LIMIT 1",
            (self.state._digest(message_id),),
        ).fetchone()
        if row is None:
            return None
        try:
            return str(json.loads(row[0])["response"])
        except (KeyError, TypeError, ValueError):
            return None

    def _cache_response(self, message_id: str, response: str) -> None:
        self.state.event("outbound_cached", message_id=message_id, response=response)

    def _active_run_context(self) -> dict[str, Any] | None:
        """Read the current active run from the controller, never a stale constant."""

        try:
            raw = self.controller.handle_text("active-runs", self.allowed_sender)
            payload = json.loads(raw)
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            LOGGER.warning("active run lookup failed: %s", exc)
            return None
        if not isinstance(payload, Mapping):
            return None
        runs = payload.get("runs")
        if not isinstance(runs, list):
            return None
        for run in runs:
            if not isinstance(run, Mapping):
                continue
            run_id = run.get("run_id")
            if isinstance(run_id, str) and run_id:
                return dict(run)
        return None

    def _create_challenge(self, envelope: SignalEnvelope) -> str:
        run = self._active_run_context()
        if run is None:
            return _execution_error(
                "no_active_run",
                message=(
                    "There is no active TOP-DELIVERY run to authorize. "
                    "No authorization request was created."
                ),
                next_action="status",
            )
        run_id = str(run["run_id"])
        action = canonical_action(
            {
                "action": "queue_next_prompt",
                "target": "comms-01-control-plane",
                "run_id": run_id,
                "dry_run": True,
            },
            active_run_id=run_id,
        )
        digest = action_digest(action, active_run_id=run_id)
        session_authorized, session_expires_at = self.state.authorize_from_session(
            self.operator_id,
            action,
            digest,
            envelope.message_id,
            self.now(),
        )
        if session_authorized:
            self.state.event(
                "action_queued",
                message_id=envelope.message_id,
                authorization_method="seven-day-session",
            )
            return json.dumps(
                {
                    "mode": AUTHORIZATION_MODE,
                    "action": "queue_next_prompt",
                    "action_description": _action_description(action),
                    "action_details": action,
                    "authorization": "accepted",
                    "authorization_method": "seven-day-session",
                    "execution": "not_started",
                    "next_action": "status",
                    "phase": run.get("phase"),
                    "run_id": run_id,
                    "session_expires_at": session_expires_at,
                    "state": "pending-parent",
                    "message": (
                        "Active seven-day Comms-01 session used. Permission was "
                        "recorded for this action; no prompt has executed."
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        result = self.auth_rpc.call(
            "POST /v1/challenges",
            {"action_id": action["action"], "action_hash": digest, "scope": action["target"]},
        )
        if not isinstance(result, Mapping):
            raise RpcError("authorization challenge response is malformed")
        challenge_id = result.get("challenge_id")
        expires_at = result.get("expires_at")
        if not isinstance(challenge_id, str) or not isinstance(expires_at, str):
            raise RpcError("authorization challenge response is incomplete")
        self.state.remember_challenge(challenge_id, action, digest)
        self.state.event("challenge_created", message_id=envelope.message_id, challenge_id=challenge_id)
        return json.dumps(
            {
                "mode": AUTHORIZATION_MODE,
                "action": "queue_next_prompt",
                "action_description": _action_description(action),
                "action_details": action,
                "action_digest": digest,
                "challenge_id": challenge_id,
                "expires_at": expires_at,
                "phase": run.get("phase"),
                "purpose": (
                    "Records permission to queue the next approved prompt; "
                    "it does not execute a prompt."
                ),
                "run_id": run_id,
                "reply": "authorize CODE",
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def _bare_code_guidance(self) -> str:
        now = self.now()
        pending = self.state.latest_pending_action(now)
        if pending is None:
            if self.state.has_stale_pending_challenge(now):
                message = (
                    "No active authorization request remains; the previous "
                    "request expired. Send next for a new request."
                )
            else:
                message = (
                    "A bare six-digit code is not a command. Send "
                    "next first, then reply with authorize CODE."
                )
            return _execution_error(
                "bare_code_rejected",
                message=message,
                next_action="next",
            )
        challenge_id, digest, action = pending
        return _execution_error(
            "bare_code_rejected",
            message=(
                "Use authorize CODE, not the six-digit code by itself. "
                "CODE must be the current authenticator value."
            ),
            next_action="authorize CODE",
            action_description=_action_description(action),
            action_details=action,
            run_id=action.get("run_id"),
            phase=action.get("phase"),
        )

    def _authorize(self, envelope: SignalEnvelope, words: list[str]) -> str:
        action_details: dict[str, Any] | None = None
        if len(words) == 2:
            code = words[1]
            pending = self.state.latest_pending_action(self.now())
            if pending is None:
                return _execution_error(
                    "challenge_required",
                    message=(
                        "There is no active authorization request. "
                        "Send next first."
                    ),
                    next_action="next",
                )
            challenge_id, digest, action_details = pending
        elif len(words) == 4:
            # Keep the old form temporarily so already-issued prompts remain
            # usable, while the operator-facing protocol uses authorize CODE.
            challenge_id, digest, code = words[1], words[2], words[3]
            action_details = self.state.action_for_challenge(challenge_id)
        else:
            return _execution_error(
                "authorize_syntax",
                message=(
                    "Use exactly: authorize CODE, after next. "
                    "CODE is your current six-digit authenticator value."
                ),
                next_action="next",
            )
        if not _HEX64.fullmatch(digest):
            return _execution_error(
                "action_hash_invalid",
                message="action digest must be a lowercase 64-character hex SHA-256",
                next_action="next",
            )
        if not _SIX_DIGIT.fullmatch(code):
            return _execution_error(
                "code_invalid",
                message="authorization code must be exactly six ASCII digits",
                next_action="authorize CODE",
            )
        stored_digest = self.state.pending_challenge_digest(challenge_id)
        if stored_digest is None:
            return _authorization_service_error("challenge_unknown")
        if stored_digest != digest:
            return _authorization_service_error("action_hash_mismatch")
        if self.state.is_authorized(challenge_id):
            return _authorization_service_error("authorization_duplicate")
        try:
            result = self.auth_rpc.call(
                f"POST /v1/challenges/{challenge_id}/authorize",
                {"code": code, "action_hash": digest},
            )
        except AuthServiceError as exc:
            return _authorization_service_error(exc.error_code)
        except RpcError:
            return _authorization_service_error("authorization_service_unavailable")
        if not isinstance(result, Mapping) or result.get("authorized") is not True:
            return _authorization_service_error("authorization_rejected")
        created = self.state.authorize(challenge_id, digest, result)
        if not created:
            return _authorization_service_error("authorization_duplicate")
        action_details = action_details or self.state.action_for_challenge(challenge_id) or {}
        session_expires_at = self.state.grant_session(
            self.operator_id,
            str(action_details.get("action", "")),
            str(action_details.get("target", "")),
            challenge_id,
            self.now(),
        )
        self.state.event("action_queued", message_id=envelope.message_id, challenge_id=challenge_id)
        return json.dumps(
            {
                "mode": AUTHORIZATION_MODE,
                "action": "queue_next_prompt",
                "action_description": _action_description(action_details),
                "action_details": action_details,
                "authorization": "accepted",
                "authorization_method": "2fa-code",
                "challenge_id": challenge_id,
                "execution": "not_started",
                "next_action": "status",
                "phase": action_details.get("phase"),
                "run_id": action_details.get("run_id"),
                "session_expires_at": session_expires_at,
                "state": "pending-parent",
                "message": (
                    "2FA accepted. Permission was recorded for this action; "
                    "no prompt has executed."
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def process_envelope(self, raw: Any) -> tuple[str, str] | None:
        envelope = self._data_envelope(raw)
        if envelope is None:
            return None
        if envelope.sender_id != self.allowed_sender or envelope.is_group:
            self.state.event("message_rejected", message_id=envelope.message_id, reason="sender_or_group")
            return None
        authorized = self._authorized_envelope(envelope)
        decision = self.policy.evaluate(authorized)
        if not decision.allowed:
            self.state.event("message_rejected", message_id=envelope.message_id, reason=decision.code)
            return None
        cached = self._cached_response(authorized.message_id)
        if cached is not None:
            return authorized.message_id, cached
        text = authorized.text.strip()
        words = text.split()
        read_only_aliases = {
            "architecture summary": "architecture-summary",
            "type recommended": "recommended",
            "trading summary": "trading-summary",
        }
        if _SIX_DIGIT.fullmatch(text):
            response = self._bare_code_guidance()
        elif words and words[0] == "commands" and len(words) == 1:
            response = json.dumps(
                {
                    "mode": READ_ONLY_MODE,
                    "status": "ready",
                    "commands": list(_SIGNAL_COMMANDS),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        elif text in read_only_aliases:
            response = self.controller.handle_text(
                read_only_aliases[text], authorized.sender_id, is_group=False
            )
        elif words and words[0] in _EXECUTION_COMMANDS:
            if not self.execution_limiter.allow(authorized.sender_id):
                response = _execution_error(
                    "rate_limited",
                    message=(
                        "Too many 2FA commands were sent in the last minute. "
                        "Wait before sending next or authorize again."
                    ),
                    next_action="wait and retry next or authorize",
                )
            elif words[0] in {"next", "queue-next-prompt"} and len(words) == 1:
                response = self._create_challenge(authorized)
            elif words[0] == "authorize":
                response = self._authorize(authorized, words)
            else:
                response = _execution_error(
                    "command_syntax",
                    message=(
                        "2FA commands must be exactly next or "
                        "authorize <challenge-id> <action-digest> <6-digit-code>."
                    ),
                    next_action="next",
                )
        else:
            response = self.bridge.handle(authorized)
        self._cache_response(authorized.message_id, response)
        return authorized.message_id, response

    def flush(self, item: tuple[str, str] | None) -> bool:
        if item is None:
            return True
        message_id, response = item
        outbound = format_signal_outbound(response)
        try:
            sent = self._send(outbound)
        except Exception:
            LOGGER.exception("Signal reply failed")
            sent = False
        self.state.event("reply_sent" if sent else "reply_failed", message_id=message_id)
        return sent

    def receive_once(self, *, timeout: int = 10, max_messages: int = 20) -> int:
        result = self.rpc.call(
            "receive",
            # signal-cli is running in single-account mode; its receive RPC
            # rejects an account field and uses the daemon's configured account.
            {"timeout": timeout, "maxMessages": max_messages},
            timeout=timeout + 15,
        )
        if not isinstance(result, list):
            raise RpcError("rpc receive returned a malformed result")
        count = 0
        for raw in result:
            item = self.process_envelope(raw)
            if item is not None:
                count += 1
                self.flush(item)
        return count

    def run_forever(self) -> None:
        identity_checked_at = 0.0
        while True:
            if self.now() - identity_checked_at >= 300:
                try:
                    trust = self.verify_identity()
                except RpcError as exc:
                    # A daemon restart can make its localhost RPC briefly
                    # unavailable.  Keep the adapter alive and retry without
                    # treating a transient dependency race as a bad identity.
                    LOGGER.warning("Signal identity check retry: %s", exc)
                    time.sleep(5)
                    continue
                LOGGER.info("Signal identity pinned; trust=%s", trust)
                identity_checked_at = self.now()
            try:
                self.receive_once()
            except (RpcError, OSError) as exc:
                LOGGER.warning("Signal receive retry: %s", exc)
                time.sleep(5)

    def close(self) -> None:
        self.bridge.close()
        self.state.close()


def _build_adapter() -> SignalAdapter:
    account = os.environ["TOP_DELIVERY_SIGNAL_ACCOUNT"]
    sender = os.environ["TOP_DELIVERY_SIGNAL_RECIPIENT"]
    operator_id = os.environ.get("TOP_DELIVERY_OPERATOR_ID", "operator-01")
    signal_rpc = JsonRpcClient(os.environ.get("TOP_DELIVERY_SIGNAL_RPC", "http://127.0.0.1:8080/api/v1/rpc"))
    auth_rpc = AuthClient(
        os.environ.get("TOP_DELIVERY_AUTH_RPC", "http://127.0.0.1:8787"),
        os.environ["TOP_DELIVERY_AUTH_INTERNAL_TOKEN"],
    )
    return SignalAdapter(
        rpc=signal_rpc,
        auth_rpc=auth_rpc,
        controller=ControllerSocketClient(
            os.environ.get("TOP_DELIVERY_CONTROLLER_SOCKET", "/run/top-delivery/controller.sock"),
            operator_id,
            transport_sender=sender,
        ),
        state_db=os.environ.get("TOP_DELIVERY_SIGNAL_DB", "/var/lib/top-delivery/signal.sqlite3"),
        account=account,
        allowed_sender=sender,
        pinned_fingerprint=os.environ["TOP_DELIVERY_SIGNAL_FINGERPRINT"],
        operator_id=operator_id,
    )


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("TOP_DELIVERY_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    adapter = _build_adapter()
    try:
        adapter.run_forever()
    finally:
        adapter.close()


if __name__ == "__main__":
    main()
