"""Deterministic, read-only TOP-DELIVERY controller primitives.

This module deliberately has no process, network, broker, or operational
database integration.  The only database use is the local append-only audit
and inert queue store.  All delivery decisions are made from files below the
configured read-only root.
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import math
import os
import re
import shlex
import sqlite3
import threading
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Collection, Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo


LOGGER = logging.getLogger(__name__)

COMMANDS: tuple[str, ...] = (
    "status",
    "architecture-summary",
    "recommended",
    "artifact lookup",
    "active-runs",
    "latest-evidence",
    "next-step",
    "trading-summary",
)

READ_ONLY_MODE = "read-only"
READ_ONLY_COMMANDS_TEXT = (
    "status [run_id], architecture-summary, recommended, active-runs, "
    "latest-evidence [run_id], next-step [run_id], "
    "trading-summary [YYYY-MM-DD], artifact lookup [run_id] <path>"
)
AUTHORIZATION_COMMANDS_TEXT = (
    "next (creates a 2FA challenge) and authorize CODE "
    "(submits the code for the current pending challenge) are separate "
    "2FA commands handled by the Signal adapter, not read-only "
    "controller commands"
)

_COMMAND_WORDS = frozenset(
    {
        "status",
        "architecture-summary",
        "recommended",
        "artifact",
        "active-runs",
        "latest-evidence",
        "next-step",
        "trading-summary",
    }
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_TARGET_RE = re.compile(r"^disposable-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$")
_TERMINAL_CHILD_STATES = frozenset(
    {
        "cancelled",
        "canceled",
        "complete",
        "completed",
        "done",
        "error",
        "failed",
        "success",
        "succeeded",
        "terminated",
    }
)
_TERMINAL_RUN_STATES = frozenset(
    {
        "cancelled",
        "canceled",
        "complete",
        "completed",
        "failed",
        "succeeded",
        "success",
        "terminated",
    }
)


class ControllerError(Exception):
    """Base class for expected, controller-authored failures."""

    code = "controller-error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CommandRejectedError(ControllerError):
    code = "command-rejected"


class UnauthorizedSenderError(CommandRejectedError):
    code = "unauthorized-sender"


class GroupMessageRejectedError(CommandRejectedError):
    code = "group-message-rejected"


class UnknownCommandError(CommandRejectedError):
    code = "unknown-command"


class InvalidCommandError(CommandRejectedError):
    code = "invalid-command"


class TargetRejectedError(ControllerError):
    code = "target-rejected"


class PathRejectedError(ControllerError):
    code = "path-rejected"


class ConfigurationError(ControllerError):
    code = "configuration-error"


class AuditError(ControllerError):
    code = "audit-error"


class ChildRegistryError(ControllerError):
    code = "child-registry-error"


class RateLimitExceededError(ControllerError):
    code = "rate-limited"

    def __init__(self, retry_after: float) -> None:
        self.retry_after = max(0.0, retry_after)
        super().__init__("rate limit exceeded")


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [str(key) for key in value]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ControllerError("response contains non-serializable data") from exc


def response_json(value: Mapping[str, Any]) -> str:
    """Return the one-line, byte-stable representation sent to Signal."""

    return _canonical_json(value)


def _normalization_is_stable(value: str) -> bool:
    return (
        value == unicodedata.normalize("NFC", value)
        and value == unicodedata.normalize("NFKC", value)
    )


def _validate_identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or not _normalization_is_stable(value):
        raise ControllerError(f"{label} is invalid")
    if not value.isascii() or not _IDENTIFIER_RE.fullmatch(value):
        raise ControllerError(f"{label} is invalid")
    return value


def validate_target_id(target_id: str) -> str:
    """Validate the intentionally small positive target allow-list.

    There is no alias expansion.  A target must be the fixed control-plane
    identifier or an ASCII disposable identifier with a non-empty suffix.
    """

    if not isinstance(target_id, str) or not target_id:
        raise TargetRejectedError("target is not an allowed identifier")
    if not _normalization_is_stable(target_id) or not target_id.isascii():
        raise TargetRejectedError("target is not an allowed identifier")
    if (
        "/" in target_id
        or "\\" in target_id
        or "\x00" in target_id
        or target_id in {".", ".."}
        or ":" in target_id
    ):
        raise TargetRejectedError("target is not an allowed identifier")
    if target_id == "comms-01-control-plane" or _TARGET_RE.fullmatch(target_id):
        return target_id
    raise TargetRejectedError("target is not an allowed identifier")


def is_allowed_target(target_id: str) -> bool:
    try:
        validate_target_id(target_id)
    except TargetRejectedError:
        return False
    return True


@dataclass(frozen=True)
class ParsedCommand:
    command: str
    args: tuple[str, ...]
    sender_id: str

    @property
    def name(self) -> str:
        return self.command


class CommandParser:
    """Closed parser for the controller's six commands."""

    def __init__(
        self,
        authorized_senders: Collection[str] | None = None,
        *,
        allowed_senders: Collection[str] | None = None,
    ) -> None:
        if authorized_senders is not None and allowed_senders is not None:
            raise ConfigurationError("configure one sender allow-list")
        senders = (
            authorized_senders
            if authorized_senders is not None
            else (allowed_senders if allowed_senders is not None else ())
        )
        if isinstance(senders, str):
            senders = (senders,)
        self._authorized_senders = frozenset(
            sender for sender in senders if isinstance(sender, str) and sender
        )

    @property
    def authorized_senders(self) -> frozenset[str]:
        return self._authorized_senders

    def parse(
        self,
        text: str,
        sender_id: str,
        *,
        is_group: bool = False,
        group: bool = False,
        group_id: str | None = None,
    ) -> ParsedCommand:
        if is_group or group or group_id is not None:
            raise GroupMessageRejectedError("group messages are not accepted")
        if not isinstance(sender_id, str) or sender_id not in self._authorized_senders:
            raise UnauthorizedSenderError("sender is not authorized")
        if not isinstance(text, str) or not text or len(text) > 512:
            raise InvalidCommandError("command has an invalid length")
        try:
            words = shlex.split(text, comments=False, posix=True)
        except ValueError as exc:
            raise InvalidCommandError("command quoting is invalid") from exc
        if not words or words[0] not in _COMMAND_WORDS:
            raise UnknownCommandError("command is not supported")

        first = words[0]
        if first == "artifact":
            if len(words) < 2 or words[1] != "lookup":
                raise UnknownCommandError("command is not supported")
            command = "artifact lookup"
            args = words[2:]
            if len(args) not in {1, 2}:
                raise InvalidCommandError("artifact lookup takes one or two arguments")
        elif first in {"status", "latest-evidence", "next-step", "trading-summary"}:
            command = first
            args = words[1:]
            if len(args) > 1:
                raise InvalidCommandError(f"{command} takes zero or one argument")
        else:
            command = first
            args = words[1:]
            if args:
                raise InvalidCommandError(f"{command} takes no arguments")

        return ParsedCommand(command=command, args=tuple(args), sender_id=sender_id)

    parse_command = parse


@dataclass(frozen=True)
class ControllerConfig:
    root: Path
    authorized_senders: frozenset[str] = field(default_factory=frozenset)
    audit_db: Path | str = ":memory:"
    routing_path: Path | None = None
    default_run_id: str | None = None
    rate_limit_count: int = 30
    rate_limit_window_seconds: float = 60.0

    def __post_init__(self) -> None:
        root = Path(self.root)
        object.__setattr__(self, "root", root)
        if isinstance(self.authorized_senders, str):
            senders = frozenset({self.authorized_senders})
        else:
            senders = frozenset(self.authorized_senders)
        object.__setattr__(self, "authorized_senders", senders)
        if self.routing_path is not None:
            object.__setattr__(self, "routing_path", Path(self.routing_path))
        if self.default_run_id is not None:
            _validate_identifier(self.default_run_id, "default run id")


class AuditLog:
    """A local append-only audit store and inert queue backing store."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = path
        if str(path) != ":memory:":
            path_obj = Path(path)
            try:
                path_obj.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise AuditError("audit database directory is unavailable") from exc
            connect_path = str(path_obj)
        else:
            connect_path = ":memory:"
        try:
            self._connection = sqlite3.connect(
                connect_path,
                check_same_thread=False,
                isolation_level="DEFERRED",
            )
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._initialize()
        except sqlite3.Error as exc:
            raise AuditError("audit database could not be initialized") from exc
        self._lock = threading.RLock()

    def _initialize(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_ns INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit log is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit log is append-only');
            END;
            CREATE TABLE IF NOT EXISTS inert_queue (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL UNIQUE,
                target_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_ns INTEGER NOT NULL
            );
            """
        )
        self._connection.commit()

    def append(self, event_type: str, data: Mapping[str, Any]) -> int:
        if not isinstance(event_type, str) or not event_type:
            raise AuditError("audit event type is invalid")
        payload = _canonical_json(dict(data))
        with self._lock:
            try:
                cursor = self._connection.execute(
                    """
                    INSERT INTO audit_events
                        (occurred_ns, event_type, event_json)
                    VALUES (?, ?, ?)
                    """,
                    (time.time_ns(), event_type, payload),
                )
                self._connection.commit()
                return int(cursor.lastrowid)
            except sqlite3.Error as exc:
                self._connection.rollback()
                raise AuditError("audit event could not be appended") from exc

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            try:
                rows = self._connection.execute(
                    """
                    SELECT event_id, occurred_ns, event_type, event_json
                    FROM audit_events
                    ORDER BY event_id
                    """
                ).fetchall()
            except sqlite3.Error as exc:
                raise AuditError("audit events could not be read") from exc
        result: list[dict[str, Any]] = []
        for event_id, occurred_ns, event_type, event_json in rows:
            result.append(
                {
                    "event_id": int(event_id),
                    "occurred_ns": int(occurred_ns),
                    "event_type": str(event_type),
                    "data": json.loads(event_json),
                }
            )
        return result

    def enqueue(
        self,
        *,
        idempotency_key: str,
        target_id: str,
        payload_json: str,
    ) -> bool:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ControllerError("idempotency key is required")
        try:
            validate_target_id(target_id)
        except TargetRejectedError:
            raise
        with self._lock:
            try:
                cursor = self._connection.execute(
                    """
                    INSERT OR IGNORE INTO inert_queue
                        (idempotency_key, target_id, payload_json, created_ns)
                    VALUES (?, ?, ?, ?)
                    """,
                    (idempotency_key, target_id, payload_json, time.time_ns()),
                )
                self._connection.commit()
                return cursor.rowcount == 1
            except sqlite3.Error as exc:
                self._connection.rollback()
                raise AuditError("inert queue item could not be recorded") from exc

    def queue_items(self) -> list[dict[str, Any]]:
        with self._lock:
            try:
                rows = self._connection.execute(
                    """
                    SELECT item_id, idempotency_key, target_id, payload_json,
                           created_ns
                    FROM inert_queue
                    ORDER BY item_id
                    """
                ).fetchall()
            except sqlite3.Error as exc:
                raise AuditError("inert queue could not be read") from exc
        return [
            {
                "item_id": int(item_id),
                "idempotency_key": str(idempotency_key),
                "target_id": str(target_id),
                "payload": json.loads(payload_json),
                "created_ns": int(created_ns),
                "state": "pending",
            }
            for item_id, idempotency_key, target_id, payload_json, created_ns in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@dataclass(frozen=True)
class QueueReceipt:
    idempotency_key: str
    target_id: str
    created: bool
    state: str = "pending"

    @property
    def accepted(self) -> bool:
        return True


class InertQueue:
    """Idempotent storage only; this class intentionally has no executor."""

    def __init__(self, audit: AuditLog | Path | str | None = None) -> None:
        self._owns_audit = not isinstance(audit, AuditLog)
        self._audit = audit if isinstance(audit, AuditLog) else AuditLog(
            ":memory:" if audit is None else audit
        )

    def enqueue(
        self,
        target_id: str,
        payload: Mapping[str, Any] | str,
        *,
        idempotency_key: str,
    ) -> QueueReceipt:
        validate_target_id(target_id)
        if isinstance(payload, str):
            payload_value: Any = {"command": payload}
        else:
            payload_value = dict(payload)
        payload_json = _canonical_json(payload_value)
        created = self._audit.enqueue(
            idempotency_key=idempotency_key,
            target_id=target_id,
            payload_json=payload_json,
        )
        if created:
            self._audit.append(
                "queue-enqueued",
                {
                    "idempotency_key": idempotency_key,
                    "target_id": target_id,
                },
            )
        return QueueReceipt(
            idempotency_key=idempotency_key,
            target_id=target_id,
            created=created,
        )

    put = enqueue

    def pending(self) -> list[dict[str, Any]]:
        return self._audit.queue_items()

    def close(self) -> None:
        if self._owns_audit:
            self._audit.close()


class RateLimiter:
    """A deterministic-in-behaviour sliding-window facility with an injected clock."""

    def __init__(
        self,
        limit: int = 30,
        window_seconds: float = 60.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit < 1 or not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ConfigurationError("rate-limit settings are invalid")
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._events: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True

    def require(self, key: str) -> None:
        if self.allow(key):
            return
        with self._lock:
            events = self._events.get(key, ())
            retry_after = (
                self.window_seconds - (self._clock() - events[0])
                if events
                else self.window_seconds
            )
        raise RateLimitExceededError(retry_after)

    check = allow


@dataclass(frozen=True)
class ChildRecord:
    child_id: str
    parent_run_id: str
    status: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


class ChildRegistry:
    """In-memory child metadata; no child process is ever started or inspected."""

    def __init__(self, audit: AuditLog | None = None) -> None:
        self._audit = audit
        self._children: dict[str, ChildRecord] = {}
        self._lock = threading.RLock()

    def register_child(
        self,
        child_id: str,
        parent_run_id: str,
        *,
        status: str = "pending",
        metadata: Mapping[str, Any] | None = None,
    ) -> ChildRecord:
        try:
            _validate_identifier(child_id, "child id")
            _validate_identifier(parent_run_id, "parent run id")
        except ControllerError as exc:
            raise ChildRegistryError(exc.message) from exc
        normalized_status = str(status).strip().lower() or "pending"
        record = ChildRecord(
            child_id=child_id,
            parent_run_id=parent_run_id,
            status=normalized_status,
            metadata=dict(metadata or {}),
        )
        with self._lock:
            existing = self._children.get(child_id)
            if existing is not None:
                if existing != record:
                    raise ChildRegistryError("child id is already registered")
                return existing
            self._children[child_id] = record
        if self._audit is not None:
            self._audit.append(
                "child-registered",
                {
                    "child_id": child_id,
                    "parent_run_id": parent_run_id,
                    "status": normalized_status,
                },
            )
        return record

    register = register_child

    def set_status(self, child_id: str, status: str) -> ChildRecord:
        with self._lock:
            existing = self._children.get(child_id)
            if existing is None:
                raise ChildRegistryError("child is not registered")
            updated = ChildRecord(
                child_id=existing.child_id,
                parent_run_id=existing.parent_run_id,
                status=str(status).strip().lower() or "pending",
                metadata=dict(existing.metadata),
            )
            self._children[child_id] = updated
        if self._audit is not None:
            self._audit.append(
                "child-status",
                {"child_id": child_id, "status": updated.status},
            )
        return updated

    update_status = set_status

    def list_children(self, parent_run_id: str | None = None) -> list[ChildRecord]:
        with self._lock:
            records = list(self._children.values())
        if parent_run_id is not None:
            records = [item for item in records if item.parent_run_id == parent_run_id]
        return sorted(records, key=lambda item: item.child_id)

    children = list_children

    def cleanup_terminal_children(self, parent_run_id: str | None = None) -> tuple[str, ...]:
        with self._lock:
            removable = [
                item.child_id
                for item in self._children.values()
                if item.status in _TERMINAL_CHILD_STATES
                and (parent_run_id is None or item.parent_run_id == parent_run_id)
            ]
            for child_id in removable:
                del self._children[child_id]
        removed = tuple(sorted(removable))
        if removed and self._audit is not None:
            self._audit.append(
                "child-terminal-cleanup",
                {"child_ids": list(removed), "parent_run_id": parent_run_id},
            )
        return removed

    cleanup_terminal = cleanup_terminal_children


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    phase: str | None
    status: str
    evidence_paths: tuple[str, ...]
    blockers: tuple[str, ...]
    next_action: str | None
    artifact_paths: tuple[str, ...]
    source: Path


def _strip_yaml_comment(value: str) -> str:
    quoted: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted == '"':
            escaped = True
            continue
        if char in {"'", '"'}:
            if quoted == char:
                quoted = None
            elif quoted is None:
                quoted = char
        elif char == "#" and quoted is None and (
            index == 0 or value[index - 1].isspace()
        ):
            return value[:index].rstrip()
    return value.rstrip()


def _yaml_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return None
    if value in {"null", "Null", "NULL", "~"}:
        return None
    if value in {"true", "True", "TRUE"}:
        return True
    if value in {"false", "False", "FALSE"}:
        return False
    if value.startswith(("'", '"')) and value.endswith(value[0]):
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value[1:-1]
    if value.startswith(("[", "{")):
        for parser in (json.loads, ast.literal_eval):
            try:
                return parser(value)
            except (TypeError, ValueError, SyntaxError, json.JSONDecodeError):
                continue
    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value)
        except ValueError:
            pass
    if re.fullmatch(r"-?(?:\d+\.\d*|\d*\.\d+)", value):
        try:
            return float(value)
        except ValueError:
            pass
    return value


def _yaml_key_value(value: str) -> tuple[str, str] | None:
    match = re.match(r"^([^:][^:]*):(.*)$", value)
    if match is None:
        return None
    key = match.group(1).strip()
    if not key:
        return None
    return key, match.group(2).strip()


def _parse_simple_yaml(text: str) -> Any:
    """Parse the small YAML subset used by routing manifests.

    It intentionally does not implement YAML tags, anchors, or executable
    constructs.  JSON is attempted before this parser by the document reader.
    """

    lines: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip())]:
            raise ValueError("tabs are not supported in routing YAML")
        content = _strip_yaml_comment(raw_line).strip()
        if not content:
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        lines.append((indent, content))
    if not lines:
        return {}

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(lines) or lines[index][0] < indent:
            return {}, index
        if lines[index][0] != indent:
            raise ValueError("invalid YAML indentation")
        is_list = lines[index][1] == "-" or lines[index][1].startswith("- ")
        output: Any = [] if is_list else {}
        while index < len(lines):
            current_indent, content = lines[index]
            if current_indent < indent:
                break
            if current_indent != indent:
                raise ValueError("invalid YAML indentation")
            if is_list:
                if not (content == "-" or content.startswith("- ")):
                    break
                item = content[1:].strip()
                index += 1
                if not item:
                    if index < len(lines) and lines[index][0] > indent:
                        child_indent = lines[index][0]
                        parsed, index = parse_block(index, child_indent)
                    else:
                        parsed = None
                    output.append(parsed)
                    continue
                key_value = _yaml_key_value(item)
                if key_value is None:
                    output.append(_yaml_scalar(item))
                    continue
                key, raw_value = key_value
                item_dict: dict[str, Any] = {
                    key: _yaml_scalar(raw_value) if raw_value else None
                }
                if index < len(lines) and lines[index][0] > indent:
                    child_indent = lines[index][0]
                    parsed, index = parse_block(index, child_indent)
                    if raw_value:
                        if isinstance(parsed, Mapping):
                            item_dict.update(parsed)
                    elif isinstance(parsed, Mapping):
                        item_dict[key] = parsed
                    else:
                        item_dict[key] = parsed
                output.append(item_dict)
            else:
                if content.startswith("- ") or content == "-":
                    break
                key_value = _yaml_key_value(content)
                if key_value is None:
                    raise ValueError("mapping entry is invalid")
                key, raw_value = key_value
                index += 1
                if raw_value:
                    output[key] = _yaml_scalar(raw_value)
                elif index < len(lines) and lines[index][0] > indent:
                    child_indent = lines[index][0]
                    output[key], index = parse_block(index, child_indent)
                else:
                    output[key] = None
        return output, index

    parsed, position = parse_block(0, lines[0][0])
    if position != len(lines):
        raise ValueError("trailing YAML content")
    return parsed


def _read_document(path: Path) -> Any:
    data = path.read_bytes()
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _parse_simple_yaml(data.decode("utf-8"))


class ArtifactStore:
    """Read-only import and hashing of manifests and declared artifacts."""

    def __init__(self, root: Path) -> None:
        try:
            resolved = root.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ConfigurationError("configured root is unavailable") from exc
        if not resolved.is_dir():
            raise ConfigurationError("configured root is not a directory")
        self.root = resolved

    def _safe_relative(self, value: str) -> Path:
        if not isinstance(value, str) or not value or not _normalization_is_stable(value):
            raise PathRejectedError("path is not a stable relative path")
        if (
            not value.isascii()
            or "\x00" in value
            or "\\" in value
            or value.startswith("/")
            or re.match(r"^[A-Za-z]:", value) is not None
        ):
            raise PathRejectedError("path is not a stable relative path")
        parts = value.split("/")
        if any(not part or part in {".", ".."} for part in parts):
            raise PathRejectedError("path is not a stable relative path")
        candidate = (self.root / Path(*parts)).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise PathRejectedError("path escapes the configured root") from exc
        return candidate

    def _display_path(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def resolve_declared(self, value: str, source: Path) -> Path:
        """Resolve root-relative or manifest-directory-relative artifacts.

        Run manifests conventionally declare ``artifacts/foo`` relative to
        their own run directory.  Older manifests may use paths relative to
        the TOP root.  Accept both forms while keeping the same strict path
        validation and root containment checks.
        """
        root_candidate = self._safe_relative(value)
        try:
            root_resolved = root_candidate.resolve(strict=True)
            root_resolved.relative_to(self.root)
            if root_resolved.is_file():
                return root_resolved
        except (OSError, RuntimeError, ValueError):
            pass
        try:
            source_parent = source.resolve(strict=True).parent.relative_to(self.root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise PathRejectedError("manifest source is outside the configured root") from exc
        scoped = (source_parent / Path(value)).as_posix()
        scoped_candidate = self._safe_relative(scoped)
        try:
            scoped_resolved = scoped_candidate.resolve(strict=True)
            scoped_resolved.relative_to(self.root)
            if scoped_resolved.is_file():
                return scoped_resolved
        except (OSError, RuntimeError, ValueError):
            pass
        raise PathRejectedError("declared artifact is unavailable")

    def read_relative(self, value: str) -> tuple[Path, bytes]:
        path = self._safe_relative(value)
        try:
            if not path.is_file():
                raise FileNotFoundError(value)
            return path, path.read_bytes()
        except (OSError, ValueError) as exc:
            raise PathRejectedError("file is unavailable") from exc

    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def hash_file(self, path: Path) -> tuple[str, int]:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.root)
            if not resolved.is_file():
                raise OSError("not a regular file")
            digest = hashlib.sha256()
            size = 0
            with resolved.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            return digest.hexdigest(), size
        except (OSError, RuntimeError, ValueError) as exc:
            raise PathRejectedError("evidence file is unavailable") from exc

    def manifest_paths(self) -> list[Path]:
        found: list[Path] = []
        for directory, directories, filenames in os.walk(
            self.root, topdown=True, followlinks=False
        ):
            directories[:] = sorted(
                name
                for name in directories
                if not (Path(directory) / name).is_symlink()
            )
            for filename in sorted(filenames):
                if filename == "manifest.json" or filename in {
                    "manifest.yaml",
                    "manifest.yml",
                }:
                    found.append(Path(directory) / filename)
        return sorted(found, key=lambda item: self._display_path(item))

    def candidate_manifest_paths(self, run_id: str) -> list[Path]:
        _validate_identifier(run_id, "run id")
        candidates = [
            self.root / "manifests" / f"{run_id}.json",
            self.root / "manifests" / f"{run_id}.yaml",
            self.root / "manifests" / run_id / "manifest.json",
            self.root / "runs" / run_id / "manifest.json",
            self.root / "runs" / f"{run_id}.json",
            self.root / run_id / "manifest.json",
            self.root / f"{run_id}.json",
        ]
        return [path for path in candidates if path.resolve(strict=False).is_file()]

    def read_manifest_objects(self, path: Path) -> list[Mapping[str, Any]]:
        document = _read_document(path)
        if isinstance(document, Mapping) and isinstance(document.get("runs"), list):
            return [
                item for item in document["runs"] if isinstance(item, Mapping)
            ]
        if isinstance(document, Mapping) and isinstance(document.get("run"), Mapping):
            return [document["run"]]
        if isinstance(document, Mapping):
            return [document]
        raise ValueError("manifest is not an object")


def _artifact_paths(value: Any) -> list[str]:
    result: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(item, Mapping):
                path = item.get("path", item.get("artifact_path", key))
            else:
                path = key
            if path is not None:
                result.append(str(path))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            if isinstance(item, Mapping):
                path = item.get("path", item.get("artifact_path", item.get("name")))
            else:
                path = item
            if path is not None:
                result.append(str(path))
    elif value is not None:
        result.append(str(value))
    return _dedupe_strings(result)


class TopDeliveryController:
    """The pure command dispatcher and read-only TOP-DELIVERY view."""

    def __init__(
        self,
        root: Path | ControllerConfig,
        authorized_senders: Collection[str] | None = None,
        *,
        allowed_senders: Collection[str] | None = None,
        audit_db: Path | str | AuditLog | None = None,
        audit_path: Path | str | None = None,
        default_run_id: str | None = None,
        routing_path: Path | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        if isinstance(root, ControllerConfig):
            if any(
                value is not None
                for value in (
                    authorized_senders,
                    allowed_senders,
                    audit_db,
                    audit_path,
                    default_run_id,
                    routing_path,
                )
            ):
                raise ConfigurationError("controller config cannot be overridden")
            config = root
        else:
            if authorized_senders is not None and allowed_senders is not None:
                raise ConfigurationError("configure one sender allow-list")
            senders = (
                authorized_senders
                if authorized_senders is not None
                else (allowed_senders if allowed_senders is not None else ())
            )
            if isinstance(senders, str):
                senders = (senders,)
            if audit_db is not None and audit_path is not None:
                raise ConfigurationError("configure one audit database path")
            configured_audit: Path | str = (
                audit_db if audit_db is not None else (audit_path or ":memory:")
            )
            config = ControllerConfig(
                root=Path(root),
                authorized_senders=frozenset(senders),
                audit_db=configured_audit
                if not isinstance(configured_audit, AuditLog)
                else ":memory:",
                default_run_id=default_run_id,
                routing_path=routing_path,
            )
        self.config = config
        self.store = ArtifactStore(config.root)
        if isinstance(audit_db, AuditLog):
            self.audit = audit_db
            self._owns_audit = False
        else:
            self.audit = AuditLog(config.audit_db)
            self._owns_audit = True
        self.parser = CommandParser(config.authorized_senders)
        self.rate_limiter = rate_limiter or RateLimiter(
            config.rate_limit_count, config.rate_limit_window_seconds
        )
        self.queue = InertQueue(self.audit)
        self.children = ChildRegistry(self.audit)

    def close(self) -> None:
        if self._owns_audit:
            self.audit.close()

    def _record_from_object(
        self, document: Mapping[str, Any], source: Path
    ) -> RunRecord | None:
        run_id_value = document.get("run_id", document.get("id"))
        if run_id_value is None:
            return None
        run_id = str(run_id_value)
        if not _IDENTIFIER_RE.fullmatch(run_id):
            return None
        phase_value = document.get("phase", document.get("current_phase"))
        phase = None if phase_value is None else str(phase_value)
        status_value = document.get("status", "pending")
        status = str(status_value).strip().lower() or "pending"
        evidence_value = document.get(
            "evidence_paths", document.get("evidence", document.get("evidence_files"))
        )
        evidence_paths = tuple(_artifact_paths(evidence_value))
        blockers = tuple(
            _dedupe_strings(
                _as_string_list(document.get("blockers", document.get("blocked_by")))
            )
        )
        next_value = document.get("next_action", document.get("next_step"))
        next_action = None if next_value is None else str(next_value)
        artifact_value = document.get("artifacts", document.get("artifact_paths"))
        artifact_paths = tuple(_artifact_paths(artifact_value))
        return RunRecord(
            run_id=run_id,
            phase=phase,
            status=status,
            evidence_paths=evidence_paths,
            blockers=blockers,
            next_action=next_action,
            artifact_paths=artifact_paths,
            source=source,
        )

    def _records(self) -> list[RunRecord]:
        records: dict[str, RunRecord] = {}
        for path in self.store.manifest_paths():
            try:
                objects = self.store.read_manifest_objects(path)
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                LOGGER.warning("ignoring unreadable manifest %s: %s", path, exc)
                continue
            for document in objects:
                record = self._record_from_object(document, path)
                if record is not None and record.run_id not in records:
                    records[record.run_id] = record
        return [records[key] for key in sorted(records)]

    def _record(self, run_id: str) -> RunRecord | None:
        _validate_identifier(run_id, "run id")
        candidates = self.store.candidate_manifest_paths(run_id)
        paths = candidates + [
            path for path in self.store.manifest_paths() if path not in candidates
        ]
        for path in paths:
            try:
                objects = self.store.read_manifest_objects(path)
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                LOGGER.warning("ignoring unreadable manifest %s: %s", path, exc)
                continue
            for document in objects:
                record = self._record_from_object(document, path)
                if record is not None and record.run_id == run_id:
                    return record
        return None

    def _default_record(self) -> RunRecord | None:
        if self.config.default_run_id is not None:
            return self._record(self.config.default_run_id)
        records = self._records()
        return records[-1] if records else None

    def _evidence(
        self, record: RunRecord
    ) -> tuple[list[dict[str, Any]], list[str]]:
        evidence: list[dict[str, Any]] = []
        blockers: list[str] = []
        for relative_path in record.evidence_paths:
            try:
                path = self.store.resolve_declared(relative_path, record.source)
                digest, size = self.store.hash_file(path)
            except PathRejectedError:
                blockers.append(f"evidence-unavailable:{relative_path}")
                continue
            evidence.append(
                {
                    "path": relative_path,
                    "sha256": digest,
                    "size": size,
                }
            )
        return evidence, blockers

    @staticmethod
    def _base_response(
        *,
        run_id: str | None,
        phase: str | None,
        status: str,
        evidence_paths: Iterable[str] = (),
        blockers: Iterable[str] = (),
        next_action: str | None = None,
        mode: str = READ_ONLY_MODE,
    ) -> dict[str, Any]:
        return {
            "mode": mode,
            "run_id": run_id,
            "phase": phase,
            "status": status,
            "evidence_paths": _dedupe_strings(str(item) for item in evidence_paths),
            "blockers": _dedupe_strings(str(item) for item in blockers),
            "next_action": next_action,
        }

    def _unknown_response(self, next_action: str) -> dict[str, Any]:
        return self._base_response(
            run_id=None,
            phase=None,
            status="unknown",
            next_action=next_action,
        )

    def _record_response(self, record: RunRecord) -> dict[str, Any]:
        evidence, evidence_blockers = self._evidence(record)
        blockers = _dedupe_strings((*record.blockers, *evidence_blockers))
        status = record.status
        if not status or status == "unknown":
            status = "pending"
        return {
            **self._base_response(
                run_id=record.run_id,
                phase=record.phase,
                status=status,
                evidence_paths=record.evidence_paths,
                blockers=blockers,
                next_action=record.next_action,
            ),
            "evidence": evidence,
            "manifest_path": self.store._display_path(record.source),
        }

    def _status(self, args: Sequence[str]) -> dict[str, Any]:
        if len(args) > 1:
            raise InvalidCommandError("status takes zero or one argument")
        record = self._record(args[0]) if args else self._default_record()
        if record is None:
            return self._unknown_response("provide a known run_id")
        return self._record_response(record)

    def _architecture_summary(self) -> dict[str, Any]:
        project_path = self._project_status_path()
        if project_path is not None:
            try:
                data = project_path.read_bytes()
                document = _read_document(project_path)
                if not isinstance(document, Mapping) or not isinstance(
                    document.get("tree"), list
                ):
                    raise ValueError("project status document has no tree")
                digest = hashlib.sha256(data).hexdigest()
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                LOGGER.warning("project architecture summary unavailable: %s", exc)
                return self._base_response(
                    run_id=None,
                    phase=None,
                    status="pending",
                    blockers=["architecture-summary-unavailable"],
                    next_action="repair architecture/project-status.json",
                )
            return {
                **self._base_response(
                    run_id=None,
                    phase=None,
                    status="ready",
                    evidence_paths=[self.store._display_path(project_path)],
                    next_action="recommended",
                ),
                "architecture_summary": document,
                "architecture_path": self.store._display_path(project_path),
                "architecture_sha256": digest,
            }

        configured = self.config.routing_path
        path = (
            configured
            if configured is not None and configured.is_absolute()
            else self.store.root
            / (
                configured
                if configured is not None
                else Path("architecture") / "model-routing.yaml"
            )
        )
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                raise OSError("routing file is not regular")
            data = resolved.read_bytes()
            document = _read_document(resolved)
            digest = hashlib.sha256(data).hexdigest()
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            LOGGER.warning("routing summary unavailable: %s", exc)
            return self._base_response(
                run_id=None,
                phase=None,
                status="pending",
                blockers=["architecture-summary-unavailable"],
                next_action="provide architecture/model-routing.yaml",
            )
        if isinstance(document, Mapping):
            keys = sorted(str(key) for key in document)
            routes = document.get(
                "routes",
                document.get("model_routes", document.get("routing", [])),
            )
            if isinstance(routes, Mapping):
                route_count = len(routes)
            elif isinstance(routes, Sequence) and not isinstance(routes, (str, bytes)):
                route_count = len(routes)
            else:
                route_count = 0
        else:
            keys = []
            route_count = 0
        display_path = self.store._display_path(resolved)
        return {
            **self._base_response(
                run_id=None,
                phase=None,
                status="ready",
                evidence_paths=[display_path],
                next_action="review the selected routing fallback",
            ),
            "architecture": document,
            "architecture_path": display_path,
            "routing_sha256": digest,
            "top_level_keys": keys,
            "route_count": route_count,
        }

    def _project_status_path(self) -> Path | None:
        for candidate in (
            self.store.root / "architecture" / "project-status.json",
            self.store.root / "architecture" / "project-status.yaml",
            self.store.root / "architecture" / "project-status.yml",
        ):
            try:
                if candidate.resolve(strict=True).is_file():
                    return candidate
            except OSError:
                continue
        return None

    def _recommended(self) -> dict[str, Any]:
        path = self._project_status_path()
        if path is None:
            return self._base_response(
                run_id=None,
                phase=None,
                status="pending",
                blockers=["recommended-order-unavailable"],
                next_action="repair architecture/project-status.json",
            )
        try:
            data = path.read_bytes()
            document = _read_document(path)
            order = document.get("recommended_order") if isinstance(document, Mapping) else None
            if not isinstance(order, list) or not all(isinstance(item, str) for item in order):
                raise ValueError("recommended order is not a string list")
            digest = hashlib.sha256(data).hexdigest()
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            LOGGER.warning("recommended order unavailable: %s", exc)
            return self._base_response(
                run_id=None,
                phase=None,
                status="pending",
                blockers=["recommended-order-unavailable"],
                next_action="repair architecture/project-status.json",
            )
        return {
            **self._base_response(
                run_id=None,
                phase=None,
                status="ready",
                evidence_paths=[self.store._display_path(path)],
                next_action="architecture-summary",
            ),
            "recommended_order": order,
            "architecture_path": self.store._display_path(path),
            "architecture_sha256": digest,
        }

    @staticmethod
    def _summary_date(value: str | None) -> str:
        now = datetime.now(ZoneInfo("America/New_York"))
        if value is None or value == "today":
            return now.date().isoformat()
        if value == "yesterday":
            return (now - timedelta(days=1)).date().isoformat()
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise InvalidCommandError(
                "trading-summary date must be today, yesterday, or YYYY-MM-DD"
            ) from exc
        return parsed.date().isoformat()

    def _trading_summary(self, args: Sequence[str]) -> dict[str, Any]:
        if len(args) > 1:
            raise InvalidCommandError("trading-summary takes zero or one argument")
        requested_date = self._summary_date(args[0] if args else None)
        path = self.store.root / "reports" / f"trading-summary-{requested_date}.json"
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                raise OSError("summary is not a regular file")
            data = resolved.read_bytes()
            document = _read_document(resolved)
            if not isinstance(document, Mapping) or document.get("date") != requested_date:
                raise ValueError("summary date does not match requested date")
            digest = hashlib.sha256(data).hexdigest()
        except FileNotFoundError:
            return {
                **self._base_response(
                    run_id=None,
                    phase=None,
                    status="pending",
                    blockers=["trading-summary-unavailable"],
                    next_action=f"publish trading-summary {requested_date}",
                ),
                "requested_date": requested_date,
                "trading_summary": None,
            }
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            LOGGER.warning("trading summary unavailable: %s", exc)
            return {
                **self._base_response(
                    run_id=None,
                    phase=None,
                    status="pending",
                    blockers=["trading-summary-invalid"],
                    next_action=f"repair trading-summary {requested_date}",
                ),
                "requested_date": requested_date,
                "trading_summary": None,
            }
        return {
            **self._base_response(
                run_id=None,
                phase=None,
                status="ready",
                evidence_paths=[self.store._display_path(resolved)],
                next_action="status",
            ),
            "requested_date": requested_date,
            "trading_summary": document,
            "summary_path": self.store._display_path(resolved),
            "summary_sha256": digest,
        }

    def _active_runs(self) -> dict[str, Any]:
        active = [
            record
            for record in self._records()
            if record.status not in _TERMINAL_RUN_STATES
        ]
        summaries = [
            {
                "run_id": record.run_id,
                "phase": record.phase,
                "status": record.status,
                "blockers": list(record.blockers),
                "next_action": record.next_action,
            }
            for record in active
        ]
        if not active:
            response = self._unknown_response("provide a run manifest with an active status")
        else:
            response = self._base_response(
                run_id=None,
                phase=None,
                status="active",
                next_action="inspect one of the active runs",
            )
        response["runs"] = summaries
        return response

    def _latest_evidence(self, args: Sequence[str]) -> dict[str, Any]:
        if len(args) > 1:
            raise InvalidCommandError("latest-evidence takes zero or one argument")
        records = [self._record(args[0])] if args else self._records()
        records = [record for record in records if record is not None]
        choices: list[tuple[int, str, str, RunRecord, Path]] = []
        for record in records:
            for relative_path in record.evidence_paths:
                try:
                    path = self.store.resolve_declared(relative_path, record.source)
                    stat = path.stat()
                    if not path.is_file():
                        continue
                    choices.append(
                        (
                            int(stat.st_mtime_ns),
                            record.run_id,
                            relative_path,
                            record,
                            path,
                        )
                    )
                except (OSError, PathRejectedError):
                    continue
        if not choices:
            if records:
                record = records[0]
                response = self._record_response(record)
                response["status"] = "pending"
                response["blockers"] = _dedupe_strings(
                    (*response["blockers"], "latest-evidence-unavailable")
                )
                response["next_action"] = "provide readable evidence"
                response["latest_evidence"] = None
                return response
            return self._unknown_response("provide a known run_id")
        _, _, relative_path, record, path = max(
            choices, key=lambda item: (item[0], item[1], item[2])
        )
        digest, size = self.store.hash_file(path)
        return {
            **self._base_response(
                run_id=record.run_id,
                phase=record.phase,
                status="ready",
                evidence_paths=[relative_path],
                blockers=record.blockers,
                next_action=record.next_action,
            ),
            "latest_evidence": {
                "path": relative_path,
                "sha256": digest,
                "size": size,
            },
        }

    def _next_step(self, args: Sequence[str]) -> dict[str, Any]:
        if len(args) > 1:
            raise InvalidCommandError("next-step takes zero or one argument")
        record = self._record(args[0]) if args else self._default_record()
        if record is None:
            return self._unknown_response("provide a known run_id")
        response = self._record_response(record)
        if record.next_action is None or not record.next_action.strip():
            response["status"] = "pending"
            response["next_action"] = "await a manifest next_action"
            response["blockers"] = _dedupe_strings(
                (*response["blockers"], "next-action-unavailable")
            )
        else:
            response["next_action"] = record.next_action
        return response

    def _artifact_lookup(self, args: Sequence[str]) -> dict[str, Any]:
        if len(args) not in {1, 2}:
            raise InvalidCommandError("artifact lookup takes one or two arguments")
        record: RunRecord | None
        query: str
        if len(args) == 2:
            record = self._record(args[0])
            query = args[1]
            if record is None:
                return self._unknown_response("provide a known run_id")
            records: list[RunRecord] = [record]
        else:
            query = args[0]
            record = None
            records = self._records()
        if record is not None:
            self.store.resolve_declared(query, record.source)
        else:
            self.store._safe_relative(query)
        matching: list[tuple[RunRecord | None, Path]] = []
        for candidate_record in records:
            declared = set(
                (*candidate_record.artifact_paths, *candidate_record.evidence_paths)
            )
            if query not in declared:
                continue
            try:
                path = self.store.resolve_declared(query, candidate_record.source)
                if path.is_file():
                    matching.append((candidate_record, path))
            except PathRejectedError:
                raise
        # A direct lookup is limited to paths declared by a manifest.  A file
        # merely living under artifacts/ or evidence/ is not evidence.
        if matching:
            selected_record, path = sorted(
                matching,
                key=lambda item: (
                    item[0].run_id if item[0] is not None else "",
                    self.store._display_path(item[1]),
                ),
            )[0]
            digest, size = self.store.hash_file(path)
            evidence_paths = (
                selected_record.evidence_paths if selected_record is not None else ()
            )
            return {
                **self._base_response(
                    run_id=selected_record.run_id if selected_record else None,
                    phase=selected_record.phase if selected_record else None,
                    status="ready",
                    evidence_paths=evidence_paths,
                    blockers=selected_record.blockers if selected_record else (),
                    next_action=(
                        selected_record.next_action
                        if selected_record is not None
                        else "review the artifact"
                    ),
                ),
                "artifact": {
                    "path": query,
                    "sha256": digest,
                    "size": size,
                },
            }
        if record is not None and query in {
            *record.artifact_paths,
            *record.evidence_paths,
        }:
            response = self._record_response(record)
            response["status"] = "pending"
            response["blockers"] = _dedupe_strings(
                (*response["blockers"], f"artifact-unavailable:{query}")
            )
            response["next_action"] = "provide the declared artifact"
            response["artifact"] = None
            return response
        return self._unknown_response("provide a declared artifact path")

    def dispatch(self, parsed: ParsedCommand) -> dict[str, Any]:
        if parsed.command == "status":
            return self._status(parsed.args)
        if parsed.command == "architecture-summary":
            return self._architecture_summary()
        if parsed.command == "recommended":
            return self._recommended()
        if parsed.command == "artifact lookup":
            return self._artifact_lookup(parsed.args)
        if parsed.command == "active-runs":
            return self._active_runs()
        if parsed.command == "latest-evidence":
            return self._latest_evidence(parsed.args)
        if parsed.command == "next-step":
            return self._next_step(parsed.args)
        if parsed.command == "trading-summary":
            return self._trading_summary(parsed.args)
        raise UnknownCommandError("command is not supported")

    def _read_only_help_next_action(self) -> str:
        return (
            f"Send one supported read-only command: {READ_ONLY_COMMANDS_TEXT}. "
            f"For 2FA execution, {AUTHORIZATION_COMMANDS_TEXT}."
        )

    def _error_response(self, error: ControllerError) -> dict[str, Any]:
        if isinstance(error, UnknownCommandError):
            next_action = self._read_only_help_next_action()
            message = (
                f"Unknown command. Supported read-only commands: "
                f"{READ_ONLY_COMMANDS_TEXT}. {AUTHORIZATION_COMMANDS_TEXT}."
            )
        elif isinstance(error, InvalidCommandError):
            next_action = self._read_only_help_next_action()
            message = (
                f"{error.message}. Supported read-only commands: "
                f"{READ_ONLY_COMMANDS_TEXT}. {AUTHORIZATION_COMMANDS_TEXT}."
            )
        else:
            next_action = self._read_only_help_next_action()
            message = error.message
        return {
            **self._base_response(
                run_id=None,
                phase=None,
                status="error",
                blockers=[error.code],
                next_action=next_action,
            ),
            "error": {"code": error.code, "message": message},
            "supported_read_only_commands": list(COMMANDS),
            "authorization_commands": [
                "next",
                "authorize CODE",
            ],
        }

    def handle_command(
        self,
        command: ParsedCommand | str,
        sender_id: str | None = None,
        *,
        is_group: bool = False,
        group: bool = False,
    ) -> dict[str, Any]:
        if isinstance(command, str):
            if sender_id is None:
                raise UnauthorizedSenderError("sender is not authorized")
            parsed = self.parser.parse(
                command,
                sender_id,
                is_group=is_group,
                group=group,
            )
        else:
            parsed = command
        return self.dispatch(parsed)

    def handle_text(
        self,
        text: str,
        sender_id: str,
        *,
        is_group: bool = False,
        group: bool = False,
        group_id: str | None = None,
    ) -> str:
        parsed: ParsedCommand | None = None
        try:
            parsed = self.parser.parse(
                text,
                sender_id,
                is_group=is_group,
                group=group,
                group_id=group_id,
            )
            self.rate_limiter.require(sender_id)
            response = self.dispatch(parsed)
            self.audit.append(
                "command",
                {
                    "accepted": True,
                    "command": parsed.command,
                    "sender_sha256": hashlib.sha256(
                        sender_id.encode("utf-8")
                    ).hexdigest(),
                },
            )
        except ControllerError as exc:
            response = self._error_response(exc)
            try:
                self.audit.append(
                    "command",
                    {
                        "accepted": False,
                        "command": parsed.command if parsed is not None else None,
                        "error": exc.code,
                    },
                )
            except AuditError:
                LOGGER.exception("could not append rejected command audit event")
        return response_json(response)

    handle = handle_text
    forwardable_response = handle_text


Controller = TopDeliveryController

__all__ = [
    "AUTHORIZATION_COMMANDS_TEXT",
    "COMMANDS",
    "READ_ONLY_COMMANDS_TEXT",
    "READ_ONLY_MODE",
    "ArtifactStore",
    "AuditError",
    "AuditLog",
    "ChildRecord",
    "ChildRegistry",
    "CommandParser",
    "CommandRejectedError",
    "ConfigurationError",
    "Controller",
    "ControllerConfig",
    "ControllerError",
    "GroupMessageRejectedError",
    "InertQueue",
    "InvalidCommandError",
    "ParsedCommand",
    "PathRejectedError",
    "QueueReceipt",
    "RateLimitExceededError",
    "RateLimiter",
    "RunRecord",
    "TargetRejectedError",
    "TopDeliveryController",
    "UnauthorizedSenderError",
    "UnknownCommandError",
    "is_allowed_target",
    "response_json",
    "validate_target_id",
]
