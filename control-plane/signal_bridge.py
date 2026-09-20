"""Pure Signal boundary for the controller.

This module deliberately has no transport, process, model, or command-parser
integration.  A SignalEnvelope is parsed at the boundary and the bridge only
passes an already-authorized direct message to ``handle_text``.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from os import PathLike
from typing import Any, Optional, Union


_ENVELOPE_KEYS = frozenset(
    {"message_id", "sender_id", "identity_fingerprint", "text", "is_group"}
)
_MISSING = object()


def _error_reply(code: str) -> str:
    """Return a deterministic bridge-authored error and nothing else."""

    return json.dumps(
        {"error": code},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def _ascii_token_is_valid(value: Any, maximum: int) -> bool:
    if type(value) is not str or not value or len(value) > maximum:
        return False
    if unicodedata.normalize("NFC", value) != value:
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return all(0x21 <= ord(character) <= 0x7E for character in value)


def _text_is_valid(value: Any, maximum: int) -> bool:
    if type(value) is not str or len(value) > maximum:
        return False
    if "\x00" in value or unicodedata.normalize("NFC", value) != value:
        return False
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    return True


class SignalEnvelopeError(ValueError):
    """Raised when a mapping is not the closed SignalEnvelope schema."""

    def __init__(self, code: str = "malformed_envelope") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SignalEnvelope:
    """The only input shape accepted by SignalBridge.

    Identity and routing fields are restricted to printable, NFC-stable ASCII.
    Message text may contain Unicode, but must be UTF-8 encodable and NFC
    stable; it is never interpreted or rewritten by this module.
    """

    message_id: str
    sender_id: str
    identity_fingerprint: str
    text: str
    is_group: bool

    def __post_init__(self) -> None:
        if not _ascii_token_is_valid(self.message_id, 256):
            raise SignalEnvelopeError()
        if not _ascii_token_is_valid(self.sender_id, 256):
            raise SignalEnvelopeError()
        if not _ascii_token_is_valid(self.identity_fingerprint, 1024):
            raise SignalEnvelopeError()
        if not _text_is_valid(self.text, 65536):
            raise SignalEnvelopeError()
        if type(self.is_group) is not bool:
            raise SignalEnvelopeError()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "SignalEnvelope":
        if not isinstance(raw, Mapping):
            raise SignalEnvelopeError()
        try:
            keys = frozenset(raw.keys())
        except (AttributeError, TypeError):
            raise SignalEnvelopeError() from None

        if "sender_id" not in keys:
            raise SignalEnvelopeError("sender_missing")
        if keys != _ENVELOPE_KEYS:
            raise SignalEnvelopeError()
        try:
            sender_id = raw["sender_id"]
        except (KeyError, TypeError):
            raise SignalEnvelopeError("sender_missing") from None
        if sender_id is None or sender_id == "":
            raise SignalEnvelopeError("sender_missing")

        try:
            return cls(
                message_id=raw["message_id"],
                sender_id=sender_id,
                identity_fingerprint=raw["identity_fingerprint"],
                text=raw["text"],
                is_group=raw["is_group"],
            )
        except KeyError:
            raise SignalEnvelopeError() from None

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "SignalEnvelope":
        return cls.from_mapping(raw)

    @classmethod
    def parse_mapping(cls, raw: Mapping[str, Any]) -> "SignalEnvelope":
        return cls.from_mapping(raw)

    @property
    def fingerprint(self) -> str:
        return self.identity_fingerprint

    def as_mapping(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "identity_fingerprint": self.identity_fingerprint,
            "text": self.text,
            "is_group": self.is_group,
        }


def parse_signal_envelope(raw: Mapping[str, Any]) -> SignalEnvelope:
    return SignalEnvelope.from_mapping(raw)


def parse_signal_envelope_reply(raw: Mapping[str, Any]) -> str:
    """Parse without involving a bridge or controller.

    This helper is useful to a transport adapter that needs a deterministic
    rejection for malformed input while preserving the bridge-only boundary.
    """

    try:
        SignalEnvelope.from_mapping(raw)
    except SignalEnvelopeError as error:
        return _error_reply(error.code)
    return _error_reply("envelope_requires_bridge")


@dataclass(frozen=True)
class IdentityDecision:
    allowed: bool
    code: str
    identity_key_change: bool = False


class SignalIdentityPolicy:
    """A fail-closed policy containing exactly one sender and one fingerprint."""

    __slots__ = ("_approved_sender_id", "_pinned_identity_fingerprint")

    def __init__(
        self,
        approved_sender_id: str,
        pinned_identity_fingerprint: Any = _MISSING,
        *,
        pinned_fingerprint: Any = _MISSING,
    ) -> None:
        if (
            pinned_identity_fingerprint is _MISSING
            and pinned_fingerprint is _MISSING
        ):
            raise ValueError("one pinned identity fingerprint is required")
        if (
            pinned_identity_fingerprint is not _MISSING
            and pinned_fingerprint is not _MISSING
        ):
            raise ValueError("exactly one pinned identity fingerprint is required")
        fingerprint = (
            pinned_identity_fingerprint
            if pinned_identity_fingerprint is not _MISSING
            else pinned_fingerprint
        )
        if not _ascii_token_is_valid(approved_sender_id, 256):
            raise ValueError("invalid approved sender id")
        if not _ascii_token_is_valid(fingerprint, 1024):
            raise ValueError("invalid pinned identity fingerprint")
        self._approved_sender_id = approved_sender_id
        self._pinned_identity_fingerprint = fingerprint

    @property
    def approved_sender_id(self) -> str:
        return self._approved_sender_id

    @property
    def approved_sender_ids(self) -> tuple[str]:
        return (self._approved_sender_id,)

    @property
    def pinned_identity_fingerprint(self) -> str:
        return self._pinned_identity_fingerprint

    @property
    def pinned_fingerprint(self) -> str:
        return self._pinned_identity_fingerprint

    def evaluate(self, envelope: SignalEnvelope) -> IdentityDecision:
        if not isinstance(envelope, SignalEnvelope):
            return IdentityDecision(False, "malformed_envelope")
        if envelope.is_group:
            return IdentityDecision(False, "group_not_allowed")
        if not envelope.sender_id:
            return IdentityDecision(False, "sender_missing")
        if envelope.sender_id != self._approved_sender_id:
            return IdentityDecision(False, "sender_unknown")
        if envelope.identity_fingerprint != self._pinned_identity_fingerprint:
            return IdentityDecision(
                False, "identity_key_changed", identity_key_change=True
            )
        return IdentityDecision(True, "allowed")

    def check(self, envelope: SignalEnvelope) -> IdentityDecision:
        return self.evaluate(envelope)

    def is_allowed(self, envelope: SignalEnvelope) -> bool:
        return self.evaluate(envelope).allowed


class BoundedRateLimiter:
    """A bounded, rolling-window in-memory limiter."""

    def __init__(
        self,
        max_messages: int,
        window_seconds: float,
        *,
        max_keys: int = 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(max_messages) is not int or max_messages <= 0:
            raise ValueError("max_messages must be positive")
        if type(max_keys) is not int or max_keys <= 0:
            raise ValueError("max_keys must be positive")
        if not isinstance(window_seconds, (int, float)) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self.max_messages = max_messages
        self.window_seconds = float(window_seconds)
        self.max_keys = max_keys
        self._clock = clock
        self._buckets: "OrderedDict[str, deque[float]]" = OrderedDict()

    def allow(self, key: str) -> bool:
        now = float(self._clock())
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self.max_keys:
                self._buckets.popitem(last=False)
            bucket = deque(maxlen=self.max_messages)
            self._buckets[key] = bucket
        else:
            self._buckets.move_to_end(key)

        cutoff = now - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= self.max_messages:
            return False
        bucket.append(now)
        return True

    @property
    def key_count(self) -> int:
        return len(self._buckets)


class HermesCommandDisabledError(RuntimeError):
    """Hermes cannot author or transform typed command replies here."""

    def __init__(self) -> None:
        super().__init__("Hermes typed commands are disabled at the Signal boundary")


class HermesCommandGuard:
    """Explicit negative capability for any Hermes typed-command path."""

    @staticmethod
    def _disabled(*args: Any, **kwargs: Any) -> None:
        raise HermesCommandDisabledError()

    __call__ = _disabled
    author = _disabled
    transform = _disabled
    author_typed_reply = _disabled
    transform_typed_reply = _disabled
    dispatch = _disabled


def hermes_typed_command(*args: Any, **kwargs: Any) -> None:
    raise HermesCommandDisabledError()


class SignalBridge:
    """Controller-only Signal boundary with durable idempotency."""

    AUDIT_TABLE = "signal_bridge_audit"
    CACHE_TABLE = "signal_bridge_message_cache"

    def __init__(
        self,
        controller: Any,
        identity_policy: SignalIdentityPolicy,
        db_path: Union[str, PathLike[str], sqlite3.Connection] = ":memory:",
        *,
        max_messages: int = 10,
        window_seconds: float = 60.0,
        max_rate_entries: int = 1024,
        clock: Callable[[], float] = time.monotonic,
        rate_limiter: Optional[BoundedRateLimiter] = None,
    ) -> None:
        handle_text = getattr(controller, "handle_text", None)
        if not callable(handle_text):
            raise TypeError("controller must provide handle_text")
        if not isinstance(identity_policy, SignalIdentityPolicy):
            raise TypeError("identity_policy must be SignalIdentityPolicy")
        self._controller = controller
        self._policy = identity_policy
        self._lock = threading.RLock()
        self._owns_connection = not isinstance(db_path, sqlite3.Connection)
        if self._owns_connection:
            self._connection = sqlite3.connect(
                str(db_path), timeout=30.0, check_same_thread=False
            )
        else:
            self._connection = db_path
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._ensure_schema()
        self._rate_limiter = rate_limiter or BoundedRateLimiter(
            max_messages,
            window_seconds,
            max_keys=max_rate_entries,
            clock=clock,
        )

    def _ensure_schema(self) -> None:
        self._connection.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS {self.AUDIT_TABLE} (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message_id_digest TEXT,
                details_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {self.CACHE_TABLE} (
                message_id TEXT PRIMARY KEY,
                output BLOB NOT NULL,
                stored_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS signal_bridge_audit_no_update
            BEFORE UPDATE ON {self.AUDIT_TABLE}
            BEGIN
                SELECT RAISE(ABORT, 'signal audit is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS signal_bridge_audit_no_delete
            BEFORE DELETE ON {self.AUDIT_TABLE}
            BEGIN
                SELECT RAISE(ABORT, 'signal audit is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS signal_bridge_cache_no_update
            BEFORE UPDATE ON {self.CACHE_TABLE}
            BEGIN
                SELECT RAISE(ABORT, 'signal cache is immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS signal_bridge_cache_no_delete
            BEFORE DELETE ON {self.CACHE_TABLE}
            BEGIN
                SELECT RAISE(ABORT, 'signal cache is immutable');
            END;
            """
        )
        self._connection.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="microseconds")

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()

    def _append_audit(
        self,
        event_type: str,
        message_id: Optional[str],
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        details_json = json.dumps(
            dict(details or {}),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        self._connection.execute(
            f"""
            INSERT INTO {self.AUDIT_TABLE}
                (occurred_at, event_type, message_id_digest, details_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                self._now(),
                event_type,
                self._digest(message_id) if message_id is not None else None,
                details_json,
            ),
        )
        self._connection.commit()

    def _cached(self, message_id: str) -> Optional[str]:
        row = self._connection.execute(
            f"SELECT output FROM {self.CACHE_TABLE} WHERE message_id = ?",
            (message_id,),
        ).fetchone()
        if row is None:
            return None
        value = row[0]
        if isinstance(value, str):
            return value
        return bytes(value).decode("utf-8", "strict")

    def _cache(self, envelope: SignalEnvelope, response: str) -> str:
        encoded = response.encode("utf-8", "strict")
        self._connection.execute(
            f"""
            INSERT OR IGNORE INTO {self.CACHE_TABLE}
                (message_id, output, stored_at)
            VALUES (?, ?, ?)
            """,
            (envelope.message_id, sqlite3.Binary(encoded), self._now()),
        )
        self._connection.commit()
        existing = self._cached(envelope.message_id)
        return response if existing is None else existing

    def _finish(
        self,
        envelope: SignalEnvelope,
        event_type: str,
        response: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> str:
        self._append_audit(event_type, envelope.message_id, details)
        return self._cache(envelope, response)

    def handle(self, envelope: Any) -> str:
        """Handle only a parsed envelope; never parse or transform commands."""

        if not isinstance(envelope, SignalEnvelope):
            return _error_reply("malformed_envelope")

        with self._lock:
            cached = self._cached(envelope.message_id)
            if cached is not None:
                self._append_audit("duplicate_message", envelope.message_id)
                return cached

            decision = self._policy.evaluate(envelope)
            if not decision.allowed:
                if decision.identity_key_change:
                    event_type = "identity_key_change"
                    details = {
                        "reason": "pinned_identity_mismatch",
                        "sender_id_digest": self._digest(envelope.sender_id),
                        "observed_fingerprint_digest": self._digest(
                            envelope.identity_fingerprint
                        ),
                        "pinned_fingerprint_digest": self._digest(
                            self._policy.pinned_identity_fingerprint
                        ),
                    }
                else:
                    event_type = "rejected_" + decision.code
                    details = (
                        {
                            "sender_id_digest": self._digest(envelope.sender_id),
                        }
                        if decision.code == "sender_unknown"
                        else {}
                    )
                return self._finish(
                    envelope,
                    event_type,
                    _error_reply(decision.code),
                    details,
                )

            if not self._rate_limiter.allow(envelope.sender_id):
                return self._finish(
                    envelope,
                    "rate_limited",
                    _error_reply("rate_limited"),
                )

            try:
                output = self._controller.handle_text(
                    envelope.text,
                    envelope.sender_id,
                    is_group=False,
                )
            except Exception:
                return self._finish(
                    envelope,
                    "controller_error",
                    _error_reply("controller_error"),
                )

            if not isinstance(output, str):
                return self._finish(
                    envelope,
                    "controller_output_invalid",
                    _error_reply("controller_output_invalid"),
                )
            try:
                output.encode("utf-8", "strict")
            except UnicodeEncodeError:
                return self._finish(
                    envelope,
                    "controller_output_invalid",
                    _error_reply("controller_output_invalid"),
                )

            # Do not load, dump, trim, or otherwise inspect controller output.
            return self._finish(envelope, "controller_invoked", output)

    def handle_envelope(self, envelope: Any) -> str:
        return self.handle(envelope)

    def handle_preparsed(self, envelope: Any) -> str:
        return self.handle(envelope)

    process = handle

    @staticmethod
    def hermes_command(*args: Any, **kwargs: Any) -> None:
        raise HermesCommandDisabledError()

    def audit_events(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT event_id, occurred_at, event_type,
                       message_id_digest, details_json
                FROM {self.AUDIT_TABLE}
                ORDER BY event_id
                """
            ).fetchall()
        return [
            {
                "event_id": row[0],
                "occurred_at": row[1],
                "event_type": row[2],
                "message_id_digest": row[3],
                "details": json.loads(row[4]),
            }
            for row in rows
        ]

    get_audit_events = audit_events
    read_audit_events = audit_events

    def close(self) -> None:
        with self._lock:
            if self._owns_connection:
                self._connection.close()

    def __enter__(self) -> "SignalBridge":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


__all__ = [
    "BoundedRateLimiter",
    "HermesCommandDisabledError",
    "HermesCommandGuard",
    "IdentityDecision",
    "SignalBridge",
    "SignalEnvelope",
    "SignalEnvelopeError",
    "SignalIdentityPolicy",
    "hermes_typed_command",
    "parse_signal_envelope",
    "parse_signal_envelope_reply",
]
