"""Durable, action-bound 2FA authorization primitives."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
import unicodedata
import uuid

logger = logging.getLogger(__name__)

ACTIVE_RUN_ID = "20260810T004319Z-b626467e"
CHALLENGE_TTL_SECONDS = 60
DEFAULT_TOTP_STEP_SECONDS = 30
ALLOWED_ACTIONS = frozenset(
    {
        "create_next_prompt",
        "queue_next_prompt",
        "retry_queueable_child",
        "reap_terminal_child",
    }
)
_REQUIRED_ACTION_FIELDS = frozenset({"action", "target", "run_id", "dry_run"})
_ALLOWED_ACTION_FIELDS = _REQUIRED_ACTION_FIELDS | {"prompt_id"}
_TARGET_RE = re.compile(r"disposable-[A-Za-z0-9][A-Za-z0-9_-]*\Z", re.ASCII)
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z", re.ASCII)
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_FORBIDDEN_TERMS = ("production", "prod", "broker", "ledger", "network", "staging")


class DomainError(Exception):
    code = "domain_error"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.code)


class CanonicalizationError(DomainError):
    code = "canonicalization_error"


class InvalidActionError(CanonicalizationError):
    code = "invalid_action"


class ActionShapeError(InvalidActionError):
    code = "invalid_action_shape"


class InvalidFieldError(InvalidActionError):
    code = "invalid_field"


class FieldTypeError(InvalidFieldError):
    code = "invalid_field_type"


class NonAsciiError(InvalidFieldError):
    code = "non_ascii"


class UnicodeNormalizationError(InvalidFieldError):
    code = "unicode_normalization_changed"


class PathTraversalError(InvalidFieldError):
    code = "path_or_traversal"


class ForbiddenTermError(InvalidFieldError):
    code = "forbidden_term"


class UnsupportedActionError(InvalidActionError):
    code = "unsupported_action"


class InvalidTargetError(InvalidFieldError):
    code = "invalid_target"


class RunDeniedError(InvalidActionError):
    code = "run_denied"
    classification = "non_active"


class StagingRunDeniedError(RunDeniedError):
    code = "staging_run_denied"
    classification = "staging"


class PriorRunDeniedError(RunDeniedError):
    code = "prior_run_denied"
    classification = "prior"


class ChallengeError(DomainError):
    code = "challenge_error"


class ChallengeNotFoundError(ChallengeError):
    code = "challenge_not_found"


class ChallengeExpiredError(ChallengeError):
    code = "challenge_expired"


class ChallengeAlreadyConsumedError(ChallengeError):
    code = "challenge_already_consumed"


class WrongOperatorError(ChallengeError):
    code = "wrong_operator"


class WrongHashError(ChallengeError):
    code = "wrong_hash"


class ActionMismatchError(ChallengeError):
    code = "action_mismatch"


class InvalidCodeError(ChallengeError):
    code = "invalid_code"


class CodeMismatchError(ChallengeError):
    code = "code_mismatch"


class CodeReplayError(ChallengeError):
    code = "code_replay"


class InvalidVerifierError(ChallengeError):
    code = "invalid_verifier"


class InvalidVerifierResultError(ChallengeError):
    code = "invalid_verifier_result"


class VerifierExecutionError(ChallengeError):
    code = "verifier_execution_error"


class ClockError(ChallengeError):
    code = "invalid_clock"


class StoreError(DomainError):
    code = "store_error"


class StoreClosedError(StoreError):
    code = "store_closed"


ExpiredChallengeError = ChallengeExpiredError
DuplicateConsumeError = ChallengeAlreadyConsumedError
OperatorMismatchError = WrongOperatorError
ReusedCodeError = CodeReplayError


def _text(field: str, value: object) -> str:
    if type(value) is not str:
        raise FieldTypeError(f"{field} must be a string")
    if not value:
        raise InvalidFieldError(f"{field} must not be empty")
    if unicodedata.normalize("NFC", value) != value:
        raise UnicodeNormalizationError(f"{field} is not NFC-stable")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise NonAsciiError(f"{field} must be ASCII") from exc
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise InvalidFieldError(f"{field} contains a control character")
    if any(marker in value for marker in ("/", "\\", "..", "%", ":")):
        raise PathTraversalError(f"{field} contains a path or traversal marker")
    if any(char.isspace() for char in value):
        raise InvalidFieldError(f"{field} contains whitespace")
    return value


def _reject_forbidden(field: str, value: str) -> None:
    lowered = value.lower()
    if any(term in lowered for term in _FORBIDDEN_TERMS):
        raise ForbiddenTermError(f"{field} contains a forbidden term")


def _validate_identifier(field: str, value: object) -> str:
    text = _text(field, value)
    if not _IDENTIFIER_RE.fullmatch(text):
        raise InvalidFieldError(f"{field} is not a safe identifier")
    return text


def canonical_action(
    action: Mapping[str, object],
    *,
    active_run_id: str | None = None,
) -> dict[str, str | bool]:
    if type(action) is not dict:
        raise ActionShapeError("action must be an exact dictionary")
    keys = frozenset(action)
    if keys not in (_REQUIRED_ACTION_FIELDS, _ALLOWED_ACTION_FIELDS):
        raise ActionShapeError("action fields do not match the exact schema")

    action_name = _text("action", action["action"])
    if action_name not in ALLOWED_ACTIONS:
        raise UnsupportedActionError("action is not permitted")

    target = _text("target", action["target"])
    if target != "comms-01-control-plane" and not _TARGET_RE.fullmatch(target):
        raise InvalidTargetError("target is not permitted")

    run_id = _text("run_id", action["run_id"])
    expected_run_id = active_run_id or ACTIVE_RUN_ID
    if run_id != expected_run_id:
        if "staging" in run_id.lower():
            raise StagingRunDeniedError("staging runs are denied")
        raise PriorRunDeniedError("non-active prior runs are denied")

    prompt_id: str | None = None
    if "prompt_id" in action:
        prompt_id = _validate_identifier("prompt_id", action["prompt_id"])

    if type(action["dry_run"]) is not bool:
        raise FieldTypeError("dry_run must be a boolean")

    for field, value in (
        ("action", action_name),
        ("target", target),
        ("run_id", run_id),
        ("prompt_id", prompt_id),
    ):
        if value is not None:
            _reject_forbidden(field, value)

    result: dict[str, str | bool] = {
        "action": action_name,
        "target": target,
        "run_id": run_id,
    }
    if prompt_id is not None:
        result["prompt_id"] = prompt_id
    result["dry_run"] = action["dry_run"]
    return result


def canonical_json(
    action: Mapping[str, object],
    *,
    active_run_id: str | None = None,
) -> str:
    canonical = canonical_action(action, active_run_id=active_run_id)
    return json.dumps(
        canonical,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonicalize_action(action: Mapping[str, object]) -> str:
    return canonical_json(action)


def action_digest(
    action: Mapping[str, object],
    *,
    active_run_id: str | None = None,
) -> str:
    return hashlib.sha256(
        canonical_json(action, active_run_id=active_run_id).encode("ascii")
    ).hexdigest()


def action_sha256(action: Mapping[str, object]) -> str:
    return action_digest(action)


def _validate_operator(operator_id: object) -> str:
    value = _text("operator_id", operator_id)
    if len(value) > 256:
        raise InvalidFieldError("operator_id is too long")
    _reject_forbidden("operator_id", value)
    return value


def _validate_code(code: object) -> str:
    if type(code) is not str or len(code) != 6 or any(
        character < "0" or character > "9" for character in code
    ):
        raise InvalidCodeError("code must be exactly six ASCII digits")
    return code


def _validate_hash(value: object) -> str:
    if type(value) is not str or not _HASH_RE.fullmatch(value):
        raise WrongHashError("action digest must be lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class ChallengePrompt:
    prompt_id: str
    action_json: str
    action_digest: str
    issued_at: float
    expires_at: float

    @property
    def challenge_id(self) -> str:
        return self.prompt_id

    def as_dict(self) -> dict[str, str | float]:
        return {
            "prompt_id": self.prompt_id,
            "action_json": self.action_json,
            "action_digest": self.action_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class QueueReceipt:
    receipt_id: str
    prompt_id: str
    action_digest: str
    accepted_at: float
    dry_run: bool

    def as_dict(self) -> dict[str, str | float | bool]:
        return {
            "receipt_id": self.receipt_id,
            "prompt_id": self.prompt_id,
            "action_digest": self.action_digest,
            "accepted_at": self.accepted_at,
            "dry_run": self.dry_run,
        }


Verifier = Callable[[str, str, int], bool]


class ChallengeStore:
    """SQLite-backed challenge store.

    The verifier is pure and is called as ``verifier(operator_id, code,
    totp_time_step)``.  It must return exactly ``True`` or ``False``.
    """

    def __init__(
        self,
        sqlite_path: str | os.PathLike[str],
        verifier: Verifier,
        *,
        clock: Callable[[], int | float] = time.time,
        totp_step_seconds: int = DEFAULT_TOTP_STEP_SECONDS,
    ) -> None:
        if not callable(verifier):
            raise InvalidVerifierError("verifier must be callable")
        if not callable(clock):
            raise ClockError("clock must be callable")
        if type(totp_step_seconds) is not int or totp_step_seconds <= 0:
            raise ClockError("TOTP step must be a positive integer")
        try:
            database_name = os.fspath(sqlite_path)
            self._connection = sqlite3.connect(
                database_name,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._create_schema()
        except (OSError, TypeError, sqlite3.Error) as exc:
            try:
                self._connection.close()
            except (AttributeError, sqlite3.Error):
                pass
            raise StoreError("unable to open the SQLite authorization store") from exc
        self._verifier = verifier
        self._clock = clock
        self._totp_step_seconds = totp_step_seconds
        self._lock = threading.RLock()
        self._closed = False

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS challenges (
                prompt_id TEXT PRIMARY KEY,
                operator_id TEXT NOT NULL,
                action_name TEXT NOT NULL,
                action_json TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                consumed_step INTEGER,
                receipt_id TEXT
            );
            CREATE TABLE IF NOT EXISTS replay_bindings (
                operator_id TEXT NOT NULL,
                code_digest TEXT NOT NULL,
                totp_step INTEGER NOT NULL,
                prompt_id TEXT NOT NULL,
                used_at REAL NOT NULL,
                PRIMARY KEY (operator_id, code_digest, totp_step)
            );
            CREATE TABLE IF NOT EXISTS audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                prompt_id TEXT,
                operator_id TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS audit_append_only_update
            BEFORE UPDATE ON audit
            BEGIN
                SELECT RAISE(ABORT, 'audit is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_append_only_delete
            BEFORE DELETE ON audit
            BEGIN
                SELECT RAISE(ABORT, 'audit is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS replay_binding_append_only_update
            BEFORE UPDATE ON replay_bindings
            BEGIN
                SELECT RAISE(ABORT, 'replay bindings are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS replay_binding_append_only_delete
            BEFORE DELETE ON replay_bindings
            BEGIN
                SELECT RAISE(ABORT, 'replay bindings are append-only');
            END;
            """
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise StoreClosedError("challenge store is closed")

    def _now(self) -> float:
        try:
            raw = self._clock()
            if type(raw) not in (int, float):
                raise TypeError
            value = float(raw)
        except (Exception,) as exc:
            if isinstance(exc, ClockError):
                raise
            raise ClockError("clock did not return a finite timestamp") from exc
        if not math.isfinite(value) or value < 0:
            raise ClockError("clock did not return a finite timestamp")
        return value

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}{uuid.uuid4().hex}"

    def _append_audit(
        self,
        event: str,
        prompt_id: str | None,
        operator_id: str,
        occurred_at: float,
        details: Mapping[str, object],
    ) -> None:
        details_json = json.dumps(
            dict(details),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        self._connection.execute(
            """
            INSERT INTO audit
                (event, prompt_id, operator_id, occurred_at, details_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event, prompt_id, operator_id, occurred_at, details_json),
        )

    def _rollback(self) -> None:
        try:
            self._connection.rollback()
        except sqlite3.Error:
            pass

    def _audit_denial(
        self,
        prompt_id: str,
        operator_id: str,
        occurred_at: float,
        error: ChallengeError,
    ) -> None:
        try:
            with self._lock:
                self._connection.execute("BEGIN IMMEDIATE")
                self._append_audit(
                    "authorization_denied",
                    prompt_id,
                    operator_id,
                    occurred_at,
                    {"reason": error.code},
                )
                self._connection.commit()
        except (DomainError, sqlite3.Error):
            self._rollback()
            logger.warning("authorization denial could not be audited")

    def create_challenge(
        self,
        action: Mapping[str, object],
        operator_id: str,
    ) -> ChallengePrompt:
        canonical = canonical_action(action)
        action_json = json.dumps(
            canonical,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        digest = hashlib.sha256(action_json.encode("ascii")).hexdigest()
        operator = _validate_operator(operator_id)
        issued_at = self._now()
        expires_at = issued_at + CHALLENGE_TTL_SECONDS
        prompt_id = self._new_id("prompt-")

        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT INTO challenges
                        (prompt_id, operator_id, action_name, action_json,
                         action_digest, dry_run, issued_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        prompt_id,
                        operator,
                        canonical["action"],
                        action_json,
                        digest,
                        int(canonical["dry_run"]),
                        issued_at,
                        expires_at,
                    ),
                )
                self._append_audit(
                    "challenge_created",
                    prompt_id,
                    operator,
                    issued_at,
                    {"action_digest": digest, "expires_at": expires_at},
                )
                self._connection.commit()
            except sqlite3.Error as exc:
                self._rollback()
                raise StoreError("unable to persist the challenge") from exc

        return ChallengePrompt(
            prompt_id=prompt_id,
            action_json=action_json,
            action_digest=digest,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def create_next_prompt(
        self,
        action: Mapping[str, object],
        operator_id: str,
    ) -> ChallengePrompt:
        return self.create_challenge(action, operator_id)

    def issue_challenge(
        self,
        action: Mapping[str, object],
        operator_id: str,
    ) -> ChallengePrompt:
        return self.create_challenge(action, operator_id)

    def get_prompt(self, prompt_id: str) -> ChallengePrompt | None:
        identifier = _validate_identifier("prompt_id", prompt_id)
        with self._lock:
            self._ensure_open()
            try:
                row = self._connection.execute(
                    """
                    SELECT prompt_id, action_json, action_digest,
                           issued_at, expires_at
                    FROM challenges
                    WHERE prompt_id = ?
                    """,
                    (identifier,),
                ).fetchone()
            except sqlite3.Error as exc:
                raise StoreError("unable to read the challenge") from exc
        if row is None:
            return None
        return ChallengePrompt(
            prompt_id=row["prompt_id"],
            action_json=row["action_json"],
            action_digest=row["action_digest"],
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
        )

    def authorize(
        self,
        prompt_id: str,
        operator_id: str,
        code: str,
        action_digest: str | None = None,
    ) -> QueueReceipt:
        return self._authorize(
            prompt_id,
            operator_id,
            code,
            action_digest=action_digest,
            expected_action=None,
        )

    def authorize_action(
        self,
        action: Mapping[str, object],
        prompt_id: str,
        operator_id: str,
        code: str,
    ) -> QueueReceipt:
        digest = action_digest(action)
        return self._authorize(
            prompt_id,
            operator_id,
            code,
            action_digest=digest,
            expected_action=None,
        )

    def _authorize(
        self,
        prompt_id: str,
        operator_id: str,
        code: str,
        *,
        action_digest: str | None,
        expected_action: str | None,
    ) -> QueueReceipt:
        identifier = _validate_identifier("prompt_id", prompt_id)
        operator = _validate_operator(operator_id)
        verified_code = _validate_code(code)
        expected_digest = (
            None if action_digest is None else _validate_hash(action_digest)
        )
        occurred_at = self._now()
        totp_step = math.floor(occurred_at / self._totp_step_seconds)
        code_hash = hashlib.sha256(verified_code.encode("ascii")).hexdigest()

        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise StoreError("unable to begin authorization transaction") from exc

            try:
                row = self._connection.execute(
                    """
                    SELECT operator_id, action_name, action_digest, dry_run,
                           expires_at, consumed_at
                    FROM challenges
                    WHERE prompt_id = ?
                    """,
                    (identifier,),
                ).fetchone()
                if row is None:
                    raise ChallengeNotFoundError("challenge does not exist")
                if row["operator_id"] != operator:
                    raise WrongOperatorError("operator is not bound to challenge")
                if expected_action is not None and row["action_name"] != expected_action:
                    raise ActionMismatchError("challenge action does not match")
                if expected_digest is not None and not hmac.compare_digest(
                    row["action_digest"], expected_digest
                ):
                    raise WrongHashError("action digest does not match challenge")
                if row["consumed_at"] is not None:
                    raise ChallengeAlreadyConsumedError("challenge was already consumed")
                if occurred_at >= float(row["expires_at"]):
                    raise ChallengeExpiredError("challenge has expired")

                try:
                    verdict = self._verifier(operator, verified_code, totp_step)
                except Exception as exc:
                    raise VerifierExecutionError("verifier failed") from exc
                if type(verdict) is not bool:
                    raise InvalidVerifierResultError("verifier must return a boolean")
                if not verdict:
                    raise CodeMismatchError("two-factor code was rejected")

                try:
                    self._connection.execute(
                        """
                        INSERT INTO replay_bindings
                            (operator_id, code_digest, totp_step, prompt_id, used_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (operator, code_hash, totp_step, identifier, occurred_at),
                    )
                except sqlite3.IntegrityError as exc:
                    raise CodeReplayError(
                        "code was already used for this operator and time step"
                    ) from exc

                receipt_id = self._new_id("receipt-")
                updated = self._connection.execute(
                    """
                    UPDATE challenges
                    SET consumed_at = ?, consumed_step = ?, receipt_id = ?
                    WHERE prompt_id = ? AND consumed_at IS NULL
                    """,
                    (occurred_at, totp_step, receipt_id, identifier),
                ).rowcount
                if updated != 1:
                    raise ChallengeAlreadyConsumedError("challenge was already consumed")

                self._append_audit(
                    "authorization_succeeded",
                    identifier,
                    operator,
                    occurred_at,
                    {
                        "action_digest": row["action_digest"],
                        "code_digest": code_hash,
                        "receipt_id": receipt_id,
                        "totp_step": totp_step,
                    },
                )
                self._connection.commit()
            except ChallengeError as exc:
                self._rollback()
                self._audit_denial(identifier, operator, occurred_at, exc)
                raise
            except sqlite3.Error as exc:
                self._rollback()
                raise StoreError("authorization transaction failed") from exc

        return QueueReceipt(
            receipt_id=receipt_id,
            prompt_id=identifier,
            action_digest=row["action_digest"],
            accepted_at=occurred_at,
            dry_run=bool(row["dry_run"]),
        )

    def queue_next_prompt(
        self,
        prompt_id: str,
        operator_id: str,
        code: str,
        action_digest: str | None = None,
    ) -> QueueReceipt:
        return self._authorize(
            prompt_id,
            operator_id,
            code,
            action_digest=action_digest,
            expected_action="queue_next_prompt",
        )

    def retry_queueable_child(
        self,
        prompt_id: str,
        operator_id: str,
        code: str,
        action_digest: str | None = None,
    ) -> QueueReceipt:
        return self._authorize(
            prompt_id,
            operator_id,
            code,
            action_digest=action_digest,
            expected_action="retry_queueable_child",
        )

    def reap_terminal_child(
        self,
        prompt_id: str,
        operator_id: str,
        code: str,
        action_digest: str | None = None,
    ) -> QueueReceipt:
        return self._authorize(
            prompt_id,
            operator_id,
            code,
            action_digest=action_digest,
            expected_action="reap_terminal_child",
        )

    def audit_events(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            self._ensure_open()
            try:
                rows = self._connection.execute(
                    """
                    SELECT audit_id, event, prompt_id, operator_id,
                           occurred_at, details_json
                    FROM audit
                    ORDER BY audit_id
                    """
                ).fetchall()
            except sqlite3.Error as exc:
                raise StoreError("unable to read the audit") from exc
        return tuple(dict(row) for row in rows)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                try:
                    self._connection.close()
                except sqlite3.Error as exc:
                    raise StoreError("unable to close the SQLite store") from exc
                finally:
                    self._closed = True

    def __enter__(self) -> ChallengeStore:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        self.close()
        return False


__all__ = [
    "ACTIVE_RUN_ID",
    "ALLOWED_ACTIONS",
    "ActionMismatchError",
    "ActionShapeError",
    "CanonicalizationError",
    "ChallengeAlreadyConsumedError",
    "ChallengeError",
    "ChallengeExpiredError",
    "ChallengeNotFoundError",
    "ChallengePrompt",
    "ChallengeStore",
    "CodeMismatchError",
    "CodeReplayError",
    "DomainError",
    "DuplicateConsumeError",
    "ExpiredChallengeError",
    "FieldTypeError",
    "ForbiddenTermError",
    "InvalidActionError",
    "InvalidCodeError",
    "InvalidFieldError",
    "InvalidTargetError",
    "InvalidVerifierError",
    "InvalidVerifierResultError",
    "NonAsciiError",
    "OperatorMismatchError",
    "PathTraversalError",
    "PriorRunDeniedError",
    "QueueReceipt",
    "ReusedCodeError",
    "RunDeniedError",
    "StagingRunDeniedError",
    "StoreClosedError",
    "StoreError",
    "UnicodeNormalizationError",
    "UnsupportedActionError",
    "VerifierExecutionError",
    "WrongHashError",
    "WrongOperatorError",
    "action_digest",
    "action_sha256",
    "canonical_action",
    "canonical_json",
    "canonicalize_action",
]
