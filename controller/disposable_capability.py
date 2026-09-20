"""Signed disposable harness capabilities for database lifecycle and downgrade."""

from __future__ import annotations

import json
import os
import fcntl
import base64
import binascii
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from authority_pins import (
    COMMS01_DATABASE_ENDPOINTS,
    COMMS01_DATABASE_PORT,
    DISPOSABLE_CAPABILITY_SIGNING_KEY_PATH,
    DISPOSABLE_HARNESS_CAPABILITY_PATH,
    DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH,
)
from attestation import COMMS01_CONTROLLER_SERVICE, load_comms01_attestation
from pinned_trust import read_pinned_bytes, verify_pinned_file_trust
from exceptions import AuthorizationFailureError, ScopeBoundaryViolationError
from longspan_crypto import digest_payload
from operator_asymmetric import sign_message, verify_message_signature

CAPABILITY_OPERATIONS = frozenset(
    {
        "create_database",
        "drop_database",
        "schema_downgrade",
        "authority_downgrade",
        "evidence_downgrade",
        "migration_downgrade",
        "disposable_downgrade",
    }
)

DOWNGRADE_CAPABILITY_OPERATIONS = frozenset(
    {
        "schema_downgrade",
        "authority_downgrade",
        "evidence_downgrade",
        "migration_downgrade",
        "disposable_downgrade",
    }
)

CONSUMED_NONCE_PATH = "/etc/top-delivery/comms01-disposable-consumed-nonces.json"
MAX_CAPABILITY_TTL_SECONDS = 3600
MAX_CONSUMED_NONCES = 4096
MAX_CAPABILITY_FILE_BYTES = 64 * 1024


@dataclass(frozen=True)
class SignedDisposableCapability:
    operation: str
    database_name: str
    database_role: str
    controller_service: str
    nonce: str
    expires_at: str
    migration_revision: str | None
    signature: str
    database_endpoint: str
    database_port: int


def _capability_body(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "operation": str(payload["operation"]),
        "database_name": str(payload["database_name"]),
        "database_role": str(payload["database_role"]),
        "controller_service": str(payload["controller_service"]),
        "nonce": str(payload["nonce"]),
        "expires_at": str(payload["expires_at"]),
        "migration_revision": payload.get("migration_revision"),
        "database_endpoint": str(payload["database_endpoint"]).lower(),
        "database_port": int(payload["database_port"]),
    }


def _load_signing_key() -> str:
    key_path = Path(DISPOSABLE_CAPABILITY_SIGNING_KEY_PATH)
    if key_path.is_symlink() or not key_path.is_file():
        raise AuthorizationFailureError("disposable capability signing key is missing")
    key_stat = key_path.stat()
    if (
        key_stat.st_uid != 0
        or key_stat.st_gid != 0
        or key_stat.st_mode & 0o077
        or (key_stat.st_mode & 0o777) != 0o600
    ):
        raise AuthorizationFailureError(
            "disposable capability signing key must be root-owned and mode 0600"
        )
    secret = key_path.read_text(encoding="utf-8").strip()
    if not secret:
        raise AuthorizationFailureError("disposable capability signing key is empty")
    return secret


def _load_verification_key() -> str:
    try:
        public_key = read_pinned_bytes(
            DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH,
            allow_public_key_read=True,
        ).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise AuthorizationFailureError(
            "disposable capability verifier key is not valid ASCII"
        ) from exc
    if not public_key:
        raise AuthorizationFailureError("disposable capability verifier key is empty")
    try:
        padding = "=" * (-len(public_key) % 4)
        decoded = base64.b64decode(
            public_key + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, TypeError) as exc:
        raise AuthorizationFailureError(
            "disposable capability verifier key is malformed"
        ) from exc
    if len(decoded) != 32:
        raise AuthorizationFailureError(
            "disposable capability verifier key must be an Ed25519 public key"
        )
    return public_key


def sign_disposable_capability(payload: dict[str, Any], *, signing_key: str | None = None) -> str:
    body = _capability_body(payload)
    secret = signing_key or _load_signing_key()
    return sign_message(digest_payload(body), secret)


def verify_disposable_capability_signature(capability: SignedDisposableCapability) -> None:
    body = {
        "operation": capability.operation,
        "database_name": capability.database_name,
        "database_role": capability.database_role,
        "controller_service": capability.controller_service,
        "nonce": capability.nonce,
        "expires_at": capability.expires_at,
        "migration_revision": capability.migration_revision,
        "database_endpoint": capability.database_endpoint,
        "database_port": capability.database_port,
    }
    if not verify_message_signature(
        digest_payload(body),
        capability.signature,
        _load_verification_key(),
    ):
        raise AuthorizationFailureError("disposable capability signature is invalid")


def _assert_private_directory(fd: int, path: str) -> None:
    directory_stat = os.fstat(fd)
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or directory_stat.st_uid != 0
        or directory_stat.st_mode & 0o022
        or directory_stat.st_mode & 0o6000
    ):
        raise AuthorizationFailureError(
            f"disposable capability parent directory is not root-private: {path}"
        )


def _open_pinned_capability_file(file_path: Path) -> int:
    """Open the pinned capability by basename after walking trusted parents."""
    if not file_path.is_absolute() or len(file_path.parts) < 2:
        raise AuthorizationFailureError("disposable capability path must be absolute")
    directory_fds: list[int] = []
    try:
        current_fd = os.open(
            os.sep,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        directory_fds.append(current_fd)
        _assert_private_directory(current_fd, os.sep)
        for index, component in enumerate(file_path.parts[1:-1], start=1):
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            directory_fds.append(next_fd)
            component_path = Path(os.sep).joinpath(*file_path.parts[1 : index + 1])
            _assert_private_directory(next_fd, str(component_path))
            current_fd = next_fd
        return os.open(
            file_path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current_fd,
        )
    except OSError as exc:
        raise AuthorizationFailureError(
            f"disposable capability file is not safely openable: {file_path}"
        ) from exc
    finally:
        for directory_fd in reversed(directory_fds):
            try:
                os.close(directory_fd)
            except OSError:
                pass


def read_capability_json_file(path: str) -> dict:
    file_path = Path(path)
    if str(file_path) == str(Path(DISPOSABLE_HARNESS_CAPABILITY_PATH)):
        try:
            verify_pinned_file_trust(path, require_root_owner=True)
        except ScopeBoundaryViolationError as exc:
            raise AuthorizationFailureError(
                "disposable capability file is not pinned to a trusted owner/path"
            ) from exc
    try:
        if str(file_path) == str(Path(DISPOSABLE_HARNESS_CAPABILITY_PATH)):
            fd = _open_pinned_capability_file(file_path)
        else:
            fd = os.open(file_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise AuthorizationFailureError(
            f"disposable capability file is not safely openable: {path}"
        ) from exc
    try:
        file_stat = os.fstat(fd)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != 0
            or file_stat.st_mode & 0o077
            or file_stat.st_mode & 0o6000
        ):
            raise AuthorizationFailureError(
                "disposable capability file must be a private regular file"
            )
        if file_stat.st_size > MAX_CAPABILITY_FILE_BYTES:
            raise AuthorizationFailureError(
                "disposable capability file exceeds the maximum permitted size"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                fd,
                min(64 * 1024, MAX_CAPABILITY_FILE_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CAPABILITY_FILE_BYTES:
                raise AuthorizationFailureError(
                    "disposable capability file exceeds the maximum permitted size"
                )
        final_stat = os.fstat(fd)
        if final_stat.st_ino != file_stat.st_ino or final_stat.st_size != file_stat.st_size:
            raise AuthorizationFailureError(
                "disposable capability file changed while being read"
            )
        raw = b"".join(chunks)
        if len(raw) > MAX_CAPABILITY_FILE_BYTES:
            raise AuthorizationFailureError(
                "disposable capability file exceeds the maximum permitted size"
            )
    finally:
        os.close(fd)
    try:
        payload = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationFailureError(f"disposable capability file is invalid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise AuthorizationFailureError("disposable capability file must be a JSON object")
    return payload


def load_signed_disposable_capability() -> SignedDisposableCapability | None:
    path = Path(DISPOSABLE_HARNESS_CAPABILITY_PATH)
    if not path.is_file():
        return None
    payload = read_capability_json_file(DISPOSABLE_HARNESS_CAPABILITY_PATH)
    required = (
        "operation",
        "database_name",
        "database_role",
        "controller_service",
        "nonce",
        "expires_at",
        "database_endpoint",
        "database_port",
        "signature",
    )
    missing = [field for field in required if not payload.get(field)]
    if missing:
        raise AuthorizationFailureError(
            f"disposable capability file is incomplete: {', '.join(missing)}"
        )
    operation = str(payload["operation"])
    endpoint = str(payload["database_endpoint"]).lower()
    try:
        database_port = int(payload["database_port"])
    except (TypeError, ValueError) as exc:
        raise AuthorizationFailureError(
            "disposable capability database_port is invalid"
        ) from exc
    if endpoint not in COMMS01_DATABASE_ENDPOINTS:
        raise AuthorizationFailureError(
            "disposable capability endpoint is outside the local Comms-01 boundary"
        )
    if not 1 <= database_port <= 65535:
        raise AuthorizationFailureError("disposable capability database_port is invalid")
    if database_port != COMMS01_DATABASE_PORT:
        raise AuthorizationFailureError(
            "disposable capability database_port is not the pinned Comms-01 port"
        )
    if operation in DOWNGRADE_CAPABILITY_OPERATIONS and not str(
        payload.get("migration_revision") or ""
    ).strip():
        raise AuthorizationFailureError(
            "downgrade capability must bind an exact migration revision"
        )
    capability = SignedDisposableCapability(
        operation=operation,
        database_name=str(payload["database_name"]),
        database_role=str(payload["database_role"]),
        controller_service=str(payload["controller_service"]),
        nonce=str(payload["nonce"]),
        expires_at=str(payload["expires_at"]),
        migration_revision=(
            str(payload["migration_revision"]) if payload.get("migration_revision") else None
        ),
        signature=str(payload["signature"]),
        database_endpoint=endpoint,
        database_port=database_port,
    )
    verify_disposable_capability_signature(capability)
    attestation = load_comms01_attestation(strict_owner=True)
    if (
        capability.controller_service != COMMS01_CONTROLLER_SERVICE
        or capability.controller_service != attestation.controller_service
    ):
        raise AuthorizationFailureError("disposable capability controller service mismatch")
    expires = datetime.fromisoformat(capability.expires_at)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if expires <= now:
        raise AuthorizationFailureError("disposable capability expired")
    if (expires - now).total_seconds() > MAX_CAPABILITY_TTL_SECONDS:
        raise AuthorizationFailureError("disposable capability TTL exceeds bound")
    return capability


def _nonce_store_path() -> Path:
    return Path(CONSUMED_NONCE_PATH)


def _open_consumed_nonce_store():
    """Open the root-private replay store without creating its parent."""
    path = _nonce_store_path()
    try:
        parent_stat = path.parent.lstat()
    except OSError as exc:
        raise AuthorizationFailureError(
            "disposable capability nonce-store parent is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != 0
        or parent_stat.st_mode & 0o022
    ):
        raise AuthorizationFailureError(
            "disposable capability nonce-store parent is not root-private"
        )
    try:
        fd = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        raise AuthorizationFailureError(
            "disposable capability nonce store is not safely openable"
        ) from exc
    try:
        file_stat = os.fstat(fd)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != 0
            or file_stat.st_mode & 0o077
            or file_stat.st_mode & 0o6000
        ):
            raise AuthorizationFailureError(
                "disposable capability nonce store must be root-owned 0600"
            )
        return os.fdopen(fd, "r+", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


def _parse_nonce_timestamp(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise AuthorizationFailureError(
            f"disposable capability nonce store has invalid {field}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _consume_nonce(nonce: str, expires_at: str) -> None:
    with _open_consumed_nonce_store() as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            raw = handle.read().strip() or "{}"
            try:
                document = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AuthorizationFailureError(
                    "disposable capability nonce store is malformed"
                ) from exc
            if not isinstance(document, dict):
                raise AuthorizationFailureError(
                    "disposable capability nonce store has invalid entries"
                )
            now = datetime.now(timezone.utc)
            live_document: dict[str, dict[str, str]] = {}
            for stored_nonce, entry in document.items():
                if not isinstance(stored_nonce, str):
                    raise AuthorizationFailureError(
                        "disposable capability nonce store has invalid entries"
                    )
                # Migrate the pre-v60 string format safely. Its maximum
                # replay-relevant lifetime is the capability TTL, so an old
                # consumed timestamp can be converted without extending the
                # trust window.
                if isinstance(entry, str):
                    consumed_at = _parse_nonce_timestamp(entry, field="consumed_at")
                    inferred_expires = consumed_at + timedelta(
                        seconds=MAX_CAPABILITY_TTL_SECONDS
                    )
                    if inferred_expires > now:
                        live_document[stored_nonce] = {
                            "consumed_at": entry,
                            "expires_at": inferred_expires.isoformat(),
                        }
                    continue
                if not isinstance(entry, dict):
                    raise AuthorizationFailureError(
                        "disposable capability nonce store has invalid entries"
                    )
                consumed_at = entry.get("consumed_at")
                stored_expires_at = entry.get("expires_at")
                if not isinstance(consumed_at, str) or not isinstance(
                    stored_expires_at, str
                ):
                    raise AuthorizationFailureError(
                        "disposable capability nonce store has invalid entries"
                    )
                _parse_nonce_timestamp(consumed_at, field="consumed_at")
                expires = _parse_nonce_timestamp(
                    stored_expires_at, field="expires_at"
                )
                if expires > now:
                    live_document[stored_nonce] = {
                        "consumed_at": consumed_at,
                        "expires_at": stored_expires_at,
                    }
            if nonce in live_document:
                raise AuthorizationFailureError("disposable capability nonce already consumed")
            if len(live_document) >= MAX_CONSUMED_NONCES:
                raise AuthorizationFailureError(
                    "disposable capability nonce store is full of unexpired entries"
                )
            live_document[nonce] = {
                "consumed_at": now.isoformat(),
                "expires_at": expires_at,
            }
            handle.seek(0)
            handle.truncate()
            handle.write(json.dumps(live_document, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def require_disposable_capability(
    *,
    operation: str,
    database_name: str | None = None,
    database_role: str | None = None,
    migration_revision: str | None = None,
    consume_nonce: bool = False,
) -> SignedDisposableCapability:
    if operation not in CAPABILITY_OPERATIONS:
        raise AuthorizationFailureError(f"unsupported disposable capability operation: {operation}")
    capability = load_signed_disposable_capability()
    if capability is None:
        raise AuthorizationFailureError("verified signed disposable capability is required")
    if capability.operation != operation:
        if not (
            capability.operation == "disposable_downgrade"
            and operation in DOWNGRADE_CAPABILITY_OPERATIONS
        ):
            raise AuthorizationFailureError("disposable capability operation mismatch")
    if database_name is not None:
        if capability.database_name != database_name:
            raise AuthorizationFailureError("disposable capability database name mismatch")
    if database_role is not None and capability.database_role != database_role:
        raise AuthorizationFailureError("disposable capability database role mismatch")
    if operation in DOWNGRADE_CAPABILITY_OPERATIONS and not migration_revision:
        raise AuthorizationFailureError(
            "downgrade capability requires an exact migration revision"
        )
    if operation in DOWNGRADE_CAPABILITY_OPERATIONS and (
        capability.migration_revision is None
        or capability.migration_revision != migration_revision
    ):
        raise AuthorizationFailureError("disposable capability migration revision mismatch")
    if consume_nonce:
        _consume_nonce(capability.nonce, capability.expires_at)
    return capability


def consume_verified_disposable_capability(
    capability: SignedDisposableCapability,
) -> None:
    """Revalidate the pinned capability and consume its nonce exactly once.

    The caller may have held the parsed object across database checks.  Reload
    the root-pinned capability file before burning the nonce so a replacement
    file cannot cause a stale, previously-verified object to authorize a
    different operation, target, role, or migration revision.
    """
    if not isinstance(capability, SignedDisposableCapability):
        raise AuthorizationFailureError("verified disposable capability is required")
    current = load_signed_disposable_capability()
    if current is None or current != capability:
        raise AuthorizationFailureError(
            "disposable capability changed after verification"
        )
    # load_signed_disposable_capability already verifies the signature,
    # attestation binding, endpoint/port allowlist, and expiry.  Repeat the
    # signature check explicitly at the consumption boundary so this function
    # remains safe if those validation steps are refactored later.
    verify_disposable_capability_signature(current)
    _consume_nonce(capability.nonce, capability.expires_at)


def require_migration_downgrade_capability(*, revision: str) -> None:
    require_disposable_capability(
        operation="migration_downgrade",
        migration_revision=revision,
        consume_nonce=True,
    )


def _alembic_downgrade_target() -> str:
    """Resolve the explicit canonical command target, never a module fallback."""
    from migration_target import requested_revision

    target = requested_revision("downgrade")
    if not target:
        raise AuthorizationFailureError(
            "migration downgrade target is unavailable; refusing an unbound capability check"
        )
    return target


def require_connected_migration_downgrade(*, revision: str) -> None:
    """Bind downgrade to the live Alembic connection identity.

    Nonce consumption is performed once by migrations/env.py for raw Alembic and
    wrappers. This helper re-checks identity/revision without consuming again.
    The capability binds to the canonical Alembic command target, while the
    executing revision must also be an exact member of that target's reviewed
    downgrade path. This prevents a copied revision module from reusing a valid
    target witness outside the intended migration sequence.
    """
    from alembic import op
    import sqlalchemy as sa

    connection = op.get_bind()
    row = connection.execute(sa.text("SELECT current_database(), current_user")).one()
    database_name, database_role = row[0], row[1]
    if not (
        str(database_name).startswith("td_test_")
        or str(database_name).startswith("td_downgrade_")
    ):
        raise AuthorizationFailureError(
            f"migration downgrade blocked on non-disposable database {database_name!r}"
        )
    target = _alembic_downgrade_target()
    ordered_revisions = (
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
    )
    try:
        target_index = ordered_revisions.index(target)
        revision_index = ordered_revisions.index(revision)
    except ValueError:
        target_index = revision_index = -1
    if target_index < 0 or revision_index <= target_index:
        raise AuthorizationFailureError(
            "migration downgrade revision is outside the canonical target path"
        )
    require_disposable_capability(
        operation="migration_downgrade",
        database_name=str(database_name),
        database_role=str(database_role),
        migration_revision=target,
        consume_nonce=False,
    )


def build_capability_file_payload(
    *,
    operation: str,
    database_name: str,
    database_role: str,
    controller_service: str,
    nonce: str,
    expires_at: str,
    signing_key: str,
    database_endpoint: str,
    database_port: int,
    migration_revision: str | None = None,
) -> dict[str, Any]:
    body = {
        "operation": operation,
        "database_name": database_name,
        "database_role": database_role,
        "controller_service": controller_service,
        "nonce": nonce,
        "expires_at": expires_at,
        "migration_revision": migration_revision,
        "database_endpoint": str(database_endpoint).lower(),
        "database_port": int(database_port),
    }
    return {**body, "signature": sign_disposable_capability(body, signing_key=signing_key)}


def write_test_capability_file(path: str, payload: dict[str, Any]) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    file_path.chmod(0o600)


def capability_database_name(db_url: str) -> str:
    return urlsplit(db_url).path.lstrip("/")
