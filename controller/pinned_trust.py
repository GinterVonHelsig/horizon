"""Pinned file trust verification shared by attestation and disposable capabilities."""

from __future__ import annotations

import json
import errno
import os
import stat
from pathlib import Path

from authority_pins import (
    AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
    AUTHORITY_SERVICE_GID,
    AUTHORITY_SERVICE_UID,
    AUTHORITY_WRITE_SIGNING_SECRET_PATH,
    COMMS01_ATTESTATION_PATH,
    DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH,
    LEDGER_MAC_KEY_PATH,
    OPERATOR_PUBLIC_KEYS_PATH,
    RUNNER_ENVELOPE_PUBLIC_KEY_PATH,
    TERRA_GATEWAY_MAC_KEY_PATH,
    TERRA_RECEIPT_PUBLIC_KEYS_PATH,
    WORKFLOW_DATABASE_TARGET_PATH,
)
from authority_test_seam import allowed_test_owner_uids
from exceptions import ScopeBoundaryViolationError


_SOURCE_PINNED_EXECUTABLE_MANIFEST_PATH = Path(__file__).with_name(
    "pinned-executables.json"
).resolve()
_PINNED_EXECUTABLE_MANIFEST_PATH = _SOURCE_PINNED_EXECUTABLE_MANIFEST_PATH
MAX_PINNED_FILE_BYTES = 1024 * 1024

# Runtime-read trust inputs remain root-owned, but the dedicated service group
# may read them with exactly 0640 permissions. The path allowlist prevents a
# caller from turning an arbitrary file into a service-readable trust anchor.
SERVICE_GROUP_READABLE_PATHS = frozenset(
    Path(path).resolve()
    for path in (
        OPERATOR_PUBLIC_KEYS_PATH,
        TERRA_RECEIPT_PUBLIC_KEYS_PATH,
        COMMS01_ATTESTATION_PATH,
        AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
        WORKFLOW_DATABASE_TARGET_PATH,
        DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH,
        AUTHORITY_WRITE_SIGNING_SECRET_PATH,
        LEDGER_MAC_KEY_PATH,
        TERRA_GATEWAY_MAC_KEY_PATH,
        RUNNER_ENVELOPE_PUBLIC_KEY_PATH,
    )
)


def owner_allowed(uid: int) -> bool:
    # Production pins are root-owned; authority service uid is also trusted.
    if uid in {0, AUTHORITY_SERVICE_UID}:
        return True
    return uid in allowed_test_owner_uids()


def _absolute_lexical_path(path: str | os.PathLike[str]) -> Path:
    """Normalize a path without resolving symlinks or reopening it by name."""

    return Path(os.path.abspath(os.fspath(path)))


def _requires_secure_ancestors(file_path: Path, *, secure_source: bool = False) -> bool:
    """Runtime trust inputs must not traverse attacker-writable directories."""

    lexical = str(file_path)
    return secure_source or (
        lexical == "/etc/top-delivery"
        or lexical.startswith("/etc/top-delivery/")
        or file_path == _SOURCE_PINNED_EXECUTABLE_MANIFEST_PATH
    )


def _assert_secure_ancestors(file_path: Path, *, secure_source: bool = False) -> None:
    """Verify the runtime trust directory chain through directory descriptors."""

    if not _requires_secure_ancestors(file_path, secure_source=secure_source):
        return
    directory_fds: list[int] = []
    try:
        current_fd = os.open(
            os.sep,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        directory_fds.append(current_fd)
        root_stat = os.fstat(current_fd)
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != 0
            or root_stat.st_mode & (0o022 | 0o6000)
        ):
            raise ScopeBoundaryViolationError(
                f"pinned trust path has an unsafe root ancestor: {file_path}"
            )
        for component in file_path.parts[1:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            directory_fds.append(next_fd)
            directory_stat = os.fstat(next_fd)
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or directory_stat.st_uid != 0
                or directory_stat.st_mode & (0o022 | 0o6000)
            ):
                raise ScopeBoundaryViolationError(
                    f"pinned trust path has an unsafe ancestor: {file_path}"
                )
            current_fd = next_fd
    except ScopeBoundaryViolationError:
        raise
    except OSError as exc:
        raise ScopeBoundaryViolationError(
            f"pinned trust path is not safely traversable: {file_path}"
        ) from exc
    finally:
        for directory_fd in reversed(directory_fds):
            try:
                os.close(directory_fd)
            except OSError:
                pass


def _open_verified_fd(
    path: str,
    *,
    allow_service_group_read: bool = False,
    allow_public_key_read: bool = False,
    require_root_owner: bool = True,
    secure_source: bool = False,
) -> tuple[int, Path]:
    """Open and validate one pinned file, returning the validated descriptor.

    All security decisions are made from ``fstat`` on this descriptor.  The
    caller must consume the descriptor and must not reopen the returned path.
    ``O_NOFOLLOW`` protects the final path component; runtime paths additionally
    require root-owned, non-group/world-writable ancestors.
    """

    file_path = _absolute_lexical_path(path)
    service_group_path = file_path in SERVICE_GROUP_READABLE_PATHS
    executable_manifest = file_path == _PINNED_EXECUTABLE_MANIFEST_PATH
    public_key_path = file_path == _absolute_lexical_path(
        DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH
    )
    if (
        allow_service_group_read
        and not executable_manifest
        and not service_group_path
    ):
        raise ScopeBoundaryViolationError(
            "service-group read is permitted only for pinned runtime trust inputs"
        )
    if allow_public_key_read and not public_key_path:
        raise ScopeBoundaryViolationError(
            "public-key read is permitted only for the pinned capability verifier"
        )
    _assert_secure_ancestors(file_path, secure_source=secure_source)
    try:
        fd = os.open(
            os.fspath(file_path),
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError as exc:
        raise ScopeBoundaryViolationError(f"attestation file is missing: {path}") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ScopeBoundaryViolationError(f"attestation file is a symlink: {path}") from exc
        raise ScopeBoundaryViolationError(
            f"attestation file is not safely openable: {path}"
        ) from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ScopeBoundaryViolationError(f"pinned file is not regular: {path}")
        if file_stat.st_size > MAX_PINNED_FILE_BYTES:
            raise ScopeBoundaryViolationError(f"pinned file is too large: {path}")
        if require_root_owner and file_stat.st_uid != 0:
            raise ScopeBoundaryViolationError(f"pinned file must be root-owned: {path}")
        if allow_public_key_read and file_stat.st_uid != 0:
            raise ScopeBoundaryViolationError(
                f"pinned capability verifier must be root-owned: {path}"
            )
        if not owner_allowed(file_stat.st_uid):
            raise ScopeBoundaryViolationError(f"attestation file owner is not trusted: {path}")
        if secure_source:
            # Alembic source is executable trust material.  It may remain
            # readable by the runtime, but its file and every ancestor must
            # be root-owned and non-writable by group/other.  The descriptor
            # returned here is the same descriptor consumed by the caller.
            if file_stat.st_uid != 0 or file_stat.st_mode & 0o022:
                raise ScopeBoundaryViolationError(
                    f"migration source is not root-owned and non-writable: {path}"
                )
        elif file_stat.st_uid == 0:
            if allow_service_group_read or allow_public_key_read or service_group_path:
                if file_stat.st_gid == AUTHORITY_SERVICE_GID:
                    mode = stat.S_IMODE(file_stat.st_mode)
                    allowed_modes = (
                        {0o640, 0o644} if executable_manifest else {0o640}
                    )
                    if mode not in allowed_modes:
                        raise ScopeBoundaryViolationError(
                            f"pinned trust anchor permissions are not exact: {path}"
                        )
                elif file_stat.st_gid == 0 and stat.S_IMODE(file_stat.st_mode) in (
                    {0o600} if service_group_path else {0o600, 0o640, 0o644}
                ):
                    pass
                else:
                    raise ScopeBoundaryViolationError(
                        f"pinned public/manifest group is not the pinned authority service group: {path}"
                    )
            elif file_stat.st_mode & 0o077:
                raise ScopeBoundaryViolationError(
                    f"attestation file permissions are too permissive: {path}"
                )
        elif allow_service_group_read:
            raise ScopeBoundaryViolationError(
                f"service-group readable manifest must be root-owned: {path}"
            )
        elif file_stat.st_mode & 0o077:
            raise ScopeBoundaryViolationError(
                f"attestation file permissions are too permissive: {path}"
            )
        return fd, file_path
    except BaseException:
        os.close(fd)
        raise


def read_pinned_bytes(
    path: str,
    *,
    allow_service_group_read: bool = False,
    allow_public_key_read: bool = False,
    require_root_owner: bool = True,
) -> bytes:
    """Read validated bytes from the same descriptor used for trust checks."""

    fd, file_path = _open_verified_fd(
        path,
        allow_service_group_read=allow_service_group_read,
        allow_public_key_read=allow_public_key_read,
        require_root_owner=require_root_owner,
    )
    try:
        before = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_PINNED_FILE_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_PINNED_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        if total > MAX_PINNED_FILE_BYTES:
            raise ScopeBoundaryViolationError(f"pinned file is too large: {file_path}")
        if (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            before.st_mode,
            before.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            after.st_mode,
            after.st_size,
        ) or total != before.st_size:
            raise ScopeBoundaryViolationError(
                f"pinned file changed while being read: {file_path}"
            )
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_verified_source_bytes(path: str) -> bytes:
    """Read executable migration source through a root-owned secure path."""

    fd, file_path = _open_verified_fd(
        path,
        require_root_owner=True,
        secure_source=True,
    )
    try:
        before = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_PINNED_FILE_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_PINNED_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        if total > MAX_PINNED_FILE_BYTES or before.st_size != total:
            raise ScopeBoundaryViolationError(
                f"migration source is too large or changed while being read: {file_path}"
            )
        if (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
            before.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_mode,
            after.st_size,
        ):
            raise ScopeBoundaryViolationError(
                f"migration source changed while being read: {file_path}"
            )
        return b"".join(chunks)
    finally:
        os.close(fd)


def verify_pinned_file_trust(
    path: str,
    *,
    allow_service_group_read: bool = False,
    allow_public_key_read: bool = False,
    require_root_owner: bool = True,
) -> Path:
    fd, file_path = _open_verified_fd(
        path,
        allow_service_group_read=allow_service_group_read,
        allow_public_key_read=allow_public_key_read,
        require_root_owner=require_root_owner,
    )
    os.close(fd)
    return file_path


def read_json_file(
    path: str,
    *,
    strict_owner: bool = True,
    allow_service_group_read: bool = False,
    require_root_owner: bool = True,
) -> dict:
    if not strict_owner:
        raise ScopeBoundaryViolationError(
            "unverified trust-anchor reads are disabled; use the explicit test seam"
        )
    raw = read_pinned_bytes(
        path,
        allow_service_group_read=allow_service_group_read,
        require_root_owner=require_root_owner,
    )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScopeBoundaryViolationError(f"attestation file is invalid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ScopeBoundaryViolationError(f"attestation file must be a JSON object: {path}")
    return payload
