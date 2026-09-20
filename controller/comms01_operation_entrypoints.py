"""Fail-closed Comms-01 side-effect entrypoint adapters.

The repository currently has no generic backup, restore, or service runner.
These are the only approved adapters future callers may use: they force the
technical operation contract at the call boundary instead of relying on a
runbook comment or caller discipline. Authority rotation is enforced directly
in ``authority_service_server`` because it has the live socket side effect.
"""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from authority_pins import RESTORE_FENCE_ROOT as _PINNED_RESTORE_FENCE_ROOT
from comms01_authority import ExternalOperatorApprovalReceipt
from comms01_operation_policy import (
    assert_comms01_operation,
    open_pinned_backup_file,
)
from comms01_scope import (
    assert_database_url,
    is_disposable_test_database,
    strict_libpq_query,
)
from exceptions import (
    AuthorizationFailureError,
    ProvenanceMismatchError,
    ScopeBoundaryViolationError,
)
from pinned_trust import read_json_file


MAX_RESTORE_BYTES = 512 * 1024 * 1024
PINNED_PG_RESTORE_EXECUTABLE = "/usr/lib/postgresql/17/bin/pg_restore"
PINNED_SYSTEMCTL_EXECUTABLE = "/usr/bin/systemctl"
PINNED_EXECUTABLE_MANIFEST_PATH = Path(__file__).with_name("pinned-executables.json")


def _load_pinned_executable_manifest() -> dict[str, dict[str, str]]:
    """Load the reviewed executable/package attestation from the source tree."""
    try:
        payload = read_json_file(
            str(PINNED_EXECUTABLE_MANIFEST_PATH),
            strict_owner=True,
            allow_service_group_read=True,
        )
    except (OSError, ScopeBoundaryViolationError, json.JSONDecodeError) as exc:
        raise ScopeBoundaryViolationError(
            "Comms-01 pinned executable manifest is unavailable or invalid"
        ) from exc
    if payload.get("schema_version") != 1 or not isinstance(payload.get("executables"), dict):
        raise ScopeBoundaryViolationError("Comms-01 pinned executable manifest schema is invalid")
    manifest: dict[str, dict[str, str]] = {}
    for executable, metadata in payload["executables"].items():
        if not isinstance(executable, str) or not executable.startswith("/"):
            raise ScopeBoundaryViolationError("pinned executable manifest path is invalid")
        if not isinstance(metadata, dict):
            raise ScopeBoundaryViolationError("pinned executable manifest entry is invalid")
        digest = str(metadata.get("sha256") or "")
        package = str(metadata.get("package") or "")
        package_version = str(metadata.get("package_version") or "")
        alternates_raw = metadata.get("sha256_alternates")
        alternates: list[str] = []
        if alternates_raw is not None:
            if not isinstance(alternates_raw, list):
                raise ScopeBoundaryViolationError(
                    f"pinned executable manifest alternates are invalid: {executable}"
                )
            alternates = [str(item) for item in alternates_raw]
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not package or not package_version:
            raise ScopeBoundaryViolationError(
                f"pinned executable manifest metadata is incomplete: {executable}"
            )
        for alternate in alternates:
            if not re.fullmatch(r"[0-9a-f]{64}", alternate):
                raise ScopeBoundaryViolationError(
                    f"pinned executable manifest alternate digest is invalid: {executable}"
                )
        manifest[executable] = {
            "sha256": digest,
            "sha256_alternates": alternates,
            "package": package,
            "package_version": package_version,
        }
    required = {PINNED_PG_RESTORE_EXECUTABLE, PINNED_SYSTEMCTL_EXECUTABLE}
    if set(manifest) != required:
        raise ScopeBoundaryViolationError(
            "pinned executable manifest does not match the fixed Comms-01 command set"
        )
    return manifest


PINNED_EXECUTABLE_METADATA = _load_pinned_executable_manifest()
PINNED_EXECUTABLE_SHA256 = {
    executable: metadata["sha256"]
    for executable, metadata in PINNED_EXECUTABLE_METADATA.items()
}


def _approved_executable_digests(executable_path: str) -> frozenset[str]:
    metadata = PINNED_EXECUTABLE_METADATA.get(executable_path)
    if metadata is None:
        return frozenset()
    digests = {metadata["sha256"]}
    for alternate in metadata.get("sha256_alternates", []):
        digests.add(alternate)
    return frozenset(digests)
SUBPROCESS_TIMEOUT_SECONDS = 60.0
RESTORE_TIMEOUT_BASE_SECONDS = 60.0
RESTORE_TIMEOUT_PER_MEGABYTE_SECONDS = 2.0
# At the 512 MiB input ceiling this is about 18 minutes (60s + 2s/MiB);
# keep a hard upper bound below one maintenance window rather than allowing
# an unbounded destructive child to hold a disposable target for an hour.
RESTORE_TIMEOUT_MAX_SECONDS = 1200.0
MAX_CHILD_DIAGNOSTIC_BYTES = 4096
MAX_RESTORE_FAILURE_RECORDS = 32
MAX_RESTORE_FAILURE_STATE_QUARANTINES = 4
RESTORE_FAILURE_ROTATION_LOCK_NAME = ".restore-failure-rotation.lock"
RESTORE_TARGET_LOCK_NAME = ".restore-target.lock"
MAX_RESTORE_CLEARANCE_RECORDS = 32
_SAFE_SUBPROCESS_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
}


class PinnedCommandTimeoutError(AuthorizationFailureError):
    """A fixed child exceeded its operation-specific deadline."""

    def __init__(self, message: str, *, diagnostics: str = "") -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


class PartialRestoreError(AuthorizationFailureError):
    """A destructive disposable restore may have stopped mid-operation."""


def _write_all(fd: int, payload: bytes) -> None:
    """Write every byte or fail before recording a purportedly durable state."""
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("bounded file write made no progress")
        view = view[written:]


def _open_pinned_executable(path: str) -> int:
    """Open one root-owned executable by descriptor, never through PATH."""
    candidate = os.path.normpath(path)
    components = candidate.split(os.sep)
    if not candidate.startswith(os.sep) or len(components) < 3 or not components[-1]:
        raise ScopeBoundaryViolationError("pinned Comms-01 executable path must be absolute")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        current_fd = os.open(os.sep, directory_flags)
    except OSError as exc:
        raise ScopeBoundaryViolationError("pinned executable root cannot be opened") from exc
    try:
        root_stat = os.fstat(current_fd)
        if root_stat.st_uid != 0 or root_stat.st_mode & 0o022:
            raise ScopeBoundaryViolationError(
                f"pinned executable root is not root-owned and private: {path}"
            )
        for component in components[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            previous_fd = current_fd
            current_fd = next_fd
            os.close(previous_fd)
            directory_stat = os.fstat(current_fd)
            if directory_stat.st_uid != 0 or directory_stat.st_mode & 0o022:
                raise ScopeBoundaryViolationError(
                    f"pinned executable directory is not root-owned and private: {path}"
                )
        fd = os.open(
            components[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current_fd,
        )
        executable_stat = os.fstat(fd)
        if not stat.S_ISREG(executable_stat.st_mode):
            raise ScopeBoundaryViolationError(
                f"pinned Comms-01 executable is not a regular file: {path}"
            )
        if executable_stat.st_uid != 0 or executable_stat.st_mode & 0o022:
            raise ScopeBoundaryViolationError(
                f"pinned Comms-01 executable is not root-owned and non-writable: {path}"
            )
        if not executable_stat.st_mode & 0o111:
            raise ScopeBoundaryViolationError(
                f"pinned Comms-01 executable is not executable: {path}"
            )
        expected_digests = _approved_executable_digests(candidate)
        if not expected_digests:
            raise ScopeBoundaryViolationError(
                f"pinned Comms-01 executable is absent from the reviewed manifest: {path}"
            )
        digest = hashlib.sha256()
        offset = 0
        while offset < executable_stat.st_size:
            chunk = os.pread(fd, min(1024 * 1024, executable_stat.st_size - offset), offset)
            if not chunk:
                raise ScopeBoundaryViolationError(
                    f"pinned Comms-01 executable changed while being verified: {path}"
                )
            digest.update(chunk)
            offset += len(chunk)
        if digest.hexdigest() not in expected_digests:
            raise ScopeBoundaryViolationError(
                f"pinned Comms-01 executable digest does not match approval: {path}"
            )
        return fd
    except BaseException:
        if "fd" in locals():
            os.close(fd)
        raise
    finally:
        os.close(current_fd)


def _password_free_database_url(database_url: str) -> tuple[str, str | None]:
    """Return a pg_restore URL with credentials removed from argv."""
    query = strict_libpq_query(database_url)
    parsed = urlsplit(database_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise AuthorizationFailureError("restore database URL has an invalid port") from exc
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    if parsed.username is not None:
        netloc = f"{quote(unquote(parsed.username), safe='')}@{netloc}"
    # The Comms-01 target contract permits only the explicitly pinned Unix
    # socket and port query pair for socket URLs. Preserve that verified
    # routing exactly; silently dropping it could send pg_restore to a default
    # socket/port different from the target checked above.
    query_keys = {key.lower() for key in query}
    if not query_keys <= {"host", "port"}:
        raise AuthorizationFailureError(
            "restore database URL contains an unapproved routing parameter"
        )
    safe_url = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))
    password = unquote(parsed.password) if parsed.password is not None else None
    return safe_url, password


def _create_sealed_restore_fd(payload: bytes) -> int:
    """Create an immutable, runner-private descriptor for pg_restore input."""
    if not hasattr(os, "memfd_create"):
        raise ScopeBoundaryViolationError("sealed restore descriptors are unavailable")
    flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
    fd = os.memfd_create("top-delivery-restore", flags)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("sealed restore write made no progress")
            view = view[written:]
        # libpq requires a password file to be private.  Apply this to all
        # sealed descriptors before the child receives the passfile path.
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        _seal_restore_fd(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _seal_restore_fd(fd: int) -> None:
    seal_flags = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SEAL
    )
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seal_flags)


def _pgpass_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace(":", "\\:")


def _create_restore_passfile_fd(database_url: str, password: str) -> int:
    parsed = urlsplit(database_url)
    query = strict_libpq_query(database_url)
    username = unquote(parsed.username or "")
    host = parsed.hostname or query.get("host", [""])[0]
    database = parsed.path.lstrip("/")
    try:
        port = parsed.port
        if port is None and query.get("port"):
            port = int(query["port"][0])
    except (TypeError, ValueError) as exc:
        raise AuthorizationFailureError("restore password target port is invalid") from exc
    if not username or not host or not database or port is None or port <= 0:
        raise AuthorizationFailureError("restore password requires an explicit database role")
    payload = (
        f"{_pgpass_escape(host)}:{port}:{_pgpass_escape(database)}:"
        f"{_pgpass_escape(username)}:{_pgpass_escape(password)}\n"
    ).encode("utf-8")
    return _create_sealed_restore_fd(payload)


def _open_verified_restore_fd(
    *,
    database_url: str,
    backup_path: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt,
    restore_target: dict[str, Any],
) -> tuple[int, str]:
    """Stream an approved backup into a sealed descriptor without a second payload copy."""
    target = dict(restore_target)
    target["backup_path"] = backup_path
    # The exact restore receipt was verified by the locked caller immediately
    # before this helper.  Open only the already-pinned artifact here so the
    # same receipt is not consumed/verified a second time.
    source_fd = open_pinned_backup_file(backup_path, purpose="restore")
    restore_fd: int | None = None
    try:
        expected_size = target.get("backup_size")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool):
            raise AuthorizationFailureError("restore backup size is not approved")
        if expected_size <= 0 or expected_size > MAX_RESTORE_BYTES:
            raise ScopeBoundaryViolationError("restore backup size is outside the bounded limit")
        file_stat = os.fstat(source_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ScopeBoundaryViolationError("restore backup must be a regular file")
        if file_stat.st_size != expected_size:
            raise AuthorizationFailureError("restore backup size does not match approval")
        if not hasattr(os, "memfd_create"):
            raise ScopeBoundaryViolationError("sealed restore descriptors are unavailable")
        flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
        restore_fd = os.memfd_create("top-delivery-restore", flags)
        os.lseek(source_fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(source_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise AuthorizationFailureError("restore backup was truncated after approval")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(restore_fd, view)
                if written <= 0:
                    raise OSError("sealed restore write made no progress")
                view = view[written:]
            remaining -= len(chunk)
        if os.read(source_fd, 1):
            raise AuthorizationFailureError("restore backup grew after approval")
        actual_digest = digest.hexdigest()
        if actual_digest != str(target.get("backup_digest") or ""):
            raise AuthorizationFailureError("restore backup digest does not match approval")
        os.fsync(restore_fd)
        _seal_restore_fd(restore_fd)
        os.lseek(restore_fd, 0, os.SEEK_SET)
        return restore_fd, actual_digest
    except BaseException:
        if restore_fd is not None:
            os.close(restore_fd)
        raise
    finally:
        os.close(source_fd)


def _read_bounded_child_diagnostics(stream: Any | None) -> str:
    """Read a bounded diagnostic prefix without allowing child output to grow memory."""
    if stream is None:
        return ""
    stream.seek(0)
    raw = stream.read(MAX_CHILD_DIAGNOSTIC_BYTES + 1)
    truncated = len(raw) > MAX_CHILD_DIAGNOSTIC_BYTES
    if truncated:
        raw = raw[:MAX_CHILD_DIAGNOSTIC_BYTES]
    text = raw.decode("utf-8", errors="replace").replace("\x00", "�")
    if truncated:
        text += "\n[child diagnostics truncated]"
    return text


def _run_fixed_command(
    *,
    executable: str,
    arguments: tuple[str, ...],
    check: bool,
    pass_fds: tuple[int, ...] = (),
    env: dict[str, str] | None = None,
    timeout_seconds: float = SUBPROCESS_TIMEOUT_SECONDS,
    capture_diagnostics: bool = False,
    capture_stdout: bool = False,
):
    executable_fd = _open_pinned_executable(executable)
    diagnostic_file = tempfile.TemporaryFile(mode="w+b") if capture_diagnostics else None
    stdout_target = subprocess.PIPE if capture_stdout else subprocess.DEVNULL
    try:
        try:
            result = subprocess.run(
                (f"/proc/self/fd/{executable_fd}", *arguments),
                check=check,
                stdout=stdout_target,
                stderr=diagnostic_file if diagnostic_file is not None else subprocess.DEVNULL,
                text=True,
                timeout=timeout_seconds,
                env=dict(_SAFE_SUBPROCESS_ENV if env is None else env),
                pass_fds=(executable_fd, *pass_fds),
            )
        except subprocess.TimeoutExpired as exc:
            diagnostics = _read_bounded_child_diagnostics(diagnostic_file)
            raise PinnedCommandTimeoutError(
                f"pinned Comms-01 command exceeded {timeout_seconds:g}s",
                diagnostics=diagnostics,
            ) from exc
        if diagnostic_file is not None:
            result.stderr = _read_bounded_child_diagnostics(diagnostic_file)
        return result
    finally:
        if diagnostic_file is not None:
            diagnostic_file.close()
        os.close(executable_fd)


def open_backup_target(
    *,
    database_url: str,
    backup_path: str,
    purpose: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt | None = None,
    rotation_target: dict[str, Any] | None = None,
) -> int:
    """Gate and safely open the exact Comms-01 backup target."""
    assert_comms01_operation(
        operation=purpose,
        database_url=database_url,
        backup_path=backup_path,
        operator_approval_receipt=operator_approval_receipt,
        rotation_target=rotation_target,
    )
    return open_pinned_backup_file(backup_path, purpose=purpose)


def authorize_restore(
    *,
    database_url: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt,
    restore_target: dict[str, Any],
) -> None:
    """Gate a restore before the caller reads or writes any database state."""
    assert_comms01_operation(
        operation="restore",
        database_url=database_url,
        backup_path=str(restore_target.get("backup_path") or ""),
        operator_approval_receipt=operator_approval_receipt,
        rotation_target=restore_target,
    )


def authorize_service_action(*, operation: str, service_name: str) -> None:
    """Gate a Comms-01 service status/restart action."""
    assert_comms01_operation(operation=operation, service_name=service_name)


def backup_bytes(*, database_url: str, backup_path: str, payload: bytes) -> str:
    """Write one exact backup artifact through the only backup side effect."""
    if len(payload) > MAX_RESTORE_BYTES:
        raise ScopeBoundaryViolationError("backup payload is outside the bounded limit")
    fd = open_backup_target(
        database_url=database_url,
        backup_path=backup_path,
        purpose="backup",
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("backup write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return hashlib.sha256(payload).hexdigest()


def _open_verified_restore(
    *,
    database_url: str,
    backup_path: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt,
    restore_target: dict[str, Any],
) -> tuple[bytes, str]:
    """Read and verify one approved restore artifact before sealing a copy."""
    target = dict(restore_target)
    target["backup_path"] = backup_path
    authorize_restore(
        database_url=database_url,
        operator_approval_receipt=operator_approval_receipt,
        restore_target=target,
    )
    fd = open_backup_target(
        database_url=database_url,
        backup_path=backup_path,
        purpose="restore",
        operator_approval_receipt=operator_approval_receipt,
        rotation_target=target,
    )
    try:
        expected_size = target.get("backup_size")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool):
            raise AuthorizationFailureError("restore backup size is not approved")
        if expected_size <= 0 or expected_size > MAX_RESTORE_BYTES:
            raise ScopeBoundaryViolationError("restore backup size is outside the bounded limit")
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ScopeBoundaryViolationError("restore backup must be a regular file")
        if file_stat.st_size != expected_size:
            raise AuthorizationFailureError("restore backup size does not match approval")
        chunks: list[bytes] = []
        remaining = expected_size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise AuthorizationFailureError("restore backup was truncated after approval")
            chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise AuthorizationFailureError("restore backup grew after approval")
        payload = b"".join(chunks)
        actual_digest = digest.hexdigest()
        if actual_digest != str(target.get("backup_digest") or ""):
            raise AuthorizationFailureError("restore backup digest does not match approval")
        return payload, actual_digest
    except BaseException:
        raise
    finally:
        os.close(fd)


def restore_bytes(
    *,
    database_url: str,
    backup_path: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt,
    restore_target: dict[str, Any],
) -> tuple[bytes, str]:
    """Read a previously approved backup without applying it to a database."""
    payload, actual_digest = _open_verified_restore(
        database_url=database_url,
        backup_path=backup_path,
        operator_approval_receipt=operator_approval_receipt,
        restore_target=restore_target,
    )
    return payload, actual_digest


def _verify_disposable_restore_target(
    database_url: str,
    restore_target: dict[str, Any],
    *,
    verify_schema: bool = True,
) -> None:
    """Verify the approved live database identity and schema before restore."""
    import psycopg2

    from comms01_scope import verify_connection_identity

    parsed = urlsplit(database_url)
    query = strict_libpq_query(database_url)
    query_host = query.get("host", [""])[0]
    query_port = query.get("port", [""])[0]
    expected_name = str(restore_target.get("database_name") or "")
    expected_role = str(restore_target.get("database_role") or "")
    expected_endpoint = str(restore_target.get("database_endpoint") or "")
    expected_cluster = str(
        restore_target.get("cluster_system_identifier") or ""
    )
    expected_oid = str(restore_target.get("database_oid") or "")
    if (
        not expected_name
        or not expected_role
        or not expected_endpoint
        or not expected_cluster
        or not expected_oid
    ):
        raise AuthorizationFailureError("disposable restore target identity is incomplete")
    if parsed.path.lstrip("/") != expected_name or parsed.username != expected_role:
        raise AuthorizationFailureError("disposable restore target binding does not match URL")
    try:
        expected_port = int(restore_target.get("database_port"))
    except (TypeError, ValueError) as exc:
        raise AuthorizationFailureError("disposable restore target port is invalid") from exc
    if expected_port <= 0:
        raise AuthorizationFailureError("disposable restore target port is invalid")
    effective_port = parsed.port
    if effective_port is None and query_port:
        try:
            effective_port = int(query_port)
        except ValueError as exc:
            raise AuthorizationFailureError("restore target query port is invalid") from exc
    if effective_port != expected_port:
        raise AuthorizationFailureError("disposable restore target URL/port mismatch")
    effective_endpoint = parsed.hostname or query_host
    if effective_endpoint != expected_endpoint:
        raise AuthorizationFailureError("disposable restore target URL/endpoint mismatch")
    with closing(psycopg2.connect(database_url)) as conn:
        verify_connection_identity(
            database_url=database_url,
            connection=conn,
            expected_role=expected_role,
        )
        with conn.cursor() as cur:
            cur.execute(
                "SELECT current_database(), current_user, inet_server_addr()::text, "
                "inet_server_port(), current_setting('port')"
            )
            row = cur.fetchone()
            if row is None:
                raise AuthorizationFailureError("restore target identity could not be resolved")
            if row[0] != expected_name or row[1] != expected_role:
                raise AuthorizationFailureError("disposable restore connected to the wrong target")
            actual_port = row[3] if row[3] is not None else int(row[4])
            if int(actual_port) != expected_port:
                raise AuthorizationFailureError("disposable restore connected to the wrong port")
            if expected_endpoint.startswith("/"):
                # A restricted role may not inspect unix_socket_directories.
                # The pinned libpq URL and a successful connection through its
                # socket path are the endpoint proof; inet_server_addr() must
                # remain NULL for that connection.
                if row[2] is not None or query_host != expected_endpoint:
                    raise AuthorizationFailureError(
                        "disposable restore connected through the wrong Unix socket"
                    )
            elif str(row[2] or "").split("/", 1)[0].lower() != expected_endpoint.lower():
                raise AuthorizationFailureError("disposable restore connected to the wrong endpoint")
            cur.execute("SELECT system_identifier::text FROM pg_control_system()")
            cluster_row = cur.fetchone()
            cur.execute(
                "SELECT oid::text FROM pg_database WHERE datname = current_database()"
            )
            oid_row = cur.fetchone()
            if (
                cluster_row is None
                or str(cluster_row[0]) != expected_cluster
                or oid_row is None
                or str(oid_row[0]) != expected_oid
            ):
                raise ProvenanceMismatchError(
                    "disposable restore connected to the wrong PostgreSQL cluster/database"
                )
            if not verify_schema:
                return
            cur.execute("SELECT version_num FROM alembic_version")
            head_row = cur.fetchone()
            expected_head = str(restore_target.get("migration_head") or "")
            if head_row is None or head_row[0] != expected_head:
                raise AuthorizationFailureError(
                    "disposable restore target migration head is not approved"
                )
            from db import assert_migration_source_provenance

            assert_migration_source_provenance(cur, expected_head)


def _verify_disposable_restore_identity(
    database_url: str, restore_target: dict[str, Any]
) -> None:
    """Verify only immutable target identity before recovering a damaged schema."""
    _verify_disposable_restore_target(
        database_url, restore_target, verify_schema=False
    )


def _verify_disposable_restore_state(
    database_url: str,
    expected_migration_head: str,
    restore_target: dict[str, Any],
) -> None:
    """Verify identity and migration head after a restore or timeout."""
    if str(restore_target.get("migration_head") or "") != expected_migration_head:
        raise AuthorizationFailureError("restore target migration head binding changed")
    _verify_disposable_restore_target(database_url, restore_target)


def _assert_restore_fence_root() -> str:
    """Require the pre-created root-owned fence store before any restore."""
    root = os.path.normpath(_PINNED_RESTORE_FENCE_ROOT)
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise ScopeBoundaryViolationError(
            "Comms-01 restore fence root is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != 0
        or root_stat.st_mode & 0o077
    ):
        raise ScopeBoundaryViolationError(
            "Comms-01 restore fence root must be a root-owned 0700 directory"
        )
    return root


def _restore_fence_path(database_url: str, restore_target: dict[str, Any]) -> str:
    """Return one route- and role-independent fence for one cluster/database."""
    del database_url
    identity = _restore_fence_identity(restore_target)
    identity_fields = (
        identity["database_name"],
        identity["cluster_system_identifier"],
        identity["database_oid"],
    )
    # The Comms-01 policy pins the PostgreSQL endpoint independently; role and
    # route are deliberately excluded, while the immutable cluster system id
    # and database OID prevent same-name cross-cluster or drop/recreate aliasing.
    key = hashlib.sha256("\x1f".join(identity_fields).encode("utf-8")).hexdigest()
    return os.path.join(_assert_restore_fence_root(), f"fence-{key}")


def _restore_fence_identity(restore_target: dict[str, Any]) -> dict[str, str]:
    """Normalize and strictly validate immutable fence identity fields."""
    identity = {
        "database_name": str(restore_target.get("database_name") or "").strip(),
        "cluster_system_identifier": str(
            restore_target.get("cluster_system_identifier") or ""
        ).strip(),
        "database_oid": str(restore_target.get("database_oid") or "").strip(),
    }
    if (
        not re.fullmatch(r"[A-Za-z0-9_]{1,63}", identity["database_name"])
        or not re.fullmatch(r"[0-9]+", identity["cluster_system_identifier"])
        or not re.fullmatch(r"[0-9]+", identity["database_oid"])
    ):
        raise ScopeBoundaryViolationError(
            "restore target identity contains invalid fence characters"
        )
    return identity


def _acquire_restore_target_lock(
    database_url: str, restore_target: dict[str, Any]
) -> int:
    """Hold a root-owned exclusive lock across check, restore and verification."""
    fence_path = _restore_fence_path(database_url, restore_target)
    lock_path = str(Path(fence_path).parent / RESTORE_TARGET_LOCK_NAME)
    try:
        fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        lock_stat = os.fstat(fd)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != 0
            or lock_stat.st_mode & 0o077
            or lock_stat.st_mode & 0o6000
        ):
            raise ScopeBoundaryViolationError(
                "Comms-01 restore target lock must be a root-owned private regular file"
            )
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except BaseException:
        if "fd" in locals():
            os.close(fd)
        raise


def _write_restore_fence(
    database_url: str,
    backup_path: str,
    restore_target: dict[str, Any],
    reason: str,
) -> None:
    """Persist a target-wide fence until authenticated snapshot recovery."""
    fence_path = _restore_fence_path(database_url, restore_target)
    try:
        fd = os.open(
            fence_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError:
        return
    try:
        fence_stat = os.fstat(fd)
        if fence_stat.st_uid != 0 or fence_stat.st_mode & 0o077:
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence must be root-owned and private"
            )
        identity = _restore_fence_identity(restore_target)
        safe_reason = str(reason).replace("\r", " ").replace("\n", " ")[:240]
        payload = (
            "partial_restore_fence\n"
            f"database_name={identity['database_name']}\n"
            f"cluster_system_identifier={identity['cluster_system_identifier']}\n"
            f"database_oid={identity['database_oid']}\n"
            f"database_url_sha256={hashlib.sha256(database_url.encode('utf-8')).hexdigest()}\n"
            f"backup_path_sha256={hashlib.sha256(backup_path.encode('utf-8')).hexdigest()}\n"
            f"reason={safe_reason}\n"
            f"created_at={time.time():.6f}\n"
        ).encode("utf-8")
        _write_all(fd, payload)
        os.fsync(fd)
        directory_fd = os.open(
            _assert_restore_fence_root(),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(fd)


def _write_restore_fence_clearance(
    *,
    fence_path: str,
    approval_id: str,
    snapshot_digest: str,
    restore_target: dict[str, Any] | None = None,
) -> None:
    """Serialize and bound authenticated clearance records before fence removal."""
    root = Path(_assert_restore_fence_root())
    approval_key = hashlib.sha256(approval_id.encode("utf-8")).hexdigest()
    lock_fd = _open_restore_failure_rotation_lock(root)
    try:
        _rotate_restore_clearance_records_locked(root, fence_path, approval_key)
        _write_restore_fence_clearance_locked(
            fence_path=fence_path,
            approval_id=approval_id,
            snapshot_digest=snapshot_digest,
            restore_target=restore_target,
        )
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _rotate_restore_clearance_records_locked(
    root: Path,
    fence_path: str,
    approval_key: str,
) -> None:
    """Keep only the newest bounded clearance records under the rotation lock."""
    prefix = f"{Path(fence_path).name}.cleared-"
    current_path = root / f"{prefix}{approval_key}"
    temporary_pattern = re.compile(
        rf"^{re.escape(prefix)}[0-9a-f]{{64}}\.tmp-[0-9a-f]+$"
    )
    records_with_mtime: list[tuple[Path, int]] = []
    for candidate in root.glob(f"{prefix}*"):
        if temporary_pattern.fullmatch(candidate.name):
            continue
        candidate_stat = candidate.lstat()
        if (
            not stat.S_ISREG(candidate_stat.st_mode)
            or candidate_stat.st_uid != 0
            or candidate_stat.st_mode & 0o077
        ):
            raise ScopeBoundaryViolationError(
                f"restore fence clearance is not root-private regular file: {candidate}"
            )
        records_with_mtime.append((candidate, candidate_stat.st_mtime_ns))
    records = [
        candidate
        for candidate, _mtime in sorted(records_with_mtime, key=lambda item: item[1])
    ]
    if current_path in records:
        return
    overflow = max(0, len(records) - (MAX_RESTORE_CLEARANCE_RECORDS - 1))
    for candidate in records[:overflow]:
        candidate.unlink()


def _write_restore_fence_clearance_locked(
    *,
    fence_path: str,
    approval_id: str,
    snapshot_digest: str,
    restore_target: dict[str, Any] | None = None,
) -> None:
    """Record authenticated fence recovery before removing the durable fence."""
    root = _assert_restore_fence_root()
    approval_key = hashlib.sha256(approval_id.encode("utf-8")).hexdigest()
    clearance_path = f"{fence_path}.cleared-{approval_key}"
    stable_fields = {
        "approval_id_sha256": approval_key,
        "snapshot_digest": snapshot_digest,
    }
    payload_lines = ["partial_restore_fence_clearance\n"]
    payload_lines.extend(
        f"{key}={value}\n" for key, value in stable_fields.items()
    )
    payload_lines.append(f"cleared_at={time.time():.6f}\n")
    if restore_target is not None:
        identity = _restore_fence_identity(restore_target)
        stable_fields.update(
            {
                "database_name": identity["database_name"],
                "cluster_system_identifier": identity["cluster_system_identifier"],
                "database_oid": identity["database_oid"],
                "migration_head": str(restore_target.get("migration_head") or ""),
                "restore_verified": "1",
            }
        )
        payload_lines = ["partial_restore_fence_clearance\n"]
        payload_lines.extend(
            f"{key}={value}\n" for key, value in stable_fields.items()
        )
        payload_lines.append(f"cleared_at={time.time():.6f}\n")
    payload = "".join(payload_lines).encode("utf-8")
    if os.path.lexists(clearance_path):
        try:
            existing_fd = os.open(
                clearance_path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as exc:
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance is not safely openable"
            ) from exc
        try:
            existing_stat = os.fstat(existing_fd)
            if (
                not stat.S_ISREG(existing_stat.st_mode)
                or existing_stat.st_uid != 0
                or existing_stat.st_mode & 0o077
                or existing_stat.st_size <= 0
                or existing_stat.st_size > 8192
            ):
                raise ScopeBoundaryViolationError(
                    "Comms-01 restore fence clearance is not root-owned and private"
                )
            existing_raw = os.read(existing_fd, existing_stat.st_size + 1)
            if len(existing_raw) != existing_stat.st_size:
                raise ScopeBoundaryViolationError(
                    "Comms-01 restore fence clearance size changed while reading"
                )
            existing = existing_raw.decode("utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance is unreadable"
            ) from exc
        finally:
            os.close(existing_fd)
        fields: dict[str, str] = {}
        lines = existing.splitlines()
        if not lines or lines[0] != "partial_restore_fence_clearance":
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance header is malformed"
            )
        for line in lines[1:]:
            if "=" not in line:
                raise ScopeBoundaryViolationError(
                    "Comms-01 restore fence clearance contains malformed fields"
                )
            key, value = line.split("=", 1)
            if key in fields:
                raise ScopeBoundaryViolationError(
                    "Comms-01 restore fence clearance contains duplicate fields"
                )
            fields[key] = value
        expected_keys = set(stable_fields) | {"cleared_at"}
        if set(fields) != expected_keys:
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance fields are not canonical"
            )
        if any(
            any(char in value for char in "\x00\r\n")
            for value in fields.values()
        ):
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance contains control characters"
            )
        if any(fields.get(key) != value for key, value in stable_fields.items()):
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance does not match this recovery"
            )
        if "cleared_at" not in fields:
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance timestamp is missing"
            )
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", fields["cleared_at"]):
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance timestamp is invalid"
            )
        return
    temporary_path = Path(f"{clearance_path}.tmp-{time.time_ns():x}")
    fd = os.open(
        temporary_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        clearance_stat = os.fstat(fd)
        if (
            not stat.S_ISREG(clearance_stat.st_mode)
            or clearance_stat.st_uid != 0
            or clearance_stat.st_mode & 0o077
        ):
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence clearance must be root-owned and private"
            )
        _write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    os.replace(temporary_path, clearance_path)
    directory_fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _clear_verified_restore_fence(
    *,
    fence_path: str,
    restore_target: dict[str, Any],
    approval_id: str,
    snapshot_digest: str,
) -> None:
    """Remove a fence only after the locked restore has been verified."""
    try:
        fence_fd = os.open(
            fence_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError as exc:
        raise PartialRestoreError(
            "verified restore has no durable fence to clear"
        ) from exc
    try:
        _assert_restore_fence_matches_target(fence_fd, restore_target)
    finally:
        os.close(fence_fd)
    try:
        _write_restore_fence_clearance(
            fence_path=fence_path,
            approval_id=approval_id,
            snapshot_digest=snapshot_digest,
            restore_target=restore_target,
        )
        _cleanup_restore_failure_artifacts(
            Path(_assert_restore_fence_root()), fence_path
        )
        os.unlink(fence_path)
        root_fd = os.open(
            _assert_restore_fence_root(),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
    except Exception as exc:
        raise PartialRestoreError(
            "verified restore completed but its durable fence could not be cleared"
        ) from exc


def _assert_restore_fence_matches_target(
    fence_fd: int, restore_target: dict[str, Any]
) -> None:
    """Reject a fence file whose stored immutable identity is not this target."""
    fence_stat = os.fstat(fence_fd)
    if (
        not stat.S_ISREG(fence_stat.st_mode)
        or fence_stat.st_uid != 0
        or fence_stat.st_mode & 0o077
    ):
        raise ScopeBoundaryViolationError(
            "Comms-01 restore fence must be a root-owned private regular file"
        )
    if fence_stat.st_size <= 0 or fence_stat.st_size > 8192:
        raise ScopeBoundaryViolationError("Comms-01 restore fence size is invalid")
    os.lseek(fence_fd, 0, os.SEEK_SET)
    raw = os.read(fence_fd, fence_stat.st_size + 1)
    if len(raw) != fence_stat.st_size or not raw.startswith(b"partial_restore_fence\n"):
        raise ScopeBoundaryViolationError("Comms-01 restore fence header is malformed")
    fields: dict[str, str] = {}
    allowed_keys = {
        "database_name",
        "cluster_system_identifier",
        "database_oid",
        "database_url_sha256",
        "backup_path_sha256",
        "reason",
        "created_at",
    }
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise ScopeBoundaryViolationError("Comms-01 restore fence is not UTF-8") from exc
    for line in lines[1:]:
        if "=" not in line:
            raise ScopeBoundaryViolationError("Comms-01 restore fence line is malformed")
        key, value = line.split("=", 1)
        if key not in allowed_keys or key in fields:
            raise ScopeBoundaryViolationError("Comms-01 restore fence fields are invalid")
        if any(ord(character) < 0x20 for character in value):
            raise ScopeBoundaryViolationError(
                "Comms-01 restore fence values contain control characters"
            )
        fields[key] = value
    required_keys = allowed_keys - {"reason"}
    if not required_keys <= fields.keys():
        raise ScopeBoundaryViolationError("Comms-01 restore fence fields are incomplete")
    if not re.fullmatch(r"[0-9a-f]{64}", fields["database_url_sha256"]):
        raise ScopeBoundaryViolationError(
            "Comms-01 restore fence database URL digest is invalid"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", fields["backup_path_sha256"]):
        raise ScopeBoundaryViolationError(
            "Comms-01 restore fence backup path digest is invalid"
        )
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", fields["created_at"]):
        raise ScopeBoundaryViolationError("Comms-01 restore fence timestamp is invalid")
    try:
        stored_identity = _restore_fence_identity(fields)
    except ScopeBoundaryViolationError:
        raise
    if any(fields.get(key) != value for key, value in stored_identity.items()):
        raise ScopeBoundaryViolationError(
            "Comms-01 restore fence identity is not normalized"
        )
    expected = _restore_fence_identity(restore_target)
    if any(stored_identity.get(key) != value for key, value in expected.items()):
        raise ProvenanceMismatchError(
            "restore fence identity does not match the approved live target"
        )


def _bind_restore_cluster_identity(
    database_url: str, restore_target: dict[str, Any]
) -> dict[str, Any]:
    """Bind a target to live cluster/database identity before fencing it."""
    import psycopg2

    from comms01_scope import verify_connection_identity

    _assert_restore_target_url_binding(database_url, restore_target)
    expected_name = str(restore_target.get("database_name") or "")
    expected_role = str(restore_target.get("database_role") or "")
    with closing(psycopg2.connect(database_url)) as conn:
        verify_connection_identity(
            database_url=database_url,
            connection=conn,
            expected_role=expected_role,
        )
        with conn.cursor() as cur:
            cur.execute(
                "SELECT current_database(), current_user, "
                "system_identifier::text FROM pg_control_system()"
            )
            identity_row = cur.fetchone()
            cur.execute(
                "SELECT oid::text FROM pg_database WHERE datname = current_database()"
            )
            oid_row = cur.fetchone()
    if (
        identity_row is None
        or identity_row[0] != expected_name
        or identity_row[1] != expected_role
        or not identity_row[2]
        or oid_row is None
        or not oid_row[0]
    ):
        raise AuthorizationFailureError(
            "restore target cluster/database identity could not be established"
        )
    bound = dict(restore_target)
    bound["cluster_system_identifier"] = str(identity_row[2])
    bound["database_oid"] = str(oid_row[0])
    return bound


def _assert_restore_target_url_binding(
    database_url: str, restore_target: dict[str, Any]
) -> None:
    """Validate the pinned URL/target contract without opening a connection."""
    assert_database_url(database_url)
    parsed = urlsplit(database_url)
    query = strict_libpq_query(database_url)
    query_host = query.get("host", [""])[0]
    query_port = query.get("port", [""])[0]
    expected_name = str(restore_target.get("database_name") or "")
    expected_role = str(restore_target.get("database_role") or "")
    expected_endpoint = str(restore_target.get("database_endpoint") or "")
    if (
        not expected_name
        or not expected_role
        or not expected_endpoint
        or parsed.path.lstrip("/") != expected_name
        or parsed.username != expected_role
    ):
        raise AuthorizationFailureError("restore target binding does not match URL")
    try:
        expected_port = int(restore_target.get("database_port"))
        effective_port = parsed.port
        if effective_port is None and query_port:
            effective_port = int(query_port)
    except (TypeError, ValueError) as exc:
        raise AuthorizationFailureError("restore target port is invalid") from exc
    effective_endpoint = parsed.hostname or query_host
    if expected_port <= 0 or effective_port != expected_port:
        raise AuthorizationFailureError("restore target URL/port mismatch")
    if effective_endpoint != expected_endpoint:
        raise AuthorizationFailureError("restore target URL/endpoint mismatch")


def clear_restore_fence_after_snapshot_recovery(
    *,
    database_url: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt,
    restore_target: dict[str, Any],
    recovery_snapshot_path: str,
    recovery_snapshot_digest: str,
    recovery_snapshot_size: int,
) -> str:
    """Clear one partial-restore fence only after 2FA and recovery proof."""
    if not is_disposable_test_database(database_url):
        raise ScopeBoundaryViolationError(
            "restore fence clearing is permitted only for a disposable Comms-01 database"
        )
    target = dict(restore_target)
    target.update(
        {
            "recovery_snapshot_path": recovery_snapshot_path,
            "recovery_snapshot_digest": recovery_snapshot_digest,
            "recovery_snapshot_size": recovery_snapshot_size,
        }
    )
    recovery_migration_head = str(
        target.get("recovery_snapshot_migration_head") or ""
    )
    recovery_source_digest = str(
        target.get("recovery_snapshot_source_digest") or ""
    )
    if recovery_migration_head != str(target.get("migration_head") or ""):
        raise AuthorizationFailureError(
            "recovery snapshot migration head is not bound to the target"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", recovery_source_digest):
        raise AuthorizationFailureError(
            "recovery snapshot source provenance is not bound"
        )
    from db import migration_source_digest

    if recovery_source_digest != migration_source_digest(recovery_migration_head):
        raise ProvenanceMismatchError(
            "recovery snapshot source provenance does not match the reviewed migration"
        )
    # Validate the caller-selected route and pinned target before any database
    # connection is opened.  Identity binding below is then an observation of
    # the already-authorized endpoint, not the first scope check.
    _assert_restore_target_url_binding(database_url, target)
    # Bind immutable PostgreSQL cluster/database identity before constructing
    # or verifying the operator receipt.  The caller cannot authorize one
    # target and then substitute a same-name database on another cluster.
    target = _bind_restore_cluster_identity(database_url, target)
    assert_comms01_operation(
        operation="restore-fence-clear",
        database_url=database_url,
        backup_path=recovery_snapshot_path,
        operator_approval_receipt=operator_approval_receipt,
        rotation_target=target,
    )
    lock_fd = _acquire_restore_target_lock(database_url, target)
    try:
        stable_target = _bind_restore_cluster_identity(database_url, target)
        if any(
            stable_target[field] != target[field]
            for field in ("cluster_system_identifier", "database_oid")
        ):
            raise ProvenanceMismatchError(
                "restore fence target cluster/database identity changed before recovery"
            )
        target = stable_target
        fence_path = _restore_fence_path(database_url, target)
        try:
            fence_fd = os.open(
                fence_path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except FileNotFoundError as exc:
            raise AuthorizationFailureError(
                "no partial-restore fence exists for the approved target"
            ) from exc
        try:
            _assert_restore_fence_matches_target(fence_fd, target)
        finally:
            os.close(fence_fd)
        recovery_target = dict(target)
        recovery_target.update(
            {
                "backup_path": recovery_snapshot_path,
                "backup_digest": recovery_snapshot_digest,
                "backup_size": recovery_snapshot_size,
                "migration_head": recovery_migration_head,
            }
        )
        actual_snapshot_digest = _execute_verified_pg_restore_locked(
            database_url=database_url,
            backup_path=recovery_snapshot_path,
            operator_approval_receipt=operator_approval_receipt,
            restore_target=recovery_target,
            recovery_mode=True,
        )
        _clear_verified_restore_fence(
            fence_path=fence_path,
            restore_target=target,
            approval_id=operator_approval_receipt.approval_id,
            snapshot_digest=actual_snapshot_digest,
        )
        return actual_snapshot_digest
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _fence_restore_target(
    database_url: str,
    backup_path: str,
    restore_target: dict[str, Any],
    reason: str,
    diagnostics: str = "",
) -> None:
    """Fence fail-closed; never surface a partial restore without durable evidence."""
    try:
        _write_restore_fence(database_url, backup_path, restore_target, reason)
        _write_restore_failure_evidence(
            fence_path=_restore_fence_path(database_url, restore_target),
            restore_target=restore_target,
            reason=reason,
            diagnostics=diagnostics,
        )
    except Exception as exc:
        raise PartialRestoreError(
            "disposable restore outcome is unknown and target fencing could not be persisted"
        ) from exc


def _write_restore_failure_evidence(
    *,
    fence_path: str,
    restore_target: dict[str, Any],
    reason: str,
    diagnostics: str,
) -> None:
    """Persist bounded child diagnostics beside the durable restore fence."""
    root = Path(_assert_restore_fence_root())
    identity = _restore_fence_identity(restore_target)
    safe_reason = str(reason).replace("\x00", "�").replace("\r", " ").replace("\n", " ")[:240]
    safe_diagnostics = str(diagnostics).replace("\x00", "�")[:MAX_CHILD_DIAGNOSTIC_BYTES]
    evidence_key = hashlib.sha256(
        (safe_reason + "\n" + safe_diagnostics).encode("utf-8")
    ).hexdigest()
    # Keep identical repeated failures as separate durable occurrences; a
    # content-only O_EXCL filename would silently discard the second event.
    # Rotation and creation are one locked transaction so the bounded count
    # cannot be exceeded by a concurrent writer.
    evidence_path = root / f"{Path(fence_path).name}.failure-{evidence_key}-{time.time_ns():x}"
    payload = (
        "partial_restore_failure\n"
        f"database_name={identity['database_name']}\n"
        f"cluster_system_identifier={identity['cluster_system_identifier']}\n"
        f"database_oid={identity['database_oid']}\n"
        f"reason={safe_reason}\n"
        f"diagnostics_sha256={hashlib.sha256(safe_diagnostics.encode('utf-8')).hexdigest()}\n"
        f"recorded_at={time.time():.6f}\n"
        "diagnostics_begin\n"
        f"{safe_diagnostics}\n"
        "diagnostics_end\n"
    ).encode("utf-8")
    _rotate_restore_failure_evidence(
        root,
        fence_path,
        evidence_path=evidence_path,
        payload=payload,
    )


def _open_restore_failure_rotation_lock(root: Path) -> int:
    """Open the one permanent root-wide mutex for failure evidence."""
    lock_path = root / RESTORE_FAILURE_ROTATION_LOCK_NAME
    lock_fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        lock_stat = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != 0
            or lock_stat.st_mode & 0o077
        ):
            raise ScopeBoundaryViolationError(
                "restore failure rotation lock must be root-owned and private"
            )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        return lock_fd
    except BaseException:
        os.close(lock_fd)
        raise


def _rotate_restore_failure_evidence(
    root: Path,
    fence_path: str,
    *,
    evidence_path: Path | None = None,
    payload: bytes | None = None,
) -> None:
    """Bound and append restore-failure evidence under one host-local mutex."""
    fence_name = Path(fence_path).name
    state_path = root / f"{fence_name}.rotation-state"
    dropped_counter_path = root / f"{fence_name}.rotation-drop-count"
    quarantine_counter_path = root / f"{fence_name}.rotation-quarantine-count"
    lock_fd = _open_restore_failure_rotation_lock(root)
    try:
        existing_failures_with_mtime: list[tuple[Path, int]] = []
        for candidate in root.glob(f"{Path(fence_path).name}.failure-*"):
            candidate_stat = candidate.lstat()
            if (
                not stat.S_ISREG(candidate_stat.st_mode)
                or candidate_stat.st_uid != 0
                or candidate_stat.st_mode & 0o077
            ):
                # Deliberately fail closed on a hostile evidence entry. The
                # operator must inspect and quarantine it out of band; the
                # fence remains active and no untrusted path is deleted.
                raise ScopeBoundaryViolationError(
                    f"restore failure evidence is not root-private regular file: {candidate}"
                )
            existing_failures_with_mtime.append((candidate, candidate_stat.st_mtime_ns))
        existing_failures = [
            candidate
            for candidate, _mtime in sorted(
                existing_failures_with_mtime, key=lambda item: item[1]
            )
        ]
        prior_dropped = 0
        prior_quarantined = 0
        state_reset = False
        counter_reset = False
        if os.path.lexists(dropped_counter_path):
            dropped_counter_stat = dropped_counter_path.lstat()
            if (
                not stat.S_ISREG(dropped_counter_stat.st_mode)
                or dropped_counter_stat.st_uid != 0
                or dropped_counter_stat.st_mode & 0o077
            ):
                raise ScopeBoundaryViolationError(
                    "restore failure drop counter is not root-owned and private"
                )
            dropped_counter_match = re.fullmatch(
                r"dropped_occurrences=(\d+)\n?",
                dropped_counter_path.read_text(encoding="utf-8"),
            )
            if dropped_counter_match is None:
                drop_counter_quarantine_path = Path(
                    f"{dropped_counter_path}.malformed-{time.time_ns():x}"
                )
                os.rename(dropped_counter_path, drop_counter_quarantine_path)
                drop_counter_quarantine_stat = drop_counter_quarantine_path.lstat()
                if (
                    not stat.S_ISREG(drop_counter_quarantine_stat.st_mode)
                    or drop_counter_quarantine_stat.st_uid != 0
                    or drop_counter_quarantine_stat.st_mode & 0o077
                ):
                    raise ScopeBoundaryViolationError(
                        "quarantined restore failure drop counter is not root-private"
                    )
                counter_reset = True
            else:
                prior_dropped = int(dropped_counter_match.group(1))
        if os.path.lexists(quarantine_counter_path):
            counter_stat = quarantine_counter_path.lstat()
            if (
                not stat.S_ISREG(counter_stat.st_mode)
                or counter_stat.st_uid != 0
                or counter_stat.st_mode & 0o077
            ):
                raise ScopeBoundaryViolationError(
                    "restore failure quarantine counter is not root-owned and private"
                )
            counter_match = re.fullmatch(
                r"quarantined_occurrences=(\d+)\n?",
                quarantine_counter_path.read_text(encoding="utf-8"),
            )
            if counter_match is None:
                counter_quarantine_path = Path(
                    f"{quarantine_counter_path}.malformed-{time.time_ns():x}"
                )
                os.rename(quarantine_counter_path, counter_quarantine_path)
                counter_quarantine_stat = counter_quarantine_path.lstat()
                if (
                    not stat.S_ISREG(counter_quarantine_stat.st_mode)
                    or counter_quarantine_stat.st_uid != 0
                    or counter_quarantine_stat.st_mode & 0o077
                ):
                    raise ScopeBoundaryViolationError(
                        "quarantined restore failure counter is not root-private"
                    )
                counter_reset = True
            else:
                prior_quarantined = int(counter_match.group(1))
        if os.path.lexists(state_path):
            state_stat = state_path.lstat()
            if (
                not stat.S_ISREG(state_stat.st_mode)
                or state_stat.st_uid != 0
                or state_stat.st_mode & 0o077
            ):
                raise ScopeBoundaryViolationError(
                    "restore failure rotation state is not root-owned and private"
                )
            state_text = state_path.read_text(encoding="utf-8")
            match = re.search(
                r"^dropped_occurrences=(\d+)$", state_text, re.MULTILINE
            )
            quarantined_match = re.search(
                r"^quarantined_occurrences=(\d+)$", state_text, re.MULTILINE
            )
            if match is None:
                quarantine_path = Path(
                    f"{state_path}.malformed-{time.time_ns():x}"
                )
                os.rename(state_path, quarantine_path)
                quarantine_stat = quarantine_path.lstat()
                if (
                    not stat.S_ISREG(quarantine_stat.st_mode)
                    or quarantine_stat.st_uid != 0
                    or quarantine_stat.st_mode & 0o077
                ):
                    raise ScopeBoundaryViolationError(
                        "quarantined restore failure rotation state is not root-private"
                    )
                state_reset = True
            else:
                prior_dropped = max(prior_dropped, int(match.group(1)))
                prior_quarantined = max(
                    prior_quarantined,
                    int(quarantined_match.group(1)) if quarantined_match else 0,
                )
        quarantined_with_mtime: list[tuple[Path, int]] = []
        for candidate in root.glob(f"{state_path.name}.malformed-*"):
            candidate_stat = candidate.lstat()
            if (
                not stat.S_ISREG(candidate_stat.st_mode)
                or candidate_stat.st_uid != 0
                or candidate_stat.st_mode & 0o077
            ):
                raise ScopeBoundaryViolationError(
                    f"quarantined restore failure state is not root-private regular file: {candidate}"
                )
            quarantined_with_mtime.append((candidate, candidate_stat.st_mtime_ns))
        quarantined = [
            candidate
            for candidate, _mtime in sorted(
                quarantined_with_mtime, key=lambda item: item[1]
            )
        ]
        counter_quarantines_with_mtime: list[tuple[Path, int]] = []
        for candidate in root.glob(
            f"{quarantine_counter_path.name}.malformed-*"
        ):
            candidate_stat = candidate.lstat()
            if (
                not stat.S_ISREG(candidate_stat.st_mode)
                or candidate_stat.st_uid != 0
                or candidate_stat.st_mode & 0o077
            ):
                raise ScopeBoundaryViolationError(
                    f"quarantined restore failure counter is not root-private regular file: {candidate}"
                )
            counter_quarantines_with_mtime.append((candidate, candidate_stat.st_mtime_ns))
        counter_quarantines = [
            candidate
            for candidate, _mtime in sorted(
                counter_quarantines_with_mtime, key=lambda item: item[1]
            )
        ]
        counter_quarantine_overflow = max(
            0,
            len(counter_quarantines) - MAX_RESTORE_FAILURE_STATE_QUARANTINES,
        )
        for candidate in counter_quarantines[:counter_quarantine_overflow]:
            candidate.unlink()
        drop_counter_quarantines_with_mtime: list[tuple[Path, int]] = []
        for candidate in root.glob(f"{dropped_counter_path.name}.malformed-*"):
            candidate_stat = candidate.lstat()
            if (
                not stat.S_ISREG(candidate_stat.st_mode)
                or candidate_stat.st_uid != 0
                or candidate_stat.st_mode & 0o077
            ):
                raise ScopeBoundaryViolationError(
                    f"quarantined restore failure drop counter is not root-private regular file: {candidate}"
                )
            drop_counter_quarantines_with_mtime.append(
                (candidate, candidate_stat.st_mtime_ns)
            )
        drop_counter_quarantines = [
            candidate
            for candidate, _mtime in sorted(
                drop_counter_quarantines_with_mtime, key=lambda item: item[1]
            )
        ]
        for candidate in drop_counter_quarantines[
            : max(
                0,
                len(drop_counter_quarantines)
                - MAX_RESTORE_FAILURE_STATE_QUARANTINES,
            )
        ]:
            candidate.unlink()
        quarantine_overflow = max(
            0, len(quarantined) - MAX_RESTORE_FAILURE_STATE_QUARANTINES
        )
        quarantined_dropped = 0
        for candidate in quarantined[:quarantine_overflow]:
            candidate.unlink()
            quarantined_dropped += 1
        # Preserve the first occurrence as the durable root of the incident
        # and retain the newest records for diagnosis.
        overflow = max(0, len(existing_failures) - (MAX_RESTORE_FAILURE_RECORDS - 1))
        dropped = 0
        for candidate in existing_failures[1 : 1 + overflow]:
            candidate.unlink()
            dropped += 1
        if dropped or state_reset or counter_reset or quarantined_dropped:
            state_payload = (
                f"dropped_occurrences={prior_dropped + dropped}\n"
                f"quarantined_occurrences={prior_quarantined + quarantined_dropped}\n"
                f"last_rotation_at={time.time():.6f}\n"
            ).encode("utf-8")
            temp_path = Path(f"{state_path}.tmp-{time.time_ns():x}")
            temp_fd = os.open(
                temp_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                _write_all(temp_fd, state_payload)
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)
            os.replace(temp_path, state_path)
            counter_payload = (
                f"quarantined_occurrences={prior_quarantined + quarantined_dropped}\n"
            ).encode("utf-8")
            counter_temp_path = Path(
                f"{quarantine_counter_path}.tmp-{time.time_ns():x}"
            )
            counter_fd = os.open(
                counter_temp_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                _write_all(counter_fd, counter_payload)
                os.fsync(counter_fd)
            finally:
                os.close(counter_fd)
            os.replace(counter_temp_path, quarantine_counter_path)
            dropped_counter_payload = (
                f"dropped_occurrences={prior_dropped + dropped}\n"
            ).encode("utf-8")
            dropped_counter_temp_path = Path(
                f"{dropped_counter_path}.tmp-{time.time_ns():x}"
            )
            dropped_counter_fd = os.open(
                dropped_counter_temp_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                _write_all(dropped_counter_fd, dropped_counter_payload)
                os.fsync(dropped_counter_fd)
            finally:
                os.close(dropped_counter_fd)
            os.replace(dropped_counter_temp_path, dropped_counter_path)
            directory_fd = os.open(
                root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        if evidence_path is not None or payload is not None:
            if evidence_path is None or payload is None:
                raise ValueError("evidence path and payload must be supplied together")
            if evidence_path.parent != root or not evidence_path.name.startswith(
                f"{Path(fence_path).name}.failure-"
            ):
                raise ScopeBoundaryViolationError(
                    "restore failure evidence path escaped its pinned fence root"
                )
            try:
                evidence_fd = os.open(
                    evidence_path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                )
            except FileExistsError as exc:
                raise ScopeBoundaryViolationError(
                    "restore failure evidence path already exists"
                ) from exc
            try:
                evidence_stat = os.fstat(evidence_fd)
                if (
                    not stat.S_ISREG(evidence_stat.st_mode)
                    or evidence_stat.st_uid != 0
                    or evidence_stat.st_mode & 0o077
                ):
                    raise ScopeBoundaryViolationError(
                        "Comms-01 restore failure evidence must be root-owned and private"
                    )
                _write_all(evidence_fd, payload)
                os.fsync(evidence_fd)
            finally:
                os.close(evidence_fd)
            directory_fd = os.open(
                root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _cleanup_restore_failure_artifacts(root: Path, fence_path: str) -> None:
    """Retain incident evidence and remove only incomplete temporary state."""
    lock_fd = _open_restore_failure_rotation_lock(root)
    try:
        # Failure records, rotation state, and malformed-state quarantines are
        # durable incident evidence and must survive verified fence clearance.
        # Only abandoned atomic-write temporary files are safe to remove.
        fence_name = Path(fence_path).name
        candidates = list(root.glob(f"{fence_name}.rotation-state.tmp-*"))
        candidates.extend(
            root.glob(f"{fence_name}.rotation-quarantine-count.tmp-*")
        )
        candidates.extend(root.glob(f"{fence_name}.rotation-drop-count.tmp-*"))
        candidates.extend(root.glob(f"{fence_name}.cleared-*.tmp-*"))
        for candidate in candidates:
            candidate_stat = candidate.lstat()
            if not stat.S_ISREG(candidate_stat.st_mode) or candidate.is_symlink():
                raise ScopeBoundaryViolationError(
                    f"restore failure artifact is not a regular file: {candidate}"
                )
            if candidate_stat.st_uid != 0 or candidate_stat.st_mode & 0o077:
                raise ScopeBoundaryViolationError(
                    f"restore failure artifact is not root-private: {candidate}"
                )
            candidate.unlink()
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    directory_fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def restore_disposable_database(
    *,
    database_url: str,
    backup_path: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt,
    restore_target: dict[str, Any],
) -> str:
    """Restore one dump while holding the target's exclusive Comms-01 lock."""
    if not is_disposable_test_database(database_url):
        raise ScopeBoundaryViolationError(
            "database restore is permitted only for a disposable Comms-01 database"
        )
    target = dict(restore_target)
    target["backup_path"] = backup_path
    target = _bind_restore_cluster_identity(database_url, target)
    lock_fd = _acquire_restore_target_lock(database_url, target)
    try:
        stable_target = _bind_restore_cluster_identity(database_url, target)
        if any(
            stable_target[field] != target[field]
            for field in ("cluster_system_identifier", "database_oid")
        ):
            raise ProvenanceMismatchError(
                "restore target cluster/database identity changed before execution"
            )
        target = stable_target
        return _restore_disposable_database_locked(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=operator_approval_receipt,
            restore_target=target,
        )
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _execute_verified_pg_restore_locked(
    *,
    database_url: str,
    backup_path: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt,
    restore_target: dict[str, Any],
    recovery_mode: bool = False,
) -> str:
    """Apply one sealed approved dump and verify the target before returning."""
    expected_migration_head = str(restore_target.get("migration_head") or "")
    if not expected_migration_head:
        raise AuthorizationFailureError(
            "disposable restore requires an expected Alembic migration head"
        )
    sealed_fd, actual_digest = _open_verified_restore_fd(
        database_url=database_url,
        backup_path=backup_path,
        operator_approval_receipt=operator_approval_receipt,
        restore_target=restore_target,
    )
    passfile_fd: int | None = None
    try:
        # Re-check the actual connected database, role, endpoint and port
        # before any destructive flag reaches pg_restore. The payload is a
        # sealed descriptor, so a named-source swap cannot change the bytes.
        if recovery_mode:
            _verify_disposable_restore_identity(database_url, restore_target)
        else:
            _verify_disposable_restore_target(database_url, restore_target)
        restore_url, password = _password_free_database_url(database_url)
        child_env = dict(_SAFE_SUBPROCESS_ENV)
        if password is not None:
            passfile_fd = _create_restore_passfile_fd(database_url, password)
            child_env["PGPASSFILE"] = f"/proc/self/fd/{passfile_fd}"
        restore_timeout = min(
            RESTORE_TIMEOUT_MAX_SECONDS,
            RESTORE_TIMEOUT_BASE_SECONDS
            + (int(restore_target["backup_size"]) / (1024 * 1024))
            * RESTORE_TIMEOUT_PER_MEGABYTE_SECONDS,
        )
        try:
            result = _run_fixed_command(
                executable=PINNED_PG_RESTORE_EXECUTABLE,
                arguments=(
                    "--exit-on-error",
                    "--clean",
                    "--if-exists",
                    "--no-owner",
                    "--dbname",
                    restore_url,
                    f"/proc/self/fd/{sealed_fd}",
                ),
                check=False,
                pass_fds=tuple(
                    fd for fd in (sealed_fd, passfile_fd) if fd is not None
                ),
                env=child_env,
                timeout_seconds=restore_timeout,
                capture_diagnostics=True,
            )
        except PinnedCommandTimeoutError as exc:
            _fence_restore_target(
                database_url,
                backup_path,
                restore_target,
                "pg_restore timeout",
                exc.diagnostics,
            )
            try:
                _verify_disposable_restore_state(
                    database_url, expected_migration_head, restore_target
                )
                state = "identity and Alembic-head checks passed"
            except Exception as state_exc:
                state = f"post-timeout state is unknown: {state_exc}"
            raise PartialRestoreError(
                f"disposable restore exceeded {restore_timeout:g}s; {state}; "
                "restore outcome requires disposable snapshot recovery"
            ) from exc
        if result.returncode != 0:
            _fence_restore_target(
                database_url,
                backup_path,
                restore_target,
                f"pg_restore exit {result.returncode}",
                str(getattr(result, "stderr", "") or ""),
            )
            raise PartialRestoreError(
                "disposable restore exited nonzero; target is fenced and requires "
                "disposable snapshot recovery"
            )
        try:
            _verify_disposable_restore_state(
                database_url, expected_migration_head, restore_target
            )
        except Exception as exc:
            _fence_restore_target(
                database_url,
                backup_path,
                restore_target,
                f"post-restore verification failed: {type(exc).__name__}",
                str(exc),
            )
            raise PartialRestoreError(
                "post-restore identity or Alembic-head verification failed; "
                "target is fenced and requires disposable snapshot recovery"
            ) from exc
    finally:
        if passfile_fd is not None:
            os.close(passfile_fd)
        os.close(sealed_fd)
    return actual_digest


def _restore_disposable_database_locked(
    *,
    database_url: str,
    backup_path: str,
    operator_approval_receipt: ExternalOperatorApprovalReceipt,
    restore_target: dict[str, Any],
) -> str:
    """Restore one approved dump into a disposable Comms-01 test database only."""
    if not is_disposable_test_database(database_url):
        raise ScopeBoundaryViolationError(
            "database restore is permitted only for a disposable Comms-01 database"
        )
    target = dict(restore_target)
    target["backup_path"] = backup_path
    # Authenticate the exact backup request before checking persisted fence
    # state or opening the backup file.  Live cluster binding is read-only and
    # has already been performed before this locked helper is entered.
    authorize_restore(
        database_url=database_url,
        operator_approval_receipt=operator_approval_receipt,
        restore_target=target,
    )
    fence_path = _restore_fence_path(database_url, restore_target)
    if os.path.lexists(fence_path):
        fence_fd = os.open(
            fence_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            _assert_restore_fence_matches_target(fence_fd, restore_target)
        finally:
            os.close(fence_fd)
        raise PartialRestoreError(
            "disposable restore target is fenced after a prior partial restore; "
            "recover the target from its disposable snapshot before reuse"
        )
    if not str(restore_target.get("migration_head") or ""):
        raise AuthorizationFailureError(
            "disposable restore requires an expected Alembic migration head"
        )
    try:
        # The fence is created before opening the approved payload or spawning
        # pg_restore.  A crash at any point therefore leaves the target
        # unavailable until a separately authorised snapshot recovery succeeds.
        _write_restore_fence(
            database_url,
            backup_path,
            restore_target,
            "restore in progress",
        )
    except Exception as exc:
        raise PartialRestoreError(
            "disposable restore could not persist its in-progress fence"
        ) from exc
    try:
        actual_digest = _execute_verified_pg_restore_locked(
            database_url=database_url,
            backup_path=backup_path,
            operator_approval_receipt=operator_approval_receipt,
            restore_target=restore_target,
        )
    except PartialRestoreError:
        raise
    except AuthorizationFailureError as exc:
        # Preserve the typed boundary error, but also record it. The helper
        # normally fails before spawning pg_restore; if a future adapter moves
        # an authorization check later, this evidence still makes the fence
        # outcome observable without laundering the error into a false success.
        try:
            _write_restore_failure_evidence(
                fence_path=fence_path,
                restore_target=restore_target,
                reason=f"restore authorization failure: {type(exc).__name__}",
                diagnostics=str(exc),
            )
        except Exception as evidence_exc:
            exc.add_note(
                "restore authorization evidence persistence failed: "
                f"{type(evidence_exc).__name__}: {evidence_exc}"
            )
        raise
    except Exception as exc:
        # Failures before the pg_restore child starts still leave an
        # in-progress fence. Persist a bounded occurrence so operators can
        # distinguish a pre-child validation failure from an unknown restore.
        _fence_restore_target(
            database_url,
            backup_path,
            restore_target,
            f"pre-child restore failure: {type(exc).__name__}",
            str(exc),
        )
        raise PartialRestoreError(
            "disposable restore failed before pg_restore started; target is fenced"
        ) from exc
    _clear_verified_restore_fence(
        fence_path=fence_path,
        restore_target=restore_target,
        approval_id=operator_approval_receipt.approval_id,
        snapshot_digest=actual_digest,
    )
    return actual_digest


def service_status(*, service_name: str) -> str:
    """Query one allow-listed Comms-01 service; arbitrary commands are impossible."""
    authorize_service_action(operation="service-status", service_name=service_name)
    result = _run_fixed_command(
        executable=PINNED_SYSTEMCTL_EXECUTABLE,
        arguments=("is-active", service_name),
        check=False,
        capture_stdout=True,
    )
    state = (result.stdout or "").strip().lower()
    if state in {"active", "activating"}:
        return state
    return "inactive"


def service_restart(*, service_name: str) -> None:
    """Restart one allow-listed Comms-01 service through the fixed command path."""
    authorize_service_action(operation="service-restart", service_name=service_name)
    _run_fixed_command(
        executable=PINNED_SYSTEMCTL_EXECUTABLE,
        arguments=("restart", service_name),
        check=True,
    )


__all__ = [
    "authorize_restore",
    "authorize_service_action",
    "backup_bytes",
    "clear_restore_fence_after_snapshot_recovery",
    "open_backup_target",
    "restore_bytes",
    "restore_disposable_database",
    "service_restart",
    "service_status",
]
