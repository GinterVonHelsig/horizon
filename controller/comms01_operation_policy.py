"""Technical operation pins for the Comms-01 control-plane boundary.

This module is intentionally small and side-effect free.  Callers must prove
the target before invoking a backup, restore, service operation, or authority
rotation.  Release/deployment authority remains outside Comms-01 and is
rejected here rather than inferred from metadata.
"""

from __future__ import annotations

import os
import re
import stat
from typing import Any
from pathlib import Path
from urllib.parse import urlsplit

from authority_pins import COMMS01_BACKUP_ROOTS
from comms01_authority import (
    ExternalOperatorApprovalReceipt,
    verify_external_operator_approval_receipt,
)
from comms01_scope import (
    assert_comms01_entrypoint,
    assert_database_url,
    assert_service_name,
    assert_host_fingerprint,
    strict_libpq_query,
    verified_local_host_fingerprint,
)
from exceptions import AuthorizationFailureError, ScopeBoundaryViolationError
from release_boundary import deny_release_action


_OPERATIONS = frozenset(
    {
        "backup",
        "restore",
        "restore-fence-clear",
        "service-status",
        "service-restart",
        "authority-provision",
        "authority-rotate",
        "deploy",
    }
)
_SERVICE_OPERATIONS = frozenset(
    {"service-status", "service-restart", "authority-provision", "authority-rotate"}
)
_TWO_FACTOR_OPERATIONS = frozenset(
    {"restore", "restore-fence-clear", "authority-provision", "authority-rotate"}
)


def _assert_backup_path(path: str) -> None:
    if not path or not os.path.isabs(path):
        raise ScopeBoundaryViolationError("Comms-01 backup target must be an absolute path")
    candidate = os.path.normpath(path)
    if "\x00" in candidate:
        raise ScopeBoundaryViolationError("Comms-01 backup target contains NUL")
    # Reject symlinked ancestors as well as a symlink leaf.  The path is
    # validated again immediately before the filesystem operation by the
    # caller; this preflight prevents ordinary wrong-target mistakes while the
    # caller's no-follow/openat path closes the remaining TOCTOU window.
    current = Path(candidate)
    ancestors: list[Path] = []
    while current != current.parent:
        ancestors.append(current)
        current = current.parent
    for component in ancestors:
        if component.is_symlink():
            raise ScopeBoundaryViolationError(
                "Comms-01 backup target may not contain a symlinked path component"
            )
    for root in COMMS01_BACKUP_ROOTS:
        root_norm = os.path.normpath(root)
        try:
            if os.path.commonpath((candidate, root_norm)) == root_norm:
                return
        except ValueError:
            continue
    raise ScopeBoundaryViolationError(
        "backup target is outside the pinned Comms-01 backup roots"
    )


def open_pinned_backup_file(
    path: str,
    *,
    purpose: str,
) -> int:
    """Open a Comms-01 backup file with descriptor-based no-follow checks.

    Backup/restore callers must use this primitive after
    :func:`assert_comms01_operation`.  Walking from the filesystem root and
    opening every directory component with ``O_NOFOLLOW`` closes the
    check-then-use symlink window that a string/path preflight alone cannot
    close.  The caller owns and must close the returned descriptor.
    """
    if purpose not in {"backup", "restore"}:
        raise ScopeBoundaryViolationError(
            "backup file purpose must be exactly 'backup' or 'restore'"
        )
    _assert_backup_path(path)
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if purpose == "backup"
        else os.O_RDONLY
    )
    candidate = Path(os.path.normpath(path))
    components = candidate.parts
    if len(components) < 2 or components[0] != "/":
        raise ScopeBoundaryViolationError("backup target must name a file below a pinned root")
    if not components[-1] or components[-1] in {".", ".."}:
        raise ScopeBoundaryViolationError("backup target must name a file")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    current_fd = os.open("/", directory_flags)
    try:
        root_stat = os.fstat(current_fd)
        if root_stat.st_uid != 0 or root_stat.st_mode & 0o022:
            raise ScopeBoundaryViolationError(
                "backup target has an unsafe root directory"
            )
        matched_root = max(
            (
                Path(os.path.normpath(root))
                for root in COMMS01_BACKUP_ROOTS
                if os.path.commonpath((str(candidate), os.path.normpath(root)))
                == os.path.normpath(root)
            ),
            key=lambda path: len(path.parts),
        )
        secure_from_index = len(matched_root.parts) - 1
        for index, component in enumerate(components[1:-1], start=1):
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            directory_stat = os.fstat(next_fd)
            if index >= secure_from_index and (
                directory_stat.st_uid != 0
                or directory_stat.st_mode & 0o022
                or not stat.S_ISDIR(directory_stat.st_mode)
            ):
                os.close(next_fd)
                raise ScopeBoundaryViolationError(
                    "backup target has a non-root-owned or writable directory"
                )
            previous_fd = current_fd
            try:
                os.close(previous_fd)
            except BaseException:
                # Keep ownership of the previous descriptor until close
                # succeeds, and explicitly release the newly opened one if
                # the close itself fails.
                try:
                    os.close(next_fd)
                except OSError:
                    pass
                raise
            current_fd = next_fd
        return os.open(
            components[-1],
            flags | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=current_fd,
        )
    finally:
        # The returned file descriptor is independent of the parent
        # directory descriptor; close the latter on both success and failure.
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass


def assert_comms01_operation(
    *,
    operation: str,
    database_url: str | None = None,
    service_name: str | None = None,
    host_fingerprint: str | None = None,
    backup_path: str | None = None,
    operator_approval_receipt: ExternalOperatorApprovalReceipt | None = None,
    rotation_target: dict[str, Any] | None = None,
) -> None:
    """Validate one bounded Comms-01 operation before side effects."""
    normalized = operation.strip().lower().replace("_", "-")
    if normalized not in _OPERATIONS:
        raise ScopeBoundaryViolationError(
            f"operation {operation!r} is outside the Comms-01 operation contract"
        )
    local_host_fingerprint = verified_local_host_fingerprint()
    if host_fingerprint is not None and host_fingerprint != local_host_fingerprint:
        raise ScopeBoundaryViolationError(
            "operation host fingerprint is not the locally attested Comms-01 host"
        )
    assert_comms01_entrypoint(
        scope="comms-01",
        database_url=database_url,
        service_name=service_name,
        host_fingerprint=local_host_fingerprint,
    )
    assert_host_fingerprint(local_host_fingerprint)
    if database_url is not None:
        assert_database_url(database_url)
    if normalized == "backup":
        if backup_path is None:
            raise ScopeBoundaryViolationError("backup operation requires a pinned target path")
        _assert_backup_path(backup_path)
        if database_url is None:
            raise ScopeBoundaryViolationError("backup operation requires the pinned database")
    if normalized in _TWO_FACTOR_OPERATIONS:
        if operator_approval_receipt is None:
            raise AuthorizationFailureError(
                f"{normalized} requires a signed external 2FA receipt"
            )
        if rotation_target is None:
            raise AuthorizationFailureError(
                f"{normalized} requires an explicit target binding"
            )
        required = (
            "run_id",
            "operator_identity",
            "reviewed_sha",
            "tree_sha",
            "source_digest",
            "controller_epoch",
            "config_version",
            "challenge_epoch",
        )
        missing = [field for field in required if rotation_target.get(field) is None]
        if missing:
            raise AuthorizationFailureError(
                f"{normalized} target binding is incomplete: {', '.join(missing)}"
            )
        from longspan_crypto import digest_payload, hash_capability_token

        if normalized == "authority-provision":
            for field in ("terra_auth_token", "operator_auth_token"):
                if not rotation_target.get(field):
                    raise AuthorizationFailureError(
                        f"authority provisioning target is missing {field}"
                    )
            expected_action_digest = digest_payload(
                {
                    "action": "initial_provision",
                    "run_id": rotation_target["run_id"],
                    "operator_identity": rotation_target["operator_identity"],
                    "reviewed_sha": rotation_target["reviewed_sha"],
                    "tree_sha": rotation_target["tree_sha"],
                    "source_digest": rotation_target["source_digest"],
                    "controller_epoch": int(rotation_target["controller_epoch"]),
                    "config_version": int(rotation_target["config_version"]),
                    "terra_auth_hash": hash_capability_token(
                        rotation_target["terra_auth_token"]
                    ),
                    "operator_auth_hash": hash_capability_token(
                        rotation_target["operator_auth_token"]
                    ),
                }
            )
            expected_action_type = "initial_provision"
        elif normalized == "authority-rotate":
            for field in ("new_terra_auth_token", "new_operator_auth_token"):
                if not rotation_target.get(field):
                    raise AuthorizationFailureError(
                        f"authority rotation target is missing {field}"
                    )
            expected_action_digest = digest_payload(
                {
                    "action": "rotate_authority",
                    "run_id": rotation_target["run_id"],
                    "operator_identity": rotation_target["operator_identity"],
                    "reviewed_sha": rotation_target["reviewed_sha"],
                    "tree_sha": rotation_target["tree_sha"],
                    "source_digest": rotation_target["source_digest"],
                    "controller_epoch": int(rotation_target["controller_epoch"]),
                    "config_version": int(rotation_target["config_version"]),
                    "terra_auth_hash": hash_capability_token(
                        rotation_target["new_terra_auth_token"]
                    ),
                    "operator_auth_hash": hash_capability_token(
                        rotation_target["new_operator_auth_token"]
                    ),
                }
            )
            expected_action_type = "rotate_authority"
        elif normalized == "restore":
            if database_url is None:
                raise ScopeBoundaryViolationError(
                    "restore operation requires the pinned database"
                )
            restore_path = str(rotation_target.get("backup_path") or "")
            if not restore_path:
                raise AuthorizationFailureError(
                    "restore operation requires an explicit backup path"
                )
            _assert_backup_path(restore_path)
            backup_digest = str(rotation_target.get("backup_digest") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", backup_digest):
                raise AuthorizationFailureError(
                    "restore operation requires a SHA-256 backup digest"
                )
            backup_size = rotation_target.get("backup_size")
            if (
                not isinstance(backup_size, int)
                or isinstance(backup_size, bool)
                or backup_size <= 0
                or backup_size > 512 * 1024 * 1024
            ):
                raise AuthorizationFailureError(
                    "restore operation requires a bounded backup size"
                )
            migration_head = str(rotation_target.get("migration_head") or "")
            if not re.fullmatch(r"[0-9]+_[A-Za-z0-9_]+", migration_head):
                raise AuthorizationFailureError(
                    "restore operation requires an explicit Alembic migration head"
                )
            for field in (
                "database_name",
                "database_role",
                "database_endpoint",
                "database_port",
                "cluster_system_identifier",
                "database_oid",
            ):
                if rotation_target.get(field) is None:
                    raise AuthorizationFailureError(
                        f"restore operation requires {field} target binding"
                    )
            for field in ("cluster_system_identifier", "database_oid"):
                if not re.fullmatch(r"[0-9]+", str(rotation_target[field])):
                    raise AuthorizationFailureError(
                        f"restore operation requires a verified numeric {field}"
                    )
            parsed = urlsplit(database_url)
            query = strict_libpq_query(database_url)
            query_host = query.get("host", [""])[0]
            query_port = query.get("port", [""])[0]
            try:
                effective_port = parsed.port
                if effective_port is None and query_port:
                    effective_port = int(query_port)
                target_port = int(rotation_target["database_port"])
            except (TypeError, ValueError) as exc:
                raise AuthorizationFailureError(
                    "restore operation target port is invalid"
                ) from exc
            effective_endpoint = parsed.hostname or query_host
            if (
                str(rotation_target["database_name"]) != parsed.path.lstrip("/")
                or str(rotation_target["database_role"]) != str(parsed.username or "")
                or str(rotation_target["database_endpoint"]) != effective_endpoint
                or target_port != effective_port
                or target_port <= 0
            ):
                raise AuthorizationFailureError(
                    "restore operation target binding does not match database URL"
                )
            expected_action_digest = digest_payload(
                {
                    "action": "restore",
                    "run_id": rotation_target["run_id"],
                    "operator_identity": rotation_target["operator_identity"],
                    "reviewed_sha": rotation_target["reviewed_sha"],
                    "tree_sha": rotation_target["tree_sha"],
                    "source_digest": rotation_target["source_digest"],
                    "controller_epoch": int(rotation_target["controller_epoch"]),
                    "config_version": int(rotation_target["config_version"]),
                    "challenge_epoch": int(rotation_target["challenge_epoch"]),
                    "database_url": database_url,
                    "backup_path": os.path.normpath(restore_path),
                    "backup_digest": backup_digest,
                    "backup_size": backup_size,
                    "migration_head": migration_head,
                    "database_name": str(rotation_target["database_name"]),
                    "database_role": str(rotation_target["database_role"]),
                    "database_endpoint": str(rotation_target["database_endpoint"]),
                    "database_port": target_port,
                    "cluster_system_identifier": str(
                        rotation_target["cluster_system_identifier"]
                    ),
                    "database_oid": str(rotation_target["database_oid"]),
                }
            )
            expected_action_type = "restore"
        else:
            if database_url is None:
                raise ScopeBoundaryViolationError(
                    "restore fence clearing requires the pinned database"
                )
            recovery_path = str(rotation_target.get("recovery_snapshot_path") or "")
            if not recovery_path:
                raise AuthorizationFailureError(
                    "restore fence clearing requires a recovery snapshot path"
                )
            _assert_backup_path(recovery_path)
            recovery_digest = str(
                rotation_target.get("recovery_snapshot_digest") or ""
            )
            if not re.fullmatch(r"[0-9a-f]{64}", recovery_digest):
                raise AuthorizationFailureError(
                    "restore fence clearing requires a SHA-256 recovery snapshot digest"
                )
            recovery_size = rotation_target.get("recovery_snapshot_size")
            if (
                not isinstance(recovery_size, int)
                or isinstance(recovery_size, bool)
                or recovery_size <= 0
                or recovery_size > 512 * 1024 * 1024
            ):
                raise AuthorizationFailureError(
                    "restore fence clearing requires a bounded recovery snapshot size"
                )
            migration_head = str(rotation_target.get("migration_head") or "")
            if not re.fullmatch(r"[0-9]+_[A-Za-z0-9_]+", migration_head):
                raise AuthorizationFailureError(
                    "restore fence clearing requires an explicit Alembic migration head"
                )
            recovery_migration_head = str(
                rotation_target.get("recovery_snapshot_migration_head") or ""
            )
            if recovery_migration_head != migration_head:
                raise AuthorizationFailureError(
                    "restore fence clearing recovery migration head must match the target"
                )
            recovery_source_digest = str(
                rotation_target.get("recovery_snapshot_source_digest") or ""
            )
            if not re.fullmatch(r"[0-9a-f]{64}", recovery_source_digest):
                raise AuthorizationFailureError(
                    "restore fence clearing requires the approved recovery source digest"
                )
            for field in (
                "database_name",
                "database_role",
                "database_endpoint",
                "database_port",
                "cluster_system_identifier",
                "database_oid",
            ):
                if rotation_target.get(field) is None:
                    raise AuthorizationFailureError(
                        f"restore fence clearing requires {field} target binding"
                    )
            for field in ("cluster_system_identifier", "database_oid"):
                if not re.fullmatch(r"[0-9]+", str(rotation_target[field])):
                    raise AuthorizationFailureError(
                        f"restore fence clearing requires a verified numeric {field}"
                    )
            parsed = urlsplit(database_url)
            query = strict_libpq_query(database_url)
            query_host = query.get("host", [""])[0]
            query_port = query.get("port", [""])[0]
            try:
                effective_port = parsed.port
                if effective_port is None and query_port:
                    effective_port = int(query_port)
                target_port = int(rotation_target["database_port"])
            except (TypeError, ValueError) as exc:
                raise AuthorizationFailureError(
                    "restore fence clearing target port is invalid"
                ) from exc
            effective_endpoint = parsed.hostname or query_host
            if (
                str(rotation_target["database_name"]) != parsed.path.lstrip("/")
                or str(rotation_target["database_role"])
                != str(parsed.username or "")
                or str(rotation_target["database_endpoint"]) != effective_endpoint
                or target_port != effective_port
                or target_port <= 0
            ):
                raise AuthorizationFailureError(
                    "restore fence clearing target binding does not match database URL"
                )
            expected_action_digest = digest_payload(
                {
                    "action": "clear_restore_fence",
                    "run_id": rotation_target["run_id"],
                    "operator_identity": rotation_target["operator_identity"],
                    "reviewed_sha": rotation_target["reviewed_sha"],
                    "tree_sha": rotation_target["tree_sha"],
                    "source_digest": rotation_target["source_digest"],
                    "controller_epoch": int(rotation_target["controller_epoch"]),
                    "config_version": int(rotation_target["config_version"]),
                    "challenge_epoch": int(rotation_target["challenge_epoch"]),
                    "database_url": database_url,
                    "recovery_snapshot_path": os.path.normpath(recovery_path),
                    "recovery_snapshot_digest": recovery_digest,
                    "recovery_snapshot_size": recovery_size,
                    "migration_head": migration_head,
                    "recovery_snapshot_migration_head": recovery_migration_head,
                    "recovery_snapshot_source_digest": recovery_source_digest,
                    "database_name": str(rotation_target["database_name"]),
                    "database_role": str(rotation_target["database_role"]),
                    "database_endpoint": str(rotation_target["database_endpoint"]),
                    "database_port": target_port,
                    "cluster_system_identifier": str(
                        rotation_target["cluster_system_identifier"]
                    ),
                    "database_oid": str(rotation_target["database_oid"]),
                }
            )
            expected_action_type = "clear_restore_fence"
        if not expected_action_digest:
            raise AuthorizationFailureError(
                f"{normalized} target binding has no action digest"
            )
        verify_external_operator_approval_receipt(
            receipt=operator_approval_receipt,
            expected_action_digest=expected_action_digest,
            expected_action_type=expected_action_type,
            expected_run_id=str(rotation_target["run_id"]),
            expected_operator_identity=str(rotation_target["operator_identity"]),
            expected_controller_epoch=int(rotation_target["controller_epoch"]),
            expected_config_version=int(rotation_target["config_version"]),
            expected_challenge_epoch=int(rotation_target["challenge_epoch"]),
        )
    if normalized in _SERVICE_OPERATIONS:
        if not service_name:
            raise ScopeBoundaryViolationError(
                "service operation requires an explicit Comms-01 service name"
            )
        assert_service_name(service_name)
    if normalized == "deploy":
        # Comms-01 can validate a release, but it can never authorize or
        # execute deployment. Terra's exact-SHA release path owns that action.
        deny_release_action("deploy")


__all__ = ["assert_comms01_operation", "open_pinned_backup_file"]
