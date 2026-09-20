"""Pinned authority socket path trust verification for server and client."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from authority_pins import (
    AUTHORITY_CLIENT_PEER_UID,
    AUTHORITY_CLIENT_PEER_GID,
    AUTHORITY_SERVICE_GID,
    AUTHORITY_SERVICE_UID,
    AUTHORITY_SOCKET_GID,
    AUTHORITY_SOCKET_PATH,
)
from authority_test_seam import allowed_test_owner_uids, allowed_test_peer_uids
from exceptions import AuthorityServiceUnavailableError, AuthorizationFailureError


def _owner_allowed(uid: int, *, allowed: frozenset[int]) -> bool:
    return uid in allowed or uid in allowed_test_owner_uids()


def verify_authority_socket_path(path: str | None = None) -> Path:
    socket_path = Path(path or AUTHORITY_SOCKET_PATH)
    if socket_path.as_posix() != AUTHORITY_SOCKET_PATH:
        raise AuthorizationFailureError("authority socket path is not pinned")
    parent = socket_path.parent
    if not parent.is_dir():
        raise AuthorityServiceUnavailableError("authority socket parent directory is missing")
    if parent.is_symlink():
        raise AuthorizationFailureError("authority socket parent directory is a symlink")
    parent_stat = parent.stat()
    allowed_parents = frozenset({0, AUTHORITY_SERVICE_UID})
    if not _owner_allowed(parent_stat.st_uid, allowed=allowed_parents):
        raise AuthorizationFailureError("authority socket parent owner is not authorized")
    if parent_stat.st_mode & stat.S_IWOTH:
        raise AuthorizationFailureError("authority socket parent directory is world-writable")
    if socket_path.exists():
        if socket_path.is_symlink():
            raise AuthorizationFailureError("authority socket is a symlink")
        socket_stat = socket_path.stat()
        allowed_socket = frozenset({AUTHORITY_SERVICE_UID})
        if not _owner_allowed(socket_stat.st_uid, allowed=allowed_socket):
            raise AuthorizationFailureError("authority socket owner is not authorized")
        # The socket is deliberately shared only with the pinned peer group.
        # Do not accept a socket with an arbitrary group or mode.
        if allowed_test_owner_uids():
            if socket_stat.st_mode & 0o007:
                raise AuthorizationFailureError("authority socket permissions are too permissive")
        else:
            if socket_stat.st_gid != AUTHORITY_SOCKET_GID:
                raise AuthorizationFailureError("authority socket group is not pinned")
            if (socket_stat.st_mode & 0o777) != 0o660:
                raise AuthorizationFailureError("authority socket permissions are too permissive")
    return socket_path


def verify_authority_socket_peer(uid: int, gid: int | None = None) -> None:
    allowed = frozenset({AUTHORITY_CLIENT_PEER_UID})
    if uid in allowed:
        if gid != AUTHORITY_CLIENT_PEER_GID:
            raise AuthorizationFailureError("authority socket peer GID is not authorized")
        return
    if uid in allowed_test_peer_uids() and (gid is None or gid in allowed_test_peer_uids()):
        return
    raise AuthorizationFailureError("authority socket peer identity is not authorized")


def chown_authority_socket(socket_path: Path) -> None:
    if not socket_path.exists():
        return
    if allowed_test_owner_uids():
        return
    try:
        os.chown(socket_path, AUTHORITY_SERVICE_UID, AUTHORITY_SOCKET_GID)
    except OSError as exc:
        raise AuthorizationFailureError("authority socket ownership could not be pinned") from exc
