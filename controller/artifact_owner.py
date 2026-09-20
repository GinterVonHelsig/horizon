"""Apply the configured service owner to freshly written goal artifacts."""

from __future__ import annotations

import os
import pwd
from pathlib import Path


def _configured_owner_ids() -> tuple[int, int] | None:
    owner = os.environ.get("TOP_DELIVERY_ARTIFACT_OWNER")
    if not owner:
        return None
    try:
        passwd = pwd.getpwnam(owner)
    except KeyError:
        return None
    return passwd.pw_uid, passwd.pw_gid


def _chown_if_needed(path: Path, uid: int, gid: int) -> None:
    if path.is_symlink():
        return
    stat = path.stat()
    if stat.st_uid == uid and stat.st_gid == gid:
        return
    os.chown(path, uid, gid)


def apply_artifact_owner(path: Path, *, recursive: bool = False) -> None:
    """Apply the configured owner to ``path`` without normalizing historical trees.

    By default only the resolved path itself is updated. Historical attempt
    evidence is left untouched so poll preparation cannot fail on root-owned
    files from prior runs. Pass ``recursive=True`` only when intentionally
    seeding a freshly created directory tree at write time.
    """
    owner_ids = _configured_owner_ids()
    if owner_ids is None:
        return
    uid, gid = owner_ids
    resolved = Path(path).resolve()
    if not resolved.exists():
        return
    if recursive and resolved.is_dir():
        for child in sorted(resolved.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if child.is_symlink():
                continue
            _chown_if_needed(child, uid, gid)
    _chown_if_needed(resolved, uid, gid)
