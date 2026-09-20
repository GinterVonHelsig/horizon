"""Evidence index, manifest verification, and readiness computation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from manifest_ids import DEFAULT_PRODUCER, REQUIRED_ENTRY_IDS


@dataclass(frozen=True)
class ManifestEntry:
    entry_id: str
    artifact_path: str
    sha256: str
    producer: str
    result: str


@dataclass(frozen=True)
class ReadinessReport:
    ready: bool
    blockers: tuple[str, ...]
    entries: tuple[ManifestEntry, ...]
    provenance_verified: bool = False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def sha256_file_at(root: Path, relative_path: str) -> tuple[str, int]:
    """Hash a root-relative file with no-follow protection on every component."""
    relative = Path(relative_path)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("artifact path must be a non-empty root-relative path")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | nofollow)
    current = directory
    try:
        for index, component in enumerate(relative.parts):
            flags = os.O_RDONLY | nofollow
            if index < len(relative.parts) - 1:
                flags |= os.O_DIRECTORY
            opened = os.open(component, flags, dir_fd=current)
            if current != directory:
                os.close(current)
            current = opened
        if not stat.S_ISREG(os.fstat(current).st_mode):
            raise ValueError("evidence path is not a regular file")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(current, "rb", closefd=True) as handle:
            current = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        return digest.hexdigest(), size
    finally:
        if current not in {-1, directory}:
            os.close(current)
        os.close(directory)


def compute_readiness(
  *,
  required: dict[str, dict[str, Any]],
  submissions: dict[str, ManifestEntry],
  provenance_verified: bool,
) -> ReadinessReport:
    blockers: list[str] = []
    entries: list[ManifestEntry] = []
    for entry_id in REQUIRED_ENTRY_IDS:
        spec = required.get(entry_id)
        submission = submissions.get(entry_id)
        if spec is None:
            blockers.append(f"missing-required-spec:{entry_id}")
            continue
        if submission is None:
            blockers.append(f"missing-submission:{entry_id}")
            continue
        if submission.result != "pass":
            blockers.append(f"failed-result:{entry_id}")
        if submission.artifact_path != spec["artifact_path"]:
            blockers.append(f"path-mismatch:{entry_id}")
        expected = spec.get("expected_sha256")
        if expected and submission.sha256 != expected:
            blockers.append(f"hash-mismatch:{entry_id}")
        if submission.producer != spec["producer"]:
            blockers.append(f"provenance-mismatch:{entry_id}")
        entries.append(submission)
    if not provenance_verified:
        blockers.append("provenance-unverified")
    return ReadinessReport(
        ready=len(blockers) == 0,
        blockers=tuple(blockers),
        entries=tuple(entries),
        provenance_verified=provenance_verified,
    )


def build_required_seed(
    artifact_root: Path, *, create_files: bool = False
) -> list[dict[str, Any]]:
    """Seed manifest definitions for tests; paths are relative to artifact_root."""
    rows: list[dict[str, Any]] = []
    for entry_id in REQUIRED_ENTRY_IDS:
        rel = f"evidence/{entry_id.lower()}.json"
        path = artifact_root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if create_files and not path.exists():
            path.write_text(
                json.dumps({"entry_id": entry_id, "ok": True}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        digest = sha256_file_at(artifact_root, rel)[0] if path.exists() else None
        rows.append(
            {
                "entry_id": entry_id,
                "artifact_path": rel,
                "expected_sha256": digest,
                "producer": DEFAULT_PRODUCER,
            }
        )
    return rows


def make_submission(
    entry_id: str,
    artifact_path: Path,
    *,
    relative_to: Path | None = None,
    producer: str = DEFAULT_PRODUCER,
) -> ManifestEntry:
    if relative_to is not None:
        rel_path = artifact_path.relative_to(relative_to).as_posix()
    else:
        rel_path = artifact_path.name
    digest, _ = sha256_file(artifact_path)
    return ManifestEntry(
        entry_id=entry_id,
        artifact_path=rel_path,
        sha256=digest,
        producer=producer,
        result="pass",
    )


def new_evidence_id() -> str:
    return uuid.uuid4().hex
