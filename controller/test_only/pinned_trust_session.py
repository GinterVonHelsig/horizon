"""Snapshot/restore and live-fingerprint refuse for disposable pytest trust files.

Production runtime must never import this module. Accidental pytest on a live
Comms-01 host previously overwrote /etc/top-delivery and did not restore those
files. Snapshot/restore is the compensating control when mutation is allowed.
When the trust root directory exists but the attestation file is missing, refuse
(fail closed). A missing trust-root directory is the disposable/CI case.
"""

from __future__ import annotations

import json
import os
import stat
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from authority_pins import (
    AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
    AUTHORITY_WRITE_SIGNING_SECRET_PATH,
    COMMS01_ATTESTATION_PATH,
    DISPOSABLE_CAPABILITY_SIGNING_KEY_PATH,
    DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH,
    DISPOSABLE_HARNESS_CAPABILITY_PATH,
    LEDGER_MAC_KEY_PATH,
    MIGRATION_SOURCE_PROVENANCE_PATH,
    OPERATOR_PUBLIC_KEYS_PATH,
    TERRA_GATEWAY_MAC_KEY_PATH,
    TERRA_RECEIPT_PUBLIC_KEYS_PATH,
    WORKFLOW_DATABASE_TARGET_PATH,
)

ALLOW_LIVE_TRUST_MUTATION_ENV = "TOP_DELIVERY_ALLOW_LIVE_TRUST_MUTATION"
LIVE_HOST_FINGERPRINTS = frozenset({"comms01-comms-01"})
DEFAULT_TRUST_ROOT = "/etc/top-delivery"

PINNED_TRUST_SESSION_PATHS: tuple[str, ...] = (
    COMMS01_ATTESTATION_PATH,
    MIGRATION_SOURCE_PROVENANCE_PATH,
    OPERATOR_PUBLIC_KEYS_PATH,
    TERRA_RECEIPT_PUBLIC_KEYS_PATH,
    DISPOSABLE_CAPABILITY_SIGNING_KEY_PATH,
    DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH,
    LEDGER_MAC_KEY_PATH,
    TERRA_GATEWAY_MAC_KEY_PATH,
    DISPOSABLE_HARNESS_CAPABILITY_PATH,
    AUTHORITY_WRITE_SIGNING_SECRET_PATH,
    WORKFLOW_DATABASE_TARGET_PATH,
    AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
)


class PinnedTrustRestoreError(RuntimeError):
    """Raised after every restore attempt when one or more restores failed."""


@dataclass(frozen=True)
class PinnedFileSnapshot:
    path: str
    existed: bool
    data: bytes | None
    mode: int | None
    uid: int | None
    gid: int | None


def _trust_root_for(attestation_path: str | Path, trust_root: str | Path | None) -> Path:
    if trust_root is not None:
        return Path(trust_root)
    return Path(attestation_path).parent


def _host_fingerprint(attestation_path: str | Path) -> object:
    path = Path(attestation_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload.get("host_fingerprint")


def live_trust_mutation_forbidden(
    attestation_path: str | Path,
    environ: Mapping[str, str],
    *,
    trust_root: str | Path | None = None,
) -> bool:
    """Return True when pytest must not overwrite live Comms-01 trust files."""

    if environ.get(ALLOW_LIVE_TRUST_MUTATION_ENV) == "1":
        return False
    path = Path(attestation_path)
    root = _trust_root_for(path, trust_root)
    if not path.is_file():
        return root.is_dir()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return True
    if not isinstance(payload, dict):
        return True
    fingerprint = payload.get("host_fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        return True
    return fingerprint in LIVE_HOST_FINGERPRINTS


def refuse_live_trust_mutation(
    attestation_path: str | Path,
    environ: Mapping[str, str],
    *,
    trust_root: str | Path | None = None,
) -> None:
    """Raise before any trust-file or test-role mutation on a live host."""

    if live_trust_mutation_forbidden(
        attestation_path, environ, trust_root=trust_root
    ):
        raise RuntimeError(
            "refusing to overwrite live Comms-01 trust anchors; set "
            f"{ALLOW_LIVE_TRUST_MUTATION_ENV}=1 only on a disposable harness"
        )


def warn_if_allowing_live_fingerprint(
    attestation_path: str | Path,
    environ: Mapping[str, str],
) -> None:
    if environ.get(ALLOW_LIVE_TRUST_MUTATION_ENV) != "1":
        return
    fingerprint = _host_fingerprint(attestation_path)
    if fingerprint in LIVE_HOST_FINGERPRINTS:
        warnings.warn(
            f"{ALLOW_LIVE_TRUST_MUTATION_ENV}=1 honored for live host "
            f"fingerprint {fingerprint!r}",
            RuntimeWarning,
            stacklevel=2,
        )


def snapshot_pinned_trust_files(paths: tuple[str, ...] | list[str]) -> tuple[PinnedFileSnapshot, ...]:
    snapshots: list[PinnedFileSnapshot] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            snapshots.append(
                PinnedFileSnapshot(
                    path=str(path),
                    existed=False,
                    data=None,
                    mode=None,
                    uid=None,
                    gid=None,
                )
            )
            continue
        info = path.stat()
        snapshots.append(
            PinnedFileSnapshot(
                path=str(path),
                existed=True,
                data=path.read_bytes(),
                mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid,
                gid=info.st_gid,
            )
        )
    return tuple(snapshots)


def _restore_one(item: PinnedFileSnapshot) -> list[str]:
    notes: list[str] = []
    path = Path(item.path)
    if not item.existed:
        if path.exists() or path.is_symlink():
            path.unlink()
        return notes
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(item.data or b"")
    if item.mode is not None:
        path.chmod(item.mode)
    if item.uid is not None and item.gid is not None:
        try:
            os.chown(path, item.uid, item.gid)
        except PermissionError:
            notes.append(f"chown_failed:{path}")
    return notes


def restore_pinned_trust_files(snapshot: tuple[PinnedFileSnapshot, ...]) -> tuple[str, ...]:
    """Restore every snapshot entry. Always attempt all; then raise if any failed.

    chown PermissionError is tolerated after bytes+mode restore and recorded in
    the returned notes. Other failures are aggregated into PinnedTrustRestoreError.
    """

    errors: list[str] = []
    notes: list[str] = []
    for item in snapshot:
        try:
            notes.extend(_restore_one(item))
        except Exception as exc:  # noqa: BLE001 — must attempt remaining files
            errors.append(f"{item.path}: {type(exc).__name__}: {exc}")
    if errors:
        raise PinnedTrustRestoreError(
            "pinned trust restore incomplete: " + "; ".join(errors)
        )
    return tuple(notes)


def begin_pinned_trust_session(
    paths: tuple[str, ...] | list[str],
    attestation_path: str | Path,
    environ: Mapping[str, str],
    *,
    trust_root: str | Path | None = None,
) -> tuple[PinnedFileSnapshot, ...]:
    """Refuse live mutation, optionally warn, then snapshot. Call before any writes."""

    refuse_live_trust_mutation(
        attestation_path, environ, trust_root=trust_root
    )
    warn_if_allowing_live_fingerprint(attestation_path, environ)
    return snapshot_pinned_trust_files(paths)
