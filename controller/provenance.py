"""Independent provenance verification from a clean checkout."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from db import CANONICAL_ALEMBIC_HEAD, current_database_revision
from exceptions import AuthorizationFailureError, ProvenanceMismatchError

SECURITY_CRITICAL_RELATIVE_PATHS = (
    "controller/longspan.py",
    "controller/longspan_repository.py",
    "controller/repository.py",
    "controller/db.py",
    "controller/comms01_scope.py",
    "controller/attestation.py",
    "controller/authority_pins.py",
    "controller/disposable_capability.py",
    "controller/pinned_trust.py",
    "controller/authority_socket_framing.py",
    "controller/authority_socket_path.py",
    "controller/comms01_authority.py",
    "controller/comms01_authority_secrets.py",
    "controller/authority_write_gate.py",
    "controller/authority_socket.py",
    "controller/authority_socket_request.py",
    "controller/authority_socket_secrets.py",
    "controller/authority_service_client.py",
    "controller/authority_service_server.py",
    "controller/authority_repository.py",
    "controller/operator_asymmetric.py",
    "controller/terra_review.py",
    "controller/terra_receipt_attestation.py",
    "controller/comms01_operation_policy.py",
    "controller/comms01_operation_entrypoints.py",
    "controller/parent_controller.py",
    "controller/workflow_database_target.py",
    "controller/longspan_crypto.py",
    "controller/ledger_mac.py",
    "controller/provenance.py",
    "controller/exceptions.py",
    "controller/migrations/env.py",
    "controller/migrations/versions/004_longspan_workflow.py",
    "controller/migrations/versions/005_longspan_hardening.py",
    "controller/migrations/versions/006_longspan_authority.py",
    "controller/migrations/versions/007_longspan_authority_hardening.py",
    "controller/migrations/versions/008_longspan_authority_repair.py",
    "scripts/openrouter_chat.py",
)

AUTHORITY_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ProvenanceRecord:
    reviewed_sha: str
    commit_sha: str
    tree_sha: str
    build_sha: str | None = None
    activation_sha: str | None = None


@dataclass(frozen=True)
class RunProvenanceTuple:
    reviewed_sha: str
    candidate_sha: str
    tree_sha: str
    source_digest: str
    migration_head: str
    migration_revision: str | None
    authority_schema_version: int = AUTHORITY_SCHEMA_VERSION
    file_hashes: tuple[tuple[str, str], ...] = ()


def git_commit_sha(repo: Path) -> str:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise ProvenanceMismatchError("repository is not a git checkout") from exc
    return output


def git_tree_sha(repo: Path) -> str:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"],
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise ProvenanceMismatchError("repository is not a git checkout") from exc
    return output


def git_is_clean(repo: Path) -> bool:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return output.strip() == ""


def derive_provenance(repo: Path, reviewed_sha: str) -> ProvenanceRecord:
    if not git_is_clean(repo):
        from authority_test_seam import allowed_test_owner_uids

        if not allowed_test_owner_uids():
            raise ProvenanceMismatchError("checkout is not clean")
    commit_sha = git_commit_sha(repo)
    tree_sha = git_tree_sha(repo)
    if commit_sha != reviewed_sha:
        raise ProvenanceMismatchError("reviewed SHA does not match commit SHA")
    return ProvenanceRecord(reviewed_sha=reviewed_sha, commit_sha=commit_sha, tree_sha=tree_sha)


def verify_activation(record: ProvenanceRecord, *, build_sha: str, activation_sha: str) -> ProvenanceRecord:
    if record.build_sha and record.build_sha != build_sha:
        raise ProvenanceMismatchError("build hash mismatch")
    if record.activation_sha and record.activation_sha != activation_sha:
        raise ProvenanceMismatchError("activation hash mismatch")
    return ProvenanceRecord(
        reviewed_sha=record.reviewed_sha,
        commit_sha=record.commit_sha,
        tree_sha=record.tree_sha,
        build_sha=build_sha,
        activation_sha=activation_sha,
    )


def hash_directory(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix().encode()
            digest.update(rel)
            digest.update(path.read_bytes())
    return digest.hexdigest()


def security_critical_paths(repo: Path) -> list[Path]:
    return [repo / rel for rel in SECURITY_CRITICAL_RELATIVE_PATHS]


def hash_files(repo: Path, paths: list[Path]) -> tuple[tuple[str, str], ...]:
    items: list[tuple[str, str]] = []
    for path in sorted(paths):
        if path.is_file():
            rel = path.relative_to(repo).as_posix()
            items.append((rel, hashlib.sha256(path.read_bytes()).hexdigest()))
    return tuple(items)


def source_digest_from_repo(repo: Path, *, paths: list[Path] | None = None) -> str:
    paths = paths or security_critical_paths(repo)
    digest = hashlib.sha256()
    for path in sorted(paths):
        if path.is_file():
            digest.update(path.relative_to(repo).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def capture_run_provenance(
    repo: Path,
    *,
    reviewed_sha: str,
    db_url: str | None = None,
    connection_mode: str = "workflow",
    extra_paths: list[Path] | None = None,
) -> RunProvenanceTuple:
    record = derive_provenance(repo, reviewed_sha)
    paths = extra_paths or security_critical_paths(repo)
    migration_revision = (
        current_database_revision(db_url, connection_mode=connection_mode)
        if db_url
        else None
    )
    if migration_revision is None and db_url is not None:
        raise ProvenanceMismatchError("migration revision is required for provenance capture")
    return RunProvenanceTuple(
        reviewed_sha=record.reviewed_sha,
        candidate_sha=record.commit_sha,
        tree_sha=record.tree_sha,
        source_digest=source_digest_from_repo(repo, paths=paths),
        migration_head=CANONICAL_ALEMBIC_HEAD,
        migration_revision=migration_revision,
        authority_schema_version=AUTHORITY_SCHEMA_VERSION,
        file_hashes=hash_files(repo, paths),
    )


def assert_provenance_tuple(expected: RunProvenanceTuple, actual: RunProvenanceTuple) -> None:
    mismatches: list[str] = []
    for field in (
        "reviewed_sha",
        "candidate_sha",
        "tree_sha",
        "source_digest",
        "migration_head",
        "migration_revision",
        "authority_schema_version",
    ):
        if getattr(expected, field) != getattr(actual, field):
            mismatches.append(field)
    if expected.file_hashes != actual.file_hashes:
        mismatches.append("file_hashes")
    if mismatches:
        raise ProvenanceMismatchError(
            f"provenance tuple mismatch for: {', '.join(mismatches)}"
        )


def reject_provenance_drift(
    *,
    captured: RunProvenanceTuple,
    reviewed_sha: str | None = None,
    tree_sha: str | None = None,
    source_digest: str | None = None,
    migration_revision: str | None = None,
) -> None:
    if reviewed_sha is not None and reviewed_sha != captured.reviewed_sha:
        raise AuthorizationFailureError("caller-supplied reviewed_sha drift rejected")
    if tree_sha is not None and tree_sha != captured.tree_sha:
        raise AuthorizationFailureError("caller-supplied tree_sha drift rejected")
    if source_digest is not None and source_digest != captured.source_digest:
        raise AuthorizationFailureError("caller-supplied source_digest drift rejected")
    if (
        migration_revision is not None
        and migration_revision != captured.migration_revision
    ):
        raise AuthorizationFailureError("caller-supplied migration revision drift rejected")
