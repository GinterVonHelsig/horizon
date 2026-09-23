"""Independent source-anchor verification for the migration downgrade boundary."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from authority_pins import MIGRATION_SOURCE_PROVENANCE_PATH
from exceptions import ProvenanceMismatchError, ScopeBoundaryViolationError
from pinned_trust import read_json_file, read_verified_source_bytes

CANONICAL_MIGRATION = "008_longspan_authority_repair"
PINNED_LEGACY_MIGRATION_SOURCE_SHA256 = {
    "004_longspan_workflow": "bc01d0a94963dc64d36d1edab9cf2e602f5f96205f33c717b02f553fd3577b32",
    "005_longspan_hardening": "bd0a4a166b5a59fada29f48a146532f98ac5c7a9f46b301b7dcd1a145bd5401f",
    "006_longspan_authority": "b6a23a1240fbeb60066bb580ffcd28d5776e41f395ec6256a2cf94ebbff530eb",
    "007_longspan_authority_hardening": "2782b879d23226797d95f8666d3a6d546f9d749bf80ceb777291d44501d4c39e",
    "009_goal_schedule_task": "7f0c36e0064a5c149f8c671168df5dd4d07d7fdcef427389ee45d6d2aed647bd",
    "010_goal_claim_parent_task": "70c6419caffaa56d1f8313af9fbe2d2e260c37c5c42924f8414bdbb81628ae87",
    "011_goal_claim_fence_token_fix": "ed5afacaf1475b83615f424f0eb102b00131b3d18c96045eb8c2c7a82a40c56e",
    "012_claim_parent_scope_fix": "cb05019f949de3dc8fd5daba44bf4d1e43c3508a681cbf0a53639a4bfd68dfd7",
    "013_cleanup_expired_attempt": "911d718a54a36148d1b4410fbce75e1107f569dde99dfcf7c9c1711e32fc4e7b",
    "014_requeue_blocked_parent_task": "be05d24299ae93dc3d0c5244d9a10266c2b098327a644adbf575dde954ee672c",
}
HISTORICAL_MIGRATIONS = tuple(PINNED_LEGACY_MIGRATION_SOURCE_SHA256)
SUPPORTED_MIGRATIONS = (*HISTORICAL_MIGRATIONS, CANONICAL_MIGRATION)
SOURCE_DIGEST_ALGORITHM = "sha256"
SOURCE_DIGEST_NORMALIZATION_VERSION = 1
SOURCE_DIGEST_PATTERN = re.compile(
    rb'(?m)^(MIGRATION_SOURCE_PROVENANCE_DIGEST\s*=\s*)[\'"][0-9a-f]{64}[\'"]$'
)


def normalized_source_digest(source: bytes) -> str:
    """Hash source after replacing its self-referential digest marker."""
    normalized, replacements = SOURCE_DIGEST_PATTERN.subn(
        rb'\1"<source-digest>"', source
    )
    if replacements != 1:
        raise ProvenanceMismatchError(
            "008 migration source must contain exactly one digest marker"
        )
    return hashlib.sha256(normalized).hexdigest()


def verify_migration_source_anchor(
    revision: str,
    *,
    source_path: str | Path | None = None,
    anchor_path: str | Path = MIGRATION_SOURCE_PROVENANCE_PATH,
) -> None:
    """Verify the migration source against the separately rooted trust anchor.

    This verifier is intentionally outside the migration modules. The Alembic
    environment calls it before dispatching any historical downgrade, so a
    changed revision cannot authorize altered destructive SQL. The 008 source
    uses its self-referential marker normalization; historical legs use their
    exact raw source bytes and an independently provisioned root-owned map.
    """
    if revision not in SUPPORTED_MIGRATIONS:
        raise ProvenanceMismatchError(
            f"migration source provenance is not defined for {revision!r}"
        )
    if source_path is None:
        filename = f"{revision}.py"
        path = Path(__file__).resolve().parent / "migrations" / "versions" / filename
    else:
        path = Path(source_path)
    try:
        source = read_verified_source_bytes(str(path))
    except (OSError, ScopeBoundaryViolationError) as exc:
        raise ProvenanceMismatchError(
            f"{revision} migration source is not a root-owned trust anchor: {path}"
        ) from exc
    digest = (
        normalized_source_digest(source)
        if revision == CANONICAL_MIGRATION
        else hashlib.sha256(source).hexdigest()
    )
    anchor = read_json_file(
        str(anchor_path),
        strict_owner=True,
        require_root_owner=True,
    )
    if revision == CANONICAL_MIGRATION:
        valid = (
            anchor.get("revision") == CANONICAL_MIGRATION
            and anchor.get("algorithm") == SOURCE_DIGEST_ALGORITHM
            and anchor.get("normalization_version")
            == SOURCE_DIGEST_NORMALIZATION_VERSION
            and anchor.get("source_digest") == digest
        )
    else:
        legacy = anchor.get("legacy_source_digests")
        valid = (
            anchor.get("algorithm") == SOURCE_DIGEST_ALGORITHM
            and anchor.get("normalization_version")
            == SOURCE_DIGEST_NORMALIZATION_VERSION
            and isinstance(legacy, dict)
            and legacy.get(revision) == digest
            and PINNED_LEGACY_MIGRATION_SOURCE_SHA256.get(revision) == digest
        )
    if not valid:
        raise ProvenanceMismatchError(
            f"{revision} migration source does not match the root-owned trust anchor"
        )
