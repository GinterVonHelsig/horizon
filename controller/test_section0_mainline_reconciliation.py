"""Regression contracts preventing the old Section-0 migration fork from returning."""

from pathlib import Path

import pytest

from legacy_section0_bridge import SNAPSHOT_DIGEST_SCOPE, _shared_digest_cross_check
from migration_bootstrap import (
    MIGRATION_DATABASE_ROLE,
    normalize_legacy_routine_owners,
)

ROOT = Path(__file__).resolve().parent
MIGRATIONS = ROOT / "migrations" / "versions"


def _source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_mainline_has_one_canonical_migration_head_and_no_section0_fork() -> None:
    revisions = sorted(
        path.stem for path in MIGRATIONS.glob("*.py") if path.stem[:3].isdigit()
    )
    assert revisions == [
        "001_initial",
        "002_event_sequence",
        "003_commit_order_and_invariants",
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
    ]
    assert not (MIGRATIONS / "004_authenticated_auditor_provenance.py").exists()
    assert not (
        ROOT / "migrations" / "comms01-section0-mainline-reconciliation.md"
    ).exists()
    assert (
        ROOT.parent
        / "docs"
        / "decisions"
        / "comms01-section0-mainline-reconciliation.md"
    ).exists()


def test_mainline_contains_the_reconciled_section0_behavior() -> None:
    parent = _source("parent_controller.py")
    repository = _source("longspan_repository.py")
    longspan = _source("longspan.py")
    migration_target = _source("migration_target.py")

    assert "complete_longspan_return" in parent
    assert "atomic_parent_return_and_complete" in repository
    assert "get_auditor_snapshot" in repository
    assert "store_auditor_receipt" in repository
    assert "resume_retry_wait" in repository
    assert "class LongspanAuditor" in longspan
    assert "persisted execution evidence content digest mismatch" in longspan
    assert '"008_longspan_authority_repair"' in migration_target
    assert "004_auditor_provenance" not in migration_target


def test_workflow_cannot_provision_authority() -> None:
    longspan = _source("longspan.py")
    assert "workflow cannot provision authority" in longspan


def test_mainline_rehearsal_pins_complete_new_schema() -> None:
    rehearsal = (ROOT.parent / "scripts" / "rehearse_section0_mainline.py").read_text(
        encoding="utf-8"
    )
    assert 'FINAL_REVISION = "008_longspan_authority_repair"' in rehearsal
    assert rehearsal.count('"longspan_') >= 18
    assert '"top_delivery_downgrade_capabilities"' in rehearsal


class _RoutineOwnerCursor:
    def __init__(self, row: tuple[str | None, str | None] | None) -> None:
        self.row = row
        self.queries: list[str] = []

    def execute(self, query: object, *_args: object) -> None:
        self.queries.append(str(query))

    def fetchone(self) -> tuple[str | None, str | None] | None:
        return self.row


def test_legacy_owner_normalization_transfers_only_wrong_owner() -> None:
    cursor = _RoutineOwnerCursor(
        ("reject_evidence_index_mutation()", "postgres")
    )

    evidence = normalize_legacy_routine_owners(cursor)

    assert evidence == [
        {
            "signature": "reject_evidence_index_mutation()",
            "before_owner": "postgres",
            "after_owner": MIGRATION_DATABASE_ROLE,
            "action": "normalized",
        }
    ]
    assert any("ALTER FUNCTION" in query for query in cursor.queries)


def test_legacy_owner_normalization_is_noop_for_correct_owner() -> None:
    cursor = _RoutineOwnerCursor(
        ("reject_evidence_index_mutation()", MIGRATION_DATABASE_ROLE)
    )

    evidence = normalize_legacy_routine_owners(cursor)

    assert evidence[0]["action"] == "already-normalized"
    assert not any("ALTER FUNCTION" in query for query in cursor.queries)


def test_legacy_owner_normalization_attests_absent_routine() -> None:
    cursor = _RoutineOwnerCursor((None, None))

    evidence = normalize_legacy_routine_owners(cursor)

    assert evidence == [
        {
            "signature": "reject_evidence_index_mutation()",
            "before_owner": None,
            "after_owner": None,
            "action": "absent",
        }
    ]


def test_snapshot_producer_binds_the_bridge_digest_scope() -> None:
    capture = (ROOT.parent / "scripts" / "capture_section0_live_snapshot.py").read_text(
        encoding="utf-8"
    )
    signer = (ROOT.parent / "scripts" / "sign_section0_live_snapshot.py").read_text(
        encoding="utf-8"
    )
    assert "SNAPSHOT_DIGEST_SCOPE = (" in _source("legacy_section0_bridge.py")
    assert '"snapshot_digest_scope": SNAPSHOT_DIGEST_SCOPE' in capture
    assert 'payload.get("snapshot_digest_scope") != SNAPSHOT_DIGEST_SCOPE' in signer


def test_digest_cross_check_rejects_duplicate_table_evidence() -> None:
    source = [
        {"table": "supervisor_runs", "source_digest": "a"},
        {"table": "supervisor_runs", "source_digest": "b"},
    ]
    with pytest.raises(ValueError, match="duplicate source table"):
        _shared_digest_cross_check(source, source)
