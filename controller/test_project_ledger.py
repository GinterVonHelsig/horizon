"""Integration tests for durable Horizon project ledger ingest."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_ledger import ProjectLedgerService
from program_ingest import parse_program_file, project_node_reference, resume_pointer_for_node
from repository import PostgresRepository

ARTIFACTS_ROOT = Path("/opt/operator-harness/artifacts")

FIXTURE = Path(__file__).resolve().parent / "tests" / "fixtures" / "master-program-v1.json"


@pytest.fixture()
def postgres_repo(db_url: str) -> PostgresRepository:
    repo = PostgresRepository(db_url)
    try:
        yield repo
    finally:
        repo.close()


def test_project_ledger_returns_stable_ids_across_reingest(postgres_repo: PostgresRepository) -> None:
    service = ProjectLedgerService(postgres_repo)
    parsed = parse_program_file(FIXTURE)
    target = project_node_reference(parsed, "ATS-PMO-001")

    first = service.ingest_program_file(str(FIXTURE))
    second = service.ingest_program_file(str(FIXTURE))

    assert first.project_ledger_id == second.project_ledger_id
    assert first.node_ledger_ids["ATS-PMO-001"] == second.node_ledger_ids["ATS-PMO-001"]

    row = service.query_node(parsed.project_id, parsed.project_version, target.node_id)
    assert row["node_ledger_id"] == first.node_ledger_ids["ATS-PMO-001"]
    assert row["acceptance_criteria_version"] == target.acceptance_criteria_version
    assert row["parent_node_id"] == target.parent_node_id


def test_project_ledger_resume_pointer_resolves_for_bound_node(
    postgres_repo: PostgresRepository,
) -> None:
    service = ProjectLedgerService(postgres_repo)
    parsed = parse_program_file(FIXTURE)
    node_id = "ATS-DEL-002"
    target = project_node_reference(parsed, node_id)

    service.ingest_program_file(str(FIXTURE))
    row = service.query_node(parsed.project_id, parsed.project_version, node_id)

    resume_pointer = resume_pointer_for_node(FIXTURE, node_id)
    artifact_path = ARTIFACTS_ROOT / resume_pointer
    assert artifact_path.is_dir()
    assert row["node_id"] == target.node_id
    assert row["acceptance_criteria_version"] == target.acceptance_criteria_version
