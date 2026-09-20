"""Unit tests for master program fixture ingest."""

from __future__ import annotations

from pathlib import Path

import pytest

from program_ingest import ProgramIngestError, parse_program_file, project_node_reference

FIXTURE = Path(__file__).resolve().parent / "tests" / "fixtures" / "master-program-v1.json"


def test_fixture_program_parses_project_and_nodes() -> None:
    parsed = parse_program_file(FIXTURE)

    assert parsed.project_id == "ATS-PROGRAM"
    assert parsed.project_version == "1.0.0-draft"
    assert parsed.schema_version == "master-program.v1"
    assert len(parsed.nodes) > 0

    node = project_node_reference(parsed, "ATS-PMO-001")
    assert node.node_id == "ATS-PMO-001"
    assert node.parent_node_id == "ATS-PMO"
    assert node.acceptance_criteria_version == "horizon-v1-contract.md#project-node-identity"


def test_fixture_program_rejects_unknown_node_reference() -> None:
    parsed = parse_program_file(FIXTURE)
    with pytest.raises(ProgramIngestError, match="project node reference not found"):
        project_node_reference(parsed, "ATS-DOES-NOT-EXIST")
