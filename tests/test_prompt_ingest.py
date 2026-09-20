"""Unit tests for canonical prompt ingestion."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from prompt_ingest import PromptIngestError, derive_run_id, derive_task_id, parse_prompt_bytes


ALL_SIX_PROMPT = Path("/home/trading/prompts/p0-top-delivery-all-six-20260823.md")

EXPECTED_WORKSTREAMS = [
    (1, "KAT exact-SHA transport"),
    (2, "Broader August 23 P0 remediation candidate"),
    (3, "Active OANDA/Alpaca read-only reconciliation"),
    (4, "Writer startup-settle/readiness transport"),
    (5, "Handoff validator and browser runtime-login contract"),
    (6, "Parent-controller mainline completion and exact-SHA deployment"),
]

EXPECTED_DISPOSITIONS = {
    1: "PASS/TRANSPORTED",
    2: "PASS/RECONCILED",
    3: "RECONCILED_READ_ONLY",
    4: "PASS/TRANSPORTED",
    5: "PASS/TRANSPORTED",
    6: "PASS/DEPLOYED",
}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_all_six_prompt_parses_six_workstreams_with_dependencies() -> None:
    data = ALL_SIX_PROMPT.read_bytes()
    parsed = parse_prompt_bytes(data, source=str(ALL_SIX_PROMPT))

    assert parsed.byte_count == len(data)
    assert parsed.sha256 == _digest(data)
    assert parsed.run_id == derive_run_id(parsed.sha256)
    assert len(parsed.workstreams) == 6

    for index, (number, title) in enumerate(EXPECTED_WORKSTREAMS, start=0):
        workstream = parsed.workstreams[index]
        assert workstream.number == number
        assert workstream.title == title
        assert workstream.required_disposition == EXPECTED_DISPOSITIONS[number]
        assert workstream.task_id == derive_task_id(parsed.run_id, number)
        if number == 1:
            assert workstream.dependencies == ()
        else:
            assert workstream.dependencies == (number - 1,)

    assert parsed.allowed
    assert parsed.forbidden
    assert "broker order" in parsed.forbidden[0].lower()


def test_all_six_forbidden_preserves_wrapped_production_code_bullet() -> None:
    parsed = parse_prompt_bytes(
        ALL_SIX_PROMPT.read_bytes(),
        source=str(ALL_SIX_PROMPT),
    )
    trading_bullet = next(
        bullet for bullet in parsed.forbidden if "/home/trading" in bullet
    )
    assert "production-code mutation" in trading_bullet
    assert "do not deploy items 1, 4, or 5" in trading_bullet
    assert "into the trading VM as part of this run." in trading_bullet


def test_multiline_objective_preserved_in_all_six_prompt() -> None:
    parsed = parse_prompt_bytes(
        ALL_SIX_PROMPT.read_bytes(),
        source=str(ALL_SIX_PROMPT),
    )
    assert "Resolve the six approved near-term outcomes in one persistent," in parsed.objective
    assert parsed.objective.endswith("evidence-backed delivery run.")


def test_multiline_objective_preserved_in_synthetic_prompt(tmp_path: Path) -> None:
    prompt = tmp_path / "multiline-objective.md"
    prompt.write_text(
        "# Multiline objective\n\n"
        "**Objective:** First objective line,\n"
        "second objective line.\n\n"
        "## Mission\n\n"
        "Mission text.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n"
    )
    parsed = parse_prompt_bytes(prompt.read_bytes(), source=str(prompt))
    assert parsed.objective == "First objective line,\nsecond objective line."


def test_wrapped_authority_bullets_preserve_continuation_lines(tmp_path: Path) -> None:
    prompt = tmp_path / "wrapped.md"
    prompt.write_text(
        "# Wrapped bullets\n\n"
        "**Objective:** Test wrapping.\n\n"
        "## Mission\n\n"
        "Mission text.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- Allowed line one\n"
        "  and allowed continuation.\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- Forbidden line one\n"
        "  and forbidden continuation.\n"
    )
    parsed = parse_prompt_bytes(prompt.read_bytes(), source=str(prompt))
    assert parsed.allowed[0] == "- Allowed line one\n  and allowed continuation."
    assert parsed.forbidden[0] == "- Forbidden line one\n  and forbidden continuation."


def test_fallback_single_task_without_numbered_workstreams(tmp_path: Path) -> None:
    prompt = tmp_path / "single.md"
    prompt.write_text(
        "# Simple Goal\n\n"
        "**Objective:** Do one thing safely.\n\n"
        "## Mission\n\n"
        "Complete the scoped outcome.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- Update status artifacts.\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- Deploy to production.\n"
    )
    data = prompt.read_bytes()
    parsed = parse_prompt_bytes(data, source=str(prompt))

    assert len(parsed.workstreams) == 1
    assert parsed.workstreams[0].number == 1
    assert parsed.workstreams[0].title == "Simple Goal"
    assert parsed.workstreams[0].dependencies == ()


@pytest.mark.parametrize(
    "payload,match",
    [
        (b"", "empty"),
        (b"   \n\n", "empty"),
        (b"# No envelope\n\n**Objective:** x\n\n## Mission\n\nx\n", "authority envelope"),
    ],
)
def test_fail_closed_on_invalid_prompt(payload: bytes, match: str) -> None:
    with pytest.raises(PromptIngestError, match=match):
        parse_prompt_bytes(payload, source="invalid.md")


def test_fail_closed_on_duplicate_workstream_number(tmp_path: Path) -> None:
    prompt = tmp_path / "dup.md"
    prompt.write_text(
        "# Dup\n\n"
        "**Objective:** Test duplicate headings.\n\n"
        "## Mission\n\n"
        "Mission text.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n\n"
        "## Ordered workstreams\n\n"
        "### 1. First\n\n"
        "Body.\n\n"
        "### 1. Second\n\n"
        "## Cross-workstream acceptance matrix\n\n"
        "| Item | Required terminal disposition |\n"
        "|---|---|\n"
        "| 1. First | `PASS` |\n"
    )
    with pytest.raises(PromptIngestError, match="duplicate workstream"):
        parse_prompt_bytes(prompt.read_bytes(), source=str(prompt))


def test_fail_closed_on_missing_matrix_disposition(tmp_path: Path) -> None:
    prompt = tmp_path / "missing.md"
    prompt.write_text(
        "# Missing matrix\n\n"
        "**Objective:** Missing disposition row.\n\n"
        "## Mission\n\n"
        "Mission text.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n\n"
        "## Ordered workstreams\n\n"
        "### 1. First\n\n"
        "### 2. Second\n\n"
        "## Cross-workstream acceptance matrix\n\n"
        "| Item | Required terminal disposition |\n"
        "|---|---|\n"
        "| 1. First | `PASS` |\n"
    )
    with pytest.raises(PromptIngestError, match="missing acceptance disposition"):
        parse_prompt_bytes(prompt.read_bytes(), source=str(prompt))


def test_fail_closed_on_malformed_matrix(tmp_path: Path) -> None:
    prompt = tmp_path / "bad-matrix.md"
    prompt.write_text(
        "# Bad matrix\n\n"
        "**Objective:** Malformed table.\n\n"
        "## Mission\n\n"
        "Mission text.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n\n"
        "## Ordered workstreams\n\n"
        "### 1. First\n\n"
        "## Cross-workstream acceptance matrix\n\n"
        "not a table\n"
    )
    with pytest.raises(PromptIngestError, match="malformed acceptance matrix"):
        parse_prompt_bytes(prompt.read_bytes(), source=str(prompt))


def test_project_node_binding_parses_demo_shape(tmp_path: Path) -> None:
    prompt = tmp_path / "binding.md"
    prompt.write_text(
        "# Demo\n\n"
        "**Objective:** Prove binding.\n\n"
        "## Mission\n\n"
        "Mission text.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n\n"
        "## Project node binding\n\n"
        "| Field | Value |\n"
        "| --- | --- |\n"
        "| Program | `ATS-PROGRAM` v1.0.0-draft |\n"
        "| Node | `ATS-PMO-002-DEMO` (child of `ATS-PMO-002`) |\n"
        "| Acceptance version | `horizon-prereq-demo.v1` |\n"
    )
    parsed = parse_prompt_bytes(prompt.read_bytes(), source=str(prompt))
    assert parsed.project_node is not None
    assert parsed.project_node.project_id == "ATS-PROGRAM"
    assert parsed.project_node.project_version == "1.0.0-draft"
    assert parsed.project_node.node_id == "ATS-PMO-002-DEMO"
    assert parsed.project_node.parent_node_id == "ATS-PMO-002"
    assert parsed.project_node.acceptance_version == "horizon-prereq-demo.v1"


def test_project_node_binding_parses_demo_shape(tmp_path: Path) -> None:
    prompt = tmp_path / "binding.md"
    prompt.write_text(
        "# Demo\n\n"
        "**Objective:** Prove binding.\n\n"
        "## Mission\n\n"
        "Mission text.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n\n"
        "## Project node binding\n\n"
        "| Field | Value |\n"
        "| --- | --- |\n"
        "| Program | `ATS-PROGRAM` v1.0.0-draft |\n"
        "| Node | `ATS-PMO-002-DEMO` (child of `ATS-PMO-002`) |\n"
        "| Acceptance version | `horizon-prereq-demo.v1` |\n"
    )
    parsed = parse_prompt_bytes(prompt.read_bytes(), source=str(prompt))
    assert parsed.project_node is not None
    assert parsed.project_node.project_id == "ATS-PROGRAM"
    assert parsed.project_node.project_version == "1.0.0-draft"
    assert parsed.project_node.node_id == "ATS-PMO-002-DEMO"
    assert parsed.project_node.parent_node_id == "ATS-PMO-002"
    assert parsed.project_node.acceptance_version == "horizon-prereq-demo.v1"

