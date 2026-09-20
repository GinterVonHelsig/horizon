"""Unit tests for goal dependency scheduling helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from goal_dependencies import (
    ready_successor_workstreams,
    root_workstreams,
    workstream_priority,
)
from prompt_ingest import parse_prompt_file


def test_workstream_priority_orders_first_workstream_ahead() -> None:
    assert workstream_priority(1, 6) > workstream_priority(6, 6)


def test_root_workstreams_only_includes_dependency_free_slices(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Two-step goal\n\n"
        "**Objective:** Ship safely.\n\n"
        "## Mission\n\n"
        "Deliver two ordered slices.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- Update artifacts.\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- Broker mutation.\n\n"
        "## Ordered workstreams\n\n"
        "### 1. First slice\n\n"
        "### 2. Second slice\n\n"
        "## Cross-workstream acceptance matrix\n\n"
        "| Item | Required terminal disposition |\n"
        "|---|---|\n"
        "| 1. First | `PASS/ONE` |\n"
        "| 2. Second | `PASS/TWO` |\n"
    )
    parsed = parse_prompt_file(prompt)
    roots = root_workstreams(parsed.workstreams)
    assert len(roots) == 1
    assert roots[0].number == 1


def test_ready_successor_requires_terminal_predecessor(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    run_id = "goal-5555555555555555"
    run_dir = artifact_root / "runs" / run_id
    run_dir.mkdir(parents=True)
    spec = {
        "run_id": run_id,
        "workstreams": [
            {
                "number": 1,
                "title": "first",
                "task_id": f"{run_id}-ws-01",
                "dependencies": [],
                "required_disposition": "PASS",
            },
            {
                "number": 2,
                "title": "second",
                "task_id": f"{run_id}-ws-02",
                "dependencies": [1],
                "required_disposition": "PASS",
            },
        ],
    }
    (run_dir / "goal-spec.json").write_text(json.dumps(spec) + "\n")
    states = {f"{run_id}-ws-01": "queued"}
    assert ready_successor_workstreams(
        artifact_root, run_id, f"{run_id}-ws-01", states
    ) == []
    states = {f"{run_id}-ws-01": "blocked"}
    assert ready_successor_workstreams(
        artifact_root, run_id, f"{run_id}-ws-01", states
    ) == []
    states = {f"{run_id}-ws-01": "verified"}
    ready = ready_successor_workstreams(
        artifact_root, run_id, f"{run_id}-ws-01", states
    )
    assert [item.task_id for item in ready] == [f"{run_id}-ws-02"]
