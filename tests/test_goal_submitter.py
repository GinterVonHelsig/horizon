"""Unit tests for GoalSubmitter with an in-memory fake controller."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from goal_submitter import GoalSubmitter, TaskRoutingSnapshot
from prompt_ingest import parse_prompt_file

ALL_SIX_PROMPT = Path("/home/trading/prompts/p0-top-delivery-all-six-20260823.md")


@dataclass
class FakeParentTask:
    task_id: str
    run_id: str
    objective: str
    created: bool = True


@dataclass
class FakeParentController:
    registered_runs: list[str] = field(default_factory=list)
    scheduled: list[tuple[str, str, str, int]] = field(default_factory=list)
    existing_tasks: set[str] = field(default_factory=set)

    def register_run(self, run_id: str, state: str = "active") -> None:
        if run_id not in self.registered_runs:
            self.registered_runs.append(run_id)

    def schedule_task(
        self,
        run_id: str,
        task_id: str,
        objective: str,
        *,
        priority: int = 0,
        available_at: float | None = None,
    ) -> FakeParentTask:
        created = task_id not in self.existing_tasks
        if created:
            self.existing_tasks.add(task_id)
        self.scheduled.append((run_id, task_id, objective, priority))
        return FakeParentTask(task_id=task_id, run_id=run_id, objective=objective, created=created)


def test_all_six_submit_creates_durable_graph(tmp_path: Path) -> None:
    """All-six prompt must produce six scheduled tasks and a content-bound goal spec."""
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    controller = FakeParentController()
    submitter = GoalSubmitter(controller, artifact_root)
    parsed = parse_prompt_file(ALL_SIX_PROMPT)

    receipt = submitter.submit(ALL_SIX_PROMPT)

    assert receipt.run_id == parsed.run_id
    assert receipt.prompt_digest == parsed.sha256
    assert receipt.status == "created"
    assert len(receipt.task_ids) == 6
    assert len(controller.scheduled) == 1
    assert controller.scheduled[0][1] == parsed.workstreams[0].task_id
    assert controller.scheduled[0][3] == 6
    assert controller.registered_runs == [parsed.run_id]

    run_dir = artifact_root / "runs" / parsed.run_id
    spec = json.loads((run_dir / "goal-spec.json").read_text())
    assert spec["prompt_digest"] == parsed.sha256
    assert len(spec["workstreams"]) == 6

    for index, workstream in enumerate(spec["workstreams"], start=1):
        assert workstream["number"] == index
        assert workstream["required_disposition"]
        expected_deps = [] if index == 1 else [index - 1]
        assert workstream["dependencies"] == expected_deps
        assert receipt.dependencies[workstream["task_id"]] == expected_deps

    assert (run_dir / "prompt.snapshot.md").read_bytes() == ALL_SIX_PROMPT.read_bytes()


def test_submit_writes_artifacts_and_schedules_tasks(tmp_path: Path) -> None:
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
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    controller = FakeParentController()
    submitter = GoalSubmitter(controller, artifact_root)

    receipt = submitter.submit(prompt)
    parsed = parse_prompt_file(prompt)

    assert receipt.run_id == parsed.run_id
    assert receipt.prompt_digest == parsed.sha256
    assert receipt.status == "created"
    assert receipt.mode == "durable"
    assert controller.registered_runs == [parsed.run_id]
    assert len(controller.scheduled) == 1
    assert controller.scheduled[0][1] == parsed.workstreams[0].task_id
    assert controller.scheduled[0][3] == 2

    run_dir = artifact_root / "runs" / parsed.run_id
    snapshot = run_dir / "prompt.snapshot.md"
    spec_path = run_dir / "goal-spec.json"
    assert snapshot.read_bytes() == prompt.read_bytes()
    spec = json.loads(spec_path.read_text())
    assert spec["run_id"] == parsed.run_id
    assert spec["allowed"] == list(parsed.allowed)
    assert spec["forbidden"] == list(parsed.forbidden)
    assert len(spec["workstreams"]) == 2


def test_submit_snapshots_explicit_adapter_routes_into_goal_spec(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Routed goal\n\n"
        "**Objective:** Route adapters.\n\n"
        "## Mission\n\n"
        "Snapshot routes.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n"
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    controller = FakeParentController()
    routing = TaskRoutingSnapshot(executor_adapter="codex-cli", auditor_adapter="claude-cli")
    submitter = GoalSubmitter(controller, artifact_root, task_routing=routing)
    receipt = submitter.submit(prompt)
    spec = json.loads((artifact_root / "runs" / receipt.run_id / "goal-spec.json").read_text())
    for workstream in spec["workstreams"]:
        assert workstream["executor_adapter"] == "codex-cli"
        assert workstream["auditor_adapter"] == "claude-cli"


def test_submit_is_idempotent(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# One task\n\n"
        "**Objective:** One outcome.\n\n"
        "## Mission\n\n"
        "Do it once.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n"
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    controller = FakeParentController()
    submitter = GoalSubmitter(controller, artifact_root)

    first = submitter.submit(prompt)
    second = submitter.submit(prompt)

    assert first.status == "created"
    assert second.status == "existing"
    assert controller.registered_runs.count(first.run_id) == 1
    assert len(controller.existing_tasks) == 1
    assert len(controller.scheduled) == 2


def test_submit_rejects_precreated_empty_run_directory_without_writing(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Interrupted\n\n"
        "**Objective:** Resume after partial create.\n\n"
        "## Mission\n\n"
        "Recover from empty run dir.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n"
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    controller = FakeParentController()
    submitter = GoalSubmitter(controller, artifact_root)
    parsed = parse_prompt_file(prompt)
    run_dir = artifact_root / "runs" / parsed.run_id
    run_dir.mkdir(parents=True)

    with pytest.raises(ValueError, match="exists without a valid snapshot"):
        submitter.submit(prompt)
    assert not (run_dir / "goal-spec.json").exists()
    assert not (run_dir / "prompt.snapshot.md").exists()


def test_submit_rejects_mismatched_existing_goal_spec(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Locked\n\n"
        "**Objective:** Keep existing spec.\n\n"
        "## Mission\n\n"
        "Do not overwrite mismatched spec.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n"
    )
    other = tmp_path / "other.md"
    other.write_text(prompt.read_text().replace("Locked", "Changed"))
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    controller = FakeParentController()
    submitter = GoalSubmitter(controller, artifact_root)
    other_parsed = parse_prompt_file(other)
    run_dir = artifact_root / "runs" / other_parsed.run_id
    run_dir.mkdir(parents=True)
    spec_path = run_dir / "goal-spec.json"
    spec_path.write_text(
        json.dumps({"prompt_digest": "deadbeef", "run_id": other_parsed.run_id}) + "\n"
    )

    with pytest.raises(ValueError, match="does not match prompt digest"):
        submitter.submit(other)


def test_build_controller_durable_submit_is_not_lease_holder(tmp_path: Path) -> None:
    from unittest.mock import patch

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    with patch("parent_controller.ParentController") as controller_cls:
        from goal_submitter import build_controller

        build_controller(
            "postgresql://top_delivery_workflow@127.0.0.1:5432/top_delivery_control_p1",
            artifact_root,
            dry_run=False,
        )
    controller_cls.assert_called_once()
    assert controller_cls.call_args.kwargs["lease_holder"] is False
