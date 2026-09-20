"""New submits store acceptance_criteria as raw disposition strings."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from auditor_bind import normalize_acceptance_criteria
from goal_submitter import GoalSubmitter

TOKEN = "PASS_STRING_TOKEN"
OBJECT_DUMP = '{"disposition": "PASS_STRING_TOKEN"}'
NDJSON_SNIPPET = (
    '{"type":"user","message":{"role":"user","content":[{"type":"text","text":"'
    "token " + TOKEN + ' and escaped {\\"disposition\\": \\"PASS_STRING_TOKEN\\"}'
    '"}]}}\n'
)


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


def _tiny_prompt(path: Path) -> None:
    path.write_text(
        "# String acceptance toy\n\n"
        "**Objective:** Store the token as a string criterion.\n\n"
        "## Mission\n\n"
        "Write one workstream.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- Write artifacts.\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- Broker mutation.\n\n"
        "## Ordered workstreams\n\n"
        "### 1. Token\n\n"
        "Stop after the token.\n\n"
        "## Cross-workstream acceptance matrix\n\n"
        "| Item | Required terminal disposition |\n"
        "|---|---|\n"
        f"| 1. Token | `{TOKEN}` |\n",
        encoding="utf-8",
    )


def test_submit_stores_raw_string_acceptance_criteria(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    _tiny_prompt(prompt)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submitter = GoalSubmitter(FakeParentController(), artifact_root)
    receipt = submitter.submit(prompt)
    spec_path = artifact_root / "runs" / receipt.run_id / "goal-spec.json"
    raw = spec_path.read_text(encoding="utf-8")
    spec = json.loads(raw)
    criteria = spec["workstreams"][0]["acceptance_criteria"]
    assert criteria == [TOKEN]
    assert TOKEN in raw
    assert '{"disposition":' not in raw
    assert normalize_acceptance_criteria(criteria) == [TOKEN]
    assert TOKEN in NDJSON_SNIPPET
    assert OBJECT_DUMP not in NDJSON_SNIPPET
    assert normalize_acceptance_criteria(criteria)[0] in NDJSON_SNIPPET


def test_normalize_keeps_object_form_for_old_specs() -> None:
    assert normalize_acceptance_criteria([{"disposition": TOKEN}]) == [OBJECT_DUMP]
    assert normalize_acceptance_criteria([TOKEN]) == [TOKEN]
    assert OBJECT_DUMP not in NDJSON_SNIPPET
    assert TOKEN in NDJSON_SNIPPET
