"""Tests for task-6 clean re-acceptance without operator SQL or manual chown."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from goal_dependencies import TERMINAL_PARENT_STATES
from prompt_ingest import derive_task_id, parse_prompt_file

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "task6-clean-reacceptance-prompt.md"
SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
import sys

sys.path.insert(0, str(SCRIPTS))
from task6_clean_reacceptance import (  # noqa: E402
    all_workstreams_terminal,
    expected_task_ids,
    prepare_artifact_root,
)


def test_fixture_parses_six_linear_workstreams() -> None:
    parsed = parse_prompt_file(FIXTURE)
    assert len(parsed.workstreams) == 6
    assert parsed.workstreams[0].dependencies == ()
    for index in range(1, 6):
        assert parsed.workstreams[index].dependencies == (index,)
    assert parsed.run_id.startswith("goal-")


def test_fixture_run_id_is_stable() -> None:
    first = parse_prompt_file(FIXTURE)
    second = parse_prompt_file(FIXTURE)
    assert first.run_id == second.run_id
    assert first.sha256 == second.sha256


def test_all_workstreams_terminal_requires_six_terminal_states() -> None:
    parsed = parse_prompt_file(FIXTURE)
    ids = expected_task_ids(parsed.run_id, len(parsed.workstreams))
    partial = {ids[0]: "blocked"}
    assert not all_workstreams_terminal(partial, ids)
    complete = {task_id: "blocked" for task_id in ids}
    assert all_workstreams_terminal(complete, ids)
    leased = dict(complete)
    leased[ids[-1]] = "leased"
    assert not all_workstreams_terminal(leased, ids)


def test_terminal_states_match_goal_dependencies() -> None:
    for state in ("verified", "parked", "blocked", "failed"):
        assert state in TERMINAL_PARENT_STATES
    assert "leased" not in TERMINAL_PARENT_STATES
    assert "running" not in TERMINAL_PARENT_STATES


def test_prepare_artifact_root_applies_owner_without_manual_chown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = "task6-owner"
    monkeypatch.setenv("TOP_DELIVERY_ARTIFACT_OWNER", owner)
    chown_calls: list[tuple[str, int, int]] = []

    def fake_getpwnam(name: str) -> object:
        assert name == owner
        return type("Passwd", (), {"pw_uid": 4242, "pw_gid": 4243})()

    def fake_chown(path: str, uid: int, gid: int) -> None:
        chown_calls.append((path, uid, gid))

    import artifact_owner

    monkeypatch.setattr(artifact_owner.pwd, "getpwnam", fake_getpwnam)
    monkeypatch.setattr(artifact_owner.os, "chown", fake_chown)

    root = prepare_artifact_root(tmp_path / "artifacts")
    assert root.is_dir()
    assert chown_calls
    assert all(uid == 4242 and gid == 4243 for _, uid, gid in chown_calls)
    assert str(root) in {str(path) for path, _, _ in chown_calls}


def test_fixture_submit_schedules_root_only(tmp_path: Path) -> None:
    from dataclasses import dataclass, field

    from goal_submitter import GoalSubmitter
    from goal_dependencies import root_workstreams

    @dataclass
    class FakeParentController:
        scheduled: list[tuple[str, str, str, int]] = field(default_factory=list)
        existing_tasks: set[str] = field(default_factory=set)

        def register_run(self, run_id: str, state: str = "active") -> None:
            return None

        def schedule_task(
            self,
            run_id: str,
            task_id: str,
            objective: str,
            *,
            priority: int = 0,
            available_at: float | None = None,
        ) -> object:
            if task_id not in self.existing_tasks:
                self.existing_tasks.add(task_id)
            self.scheduled.append((run_id, task_id, objective, priority))
            return object()

    parsed = parse_prompt_file(FIXTURE)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    controller = FakeParentController()
    receipt = GoalSubmitter(controller, artifact_root).submit(FIXTURE)

    assert receipt.status == "created"
    assert len(controller.scheduled) == 1
    root = root_workstreams(parsed.workstreams)[0]
    assert controller.scheduled[0][1] == derive_task_id(parsed.run_id, root.number)
    spec = json.loads((artifact_root / "runs" / parsed.run_id / "goal-spec.json").read_text())
    assert spec["run_id"] == parsed.run_id
    assert len(spec["workstreams"]) == 6
