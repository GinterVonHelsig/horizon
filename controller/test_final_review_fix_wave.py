"""PG-backed final-review fix wave tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exceptions import DependencyScheduleError
from parent_controller import ParentController


def _controller(db_url: str, artifact_root: Path) -> ParentController:
    return ParentController(
        db_url,
        stale_after=10,
        controller_lease_seconds=5,
        artifact_root=artifact_root,
        lease_holder=False,
    )


def _goal_spec(run_dir: Path, run_id: str) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "goal-spec.json").write_text(
        json.dumps(
            {
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
        )
        + "\n"
    )


def test_goal_pause_blocks_claim_next(db_url: str, artifact_root: Path) -> None:
    from goal_states import WAITING_OPERATOR

    controller = _controller(db_url, artifact_root)
    run_id = "run-pause-1"
    controller.register_run(run_id)
    controller.schedule_task(run_id, "task-1", "work")
    controller.persist_goal_state(run_id, WAITING_OPERATOR)
    assert controller.claim_next(run_id, "worker") is None
    controller.close()


def test_complete_task_schedules_successor(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    run_id = "run-successor-1"
    _goal_spec(artifact_root / "runs" / run_id, run_id)
    controller.register_run(run_id)
    controller.schedule_task(run_id, f"{run_id}-ws-01", "first")
    claimed = controller.claim_next(run_id, "worker")
    assert claimed is not None
    controller.complete_task(run_id, claimed.task_id, claimed.generation or "", "verified")
    states = controller._repo.list_parent_task_states(run_id)
    assert states[f"{run_id}-ws-02"] == "queued"
    controller.close()


def test_dependency_schedule_failure_raises(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    run_id = "run-sched-fail-1"
    controller.register_run(run_id)
    controller.schedule_task(run_id, "task-1", "first")
    claimed = controller.claim_next(run_id, "worker")
    assert claimed is not None
    with pytest.raises(DependencyScheduleError):
        controller.complete_task(run_id, claimed.task_id, claimed.generation or "", "verified")
    controller.close()


def test_worker_claims_across_active_runs(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-a")
    controller.register_run("run-b")
    controller.schedule_task("run-a", "task-a", "a")
    controller.schedule_task("run-b", "task-b", "b")
    claimed = controller.claim_next_available("worker")
    assert claimed is not None
    assert claimed.task_id in {"task-a", "task-b"}
    controller.close()
