"""Tests for worker cleanup failure surfacing."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from worker import TaskWorker


class FakeTask:
    def __init__(self) -> None:
        self.run_id = "run-1"
        self.task_id = "task-1"
        self.objective = "work"
        self.generation = "1"


class FakeController:
    def __init__(self) -> None:
        self.cleanup_failures: list[dict[str, str]] = []

    def claim_next(self, run_id: str, owner: str) -> FakeTask | None:
        return FakeTask()

    def resolve_parent_attempt(self, task_id: str, generation: str) -> tuple[str, int]:
        return "attempt-1", 1

    def complete_task(self, run_id: str, task_id: str, generation: str, state: str) -> object:
        return None

    def retry_task(self, *args: object, **kwargs: object) -> object:
        return None

    def record_evidence(self, **kwargs: object) -> str:
        return "evidence-1"

    def idempotent_cleanup(self, attempt_id: str, *, run_id: str) -> bool:
        raise RuntimeError("cleanup boom")

    def record_cleanup_failure(
        self, run_id: str, attempt_id: str, *, error: str, phase: str = "worker_finalize"
    ) -> None:
        self.cleanup_failures.append(
            {
                "run_id": run_id,
                "attempt_id": attempt_id,
                "error": error,
                "phase": phase,
            }
        )


def test_worker_records_cleanup_failure_instead_of_silent_return(tmp_path: Path) -> None:
    controller = FakeController()
    artifact_root = tmp_path / "artifacts"
    run_dir = artifact_root / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    spec = {
        "run_id": "run-1",
        "workstreams": [
            {
                "number": 1,
                "title": "work",
                "task_id": "task-1",
                "dependencies": [],
            }
        ],
    }
    (run_dir / "goal-spec.json").write_text(json.dumps(spec) + "\n")

    worker = TaskWorker(controller, artifact_root, {})
    worker.run_once("run-1", "worker")
    assert controller.cleanup_failures == [
        {
            "run_id": "run-1",
            "attempt_id": "attempt-1",
            "error": "RuntimeError",
            "phase": "worker_finalize",
        }
    ]
