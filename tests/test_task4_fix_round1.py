"""Regression tests for task-4 review fix round 1."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from goal_runner import GoalRunner, GoalSnapshot
from goal_states import ACTIVE, HARD_BLOCKED_PATH
from harness_adapters.contract import HarnessAdapter, HarnessRequest, HarnessResult
from model_routing import load_model_routing, resolve_phase_route
from worktree_transport import WorktreeTransport
from worker import TaskWorker

TEST_ARTIFACT = "test artifact"
TEST_ARTIFACT_SHA256 = hashlib.sha256(TEST_ARTIFACT.encode()).hexdigest()


@dataclass
class FakeTask:
    task_id: str
    run_id: str
    objective: str
    state: str = "leased"
    generation: str = "1"
    attempt: int = 2
    metadata: dict[str, Any] = field(default_factory=dict)


class TrackingController:
    def __init__(self) -> None:
        self.tasks: dict[str, FakeTask] = {}
        self.retries: list[dict[str, Any]] = []
        self.completions: list[tuple[str, str]] = []
        self.transitioned_attempts: set[str] = set()

    def claim_next(self, run_id: str, owner: str) -> FakeTask | None:
        for task in self.tasks.values():
            if task.run_id == run_id and task.state == "scheduled":
                task.state = "leased"
                return task
        return None

    def complete_task(self, run_id: str, task_id: str, generation: str, state: str) -> FakeTask:
        task = self.tasks[task_id]
        task.state = state
        self.completions.append((task_id, state))
        self.transitioned_attempts.add(f"attempt-{task_id}")
        return task

    def retry_task(
        self, run_id: str, task_id: str, generation: str, reason: str, *, delay: float = 0.0
    ) -> FakeTask:
        task = self.tasks[task_id]
        task.state = "retry_queued"
        self.retries.append({"task_id": task_id, "reason": reason, "delay": delay})
        self.transitioned_attempts.add(f"attempt-{task_id}")
        return task

    def record_evidence(self, **kwargs: Any) -> str:
        return "evidence-1"

    def idempotent_cleanup(self, attempt_id: str, *, run_id: str) -> bool:
        if attempt_id not in self.transitioned_attempts:
            raise PermissionError("cannot clean up an unexpired attempt")
        return True

    def resolve_parent_attempt(self, task_id: str, generation: str) -> tuple[str, int]:
        return f"attempt-{task_id}", int(generation, 16)


class ScriptedAdapter(HarnessAdapter):
    def __init__(self, result: HarnessResult, *, adapter_id: str) -> None:
        self.adapter_id = adapter_id
        self.provider = "fake"
        self.model = adapter_id
        self._result = result
        self.requests: list[HarnessRequest] = []

    def execute(self, request: HarnessRequest) -> HarnessResult:
        self.requests.append(request)
        result = self._result
        if result.stdout_artifact_path and result.stdout_sha256:
            artifact = Path(request.artifact_dir) / result.stdout_artifact_path
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text(TEST_ARTIFACT)
            object.__setattr__(result, "stdout_sha256", TEST_ARTIFACT_SHA256)
        return result

    def start(self, request: HarnessRequest) -> HarnessResult:
        return self.execute(request)

    def resume(self, request: HarnessRequest, session_id: str) -> HarnessResult:
        return self.execute(request)

    def cancel(self) -> None: ...


def _failure(classification: str, *, retryable: bool = True) -> HarnessResult:
    return HarnessResult(
        adapter_id="executor",
        kind="fake",
        model="m",
        provider="p",
        status="failure",
        exit_code=1,
        duration_seconds=0.1,
        stdout_artifact_path=None,
        stdout_sha256=None,
        stderr_artifact_path=None,
        stderr_sha256=None,
        structured_payload=None,
        error_classification=classification,
        retryable=retryable,
    )


@pytest.fixture
def artifact_root(tmp_path: Path) -> Path:
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "goal-spec.json").write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "workstreams": [
                    {
                        "task_id": "task-1",
                        "path_id": "path-1",
                        "executor_adapter": "executor",
                        "auditor_adapter": "auditor",
                        "acceptance_criteria": [TEST_ARTIFACT],
                    }
                ],
            }
        )
    )
    return tmp_path


def test_queueable_retry_applies_bounded_backoff_delay(artifact_root: Path) -> None:
    controller = TrackingController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled", attempt=2)
    worker = TaskWorker(
        controller,  # type: ignore[arg-type]
        artifact_root,
        {"executor": ScriptedAdapter(_failure("rate_limit"), adapter_id="executor"), "auditor": ScriptedAdapter(_failure("rate_limit"), adapter_id="auditor")},
        goal_snapshots={"run-1": GoalSnapshot(run_id="run-1")},
    )
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "retry_queued"
    assert controller.retries
    assert controller.retries[0]["delay"] == 10


def test_hard_block_emits_hard_blocked_path_goal_state(artifact_root: Path) -> None:
    controller = TrackingController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    goals = {"run-1": GoalSnapshot(run_id="run-1", state=ACTIVE)}
    worker = TaskWorker(
        controller,  # type: ignore[arg-type]
        artifact_root,
        {"executor": ScriptedAdapter(_failure("integrity_failure", retryable=False), adapter_id="executor"), "auditor": ScriptedAdapter(_failure("integrity_failure"), adapter_id="auditor")},
        goal_snapshots=goals,
    )
    worker.run_once("run-1", "worker-1")
    assert goals["run-1"].state == HARD_BLOCKED_PATH


def test_handle_failure_does_not_reload_broken_task_context(artifact_root: Path) -> None:
    controller = TrackingController()
    controller.tasks["task-1"] = FakeTask(
        "task-1",
        "run-1",
        "obj",
        state="scheduled",
        metadata={"executor_adapter": "executor", "auditor_adapter": "auditor"},
    )
    (artifact_root / "runs" / "run-1" / "goal-spec.json").write_text("{not-json")
    worker = TaskWorker(controller, artifact_root, {  # type: ignore[arg-type]
        "executor": ScriptedAdapter(_failure("rate_limit"), adapter_id="executor"),
        "auditor": ScriptedAdapter(_failure("rate_limit"), adapter_id="auditor"),
    })
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "blocked"
    assert controller.completions[-1] == ("task-1", "blocked")


def test_writing_lease_released_after_terminal_path(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init"], cwd=source, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=source, check=True)
    (source / "README.md").write_text("base\n")
    subprocess.run(["git", "add", "README.md"], cwd=source, check=True)
    subprocess.run(["git", "commit", "-m", "base"], cwd=source, check=True)
    base_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()

    artifact_root = tmp_path / "artifacts"
    run_dir = artifact_root / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "goal-spec.json").write_text(
        json.dumps(
            {
                "workstreams": [
                    {
                        "task_id": "task-1",
                        "executor_adapter": "executor",
                        "auditor_adapter": "auditor",
                        "acceptance_criteria": [TEST_ARTIFACT],
                        "transport_source_repo": str(source),
                        "transport_base_sha": base_sha,
                    }
                ]
            }
        )
    )
    transport = WorktreeTransport(mirror_root=tmp_path / "mirror", repo_name="demo")
    controller = TrackingController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    worker = TaskWorker(
        controller,  # type: ignore[arg-type]
        artifact_root,
        {"executor": ScriptedAdapter(_failure("integrity_failure", retryable=False), adapter_id="executor"), "auditor": ScriptedAdapter(_failure("integrity_failure"), adapter_id="auditor")},
        worktree_transport=transport,
        transport_owner="worker-1",
    )
    worker.run_once("run-1", "worker-1")
    transport.acquire_writing_lease("worker-2")


def test_worker_without_mirror_transport_uses_legacy_workdir(artifact_root: Path) -> None:
    controller = TrackingController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    success = HarnessResult(
        adapter_id="executor",
        kind="fake",
        model="m",
        provider="p",
        status="success",
        exit_code=0,
        duration_seconds=0.1,
        stdout_artifact_path="stdout.txt",
        stdout_sha256=TEST_ARTIFACT_SHA256,
        stderr_artifact_path=None,
        stderr_sha256=None,
        structured_payload={
            "verdict": "approve",
            "criteria": [
                {
                    "criterion": TEST_ARTIFACT,
                    "met": True,
                    "rationale": "fixture",
                    "evidence_refs": [{"name": "stdout", "sha256": TEST_ARTIFACT_SHA256}],
                }
            ],
        },
        error_classification=None,
        retryable=False,
    )
    executor = ScriptedAdapter(success, adapter_id="executor")
    worker = TaskWorker(
        controller,  # type: ignore[arg-type]
        artifact_root,
        {"executor": executor, "auditor": ScriptedAdapter(success, adapter_id="auditor")},
        worktree_transport=None,
    )
    worker.run_once("run-1", "worker-1")
    assert executor.requests
    cwd = Path(executor.requests[0].cwd)
    assert cwd.name == "work"
    assert cwd.is_relative_to(artifact_root / "runs" / "run-1" / "attempts")


def test_phase_7_openrouter_fallback_records_reason() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    record = resolve_phase_route(routing, "7", use_fallback_index=1)
    assert record.provider == "openrouter"
    assert record.fallback_reason == "explicit-escalation-or-budget-approved-fallback"
