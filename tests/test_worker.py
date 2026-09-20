"""Worker orchestration tests with fake controller and adapters."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from harness_adapters.contract import HarnessAdapter, HarnessRequest, HarnessResult
from worker import TaskWorker, WorkerControllerLike, WorkerLoop

TEST_ARTIFACT = "test artifact"
TEST_ARTIFACT_SHA256 = hashlib.sha256(TEST_ARTIFACT.encode()).hexdigest()
DEFAULT_CRITERION = TEST_ARTIFACT


def auditor_structured(verdict: str = "approve", criterion: str = DEFAULT_CRITERION) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "criteria": [
            {
                "criterion": criterion,
                "met": verdict == "approve",
                "rationale": "fixture",
                "evidence_refs": [{"name": "stdout", "sha256": TEST_ARTIFACT_SHA256}],
            }
        ],
    }


@dataclass
class FakeTask:
    task_id: str
    run_id: str
    objective: str
    state: str = "leased"
    generation: str = "1"
    attempt: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class ProductionShapedController(WorkerControllerLike):
  """Fake controller matching ParentController worker surface semantics."""

  def __init__(self) -> None:
    self.tasks: dict[str, FakeTask] = {}
    self.cleanups: list[str] = []
    self.retries: list[str] = []
    self.completions: list[tuple[str, str]] = []
    self.evidence: list[dict[str, Any]] = []
    self.transitioned_attempts: set[str] = set()
    self.events: list[str] = []

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
    self.events.append("complete")
    return task

  def retry_task(
      self, run_id: str, task_id: str, generation: str, reason: str, *, delay: float = 0.0,
  ) -> FakeTask:
    task = self.tasks[task_id]
    task.state = "retry_queued"
    task.attempt += 1
    self.retries.append(task_id)
    self.transitioned_attempts.add(f"attempt-{task_id}")
    self.events.append("retry")
    return task

  def record_evidence(self, **kwargs: Any) -> str:
    self.evidence.append(kwargs)
    return "evidence-1"

  def idempotent_cleanup(self, attempt_id: str, *, run_id: str) -> bool:
    if attempt_id not in self.transitioned_attempts:
      raise PermissionError("cannot clean up an unexpired attempt")
    self.cleanups.append(attempt_id)
    self.events.append("cleanup")
    return True

  def resolve_parent_attempt(self, task_id: str, generation: str) -> tuple[str, int]:
    return f"attempt-{task_id}", int(generation, 16)


FakeController = ProductionShapedController


class ScriptedAdapter(HarnessAdapter):
    def __init__(self, adapter_id: str, responses: list[HarnessResult]) -> None:
        self.adapter_id = adapter_id
        self.provider = "fake"
        self.model = adapter_id
        self._responses = list(responses)
        self.calls = 0
        self.requests: list[HarnessRequest] = []
        self.cancel_calls = 0

    def execute(self, request: HarnessRequest) -> HarnessResult:
        self.calls += 1
        self.requests.append(request)
        result = self._responses.pop(0)
        for path, digest in ((result.stdout_artifact_path, result.stdout_sha256), (result.stderr_artifact_path, result.stderr_sha256)):
            if path and digest:
                artifact = Path(request.artifact_dir) / path
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(TEST_ARTIFACT)
                object.__setattr__(result, "stdout_sha256" if path == result.stdout_artifact_path else "stderr_sha256", __import__("hashlib").sha256(b"test artifact").hexdigest())
        return result

    def start(self, request: HarnessRequest) -> HarnessResult:
        return self.execute(request)

    def resume(self, request: HarnessRequest, session_id: str) -> HarnessResult:
        return self.execute(request)

    def cancel(self) -> None:
        self.cancel_calls += 1


def _success_payload(verdict: str = "approve") -> HarnessResult:
    return HarnessResult(
        adapter_id="fake",
        kind="fake",
        model="m",
        provider="p",
        status="success",
        exit_code=0,
        duration_seconds=0.1,
        stdout_artifact_path="stdout.txt",
        stdout_sha256="a" * 64,
        stderr_artifact_path=None,
        stderr_sha256=None,
        structured_payload=auditor_structured(verdict),
        error_classification=None,
        retryable=False,
    )


def _failure(retryable: bool, classification: str) -> HarnessResult:
    return HarnessResult(
        adapter_id="fake",
        kind="fake",
        model="m",
        provider="p",
        status="failure",
        exit_code=1,
        duration_seconds=0.1,
        stdout_artifact_path=None,
        stdout_sha256=None,
        stderr_artifact_path="stderr.txt",
        stderr_sha256="b" * 64,
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
                        "executor_adapter": "executor",
                        "auditor_adapter": "auditor",
                        "acceptance_criteria": [DEFAULT_CRITERION],
                    }
                ],
            }
        )
    )
    return tmp_path


def test_worker_requires_auditor_approval(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": ScriptedAdapter("executor", [_success_payload()]),
        "auditor": ScriptedAdapter("auditor", [_success_payload("approve")]),
    }
    worker = TaskWorker(controller, artifact_root, adapters)  # type: ignore[arg-type]
    result = worker.run_once("run-1", "worker-1")
    assert result is not None
    assert controller.completions[-1] == ("task-1", "verified")


def test_executor_success_without_auditor_approval_does_not_verify(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": ScriptedAdapter("executor", [_success_payload()]),
        "auditor": ScriptedAdapter("auditor", [_success_payload("reject")]),
    }
    worker = TaskWorker(controller, artifact_root, adapters)  # type: ignore[arg-type]
    worker.run_once("run-1", "worker-1")
    assert controller.retries == []
    assert controller.completions[-1] == ("task-1", "blocked")


def test_non_retryable_failure_blocks_task(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": ScriptedAdapter("executor", [_failure(False, "integrity_failure")]),
        "auditor": ScriptedAdapter("auditor", []),
    }
    worker = TaskWorker(controller, artifact_root, adapters)  # type: ignore[arg-type]
    worker.run_once("run-1", "worker-1")
    assert controller.completions[-1] == ("task-1", "blocked")


def test_auditor_payload_must_match_full_schema(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    invalid = _success_payload()
    object.__setattr__(invalid, "structured_payload", {"verdict": "approve", "unexpected": True})
    adapters = {"executor": ScriptedAdapter("executor", [_success_payload()]), "auditor": ScriptedAdapter("auditor", [invalid])}
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == "retry_queued"
    assert controller.completions == []


def test_failed_auditor_cannot_approve(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    failed_approve = _failure(True, "rate_limit")
    object.__setattr__(failed_approve, "structured_payload", {"verdict": "approve"})
    adapters = {"executor": ScriptedAdapter("executor", [_success_payload()]), "auditor": ScriptedAdapter("auditor", [failed_approve])}
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == "retry_queued"
    assert controller.completions == []


def test_auditor_receives_executor_evidence_acceptance_and_task_cwd(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled", metadata={
        "executor_adapter": "executor", "auditor_adapter": "auditor",
        "acceptance_criteria": [DEFAULT_CRITERION],
    })
    executor = ScriptedAdapter("executor", [_success_payload()])
    auditor = ScriptedAdapter("auditor", [_success_payload()])
    TaskWorker(controller, artifact_root, {"executor": executor, "auditor": auditor}).run_once("run-1", "worker")  # type: ignore[arg-type]
    request = auditor.requests[0]
    assert Path(request.cwd).name == "work"
    assert Path(request.cwd).is_relative_to(artifact_root / "runs" / "run-1" / "attempts")
    assert request.metadata["acceptance_criteria"] == [DEFAULT_CRITERION]
    assert "TRUSTED EVIDENCE" in request.prompt
    assert request.metadata["executor_evidence"]["stdout_sha256"]
    assert "EXECUTOR EVIDENCE" in request.prompt


def test_adapter_configuration_exception_blocks(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")

    class MisconfiguredAdapter(ScriptedAdapter):
        def execute(self, request: HarnessRequest) -> HarnessResult:
            raise ValueError("cwd outside allowed roots")

    adapters = {"executor": MisconfiguredAdapter("executor", []), "auditor": ScriptedAdapter("auditor", [])}
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == "blocked"
    assert len(controller.cleanups) == 1


def test_cleanup_runs_on_exception_and_exception_is_mapped(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")

    class BrokenAdapter(ScriptedAdapter):
        def execute(self, request: HarnessRequest) -> HarnessResult:
            raise RuntimeError("boom")

    adapters = {"executor": BrokenAdapter("executor", []), "auditor": ScriptedAdapter("auditor", [])}
    worker = TaskWorker(controller, artifact_root, adapters)  # type: ignore[arg-type]
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "retry_queued"
    assert controller.cleanups == ["attempt-task-1"]
    assert controller.events.index("retry") < controller.events.index("cleanup")


def test_child_process_uses_isolated_attempt_workdir_not_artifact_root(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = ScriptedAdapter("executor", [_success_payload()])
    auditor = ScriptedAdapter("auditor", [_success_payload("approve")])
    TaskWorker(controller, artifact_root, {"executor": executor, "auditor": auditor}).run_once("run-1", "worker")  # type: ignore[arg-type]
    workdir = Path(executor.requests[0].cwd)
    assert workdir.name == "work"
    assert workdir.is_relative_to(artifact_root / "runs" / "run-1" / "attempts")
    assert workdir != artifact_root.resolve()


def test_worker_uses_resolve_parent_attempt_only(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    assert not hasattr(controller, "resolve_attempt")
    adapters = {
        "executor": ScriptedAdapter("executor", [_success_payload()]),
        "auditor": ScriptedAdapter("auditor", [_success_payload("approve")]),
    }
    TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]


def test_invalid_route_blocks_only_claimed_task_and_cleanup_once(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled", metadata={"executor_adapter":"missing", "auditor_adapter":"auditor"})
    controller.tasks["task-2"] = FakeTask("task-2", "run-1", "other", state="scheduled")
    result = TaskWorker(controller, artifact_root, {"auditor": ScriptedAdapter("auditor", [])}).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == "blocked"
    assert controller.tasks["task-2"].state == "scheduled"
    assert len(controller.cleanups) == 1


def test_missing_explicit_route_blocks_without_default_fallback(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    (artifact_root / "runs" / "run-1" / "goal-spec.json").write_text(json.dumps({"workstreams": [{"task_id":"task-1"}]}))
    result = TaskWorker(controller, artifact_root, {}, default_executor="x", default_auditor="y").run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == "blocked"


def test_invalid_evidence_path_or_digest_blocks_task(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    bad = _success_payload()
    object.__setattr__(bad, "stdout_artifact_path", "../escape.txt")
    adapters = {"executor": ScriptedAdapter("executor", [bad]), "auditor": ScriptedAdapter("auditor", [])}
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == "blocked"
    assert controller.evidence == []


def test_worker_records_content_hashed_evidence(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": ScriptedAdapter("executor", [_success_payload()]),
        "auditor": ScriptedAdapter("auditor", [_success_payload("approve")]),
    }
    worker = TaskWorker(controller, artifact_root, adapters)  # type: ignore[arg-type]
    worker.run_once("run-1", "worker-1")
    assert controller.evidence
    assert controller.evidence[0]["producer"] in {"executor", "auditor"}
    assert controller.evidence[0]["artifact_path"].startswith("runs/run-1/attempts/attempt-task-1/executor/")


@pytest.mark.parametrize("classification,retryable,expected", [("auth_failure", False, "parked"), ("timeout", True, "retry_queued")])
def test_worker_retry_policy_parks_auth_but_retries_timeout(artifact_root: Path, classification, retryable, expected) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {"executor": ScriptedAdapter("executor", [_failure(retryable, classification)]), "auditor": ScriptedAdapter("auditor", [])}
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == expected


def test_shutdown_cancelled_executor_requeues_instead_of_blocking(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    cancelled = _failure(False, "cancelled")
    adapters = {
        "executor": ScriptedAdapter("executor", [cancelled]),
        "auditor": ScriptedAdapter("auditor", []),
    }
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == "retry_queued"
    assert controller.retries == ["task-1"]
    assert controller.completions == []


def test_task_metadata_merges_with_goal_spec_workstream_routes(artifact_root: Path) -> None:
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask(
        "task-1",
        "run-1",
        "obj",
        state="scheduled",
        metadata={"controller_epoch": 3, "lease_owner": "worker"},
    )
    adapters = {
        "executor": ScriptedAdapter("executor", [_success_payload()]),
        "auditor": ScriptedAdapter("auditor", [_success_payload("approve")]),
    }
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result and result.terminal_state == "verified"
    assert controller.completions[-1] == ("task-1", "verified")


def test_cancel_active_adapter_is_forwarded_once(artifact_root: Path) -> None:
    controller = FakeController()
    adapter = ScriptedAdapter("executor", [])
    worker = TaskWorker(controller, artifact_root, {"executor": adapter})  # type: ignore[arg-type]
    worker._active_adapter = adapter  # exercise signal-safe forwarding boundary
    worker.cancel_active()
    worker.cancel_active()
    assert adapter.cancel_calls == 1


def test_worker_loop_signal_cancels_active_adapter(artifact_root: Path) -> None:
    controller = FakeController()
    adapter = ScriptedAdapter("executor", [])
    worker = TaskWorker(controller, artifact_root, {"executor": adapter})  # type: ignore[arg-type]
    worker._active_adapter = adapter
    loop = WorkerLoop(worker, run_id="run-1", owner="worker", once=True)
    loop._handle_signal(15, None)
    assert adapter.cancel_calls == 1


class RecoveringFakeController(ProductionShapedController):
    def __init__(self) -> None:
        super().__init__()
        self.recoveries: list[int] = []
        self.recover_payload: dict[str, Any] = {
            "reason": "recovered_contract_failure",
            "recovered": True,
        }

    def recover_executor_contract_failure(
        self,
        run_id: str,
        task_id: str,
        generation: str,
        failure_class: str,
        *,
        expected_attempt: int,
        max_retries: int = 5,
    ) -> dict[str, Any]:
        self.recoveries.append(expected_attempt)
        task = self.tasks[task_id]
        task.state = "queued"
        self.transitioned_attempts.add(f"attempt-{task_id}")
        self.events.append("recover")
        return dict(self.recover_payload)


def test_malformed_executor_output_blocks_without_replaying(artifact_root: Path) -> None:
    controller = RecoveringFakeController()
    controller.tasks["task-1"] = FakeTask(
        "task-1", "run-1", "obj", state="scheduled", attempt=0
    )
    adapters = {
        "executor": ScriptedAdapter(
            "executor", [_failure(True, "malformed_structured_output")]
        ),
        "auditor": ScriptedAdapter("auditor", []),
    }
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "blocked:executor_outcome_requires_review"
    assert controller.recoveries == []
    assert controller.completions == [("task-1", "blocked")]
