"""Worker integration tests for GoalRunner, transport, and budget wiring."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from goal_runner import GoalRunner, GoalSnapshot
from goal_states import HARD_BLOCKED_PATH
from harness_adapters.contract import HarnessAdapter, HarnessRequest, HarnessResult
from openrouter_budget import BudgetLimits, OpenRouterBudgetGuard
from operator_asymmetric import generate_keypair
from terra_release_policy import issue_authoritative_receipt
from worktree_transport import WorktreeTransport
from worker import TaskWorker, WorkerLoop

TEST_ARTIFACT = "test artifact"
TEST_ARTIFACT_SHA256 = hashlib.sha256(TEST_ARTIFACT.encode()).hexdigest()


def auditor_structured(verdict: str = "approve") -> dict[str, Any]:
    return {
        "verdict": verdict,
        "criteria": [
            {
                "criterion": TEST_ARTIFACT,
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
    attempt: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


class IntegrationController:
    def __init__(self) -> None:
        self.tasks: dict[str, FakeTask] = {}
        self.retries: list[tuple[str, str]] = []
        self.completions: list[tuple[str, str]] = []
        self.cleanups: list[str] = []
        self.transitioned_attempts: set[str] = set()
        self.signal_status: list[dict[str, Any]] = []

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
        self, run_id: str, task_id: str, generation: str, reason: str, *, delay: float = 0.0,
    ) -> FakeTask:
        task = self.tasks[task_id]
        task.state = "retry_queued"
        task.attempt += 1
        self.retries.append((task_id, reason))
        self.transitioned_attempts.add(f"attempt-{task_id}")
        return task

    def record_evidence(self, **kwargs: Any) -> str:
        return "evidence-1"

    def idempotent_cleanup(self, attempt_id: str, *, run_id: str) -> bool:
        if attempt_id not in self.transitioned_attempts:
            raise PermissionError("cannot clean up an unexpired attempt")
        self.cleanups.append(attempt_id)
        return True

    def resolve_parent_attempt(self, task_id: str, generation: str) -> tuple[str, int]:
        return f"attempt-{task_id}", int(generation, 16)


class ScriptedAdapter(HarnessAdapter):
    def __init__(self, adapter_id: str, responses: list[HarnessResult], *, provider: str = "fake") -> None:
        self.adapter_id = adapter_id
        self.provider = provider
        self.model = adapter_id
        self._responses = list(responses)
        self.requests: list[HarnessRequest] = []

    def execute(self, request: HarnessRequest) -> HarnessResult:
        self.requests.append(request)
        result = self._responses.pop(0)
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


def _git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(cwd), text=True).strip()


def _init_source_repo(path: Path) -> str:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")
    (path / "README.md").write_text("base\n")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "base")
    return _git(path, "rev-parse", "HEAD")


def _failure(classification: str, *, retryable: bool = False, provider: str = "fake") -> HarnessResult:
    return HarnessResult(
        adapter_id="executor",
        kind="fake",
        model="m",
        provider=provider,
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


def _success(verdict: str = "approve") -> HarnessResult:
    return HarnessResult(
        adapter_id="fake",
        kind="fake",
        model="m",
        provider="fake",
        status="success",
        exit_code=0,
        duration_seconds=0.1,
        stdout_artifact_path="stdout.txt",
        stdout_sha256=TEST_ARTIFACT_SHA256,
        stderr_artifact_path=None,
        stderr_sha256=None,
        structured_payload=auditor_structured(verdict),
        error_classification=None,
        retryable=False,
    )


@pytest.fixture
def transport_bundle(tmp_path: Path) -> dict[str, Any]:
    source = tmp_path / "source-repo"
    base_sha = _init_source_repo(source)
    dirty = tmp_path / "dirty-checkout"
    subprocess.run(["cp", "-a", f"{source}/.", str(dirty)], check=True)
    (dirty / "local-only.txt").write_text("dirty\n")
    artifact_root = tmp_path / "artifacts"
    run_dir = artifact_root / "runs" / "run-1"
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
                        "transport_source_repo": str(source),
                        "transport_base_sha": base_sha,
                        "user_checkout_path": str(dirty),
                    }
                ],
            }
        )
    )
    transport = WorktreeTransport(mirror_root=tmp_path / "mirror", repo_name="goal-runner")
    transport.initialize_mirror(source)
    return {
        "artifact_root": artifact_root,
        "transport": transport,
        "source": source,
        "base_sha": base_sha,
        "dirty": dirty,
    }


def _worker(
    controller: IntegrationController,
    bundle: dict[str, Any],
    adapters: dict[str, HarnessAdapter],
    *,
    budget_guard: OpenRouterBudgetGuard | None = None,
) -> TaskWorker:
    goal_runner = GoalRunner(budget_guard=budget_guard)
    goals = {"run-1": GoalSnapshot(run_id="run-1")}
    return TaskWorker(
        controller,  # type: ignore[arg-type]
        bundle["artifact_root"],
        adapters,
        goal_runner=goal_runner,
        worktree_transport=bundle["transport"],
        goal_snapshots=goals,
        transport_owner="worker-test",
    )


def test_queueable_rate_limit_retries_via_goal_runner(transport_bundle: dict[str, Any]) -> None:
    controller = IntegrationController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    worker = _worker(
        controller,
        transport_bundle,
        {
            "executor": ScriptedAdapter("executor", [_failure("rate_limit", retryable=True)]),
            "auditor": ScriptedAdapter("auditor", []),
        },
    )
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "retry_queued"
    assert controller.retries
    assert "provider_limit" in controller.retries[0][1]


def test_missing_credential_parks_without_killing_worker_loop(transport_bundle: dict[str, Any]) -> None:
    controller = IntegrationController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    worker = _worker(
        controller,
        transport_bundle,
        {
            "executor": ScriptedAdapter("executor", [_failure("auth_failure", retryable=False)]),
            "auditor": ScriptedAdapter("auditor", []),
        },
    )
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "parked"
    assert controller.completions[-1] == ("task-1", "parked")
    assert controller.retries == []
    loop = WorkerLoop(worker, run_id="run-1", owner="worker-1", once=True)
    loop.run()


def test_openrouter_adapter_refuses_silent_fallback(transport_bundle: dict[str, Any]) -> None:
    controller = IntegrationController()
    controller.tasks["task-1"] = FakeTask(
        "task-1",
        "run-1",
        "obj",
        state="scheduled",
        metadata={"openrouter_fallback": False},
    )
    spec_path = transport_bundle["artifact_root"] / "runs" / "run-1" / "goal-spec.json"
    spec = json.loads(spec_path.read_text())
    spec["workstreams"][0]["openrouter_fallback"] = False
    spec_path.write_text(json.dumps(spec))
    guard = OpenRouterBudgetGuard(BudgetLimits(per_run_usd=Decimal("5"), monthly_usd=Decimal("50")))
    worker = _worker(
        controller,
        transport_bundle,
        {
            "executor": ScriptedAdapter("executor", [_success()], provider="openrouter"),
            "auditor": ScriptedAdapter("auditor", [_success()]),
        },
        budget_guard=guard,
    )
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "parked"
    assert controller.completions[-1] == ("task-1", "parked")
    assert guard.ledger.spent_for_run("run-1") == Decimal("0")


def test_openrouter_adapter_allows_explicit_budgeted_fallback(transport_bundle: dict[str, Any]) -> None:
    controller = IntegrationController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    guard = OpenRouterBudgetGuard(
        BudgetLimits(per_run_usd=Decimal("5"), monthly_usd=Decimal("50")),
        ledger_path=transport_bundle["artifact_root"] / "openrouter-budget-ledger.json",
    )
    bundle = transport_bundle
    spec = json.loads((bundle["artifact_root"] / "runs" / "run-1" / "goal-spec.json").read_text())
    spec["workstreams"][0]["openrouter_fallback"] = True
    spec["workstreams"][0]["openrouter_fallback_reason"] = "provider-limit"
    spec["workstreams"][0]["openrouter_estimated_cost_usd"] = "0.50"
    (bundle["artifact_root"] / "runs" / "run-1" / "goal-spec.json").write_text(json.dumps(spec))
    worker = _worker(
        controller,
        bundle,
        {
            "executor": ScriptedAdapter("executor", [_success()], provider="openrouter"),
            "auditor": ScriptedAdapter("auditor", [_success("approve")]),
        },
        budget_guard=guard,
    )
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "verified"
    assert guard.ledger.spent_for_run("run-1") == Decimal("0.50")


def test_attempt_cwd_uses_fresh_worktree_not_dirty_checkout(transport_bundle: dict[str, Any]) -> None:
    controller = IntegrationController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = ScriptedAdapter("executor", [_success()])
    auditor = ScriptedAdapter("auditor", [_success("approve")])
    dirty = transport_bundle["dirty"]
    before = _git(dirty, "status", "--porcelain")
    worker = _worker(controller, transport_bundle, {"executor": executor, "auditor": auditor})
    worker.run_once("run-1", "worker-1")
    after = _git(dirty, "status", "--porcelain")
    assert before == after
    cwd = Path(executor.requests[0].cwd)
    assert cwd != dirty.resolve()
    evidence = json.loads(
        (transport_bundle["artifact_root"] / "runs" / "run-1" / "attempts" / "attempt-task-1" / "dirty-checkout-evidence.json").read_text()
    )
    assert evidence["dirty"] is True


def test_integrity_failure_blocks_path_only(transport_bundle: dict[str, Any]) -> None:
    controller = IntegrationController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    worker = _worker(
        controller,
        transport_bundle,
        {
            "executor": ScriptedAdapter("executor", [_failure("integrity_failure")]),
            "auditor": ScriptedAdapter("auditor", []),
        },
    )
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "blocked"
    assert worker.goal_snapshots["run-1"].state == HARD_BLOCKED_PATH


def test_release_policy_receipt_written_on_verify(transport_bundle: dict[str, Any]) -> None:
    private_key, public_key = generate_keypair()
    controller = IntegrationController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    bundle = transport_bundle
    candidate_sha = "b" * 40
    spec = json.loads((bundle["artifact_root"] / "runs" / "run-1" / "goal-spec.json").read_text())
    spec["workstreams"][0]["release_policy"] = {
        "base_sha": bundle["base_sha"],
        "candidate_sha": candidate_sha,
        "tree_sha": "c" * 40,
        "reviewed_sha": candidate_sha,
        "backup_manifest_sha256": "d" * 64,
        "rollback_plan_sha256": "e" * 64,
        "broker_safety": "flat",
        "database_safety": "verified",
        "scope_envelope_sha256": "f" * 64,
        "policy_signing_key": private_key,
        "policy_verify_key": public_key,
    }
    (bundle["artifact_root"] / "runs" / "run-1" / "goal-spec.json").write_text(json.dumps(spec))
    worker = _worker(
        controller,
        bundle,
        {
            "executor": ScriptedAdapter("executor", [_success()]),
            "auditor": ScriptedAdapter("auditor", [_success("approve")]),
        },
    )
    result = worker.run_once("run-1", "worker-1")
    assert result and result.terminal_state == "verified"
    receipt_path = (
        bundle["artifact_root"] / "runs" / "run-1" / "attempts" / "attempt-task-1" / "release-policy-receipt.json"
    )
    receipt = json.loads(receipt_path.read_text())
    assert receipt["authoritative"] is True
    assert receipt["paid_model_call_required"] is False
