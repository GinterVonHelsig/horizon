"""Final-review fix wave regression tests (Important findings #2–#10)."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from comms01_release_deploy import RecoveryEvidence, recovery_evidence_passes
from failure_taxonomy import classify_failure, harness_failure_reason
from goal_dependencies import DEPENDENCY_SUCCESS_STATES, ready_successor_workstreams
from harness_adapters.cli_adapters import CliHarnessAdapter
from harness_adapters.contract import HarnessRequest
from harness_adapters.subprocess_runner import SubprocessRunner
from openrouter_budget import BudgetLimits, OpenRouterBudgetGuard
from worktree_transport import WorktreeTransport, WritingLeaseRequiredError


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


def test_recovery_passes_with_empty_queue_generation() -> None:
    recovery = RecoveryEvidence(
        controller_active=True,
        worker_active=True,
        supervisor_active=True,
        queue_generation=0,
        signal_readable=True,
        signal_writable=True,
        duplicate_side_effects=False,
    )
    assert recovery_evidence_passes(recovery)


def test_hard_blocked_path_does_not_pause_claims(tmp_path: Path) -> None:
    from goal_state_store import GoalStateStore, PAUSED_GOAL_STATES
    from goal_states import HARD_BLOCKED_PATH, WAITING_OPERATOR

    store = GoalStateStore(tmp_path)
    store.write("run-1", HARD_BLOCKED_PATH)
    assert store.is_paused("run-1") is False
    assert HARD_BLOCKED_PATH not in PAUSED_GOAL_STATES
    store.write("run-1", WAITING_OPERATOR)
    assert store.is_paused("run-1") is True


def test_worker_survives_post_commit_schedule_failure(tmp_path: Path) -> None:
    from exceptions import DependencyScheduleError
    from worker import TaskWorker

    class Controller:
        def __init__(self) -> None:
            self.complete_calls = 0
            self.retry_calls = 0

        def complete_task(self, run_id: str, task_id: str, generation: str, state: str) -> None:
            self.complete_calls += 1
            raise DependencyScheduleError("boom")

        def retry_successor_schedule(self, run_id: str, task_id: str) -> None:
            self.retry_calls += 1

    controller = Controller()
    worker = TaskWorker(controller, tmp_path, {})  # type: ignore[arg-type]
    worker._complete_verified("run-1", "task-1", "deadbeef")
    assert controller.complete_calls == 1
    assert controller.retry_calls == 1


def test_blocked_predecessor_does_not_unlock_successor(tmp_path: Path) -> None:
    run_id = "goal-deps000000001"
    artifact_root = tmp_path / "artifacts"
    _goal_spec(artifact_root / "runs" / run_id, run_id)
    states = {f"{run_id}-ws-01": "blocked"}
    assert ready_successor_workstreams(artifact_root, run_id, f"{run_id}-ws-01", states) == []
    states = {f"{run_id}-ws-01": "verified"}
    ready = ready_successor_workstreams(artifact_root, run_id, f"{run_id}-ws-01", states)
    assert [item.task_id for item in ready] == [f"{run_id}-ws-02"]
    assert "verified" in DEPENDENCY_SUCCESS_STATES


def test_worker_loop_accepts_optional_run_id() -> None:
    import inspect
    from worker import WorkerLoop

    signature = inspect.signature(WorkerLoop.__init__)
    assert signature.parameters["run_id"].annotation in {"str | None", None}


def test_harness_cli_unavailable_is_capability_remediation() -> None:
    reason = harness_failure_reason("executor", "missing_executable", retryable=False)
    classification = classify_failure(reason, attempt=1)
    assert classification.disposition == "capability_remediation"
    assert classification.remediation_task is True


def test_openrouter_budget_persists_and_records_after_authorization(tmp_path: Path) -> None:
    ledger_path = tmp_path / "openrouter-budget-ledger.json"
    limits = BudgetLimits(per_run_usd=Decimal("1.00"), monthly_usd=Decimal("10.00"))
    guard = OpenRouterBudgetGuard(limits, ledger_path=ledger_path)
    authorization = guard.authorize_fallback(
        run_id="run-1",
        reason="explicit-test",
        estimated_cost_usd=Decimal("0.25"),
        explicit_fallback=True,
    )
    assert guard.ledger.spent_for_run("run-1") == Decimal("0")
    guard.record_spend(authorization)
    assert ledger_path.is_file()
    reloaded = OpenRouterBudgetGuard(limits, ledger_path=ledger_path)
    assert reloaded.ledger.spent_for_run("run-1") == Decimal("0.25")


def test_writing_lease_persists_across_transport_instances(tmp_path: Path) -> None:
    transport_a = WorktreeTransport(mirror_root=tmp_path / "mirror", repo_name="demo")
    transport_b = WorktreeTransport(mirror_root=tmp_path / "mirror", repo_name="demo")
    transport_a.acquire_writing_lease("worker-1")
    with pytest.raises(WritingLeaseRequiredError):
        transport_b.acquire_writing_lease("worker-2")
    transport_a.release_writing_lease("worker-1")
    transport_b.acquire_writing_lease("worker-2")


def test_cli_adapter_resume_writes_checkpoint_and_executes(tmp_path: Path) -> None:
    exe = tmp_path / "claude"
    exe.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"type":"assistant","message":{"content":"{}"}}\'\n')
    exe.chmod(0o700)
    adapter = CliHarnessAdapter(
        adapter_id="claude",
        kind="claude_cli",
        executable=str(exe),
        model="m",
        provider="p",
        credential_env=(),
        timeout_seconds=5,
        allowed_cwd_roots=(str(tmp_path),),
        runner=SubprocessRunner(artifact_dir=tmp_path / "out", allowlisted_env=()),
    )
    request = HarnessRequest(
        "r", "t", "a", "o", "prompt", str(tmp_path), 5, {"type": "object"}, (), str(tmp_path / "out"), {}
    )
    result = adapter.resume(request, "session-123")
    assert result.status == "success"
    assert (tmp_path / "out" / "harness-session.json").is_file()




def test_requirements_include_pyyaml() -> None:
    requirements = (Path(__file__).resolve().parents[1] / "controller" / "requirements.txt").read_text()
    assert "PyYAML" in requirements


def test_migration_authorization_doc_exists() -> None:
    doc = Path(__file__).resolve().parents[1] / "controller" / "migrations" / "MIGRATION_AUTHORIZATION.md"
    assert doc.is_file()
    text = doc.read_text()
    assert "010" in text and "013" in text
