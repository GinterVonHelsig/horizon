"""Tests for goal runner orchestration."""

from __future__ import annotations

from decimal import Decimal

import pytest

from goal_runner import GoalRunner, GoalSnapshot, TaskSnapshot
from goal_states import ACTIVE, HARD_BLOCKED_PATH, RETRY_QUEUE, WAITING_OPERATOR
from openrouter_budget import BudgetLimits, OpenRouterBudgetGuard, SilentFallbackError


def test_missing_credential_parks_task_and_keeps_parent_alive() -> None:
    runner = GoalRunner()
    goal = GoalSnapshot(run_id="run-1", state=ACTIVE)
    task = TaskSnapshot(task_id="task-1", path_id="path-1", attempt=1)
    decision = runner.handle_task_failure(goal, task, "missing_credential:CODEX_HOME")
    runner.apply_decision(goal, decision)
    assert decision.task_state == "parked"
    assert decision.signal_projection is not None
    assert decision.signal_projection.readiness == "parked"
    assert goal.state == WAITING_OPERATOR
    assert goal.service_alive is True


def test_hard_safety_failure_blocks_path_only() -> None:
    runner = GoalRunner()
    goal = GoalSnapshot(run_id="run-1", state=ACTIVE, active_paths={"path-1", "path-2"})
    task = TaskSnapshot(task_id="task-1", path_id="path-1", attempt=1)
    decision = runner.handle_task_failure(goal, task, "integrity_failure:checksum")
    runner.apply_decision(goal, decision)
    assert decision.classification.disposition == "hard_block_path"
    assert goal.state == HARD_BLOCKED_PATH
    assert "path-1" in goal.blocked_paths


def test_queueable_failure_queues_retry_with_backoff() -> None:
    runner = GoalRunner()
    goal = GoalSnapshot(run_id="run-1", state=ACTIVE)
    task = TaskSnapshot(task_id="task-1", path_id="path-1", attempt=2)
    decision = runner.handle_task_failure(goal, task, "test_failure:unit")
    runner.apply_decision(goal, decision)
    assert decision.task_state == RETRY_QUEUE
    assert decision.retry_delay_seconds is not None
    assert goal.state == RETRY_QUEUE


def test_openrouter_guard_integration() -> None:
    guard = OpenRouterBudgetGuard(BudgetLimits(per_run_usd=Decimal("3"), monthly_usd=Decimal("30")))
    runner = GoalRunner(budget_guard=guard)
    with pytest.raises(SilentFallbackError):
        runner.authorize_openrouter_fallback(
            run_id="run-1",
            reason="provider-limit",
            estimated_cost_usd=Decimal("1"),
            explicit_fallback=False,
        )
