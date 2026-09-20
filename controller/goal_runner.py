"""Run-until-goal orchestration across taxonomy, states, budgets, and transport."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from failure_taxonomy import FailureClassification, classify_failure, is_whole_goal_pause
from goal_states import (
    ACTIVE,
    RETRY_QUEUE,
    WAITING_OPERATOR,
    GoalStateTransition,
    transition_for_failure,
    validate_goal_state,
)
from openrouter_budget import FallbackAuthorization, OpenRouterBudgetGuard, SilentFallbackError
from signal_status import SignalStatusProjection, SignalStatusReader


@dataclass
class TaskSnapshot:
    task_id: str
    path_id: str
    attempt: int = 1
    state: str = "scheduled"


@dataclass
class GoalSnapshot:
    run_id: str
    state: str = ACTIVE
    active_paths: set[str] = field(default_factory=set)
    blocked_paths: set[str] = field(default_factory=set)
    service_alive: bool = True


@dataclass(frozen=True)
class GoalRunDecision:
    goal_transition: GoalStateTransition | None
    task_state: str
    classification: FailureClassification
    retry_delay_seconds: int | None = None
    signal_projection: SignalStatusProjection | None = None
    remediation_task: bool = False


class GoalRunner:
    """Classify failures, update durable goal state, and preserve parent uptime."""

    def __init__(
        self,
        *,
        signal_reader: SignalStatusReader | None = None,
        budget_guard: OpenRouterBudgetGuard | None = None,
    ) -> None:
        self._signal = signal_reader or SignalStatusReader()
        self._budget_guard = budget_guard

    def handle_task_failure(
        self,
        goal: GoalSnapshot,
        task: TaskSnapshot,
        reason: str,
    ) -> GoalRunDecision:
        if not goal.service_alive:
            raise RuntimeError("parent service is not alive")
        validate_goal_state(goal.state)
        classification = classify_failure(reason, attempt=task.attempt)
        pause_whole_goal = is_whole_goal_pause(classification)
        transition = transition_for_failure(
            goal.state,
            disposition=classification.disposition,
            pause_whole_goal=pause_whole_goal,
        )

        if classification.disposition == "park_operator":
            projection = self._signal.project(
                run_id=goal.run_id,
                readiness="parked",
                blockers=(reason,),
                last_event_seq=task.attempt,
                task_summary={"task_id": task.task_id, "state": "parked"},
            )
            return GoalRunDecision(
                goal_transition=transition,
                task_state="parked",
                classification=classification,
                signal_projection=projection,
            )

        if classification.disposition == "capability_remediation":
            projection = self._signal.project(
                run_id=goal.run_id,
                readiness="parked",
                blockers=(reason,),
                last_event_seq=task.attempt,
                task_summary={
                    "task_id": task.task_id,
                    "state": "parked",
                    "remediation": "CAPABILITY_REMEDIATION",
                },
            )
            return GoalRunDecision(
                goal_transition=transition,
                task_state="parked",
                classification=classification,
                signal_projection=projection,
                remediation_task=True,
            )

        if classification.disposition == "queueable":
            return GoalRunDecision(
                goal_transition=transition,
                task_state=RETRY_QUEUE,
                classification=classification,
                retry_delay_seconds=classification.retry_delay_seconds,
                remediation_task=classification.remediation_task,
            )

        if classification.disposition == "hard_block_path":
            goal.blocked_paths.add(task.path_id)
            return GoalRunDecision(
                goal_transition=transition,
                task_state="blocked",
                classification=classification,
            )

        projection = self._signal.project(
            run_id=goal.run_id,
            readiness="paused",
            blockers=(reason,),
            last_event_seq=task.attempt,
            task_summary={"task_id": task.task_id, "state": WAITING_OPERATOR},
        )
        return GoalRunDecision(
            goal_transition=transition,
            task_state=WAITING_OPERATOR,
            classification=classification,
            signal_projection=projection,
        )

    def authorize_openrouter_fallback(
        self,
        *,
        run_id: str,
        reason: str,
        estimated_cost_usd: Decimal,
        explicit_fallback: bool,
    ) -> FallbackAuthorization:
        if self._budget_guard is None:
            raise ValueError("OpenRouter budget guard is not configured")
        return self._budget_guard.authorize_fallback(
            run_id=run_id,
            reason=reason,
            estimated_cost_usd=estimated_cost_usd,
            explicit_fallback=explicit_fallback,
        )

    def apply_decision(self, goal: GoalSnapshot, decision: GoalRunDecision) -> None:
        if decision.goal_transition is not None:
            goal.state = decision.goal_transition.next_state
        goal.service_alive = True

    def ensure_no_silent_openrouter(self, *, explicit_fallback: bool) -> None:
        if not explicit_fallback:
            raise SilentFallbackError("OpenRouter fallback requires explicit budget approval")
