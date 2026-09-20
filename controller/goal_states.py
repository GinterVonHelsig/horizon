"""Durable goal and task states for run-until-goal orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

ACTIVE: Final = "ACTIVE"
WAITING_DEPENDENCY: Final = "WAITING_DEPENDENCY"
WAITING_OPERATOR: Final = "WAITING_OPERATOR"
RETRY_QUEUE: Final = "RETRY_QUEUE"
HARD_BLOCKED_PATH: Final = "HARD_BLOCKED_PATH"
COMPLETE_WITH_RESIDUALS: Final = "COMPLETE_WITH_RESIDUALS"
COMPLETE: Final = "COMPLETE"

GOAL_STATES: frozenset[str] = frozenset(
    {
        ACTIVE,
        WAITING_DEPENDENCY,
        WAITING_OPERATOR,
        RETRY_QUEUE,
        HARD_BLOCKED_PATH,
        COMPLETE_WITH_RESIDUALS,
        COMPLETE,
    }
)

TERMINAL_GOAL_STATES: frozenset[str] = frozenset({COMPLETE_WITH_RESIDUALS, COMPLETE})


@dataclass(frozen=True)
class GoalStateTransition:
    previous_state: str
    next_state: str
    reason: str


def validate_goal_state(state: str) -> str:
    if state not in GOAL_STATES:
        raise ValueError(f"unknown goal state: {state}")
    return state


def transition_for_failure(
    current_state: str,
    *,
    disposition: str,
    pause_whole_goal: bool,
) -> GoalStateTransition:
    validate_goal_state(current_state)
    if current_state in TERMINAL_GOAL_STATES:
        raise ValueError("terminal goal states cannot transition")

    if disposition == "park_operator":
        return GoalStateTransition(current_state, WAITING_OPERATOR, "parked_for_operator")
    if disposition == "capability_remediation":
        return GoalStateTransition(current_state, WAITING_OPERATOR, "capability_remediation")
    if disposition == "pause_goal":
        return GoalStateTransition(current_state, WAITING_OPERATOR, "goal_paused_for_safety")
    if disposition == "hard_block_path":
        if pause_whole_goal:
            return GoalStateTransition(current_state, WAITING_OPERATOR, "goal_paused_for_safety")
        return GoalStateTransition(current_state, HARD_BLOCKED_PATH, "path_blocked_independent_work_continues")
    if disposition == "queueable":
        return GoalStateTransition(current_state, RETRY_QUEUE, "queueable_failure")
    raise ValueError(f"unknown failure disposition: {disposition}")


def transition_for_dependency_wait(current_state: str) -> GoalStateTransition:
    validate_goal_state(current_state)
    if current_state in TERMINAL_GOAL_STATES:
        raise ValueError("terminal goal states cannot transition")
    return GoalStateTransition(current_state, WAITING_DEPENDENCY, "waiting_on_dependency")


def transition_for_completion(
    current_state: str,
    *,
    has_residuals: bool,
) -> GoalStateTransition:
    validate_goal_state(current_state)
    if current_state in TERMINAL_GOAL_STATES:
        raise ValueError("terminal goal states cannot transition")
    next_state = COMPLETE_WITH_RESIDUALS if has_residuals else COMPLETE
    return GoalStateTransition(current_state, next_state, "goal_completed")


def transition_from_retry_queue(current_state: str) -> GoalStateTransition:
    validate_goal_state(current_state)
    if current_state != RETRY_QUEUE:
        raise ValueError("retry resume requires RETRY_QUEUE")
    return GoalStateTransition(current_state, ACTIVE, "retry_resumed")
