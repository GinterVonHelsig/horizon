"""Tests for durable goal state transitions."""

from __future__ import annotations

import pytest

from goal_states import (
    ACTIVE,
    COMPLETE,
    HARD_BLOCKED_PATH,
    RETRY_QUEUE,
    WAITING_OPERATOR,
    transition_for_failure,
)


def test_queueable_failure_moves_goal_to_retry_queue() -> None:
    transition = transition_for_failure(ACTIVE, disposition="queueable", pause_whole_goal=False)
    assert transition.next_state == RETRY_QUEUE


def test_hard_block_emits_hard_blocked_path_state() -> None:
    transition = transition_for_failure(ACTIVE, disposition="hard_block_path", pause_whole_goal=False)
    assert transition.next_state == HARD_BLOCKED_PATH


def test_goal_pause_moves_to_waiting_operator() -> None:
    transition = transition_for_failure(ACTIVE, disposition="pause_goal", pause_whole_goal=True)
    assert transition.next_state == WAITING_OPERATOR


def test_park_operator_moves_to_waiting_operator() -> None:
    transition = transition_for_failure(ACTIVE, disposition="park_operator", pause_whole_goal=False)
    assert transition.next_state == WAITING_OPERATOR


def test_terminal_states_reject_transitions() -> None:
    with pytest.raises(ValueError, match="terminal"):
        transition_for_failure(COMPLETE, disposition="queueable", pause_whole_goal=False)
