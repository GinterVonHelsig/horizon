"""Tests for failure taxonomy and bounded backoff."""

from __future__ import annotations

import pytest

from failure_taxonomy import (
    MAX_BACKOFF_SECONDS,
    bounded_backoff_seconds,
    classify_failure,
)


def test_queueable_failure_creates_remediation_with_bounded_backoff() -> None:
    classification = classify_failure("provider_limit:429", attempt=3)
    assert classification.disposition == "queueable"
    assert classification.remediation_task is True
    assert classification.retry_delay_seconds == bounded_backoff_seconds(3)
    assert classification.retry_delay_seconds <= MAX_BACKOFF_SECONDS


def test_hard_safety_failure_blocks_only_path() -> None:
    classification = classify_failure("integrity_failure:checksum")
    assert classification.disposition == "hard_block_path"


def test_goal_pause_failures_are_classified() -> None:
    classification = classify_failure("wrong_target:comms-01")
    assert classification.disposition == "pause_goal"


def test_missing_credential_parks_for_operator() -> None:
    classification = classify_failure("missing_credential:OPENROUTER_API_KEY")
    assert classification.disposition == "park_operator"
    assert classification.retry_delay_seconds is None
