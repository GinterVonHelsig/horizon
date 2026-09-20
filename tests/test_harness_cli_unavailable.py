"""Tests for harness_cli_unavailable capability remediation taxonomy."""

from __future__ import annotations

from failure_taxonomy import classify_failure, harness_failure_reason


def test_harness_cli_unavailable_emits_capability_remediation() -> None:
    reason = harness_failure_reason("executor", "missing_executable", retryable=False)
    classification = classify_failure(reason, attempt=1)
    assert reason.startswith("harness_cli_unavailable:")
    assert classification.kind == "harness_cli_unavailable"
    assert classification.disposition == "capability_remediation"
    assert classification.retry_delay_seconds is None
    assert classification.remediation_task is True
