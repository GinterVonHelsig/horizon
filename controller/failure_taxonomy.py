"""Retry versus hard-block failure taxonomy with bounded backoff."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

QUEUEABLE_FAILURE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "provider_limit",
        "missing_dependency",
        "child_crash",
        "test_failure",
        "browser_retry",
        "git_transport_failure",
        "temporary_auth_expiry",
    }
)

GOAL_PAUSE_FAILURE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "wrong_target",
        "credential_exposure",
        "ambiguous_consequential_side_effect",
        "data_loss_risk",
        "failed_rollback",
        "authority_violation",
    }
)

PARK_OPERATOR_FAILURE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "missing_credential",
        "human_decision_required",
    }
)

CAPABILITY_REMEDIATION_KINDS: Final[frozenset[str]] = frozenset(
    {
        "harness_cli_unavailable",
    }
)

MAX_BACKOFF_SECONDS: Final = 3600
BASE_BACKOFF_SECONDS: Final = 5


@dataclass(frozen=True)
class FailureClassification:
    kind: str
    disposition: str
    retry_delay_seconds: int | None = None
    remediation_task: bool = False


def bounded_backoff_seconds(attempt: int) -> int:
    if attempt < 1:
        raise ValueError("attempt must be positive")
    delay = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
    return min(MAX_BACKOFF_SECONDS, delay)


def classify_failure(reason: str, *, attempt: int = 1) -> FailureClassification:
    if not reason:
        raise ValueError("failure reason is required")
    kind = reason.split(":", 1)[0]
    if kind in PARK_OPERATOR_FAILURE_KINDS:
        return FailureClassification(kind=kind, disposition="park_operator")
    if kind in GOAL_PAUSE_FAILURE_KINDS:
        return FailureClassification(kind=kind, disposition="pause_goal")
    if kind in CAPABILITY_REMEDIATION_KINDS:
        return FailureClassification(
            kind=kind,
            disposition="capability_remediation",
            remediation_task=True,
        )
    if kind in QUEUEABLE_FAILURE_KINDS:
        return FailureClassification(
            kind=kind,
            disposition="queueable",
            retry_delay_seconds=bounded_backoff_seconds(attempt),
            remediation_task=True,
        )
    return FailureClassification(kind=kind, disposition="hard_block_path")


def is_whole_goal_pause(classification: FailureClassification) -> bool:
    return classification.disposition == "pause_goal"


_HARNESS_KIND_MAP: dict[str, str] = {
    "rate_limit": "provider_limit",
    "transport_failure": "git_transport_failure",
    "timeout": "provider_limit",
    "malformed_structured_output": "test_failure",
    "process_failure": "child_crash",
    "cancelled": "child_crash",
    "missing_executable": "harness_cli_unavailable",
    "authority_failure": "authority_violation",
    "wrong_target": "wrong_target",
    "credential_exposure": "credential_exposure",
    "integrity_failure": "integrity_failure",
    "configuration_failure": "configuration_failure",
    "endpoint_not_allowed": "endpoint_not_allowed",
}


def harness_failure_reason(role: str, classification: str, *, retryable: bool = False) -> str:
    if classification == "auth_failure":
        kind = "temporary_auth_expiry" if retryable else "missing_credential"
    else:
        kind = _HARNESS_KIND_MAP.get(classification, classification)
    return f"{kind}:{role}:{classification}"
