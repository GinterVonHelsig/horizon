"""Workflow guardrails; authority write credentials are not obtainable here."""

from __future__ import annotations

from comms01_authority_secrets import workflow_may_not_access_authority_secrets


def assert_workflow_cannot_access_authority_secrets() -> None:
    workflow_may_not_access_authority_secrets()
