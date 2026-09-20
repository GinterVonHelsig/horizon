"""Tests for deterministic Terra release policy receipts."""

from __future__ import annotations

import pytest

from operator_asymmetric import generate_keypair
from terra_release_policy import (
    ReleasePolicyInput,
    ReleasePolicyViolation,
    issue_authoritative_receipt,
    verify_release_policy_receipt,
)


def _sample_input(**overrides: object) -> ReleasePolicyInput:
    payload = {
        "run_id": "run-1",
        "task_id": "task-1",
        "base_sha": "a" * 40,
        "candidate_sha": "b" * 40,
        "tree_sha": "c" * 40,
        "reviewed_sha": "b" * 40,
        "backup_manifest_sha256": "d" * 64,
        "rollback_plan_sha256": "e" * 64,
        "broker_safety": "flat",
        "database_safety": "verified",
        "scope_envelope_sha256": "f" * 64,
    }
    payload.update(overrides)
    return ReleasePolicyInput(**payload)


def test_terra_policy_receipt_is_authoritative_without_paid_model_call() -> None:
    private_key, public_key = generate_keypair()
    receipt = issue_authoritative_receipt(_sample_input(), private_key_b64=private_key)
    assert receipt.to_dict()["authoritative"] is True
    assert receipt.to_dict()["paid_model_call_required"] is False
    assert verify_release_policy_receipt(receipt, public_key_b64=public_key)


def test_terra_policy_rejects_missing_backup() -> None:
  private_key, _ = generate_keypair()
  with pytest.raises(ReleasePolicyViolation, match="backup"):
      issue_authoritative_receipt(
          _sample_input(backup_manifest_sha256=""),
          private_key_b64=private_key,
      )
