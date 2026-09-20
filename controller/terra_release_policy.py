"""Deterministic Terra release-policy checks and signed receipts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from operator_asymmetric import sign_message, verify_message_signature

POLICY_SCHEMA = "top-delivery/terra-release-policy/v1"

_REQUIRED_POLICY_FIELDS = (
    "schema",
    "run_id",
    "task_id",
    "base_sha",
    "candidate_sha",
    "tree_sha",
    "reviewed_sha",
    "backup_manifest_sha256",
    "rollback_plan_sha256",
    "broker_safety",
    "database_safety",
    "scope_envelope_sha256",
    "decision",
)


@dataclass(frozen=True)
class ReleasePolicyInput:
    run_id: str
    task_id: str
    base_sha: str
    candidate_sha: str
    tree_sha: str
    reviewed_sha: str
    backup_manifest_sha256: str
    rollback_plan_sha256: str
    broker_safety: str
    database_safety: str
    scope_envelope_sha256: str


@dataclass(frozen=True)
class ReleasePolicyReceipt:
    payload: dict[str, Any]
    policy_digest: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "policy_digest": self.policy_digest,
            "signature": self.signature,
            "authoritative": True,
            "paid_model_call_required": False,
        }


class ReleasePolicyViolation(ValueError):
    pass


def _policy_message(payload: dict[str, Any]) -> str:
    ordered = {field: payload[field] for field in _REQUIRED_POLICY_FIELDS}
    return json.dumps(ordered, sort_keys=True, separators=(",", ":"))


def evaluate_release_policy(policy_input: ReleasePolicyInput) -> dict[str, Any]:
    if policy_input.reviewed_sha != policy_input.candidate_sha:
        raise ReleasePolicyViolation("reviewed_sha must match candidate_sha")
    if policy_input.base_sha == policy_input.candidate_sha:
        raise ReleasePolicyViolation("candidate must advance beyond base_sha")
    if policy_input.broker_safety != "flat":
        raise ReleasePolicyViolation("broker safety gate failed")
    if policy_input.database_safety != "verified":
        raise ReleasePolicyViolation("database safety gate failed")
    if not policy_input.backup_manifest_sha256:
        raise ReleasePolicyViolation("backup manifest is required")
    if not policy_input.rollback_plan_sha256:
        raise ReleasePolicyViolation("rollback plan is required")

    return {
        "schema": POLICY_SCHEMA,
        "run_id": policy_input.run_id,
        "task_id": policy_input.task_id,
        "base_sha": policy_input.base_sha,
        "candidate_sha": policy_input.candidate_sha,
        "tree_sha": policy_input.tree_sha,
        "reviewed_sha": policy_input.reviewed_sha,
        "backup_manifest_sha256": policy_input.backup_manifest_sha256,
        "rollback_plan_sha256": policy_input.rollback_plan_sha256,
        "broker_safety": policy_input.broker_safety,
        "database_safety": policy_input.database_safety,
        "scope_envelope_sha256": policy_input.scope_envelope_sha256,
        "decision": "approve",
    }


def sign_release_policy_receipt(
    payload: dict[str, Any],
    *,
    private_key_b64: str,
) -> ReleasePolicyReceipt:
    missing = [field for field in _REQUIRED_POLICY_FIELDS if field not in payload]
    if missing:
        raise ReleasePolicyViolation("policy payload missing: " + ", ".join(missing))
    message = _policy_message(payload)
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    signature = sign_message(message, private_key_b64)
    return ReleasePolicyReceipt(payload=payload, policy_digest=digest, signature=signature)


def verify_release_policy_receipt(
    receipt: ReleasePolicyReceipt,
    *,
    public_key_b64: str,
) -> bool:
    message = _policy_message(receipt.payload)
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    if digest != receipt.policy_digest:
        return False
    return verify_message_signature(message, receipt.signature, public_key_b64)


def issue_authoritative_receipt(
    policy_input: ReleasePolicyInput,
    *,
    private_key_b64: str,
) -> ReleasePolicyReceipt:
    payload = evaluate_release_policy(policy_input)
    return sign_release_policy_receipt(payload, private_key_b64=private_key_b64)
