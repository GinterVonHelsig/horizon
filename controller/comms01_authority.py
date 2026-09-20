"""Comms-01 authorization boundary client for Longspan authority provisioning and rotation."""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from authority_pins import CURRENT_OPERATOR_KEY_VERSION
from authority_service_client import AuthorityServiceReceipt, request_authority_operation, verify_authority_service_receipt
from comms01_authority_secrets import operator_verification_key
from comms01_scope import assert_comms01_entrypoint
from exceptions import AuthorizationFailureError
from longspan_crypto import (
    digest_payload,
    hash_capability_token,
    sign_payload,
    verify_capability_hash,
    verify_payload_signature,
)
from longspan_repository import LongspanRepository
from operator_asymmetric import challenge_signing_message, verify_message_signature
from provenance import capture_run_provenance, reject_provenance_drift

DEFAULT_CHALLENGE_TTL_SECONDS = 300


@dataclass(frozen=True)
class AuthorityApprovalReceipt:
    receipt_id: str
    run_id: str
    task_id: str | None
    child_id: str | None
    attempt_number: int | None
    fence_token: int | None
    controller_epoch: int
    evidence_chain_head: str | None
    reviewed_sha: str
    tree_sha: str
    source_digest: str
    config_version: int
    decision: str
    approval_identity: str
    signature: str
    digest: str


@dataclass(frozen=True)
class OperatorTwoFactorChallenge:
    approval_id: str
    operator_identity: str
    action_type: str
    action_digest: str
    run_id: str
    nonce: str
    expires_at: str
    key_version: int
    controller_epoch: int
    config_version: int
    challenge_epoch: int
    challenge_digest: str


@dataclass(frozen=True)
class ExternalOperatorApprovalReceipt:
    approval_id: str
    operator_identity: str
    nonce: str
    expires_at: str
    action_type: str
    action_digest: str
    run_id: str
    key_version: int
    controller_epoch: int
    config_version: int
    signature: str


def _challenge_payload(
    *,
    approval_id: str,
    operator_identity: str,
    action_type: str,
    action_digest: str,
    run_id: str,
    nonce: str,
    expires_at: str,
    key_version: int,
    controller_epoch: int,
    config_version: int,
    challenge_epoch: int,
) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "operator_identity": operator_identity,
        "action_type": action_type,
        "action_digest": action_digest,
        "run_id": run_id,
        "nonce": nonce,
        "expires_at": expires_at,
        "key_version": key_version,
        "controller_epoch": controller_epoch,
        "config_version": config_version,
        "challenge_epoch": challenge_epoch,
    }


def _challenge_digest_from_payload(payload: dict[str, Any]) -> str:
    return digest_payload(payload)


def _verify_external_operator_receipt(
    *,
    receipt: ExternalOperatorApprovalReceipt,
    expected_action_digest: str,
    expected_action_type: str,
    expected_run_id: str,
    expected_operator_identity: str,
    expected_controller_epoch: int,
    expected_config_version: int,
    expected_challenge_epoch: int,
) -> None:
    if receipt.operator_identity != expected_operator_identity:
        raise AuthorizationFailureError("operator approval identity mismatch")
    if receipt.action_type != expected_action_type:
        raise AuthorizationFailureError("operator approval action type mismatch")
    if receipt.action_digest != expected_action_digest:
        raise AuthorizationFailureError("operator approval action digest mismatch")
    if receipt.run_id != expected_run_id:
        raise AuthorizationFailureError("operator approval run binding mismatch")
    if receipt.key_version != CURRENT_OPERATOR_KEY_VERSION:
        raise AuthorizationFailureError("operator approval key version mismatch")
    if receipt.controller_epoch != expected_controller_epoch:
        raise AuthorizationFailureError("operator approval controller epoch mismatch")
    if receipt.config_version != expected_config_version:
        raise AuthorizationFailureError("operator approval config version mismatch")
    expires = datetime.fromisoformat(receipt.expires_at)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires.timestamp() <= datetime.now(timezone.utc).timestamp():
        raise AuthorizationFailureError("operator approval receipt expired")
    payload = _challenge_payload(
        approval_id=receipt.approval_id,
        operator_identity=receipt.operator_identity,
        action_type=receipt.action_type,
        action_digest=receipt.action_digest,
        run_id=receipt.run_id,
        nonce=receipt.nonce,
        expires_at=receipt.expires_at,
        key_version=CURRENT_OPERATOR_KEY_VERSION,
        controller_epoch=receipt.controller_epoch,
        config_version=receipt.config_version,
        challenge_epoch=expected_challenge_epoch,
    )
    signing_message = challenge_signing_message(payload)
    public_key = operator_verification_key()
    if not verify_message_signature(signing_message, receipt.signature, public_key):
        raise AuthorizationFailureError("operator approval signature is invalid")


def verify_external_operator_approval_receipt(
    *,
    receipt: ExternalOperatorApprovalReceipt,
    expected_action_digest: str,
    expected_action_type: str,
    expected_run_id: str,
    expected_operator_identity: str,
    expected_controller_epoch: int,
    expected_config_version: int,
    expected_challenge_epoch: int,
) -> None:
    """Public verification seam for side-effect operation preflight gates."""
    _verify_external_operator_receipt(
        receipt=receipt,
        expected_action_digest=expected_action_digest,
        expected_action_type=expected_action_type,
        expected_run_id=expected_run_id,
        expected_operator_identity=expected_operator_identity,
        expected_controller_epoch=expected_controller_epoch,
        expected_config_version=expected_config_version,
        expected_challenge_epoch=expected_challenge_epoch,
    )


class Comms01AuthorityBoundary:
    """External operator/Terra authorization client; not callable from Manager/Executor workflow."""

    def __init__(self, repo: LongspanRepository, *, repo_root: Path | None = None) -> None:
        self._repo = repo
        self._repo_root = repo_root or Path(__file__).resolve().parents[1]

    def _capture_and_reject_provenance_drift(
        self,
        *,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
    ) -> None:
        captured = capture_run_provenance(
            self._repo_root,
            reviewed_sha=reviewed_sha,
            db_url=self._repo.repo.db_url,
        )
        reject_provenance_drift(
            captured=captured,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            migration_revision=captured.migration_revision,
        )

    def issue_operator_2fa_challenge(
        self,
        *,
        run_id: str,
        action_type: str,
        action_digest: str,
        operator_identity: str,
        controller_epoch: int,
        approval_id: str | None = None,
        config_version: int = 1,
        challenge_epoch: int | None = None,
        ttl_seconds: int = DEFAULT_CHALLENGE_TTL_SECONDS,
    ) -> OperatorTwoFactorChallenge:
        assert_comms01_entrypoint(scope="comms-01")
        approval_id = approval_id or uuid.uuid4().hex
        nonce = secrets.token_hex(16)
        challenge_epoch = challenge_epoch if challenge_epoch is not None else controller_epoch
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=max(30, ttl_seconds))
        ).isoformat()
        payload = _challenge_payload(
            approval_id=approval_id,
            operator_identity=operator_identity,
            action_type=action_type,
            action_digest=action_digest,
            run_id=run_id,
            nonce=nonce,
            expires_at=expires_at,
            key_version=CURRENT_OPERATOR_KEY_VERSION,
            controller_epoch=controller_epoch,
            config_version=config_version,
            challenge_epoch=challenge_epoch,
        )
        challenge_digest = _challenge_digest_from_payload(payload)
        self._repo.persist_operator_challenge(
            approval_id=approval_id,
            run_id=run_id,
            action_type=action_type,
            action_digest=action_digest,
            operator_identity=operator_identity,
            nonce=nonce,
            expires_at=expires_at,
            key_version=CURRENT_OPERATOR_KEY_VERSION,
            challenge_digest=challenge_digest,
            controller_epoch=controller_epoch,
            config_version=config_version,
            challenge_epoch=challenge_epoch,
        )
        return OperatorTwoFactorChallenge(
            approval_id=approval_id,
            operator_identity=operator_identity,
            action_type=action_type,
            action_digest=action_digest,
            run_id=run_id,
            nonce=nonce,
            expires_at=expires_at,
            key_version=CURRENT_OPERATOR_KEY_VERSION,
            controller_epoch=controller_epoch,
            config_version=config_version,
            challenge_epoch=challenge_epoch,
            challenge_digest=challenge_digest,
        )

    def _derive_initial_action_digest(
        self,
        *,
        run_id: str,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        terra_auth_token: str,
        operator_auth_token: str,
        operator_identity: str,
        controller_epoch: int,
    ) -> str:
        return digest_payload(
            {
                "action": "initial_provision",
                "run_id": run_id,
                "operator_identity": operator_identity,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "controller_epoch": controller_epoch,
                "config_version": 1,
                "terra_auth_hash": hash_capability_token(terra_auth_token),
                "operator_auth_hash": hash_capability_token(operator_auth_token),
            }
        )

    def _derive_rotation_action_digest(
        self,
        *,
        run_id: str,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        operator_identity: str,
        controller_epoch: int,
        next_config_version: int,
        new_terra_auth_token: str,
        new_operator_auth_token: str,
    ) -> str:
        return digest_payload(
            {
                "action": "rotate_authority",
                "run_id": run_id,
                "operator_identity": operator_identity,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "controller_epoch": controller_epoch,
                "config_version": next_config_version,
                "terra_auth_hash": hash_capability_token(new_terra_auth_token),
                "operator_auth_hash": hash_capability_token(new_operator_auth_token),
            }
        )

    def _operator_challenge_dict(
        self,
        *,
        receipt: ExternalOperatorApprovalReceipt,
        action_type: str,
        action_digest: str,
        run_id: str,
        operator_identity: str,
        controller_epoch: int,
        config_version: int,
        challenge_epoch: int,
    ) -> dict[str, Any]:
        payload = _challenge_payload(
            approval_id=receipt.approval_id,
            operator_identity=operator_identity,
            action_type=action_type,
            action_digest=action_digest,
            run_id=run_id,
            nonce=receipt.nonce,
            expires_at=receipt.expires_at,
            key_version=CURRENT_OPERATOR_KEY_VERSION,
            controller_epoch=controller_epoch,
            config_version=config_version,
            challenge_epoch=challenge_epoch,
        )
        return {
            "approval_id": receipt.approval_id,
            "run_id": run_id,
            "action_type": action_type,
            "action_digest": action_digest,
            "operator_identity": operator_identity,
            "nonce": receipt.nonce,
            "expires_at": receipt.expires_at,
            "key_version": CURRENT_OPERATOR_KEY_VERSION,
            "controller_epoch": controller_epoch,
            "config_version": config_version,
            "challenge_epoch": challenge_epoch,
            "challenge_digest": _challenge_digest_from_payload(payload),
        }

    def _receipt_to_service_payload(self, receipt: ExternalOperatorApprovalReceipt) -> dict[str, Any]:
        return {
            "approval_id": receipt.approval_id,
            "operator_identity": receipt.operator_identity,
            "nonce": receipt.nonce,
            "expires_at": receipt.expires_at,
            "action_type": receipt.action_type,
            "action_digest": receipt.action_digest,
            "run_id": receipt.run_id,
            "key_version": CURRENT_OPERATOR_KEY_VERSION,
            "controller_epoch": receipt.controller_epoch,
            "config_version": receipt.config_version,
            "signature": receipt.signature,
        }

    def initial_provision(
        self,
        *,
        run_id: str,
        terra_auth_token: str,
        operator_auth_token: str,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        controller_epoch: int,
        operator_identity: str,
        operator_approval_receipt: ExternalOperatorApprovalReceipt,
    ) -> dict[str, Any]:
        assert_comms01_entrypoint(scope="comms-01")
        if not tree_sha or not source_digest:
            raise ValueError("tree_sha and source_digest are required")
        self._capture_and_reject_provenance_drift(
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
        )
        action_digest = self._derive_initial_action_digest(
            run_id=run_id,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            terra_auth_token=terra_auth_token,
            operator_auth_token=operator_auth_token,
            operator_identity=operator_identity,
            controller_epoch=controller_epoch,
        )
        _verify_external_operator_receipt(
            receipt=operator_approval_receipt,
            expected_action_digest=action_digest,
            expected_action_type="initial_provision",
            expected_run_id=run_id,
            expected_operator_identity=operator_identity,
            expected_controller_epoch=controller_epoch,
            expected_config_version=1,
            expected_challenge_epoch=controller_epoch,
        )
        operator_challenge = self._operator_challenge_dict(
            receipt=operator_approval_receipt,
            action_type="initial_provision",
            action_digest=action_digest,
            run_id=run_id,
            operator_identity=operator_identity,
            controller_epoch=controller_epoch,
            config_version=1,
            challenge_epoch=controller_epoch,
        )
        service_receipt = request_authority_operation(
            operation="initial_provision",
            body={
                "run_id": run_id,
                "terra_auth_token": terra_auth_token,
                "operator_auth_token": operator_auth_token,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "controller_epoch": controller_epoch,
                "operator_identity": operator_identity,
                "operator_approval_receipt": self._receipt_to_service_payload(
                    operator_approval_receipt
                ),
                "operator_challenge": operator_challenge,
            },
        )
        return self._load_authority_result(
            run_id, service_receipt, approval_id=operator_approval_receipt.approval_id
        )

    def rotate_authority(
        self,
        *,
        run_id: str,
        existing_operator_auth_token: str,
        new_terra_auth_token: str,
        new_operator_auth_token: str,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        controller_epoch: int,
        operator_identity: str,
        operator_approval_receipt: ExternalOperatorApprovalReceipt,
    ) -> dict[str, Any]:
        assert_comms01_entrypoint(scope="comms-01")
        if not tree_sha or not source_digest:
            raise ValueError("tree_sha and source_digest are required")
        self._capture_and_reject_provenance_drift(
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
        )
        current = self._repo.get_authority_config(run_id)
        next_version = int(current["config_version"]) + 1
        action_digest = self._derive_rotation_action_digest(
            run_id=run_id,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            operator_identity=operator_identity,
            controller_epoch=controller_epoch,
            next_config_version=next_version,
            new_terra_auth_token=new_terra_auth_token,
            new_operator_auth_token=new_operator_auth_token,
        )
        _verify_external_operator_receipt(
            receipt=operator_approval_receipt,
            expected_action_digest=action_digest,
            expected_action_type="rotate_authority",
            expected_run_id=run_id,
            expected_operator_identity=operator_identity,
            expected_controller_epoch=controller_epoch,
            expected_config_version=next_version,
            expected_challenge_epoch=controller_epoch,
        )
        operator_challenge = self._operator_challenge_dict(
            receipt=operator_approval_receipt,
            action_type="rotate_authority",
            action_digest=action_digest,
            run_id=run_id,
            operator_identity=operator_identity,
            controller_epoch=controller_epoch,
            config_version=next_version,
            challenge_epoch=controller_epoch,
        )
        service_receipt = request_authority_operation(
            operation="rotate_authority",
            body={
                "run_id": run_id,
                "existing_operator_auth_token": existing_operator_auth_token,
                "new_terra_auth_token": new_terra_auth_token,
                "new_operator_auth_token": new_operator_auth_token,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "controller_epoch": controller_epoch,
                "operator_identity": operator_identity,
                "operator_approval_receipt": self._receipt_to_service_payload(
                    operator_approval_receipt
                ),
                "operator_challenge": operator_challenge,
            },
        )
        return self._load_authority_result(
            run_id, service_receipt, approval_id=operator_approval_receipt.approval_id
        )

    def _load_authority_result(
        self,
        run_id: str,
        service_receipt: AuthorityServiceReceipt,
        *,
        approval_id: str,
    ) -> dict[str, Any]:
        if service_receipt.run_id != run_id:
            raise AuthorizationFailureError("authority service receipt run binding mismatch")
        verify_authority_service_receipt(service_receipt, approval_id=approval_id)
        return self._repo.get_authority_config(run_id)

    def _receipt_digest_fields(
        self,
        *,
        receipt_id: str,
        run_id: str,
        task_id: str | None,
        child_id: str | None,
        attempt_number: int | None,
        fence_token: int | None,
        controller_epoch: int,
        evidence_chain_head: str | None,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        config_version: int,
        decision: str,
        approval_identity: str,
    ) -> str:
        return digest_payload(
            {
                "receipt_id": receipt_id,
                "run_id": run_id,
                "task_id": task_id,
                "child_id": child_id,
                "attempt_number": attempt_number,
                "fence_token": fence_token,
                "controller_epoch": controller_epoch,
                "evidence_chain_head": evidence_chain_head,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "config_version": config_version,
                "decision": decision,
                "approval_identity": approval_identity,
            }
        )

    def build_signed_receipt(
        self,
        *,
        run_id: str,
        task_id: str | None,
        child_id: str | None,
        attempt_number: int | None,
        fence_token: int | None,
        controller_epoch: int,
        evidence_chain_head: str | None,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        config_version: int,
        decision: str,
        approval_identity: str,
        signing_token: str,
    ) -> AuthorityApprovalReceipt:
        receipt_id = uuid.uuid4().hex
        digest = self._receipt_digest_fields(
            receipt_id=receipt_id,
            run_id=run_id,
            task_id=task_id,
            child_id=child_id,
            attempt_number=attempt_number,
            fence_token=fence_token,
            controller_epoch=controller_epoch,
            evidence_chain_head=evidence_chain_head,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            config_version=config_version,
            decision=decision,
            approval_identity=approval_identity,
        )
        signature = sign_payload(digest, signing_token)
        return AuthorityApprovalReceipt(
            receipt_id=receipt_id,
            run_id=run_id,
            task_id=task_id,
            child_id=child_id,
            attempt_number=attempt_number,
            fence_token=fence_token,
            controller_epoch=controller_epoch,
            evidence_chain_head=evidence_chain_head,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            config_version=config_version,
            decision=decision,
            approval_identity=approval_identity,
            signature=signature,
            digest=digest,
        )

    def verify_signed_receipt(
        self,
        receipt: AuthorityApprovalReceipt,
        *,
        signing_token_hash: str,
        signing_token: str,
        expected: dict[str, Any],
    ) -> None:
        if not verify_capability_hash(signing_token, signing_token_hash):
            raise AuthorizationFailureError("receipt signing token is not verified")
        for key, value in expected.items():
            if getattr(receipt, key) != value:
                raise AuthorizationFailureError(f"receipt binding mismatch for {key}")
        expected_digest = self._receipt_digest_fields(
            receipt_id=receipt.receipt_id,
            run_id=receipt.run_id,
            task_id=receipt.task_id,
            child_id=receipt.child_id,
            attempt_number=receipt.attempt_number,
            fence_token=receipt.fence_token,
            controller_epoch=receipt.controller_epoch,
            evidence_chain_head=receipt.evidence_chain_head,
            reviewed_sha=receipt.reviewed_sha,
            tree_sha=receipt.tree_sha,
            source_digest=receipt.source_digest,
            config_version=receipt.config_version,
            decision=receipt.decision,
            approval_identity=receipt.approval_identity,
        )
        if receipt.digest != expected_digest:
            raise AuthorizationFailureError("receipt digest is invalid")
        if not verify_payload_signature(receipt.digest, receipt.signature, signing_token):
            raise AuthorizationFailureError("receipt signature is invalid")

    def receipt_to_json(self, receipt: AuthorityApprovalReceipt) -> str:
        return json.dumps(
            {
                "receipt_id": receipt.receipt_id,
                "run_id": receipt.run_id,
                "task_id": receipt.task_id,
                "child_id": receipt.child_id,
                "attempt_number": receipt.attempt_number,
                "fence_token": receipt.fence_token,
                "controller_epoch": receipt.controller_epoch,
                "evidence_chain_head": receipt.evidence_chain_head,
                "reviewed_sha": receipt.reviewed_sha,
                "tree_sha": receipt.tree_sha,
                "source_digest": receipt.source_digest,
                "config_version": receipt.config_version,
                "decision": receipt.decision,
                "approval_identity": receipt.approval_identity,
                "signature": receipt.signature,
                "digest": receipt.digest,
            },
            sort_keys=True,
        )
