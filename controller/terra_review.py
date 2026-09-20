"""Out-of-band Terra review authority; separate from the Longspan execution workflow."""

from __future__ import annotations

from pathlib import Path

from longspan_repository import LongspanRepository
from parent_controller import ParentController, generation_for_fence_token
from provenance import capture_run_provenance, reject_provenance_drift
from exceptions import StaleFenceError
from terra_receipt_attestation import TerraReceiptSigner


class TerraReviewAuthority:
    """Holds the Terra review credential; only this component may write terra receipts."""

    def __init__(
        self,
        auth_token: str,
        *,
        repo_root: Path | None = None,
        signer: TerraReceiptSigner,
    ) -> None:
        if not auth_token:
            raise ValueError("terra review auth token is required")
        self._auth_token = auth_token
        self._repo_root = repo_root or Path(__file__).resolve().parents[1]
        self._signer = signer

    def register_receipt(
        self,
        repo: LongspanRepository,
        parent: ParentController,
        *,
        child_id: str,
        reviewer: str,
        decision: str,
        evidence_chain_head: str,
    ) -> dict:
        child = repo.get_child(child_id)
        attempt_number = int(child["attempt_number"])
        run_id = child["run_id"]
        parent_task = parent.task(child["task_id"])
        expected_generation = generation_for_fence_token(int(child["fence_token"]))
        if parent_task.generation != expected_generation:
            raise StaleFenceError("terra receipt parent generation is stale")
        resolved_parent_attempt_id, resolved_fence_token = parent.resolve_parent_attempt(
            child["task_id"], parent_task.generation
        )
        if resolved_parent_attempt_id != child["parent_attempt_id"]:
            raise StaleFenceError("terra receipt parent attempt is stale")
        authority = repo.get_authority_config(run_id)
        auditor = repo.get_auditor_receipt(child_id, attempt_number)
        execution = repo.get_execution_result(child_id, attempt_number)
        captured = capture_run_provenance(
            self._repo_root,
            reviewed_sha=authority["reviewed_sha"],
            db_url=repo.repo.db_url,
        )
        reject_provenance_drift(
            captured=captured,
            reviewed_sha=authority["reviewed_sha"],
            tree_sha=authority["tree_sha"],
            source_digest=authority["source_digest"],
            migration_revision=captured.migration_revision,
        )
        epoch = parent.controller_epoch(run_id)
        receipt_payload = {
            "child_id": child_id,
            "attempt_number": attempt_number,
            "reviewer": reviewer,
            "decision": decision,
            "evidence_chain_head": evidence_chain_head,
            "run_id": run_id,
            "task_id": child["task_id"],
            "reviewed_sha": authority["reviewed_sha"],
            "fence_token": int(child["fence_token"]),
            "controller_epoch": epoch,
            "tree_sha": authority["tree_sha"],
            "source_digest": authority["source_digest"],
            "request_digest": child["request_digest"],
            "migration_head": captured.migration_head,
            "authority_version": int(authority["config_version"]),
            "evidence_digest": auditor["evidence_digest"],
            "result_digest": execution["result_digest"],
        }
        authority_signature = self._signer.sign(receipt_payload)
        return repo.store_terra_receipt(
            child_id=child_id,
            expected_version=int(child["version"]),
            attempt_number=attempt_number,
            reviewer=reviewer,
            decision=decision,
            evidence_chain_head=evidence_chain_head,
            terra_auth_token=self._auth_token,
            parent_attempt_id=resolved_parent_attempt_id,
            fence_token=resolved_fence_token,
            controller_epoch=epoch,
            run_id=run_id,
            authority_signature=authority_signature,
        )
