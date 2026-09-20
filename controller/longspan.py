"""Longspan Manager, Executor, Auditor, and parent-integrated workflow."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from comms01_scope import assert_comms01_entrypoint
from authority_write_gate import assert_workflow_cannot_access_authority_secrets
from exceptions import (
    AuthorizationFailureError,
    IntegrityFailureError,
    LeaseExpiredError,
    ProvenanceMismatchError,
    SchedulingDisabledError,
    StaleAttemptError,
    StaleControllerEpochError,
    StaleFenceError,
)
from longspan_crypto import (
    canonical_evidence_document,
    canonical_evidence_digest,
    deep_copy_evidence,
    digest_payload,
    issue_capability_token,
)
from longspan_repository import LongspanRepository
from parent_controller import ParentController, ParentTask

LOGGER = logging.getLogger(__name__)

NON_RETRYABLE_ERRORS = (
    AuthorizationFailureError,
    IntegrityFailureError,
    StaleFenceError,
    LeaseExpiredError,
    ProvenanceMismatchError,
    SchedulingDisabledError,
    StaleAttemptError,
    StaleControllerEpochError,
)


def _is_non_retryable_failure(exc: BaseException) -> bool:
    return isinstance(exc, NON_RETRYABLE_ERRORS)


@dataclass(frozen=True)
class VerifiedParentState:
    run_id: str
    ready: bool
    blockers: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]
    provenance_verified: bool


@dataclass(frozen=True)
class TaskPlan:
    plan_id: str
    child_id: str
    objective: str
    acceptance_criteria: tuple[str, ...]
    scope: str
    plan_digest: str
    attempt_number: int


@dataclass(frozen=True)
class ExecutorContext:
    """Fresh task context containing only the bounded plan and verified evidence."""

    plan: TaskPlan
    verified_evidence: tuple[dict[str, Any], ...]
    attempt_number: int
    renew_lease: Callable[[], None] | None = None


@dataclass(frozen=True)
class ExecutionOutcome:
    outcome: str
    result_digest: str
    artifact_refs: tuple[str, ...]


@dataclass(frozen=True)
class AuditorVerdict:
    verdict: str
    reasons: tuple[str, ...]
    inspector_digest: str


@dataclass(frozen=True)
class ExecutionCapabilities:
    child_id: str
    manager_token: str
    executor_token: str
    version: int
    attempt_number: int


@dataclass(frozen=True)
class AuditCapabilities:
    auditor_token: str


class PlanProducer(Protocol):
    def __call__(
        self, parent_task: ParentTask, parent_state: VerifiedParentState
    ) -> tuple[str, tuple[str, ...]]: ...


class TaskHandler(Protocol):
    def __call__(self, context: ExecutorContext) -> ExecutionOutcome: ...


class ReadOnlyInspector(Protocol):
    def __call__(
        self,
        *,
        child_id: str,
        plan: TaskPlan,
        execution: ExecutionOutcome,
        evidence: tuple[dict[str, Any], ...],
        ledger_head: str | None,
    ) -> AuditorVerdict: ...


@dataclass(frozen=True)
class CyclePendingTerra:
    """Checkpoint after auditor pass; Terra receipt must be registered out-of-band."""

    parent_task: ParentTask
    child_id: str
    attempt_number: int
    ledger_head: str
    parent_generation: str
    parent_attempt_id: str
    fence_token: int


def child_idempotency_key(
    task_id: str, parent_attempt_id: str, attempt_number: int
) -> str:
    return digest_payload(
        {
            "task_id": task_id,
            "parent_attempt_id": parent_attempt_id,
            "attempt_number": attempt_number,
        }
    )


class LongspanManager:
    """Reads verified parent state and creates one bounded task plan."""

    def __init__(self, parent: ParentController, repo: LongspanRepository) -> None:
        self._parent = parent
        self._repo = repo

    def read_verified_parent_state(self, run_id: str) -> VerifiedParentState:
        report = self._parent.readiness(run_id)
        evidence = tuple(self._parent.evidence(run_id))
        return VerifiedParentState(
            run_id=run_id,
            ready=report.ready,
            blockers=report.blockers,
            evidence=evidence,
            provenance_verified=report.provenance_verified,
        )

    def assert_parent_gate(self, parent_state: VerifiedParentState) -> None:
        if not parent_state.provenance_verified:
            raise AuthorizationFailureError("parent provenance is not verified")
        if not parent_state.ready:
            raise AuthorizationFailureError("parent readiness is incomplete")

    def create_plan(
        self,
        *,
        child: dict[str, Any],
        capabilities: ExecutionCapabilities,
        parent_task: ParentTask,
        parent_attempt_id: str,
        fence_token: int,
        producer: PlanProducer,
        controller_epoch: int,
    ) -> TaskPlan:
        parent_state = self.read_verified_parent_state(parent_task.run_id)
        self.assert_parent_gate(parent_state)
        objective, criteria = producer(parent_task, parent_state)
        attempt_number = int(child["attempt_number"])
        payload = {
            "objective": objective,
            "acceptance_criteria": list(criteria),
            "scope": "comms-01",
            "parent_task_id": parent_task.task_id,
            "request_digest": child["request_digest"],
            "attempt_number": attempt_number,
        }
        plan_digest = digest_payload(payload)
        self._repo.store_plan(
            child_id=child["child_id"],
            expected_version=int(child["version"]),
            attempt_number=attempt_number,
            objective=objective,
            acceptance_criteria=list(criteria),
            scope="comms-01",
            plan_digest=plan_digest,
            manager_capability_token=capabilities.manager_token,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            controller_epoch=controller_epoch,
            run_id=parent_task.run_id,
        )
        plan_row = self._repo.get_plan(child["child_id"], attempt_number)
        return TaskPlan(
            plan_id=plan_row["plan_id"],
            child_id=child["child_id"],
            objective=plan_row["objective"],
            acceptance_criteria=tuple(plan_row["acceptance_criteria"]),
            scope=plan_row["scope"],
            plan_digest=plan_row["plan_digest"],
            attempt_number=attempt_number,
        )


class LongspanExecutor:
    """Performs scoped work from a fresh context; cannot mark completion."""

    def __init__(self, repo: LongspanRepository, *, lease_seconds: float) -> None:
        self._repo = repo
        self.lease_seconds = lease_seconds

    def execute(
        self,
        *,
        child: dict[str, Any],
        capabilities: ExecutionCapabilities,
        plan: TaskPlan,
        verified_evidence: tuple[dict[str, Any], ...],
        handler: TaskHandler,
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
    ) -> ExecutionOutcome:
        assert_comms01_entrypoint(scope="comms-01")
        # Keep the persisted snapshot separate from the executor's working
        # copy.  A handler is untrusted task code and may mutate its context;
        # that mutation must never change the evidence bytes later committed
        # for audit.
        evidence_snapshot = deep_copy_evidence(verified_evidence)
        handler_evidence = deep_copy_evidence(evidence_snapshot)
        evidence_digest = canonical_evidence_digest(evidence_snapshot)
        child = self._repo.begin_execution(
            child_id=child["child_id"],
            expected_version=int(child["version"]),
            executor_capability_token=capabilities.executor_token,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            controller_epoch=controller_epoch,
            run_id=run_id,
        )

        def renew() -> None:
            nonlocal child
            child = self._repo.renew_lease(
                child_id=child["child_id"],
                expected_version=int(child["version"]),
                role="executor",
                capability_token=capabilities.executor_token,
                lease_seconds=self.lease_seconds,
                controller_epoch=controller_epoch,
                run_id=run_id,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
            )

        renew()
        context = ExecutorContext(
            plan=plan,
            verified_evidence=handler_evidence,
            attempt_number=int(child["attempt_number"]),
            renew_lease=renew,
        )
        outcome = handler(context)
        if outcome.outcome not in {"success", "failure", "retryable"}:
            raise ValueError("executor returned invalid outcome")
        self._repo.store_execution_result(
            child_id=child["child_id"],
            expected_version=int(child["version"]),
            attempt_number=int(child["attempt_number"]),
            outcome=outcome.outcome,
            result_digest=outcome.result_digest,
            artifact_refs=list(outcome.artifact_refs),
            executor_capability_token=capabilities.executor_token,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            controller_epoch=controller_epoch,
            run_id=run_id,
            # The execution audit request binding is the immutable request
            # digest persisted on the child.  Evidence has its own digest and
            # is independently frozen/audited; do not substitute it here.
            request_digest=str(child["request_digest"]),
            evidence_digest=evidence_digest,
            evidence_json=canonical_evidence_document(evidence_snapshot),
            raw_result_ref=(
                outcome.artifact_refs[0] if outcome.artifact_refs else None
            ),
        )
        return outcome


class LongspanAuditor:
    """Independent verifier; the only role that may mark a child verified."""

    def __init__(self, repo: LongspanRepository) -> None:
        self._repo = repo

    def audit(
        self,
        *,
        child: dict[str, Any],
        capabilities: AuditCapabilities,
        plan: TaskPlan,
        verified_evidence: tuple[dict[str, Any], ...],
        inspector: ReadOnlyInspector,
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
    ) -> AuditorVerdict:
        attempt_number = int(child["attempt_number"])
        snapshot = self._repo.get_auditor_snapshot(child["child_id"], attempt_number)
        persisted_plan = snapshot["plan"]
        snapshot_child = snapshot["child"]
        for field in (
            "child_id",
            "task_id",
            "run_id",
            "parent_attempt_id",
            "fence_token",
            "request_digest",
            "version",
        ):
            if snapshot_child[field] != child[field]:
                raise IntegrityFailureError(
                    f"auditor child {field} is not bound to the snapshot"
                )
        if int(snapshot_child["attempt_number"]) != attempt_number:
            raise IntegrityFailureError("auditor child identity is not bound to the snapshot")
        if persisted_plan["plan_digest"] != plan.plan_digest:
            raise IntegrityFailureError("audited plan digest does not match persisted plan")
        persisted = snapshot["execution"]
        persisted_evidence = snapshot["evidence"]
        try:
            persisted_document = json.loads(persisted_evidence["evidence_json"])
            persisted_items = tuple(persisted_document["evidence"])
            if not all(isinstance(item, dict) for item in persisted_items):
                raise ValueError("evidence items must be objects")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntegrityFailureError(
                "persisted execution evidence is not canonical JSON"
            ) from exc
        frozen_evidence = deep_copy_evidence(persisted_items)
        computed_evidence_digest = canonical_evidence_digest(frozen_evidence)
        if persisted_evidence["evidence_digest"] != computed_evidence_digest:
            raise IntegrityFailureError(
                "persisted execution evidence content digest mismatch"
            )
        audit_row = snapshot["audit"]
        expected_request_digest = str(snapshot_child["request_digest"])
        if audit_row["request_digest"] != expected_request_digest:
            raise IntegrityFailureError("persisted execution audit request digest mismatch")
        execution = ExecutionOutcome(
            outcome=persisted["outcome"],
            result_digest=persisted["result_digest"],
            artifact_refs=tuple(persisted["artifact_refs"]),
        )
        if audit_row["result_digest"] != execution.result_digest:
            raise IntegrityFailureError("persisted execution audit result digest mismatch")
        evidence_digest = computed_evidence_digest
        if audit_row["evidence_digest"] != evidence_digest:
            raise IntegrityFailureError("persisted execution evidence digest mismatch")
        request_digest = audit_row["request_digest"]
        expected_ledger_payload = digest_payload(
            {
                "payload_digest": execution.result_digest,
                "request_digest": request_digest,
            }
        )
        entries = snapshot["ledger_entries"]
        attempt_entries = [
            entry for entry in entries if int(entry["attempt_number"]) == attempt_number
        ]
        ledger_head = attempt_entries[-1]["entry_hash"] if attempt_entries else None
        executor_events = [
            entry
            for entry in attempt_entries
            if entry["event_type"] == "executor_result"
        ]
        if not executor_events:
            raise IntegrityFailureError("missing executor_result ledger entry for attempt")
        if executor_events[-1]["payload_digest"] != expected_ledger_payload:
            raise IntegrityFailureError("ledger execution digest does not match persisted result")
        verdict = inspector(
            child_id=child["child_id"],
            plan=plan,
            execution=execution,
            evidence=frozen_evidence,
            ledger_head=ledger_head,
        )
        if verdict.verdict not in {"pass", "fail"}:
            raise ValueError("inspector returned invalid verdict")
        receipt_digest = digest_payload(
            {
                "child_id": child["child_id"],
                "attempt_number": attempt_number,
                "verdict": verdict.verdict,
                "reasons": list(verdict.reasons),
                "inspector_digest": verdict.inspector_digest,
                "ledger_head": ledger_head,
                "evidence_digest": evidence_digest,
            }
        )
        self._repo.store_auditor_receipt(
            child_id=child["child_id"],
            expected_version=int(child["version"]),
            attempt_number=attempt_number,
            verdict=verdict.verdict,
            reasons=list(verdict.reasons),
            inspector_digest=verdict.inspector_digest,
            evidence_digest=evidence_digest,
            receipt_digest=receipt_digest,
            auditor_capability_token=capabilities.auditor_token,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            controller_epoch=controller_epoch,
            run_id=run_id,
        )
        return verdict


class LongspanWorkflow:
    """Coordinates parent queue -> lease -> Manager -> Executor -> Auditor -> Terra -> parent."""

    def __init__(
        self,
        parent: ParentController,
        repo: LongspanRepository | None = None,
    ) -> None:
        self.parent = parent
        self.repo = repo or LongspanRepository(parent._repo)
        self.manager = LongspanManager(parent, self.repo)
        self.executor = LongspanExecutor(self.repo, lease_seconds=parent.stale_after)
        self.auditor = LongspanAuditor(self.repo)

    def close(self) -> None:
        if self.repo.repo is not self.parent._repo:
            self.repo.close()

    def provision_authority(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AuthorizationFailureError(
            "workflow cannot provision authority; use Comms01AuthorityBoundary"
        )

    def _issue_execution_capabilities(self) -> tuple[str, str, str, str]:
        manager_token, manager_hash = issue_capability_token()
        executor_token, executor_hash = issue_capability_token()
        return manager_token, manager_hash, executor_token, executor_hash

    def register_child_for_task(
        self,
        *,
        parent_task: ParentTask,
        parent_attempt_id: str,
        fence_token: int,
        idempotency_key: str,
        request_digest: str,
        lease_seconds: float | None = None,
    ) -> tuple[dict[str, Any], ExecutionCapabilities, bool]:
        assert_comms01_entrypoint(scope="comms-01")
        assert_workflow_cannot_access_authority_secrets()
        blocking = self.repo.find_blocking_child(parent_task.run_id, parent_task.task_id)
        if blocking is not None:
            raise PermissionError("non-terminal child already exists for task")
        epoch = self.parent.controller_epoch(parent_task.run_id)
        manager_token, manager_hash, executor_token, executor_hash = (
            self._issue_execution_capabilities()
        )
        child, created = self.repo.register_child(
            run_id=parent_task.run_id,
            task_id=parent_task.task_id,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            controller_epoch=epoch,
            manager_capability_hash=manager_hash,
            executor_capability_hash=executor_hash,
            lease_seconds=lease_seconds or self.parent.stale_after,
        )
        if not created:
            raise PermissionError(
                "child already registered for this idempotency key; "
                "resume retry_wait child instead of re-registering"
            )
        capabilities = ExecutionCapabilities(
            child_id=child["child_id"],
            manager_token=manager_token,
            executor_token=executor_token,
            version=int(child["version"]),
            attempt_number=int(child["attempt_number"]),
        )
        return child, capabilities, created

    def resume_retry_child(
        self,
        *,
        child_id: str,
        parent_attempt_id: str,
        fence_token: int,
        lease_seconds: float | None = None,
    ) -> tuple[dict[str, Any], ExecutionCapabilities]:
        child = self.repo.get_child(child_id)
        manager_token, manager_hash, executor_token, executor_hash = (
            self._issue_execution_capabilities()
        )
        epoch = self.parent.controller_epoch(child["run_id"])
        next_attempt = int(child["attempt_number"]) + 1
        fresh_request = digest_payload(
            {
                "child_id": child_id,
                "task_id": child["task_id"],
                "parent_attempt_id": parent_attempt_id,
                "fence_token": fence_token,
                "attempt_number": next_attempt,
                "controller_epoch": epoch,
            }
        )
        row = self.repo.resume_retry_wait(
            child_id=child_id,
            expected_version=int(child["version"]),
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            manager_capability_hash=manager_hash,
            executor_capability_hash=executor_hash,
            controller_epoch=epoch,
            run_id=child["run_id"],
            lease_seconds=lease_seconds or self.parent.stale_after,
            request_digest=fresh_request,
        )
        capabilities = ExecutionCapabilities(
            child_id=child_id,
            manager_token=manager_token,
            executor_token=executor_token,
            version=int(row["version"]),
            attempt_number=int(row["attempt_number"]),
        )
        self.repo.append_parent_ledger_entry(
            child_id=child_id,
            attempt_number=int(row["attempt_number"]),
            event_type="retry_resumed",
            payload_digest=digest_payload(
                {
                    "child_id": child_id,
                    "attempt": row["attempt_number"],
                    "parent_attempt_id": parent_attempt_id,
                    "fence_token": fence_token,
                }
            ),
            controller_epoch=epoch,
            run_id=row["run_id"],
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
        )
        return row, capabilities

    def remediate_rejected_child(
        self,
        *,
        child_id: str,
        parent_task: ParentTask,
        parent_attempt_id: str,
        fence_token: int,
        reason: str,
    ) -> tuple[dict[str, Any], ExecutionCapabilities]:
        child = self.repo.get_child(child_id)
        if child["state"] not in {"terra_rejected", "needs_remediation"}:
            raise PermissionError("child is not eligible for remediation")
        epoch = self.parent.controller_epoch(child["run_id"])
        row = self.repo.transition_child_state(
            child_id=child_id,
            expected_version=int(child["version"]),
            new_state="retry_wait",
            controller_epoch=epoch,
            run_id=child["run_id"],
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            clear_capabilities=True,
            bump_attempt=False,
        )
        self.repo.append_parent_ledger_entry(
            child_id=child_id,
            attempt_number=int(row["attempt_number"]),
            event_type="cycle_failure",
            payload_digest=digest_payload({"reason": reason}),
            controller_epoch=epoch,
            run_id=child["run_id"],
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
        )
        return self.resume_retry_child(
            child_id=child_id,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
        )

    def _issue_audit_capabilities(
        self,
        *,
        child: dict[str, Any],
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
    ) -> tuple[dict[str, Any], AuditCapabilities]:
        auditor_token, auditor_hash = issue_capability_token()
        child = self.repo.grant_auditor_capability(
            child_id=child["child_id"],
            expected_version=int(child["version"]),
            auditor_capability_hash=auditor_hash,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            controller_epoch=controller_epoch,
            run_id=run_id,
        )
        return child, AuditCapabilities(auditor_token=auditor_token)

    def finish_cycle_after_terra(self, pending: CyclePendingTerra) -> ParentTask:
        self.repo.require_approved_terra_receipt(
            child_id=pending.child_id,
            attempt_number=pending.attempt_number,
            evidence_chain_head=pending.ledger_head,
        )
        return self.return_to_parent(
            child_id=pending.child_id,
            parent_generation=pending.parent_generation,
            parent_attempt_id=pending.parent_attempt_id,
            fence_token=pending.fence_token,
        )

    def return_to_parent(
        self,
        *,
        child_id: str,
        parent_generation: str,
        parent_attempt_id: str,
        fence_token: int,
        terminal_state: str = "verified",
    ) -> ParentTask:
        if not parent_attempt_id or fence_token is None:
            raise ValueError("parent_attempt_id and fence_token are required for parent return")
        if terminal_state not in {"verified", "parked", "blocked", "failed"}:
            raise ValueError("invalid parent terminal state")
        child = self.repo.get_child(child_id)
        attempt_number = int(child["attempt_number"])
        epoch = self.parent.controller_epoch(child["run_id"])
        self.parent.complete_longspan_return(
            repo=self.repo,
            child_id=child_id,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            parent_generation=parent_generation,
            terminal_state=terminal_state,
        )
        return self.parent.task(child["task_id"])

    def run_until_terra_pending(
        self,
        run_id: str,
        owner: str,
        *,
        request_digest: str,
        plan_producer: PlanProducer,
        task_handler: TaskHandler,
        inspector: ReadOnlyInspector,
    ) -> tuple[ParentTask, CyclePendingTerra | None]:
        """Execute through auditor pass; Terra receipt must be registered separately."""
        assert_comms01_entrypoint(scope="comms-01")
        assert_workflow_cannot_access_authority_secrets()
        parent_task = self.parent.claim_next(run_id, owner)
        if parent_task is None:
            raise RuntimeError("no parent task to claim")
        attempt_id, fence_token = self.parent.resolve_parent_attempt(
            parent_task.task_id, parent_task.generation or ""
        )
        child: dict[str, Any] | None = None
        try:
            parent_state = self.manager.read_verified_parent_state(run_id)
            self.manager.assert_parent_gate(parent_state)
            resumable = self.repo.find_resumable_child(run_id, parent_task.task_id)
            if resumable is not None:
                child, capabilities = self.resume_retry_child(
                    child_id=resumable["child_id"],
                    parent_attempt_id=attempt_id,
                    fence_token=fence_token,
                )
            else:
                child, capabilities, _created = self.register_child_for_task(
                    parent_task=parent_task,
                    parent_attempt_id=attempt_id,
                    fence_token=fence_token,
                    idempotency_key=child_idempotency_key(
                        parent_task.task_id, attempt_id, 0
                    ),
                    request_digest=request_digest,
                )
            plan = self.manager.create_plan(
                child=child,
                capabilities=capabilities,
                parent_task=parent_task,
                parent_attempt_id=attempt_id,
                fence_token=fence_token,
                producer=plan_producer,
                controller_epoch=self.parent.controller_epoch(run_id),
            )
            child = self.repo.get_child(child["child_id"])
            frozen_evidence = deep_copy_evidence(parent_state.evidence)
            self.executor.execute(
                child=child,
                capabilities=capabilities,
                plan=plan,
                verified_evidence=frozen_evidence,
                handler=task_handler,
                parent_attempt_id=attempt_id,
                fence_token=fence_token,
                controller_epoch=self.parent.controller_epoch(run_id),
                run_id=run_id,
            )
            child = self.repo.get_child(child["child_id"])
            child, audit_caps = self._issue_audit_capabilities(
                child=child,
                parent_attempt_id=attempt_id,
                fence_token=fence_token,
                controller_epoch=self.parent.controller_epoch(run_id),
                run_id=run_id,
            )
            verdict = self.auditor.audit(
                child=child,
                capabilities=audit_caps,
                plan=plan,
                verified_evidence=frozen_evidence,
                inspector=inspector,
                parent_attempt_id=attempt_id,
                fence_token=fence_token,
                controller_epoch=self.parent.controller_epoch(run_id),
                run_id=run_id,
            )
            if verdict.verdict != "pass":
                self._record_failure(
                    run_id=run_id,
                    parent_task=parent_task,
                    child_id=child["child_id"],
                    reason="auditor-failed",
                )
                return parent_task, None
            chain_ok, issues = self.repo.verify_ledger_chain(child["child_id"])
            if not chain_ok:
                raise IntegrityFailureError(f"evidence ledger chain is invalid: {issues}")
            entries = self.repo.ledger_entries(child["child_id"])
            ledger_head = entries[-1]["entry_hash"] if entries else ""
            child = self.repo.get_child(child["child_id"])
            return parent_task, CyclePendingTerra(
                parent_task=parent_task,
                child_id=child["child_id"],
                attempt_number=int(child["attempt_number"]),
                ledger_head=ledger_head,
                parent_generation=parent_task.generation or "",
                parent_attempt_id=attempt_id,
                fence_token=fence_token,
            )
        except NON_RETRYABLE_ERRORS as exc:
            if child is not None:
                self._park_authorization_failure(
                    run_id=run_id,
                    parent_task=parent_task,
                    child_id=child["child_id"],
                    reason=str(exc),
                    parent_attempt_id=attempt_id,
                    fence_token=fence_token,
                )
            else:
                self._release_parent_claim_on_gate_failure(
                    run_id=run_id,
                    parent_task=parent_task,
                    parent_attempt_id=attempt_id,
                    reason=str(exc),
                )
            raise
        except PermissionError as exc:
            if child is not None:
                self._recover_permission_error(
                    run_id=run_id,
                    parent_task=parent_task,
                    child_id=child["child_id"],
                    reason=str(exc),
                    error=exc,
                    parent_attempt_id=attempt_id,
                    fence_token=fence_token,
                )
            else:
                self._release_parent_claim_on_gate_failure(
                    run_id=run_id,
                    parent_task=parent_task,
                    parent_attempt_id=attempt_id,
                    reason=str(exc),
                )
            raise
        except Exception:
            if child is not None:
                self._record_failure(
                    run_id=run_id,
                    parent_task=parent_task,
                    child_id=child["child_id"],
                    reason="cycle-failure",
                )
            raise
        finally:
            if child is not None:
                current = self.repo.get_child(child["child_id"])
                if current["state"] not in {
                    "terra_pending",
                    "terra_approved",
                    "parent_returned",
                    "retry_wait",
                    "parked",
                    "cancelled",
                    "expired",
                }:
                    self.parent.idempotent_cleanup(attempt_id, run_id=run_id)

    def _recover_permission_error(
        self,
        *,
        run_id: str,
        parent_task: ParentTask,
        child_id: str,
        reason: str,
        error: BaseException | None = None,
        parent_attempt_id: str,
        fence_token: int,
    ) -> None:
        child = self.repo.get_child(child_id)
        if child["state"] in {"retry_wait", "parent_returned", "parked", "cancelled"}:
            return
        if error is not None and _is_non_retryable_failure(error):
            self._park_authorization_failure(
                run_id=run_id,
                parent_task=parent_task,
                child_id=child_id,
                reason=reason,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
            )
            return
        self.repo.atomic_recover_permission_and_requeue(
            child_id=child_id,
            expected_version=int(child["version"]),
            controller_epoch=self.parent.controller_epoch(run_id),
            run_id=run_id,
            task_id=parent_task.task_id,
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            reason=reason,
            max_retries=self.parent.max_retries,
        )

    def _park_authorization_failure(
        self,
        *,
        run_id: str,
        parent_task: ParentTask,
        child_id: str,
        reason: str,
        parent_attempt_id: str,
        fence_token: int,
    ) -> None:
        child = self.repo.get_child(child_id)
        if child["state"] in {"parent_returned", "parked", "cancelled"}:
            return
        try:
            self.repo.atomic_park_child_and_parent(
                child_id=child_id,
                expected_version=int(child["version"]),
                controller_epoch=self.parent.controller_epoch(run_id),
                run_id=run_id,
                task_id=parent_task.task_id,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
                reason=reason,
            )
        except Exception:
            LOGGER.exception("failed to park authorization failure for %s", child_id)

    def _release_parent_claim_on_gate_failure(
        self,
        *,
        run_id: str,
        parent_task: ParentTask,
        parent_attempt_id: str,
        reason: str,
    ) -> None:
        try:
            self.parent.complete_task(
                run_id,
                parent_task.task_id,
                parent_task.generation or "",
                "parked",
            )
        except Exception:
            LOGGER.exception(
                "failed to park parent claim for %s after gate failure: %s",
                parent_task.task_id,
                reason,
            )

    def _record_failure(
        self,
        *,
        run_id: str,
        parent_task: ParentTask,
        child_id: str,
        reason: str,
    ) -> None:
        child = self.repo.get_child(child_id)
        if not parent_task.generation:
            raise StaleFenceError(
                f"cannot record {reason}: parent task has no live generation"
            )
        try:
            parent_attempt_id, fence_token = self.parent.resolve_parent_attempt(
                parent_task.task_id, parent_task.generation
            )
        except Exception as exc:
            LOGGER.exception("could not resolve parent fence while recording %s", child_id)
            raise StaleFenceError(
                f"cannot record {reason}: parent fence resolution failed"
            ) from exc
        try:
            self.repo.transition_child_state(
                child_id=child_id,
                expected_version=int(child["version"]),
                new_state="retry_wait",
                controller_epoch=self.parent.controller_epoch(run_id),
                run_id=run_id,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
                clear_capabilities=True,
                bump_attempt=True,
            )
            child = self.repo.get_child(child_id)
            self.repo.append_parent_ledger_entry(
                child_id=child_id,
                attempt_number=int(child["attempt_number"]),
                event_type="cycle_failure",
                payload_digest=digest_payload({"reason": reason}),
                controller_epoch=self.parent.controller_epoch(run_id),
                run_id=run_id,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
            )
        except Exception:
            LOGGER.exception("failed to record longspan cycle failure for %s", child_id)
        try:
            self.parent.retry_task(
                run_id,
                parent_task.task_id,
                parent_task.generation or "",
                reason,
            )
        except Exception:
            LOGGER.exception("failed to requeue parent task after longspan failure")

    def expire_stale(self, run_id: str) -> list[str]:
        return self.repo.expire_stale_children(
            run_id, self.parent.controller_epoch(run_id)
        )

    def park_for_rollback(self, run_id: str) -> int:
        return self.repo.park_children_for_run(run_id, self.parent.controller_epoch(run_id))

    def record_experiment(
        self,
        *,
        run_id: str,
        child_id: str | None,
        hypothesis: str,
        baseline: str,
        scope: str,
        predicted_benefit: str,
        rollback_plan: str,
        classification: str,
    ) -> dict[str, Any]:
        return self.repo.create_experiment(
            run_id=run_id,
            child_id=child_id,
            hypothesis=hypothesis,
            baseline=baseline,
            scope=scope,
            predicted_benefit=predicted_benefit,
            rollback_plan=rollback_plan,
            classification=classification,
            controller_epoch=self.parent.controller_epoch(run_id),
        )


def default_plan_producer(
    parent_task: ParentTask, parent_state: VerifiedParentState
) -> tuple[str, tuple[str, ...]]:
    criteria = ("executor-success", "auditor-pass", "terra-approved")
    return parent_task.objective, criteria


def default_task_handler(context: ExecutorContext) -> ExecutionOutcome:
    payload = {
        "plan_digest": context.plan.plan_digest,
        "evidence_count": len(context.verified_evidence),
        "attempt": context.attempt_number,
    }
    return ExecutionOutcome(
        outcome="success",
        result_digest=digest_payload(payload),
        artifact_refs=(f"artifact://{context.plan.child_id}/result.json",),
    )


def default_inspector(
    *,
    child_id: str,
    plan: TaskPlan,
    execution: ExecutionOutcome,
    evidence: tuple[dict[str, Any], ...],
    ledger_head: str | None,
) -> AuditorVerdict:
    reasons: list[str] = []
    if execution.outcome != "success":
        reasons.append("execution-not-successful")
    if plan.scope != "comms-01":
        reasons.append("scope-violation")
    if ledger_head is None:
        reasons.append("missing-ledger-head")
    digest = digest_payload(
        {
            "child_id": child_id,
            "plan_digest": plan.plan_digest,
            "execution_digest": execution.result_digest,
            "evidence_count": len(evidence),
            "ledger_head": ledger_head,
        }
    )
    return AuditorVerdict(
        verdict="pass" if not reasons else "fail",
        reasons=tuple(reasons),
        inspector_digest=digest,
    )
