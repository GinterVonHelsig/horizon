"""Restart-safe leased-task worker with independent executor and auditor lanes."""

from __future__ import annotations

import hashlib
import json
import logging
import signal
import threading
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

from exceptions import DependencyScheduleError
from failure_taxonomy import harness_failure_reason
from goal_runner import GoalRunner, GoalSnapshot, TaskSnapshot
from goal_states import RETRY_QUEUE
from harness_adapters.contract import HarnessAdapter, HarnessRequest, HarnessResult
from harness_adapters.preflight import AdapterPreflightError, preflight_adapters
from harness_adapters.schema import validate_json_schema
from harness_adapters.structured_result import EXECUTOR_RESULT_SCHEMA
from artifact_isolation import (
    ensure_run_spec,
    preflight_attempt_canary,
    resolve_run_artifact_root,
)
from artifact_owner import apply_artifact_owner
from openrouter_budget import OpenRouterBudgetGuard, SilentFallbackError
from terra_release_policy import ReleasePolicyInput, issue_authoritative_receipt
from worktree_transport import WorktreeTransport
from subworkflow_handoff import detect_capability_failure

AUDITOR_SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string", "enum": ["approve", "reject"]}},
    "required": ["verdict"],
    "additionalProperties": False,
}


LOGGER = logging.getLogger(__name__)


class WorkerControllerLike(Protocol):
    def claim_next(self, run_id: str, owner: str) -> Any: ...
    def claim_next_available(self, owner: str) -> Any: ...
    def complete_task(self, run_id: str, task_id: str, generation: str, state: str) -> Any: ...
    def retry_task(
        self, run_id: str, task_id: str, generation: str, reason: str, *, delay: float = 0.0,
    ) -> Any: ...
    def recover_executor_contract_failure(
        self,
        run_id: str,
        task_id: str,
        generation: str,
        failure_class: str,
        *,
        expected_attempt: int,
        max_retries: int = 5,
    ) -> dict[str, Any]: ...
    def record_evidence(self, **kwargs: Any) -> str: ...
    def rebind_artifact_root(self, artifact_root: Path) -> None: ...
    def idempotent_cleanup(self, attempt_id: str, *, run_id: str) -> bool: ...
    def record_cleanup_failure(
        self, run_id: str, attempt_id: str, *, error: str, phase: str = "worker_finalize"
    ) -> None: ...
    def persist_goal_state(self, run_id: str, state: str) -> None: ...
    def resolve_parent_attempt(self, task_id: str, generation: str) -> tuple[str, int]: ...


@dataclass(frozen=True)
class WorkerRunResult:
    task_id: str
    terminal_state: str


class WorkerConfigurationError(ValueError):
    pass


class EvidenceIntegrityError(ValueError):
    pass


class TaskWorker:
    def __init__(
        self, controller: WorkerControllerLike, artifact_root: Path,
        adapters: dict[str, HarnessAdapter], *, default_executor: str | None = None,
        default_auditor: str | None = None, cancel_event: Any | None = None,
        goal_runner: GoalRunner | None = None,
        worktree_transport: WorktreeTransport | None = None,
        goal_snapshots: dict[str, GoalSnapshot] | None = None,
        transport_owner: str = "top-delivery-worker",
        adapter_config: dict[str, Any] | None = None,
    ) -> None:
        self._controller = controller
        self._configured_artifact_root = Path(artifact_root).resolve()
        self._artifact_root = self._configured_artifact_root
        self._adapters = adapters
        self._adapter_config = adapter_config
        self._default_executor = default_executor
        self._default_auditor = default_auditor
        self._cancel_event = cancel_event
        self._goal_runner = goal_runner or GoalRunner()
        self._worktree_transport = worktree_transport
        self.goal_snapshots = goal_snapshots if goal_snapshots is not None else {}
        self._transport_owner = transport_owner
        self._active_adapter: HarnessAdapter | None = None
        self._pending_openrouter_authorization = None
        self._active_lock = threading.Lock()
        self._cancel_forwarded = False

    def cancel_active(self) -> None:
        with self._active_lock:
            adapter = self._active_adapter
            if adapter is None or self._cancel_forwarded:
                return
            self._cancel_forwarded = True
        adapter.cancel()

    def _preflight_adapters(self) -> None:
        from artifact_isolation import load_relay_token

        load_relay_token()
        if self._adapter_config is not None:
            preflight_adapters(self._adapter_config, probe_http=True)

    def run_once(self, run_id: str, owner: str, *, expected_task_id: str | None = None) -> WorkerRunResult | None:
        self._preflight_adapters()
        self._prepare_run_root(run_id)
        claim_options = {"expected_task_id": expected_task_id} if expected_task_id is not None else {}
        task = self._controller.claim_next(run_id, owner, **claim_options)
        if task is None:
            if expected_task_id is not None:
                raise PermissionError("expected one-shot task was not claimed")
            return None
        return self._run_claimed_task(task, owner)

    def run_once_available(self, owner: str) -> WorkerRunResult | None:
        self._preflight_adapters()
        claim = getattr(self._controller, "claim_next_available", None)
        if not callable(claim):
            return None
        task = claim(owner)
        if task is None:
            return None
        self._prepare_run_root(task.run_id)
        return self._run_claimed_task(task, owner)

    def _prepare_run_root(self, run_id: str) -> None:
        dedicated = resolve_run_artifact_root(run_id, self._configured_artifact_root)
        dedicated.mkdir(parents=True, exist_ok=True)
        if dedicated != self._configured_artifact_root:
            ensure_run_spec(
                run_id,
                configured=self._configured_artifact_root,
                dedicated=dedicated,
            )
        self._artifact_root = dedicated
        rebind = getattr(self._controller, "rebind_artifact_root", None)
        if dedicated != self._configured_artifact_root:
            if not callable(rebind):
                raise WorkerConfigurationError("controller must support rebind_artifact_root")
            rebind(dedicated)
        elif callable(rebind):
            rebind(dedicated)
        preflight_attempt_canary(self._artifact_root, run_id)

    def _run_claimed_task(self, task: Any, owner: str) -> WorkerRunResult:
        run_id = task.run_id
        generation = getattr(task, "generation", None)
        if not generation:
            raise WorkerConfigurationError("claimed parent task is missing generation")
        attempt_id, fence = self._controller.resolve_parent_attempt(task.task_id, generation)
        cleanup_done = False
        writing_lease_owner: str | None = None

        def cleanup() -> None:
            nonlocal cleanup_done
            if not cleanup_done:
                cleanup_done = True
                try:
                    self._controller.idempotent_cleanup(attempt_id, run_id=run_id)
                except Exception as exc:
                    LOGGER.exception(
                        "idempotent cleanup failed for attempt %s", attempt_id
                    )
                    record = getattr(self._controller, "record_cleanup_failure", None)
                    if callable(record):
                        try:
                            record(
                                run_id,
                                attempt_id,
                                error=type(exc).__name__,
                                phase="worker_finalize",
                            )
                        except Exception:
                            LOGGER.exception(
                                "failed to record cleanup failure for attempt %s",
                                attempt_id,
                            )
                    return

        try:
            context: dict[str, Any] | None = None
            try:
                context = self._task_context(run_id, task)
                executor_id, auditor_id = self._resolve_routing(context)
                attempt_dir = self._safe_attempt_dir(run_id, attempt_id)
                work_dir, writing_lease_owner = self._prepare_attempt_workdir(
                    run_id, attempt_id, attempt_dir, context, owner,
                )
                context = {**context, "cwd": str(work_dir)}
                executor = self._adapters[executor_id]
                auditor = self._adapters[auditor_id]
            except (KeyError, ValueError, json.JSONDecodeError) as exc:
                LOGGER.exception("configuration failure for task %s: %s", task.task_id, exc)
                return self._handle_failure(
                    task, generation, f"configuration_failure:{type(exc).__name__}", context=context,
                )

            try:
                self._authorize_adapter_execution(run_id, executor_id, context)
                executor_request = self._build_executor_request(
                    task, attempt_id, executor_id, attempt_dir / "executor", context
                )
            except SilentFallbackError as exc:
                return self._handle_failure(task, generation, f"missing_credential:{exc}", context=context)
            except (ValueError, TypeError) as exc:
                return self._handle_failure(
                    task, generation, f"configuration_failure:{type(exc).__name__}", context=context,
                )
            try:
                executor_result = self._execute_adapter(executor, executor_request)
                executor_evidence = self._persist_validate_and_record(
                    run_id, task.task_id, attempt_id, fence, "executor", attempt_dir / "executor", executor_result
                )
            except EvidenceIntegrityError:
                return self._handle_failure(task, generation, "integrity_failure", context=context)
            except (ValueError, PermissionError) as exc:
                return self._handle_failure(
                    task, generation, f"configuration_failure:{type(exc).__name__}", context=context,
                )
            except Exception as exc:
                return self._handle_failure(task, generation, f"child_crash:{type(exc).__name__}", context=context)
            finally:
                self._pending_openrouter_authorization = None

            failure_code = detect_capability_failure(attempt_dir, executor_result.structured_payload)
            if failure_code:
                create_handoff = getattr(self._controller, "create_subworkflow_handoff", None)
                if callable(create_handoff):
                    try:
                        create_handoff(
                            run_id=run_id,
                            parent_task_id=task.task_id,
                            parent_attempt_id=attempt_id,
                            parent_fence_token=fence,
                            failure_code=failure_code,
                        )
                        cleanup_done = True
                        return WorkerRunResult(task.task_id, "handoff_waiting")
                    except Exception as exc:
                        return self._handle_failure(
                            task, generation, f"configuration_failure:{type(exc).__name__}", context=context,
                        )

            if not self._execution_succeeded(executor_result):
                return self._handle_adapter_failure(task, generation, executor_result, "executor", context=context)

            try:
                self._authorize_adapter_execution(run_id, auditor_id, context)
                auditor_request = self._build_auditor_request(
                    task, attempt_id, auditor_id, attempt_dir / "auditor", context,
                    executor_result, executor_evidence,
                )
            except SilentFallbackError as exc:
                return self._handle_failure(task, generation, f"missing_credential:{exc}", context=context)
            except (ValueError, TypeError) as exc:
                return self._handle_failure(
                    task, generation, f"configuration_failure:{type(exc).__name__}", context=context,
                )
            try:
                auditor_result = self._execute_adapter(auditor, auditor_request)
                self._persist_validate_and_record(
                    run_id, task.task_id, attempt_id, fence, "auditor", attempt_dir / "auditor", auditor_result
                )
            except EvidenceIntegrityError:
                return self._handle_failure(task, generation, "integrity_failure", context=context)
            except (ValueError, PermissionError) as exc:
                return self._handle_failure(
                    task, generation, f"configuration_failure:{type(exc).__name__}", context=context,
                )
            except Exception as exc:
                return self._handle_failure(task, generation, f"child_crash:{type(exc).__name__}", context=context)

            verdict = self._auditor_verdict(auditor_result)
            if verdict == "approve":
                if context.get("handoff_id"):
                    complete_handoff = getattr(self._controller, "complete_subworkflow_handoff", None)
                    product_path = Path(str(context.get("cwd"))) / "handoff-product.json"
                    if not callable(complete_handoff):
                        return self._handle_failure(task, generation, "configuration_failure:handoff_controller_missing", context=context)
                    try:
                        complete_handoff(
                            run_id=run_id,
                            handoff_id=str(context["handoff_id"]),
                            provider_task_id=task.task_id,
                            provider_attempt_id=attempt_id,
                            provider_fence_token=fence,
                            product_path=product_path,
                        )
                    except Exception as exc:
                        return self._handle_failure(
                            task, generation, f"configuration_failure:{type(exc).__name__}", context=context,
                        )
                    cleanup_done = True
                    self._release_writing_lease(writing_lease_owner)
                    writing_lease_owner = None
                    return WorkerRunResult(task.task_id, "handoff_completed")
                self._maybe_record_release_policy(run_id, task.task_id, attempt_dir, context)
                self._release_writing_lease(writing_lease_owner)
                writing_lease_owner = None
                self._complete_verified(run_id, task.task_id, generation)
                return WorkerRunResult(task.task_id, "verified")
            if verdict == "reject":
                return self._handle_failure(task, generation, "test_failure:auditor-reject", context=context)
            if self._execution_succeeded(auditor_result):
                return self._handle_failure(
                    task, generation, "test_failure:malformed_structured_output", context=context,
                )
            return self._handle_adapter_failure(task, generation, auditor_result, "auditor", context=context)
        finally:
            self._release_writing_lease(writing_lease_owner)
            with self._active_lock:
                self._active_adapter = None
                self._cancel_forwarded = False
            cleanup()

    def _complete_verified(self, run_id: str, task_id: str, generation: str) -> None:
        """Commit verified, then retry successor scheduling if the post-commit hook fails."""
        try:
            self._controller.complete_task(run_id, task_id, generation, "verified")
            return
        except DependencyScheduleError:
            LOGGER.exception(
                "successor scheduling failed after verified commit for %s; retrying",
                task_id,
            )
        retry = getattr(self._controller, "retry_successor_schedule", None)
        if not callable(retry):
            retry = getattr(self._controller, "schedule_dependency_successors", None)
        if not callable(retry):
            return
        try:
            retry(run_id, task_id)
        except DependencyScheduleError:
            LOGGER.exception(
                "successor scheduling retry failed for %s; independent work continues",
                task_id,
            )

    def _goal_for_run(self, run_id: str) -> GoalSnapshot:
        if run_id not in self.goal_snapshots:
            self.goal_snapshots[run_id] = GoalSnapshot(run_id=run_id)
        return self.goal_snapshots[run_id]

    def _task_snapshot(self, task: Any, context: dict[str, Any] | None = None) -> TaskSnapshot:
        path_id = task.task_id
        if context is not None:
            candidate = context.get("path_id")
            if isinstance(candidate, str) and candidate:
                path_id = candidate
        attempt = getattr(task, "attempt", 1)
        if not isinstance(attempt, int) or attempt < 1:
            attempt = 1
        return TaskSnapshot(task_id=task.task_id, path_id=path_id, attempt=attempt)

    def _handle_failure(
        self,
        task: Any,
        generation: str,
        reason: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> WorkerRunResult:
        goal = self._goal_for_run(task.run_id)
        snapshot = self._task_snapshot(task, context)
        decision = self._goal_runner.handle_task_failure(goal, snapshot, reason)
        self._goal_runner.apply_decision(goal, decision)
        persist = getattr(self._controller, "persist_goal_state", None)
        if decision.goal_transition is not None and callable(persist):
            persist(task.run_id, decision.goal_transition.next_state)
        if decision.task_state == "parked":
            self._persist_signal_projection(task.run_id, decision)
            self._controller.complete_task(task.run_id, task.task_id, generation, "parked")
            return WorkerRunResult(task.task_id, "parked")
        if decision.task_state == RETRY_QUEUE:
            delay = float(decision.retry_delay_seconds or 0)
            self._controller.retry_task(
                task.run_id, task.task_id, generation, reason, delay=delay,
            )
            return WorkerRunResult(task.task_id, "retry_queued")
        if decision.classification.disposition == "pause_goal":
            self._persist_signal_projection(task.run_id, decision)
            self._controller.complete_task(task.run_id, task.task_id, generation, "parked")
            return WorkerRunResult(task.task_id, "parked")
        self._controller.complete_task(task.run_id, task.task_id, generation, "blocked")
        return WorkerRunResult(task.task_id, "blocked")

    def _handle_adapter_failure(
        self,
        task: Any,
        generation: str,
        result: HarnessResult,
        role: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> WorkerRunResult:
        classification = result.error_classification or "process_failure"
        if role == "executor" and classification == "malformed_structured_output":
            # Fail closed without generic retry_task/complete_task: 014 running-attempt
            # mutation scope cannot durably terminalize these rows, and that path is
            # the original defect. Durable exhaust/requeue is 015's job.
            recover = getattr(self._controller, "recover_executor_contract_failure", None)
            if not callable(recover):
                return WorkerRunResult(task.task_id, "failed")
            expected = getattr(task, "attempt", None)
            if not isinstance(expected, int) or expected < 1:
                return WorkerRunResult(task.task_id, "failed")
            try:
                payload = recover(
                    task.run_id,
                    task.task_id,
                    generation,
                    classification,
                    expected_attempt=expected,
                    max_retries=5,
                )
            except Exception:
                LOGGER.exception(
                    "executor-contract recovery failed for task=%s generation=%s",
                    task.task_id,
                    generation,
                )
                return WorkerRunResult(task.task_id, "failed")
            reason = payload.get("reason") if isinstance(payload, dict) else None
            if reason == "exhausted_retry_budget":
                return WorkerRunResult(task.task_id, "failed")
            if reason in {"recovered_contract_failure", "already_queued"}:
                return WorkerRunResult(task.task_id, "retry_queued")
            return WorkerRunResult(task.task_id, "failed")
        reason = harness_failure_reason(role, classification, retryable=result.retryable)
        return self._handle_failure(task, generation, reason, context=context)

    def _release_writing_lease(self, owner: str | None) -> None:
        if owner is None or self._worktree_transport is None:
            return
        self._worktree_transport.release_writing_lease(owner)

    def _persist_signal_projection(self, run_id: str, decision: Any) -> None:
        if decision.signal_projection is None:
            return
        run_dir = self._artifact_root / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        path = run_dir / "signal-status.json"
        path.write_text(
            json.dumps(decision.signal_projection.status, indent=2, sort_keys=True) + "\n"
        )

    def _prepare_attempt_workdir(
        self,
        run_id: str,
        attempt_id: str,
        attempt_dir: Path,
        context: dict[str, Any],
        owner: str,
    ) -> tuple[Path, str | None]:
        if self._worktree_transport is None:
            work_dir = attempt_dir / "work"
            work_dir.mkdir(parents=True, exist_ok=True)
            return work_dir, None

        source_repo = context.get("transport_source_repo")
        base_sha = context.get("transport_base_sha")
        transport_required = bool(context.get("transport_required"))
        if not isinstance(source_repo, str) or not isinstance(base_sha, str):
            if transport_required:
                raise WorkerConfigurationError("transport_source_repo and transport_base_sha are required")
            work_dir = attempt_dir / "work"
            work_dir.mkdir(parents=True, exist_ok=True)
            return work_dir, None

        lease_owner = owner or self._transport_owner
        user_checkout = context.get("user_checkout_path")
        if isinstance(user_checkout, str) and user_checkout:
            evidence = self._worktree_transport.capture_dirty_checkout_evidence(Path(user_checkout))
            (attempt_dir / "dirty-checkout-evidence.json").write_text(
                json.dumps(
                    {
                        "path": evidence.path,
                        "head_sha": evidence.head_sha,
                        "dirty": evidence.dirty,
                        "status_sha256": evidence.status_sha256,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )

        self._worktree_transport.initialize_mirror(Path(source_repo))
        attempt = self._worktree_transport.create_attempt_worktree(
            attempt_id=attempt_id,
            base_sha=base_sha,
        )
        (attempt_dir / "worktree.json").write_text(
            json.dumps(
                {
                    "attempt_id": attempt.attempt_id,
                    "base_sha": attempt.base_sha,
                    "tree_sha": attempt.tree_sha,
                    "worktree_path": attempt.worktree_path,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        self._worktree_transport.acquire_writing_lease(lease_owner)
        return Path(attempt.worktree_path), lease_owner

    def _authorize_adapter_execution(
        self, run_id: str, adapter_id: str, context: dict[str, Any],
    ) -> None:
        adapter = self._adapters[adapter_id]
        provider = str(getattr(adapter, "provider", "")).lower()
        if "openrouter" not in provider:
            return
        if self._selected_route(context, adapter_id) and context.get(
            "openrouter_fallback"
        ) is not False:
            # Explicit primary routes still require metering, but are not silent
            # provider fallbacks and therefore bypass only that fallback election.
            guard = self._goal_runner._budget_guard
            if guard is None:
                raise WorkerConfigurationError("OpenRouter route requires a budget guard")
            raw_cost = context.get("openrouter_estimated_cost_usd", "0.01")
            if not isinstance(raw_cost, (str, int, float, Decimal)) or Decimal(str(raw_cost)) <= 0:
                raise WorkerConfigurationError("OpenRouter estimated cost must be positive")
            self._pending_openrouter_authorization = guard.authorize_fallback(
                run_id=run_id,
                reason=context.get("openrouter_fallback_reason") or "explicit-primary-route",
                estimated_cost_usd=Decimal(str(raw_cost)),
                explicit_fallback=True,
            )
            guard.record_spend(self._pending_openrouter_authorization)
            return
        explicit = bool(context.get("openrouter_fallback"))
        reason = context.get("openrouter_fallback_reason")
        if not isinstance(reason, str) or not reason:
            reason = "provider-limit"
        raw_cost = context.get("openrouter_estimated_cost_usd", "0.01")
        estimated_cost = Decimal(str(raw_cost))
        authorization = self._goal_runner.authorize_openrouter_fallback(
            run_id=run_id,
            reason=reason,
            estimated_cost_usd=estimated_cost,
            explicit_fallback=explicit,
        )
        self._pending_openrouter_authorization = authorization

    def _maybe_record_release_policy(
        self,
        run_id: str,
        task_id: str,
        attempt_dir: Path,
        context: dict[str, Any],
    ) -> None:
        policy = context.get("release_policy")
        if not isinstance(policy, dict):
            return
        signing_key = policy.get("policy_signing_key")
        if not isinstance(signing_key, str) or not signing_key:
            raise WorkerConfigurationError("release_policy.policy_signing_key is required")
        policy_input = ReleasePolicyInput(
            run_id=run_id,
            task_id=task_id,
            base_sha=str(policy["base_sha"]),
            candidate_sha=str(policy["candidate_sha"]),
            tree_sha=str(policy["tree_sha"]),
            reviewed_sha=str(policy["reviewed_sha"]),
            backup_manifest_sha256=str(policy["backup_manifest_sha256"]),
            rollback_plan_sha256=str(policy["rollback_plan_sha256"]),
            broker_safety=str(policy["broker_safety"]),
            database_safety=str(policy["database_safety"]),
            scope_envelope_sha256=str(policy["scope_envelope_sha256"]),
        )
        receipt = issue_authoritative_receipt(policy_input, private_key_b64=signing_key)
        (attempt_dir / "release-policy-receipt.json").write_text(
            json.dumps(receipt.to_dict(), indent=2, sort_keys=True) + "\n"
        )

    def _execute_adapter(self, adapter: HarnessAdapter, request: HarnessRequest) -> HarnessResult:
        with self._active_lock:
            self._active_adapter = adapter
            self._cancel_forwarded = False
        try:
            if self._cancel_event is not None and self._cancel_event.is_set():
                self.cancel_active()
            session_path = Path(request.artifact_dir) / "harness-session.json"
            if session_path.is_file():
                payload = json.loads(session_path.read_text())
                session_id = payload.get("session_id")
                if isinstance(session_id, str) and session_id:
                    return adapter.resume(request, session_id)
            return adapter.execute(request)
        finally:
            with self._active_lock:
                if self._active_adapter is adapter:
                    self._active_adapter = None
                    self._cancel_forwarded = False

    def _task_context(self, run_id: str, task: Any) -> dict[str, Any]:
        workstream = self._workstream_context(run_id, task.task_id)
        metadata = getattr(task, "metadata", None)
        if isinstance(metadata, dict) and metadata:
            return {**workstream, **metadata}
        return workstream

    def _workstream_context(self, run_id: str, task_id: str) -> dict[str, Any]:
        from goal_dependencies import goal_spec_for_task

        spec = goal_spec_for_task(self._artifact_root, run_id, task_id)
        workstreams = spec.get("workstreams")
        if not isinstance(workstreams, list):
            raise WorkerConfigurationError("goal spec workstreams are required")
        for workstream in workstreams:
            if isinstance(workstream, dict) and workstream.get("task_id") == task_id:
                return dict(workstream)
        handoff_root = self._artifact_root / "runs" / run_id / "handoffs"
        if handoff_root.is_dir():
            for request_path in sorted(handoff_root.glob("*/request.json")):
                try:
                    request = json.loads(request_path.read_text())
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(request, dict) or request.get("provider_task_id") != task_id:
                    continue
                handoff_id = request.get("handoff_id")
                if not isinstance(handoff_id, str) or not handoff_id:
                    continue
                return {
                    "task_id": task_id,
                    "title": request.get("objective", "capability-provider handoff"),
                    "executor_adapter": request.get("executor_adapter"),
                    "auditor_adapter": request.get("auditor_adapter"),
                    "timeout_seconds": request.get("timeout_seconds", 1800),
                    "handoff_id": handoff_id,
                    "handoff_parent_task_id": request.get("parent_task_id"),
                    "handoff_request_path": str(request_path.relative_to(self._artifact_root)),
                    "acceptance_criteria": [{
                        "disposition": "PASS_VM9201_DISPOSABLE_SEAM",
                        "product_contract": request.get("product_contract"),
                        "requirement": "write a validated handoff-product.json with role, capability, target, artifact, and rollback proof",
                    }],
                    "prompt": (
                        "SUBWORKFLOW PROVIDER OBJECTIVE\n"
                        + str(request.get("objective", ""))
                        + "\n\nRead the digest-verified handoff request at "
                        + str(request_path.relative_to(self._artifact_root))
                        + ". Use only the provider registry envelope. Perform independent read-only preflight before any allowed mutation. "
                        "Write handoff-product.json under the task work directory containing only the bounded product contract, digests, sanitized paths, and rollback proof. "
                        "Never emit credentials, private keys, full prompts, responses, or unrestricted commands."
                    ),
                }
        raise WorkerConfigurationError("task workstream metadata is required")

    def _resolve_routing(self, context: dict[str, Any]) -> tuple[str, str]:
        allowed = {"executor_adapter", "auditor_adapter"}
        route = {key: context.get(key) for key in allowed}
        if not all(isinstance(value, str) and value for value in route.values()):
            raise WorkerConfigurationError("explicit executor and auditor routes are required")
        executor_id = route["executor_adapter"]
        auditor_id = route["auditor_adapter"]
        if executor_id == auditor_id:
            raise WorkerConfigurationError("executor and auditor must be distinct")
        if executor_id not in self._adapters or auditor_id not in self._adapters:
            raise WorkerConfigurationError("route adapter id is not registered")
        return executor_id, auditor_id

    @staticmethod
    def _selected_route(context: dict[str, Any], adapter_id: str) -> bool:
        """Return whether the workstream explicitly selected this adapter route."""
        return context.get("executor_adapter") == adapter_id or context.get(
            "auditor_adapter"
        ) == adapter_id

    def _safe_attempt_dir(self, run_id: str, attempt_id: str) -> Path:
        path = (self._artifact_root / "runs" / run_id / "attempts" / attempt_id).resolve()
        if not path.is_relative_to(self._artifact_root):
            raise WorkerConfigurationError("attempt path escapes artifact root")
        path.mkdir(parents=True, exist_ok=True)
        apply_artifact_owner(path)
        return path

    def _base_request(
        self, task: Any, attempt_id: str, adapter_id: str, role_dir: Path,
        context: dict[str, Any], *, prompt: str, schema: dict[str, Any] | None,
        metadata: dict[str, Any],
    ) -> HarnessRequest:
        cwd = context.get("cwd")
        if not isinstance(cwd, str) or not Path(cwd).is_absolute():
            raise WorkerConfigurationError("task cwd must be absolute")
        timeout = context.get("timeout_seconds", 600.0)
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise WorkerConfigurationError("task timeout must be positive")
        return HarnessRequest(
            task.run_id, task.task_id, attempt_id, task.objective, prompt, cwd,
            float(timeout), schema, (), str(role_dir), metadata,
        )

    @staticmethod
    def _executor_assignment_prompt(
        task: Any,
        attempt_id: str,
        context: dict[str, Any],
        authority_prompt: str,
        result_file: Path,
    ) -> str:
        title = context.get("title")
        if not isinstance(title, str) or not title:
            title = str(task.objective)
        acceptance = context.get("acceptance_criteria", [])
        if not isinstance(acceptance, list):
            acceptance = []
        assignment = {
            "run_id": task.run_id,
            "task_id": task.task_id,
            "attempt_id": attempt_id,
            "workstream_title": title,
            "acceptance_criteria": acceptance,
            "result_file": str(result_file.resolve()),
        }
        return (
            "BOUNDED WORKSTREAM ASSIGNMENT\n"
            + json.dumps(assignment, indent=2, sort_keys=True)
            + "\n\n"
            "Execute ONLY this assigned workstream. Do not execute sibling or later workstreams "
            "from the authority prompt below.\n"
            "Write factual results to the absolute result_file above (executor-result.json "
            "in the authoritative attempt work directory, not a nested work/ directory), including run_id, task_id, "
            "attempt_id, disposition, and evidence_summary. Do not request auditor verdict "
            "or self-approve acceptance.\n\n"
            "ORIGINAL AUTHORITY PROMPT\n"
            + authority_prompt
        )

    def _build_executor_request(
        self, task: Any, attempt_id: str, adapter_id: str, role_dir: Path,
        context: dict[str, Any],
    ) -> HarnessRequest:
        authority_prompt = context.get("prompt")
        if not isinstance(authority_prompt, str) or not authority_prompt:
            authority_prompt = f"EXECUTOR OBJECTIVE\n{task.objective}"
        prompt = self._executor_assignment_prompt(
            task, attempt_id, context, authority_prompt,
            role_dir.parent / "work" / "executor-result.json",
        )
        return self._base_request(
            task, attempt_id, adapter_id, role_dir, context, prompt=prompt,
            schema=(
                context.get("executor_output_schema")
                if isinstance(context.get("executor_output_schema"), dict)
                else EXECUTOR_RESULT_SCHEMA
            ),
            metadata={"role": "executor", "adapter_id": adapter_id},
        )

    def _build_auditor_request(
        self, task: Any, attempt_id: str, adapter_id: str, role_dir: Path,
        context: dict[str, Any], executor_result: HarnessResult,
        executor_evidence: list[dict[str, str]],
    ) -> HarnessRequest:
        acceptance = context.get("acceptance_criteria", [])
        if not isinstance(acceptance, list):
            raise WorkerConfigurationError("acceptance_criteria must be an array")
        immutable = {
            "adapter_id": executor_result.adapter_id,
            "model": executor_result.model,
            "provider": executor_result.provider,
            "status": executor_result.status,
            "exit_code": executor_result.exit_code,
            "artifacts": executor_evidence,
            "stdout_sha256": executor_result.stdout_sha256,
            "stderr_sha256": executor_result.stderr_sha256,
        }
        structured = executor_result.structured_payload
        extracted = structured.get("extracted_json") if isinstance(structured, dict) else None
        if isinstance(extracted, dict):
            immutable["executor_extracted_json"] = extracted
        if not acceptance:
            acceptance = [{"disposition": "COMPLETE", "verdict": "PASS"}]
        prompt = (
            "AUDIT OBJECTIVE\n" + task.objective + "\n\nACCEPTANCE CRITERIA\n" +
            json.dumps(acceptance, sort_keys=True) + "\n\nEXECUTOR EVIDENCE\n" +
            json.dumps(immutable, sort_keys=True) +
            "\n\nReturn exactly one JSON object matching the verdict schema."
        )
        return self._base_request(
            task, attempt_id, adapter_id, role_dir, context, prompt=prompt,
            schema=AUDITOR_SCHEMA,
            metadata={
                "role": "auditor", "adapter_id": adapter_id,
                "acceptance_criteria": acceptance, "executor_evidence": immutable,
            },
        )

    @staticmethod
    def _execution_succeeded(result: HarnessResult) -> bool:
        return result.status == "success" and result.exit_code == 0 and result.error_classification is None

    def _auditor_verdict(self, result: HarnessResult) -> str | None:
        if not self._execution_succeeded(result) or not isinstance(result.structured_payload, dict):
            return None
        try:
            validate_json_schema(result.structured_payload, AUDITOR_SCHEMA)
        except ValueError:
            return None
        return result.structured_payload["verdict"]

    def _persist_validate_and_record(
        self, run_id: str, task_id: str, attempt_id: str, fence: int,
        producer: str, role_dir: Path, result: HarnessResult,
    ) -> list[dict[str, str]]:
        role_dir.mkdir(parents=True, exist_ok=True)
        result_path = role_dir / "harness-result.json"
        tmp = result_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n")
        tmp.replace(result_path)
        evidence: list[dict[str, str]] = []
        for stream, path_value, expected in (
            ("stdout", result.stdout_artifact_path, result.stdout_sha256),
            ("stderr", result.stderr_artifact_path, result.stderr_sha256),
        ):
            if path_value is None and expected is None:
                continue
            if not path_value or not expected:
                raise EvidenceIntegrityError("artifact path and digest must be paired")
            candidate = Path(path_value)
            path = candidate.resolve() if candidate.is_absolute() else (role_dir / candidate).resolve()
            if not path.is_relative_to(role_dir.resolve()) or not path.is_file() or path.is_symlink():
                raise EvidenceIntegrityError("adapter artifact escapes role directory")
            digest_state = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest_state.update(chunk)
            digest = digest_state.hexdigest()
            if digest != expected:
                raise EvidenceIntegrityError("adapter artifact digest mismatch")
            relative = path.relative_to(self._artifact_root).as_posix()
            self._controller.record_evidence(
                run_id=run_id, artifact_path=relative, producer=producer,
                result="pass" if result.status == "success" else "fail",
                task_id=task_id, attempt_id=attempt_id, fence_token=fence,
            )
            evidence.append({"stream": stream, "artifact_path": relative, "sha256": digest})
        return evidence


class WorkerLoop:
    _PERMISSION_LOG_INTERVAL_SECONDS = 60.0

    def __init__(
        self, worker: TaskWorker, *, run_id: str | None, owner: str,
        poll_interval: float = 5.0, once: bool = False,
        expected_task_id: str | None = None,
    ) -> None:
        if expected_task_id is not None and (not once or not run_id):
            raise ValueError("expected task requires one-shot mode and an explicit parent")
        self._expected_task_id = expected_task_id
        self._worker = worker
        self._run_id = run_id
        self._owner = owner
        self._poll_interval = poll_interval
        self._once = once
        self._stop = False
        self._permission_error_seen = False
        self._permission_error_last_log: dict[str, float] = {}
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    @property
    def permission_error_seen(self) -> bool:
        return self._permission_error_seen

    def _log_permission_error(self, exc: PermissionError) -> None:
        key = f"worker_poll:{self._run_id or 'available'}"
        now = time.monotonic()
        last = self._permission_error_last_log.get(key)
        if last is not None and now - last < self._PERMISSION_LOG_INTERVAL_SECONDS:
            return
        self._permission_error_last_log[key] = now
        LOGGER.warning(
            "worker poll blocked: exc_type=PermissionError category=worker_poll run_id=%s errno=%s",
            self._run_id or "available",
            getattr(exc, "errno", None),
        )

    def _handle_signal(self, signum: int, frame: Any) -> None:
        self._stop = True
        self._worker.cancel_active()

    def run(self) -> bool:
        while not self._stop:
            try:
                if self._run_id:
                    options = ({"expected_task_id": self._expected_task_id}
                               if self._expected_task_id is not None else {})
                    result = self._worker.run_once(self._run_id, self._owner, **options)
                else:
                    result = self._worker.run_once_available(self._owner)
            except PermissionError as exc:
                self._permission_error_seen = True
                self._log_permission_error(exc)
                if self._once:
                    return False
                time.sleep(self._poll_interval)
                continue
            if self._once:
                return True
            if result is None and not self._stop:
                time.sleep(self._poll_interval)
        return not self._permission_error_seen
