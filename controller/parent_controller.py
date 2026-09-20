"""PostgreSQL-backed Comms-01 parent controller."""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable

if TYPE_CHECKING:
    from longspan_repository import LongspanRepository

from evidence import ManifestEntry, ReadinessReport, build_required_seed, sha256_file_at
from exceptions import ReleaseAuthorityDeniedError, SchedulingDisabledError, StaleControllerEpochError, DependencyScheduleError
from goal_state_store import GoalStateStore
from redis_advisory import RedisAdvisory
from release_boundary import deny_release_action
from repository import PostgresRepository, retry_queue_key, validate_max_retries
from signal_status import SignalStatusReader
from subworkflow_handoff import HORIZON_PREREQ_FAILURE, build_handoff_request, validate_product
from correlation_store import CorrelationStore
from prerequisite_orchestration import PrerequisiteOrchestrator

LOGGER = logging.getLogger(__name__)


def generation_for_fence_token(fence_token: int) -> str:
    """Encode a positive parent fence using the one shared generation format."""
    if int(fence_token) <= 0:
        raise ValueError("fence token must be positive")
    return f"{int(fence_token):x}"


@dataclass(frozen=True)
class ChildLease:
    task_id: str
    generation: str
    owner: str
    status: str
    heartbeat_at: float
    expires_at: float
    attempt_id: str = ""


@dataclass(frozen=True)
class SupervisorEvent:
    event_id: str
    run_id: str
    event_type: str
    occurred_at: float
    detail: dict[str, object]


@dataclass(frozen=True)
class ParentTask:
    task_id: str
    run_id: str
    objective: str
    state: str
    priority: int
    available_at: float
    attempt: int
    generation: str | None
    updated_at: float


class ParentController:
    """Authoritative parent controller backed by PostgreSQL."""

    def __init__(
        self,
        db_url: str,
        *,
        stale_after: float = 600.0,
        controller_lease_seconds: float = 30.0,
        notifier: Callable[[dict[str, object]], bool] | None = None,
        clock: Callable[[], float] = time.time,
        redis: RedisAdvisory | None = None,
        controller_owner: str | None = None,
        artifact_root: Path | None = None,
        max_retries: int = 5,
        lease_holder: bool = True,
        adapter_config: dict | None = None,
    ) -> None:
        if stale_after <= 0:
            raise ValueError("stale_after must be positive")
        validate_max_retries(max_retries)
        self.controller_owner = controller_owner or f"parent-controller-{uuid.uuid4().hex}"
        self._repo = PostgresRepository(db_url, controller_owner=self.controller_owner)
        self.stale_after = stale_after
        self.controller_lease_seconds = controller_lease_seconds
        self.lease_holder = lease_holder
        self.adapter_config = adapter_config
        self.notifier = notifier
        self.clock = clock
        self.redis = redis or RedisAdvisory(None)
        if artifact_root is None:
            raise ValueError("artifact_root is required for evidence-backed control")
        self.artifact_root = Path(artifact_root).resolve()
        if not self.artifact_root.is_dir():
            raise ValueError("artifact_root must be an existing directory")
        self.max_retries = max_retries
        self._epochs: dict[str, int] = {}
        self._signal = SignalStatusReader()
        self._goal_state_store = GoalStateStore(self.artifact_root)
        self._prerequisite_orchestrator = PrerequisiteOrchestrator(self._repo)
        self._correlation_store = CorrelationStore(self._repo)

    def close(self) -> None:
        self._repo.close()

    def _dt_to_float(self, value: datetime | str) -> float:
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()

    def _resolve_epoch_from_active_controller(self, run_id: str) -> int:
        current, owner, active = self._repo.current_epoch(run_id)
        if not active or not owner:
            raise PermissionError("controller lease is not active")
        self._repo.controller_owner = owner
        self._epochs[run_id] = current
        return current

    def _ensure_epoch(self, run_id: str) -> int:
        if not self.lease_holder:
            return self._resolve_epoch_from_active_controller(run_id)
        if run_id not in self._epochs:
            self._epochs[run_id] = self._repo.acquire_controller(
                run_id, self.controller_owner, lease_seconds=self.controller_lease_seconds
            )
            return self._epochs[run_id]
        current, current_owner, active = self._repo.current_epoch(run_id)
        cached = self._epochs[run_id]
        if current != cached:
            raise PermissionError("controller epoch was superseded")
        if active and current_owner != self.controller_owner:
            raise PermissionError("controller lease is owned by another controller")
        if not active:
            self._epochs[run_id] = self._repo.acquire_controller(
                run_id,
                self.controller_owner,
                lease_seconds=self.controller_lease_seconds,
                expected_epoch=cached,
            )
        return self._epochs[run_id]

    def register_run(self, run_id: str, state: str = "active") -> None:
        self._repo.register_run(run_id, state)
        if self.lease_holder:
            self._epochs[run_id] = self._repo.acquire_controller(
                run_id, self.controller_owner, lease_seconds=self.controller_lease_seconds
            )
        else:
            self._resolve_epoch_from_active_controller(run_id)
        self._refresh_signal(run_id)

    def reconcile_submission(self, run_id: str) -> str:
        """Bootstrap missing rows without reopening state or stealing a lease."""
        self._repo.register_run(run_id)
        state = self._repo.controller_state(run_id)
        with self._repo.transaction() as cur:
            cur.execute("SELECT state FROM supervisor_runs WHERE run_id = %s", (run_id,))
            run_state = cur.fetchone()["state"]
        if not state["scheduling_enabled"] or run_state != "active" or self._goal_state_store.is_paused(run_id):
            return "preserved_disabled"
        if not state["lease_active"] and not self.lease_holder:
            return "awaiting_controller"
        self._ensure_epoch(run_id)
        return "ready"

    def validate_submission_routing(self, routing) -> None:
        if routing is None:
            raise ValueError("durable submission requires explicit executor and auditor routes")
        self._validate_routes(routing.executor_adapter, routing.auditor_adapter)

    def _validate_routes(self, executor: str, auditor: str) -> None:
        from harness_adapters.registry import load_registry_config, validate_task_routes
        config = self.adapter_config
        if config is None:
            config_path = os.environ.get("TOP_DELIVERY_ADAPTER_CONFIG")
            if not config_path:
                raise ValueError("missing adapter configuration for executable task")
            config = load_registry_config(Path(config_path), validate_executables=False)
        validate_task_routes(config, executor, auditor)

    def validate_handoff_request(self, request: dict) -> None:
        with self._repo.transaction() as cur:
            cur.execute("SELECT request_json, state, EXTRACT(EPOCH FROM clock_timestamp() - created_at) AS age FROM subworkflow_handoffs WHERE handoff_id = %s AND run_id = %s AND provider_task_id = %s",
                        (request["handoff_id"], request["run_id"], request["provider_task_id"]))
            row = cur.fetchone()
        if row is None or row["request_json"] != request:
            raise ValueError("handoff request differs from durable authority")
        if row["state"] not in {"dispatched", "running"}:
            raise ValueError("handoff is not executable")
        if float(row["age"]) >= request["timeout_seconds"]:
            self._repo.expire_subworkflow_handoff(handoff_id=request["handoff_id"], run_id=request["run_id"], controller_epoch=self._ensure_epoch(request["run_id"]), reason="provider_time_budget_exhausted")
            raise ValueError("provider time budget exhausted")
        task = self.task(request["provider_task_id"])
        if task.attempt > request["max_attempts"]:
            raise ValueError("provider attempt budget exhausted")

    def start_or_preserve_run(self, run_id: str, state: str = "active") -> str:
        try:
            controller_state = self._repo.controller_state(run_id)
        except KeyError:
            self.register_run(run_id, state)
            return "registered"
        if not controller_state["scheduling_enabled"]:
            self._epochs[run_id] = controller_state["current_epoch"]
            self._refresh_signal(run_id, allow_disabled=True)
            return "preserved_disabled"
        self.register_run(run_id, state)
        return "registered"

    def schedule_task(
        self,
        run_id: str,
        task_id: str,
        objective: str,
        *,
        priority: int = 0,
        available_at: float | None = None,
    ) -> ParentTask:
        if not task_id or not objective:
            raise ValueError("task_id and objective are required")
        epoch = self._ensure_epoch(run_id)
        due = None
        if available_at is not None:
            due = datetime.fromtimestamp(float(available_at), tz=timezone.utc)
        row = self._repo.schedule_task(
            run_id,
            task_id,
            objective,
            priority=priority,
            available_at=due,
            controller_epoch=epoch,
        )
        self.emit(
            run_id,
            "task_scheduled",
            {"task_id": task_id, "created": bool(row.get("created", False))},
        )
        return self._to_parent_task(row)

    def task(self, task_id: str) -> ParentTask:
        return self._to_parent_task(self._repo.get_task(task_id))

    def _to_parent_task(self, row: dict) -> ParentTask:
        generation = None
        if row.get("active_attempt_id"):
            with self._repo.transaction() as cur:
                cur.execute(
                    "SELECT fence_token FROM task_attempts WHERE attempt_id = %s",
                    (row["active_attempt_id"],),
                )
                fence = cur.fetchone()
                if fence:
                    generation = generation_for_fence_token(int(fence["fence_token"]))
        return ParentTask(
            task_id=row["task_id"],
            run_id=row["run_id"],
            objective=row["objective"],
            state=row["state"],
            priority=int(row["priority"]),
            available_at=self._dt_to_float(row["available_at"]),
            attempt=int(row["attempt"]),
            generation=generation,
            updated_at=self._dt_to_float(row["updated_at"]),
        )

    def create_subworkflow_handoff(
        self,
        *,
        run_id: str,
        parent_task_id: str,
        parent_attempt_id: str,
        parent_fence_token: int,
        failure_code: str,
        provider_priority: int = 0,
        handoff_context: dict[str, str] | None = None,
    ) -> dict[str, object]:
        request = build_handoff_request(
            run_id=run_id,
            parent_task_id=parent_task_id,
            parent_attempt_id=parent_attempt_id,
            failure_code=failure_code,
            request_artifact_root=f"runs/{run_id}/handoffs",
            handoff_context=handoff_context,
        )
        # A coordinator skill name is not an executable adapter registration.
        self._validate_routes(request["executor_adapter"], request["auditor_adapter"])
        with self._repo.transaction() as cur:
            cur.execute("SELECT 1 FROM subworkflow_handoffs WHERE provider_task_id = %s", (parent_task_id,))
            if cur.fetchone():
                raise ValueError("nested prerequisite repair is forbidden; provider must stop")
        handoff_root = self.artifact_root / "runs" / run_id / "handoffs" / str(request["handoff_id"])
        handoff_root.mkdir(parents=True, exist_ok=True)
        request_path = handoff_root / "request.json"
        if not request_path.exists():
            request_path.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n")
        epoch = self._ensure_epoch(run_id)
        result = self._repo.create_subworkflow_handoff(
            run_id=run_id,
            parent_task_id=parent_task_id,
            parent_attempt_id=parent_attempt_id,
            parent_fence_token=parent_fence_token,
            controller_epoch=epoch,
            handoff_id=str(request["handoff_id"]),
            provider_task_id=str(request["provider_task_id"]),
            failure_code=failure_code,
            provider_key=str(request["provider_route"]),
            product_contract=str(request["product_contract"]),
            request_json=request,
            request_digest=str(request["request_digest"]),
            provider_objective=str(request["objective"]),
            provider_priority=provider_priority,
        )
        self.emit(
            run_id,
            "subworkflow_handoff_created",
            {"handoff_id": request["handoff_id"], "provider_task_id": request["provider_task_id"], "created": result.get("created", False)},
        )
        return {**request, **result, "request_path": str(request_path.relative_to(self.artifact_root))}

    def complete_subworkflow_handoff(
        self,
        *,
        run_id: str,
        handoff_id: str,
        provider_task_id: str,
        provider_attempt_id: str,
        provider_fence_token: int,
        product_path: Path,
    ) -> dict[str, object]:
        handoff_root = self.artifact_root / "runs" / run_id / "handoffs" / handoff_id
        request_path = handoff_root / "request.json"
        request = json.loads(request_path.read_text())
        with self._repo.transaction() as cur:
            cur.execute("SELECT request_json FROM subworkflow_handoffs WHERE handoff_id = %s AND run_id = %s", (handoff_id, run_id))
            row = cur.fetchone()
        authoritative = row["request_json"] if row else None
        if isinstance(authoritative, str):
            authoritative = json.loads(authoritative)
        if authoritative != request:
            raise ValueError("handoff request differs from durable authority")
        product = validate_product(product_path, request, self.artifact_root)
        product_json = product.pop("validated_product")
        epoch = self._ensure_epoch(run_id)
        result = self._repo.complete_subworkflow_handoff(
            handoff_id=handoff_id,
            run_id=run_id,
            provider_task_id=provider_task_id,
            provider_attempt_id=provider_attempt_id,
            provider_fence_token=provider_fence_token,
            controller_epoch=epoch,
            product_json=product_json,
            product_digest=str(product["product_sha256"]),
        )
        self.emit(run_id, "subworkflow_product_received", {"handoff_id": handoff_id, "resumed": result.get("resumed", False), "disposition": product["disposition"]})
        return {**result, "product": product}

    def detect_missing_prerequisites(
        self,
        *,
        project_id: str,
        project_version: str,
        node_id: str,
        satisfied_nodes: list[str] | tuple[str, ...] | None = None,
    ) -> list[str]:
        return self._prerequisite_orchestrator.detect_missing(
            project_id=project_id,
            project_version=project_version,
            node_id=node_id,
            satisfied_nodes=satisfied_nodes,
        )

    def deliver_prerequisite_subworkflow(
        self,
        *,
        run_id: str,
        parent_task_id: str,
        parent_attempt_id: str,
        parent_fence_token: int,
        project_id: str,
        project_version: str,
        target_node_id: str,
        prerequisite_node_id: str,
        reason: str,
        artifact_digest: str,
        reused: bool = False,
        delivered_by: str | None = None,
    ) -> dict[str, object]:
        request_digest = self._prerequisite_orchestrator.delivery_decision_digest(
            run_id=run_id,
            target_node_id=target_node_id,
            prerequisite_node_id=prerequisite_node_id,
            reason=reason,
            artifact_digest=artifact_digest,
        )
        if reused:
            decision = self._prerequisite_orchestrator.record_decision(
                run_id=run_id,
                target_node_id=target_node_id,
                prerequisite_node_id=prerequisite_node_id,
                request_digest=request_digest,
                reused=True,
                delivered_by=delivered_by,
                reason=reason,
                artifact_digest=artifact_digest,
            )
            return {"decision": decision.__dict__, "handoff": None, "created": decision.created}

        handoff = self.create_subworkflow_handoff(
            run_id=run_id,
            parent_task_id=parent_task_id,
            parent_attempt_id=parent_attempt_id,
            parent_fence_token=parent_fence_token,
            failure_code=HORIZON_PREREQ_FAILURE,
            handoff_context={
                "target_node_id": target_node_id,
                "prerequisite_node_id": prerequisite_node_id,
            },
        )
        decision = self._prerequisite_orchestrator.record_decision(
            run_id=run_id,
            target_node_id=target_node_id,
            prerequisite_node_id=prerequisite_node_id,
            request_digest=request_digest,
            reused=False,
            delivered_by=str(handoff.get("provider_task_id", "")),
            reason=reason,
            artifact_digest=artifact_digest,
            handoff_id=str(handoff.get("handoff_id", "")),
        )
        return {
            "decision": decision.__dict__,
            "handoff": handoff,
            "created": bool(handoff.get("created", False)),
        }

    def record_correlation_status(
        self,
        *,
        run_id: str,
        request_id: str,
        question: dict[str, object],
        answer: dict[str, object],
    ) -> dict[str, object]:
        recorded = self._correlation_store.record_status_answer(
            run_id=run_id,
            request_id=request_id,
            question=dict(question),
            answer=dict(answer),
        )
        self.emit(
            run_id,
            "correlation_status_recorded",
            {
                "request_id": request_id,
                "replayed": recorded.replayed,
                "replay_count": recorded.replay_count,
            },
        )
        return {
            "run_id": recorded.run_id,
            "request_id": recorded.request_id,
            "answer": recorded.answer_json,
            "answer_digest": recorded.answer_digest,
            "replayed": recorded.replayed,
            "replay_count": recorded.replay_count,
        }

    def get_correlation_status(self, *, run_id: str, request_id: str) -> dict[str, object] | None:
        recorded = self._correlation_store.get_status_answer(run_id=run_id, request_id=request_id)
        if recorded is None:
            return None
        return {
            "run_id": recorded.run_id,
            "request_id": recorded.request_id,
            "answer": recorded.answer_json,
            "answer_digest": recorded.answer_digest,
            "replay_count": recorded.replay_count,
        }

    def persist_goal_state(self, run_id: str, state: str) -> None:
        self._goal_state_store.write(run_id, state)
        self.emit(run_id, "goal_state_updated", {"state": state})

    def goal_state(self, run_id: str) -> str:
        return self._goal_state_store.read(run_id)

    def claim_next(self, run_id: str, owner: str, *, expected_task_id: str | None = None) -> ParentTask | None:
        if self._goal_state_store.is_paused(run_id):
            return None
        epoch = self._ensure_epoch(run_id)
        self._repo.tick_stale(run_id, epoch, max_retries=self.max_retries)
        claim_options = {"expected_task_id": expected_task_id} if expected_task_id is not None else {}
        reclaimed = self._repo.claim_next(
            run_id, owner, controller_epoch=epoch, lease_seconds=self.stale_after, **claim_options
        )
        if reclaimed is None:
            return None
        if reclaimed.get("needs_cleanup"):
            try:
                cleanup_epoch = self._ensure_epoch(run_id)
                cleaned = self._repo.idempotent_cleanup(
                    reclaimed["attempt_id"],
                    run_id=run_id,
                    controller_epoch=cleanup_epoch,
                    max_retries=self.max_retries,
                )
            except Exception as exc:
                LOGGER.exception(
                    "reclaimed attempt cleanup failed for %s", reclaimed["attempt_id"]
                )
                self.emit(
                    run_id,
                    "cleanup_failed",
                    {
                        "attempt_id": reclaimed["attempt_id"],
                        "task_id": reclaimed.get("task_id"),
                        "phase": "claim_next",
                        "error": type(exc).__name__,
                    },
                )
                cleaned = False
            if cleaned:
                reclaimed = self._repo.claim_next(
                    run_id,
                    owner,
                    controller_epoch=epoch,
                    lease_seconds=self.stale_after,
                    **claim_options,
                )
            else:
                return None
        if reclaimed is None:
            return None
        self.emit(
            run_id,
            "task_claimed",
            {
                "task_id": reclaimed["task_id"],
                "owner": owner,
                "reclaimed": bool(reclaimed.get("reclaimed")),
            },
        )
        return self._to_parent_task(self._repo.get_task(reclaimed["task_id"]))

    def claim_next_available(self, owner: str) -> ParentTask | None:
        for run_id in self._repo.list_schedulable_run_ids():
            task = self.claim_next(run_id, owner)
            if task is not None:
                return task
        return None

    def _resolve_attempt(self, task_id: str, generation: str) -> tuple[str, int]:
        fence_token = int(generation, 16)
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT attempt_id FROM task_attempts
                WHERE task_id = %s AND fence_token = %s
                ORDER BY created_at DESC LIMIT 1
                """,
                (task_id, fence_token),
            )
            row = cur.fetchone()
            if row is None:
                raise PermissionError("stale or unknown parent task generation")
            return row["attempt_id"], fence_token

    def complete_task(
        self, run_id: str, task_id: str, generation: str, state: str
    ) -> ParentTask:
        current = self.task(task_id)
        if current.run_id != run_id or current.generation != generation:
            raise PermissionError("stale or unknown parent task generation")
        attempt_id, fence = self._resolve_attempt(task_id, generation)
        epoch = self._ensure_epoch(run_id)
        self._repo.complete_attempt(
            run_id=run_id,
            task_id=task_id,
            attempt_id=attempt_id,
            fence_token=fence,
            controller_epoch=epoch,
            terminal_state=state,
        )
        self.emit(run_id, "task_completed", {"task_id": task_id, "state": state})
        if state == "verified":
            self.schedule_dependency_successors(run_id, task_id)
        return self.task(task_id)

    def schedule_dependency_successors(self, run_id: str, completed_task_id: str) -> None:
        """Public retry entry after a post-commit scheduling failure."""
        self._schedule_dependency_successors(run_id, completed_task_id)

    def retry_successor_schedule(self, run_id: str, completed_task_id: str) -> None:
        """Alias used by the worker after a post-commit DependencyScheduleError."""
        self.schedule_dependency_successors(run_id, completed_task_id)

    def _schedule_dependency_successors(self, run_id: str, completed_task_id: str) -> None:
        from goal_dependencies import (
            goal_spec_for_task,
            ready_successor_workstreams,
            workstream_priority,
        )

        try:
            states = self._repo.list_parent_task_states(run_id)
            successors = ready_successor_workstreams(
                self.artifact_root, run_id, completed_task_id, states
            )
            if not successors:
                return
            spec = goal_spec_for_task(self.artifact_root, run_id, completed_task_id)
            total = len(spec.get("workstreams", []))
            epoch = self._ensure_epoch(run_id)
            for workstream in successors:
                self._repo.schedule_task(
                    run_id,
                    workstream.task_id,
                    workstream.title,
                    priority=workstream_priority(workstream.number, total),
                    controller_epoch=epoch,
                )
                self.emit(
                    run_id,
                    "task_scheduled",
                    {
                        "task_id": workstream.task_id,
                        "reason": "dependency_unlock",
                        "after": completed_task_id,
                    },
                )
        except Exception as exc:
            LOGGER.exception(
                "dependency successor scheduling failed after %s", completed_task_id
            )
            self.emit(
                run_id,
                "dependency_schedule_failed",
                {
                    "completed_task_id": completed_task_id,
                    "error": type(exc).__name__,
                },
            )
            raise DependencyScheduleError(
                f"dependency successor scheduling failed after {completed_task_id}"
            ) from exc

    def retry_task(
        self,
        run_id: str,
        task_id: str,
        generation: str,
        reason: str,
        *,
        delay: float = 0.0,
        _retry_key: str | None = None,
    ) -> ParentTask:
        current = self.task(task_id)
        if current.run_id != run_id or current.generation != generation:
            raise PermissionError("stale or unknown parent task generation")
        attempt_id, fence = self._resolve_attempt(task_id, generation)
        epoch = self._ensure_epoch(run_id)
        event_type = (
            "task_failed_retry_limit"
            if current.attempt >= self.max_retries
            else "task_requeued"
        )
        self._repo.retry_task(
            run_id=run_id,
            task_id=task_id,
            attempt_id=attempt_id,
            fence_token=fence,
            controller_epoch=epoch,
            reason=reason,
            delay_seconds=max(0.0, delay),
            max_retries=self.max_retries,
            retry_key=_retry_key,
            event_type=event_type,
            event_detail={
                "task_id": task_id,
                "reason": reason,
                **(
                    {"max_retries": self.max_retries}
                    if event_type == "task_failed_retry_limit"
                    else {}
                ),
            },
        )
        return self.task(task_id)

    def tasks(self, run_id: str) -> list[ParentTask]:
        with self._repo.transaction() as cur:
            cur.execute(
                "SELECT task_id FROM parent_tasks WHERE run_id = %s ORDER BY priority DESC, task_id",
                (run_id,),
            )
            task_ids = [row["task_id"] for row in cur.fetchall()]
        return [self.task(task_id) for task_id in task_ids]

    def acquire_lease(
        self, run_id: str, task_id: str, owner: str, *, force: bool = False
    ) -> ChildLease:
        epoch = self._ensure_epoch(run_id)
        try:
            self._repo.get_task(task_id)
        except KeyError:
            self._repo.schedule_task(
                run_id, task_id, "leased child work", controller_epoch=epoch
            )
        acquired = self._repo.acquire_attempt(
            run_id=run_id,
            task_id=task_id,
            owner=owner,
            controller_epoch=epoch,
            lease_seconds=self.stale_after,
            force_expired=force,
        )
        self.emit(run_id, "child_started", {"task_id": task_id, "owner": owner})
        return self.lease(acquired["task_id"])

    def lease(self, task_id: str) -> ChildLease:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT attempt_id, task_id, fence_token, owner, status,
                       heartbeat_at, lease_expires_at
                FROM task_attempts
                WHERE task_id = %s
                ORDER BY created_at DESC LIMIT 1
                """,
                (task_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError(task_id)
            return ChildLease(
                task_id=row["task_id"],
                generation=generation_for_fence_token(int(row["fence_token"])),
                owner=row["owner"],
                status=row["status"],
                heartbeat_at=self._dt_to_float(row["heartbeat_at"]),
                expires_at=self._dt_to_float(row["lease_expires_at"]),
                attempt_id=row["attempt_id"],
            )

    def heartbeat(self, task_id: str, generation: str) -> ChildLease:
        current = self.task(task_id)
        attempt_id, fence = self._resolve_attempt(task_id, generation)
        epoch = self._ensure_epoch(current.run_id)
        self._repo.heartbeat_attempt(
            run_id=current.run_id,
            task_id=task_id,
            attempt_id=attempt_id,
            fence_token=fence,
            controller_epoch=epoch,
            lease_seconds=self.stale_after,
        )
        return self.lease(task_id)

    def complete(self, run_id: str, task_id: str, generation: str, state: str) -> None:
        attempt_id, fence = self._resolve_attempt(task_id, generation)
        epoch = self._ensure_epoch(run_id)
        self._repo.complete_attempt(
            run_id=run_id,
            task_id=task_id,
            attempt_id=attempt_id,
            fence_token=fence,
            controller_epoch=epoch,
            terminal_state=state,
        )
        self.emit(run_id, "child_completed", {"task_id": task_id, "state": state})

    def tick(self, run_id: str) -> list[str]:
        epoch = self._ensure_epoch(run_id)
        return self._repo.tick_stale(
            run_id,
            epoch,
            max_retries=self.max_retries,
            record_events=True,
        )

    def enqueue_retry(
        self,
        run_id: str,
        task_id: str,
        reason: str,
        generation: str,
        delay: float = 0.0,
    ) -> str:
        """Requeue only the caller's live fenced attempt.

        This entrypoint used to insert directly into retry_queue from a task
        id. That bypassed the active attempt, lease, capability, and attempt
        number transition. All retries now use the compare-and-swap path.
        """
        current = self.task(task_id)
        if current.run_id != run_id or current.generation != generation:
            raise PermissionError("stale or unknown parent task generation")
        if current.generation is None:
            raise PermissionError("retry requires an active fenced attempt")
        if current.attempt >= self.max_retries:
            return_key = ""
        else:
            return_key = retry_queue_key(run_id, task_id, current.attempt + 1)
        self.retry_task(
            run_id,
            task_id,
            generation,
            reason,
            delay=delay,
            _retry_key=return_key or None,
        )
        return return_key

    def emit(self, run_id: str, event_type: str, detail: dict[str, object]) -> SupervisorEvent:
        epoch = self._ensure_epoch(run_id)
        event_id = self._repo.emit_event(run_id, event_type, detail, controller_epoch=epoch)
        event = SupervisorEvent(event_id, run_id, event_type, self.clock(), detail)
        self._notify_once(event)
        self._refresh_signal(run_id)
        return event

    def _notify_once(self, event: SupervisorEvent) -> None:
        if self.notifier is None:
            return
        key = f"{event.run_id}:{event.event_id}"
        with self._repo.transaction() as cur:
            cur.execute(
                """
                INSERT INTO notifications (notification_key, run_id, event_type, state)
                VALUES (%s, %s, %s, 'pending')
                ON CONFLICT (notification_key) DO NOTHING
                """,
                (key, event.run_id, event.event_type),
            )
            if cur.rowcount != 1:
                return
        payload = {"run_id": event.run_id, "event": event.event_type, **event.detail}
        try:
            ok = bool(self.notifier(payload))
        except Exception:
            LOGGER.exception("notification failed")
            ok = False
        with self._repo.transaction() as cur:
            cur.execute(
                """
                UPDATE notifications SET sent_at = clock_timestamp(), state = %s
                WHERE notification_key = %s
                """,
                ("sent" if ok else "failed", key),
            )

    def events(self, run_id: str) -> Iterable[SupervisorEvent]:
        for row in self._repo.events(run_id):
            yield SupervisorEvent(
                row["event_id"],
                row["run_id"],
                row["event_type"],
                self._dt_to_float(row["occurred_at"]),
                row["detail"],
            )

    def seed_manifest(self, artifact_root: Path | None = None) -> None:
        root = artifact_root or self.artifact_root
        root = Path(root).resolve()
        if not root.is_dir():
            raise ValueError("artifact_root must be an existing directory")
        self._repo.seed_required_manifest(build_required_seed(root))

    def rebind_artifact_root(self, artifact_root: Path) -> None:
        """Resolve evidence and goal-state paths against a run-dedicated artifact root.

        Rebound surfaces: ``artifact_root``, ``GoalStateStore``, and
        ``TOP_DELIVERY_ARTIFACT_ROOT`` for any adapter subprocess that reads it.
        """
        root = Path(artifact_root).resolve()
        if not root.is_dir():
            raise ValueError("artifact_root must be an existing directory")
        previous = self.artifact_root
        self.artifact_root = root
        self._goal_state_store = GoalStateStore(root)
        os.environ["TOP_DELIVERY_ARTIFACT_ROOT"] = str(root)
        if previous != root:
            LOGGER.info("rebound artifact root from %s to %s", previous, root)

    def _artifact_path(self, relative_path: str) -> Path:
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("artifact path must be relative to artifact_root")
        candidate = self.artifact_root / relative
        cursor = candidate
        while cursor != self.artifact_root:
            if cursor.is_symlink():
                raise ValueError("symlinked evidence paths are not accepted")
            cursor = cursor.parent
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.artifact_root) or not resolved.is_file():
            raise FileNotFoundError(candidate)
        return resolved

    def submit_manifest_entry(self, run_id: str, entry: ManifestEntry) -> None:
        self._artifact_path(entry.artifact_path)
        digest, _ = sha256_file_at(self.artifact_root, entry.artifact_path)
        if digest != entry.sha256:
            raise ValueError("manifest entry hash does not match artifact")
        self._repo.submit_manifest_entry(
            run_id=run_id,
            entry=entry,
            controller_epoch=self._ensure_epoch(run_id),
        )

    def record_evidence(
        self,
        run_id: str,
        artifact_path: str,
        *,
        producer: str,
        result: str,
        task_id: str | None = None,
        attempt_id: str | None = None,
        fence_token: int | None = None,
    ) -> str:
        """Append an on-disk, hash-verified evidence reference under the current fence."""
        if result not in {"pass", "fail"}:
            raise ValueError("evidence result must be pass or fail")
        epoch = self._ensure_epoch(run_id)
        self._artifact_path(artifact_path)
        digest, byte_count = sha256_file_at(self.artifact_root, artifact_path)
        return self._repo.append_evidence(
            run_id=run_id,
            controller_epoch=epoch,
            artifact_path=Path(artifact_path).as_posix(),
            sha256=digest,
            byte_count=byte_count,
            producer=producer,
            result=result,
            task_id=task_id,
            attempt_id=attempt_id,
            fence_token=fence_token,
        )

    def evidence(self, run_id: str) -> list[dict]:
        return self._repo.evidence(run_id)

    def readiness(self, run_id: str) -> ReadinessReport:
        report = self._repo.readiness(run_id)
        blockers = list(report.blockers)
        for entry in report.entries:
            try:
                path = self._artifact_path(entry.artifact_path)
            except (FileNotFoundError, OSError, ValueError):
                blockers.append(f"untrusted-artifact:{entry.entry_id}")
                continue
            digest, _ = sha256_file_at(self.artifact_root, entry.artifact_path)
            if digest != entry.sha256:
                blockers.append(f"artifact-mutated:{entry.entry_id}")
        return ReadinessReport(
            ready=not blockers,
            blockers=tuple(dict.fromkeys(blockers)),
            entries=report.entries,
            provenance_verified=report.provenance_verified,
        )

    def signal_status(self, run_id: str) -> dict:
        report = self.readiness(run_id)
        projection = self._signal.project(
            run_id=run_id,
            readiness="ready" if report.ready else "incomplete",
            blockers=report.blockers,
            last_event_seq=self._repo.latest_event_seq(run_id),
        )
        return projection.status

    def execute_next(
        self,
        run_id: str,
        owner: str,
        handler: Callable[[ParentTask], str | None],
        *,
        retry_delay: float = 0.0,
    ) -> ParentTask | None:
        """Execute one injected child handler; never runs shell or models itself."""
        task = self.claim_next(run_id, owner)
        if task is None:
            return None
        attempt_id, _fence = self._resolve_attempt(task.task_id, task.generation or "")
        try:
            state = handler(task) or "verified"
            if state not in {"verified", "parked", "blocked", "failed"}:
                raise ValueError("child handler returned invalid terminal state")
            return self.complete_task(run_id, task.task_id, task.generation or "", state)
        except Exception:
            self.retry_task(
                run_id,
                task.task_id,
                task.generation or "",
                "child-handler-failure",
                delay=retry_delay,
            )
            raise
        finally:
            self.idempotent_cleanup(attempt_id, run_id=run_id)

    def _refresh_signal(self, run_id: str, *, allow_disabled: bool = False) -> None:
        report = self.readiness(run_id)
        seq = self._repo.latest_event_seq(run_id)
        projection = self._signal.project(
            run_id=run_id,
            readiness="ready" if report.ready else "incomplete",
            blockers=report.blockers,
            last_event_seq=seq,
        )
        payload = projection.status
        epoch = self._epochs[run_id] if allow_disabled else self._ensure_epoch(run_id)
        self._repo.update_signal_status(
            run_id,
            json.dumps(payload, sort_keys=True),
            projection.readiness,
            seq,
            controller_epoch=epoch,
            allow_disabled=allow_disabled,
        )
        if self.redis.enabled:
            self.redis.set_status(f"td:p1:status:{run_id}", payload)

    def attempt_release(self, action: str) -> None:
        deny_release_action(action)

    def rollback(self, run_id: str) -> int:
        epoch = self._ensure_epoch(run_id)
        new_epoch = self._repo.rollback_disable(run_id, expected_epoch=epoch)
        self._epochs[run_id] = new_epoch
        self._refresh_signal(run_id, allow_disabled=True)
        return new_epoch

    def takeover_controller(self, run_id: str, owner: str, *, force: bool = False) -> int:
        epoch = self._repo.acquire_controller(
            run_id,
            owner,
            lease_seconds=self.controller_lease_seconds,
            force_takeover=force,
        )
        self._epochs[run_id] = epoch
        return epoch

    def complete_longspan_return(
        self,
        *,
        repo: "LongspanRepository",
        child_id: str,
        parent_attempt_id: str,
        fence_token: int,
        parent_generation: str,
        terminal_state: str = "verified",
    ) -> ParentTask:
        child = repo.get_child(child_id)
        epoch = self.controller_epoch(child["run_id"])
        repo.atomic_parent_return_and_complete(
            child_id=child_id,
            expected_version=int(child["version"]),
            attempt_number=int(child["attempt_number"]),
            controller_epoch=epoch,
            run_id=child["run_id"],
            task_id=child["task_id"],
            parent_attempt_id=parent_attempt_id,
            fence_token=fence_token,
            parent_generation=parent_generation,
            terminal_state=terminal_state,
        )
        return self.task(child["task_id"])

    def idempotent_cleanup(self, attempt_id: str, *, run_id: str | None = None) -> bool:
        if run_id is None:
            raise PermissionError("cleanup requires the owning run")
        epoch = self._ensure_epoch(run_id)
        return self._repo.idempotent_cleanup(
            attempt_id, run_id=run_id, controller_epoch=epoch,
            max_retries=self.max_retries,
        )

    def record_cleanup_failure(
        self, run_id: str, attempt_id: str, *, error: str, phase: str = "worker_finalize"
    ) -> None:
        self.emit(
            run_id,
            "cleanup_failed",
            {
                "attempt_id": attempt_id,
                "phase": phase,
                "error": error,
            },
        )

    def reconnect_repository(self) -> None:
        self._repo.reconnect()

    def controller_epoch(self, run_id: str) -> int:
        return self._ensure_epoch(run_id)

    def resolve_parent_attempt(self, task_id: str, generation: str) -> tuple[str, int]:
        return self._resolve_attempt(task_id, generation)


# Public compatibility alias used by supervisor_cli and tests.
Supervisor = ParentController
