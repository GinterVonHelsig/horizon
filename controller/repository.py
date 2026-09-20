"""PostgreSQL repository for the Comms-01 parent controller."""

from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Callable, Iterator

import psycopg2.extras

from db import (
    authorize_disposable_test_mutation,
    connect,
    connect_authority,
    row_to_dict,
)
from evidence import ManifestEntry, ReadinessReport, compute_readiness
from exceptions import (
    SchedulingDisabledError,
    StaleControllerEpochError,
    StaleFenceError,
)
from program_ingest import ParsedProgram
from project_ledger import nodes_payload


# Retry budgets are control-plane resources.  Keep the caller-configurable
# value useful for bounded remediation, but never allow one task to create an
# unbounded retry queue or event stream.
MAX_RETRIES = 20


def validate_max_retries(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("max_retries must be an integer")
    if value < 0:
        raise ValueError("max_retries must be non-negative")
    if value > MAX_RETRIES:
        raise ValueError(f"max_retries must be <= {MAX_RETRIES}")
    return value


def retry_queue_key(run_id: str, task_id: str, attempt: int) -> str:
    """Return the stable idempotency key for one parent retry attempt."""
    return f"retry:{run_id}:{task_id}:attempt:{attempt}"


class PostgresRepository:
    def __init__(
        self,
        db_url: str,
        *,
        connection_mode: str = "workflow",
        controller_owner: str | None = None,
    ) -> None:
        if connection_mode not in {"workflow", "authority"}:
            raise ValueError(f"unknown PostgreSQL connection mode: {connection_mode}")
        self.connection_mode = connection_mode
        self.controller_owner = controller_owner
        if connection_mode == "authority":
            from db import resolve_authority_database_url

            self.db_url = resolve_authority_database_url(db_url)
            self._conn = connect_authority(self.db_url)
        else:
            from workflow_database_target import resolve_workflow_database_url

            self.db_url = resolve_workflow_database_url(db_url)
            self._conn = connect(self.db_url)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self, *, authorize_disposable: bool = True) -> Iterator[Any]:
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            if authorize_disposable:
                authorize_disposable_test_mutation(
                    self._conn, self.db_url, cursor=cur
                )
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    def _now_sql(self) -> str:
        return "clock_timestamp()"

    def register_run(self, run_id: str, state: str = "active") -> None:
        with self.transaction() as cur:
            cur.execute("SELECT longspan_register_run(%s, %s)", (run_id, state))

    def acquire_controller(
        self,
        run_id: str,
        owner: str,
        *,
        lease_seconds: float,
        expected_epoch: int | None = None,
        force_takeover: bool = False,
    ) -> int:
        with self.transaction() as cur:
            try:
                cur.execute(
                    "SELECT longspan_acquire_controller(%s, %s, %s, %s, %s)",
                    (run_id, owner, lease_seconds, expected_epoch, force_takeover),
                )
            except Exception as exc:
                message = str(exc).lower()
                if "scheduling disabled" in message:
                    raise SchedulingDisabledError("scheduling disabled") from exc
                if "stale controller epoch" in message:
                    raise StaleControllerEpochError("stale controller epoch") from exc
                if "controller lease held" in message:
                    raise StaleControllerEpochError("controller lease held by another owner") from exc
                raise
            row = cur.fetchone()
            if row is None:
                raise PermissionError("controller acquisition returned no epoch")
            return int(row[0] if not isinstance(row, dict) else row.get("longspan_acquire_controller"))

    def current_epoch(self, run_id: str) -> tuple[int, str | None, bool]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT current_epoch, owner,
                       lease_expires_at > clock_timestamp() AS lease_active,
                       scheduling_enabled
                FROM controller_control WHERE run_id = %s
                """,
                (run_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError(run_id)
            return int(row["current_epoch"]), row["owner"], bool(row["lease_active"] and row["scheduling_enabled"])

    def controller_state(self, run_id: str) -> dict[str, Any]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT current_epoch, owner, scheduling_enabled,
                       lease_expires_at > clock_timestamp() AS lease_active
                FROM controller_control
                WHERE run_id = %s
                """,
                (run_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError(run_id)
            return {
                "current_epoch": int(row["current_epoch"]),
                "owner": row["owner"],
                "scheduling_enabled": bool(row["scheduling_enabled"]),
                "lease_active": bool(row["lease_active"]),
            }

    def _assert_controller_epoch(
        self,
        cur: Any,
        run_id: str,
        epoch: int,
        *,
        scope_kind: str,
        fence_token: int | None = None,
        controller_operation: str = "general",
    ) -> None:
        # Lock order is part of the fencing contract: every mutator locks
        # controller_control first, then may lock parent_tasks, task_attempts,
        # retry_queue, or supervisor_events.  Rollback follows the same order.
        # Do not acquire a child/table lock before this controller row lock.
        cur.execute(
            """
            SELECT current_epoch, controller_fence_token,
                   lease_expires_at > clock_timestamp() AS active,
                   scheduling_enabled
            FROM controller_control WHERE run_id = %s
            """,
            (run_id,),
        )
        row = cur.fetchone()
        if row is None or int(row["current_epoch"]) != epoch:
            raise PermissionError("stale controller epoch")
        if not row["scheduling_enabled"]:
            raise PermissionError("scheduling disabled")
        if not row["active"]:
            raise PermissionError("controller lease expired")
        if scope_kind not in {"controller", "workflow"}:
            raise ValueError(f"unknown mutation scope kind: {scope_kind}")
        if scope_kind == "workflow":
            if fence_token is None or int(fence_token) <= 0:
                raise PermissionError("workflow mutation scope requires an explicit positive fence token")
            scope_fence = int(fence_token)
            scope_sql = "SELECT longspan_open_mutation_scope(%s, %s, %s)"
            scope_params = (run_id, epoch, scope_fence)
        else:
            if fence_token is not None:
                raise PermissionError("controller mutation scope cannot carry a task fence token")
            if not self.controller_owner:
                raise PermissionError("controller mutation scope requires a pinned controller owner")
            scope_fence = int(row["controller_fence_token"])
            if scope_fence <= 0:
                raise PermissionError("controller mutation scope requires a positive controller fence token")
            scope_sql = (
                "SELECT longspan_open_controller_mutation_scope(%s, %s, %s, %s, %s)"
            )
            scope_params = (
                run_id,
                epoch,
                scope_fence,
                self.controller_owner,
                controller_operation,
            )
        try:
            cur.execute(scope_sql, scope_params)
        except psycopg2.Error as exc:
            message = str(exc).lower()
            if "stale" in message or "fence" in message:
                raise StaleFenceError("stale controller or mutation fence") from exc
            raise PermissionError("controller mutation scope was rejected") from exc

    def schedule_task(
        self,
        run_id: str,
        task_id: str,
        objective: str,
        *,
        priority: int = 0,
        available_at: datetime | None = None,
        controller_epoch: int | None = None,
    ) -> dict[str, Any]:
        with self.transaction() as cur:
            if controller_epoch is None:
                raise PermissionError("schedule_task requires an active controller epoch")
            if not self.controller_owner:
                raise PermissionError("schedule_task requires a pinned controller owner")
            cur.execute(
                """
                SELECT controller_fence_token
                FROM controller_control
                WHERE run_id = %s
                  AND current_epoch = %s
                  AND owner = %s
                """,
                (run_id, controller_epoch, self.controller_owner),
            )
            control_row = cur.fetchone()
            if control_row is None:
                raise PermissionError("stale controller epoch")
            controller_fence = int(control_row["controller_fence_token"])
            if controller_fence <= 0:
                raise PermissionError(
                    "controller mutation scope requires a positive controller fence token"
                )
            cur.execute(
                """
                SELECT longspan_schedule_goal_task(
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                ) AS result
                """,
                (
                    run_id,
                    task_id,
                    objective,
                    priority,
                    available_at,
                    controller_epoch,
                    self.controller_owner,
                    controller_fence,
                ),
            )
            payload = cur.fetchone()["result"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            return payload

    def get_task(self, task_id: str) -> dict[str, Any]:
        with self.transaction() as cur:
            return self._fetch_task(cur, task_id)

    def list_parent_task_states(self, run_id: str) -> dict[str, str]:
        with self.transaction() as cur:
            cur.execute(
                "SELECT task_id, state FROM parent_tasks WHERE run_id = %s",
                (run_id,),
            )
            return {row["task_id"]: row["state"] for row in cur.fetchall()}

    def list_schedulable_run_ids(self) -> list[str]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT r.run_id
                FROM supervisor_runs AS r
                JOIN controller_control AS c USING (run_id)
                WHERE r.state = 'active'
                  AND c.scheduling_enabled = TRUE
                  AND c.lease_expires_at > clock_timestamp()
                ORDER BY r.updated_at DESC, r.run_id
                """
            )
            return [str(row["run_id"]) for row in cur.fetchall()]

    def list_active_run_ids(self) -> list[str]:
        """Active, scheduling-enabled runs, including those whose controller lease has expired."""
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT r.run_id
                FROM supervisor_runs AS r
                JOIN controller_control AS c USING (run_id)
                WHERE r.state = 'active'
                  AND c.scheduling_enabled = TRUE
                ORDER BY r.updated_at DESC, r.run_id
                """
            )
            return [str(row["run_id"]) for row in cur.fetchall()]

    def _fetch_task(self, cur: Any, task_id: str) -> dict[str, Any]:
        """Fetch a task without committing a caller-owned transaction."""
        cur.execute(
            """
            SELECT task_id, run_id, objective, state, priority, available_at,
                   attempt, active_attempt_id, updated_at
            FROM parent_tasks WHERE task_id = %s
            """,
            (task_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise KeyError(task_id)
        return row_to_dict(row)

    def claim_next(
        self,
        run_id: str,
        owner: str,
        *,
        controller_epoch: int,
        lease_seconds: float,
        expected_task_id: str | None = None,
    ) -> dict[str, Any] | None:
        with self.transaction() as cur:
            if expected_task_id is not None:
                cur.execute("""SELECT task_id FROM parent_tasks
                    WHERE run_id = %s AND state = 'queued'
                      AND available_at <= clock_timestamp()
                    ORDER BY priority DESC, available_at, task_id LIMIT 1""", (run_id,))
                head = cur.fetchone()
                if head is None or head["task_id"] != expected_task_id:
                    raise PermissionError("one-shot expected task is not the eligible queue head")
            cur.execute(
                """
                SELECT t.task_id, t.active_attempt_id, a.fence_token, a.controller_epoch,
                       a.lease_expires_at <= clock_timestamp() AS lease_expired
                FROM parent_tasks AS t
                JOIN task_attempts AS a
                  ON a.attempt_id = t.active_attempt_id
                 AND a.task_id = t.task_id
                 AND a.run_id = t.run_id
                WHERE t.run_id = %s
                  AND t.state = 'leased'
                  AND a.owner = %s
                  AND a.status = 'running'
                ORDER BY t.priority DESC, t.available_at, t.task_id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """,
                (run_id, owner),
            )
            owned = cur.fetchone()
            if owned is not None:
                if expected_task_id is not None:
                    raise PermissionError("one-shot expected fresh claim cannot reclaim an active attempt")
                lease_expired = bool(owned["lease_expired"])
                epoch_mismatch = int(owned["controller_epoch"]) != int(controller_epoch)
                if lease_expired:
                    return {
                        "needs_cleanup": True,
                        "attempt_id": owned["active_attempt_id"],
                        "task_id": owned["task_id"],
                    }
                fence_token = int(owned["fence_token"])
                self._assert_controller_epoch(
                    cur,
                    run_id,
                    controller_epoch,
                    scope_kind="workflow",
                    fence_token=fence_token,
                )
                if epoch_mismatch:
                    cur.execute(
                        """
                        UPDATE task_attempts
                        SET controller_epoch = %s,
                            heartbeat_at = clock_timestamp(),
                            lease_expires_at = clock_timestamp() + (%s || ' seconds')::interval,
                            status = 'running'
                        WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                          AND run_id = %s AND status = 'running' AND owner = %s
                        """,
                        (
                            controller_epoch,
                            lease_seconds,
                            owned["active_attempt_id"],
                            owned["task_id"],
                            fence_token,
                            run_id,
                            owner,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE task_attempts
                        SET heartbeat_at = clock_timestamp(),
                            lease_expires_at = clock_timestamp() + (%s || ' seconds')::interval,
                            status = 'running'
                        WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                          AND controller_epoch = %s AND run_id = %s AND status = 'running'
                        """,
                        (
                            lease_seconds,
                            owned["active_attempt_id"],
                            owned["task_id"],
                            fence_token,
                            controller_epoch,
                            run_id,
                        ),
                    )
                if cur.rowcount != 1:
                    return None
                view = self._task_view(
                    cur, owned["task_id"], owned["active_attempt_id"], fence_token
                )
                view["reclaimed"] = True
                return view
            cur.execute(
                """
                SELECT longspan_claim_next_parent_task(
                    %s, %s, %s, %s
                ) AS result
                """,
                (run_id, owner, controller_epoch, lease_seconds),
            )
            payload = cur.fetchone()["result"]
            if payload is None:
                if expected_task_id is not None:
                    raise PermissionError("expected task was not claimed")
                return None
            if isinstance(payload, str):
                payload = json.loads(payload)
            if expected_task_id is not None and payload.get("task_id") != expected_task_id:
                # Raising BEFORE transaction exit rolls back the stored function's
                # attempted claim too. No unrelated claim/attempt is committed or
                # dispatched if queue order changes between the two statements.
                raise PermissionError("queue changed during one-shot claim")
            return payload

    def acquire_attempt(
        self,
        *,
        run_id: str,
        task_id: str,
        owner: str,
        controller_epoch: int,
        lease_seconds: float,
        force_expired: bool = False,
    ) -> dict[str, Any]:
        """Acquire a named task through the same fenced transaction as claims."""
        with self.transaction() as cur:
            self._assert_controller_epoch(
                cur, run_id, controller_epoch, scope_kind="controller"
            )
            cur.execute(
                """
                SELECT task_id, run_id, state, active_attempt_id
                FROM parent_tasks WHERE task_id = %s FOR UPDATE
                """,
                (task_id,),
            )
            task = cur.fetchone()
            if task is None or task["run_id"] != run_id:
                raise PermissionError("task is not owned by this run")
            if task["state"] in {"verified", "parked", "blocked", "failed"}:
                raise PermissionError("task is not eligible for a child lease")
            cur.execute(
                """
                SELECT attempt_id,
                       lease_expires_at > clock_timestamp() AS lease_active
                FROM task_attempts
                WHERE task_id = %s AND status = 'running'
                FOR UPDATE
                """,
                (task_id,),
            )
            active = cur.fetchone()
            if active is not None and bool(active["lease_active"]):
                raise PermissionError("task already has an unexpired attempt")
            if active is not None:
                if not force_expired:
                    raise PermissionError("expired attempt requires explicit takeover")
                cur.execute(
                    """
                    UPDATE task_attempts
                    SET status = 'stale', ended_at = clock_timestamp()
                    WHERE attempt_id = %s AND lease_expires_at <= clock_timestamp()
                    """,
                    (active["attempt_id"],),
                )
                if cur.rowcount != 1:
                    raise PermissionError("cannot force-acquire a live attempt")
            attempt_increment = 1 if active is not None else 0
            cur.execute(
                """
                SELECT COALESCE(MAX(fence_token), 0) + 1 AS next_fence
                FROM task_attempts WHERE task_id = %s
                """,
                (task_id,),
            )
            fence_token = int(cur.fetchone()["next_fence"])
            attempt_id = uuid.uuid4().hex
            cur.execute(
                """
                INSERT INTO task_attempts
                    (attempt_id, task_id, run_id, fence_token, controller_epoch, owner,
                     status, heartbeat_at, lease_expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'running', clock_timestamp(),
                        clock_timestamp() + (%s || ' seconds')::interval)
                """,
                (attempt_id, task_id, run_id, fence_token, controller_epoch, owner, lease_seconds),
            )
            cur.execute(
                """
                UPDATE parent_tasks
                SET state = 'leased', active_attempt_id = %s,
                    attempt = attempt + %s, updated_at = clock_timestamp()
                WHERE task_id = %s AND run_id = %s
                """,
                (attempt_id, attempt_increment, task_id, run_id),
            )
            return self._task_view(cur, task_id, attempt_id, fence_token)

    def _task_view(
        self, cur: Any, task_id: str, attempt_id: str, fence_token: int
    ) -> dict[str, Any]:
        cur.execute(
            """
            SELECT t.task_id, t.run_id, t.objective, t.state, t.priority, t.available_at,
                   t.attempt, t.active_attempt_id, t.updated_at,
                   a.attempt_id, a.fence_token, a.owner, a.status, a.lease_expires_at
            FROM parent_tasks t
            JOIN task_attempts a ON a.attempt_id = t.active_attempt_id
            WHERE t.task_id = %s
            """,
            (task_id,),
        )
        return row_to_dict(cur.fetchone())

    def heartbeat_attempt(
        self,
        *,
        run_id: str,
        task_id: str,
        attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        lease_seconds: float,
    ) -> None:
        with self.transaction() as cur:
            self._assert_controller_epoch(
                cur,
                run_id,
                controller_epoch,
                scope_kind="workflow",
                fence_token=fence_token,
            )
            cur.execute(
                """
                UPDATE task_attempts
                SET heartbeat_at = clock_timestamp(),
                    lease_expires_at = clock_timestamp() + (%s || ' seconds')::interval,
                    status = 'running'
                WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                  AND controller_epoch = %s AND run_id = %s AND status = 'running'
                  AND lease_expires_at > clock_timestamp()
                """,
                (lease_seconds, attempt_id, task_id, fence_token, controller_epoch, run_id),
            )
            if cur.rowcount != 1:
                raise PermissionError("stale or expired attempt")

    def complete_attempt(
        self,
        *,
        run_id: str,
        task_id: str,
        attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        terminal_state: str,
        clear_active_attempt: bool = False,
    ) -> dict[str, Any]:
        if terminal_state not in {"verified", "parked", "blocked", "failed"}:
            raise ValueError("invalid terminal state")
        with self.transaction() as cur:
            self._assert_controller_epoch(
                cur,
                run_id,
                controller_epoch,
                scope_kind="workflow",
                fence_token=fence_token,
            )
            cur.execute(
                """
                SELECT task_id FROM parent_tasks
                WHERE task_id = %s AND run_id = %s AND active_attempt_id = %s
                FOR UPDATE
                """,
                (task_id, run_id, attempt_id),
            )
            if cur.fetchone() is None:
                raise StaleFenceError("parent task missing for attempt completion")
            cur.execute(
                """
                SELECT status, lease_expires_at > clock_timestamp() AS lease_active,
                       controller_epoch
                FROM task_attempts
                WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                  AND run_id = %s
                FOR UPDATE
                """,
                (attempt_id, task_id, fence_token, run_id),
            )
            attempt = cur.fetchone()
            if attempt is None or attempt["status"] != "running" or not attempt["lease_active"]:
                raise PermissionError("stale or expired attempt")
            if int(attempt["controller_epoch"]) != controller_epoch:
                cur.execute(
                    """
                    UPDATE task_attempts
                    SET controller_epoch = %s
                    WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                      AND run_id = %s AND status = 'running'
                      AND lease_expires_at > clock_timestamp()
                    """,
                    (controller_epoch, attempt_id, task_id, fence_token, run_id),
                )
                if cur.rowcount != 1:
                    raise PermissionError("stale or expired attempt")
            cur.execute(
                """
                UPDATE parent_tasks
                SET state = %s,
                    active_attempt_id = CASE WHEN %s THEN NULL ELSE active_attempt_id END,
                    updated_at = clock_timestamp()
                WHERE task_id = %s AND run_id = %s AND active_attempt_id = %s
                """,
                (terminal_state, clear_active_attempt, task_id, run_id, attempt_id),
            )
            if cur.rowcount != 1:
                raise StaleFenceError("parent task terminalization lost the fence")
            cur.execute(
                """
                UPDATE task_attempts
                SET status = %s, ended_at = clock_timestamp()
                WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                  AND run_id = %s AND status = 'running'
                  AND lease_expires_at > clock_timestamp()
                """,
                (terminal_state, attempt_id, task_id, fence_token, run_id),
            )
            if cur.rowcount != 1:
                raise StaleFenceError("attempt terminalization lost the fence")
            return self._fetch_task(cur, task_id)

    def complete_attempt_in_transaction(
        self,
        cur: Any,
        *,
        run_id: str,
        task_id: str,
        attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        terminal_state: str,
        event_type: str = "task_completed",
        event_detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if terminal_state not in {"verified", "parked", "blocked", "failed"}:
            raise ValueError("invalid terminal state")
        self._assert_controller_epoch(
            cur,
            run_id,
            controller_epoch,
            scope_kind="workflow",
            fence_token=fence_token,
        )
        cur.execute(
            """
            SELECT task_id FROM parent_tasks
            WHERE task_id = %s AND run_id = %s AND active_attempt_id = %s
            FOR UPDATE
            """,
            (task_id, run_id, attempt_id),
        )
        parent = cur.fetchone()
        if parent is None:
            raise StaleFenceError("parent task missing for attempt completion")
        cur.execute(
            """
            SELECT fence_token, status, lease_expires_at > clock_timestamp() AS lease_active,
                   controller_epoch
            FROM task_attempts
            WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
              AND run_id = %s
            FOR UPDATE
            """,
            (attempt_id, task_id, fence_token, run_id),
        )
        attempt = cur.fetchone()
        if (
            attempt is None
            or attempt["status"] != "running"
            or not attempt["lease_active"]
        ):
            raise StaleFenceError("stale parent task generation for completion")
        if int(attempt["controller_epoch"]) != controller_epoch:
            cur.execute(
                """
                UPDATE task_attempts
                SET controller_epoch = %s
                WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                  AND run_id = %s AND status = 'running'
                  AND lease_expires_at > clock_timestamp()
                """,
                (controller_epoch, attempt_id, task_id, fence_token, run_id),
            )
            if cur.rowcount != 1:
                raise StaleFenceError("stale parent task generation for completion")
        cur.execute(
            """
            UPDATE parent_tasks
            SET state = %s, updated_at = clock_timestamp()
            WHERE task_id = %s AND active_attempt_id = %s
            """,
            (terminal_state, task_id, attempt_id),
        )
        if cur.rowcount != 1:
            raise StaleFenceError("stale parent task completion")
        cur.execute(
            """
            UPDATE task_attempts
            SET status = %s, ended_at = clock_timestamp()
            WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
              AND run_id = %s AND status = 'running'
              AND lease_expires_at > clock_timestamp()
            """,
            (terminal_state, attempt_id, task_id, fence_token, run_id),
        )
        if cur.rowcount != 1:
            raise StaleFenceError("attempt terminalization lost the fence")
        cur.execute(
            "SELECT longspan_next_event_seq(%s, %s) AS event_seq",
            (run_id, controller_epoch),
        )
        sequence = cur.fetchone()
        if sequence is None:
            raise StaleFenceError("event sequence allocation lost the controller epoch")
        detail = event_detail or {"task_id": task_id, "state": terminal_state}
        cur.execute(
            """
            INSERT INTO supervisor_events
                (event_id, event_seq, run_id, controller_epoch, event_type,
                 occurred_at, detail_json)
            VALUES (%s, %s, %s, %s, %s, clock_timestamp(), %s)
            ON CONFLICT (run_id, event_seq) DO NOTHING
            """,
            (
                uuid.uuid4().hex,
                int(sequence["event_seq"]),
                run_id,
                controller_epoch,
                event_type,
                json.dumps(detail, sort_keys=True),
            ),
        )
        return self._fetch_task(cur, task_id)

    def retry_task(
        self,
        *,
        run_id: str,
        task_id: str,
        attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        reason: str,
        delay_seconds: float,
        max_retries: int = 5,
        retry_key: str | None = None,
        event_type: str | None = None,
        event_detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        validate_max_retries(max_retries)
        with self.transaction() as cur:
            self._assert_controller_epoch(
                cur,
                run_id,
                controller_epoch,
                scope_kind="workflow",
                fence_token=fence_token,
            )
            cur.execute(
                """
                SELECT attempt, active_attempt_id
                FROM parent_tasks
                WHERE task_id = %s AND run_id = %s
                FOR UPDATE
                """,
                (task_id, run_id),
            )
            parent = cur.fetchone()
            if parent is None or parent["active_attempt_id"] != attempt_id:
                raise StaleFenceError("parent retry target is stale")
            if int(parent["attempt"]) >= max_retries:
                cur.execute(
                    """
                    UPDATE parent_tasks
                    SET state = 'failed', active_attempt_id = NULL,
                        updated_at = clock_timestamp()
                    WHERE task_id = %s AND run_id = %s AND active_attempt_id = %s
                    """,
                    (task_id, run_id, attempt_id),
                )
                if cur.rowcount != 1:
                    raise StaleFenceError("retry-limit parent terminalization lost the fence")
                cur.execute(
                    """
                    UPDATE task_attempts
                    SET status = 'failed', ended_at = clock_timestamp()
                    WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                      AND controller_epoch = %s AND run_id = %s AND status = 'running'
                      AND lease_expires_at > clock_timestamp()
                    """,
                    (attempt_id, task_id, fence_token, controller_epoch, run_id),
                )
                if cur.rowcount != 1:
                    raise PermissionError("stale or expired attempt")
                if event_type:
                    self._insert_event_in_transaction(
                        cur,
                        run_id=run_id,
                        controller_epoch=controller_epoch,
                        event_type=event_type,
                        detail=event_detail or {"task_id": task_id},
                    )
                return self._fetch_task(cur, task_id)
            next_attempt = int(parent["attempt"]) + 1
            retry_key = retry_key or retry_queue_key(run_id, task_id, next_attempt)
            cur.execute(
                """
                INSERT INTO retry_queue
                    (retry_key, run_id, task_id, available_at, attempt, reason, state)
                VALUES (%s, %s, %s,
                        clock_timestamp() + (%s || ' seconds')::interval,
                        %s, %s, 'queued')
                """,
                (retry_key, run_id, task_id, delay_seconds, next_attempt, reason),
            )
            cur.execute(
                """
                UPDATE parent_tasks
                SET state = 'queued',
                    available_at = clock_timestamp() + (%s || ' seconds')::interval,
                    attempt = attempt + 1,
                    active_attempt_id = NULL,
                    updated_at = clock_timestamp()
                WHERE task_id = %s AND run_id = %s AND active_attempt_id = %s
                """,
                (delay_seconds, task_id, run_id, attempt_id),
            )
            if cur.rowcount != 1:
                raise StaleFenceError("parent retry requeue lost the fence")
            cur.execute(
                """
                UPDATE task_attempts
                SET status = 'failed', ended_at = clock_timestamp()
                WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                  AND controller_epoch = %s AND run_id = %s AND status = 'running'
                  AND lease_expires_at > clock_timestamp()
                """,
                (attempt_id, task_id, fence_token, controller_epoch, run_id),
            )
            if cur.rowcount != 1:
                raise PermissionError("stale or expired attempt")
            if event_type:
                self._insert_event_in_transaction(
                    cur,
                    run_id=run_id,
                    controller_epoch=controller_epoch,
                    event_type=event_type,
                    detail=event_detail or {"task_id": task_id},
                )
            return self._fetch_task(cur, task_id)

    def tick_stale(
        self,
        run_id: str,
        controller_epoch: int,
        max_retries: int = 5,
        *,
        record_events: bool = False,
    ) -> list[str]:
        validate_max_retries(max_retries)
        stale: list[str] = []
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT current_epoch, scheduling_enabled,
                       lease_expires_at > clock_timestamp() AS lease_active
                FROM controller_control WHERE run_id = %s
                """,
                (run_id,),
            )
            control = cur.fetchone()
            if control is None or int(control["current_epoch"]) != controller_epoch:
                raise PermissionError("stale controller epoch")
            if not control["scheduling_enabled"] or not control["lease_active"]:
                return []
            cur.execute(
                """
                SELECT ta.attempt_id, ta.task_id
                FROM task_attempts AS ta
                JOIN parent_tasks AS parent
                  ON parent.active_attempt_id = ta.attempt_id
                 AND parent.task_id = ta.task_id
                 AND parent.run_id = ta.run_id
                WHERE ta.run_id = %s
                  AND ta.status = 'running'
                  AND ta.lease_expires_at <= clock_timestamp()
                ORDER BY ta.task_id
                """,
                (run_id,),
            )
            rows = cur.fetchall()
        for row in rows:
            if self.idempotent_cleanup(
                row["attempt_id"],
                run_id=run_id,
                controller_epoch=controller_epoch,
                max_retries=max_retries,
            ):
                stale.append(row["task_id"])
                if record_events:
                    with self.transaction() as cur:
                        self._insert_event_in_transaction(
                            cur,
                            run_id=run_id,
                            controller_epoch=controller_epoch,
                            event_type="child_stale",
                            detail={"task_id": row["task_id"], "retryable": True},
                        )
                        self._insert_event_in_transaction(
                            cur,
                            run_id=run_id,
                            controller_epoch=controller_epoch,
                            event_type="retry_queued",
                            detail={"task_id": row["task_id"], "reason": "lease_expired"},
                        )
        return stale

    def _insert_event_in_transaction(
        self,
        cur: Any,
        *,
        run_id: str,
        controller_epoch: int,
        event_type: str,
        detail: dict[str, Any],
    ) -> str:
        """Append an event while the caller's state transaction is open."""
        cur.execute(
            "SELECT longspan_next_event_seq(%s, %s) AS event_seq",
            (run_id, controller_epoch),
        )
        sequence = cur.fetchone()
        if sequence is None:
            raise PermissionError("event sequence allocation lost the controller epoch")
        event_id = uuid.uuid4().hex
        cur.execute(
            """
            INSERT INTO supervisor_events
                (event_id, event_seq, run_id, controller_epoch, event_type,
                 occurred_at, detail_json)
            VALUES (%s, %s, %s, %s, %s, clock_timestamp(), %s)
            """,
            (
                event_id,
                int(sequence["event_seq"]),
                run_id,
                controller_epoch,
                event_type,
                json.dumps(detail, sort_keys=True),
            ),
        )
        return event_id

    def emit_event(
        self,
        run_id: str,
        event_type: str,
        detail: dict[str, Any],
        *,
        controller_epoch: int,
    ) -> str:
        with self.transaction() as cur:
            self._assert_controller_epoch(
                cur, run_id, controller_epoch, scope_kind="controller"
            )
            event_id = self._insert_event_in_transaction(
                cur,
                run_id=run_id,
                controller_epoch=controller_epoch,
                event_type=event_type,
                detail=detail,
            )
        return event_id

    def events(self, run_id: str) -> list[dict[str, Any]]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT event_id, event_seq, run_id, controller_epoch, event_type,
                       occurred_at, detail_json
                FROM supervisor_events WHERE run_id = %s ORDER BY event_seq
                """,
                (run_id,),
            )
            rows = []
            for row in cur.fetchall():
                item = row_to_dict(row)
                item["detail"] = json.loads(item.pop("detail_json"))
                rows.append(item)
            return rows

    def latest_event_seq(self, run_id: str) -> int:
        with self.transaction() as cur:
            cur.execute(
                "SELECT COALESCE(MAX(event_seq), 0) AS event_seq "
                "FROM supervisor_events WHERE run_id = %s",
                (run_id,),
            )
            return int(cur.fetchone()["event_seq"])

    def append_evidence(
        self,
        *,
        run_id: str,
        controller_epoch: int,
        artifact_path: str,
        sha256: str,
        byte_count: int,
        producer: str,
        result: str,
        task_id: str | None = None,
        attempt_id: str | None = None,
        fence_token: int | None = None,
    ) -> str:
        evidence_id = uuid.uuid4().hex
        with self.transaction() as cur:
            self._assert_controller_epoch(
                cur, run_id, controller_epoch, scope_kind="controller"
            )
            cur.execute(
                """
                INSERT INTO evidence_index
                    (evidence_id, run_id, task_id, attempt_id, fence_token,
                     artifact_path, sha256, byte_count, producer, result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    evidence_id,
                    run_id,
                    task_id,
                    attempt_id,
                    fence_token,
                    artifact_path,
                    sha256,
                    byte_count,
                    producer,
                    result,
                ),
            )
        return evidence_id

    def evidence(self, run_id: str) -> list[dict[str, Any]]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT evidence_id, run_id, task_id, attempt_id, fence_token,
                       artifact_path, sha256, byte_count, producer, result, created_at
                FROM evidence_index WHERE run_id = %s ORDER BY created_at, evidence_id
                """,
                (run_id,),
            )
            return [row_to_dict(row) for row in cur.fetchall()]

    def seed_required_manifest(self, rows: list[dict[str, Any]]) -> None:
        with self.transaction() as cur:
            for row in rows:
                cur.execute(
                    """
                    INSERT INTO required_manifest_entries
                        (entry_id, artifact_path, expected_sha256, producer)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (entry_id) DO UPDATE
                    SET artifact_path = EXCLUDED.artifact_path,
                        expected_sha256 = EXCLUDED.expected_sha256,
                        producer = EXCLUDED.producer
                    """,
                    (
                        row["entry_id"],
                        row["artifact_path"],
                        row.get("expected_sha256"),
                        row["producer"],
                    ),
                )

    def submit_manifest_entry(
        self,
        *,
        run_id: str,
        entry: ManifestEntry,
        controller_epoch: int,
    ) -> str:
        submission_id = uuid.uuid4().hex
        with self.transaction() as cur:
            self._assert_controller_epoch(
                cur, run_id, controller_epoch, scope_kind="controller"
            )
            cur.execute(
                """
                SELECT artifact_path, expected_sha256, producer
                FROM required_manifest_entries WHERE entry_id = %s
                FOR SHARE
                """,
                (entry.entry_id,),
            )
            expected = cur.fetchone()
            if expected is None:
                raise PermissionError("manifest entry is not approved")
            if entry.artifact_path != expected["artifact_path"]:
                raise ValueError("manifest artifact path is not approved")
            if entry.producer != expected["producer"]:
                raise ValueError("manifest producer is not approved")
            if entry.result == "pass" and (
                not expected["expected_sha256"]
                or entry.sha256 != expected["expected_sha256"]
            ):
                raise ValueError("manifest pass does not match the approved artifact hash")
            cur.execute(
                """
                INSERT INTO manifest_submissions
                    (submission_id, run_id, entry_id, artifact_path, sha256, producer, result)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    submission_id,
                    run_id,
                    entry.entry_id,
                    entry.artifact_path,
                    entry.sha256,
                    entry.producer,
                    entry.result,
                ),
            )
        return submission_id

    def readiness(self, run_id: str) -> ReadinessReport:
        with self.transaction() as cur:
            cur.execute("SELECT entry_id, artifact_path, expected_sha256, producer FROM required_manifest_entries")
            required = {row["entry_id"]: row_to_dict(row) for row in cur.fetchall()}
            cur.execute(
                """
                SELECT DISTINCT ON (entry_id) entry_id, artifact_path, sha256, producer, result
                FROM manifest_submissions
                WHERE run_id = %s
                ORDER BY entry_id, created_at DESC, submission_id DESC
                """,
                (run_id,),
            )
            submissions = {
                row["entry_id"]: ManifestEntry(
                    entry_id=row["entry_id"],
                    artifact_path=row["artifact_path"],
                    sha256=row["sha256"],
                    producer=row["producer"],
                    result=row["result"],
                )
                for row in cur.fetchall()
            }
            cur.execute(
                "SELECT verified, reviewed_sha, commit_sha, tree_sha "
                "FROM provenance_records WHERE run_id = %s",
                (run_id,),
            )
            prov = cur.fetchone()
            provenance_verified = bool(
                prov
                and prov["verified"]
                and prov["reviewed_sha"] == prov["commit_sha"]
                and prov["tree_sha"]
            )
        return compute_readiness(
            required=required,
            submissions=submissions,
            provenance_verified=provenance_verified,
        )

    def set_provenance(
        self,
        run_id: str,
        *,
        reviewed_sha: str,
        commit_sha: str,
        tree_sha: str,
        build_sha: str | None = None,
        activation_sha: str | None = None,
        verified: bool,
        controller_epoch: int | None = None,
    ) -> None:
        with self.transaction() as cur:
            if controller_epoch is None:
                cur.execute(
                    """
                    SELECT current_epoch
                    FROM controller_control
                    WHERE run_id = %s
                      AND (
                          current_database() ~ '^td_test_'
                          OR current_database() ~ '^td_downgrade_'
                      )
                    """,
                    (run_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise PermissionError(
                        "set_provenance requires the active controller epoch"
                    )
                controller_epoch = int(row["current_epoch"])
            self._assert_controller_epoch(
                cur, run_id, controller_epoch, scope_kind="controller"
            )
            cur.execute(
                """
                INSERT INTO provenance_records
                    (run_id, reviewed_sha, commit_sha, tree_sha, build_sha, activation_sha, verified)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_id) DO UPDATE
                SET reviewed_sha = EXCLUDED.reviewed_sha,
                    commit_sha = EXCLUDED.commit_sha,
                    tree_sha = EXCLUDED.tree_sha,
                    build_sha = EXCLUDED.build_sha,
                    activation_sha = EXCLUDED.activation_sha,
                    verified = EXCLUDED.verified,
                    updated_at = clock_timestamp()
                """,
                (run_id, reviewed_sha, commit_sha, tree_sha, build_sha, activation_sha, verified),
            )

    def update_signal_status(
        self,
        run_id: str,
        status_json: str,
        readiness: str,
        seq: int,
        *,
        controller_epoch: int,
        allow_disabled: bool = False,
    ) -> None:
        with self.transaction() as cur:
            if allow_disabled:
                cur.execute(
                    "SELECT longspan_open_rollback_signal_scope(%s, %s)",
                    (run_id, controller_epoch),
                )
            else:
                self._assert_controller_epoch(
                    cur, run_id, controller_epoch, scope_kind="controller"
                )
            cur.execute(
                """
                INSERT INTO signal_status (run_id, status_json, readiness, last_event_seq, updated_at)
                VALUES (%s, %s, %s, %s, clock_timestamp())
                ON CONFLICT (run_id) DO UPDATE
                SET status_json = CASE
                        WHEN EXCLUDED.last_event_seq >= signal_status.last_event_seq
                        THEN EXCLUDED.status_json ELSE signal_status.status_json END,
                    readiness = CASE
                        WHEN EXCLUDED.last_event_seq >= signal_status.last_event_seq
                        THEN EXCLUDED.readiness ELSE signal_status.readiness END,
                    last_event_seq = GREATEST(signal_status.last_event_seq, EXCLUDED.last_event_seq),
                    updated_at = clock_timestamp()
                """,
                (run_id, status_json, readiness, seq),
            )

    def get_signal_status(self, run_id: str) -> dict[str, Any] | None:
        with self.transaction() as cur:
            cur.execute(
                "SELECT status_json, readiness, last_event_seq FROM signal_status WHERE run_id = %s",
                (run_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return {
                "status": json.loads(row["status_json"]),
                "readiness": row["readiness"],
                "last_event_seq": int(row["last_event_seq"]),
            }

    def _park_longspan_children(self, cur: Any, run_id: str) -> None:
        cur.execute(
            """
            UPDATE longspan_children
            SET state = 'parked',
                updated_at = clock_timestamp(),
                version = version + 1,
                manager_capability_hash = NULL,
                executor_capability_hash = NULL,
                auditor_capability_hash = NULL,
                lease_token_hash = NULL,
                lease_expires_at = NULL
            WHERE run_id = %s
              AND state NOT IN ('parent_returned', 'parked', 'cancelled')
            """,
            (run_id,),
        )
        cur.execute(
            """
            SELECT COUNT(*) AS count FROM longspan_children
            WHERE run_id = %s
              AND state NOT IN ('parent_returned', 'parked', 'cancelled')
            """,
            (run_id,),
        )
        if int(cur.fetchone()["count"]) != 0:
            raise PermissionError("longspan child parking incomplete")

    def rollback_disable(self, run_id: str, *, expected_epoch: int) -> int:
        with self.transaction() as cur:
            # Keep controller_control as the first lock, matching every other
            # fenced mutator; this serializes rollback against old-epoch writes.
            self._assert_controller_epoch(
                cur, run_id, expected_epoch, scope_kind="controller"
            )
            cur.execute(
                """
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = 'longspan_children'
                """
            )
            if cur.fetchone() is not None:
                self._park_longspan_children(cur, run_id)
            cur.execute(
                """
                UPDATE task_attempts
                SET status = 'stale', ended_at = COALESCE(ended_at, clock_timestamp())
                WHERE run_id = %s AND status = 'running'
                """,
                (run_id,),
            )
            cur.execute(
                """
                UPDATE parent_tasks
                SET state = 'parked', active_attempt_id = NULL, updated_at = clock_timestamp()
                WHERE run_id = %s AND state IN ('queued', 'leased')
                """,
                (run_id,),
            )
            cur.execute(
                """
                UPDATE retry_queue SET state = 'parked'
                WHERE run_id = %s AND state = 'queued'
                """,
                (run_id,),
            )
            cur.execute(
                "SELECT longspan_next_event_seq(%s, %s) AS event_seq",
                (run_id, expected_epoch),
            )
            sequence = cur.fetchone()
            if sequence is None:
                raise PermissionError("rollback event sequence allocation lost the controller epoch")
            cur.execute(
                """
                INSERT INTO supervisor_events
                    (event_id, event_seq, run_id, controller_epoch, event_type, occurred_at, detail_json)
                VALUES (%s, %s, %s, %s, 'rollback_disabled', clock_timestamp(), %s)
                """,
                (
                    uuid.uuid4().hex,
                    int(sequence["event_seq"]),
                    run_id,
                    expected_epoch,
                    json.dumps({"scheduling_enabled": False}, sort_keys=True),
                ),
            )
            cur.execute(
                "SELECT longspan_disable_controller(%s, %s) AS current_epoch",
                (run_id, expected_epoch),
            )
            row = cur.fetchone()
            if row is None:
                raise PermissionError("rollback lost the controller epoch race")
            return int(row["current_epoch"])

    def idempotent_cleanup(
        self, attempt_id: str, *, run_id: str, controller_epoch: int,
        max_retries: int = 5
    ) -> bool:
        validate_max_retries(max_retries)
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT current_epoch, scheduling_enabled,
                       lease_expires_at > clock_timestamp() AS lease_active
                FROM controller_control
                WHERE run_id = %s
                """,
                (run_id,),
            )
            control = cur.fetchone()
            if control is None or not control["scheduling_enabled"] or not control["lease_active"]:
                return False
            live_epoch = int(control["current_epoch"])
            if live_epoch < controller_epoch:
                return False
            cur.execute(
                """
                SELECT current_epoch, scheduling_enabled,
                       lease_expires_at > clock_timestamp() AS lease_active
                FROM controller_control
                WHERE run_id = %s
                """,
                (run_id,),
            )
            control = cur.fetchone()
            if control is None or not control["scheduling_enabled"] or not control["lease_active"]:
                return False
            live_epoch = int(control["current_epoch"])
            if live_epoch < controller_epoch:
                return False
            cur.execute(
                """
                SELECT longspan_cleanup_expired_parent_attempt(
                    %s, %s, %s, %s
                ) AS result
                """,
                (run_id, attempt_id, live_epoch, max_retries),
            )
            row = cur.fetchone()
            if row is None:
                return False
            return bool(row["result"])

    def create_subworkflow_handoff(
        self,
        *,
        run_id: str,
        parent_task_id: str,
        parent_attempt_id: str,
        parent_fence_token: int,
        controller_epoch: int,
        handoff_id: str,
        provider_task_id: str,
        failure_code: str,
        provider_key: str,
        product_contract: str,
        request_json: dict[str, Any],
        request_digest: str,
        provider_objective: str,
        provider_priority: int,
    ) -> dict[str, Any]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_create_subworkflow_handoff(
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                ) AS result
                """,
                (
                    run_id, parent_task_id, parent_attempt_id, parent_fence_token,
                    controller_epoch, handoff_id, provider_task_id, failure_code,
                    provider_key, product_contract, json.dumps(request_json, sort_keys=True),
                    request_digest, provider_objective, provider_priority,
                ),
            )
            payload = cur.fetchone()["result"]
            return json.loads(payload) if isinstance(payload, str) else payload

    def complete_subworkflow_handoff(
        self,
        *,
        handoff_id: str,
        run_id: str,
        provider_task_id: str,
        provider_attempt_id: str,
        provider_fence_token: int,
        controller_epoch: int,
        product_json: dict[str, Any],
        product_digest: str,
    ) -> dict[str, Any]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_complete_subworkflow_handoff(
                    %s,%s,%s,%s,%s,%s,%s,%s
                ) AS result
                """,
                (
                    handoff_id, run_id, provider_task_id, provider_attempt_id,
                    provider_fence_token, controller_epoch,
                    json.dumps(product_json, sort_keys=True), product_digest,
                ),
            )
            payload = cur.fetchone()["result"]
            return json.loads(payload) if isinstance(payload, str) else payload

    def expire_subworkflow_handoff(
        self, *, handoff_id: str, run_id: str, controller_epoch: int, reason: str
    ) -> dict[str, Any]:
        with self.transaction() as cur:
            cur.execute(
                "SELECT longspan_expire_subworkflow_handoff(%s,%s,%s,%s) AS result",
                (handoff_id, run_id, controller_epoch, reason[:240]),
            )
            payload = cur.fetchone()["result"]
            return json.loads(payload) if isinstance(payload, str) else payload

    def ingest_project_program(self, parsed: ParsedProgram) -> dict[str, Any]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_ingest_project_program(
                    %s, %s, %s, %s, %s::jsonb
                ) AS payload
                """,
                (
                    parsed.project_id,
                    parsed.project_version,
                    parsed.schema_version,
                    parsed.program_digest,
                    json.dumps(nodes_payload(parsed)),
                ),
            )
            row = cur.fetchone()
            if row is None or row["payload"] is None:
                raise RuntimeError("project program ingest returned no payload")
            payload = row["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            return dict(payload)

    def get_project_node_ledger(
        self,
        project_id: str,
        project_version: str,
        node_id: str,
    ) -> dict[str, Any]:
        with self.transaction(authorize_disposable=False) as cur:
            cur.execute(
                """
                SELECT longspan_get_project_node_ledger(%s, %s, %s) AS payload
                """,
                (project_id, project_version, node_id),
            )
            row = cur.fetchone()
            if row is None or row["payload"] is None:
                raise KeyError(node_id)
            payload = row["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            return dict(payload)

    def detect_missing_prerequisites(
        self,
        project_id: str,
        project_version: str,
        node_id: str,
        satisfied_nodes: list[str],
    ) -> dict[str, Any]:
        with self.transaction(authorize_disposable=False) as cur:
            cur.execute(
                """
                SELECT longspan_detect_missing_prerequisites(%s, %s, %s, %s::jsonb) AS payload
                """,
                (
                    project_id,
                    project_version,
                    node_id,
                    json.dumps(list(satisfied_nodes)),
                ),
            )
            row = cur.fetchone()
            payload = row["payload"] if row is not None else None
            if payload is None:
                return {"missing": []}
            if isinstance(payload, str):
                payload = json.loads(payload)
            return dict(payload)

    def record_prerequisite_decision(
        self,
        *,
        run_id: str,
        target_node_id: str,
        prerequisite_node_id: str,
        request_digest: str,
        reused: bool,
        delivered_by: str | None,
        reason: str,
        artifact_digest: str,
        handoff_id: str | None,
    ) -> dict[str, Any]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_record_prerequisite_decision(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) AS payload
                """,
                (
                    run_id,
                    target_node_id,
                    prerequisite_node_id,
                    request_digest,
                    reused,
                    delivered_by,
                    reason,
                    artifact_digest,
                    handoff_id,
                ),
            )
            payload = cur.fetchone()["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            return dict(payload)

    def record_correlation_qa(
        self,
        *,
        run_id: str,
        request_id: str,
        question_kind: str,
        question_json: dict[str, Any],
        question_digest: str,
        answer_json: dict[str, Any],
        answer_digest: str,
    ) -> dict[str, Any]:
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_record_correlation_qa(
                    %s, %s, %s, %s::jsonb, %s, %s::jsonb, %s
                ) AS payload
                """,
                (
                    run_id,
                    request_id,
                    question_kind,
                    json.dumps(question_json, sort_keys=True),
                    question_digest,
                    json.dumps(answer_json, sort_keys=True),
                    answer_digest,
                ),
            )
            payload = cur.fetchone()["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            return dict(payload)

    def get_correlation_answer(self, *, run_id: str, request_id: str) -> dict[str, Any] | None:
        with self.transaction(authorize_disposable=False) as cur:
            cur.execute(
                "SELECT longspan_get_correlation_answer(%s, %s) AS payload",
                (run_id, request_id),
            )
            row = cur.fetchone()
            if row is None or row["payload"] is None:
                return None
            payload = row["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            return dict(payload)

    def reconnect(self) -> None:
        """Simulate PostgreSQL restart by reopening the connection."""
        self._conn.close()
        if self.connection_mode == "authority":
            self._conn = connect_authority(self.db_url)
        else:
            self._conn = connect(self.db_url)
