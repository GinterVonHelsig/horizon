"""PostgreSQL persistence for the Longspan child workflow."""

from __future__ import annotations

import json
import hashlib
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

import psycopg2
from psycopg2 import errors as pg_errors

from authority_socket import AuthorityWriteCredential
from authority_service_client import (
    invalidate_terra_receipt_attestation,
    request_terra_receipt_attestation,
    verify_terra_receipt_gateway_binding,
)
from comms01_scope import assert_comms01_entrypoint
from db import (
    CANONICAL_ALEMBIC_HEAD,
    authorize_disposable_test_mutation,
    connect,
    row_to_dict,
)
from exceptions import (
    AuthorityServiceCapacityError,
    AuthorityServiceUnavailableError,
    AuthorizationFailureError,
    IntegrityFailureError,
    LeaseExpiredError,
    StaleFenceError,
)
from longspan_crypto import (
    compute_ledger_entry_hash,
    digest_payload,
    hash_capability_token,
    verify_capability_hash,
)
from repository import PostgresRepository, retry_queue_key, validate_max_retries
from parent_controller import generation_for_fence_token
from terra_receipt_attestation import (
    terra_receipt_signature_components,
    verify_terra_receipt_signature,
)


CHILD_STATES = frozenset(
    {
        "ready",
        "planned",
        "executing",
        "executed",
        "auditing",
        "needs_remediation",
        "verified",
        "terra_pending",
        "terra_approved",
        "terra_rejected",
        "retry_wait",
        "parent_returned",
        "parked",
        "cancelled",
        "expired",
    }
)

EXPERIMENT_CLASSIFICATIONS = frozenset(
    {"observation", "playbook", "workflow", "code", "policy"}
)

PROTECTED_AUTHORITY_TARGETS = frozenset(
    {
        "authority",
        "acceptance_criteria",
        "model_routing",
        "release_gates",
        "policy",
    }
)

OPERATOR_APPROVAL_CLASSIFICATIONS = frozenset({"workflow", "code", "policy"})

TERMINAL_CHILD_STATES = frozenset({"parent_returned", "parked", "cancelled"})
RESUMABLE_CHILD_STATES = frozenset({"retry_wait", "terra_rejected", "needs_remediation"})
BLOCKING_CHILD_STATES = frozenset(
    {
        "ready",
        "planned",
        "executing",
        "executed",
        "terra_pending",
        "terra_approved",
    }
)

PARENT_LEDGER_EVENT_TYPES = frozenset({"retry_resumed", "cycle_failure"})


class LongspanRepository:
    def __init__(self, repo: PostgresRepository) -> None:
        self._repo = repo

    @classmethod
    def from_url(cls, db_url: str) -> LongspanRepository:
        return cls(PostgresRepository(db_url))

    def close(self) -> None:
        self._repo.close()

    @property
    def repo(self) -> PostgresRepository:
        return self._repo

    def _assert_longspan_writes_allowed(
        self,
        cur: Any,
        run_id: str,
        controller_epoch: int,
        *,
        fence_token: int | None = None,
        controller_scope: bool = False,
        controller_operation: str = "general",
    ) -> None:
        if controller_scope:
            if fence_token is not None:
                raise StaleFenceError("controller scope cannot carry a task fence")
            self._repo._assert_controller_epoch(
                cur,
                run_id,
                controller_epoch,
                scope_kind="controller",
                controller_operation=controller_operation,
            )
        else:
            if fence_token is None or int(fence_token) <= 0:
                raise StaleFenceError("longspan write requires an explicit parent fence")
            self._repo._assert_controller_epoch(
                cur,
                run_id,
                controller_epoch,
                scope_kind="workflow",
                fence_token=fence_token,
            )
        cur.execute(
            "SELECT set_config('top_delivery.controller_epoch', %s, true)",
            (str(controller_epoch),),
        )

    def _assert_parent_fence(
        self,
        child: dict[str, Any],
        *,
        parent_attempt_id: str,
        fence_token: int,
    ) -> None:
        if child["parent_attempt_id"] != parent_attempt_id:
            raise StaleFenceError("stale parent attempt for child write")
        if int(child["fence_token"]) != int(fence_token):
            raise StaleFenceError("stale parent fence token for child write")

    @staticmethod
    def _lock_child_mutation(cur: Any, child_id: str) -> None:
        """Take the database writer lock shared by every result/audit writer."""
        cur.execute(
            "SELECT pg_advisory_xact_lock(8101, hashtext(%s))",
            (child_id,),
        )

    def provision_authority_config(
        self,
        *,
        run_id: str,
        terra_auth_hash: str,
        operator_auth_hash: str,
        reviewed_sha: str,
        controller_epoch: int,
    ) -> dict[str, Any]:
        raise AuthorizationFailureError(
            "workflow cannot self-provision authority; use Comms01AuthorityBoundary"
        )

    def insert_authority_config(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AuthorizationFailureError(
            "workflow/controller cannot write authority configuration; use authority service"
        )

    def rotate_authority_config(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AuthorizationFailureError(
            "workflow/controller cannot rotate authority configuration; use authority service"
        )

    def get_authority_config(self, run_id: str) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            return self._load_authority_config(cur, run_id)

    def persist_operator_challenge(
        self,
        *,
        approval_id: str,
        run_id: str,
        action_type: str,
        action_digest: str,
        operator_identity: str,
        nonce: str,
        expires_at: str,
        key_version: int,
        challenge_digest: str,
        controller_epoch: int,
        config_version: int,
        challenge_epoch: int,
    ) -> None:
        assert_comms01_entrypoint(scope="comms-01")
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur,
                run_id,
                controller_epoch,
                controller_scope=True,
            )
            try:
                cur.execute(
                    """
                    SELECT longspan_create_operator_challenge(
                        %s, %s, %s, %s, %s, %s, %s::timestamptz, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        approval_id,
                        run_id,
                        action_type,
                        action_digest,
                        operator_identity,
                        nonce,
                        expires_at,
                        key_version,
                        challenge_digest,
                        controller_epoch,
                        config_version,
                        challenge_epoch,
                    ),
                )
            except Exception as exc:
                raise AuthorizationFailureError(
                    f"operator challenge persistence failed: {exc}"
                ) from exc

    def bind_operator_write_credential(self, *args: Any, **kwargs: Any) -> None:
        raise AuthorizationFailureError(
            "workflow/controller cannot bind authority write credentials; use authority service"
        )

    def consume_operator_challenge(
        self,
        *,
        approval_id: str,
        action_digest: str,
        controller_epoch: int,
        run_id: str,
    ) -> None:
        raise AuthorizationFailureError(
            "operator challenge consumption must occur atomically with authority writes"
        )

    def get_execution_audit(self, child_id: str, attempt_number: int) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT audit_id, child_id, attempt_number, request_digest, evidence_digest,
                       result_digest, validation_outcome, raw_result_ref, created_at
                FROM longspan_execution_audits
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError((child_id, attempt_number))
            return row_to_dict(row)

    def get_auditor_snapshot(self, child_id: str, attempt_number: int) -> dict[str, Any]:
        """Read every auditor input from one repeatable-read database snapshot.

        The auditor must never combine plan/result/evidence/audit/ledger rows
        observed in separate transactions. A concurrent retry or tampering
        attempt could otherwise make each individual read look valid while the
        combined verdict describes no single committed database state.
        """
        with self._repo.transaction(authorize_disposable=False) as cur:
            # No statement has executed yet in this repository transaction;
            # set the isolation before reading any state.
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            authorize_disposable_test_mutation(
                self._repo._conn, self._repo.db_url, cursor=cur
            )
            cur.execute("SELECT current_setting('transaction_isolation') AS isolation")
            isolation_row = cur.fetchone()
            if isolation_row is None or isolation_row["isolation"] != "repeatable read":
                raise IntegrityFailureError(
                    "auditor snapshot did not establish repeatable-read isolation"
                )
            cur.execute(
                """
                SELECT child_id, task_id, run_id, parent_attempt_id, fence_token,
                       state, idempotency_key, request_digest, attempt_number, version,
                       lease_token_hash, lease_expires_at, manager_capability_hash,
                       executor_capability_hash, auditor_capability_hash,
                       created_at, updated_at
                FROM longspan_children
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            child_row = cur.fetchone()
            if child_row is None:
                raise KeyError((child_id, attempt_number))
            cur.execute(
                """
                SELECT plan_id, child_id, attempt_number, objective,
                       acceptance_criteria_json, scope, plan_digest, created_at
                FROM longspan_plans
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            plan_row = cur.fetchone()
            if plan_row is None:
                raise KeyError((child_id, attempt_number))
            plan = row_to_dict(plan_row)
            plan["acceptance_criteria"] = json.loads(plan.pop("acceptance_criteria_json"))

            cur.execute(
                """
                SELECT result_id, child_id, attempt_number, outcome, result_digest,
                       artifact_refs_json, created_at
                FROM longspan_execution_results
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            result_row = cur.fetchone()
            if result_row is None:
                raise KeyError((child_id, attempt_number))
            execution = row_to_dict(result_row)
            execution["artifact_refs"] = json.loads(execution.pop("artifact_refs_json"))

            cur.execute(
                """
                SELECT evidence_id, child_id, attempt_number, evidence_json,
                       evidence_digest, created_at
                FROM longspan_execution_evidence
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            evidence_row = cur.fetchone()
            if evidence_row is None:
                raise KeyError((child_id, attempt_number))
            evidence = row_to_dict(evidence_row)

            cur.execute(
                """
                SELECT audit_id, child_id, attempt_number, request_digest,
                       evidence_digest, result_digest, validation_outcome,
                       raw_result_ref, created_at
                FROM longspan_execution_audits
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            audit_row = cur.fetchone()
            if audit_row is None:
                raise KeyError((child_id, attempt_number))
            audit = row_to_dict(audit_row)

            cur.execute(
                """
                SELECT entry_id, child_id, attempt_number, sequence_number,
                       event_type, producer_role, payload_digest,
                       previous_entry_hash, entry_hash, base_digest,
                       mac_key_version, created_at
                FROM longspan_evidence_ledger
                WHERE child_id = %s
                ORDER BY sequence_number
                """,
                (child_id,),
            )
            ledger_entries = [row_to_dict(row) for row in cur.fetchall()]
            return {
                "child": row_to_dict(child_row),
                "transaction_isolation": isolation_row["isolation"],
                "plan": plan,
                "execution": execution,
                "evidence": evidence,
                "audit": audit,
                "ledger_entries": ledger_entries,
            }

    def _load_authority_config(self, cur: Any, run_id: str) -> dict[str, Any]:
        # The workflow role is intentionally read-only on authority tables;
        # PostgreSQL row-locking clauses require privileges beyond the
        # controller's grant on this protected table.  The enclosing Terra
        # transaction takes an advisory lock shared by the authority mutation
        # routines instead.
        cur.execute(
            """
            SELECT run_id, terra_auth_hash, operator_auth_hash, reviewed_sha,
                   tree_sha, source_digest, config_version, approval_receipt_digest
            FROM longspan_authority_config
            WHERE run_id = %s
            """,
            (run_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise AuthorizationFailureError("longspan authority is not provisioned for run")
        return row_to_dict(row)

    def _ledger_head(self, cur: Any, child_id: str) -> str | None:
        cur.execute(
            """
            SELECT entry_hash FROM longspan_evidence_ledger
            WHERE child_id = %s
            ORDER BY sequence_number DESC
            LIMIT 1
            """,
            (child_id,),
        )
        row = cur.fetchone()
        return row["entry_hash"] if row is not None else None

    def _require_attempt_ledger_events(
        self,
        cur: Any,
        *,
        child_id: str,
        attempt_number: int,
        required: tuple[str, ...],
    ) -> None:
        cur.execute(
            """
            SELECT event_type, payload_digest
            FROM longspan_evidence_ledger
            WHERE child_id = %s AND attempt_number = %s
            """,
            (child_id, attempt_number),
        )
        found = {row["event_type"]: row["payload_digest"] for row in cur.fetchall()}
        missing = [event for event in required if event not in found]
        if missing:
            raise PermissionError(f"missing ledger events for attempt: {missing}")

    def _derive_protected_targets(
        self, *, classification: str, hypothesis: str, scope: str, baseline: str
    ) -> list[str]:
        text = f"{classification} {hypothesis} {scope} {baseline}".lower()
        targets: list[str] = []
        if classification in OPERATOR_APPROVAL_CLASSIFICATIONS:
            targets.append("operator_approval_required")
        for target in PROTECTED_AUTHORITY_TARGETS:
            if target.replace("_", "-") in text or target.replace("_", " ") in text:
                targets.append(target)
        return sorted(set(targets))

    def _transition_child(
        self,
        cur: Any,
        *,
        child_id: str,
        expected_version: int,
        new_state: str,
        manager_capability_hash: str | None = None,
        executor_capability_hash: str | None = None,
        auditor_capability_hash: str | None = None,
        lease_expires_at: datetime | None = None,
        bump_attempt: bool = False,
        clear_capabilities: bool = False,
    ) -> dict[str, Any]:
        if new_state not in CHILD_STATES:
            raise ValueError("invalid longspan child state")
        cur.execute(
            """
            UPDATE longspan_children
            SET state = %s,
                version = version + 1,
                manager_capability_hash = CASE
                    WHEN %s THEN NULL
                    ELSE COALESCE(%s, manager_capability_hash) END,
                executor_capability_hash = CASE
                    WHEN %s THEN NULL
                    ELSE COALESCE(%s, executor_capability_hash) END,
                auditor_capability_hash = CASE
                    WHEN %s THEN NULL
                    ELSE COALESCE(%s, auditor_capability_hash) END,
                lease_token_hash = CASE
                    WHEN %s THEN NULL
                    ELSE lease_token_hash END,
                lease_expires_at = CASE
                    WHEN %s THEN NULL
                    ELSE COALESCE(%s, lease_expires_at) END,
                attempt_number = CASE WHEN %s THEN attempt_number + 1 ELSE attempt_number END,
                updated_at = clock_timestamp()
            WHERE child_id = %s AND version = %s
            RETURNING child_id, task_id, run_id, parent_attempt_id, fence_token,
                      state, idempotency_key, request_digest, attempt_number, version,
                      lease_token_hash, lease_expires_at, manager_capability_hash,
                      executor_capability_hash, auditor_capability_hash,
                      created_at, updated_at
            """,
            (
                new_state,
                clear_capabilities,
                manager_capability_hash,
                clear_capabilities,
                executor_capability_hash,
                clear_capabilities,
                auditor_capability_hash,
                clear_capabilities,
                clear_capabilities,
                lease_expires_at,
                bump_attempt,
                child_id,
                expected_version,
            ),
        )
        row = cur.fetchone()
        if row is None:
            raise PermissionError("stale longspan child version or unknown child")
        return row_to_dict(row)

    def register_child(
        self,
        *,
        run_id: str,
        task_id: str,
        parent_attempt_id: str,
        fence_token: int,
        idempotency_key: str,
        request_digest: str,
        controller_epoch: int,
        manager_capability_hash: str,
        executor_capability_hash: str,
        lease_seconds: float,
    ) -> tuple[dict[str, Any], bool]:
        if not idempotency_key or not request_digest:
            raise ValueError("idempotency_key and request_digest are required")
        assert_comms01_entrypoint(scope="comms-01")
        child_id = uuid.uuid4().hex
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            cur.execute(
                """
                INSERT INTO longspan_children
                    (child_id, task_id, run_id, parent_attempt_id, fence_token, state,
                     idempotency_key, request_digest, attempt_number, version,
                     manager_capability_hash, executor_capability_hash,
                     lease_token_hash, lease_expires_at)
                VALUES (%s, %s, %s, %s, %s, 'ready', %s, %s, 0, 0, %s, %s, %s,
                        clock_timestamp() + (%s || ' seconds')::interval)
                ON CONFLICT (idempotency_key) DO NOTHING
                RETURNING child_id, task_id, run_id, parent_attempt_id, fence_token,
                          state, idempotency_key, request_digest, attempt_number, version,
                          lease_token_hash, lease_expires_at, manager_capability_hash,
                          executor_capability_hash, auditor_capability_hash,
                          created_at, updated_at
                """,
                (
                    child_id,
                    task_id,
                    run_id,
                    parent_attempt_id,
                    fence_token,
                    idempotency_key,
                    request_digest,
                    manager_capability_hash,
                    executor_capability_hash,
                    manager_capability_hash,
                    lease_seconds,
                ),
            )
            inserted = cur.fetchone()
            if inserted is not None:
                return row_to_dict(inserted), True
            cur.execute(
                """
                SELECT child_id, task_id, run_id, parent_attempt_id, fence_token,
                       state, idempotency_key, request_digest, attempt_number, version,
                       lease_token_hash, lease_expires_at, manager_capability_hash,
                       executor_capability_hash, auditor_capability_hash,
                       created_at, updated_at
                FROM longspan_children WHERE idempotency_key = %s
                FOR UPDATE
                """,
                (idempotency_key,),
            )
            existing = cur.fetchone()
            if existing is None:
                raise RuntimeError("idempotent child registration lost the race")
            row = row_to_dict(existing)
            if row["request_digest"] != request_digest:
                raise ValueError("duplicate idempotency key with different request digest")
            if (
                row["run_id"] != run_id
                or row["task_id"] != task_id
                or row["parent_attempt_id"] != parent_attempt_id
            ):
                raise ValueError("idempotency key is bound to a different parent task")
            return row, False

    def _fetch_child(self, cur: Any, child_id: str, *, for_update: bool = False) -> dict[str, Any]:
        lock = "FOR UPDATE" if for_update else ""
        cur.execute(
            f"""
            SELECT child_id, task_id, run_id, parent_attempt_id, fence_token,
                   state, idempotency_key, request_digest, attempt_number, version,
                   lease_token_hash, lease_expires_at, manager_capability_hash,
                   executor_capability_hash, auditor_capability_hash,
                   created_at, updated_at
            FROM longspan_children WHERE child_id = %s {lock}
            """,
            (child_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise KeyError(child_id)
        return row_to_dict(row)

    def get_child(self, child_id: str) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            return self._fetch_child(cur, child_id)

    def find_resumable_child(self, run_id: str, task_id: str) -> dict[str, Any] | None:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT child_id, task_id, run_id, parent_attempt_id, fence_token,
                       state, idempotency_key, request_digest, attempt_number, version,
                       lease_token_hash, lease_expires_at, manager_capability_hash,
                       executor_capability_hash, auditor_capability_hash,
                       created_at, updated_at
                FROM longspan_children
                WHERE run_id = %s AND task_id = %s AND state = ANY(%s)
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (run_id, task_id, list(RESUMABLE_CHILD_STATES)),
            )
            row = cur.fetchone()
            return row_to_dict(row) if row is not None else None

    def find_blocking_child(self, run_id: str, task_id: str) -> dict[str, Any] | None:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT child_id, task_id, run_id, parent_attempt_id, fence_token,
                       state, idempotency_key, request_digest, attempt_number, version,
                       lease_token_hash, lease_expires_at, manager_capability_hash,
                       executor_capability_hash, auditor_capability_hash,
                       created_at, updated_at
                FROM longspan_children
                WHERE run_id = %s AND task_id = %s AND state = ANY(%s)
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (run_id, task_id, list(BLOCKING_CHILD_STATES)),
            )
            row = cur.fetchone()
            return row_to_dict(row) if row is not None else None

    def find_retry_wait_child(self, run_id: str, task_id: str) -> dict[str, Any] | None:
        return self.find_resumable_child(run_id, task_id)

    def verify_capability_token(
        self, child: dict[str, Any], role: str, capability_token: str
    ) -> None:
        field = {
            "manager": "manager_capability_hash",
            "executor": "executor_capability_hash",
            "auditor": "auditor_capability_hash",
        }.get(role)
        if field is None:
            raise ValueError("invalid role")
        if not capability_token:
            raise AuthorizationFailureError(f"missing {role} capability token")
        stored_hash = child.get(field)
        if not stored_hash or not verify_capability_hash(capability_token, stored_hash):
            raise AuthorizationFailureError(f"stale or unknown {role} capability token")
        expires = child.get("lease_expires_at")
        if expires is not None:
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires.timestamp() <= datetime.now(timezone.utc).timestamp():
                raise LeaseExpiredError("longspan lease expired")

    def resume_retry_wait(
        self,
        *,
        child_id: str,
        expected_version: int,
        parent_attempt_id: str,
        fence_token: int,
        manager_capability_hash: str,
        executor_capability_hash: str,
        controller_epoch: int,
        run_id: str,
        lease_seconds: float,
        request_digest: str,
    ) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            if child["state"] not in RESUMABLE_CHILD_STATES:
                raise PermissionError("child is not waiting for retry resume")
            # A retry may only be resumed by the currently live parent attempt.
            # The child row alone is insufficient: an old parent can otherwise
            # manufacture a fresh lease after its parent lease expired.
            cur.execute(
                """
                SELECT active_attempt_id
                FROM parent_tasks
                WHERE task_id = %s AND run_id = %s
                FOR UPDATE
                """,
                (child["task_id"], run_id),
            )
            parent = cur.fetchone()
            if parent is None or parent["active_attempt_id"] != parent_attempt_id:
                raise StaleFenceError("retry resume parent attempt is not active")
            cur.execute(
                """
                SELECT attempt_id
                FROM task_attempts
                WHERE attempt_id = %s AND task_id = %s AND run_id = %s
                  AND controller_epoch = %s AND fence_token = %s
                  AND status = 'running'
                  AND lease_expires_at > clock_timestamp()
                FOR UPDATE
                """,
                (
                    parent_attempt_id,
                    child["task_id"],
                    run_id,
                    controller_epoch,
                    fence_token,
                ),
            )
            if cur.fetchone() is None:
                raise StaleFenceError("retry resume parent lease is stale or expired")
            bump_attempt = True
            next_attempt = int(child["attempt_number"]) + (1 if bump_attempt else 0)
            cur.execute(
                """
                UPDATE longspan_children
                SET state = 'ready',
                    version = version + 1,
                    parent_attempt_id = %s,
                    fence_token = %s,
                    manager_capability_hash = %s,
                    executor_capability_hash = %s,
                    auditor_capability_hash = NULL,
                    lease_token_hash = %s,
                    lease_expires_at = clock_timestamp() + (%s || ' seconds')::interval,
                    attempt_number = %s,
                    -- The database, not a caller, creates the retry key.  A
                    -- fresh random component prevents stale/replayed retry
                    -- requests from reusing an earlier attempt identity.
                    idempotency_key = encode(
                        digest(
                            convert_to(
                                concat_ws(
                                    ':', child_id, %s::TEXT, %s, gen_random_uuid()::TEXT
                                ),
                                'UTF8'
                            ),
                            'sha256'
                        ),
                        'hex'
                    ),
                    request_digest = %s,
                    updated_at = clock_timestamp()
                WHERE child_id = %s AND version = %s AND state = ANY(%s)
                RETURNING child_id, task_id, run_id, parent_attempt_id, fence_token,
                          state, idempotency_key, request_digest, attempt_number, version,
                          lease_token_hash, lease_expires_at, manager_capability_hash,
                          executor_capability_hash, auditor_capability_hash,
                          created_at, updated_at
                """,
                (
                    parent_attempt_id,
                    fence_token,
                    manager_capability_hash,
                    executor_capability_hash,
                    manager_capability_hash,
                    lease_seconds,
                    next_attempt,
                    next_attempt,
                    parent_attempt_id,
                    request_digest,
                    child_id,
                    expected_version,
                    list(RESUMABLE_CHILD_STATES),
                ),
            )
            row = cur.fetchone()
            if row is None:
                raise PermissionError("stale retry resume")
            return row_to_dict(row)

    def atomic_recover_permission_and_requeue(
        self,
        *,
        child_id: str,
        expected_version: int,
        controller_epoch: int,
        run_id: str,
        task_id: str,
        parent_attempt_id: str,
        fence_token: int,
        reason: str,
        delay_seconds: float = 0.0,
        max_retries: int = 5,
    ) -> dict[str, Any]:
        """One fenced transaction: child -> retry_wait, ledger, parent requeue."""
        validate_max_retries(max_retries)
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            if child["state"] in {"retry_wait", "parent_returned", "parked", "cancelled"}:
                return child
            self._assert_parent_fence(
                child,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
            )
            if int(child["version"]) != expected_version:
                raise StaleFenceError("stale child version for permission recovery")
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
            if parent is None or parent["active_attempt_id"] != parent_attempt_id:
                raise StaleFenceError("permission recovery parent attempt is stale")
            if int(parent["attempt"]) >= max_retries:
                child = self._transition_child(
                    cur,
                    child_id=child_id,
                    expected_version=expected_version,
                    new_state="parked",
                    clear_capabilities=True,
                )
                self._append_ledger_in_transaction(
                    cur,
                    child_id=child_id,
                    attempt_number=int(child["attempt_number"]),
                    event_type="authorization_failure",
                    producer_role="parent",
                    payload_digest=digest_payload(
                        {"reason": reason, "failure_type": "retry_limit"}
                    ),
                    run_id=run_id,
                )
                cur.execute(
                    """
                    UPDATE task_attempts
                    SET status = 'failed', ended_at = clock_timestamp()
                    WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                      AND controller_epoch = %s AND run_id = %s AND status = 'running'
                      AND lease_expires_at > clock_timestamp()
                    """,
                    (parent_attempt_id, task_id, fence_token, controller_epoch, run_id),
                )
                if cur.rowcount != 1:
                    raise StaleFenceError("retry-limit recovery attempt lost the fence")
                cur.execute(
                    """
                    UPDATE parent_tasks
                    SET state = 'failed', active_attempt_id = NULL,
                        updated_at = clock_timestamp()
                    WHERE task_id = %s AND run_id = %s AND active_attempt_id = %s
                    """,
                    (task_id, run_id, parent_attempt_id),
                )
                if cur.rowcount != 1:
                    raise StaleFenceError("retry-limit recovery parent lost the fence")
                return child
            child = self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state="retry_wait",
                clear_capabilities=True,
                bump_attempt=True,
            )
            self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=int(child["attempt_number"]),
                event_type="cycle_failure",
                producer_role="parent",
                payload_digest=digest_payload(
                    {"reason": reason, "failure_type": "execution_error"}
                ),
                run_id=run_id,
            )
            cur.execute(
                """
                UPDATE task_attempts
                SET status = 'failed', ended_at = clock_timestamp()
                WHERE attempt_id = %s AND task_id = %s AND fence_token = %s
                  AND controller_epoch = %s AND run_id = %s AND status = 'running'
                  AND lease_expires_at > clock_timestamp()
                """,
                (parent_attempt_id, task_id, fence_token, controller_epoch, run_id),
            )
            if cur.rowcount != 1:
                raise StaleFenceError("stale or expired parent attempt during recovery")
            cur.execute(
                """
                UPDATE parent_tasks
                SET state = 'queued',
                    available_at = clock_timestamp() + (%s || ' seconds')::interval,
                    attempt = attempt + 1,
                    active_attempt_id = NULL,
                    updated_at = clock_timestamp()
                WHERE task_id = %s AND active_attempt_id = %s AND run_id = %s
                """,
                (delay_seconds, task_id, parent_attempt_id, run_id),
            )
            if cur.rowcount != 1:
                raise StaleFenceError("parent task requeue lost the race")
            retry_key = retry_queue_key(run_id, task_id, int(parent["attempt"]) + 1)
            cur.execute(
                """
                INSERT INTO retry_queue
                    (retry_key, run_id, task_id, available_at, attempt, reason, state)
                VALUES (%s, %s, %s,
                        clock_timestamp() + (%s || ' seconds')::interval,
                        %s, %s, 'queued')
                """,
                (
                    retry_key,
                    run_id,
                    task_id,
                    delay_seconds,
                    int(parent["attempt"]) + 1,
                    reason,
                ),
            )
            return child

    def grant_auditor_capability(
        self,
        *,
        child_id: str,
        expected_version: int,
        auditor_capability_hash: str,
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
    ) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            # The SQL SECURITY DEFINER result/evidence/audit routines acquire
            # this same key before reading or writing their rows.  Acquiring
            # it before the child row lock preserves one lock order for both
            # direct database writers and the Python workflow path.
            self._lock_child_mutation(cur, child_id)
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
            )
            if child["state"] != "executed":
                raise PermissionError("child is not ready for auditor grant")
            cur.execute(
                """
                UPDATE longspan_children
                SET auditor_capability_hash = %s,
                    version = version + 1,
                    updated_at = clock_timestamp()
                WHERE child_id = %s AND version = %s AND state = 'executed'
                RETURNING child_id, task_id, run_id, parent_attempt_id, fence_token,
                          state, idempotency_key, request_digest, attempt_number, version,
                          lease_token_hash, lease_expires_at, manager_capability_hash,
                          executor_capability_hash, auditor_capability_hash,
                          created_at, updated_at
                """,
                (auditor_capability_hash, child_id, expected_version),
            )
            row = cur.fetchone()
            if row is None:
                raise PermissionError("stale auditor capability grant")
            return row_to_dict(row)

    def store_plan(
        self,
        *,
        child_id: str,
        expected_version: int,
        attempt_number: int,
        objective: str,
        acceptance_criteria: list[str],
        scope: str,
        plan_digest: str,
        manager_capability_token: str,
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
    ) -> dict[str, Any]:
        if scope != "comms-01":
            raise ValueError("longspan scope must be comms-01")
        assert_comms01_entrypoint(scope=scope)
        plan_id = uuid.uuid4().hex
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            # Keep auditor writes serialized with executor result/evidence
            # writers and with direct calls to the database routines.
            self._lock_child_mutation(cur, child_id)
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
            )
            self.verify_capability_token(child, "manager", manager_capability_token)
            if child["state"] != "ready":
                raise PermissionError("child is not ready for manager planning")
            if int(child["attempt_number"]) != attempt_number:
                raise PermissionError("stale plan attempt")
            cur.execute(
                """
                INSERT INTO longspan_plans
                    (plan_id, child_id, attempt_number, objective,
                     acceptance_criteria_json, scope, plan_digest)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (child_id, attempt_number) DO NOTHING
                """,
                (
                    plan_id,
                    child_id,
                    attempt_number,
                    objective,
                    json.dumps(acceptance_criteria, sort_keys=True),
                    scope,
                    plan_digest,
                ),
            )
            if cur.rowcount != 1:
                raise PermissionError("plan already exists for attempt")
            child = self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state="planned",
            )
            self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                event_type="manager_plan",
                producer_role="manager",
                payload_digest=plan_digest,
                run_id=run_id,
                capability_token=manager_capability_token,
            )
            return child

    def get_plan(self, child_id: str, attempt_number: int) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT plan_id, child_id, attempt_number, objective, acceptance_criteria_json,
                       scope, plan_digest, created_at
                FROM longspan_plans
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError((child_id, attempt_number))
            item = row_to_dict(row)
            item["acceptance_criteria"] = json.loads(item.pop("acceptance_criteria_json"))
            return item

    def begin_execution(
        self,
        *,
        child_id: str,
        expected_version: int,
        executor_capability_token: str,
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
    ) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
            )
            self.verify_capability_token(child, "executor", executor_capability_token)
            if child["state"] != "planned":
                raise PermissionError("child is not planned")
            return self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state="executing",
            )

    def store_execution_result(
        self,
        *,
        child_id: str,
        expected_version: int,
        attempt_number: int,
        outcome: str,
        result_digest: str,
        artifact_refs: list[str],
        executor_capability_token: str,
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
        request_digest: str,
        evidence_digest: str,
        evidence_json: str,
        raw_result_ref: str | None = None,
    ) -> dict[str, Any]:
        if outcome not in {"success", "failure", "retryable"}:
            raise ValueError("invalid execution outcome")
        result_id = uuid.uuid4().hex
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            # The SQL SECURITY DEFINER result/evidence/audit routines acquire
            # this same key before reading or writing their rows.  Acquiring
            # it before the child row lock preserves one lock order for both
            # direct database writers and the Python workflow path.
            self._lock_child_mutation(cur, child_id)
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
            )
            self.verify_capability_token(child, "executor", executor_capability_token)
            if child["state"] != "executing":
                raise PermissionError("child is not executing")
            if int(child["attempt_number"]) != attempt_number:
                raise PermissionError("stale execution attempt")
            cur.execute(
                """
                SELECT longspan_store_execution_evidence(
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    uuid.uuid4().hex,
                    child_id,
                    attempt_number,
                    evidence_json,
                    evidence_digest,
                    executor_capability_token,
                ),
            )
            try:
                cur.execute(
                    """
                    SELECT longspan_insert_execution_result(
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        result_id,
                        child_id,
                        attempt_number,
                        outcome,
                        result_digest,
                        json.dumps(artifact_refs, sort_keys=True),
                        executor_capability_token,
                    ),
                )
            except pg_errors.UniqueViolation as exc:
                raise PermissionError("execution result already recorded") from exc
            audit_id = uuid.uuid4().hex
            cur.execute(
                """
                SELECT longspan_append_execution_audit(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                """,
                (
                    audit_id,
                    child_id,
                    attempt_number,
                    request_digest,
                    evidence_digest,
                    result_digest,
                    outcome,
                    raw_result_ref,
                    executor_capability_token,
                ),
            )
            child = self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state="executed",
            )
            self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                event_type="executor_result",
                producer_role="executor",
                payload_digest=result_digest,
                run_id=run_id,
                request_digest=request_digest,
                capability_token=executor_capability_token,
            )
            return child

    def get_execution_result(self, child_id: str, attempt_number: int) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT result_id, child_id, attempt_number, outcome, result_digest,
                       artifact_refs_json, created_at
                FROM longspan_execution_results
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError((child_id, attempt_number))
            item = row_to_dict(row)
            item["artifact_refs"] = json.loads(item.pop("artifact_refs_json"))
            return item

    def get_execution_evidence(self, child_id: str, attempt_number: int) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT evidence_id, child_id, attempt_number, evidence_json,
                       evidence_digest, created_at
                FROM longspan_execution_evidence
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError((child_id, attempt_number))
            return row_to_dict(row)

    def store_auditor_receipt(
        self,
        *,
        child_id: str,
        expected_version: int,
        attempt_number: int,
        verdict: str,
        reasons: list[str],
        inspector_digest: str,
        receipt_digest: str,
        auditor_capability_token: str,
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
        evidence_digest: str,
    ) -> dict[str, Any]:
        if verdict not in {"pass", "fail"}:
            raise ValueError("invalid auditor verdict")
        receipt_id = uuid.uuid4().hex
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            # Keep auditor writes serialized with executor result/evidence
            # writers and with direct calls to the database routines.
            self._lock_child_mutation(cur, child_id)
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
            )
            self.verify_capability_token(child, "auditor", auditor_capability_token)
            if child["state"] != "executed":
                raise PermissionError("child is not awaiting audit")
            if int(child["attempt_number"]) != attempt_number:
                raise PermissionError("stale auditor attempt")
            cur.execute(
                """
                SELECT longspan_append_auditor_receipt(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    receipt_id,
                    child_id,
                    attempt_number,
                    verdict,
                    json.dumps(reasons, sort_keys=True),
                    inspector_digest,
                    evidence_digest,
                    receipt_digest,
                    auditor_capability_token,
                ),
            )
            next_state = "needs_remediation" if verdict == "fail" else "terra_pending"
            child = self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state=next_state,
            )
            self._require_attempt_ledger_events(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                required=("manager_plan", "executor_result"),
            )
            self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                event_type="auditor_verdict",
                producer_role="auditor",
                payload_digest=receipt_digest,
                run_id=run_id,
                capability_token=auditor_capability_token,
            )
            return child

    def get_auditor_receipt(self, child_id: str, attempt_number: int) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT receipt_id, child_id, attempt_number, verdict, reasons_json,
                       inspector_digest, evidence_digest, receipt_digest, created_at
                FROM longspan_auditor_receipts
                WHERE child_id = %s AND attempt_number = %s AND verdict = 'pass'
                """,
                (child_id, attempt_number),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError((child_id, attempt_number))
            item = row_to_dict(row)
            item["reasons"] = json.loads(item.pop("reasons_json"))
            return item

    def _load_terra_receipt_context(
        self,
        cur: Any,
        *,
        child_id: str,
        attempt_number: int,
        evidence_chain_head: str,
        terra_auth_token: str,
        parent_attempt_id: str,
        fence_token: int,
        run_id: str,
        controller_epoch: int,
        for_update: bool,
    ) -> dict[str, Any]:
        """Load and validate Terra inputs for one transaction boundary."""
        if for_update:
            # Keep the global lock order explicit and reviewable: every
            # caller acquires run scope before child scope, never relying on
            # PostgreSQL target-list evaluation order.
            cur.execute(
                "SELECT pg_advisory_xact_lock(8102, hashtext(%s))",
                (run_id,),
            )
            cur.execute(
                "SELECT pg_advisory_xact_lock(8101, hashtext(%s))",
                (child_id,),
            )
        authority = self._load_authority_config(cur, run_id)
        if not verify_capability_hash(terra_auth_token, authority["terra_auth_hash"]):
            raise PermissionError("terra review auth token is not verified")
        child = self._fetch_child(cur, child_id, for_update=for_update)
        self._assert_parent_fence(
            child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
        )
        if child["run_id"] != run_id:
            raise PermissionError("terra receipt run scope mismatch")
        if child["state"] != "terra_pending":
            raise PermissionError("child is not awaiting terra review")
        if int(child["attempt_number"]) != attempt_number:
            raise PermissionError("stale terra review attempt")
        ledger_head = self._ledger_head(cur, child_id)
        if ledger_head is None or ledger_head != evidence_chain_head:
            raise PermissionError("terra evidence chain head does not match ledger")
        # Result and auditor tables are protected by the same child fence and
        # the run/child advisory locks above.  Their workflow grants are
        # intentionally not expanded merely to obtain PostgreSQL row locks.
        cur.execute(
            """
            SELECT result_digest FROM longspan_execution_results
            WHERE child_id = %s AND attempt_number = %s
            """,
            (child_id, attempt_number),
        )
        result_row = cur.fetchone()
        if result_row is None or not result_row.get("result_digest"):
            raise PermissionError("terra review requires a persisted execution result")
        cur.execute(
            """
            SELECT evidence_digest FROM longspan_auditor_receipts
            WHERE child_id = %s AND attempt_number = %s AND verdict = 'pass'
            """,
            (child_id, attempt_number),
        )
        auditor_row = cur.fetchone()
        if auditor_row is None or not auditor_row.get("evidence_digest"):
            raise PermissionError("terra review requires a persisted evidence digest")
        return {
            "authority": authority,
            "child": child,
            "execution_result_digest": result_row["result_digest"],
            "auditor_evidence_digest": auditor_row["evidence_digest"],
        }

    @contextmanager
    def _terra_receipt_transaction(
        self,
        attestation_id: str,
        receipt_payload: dict[str, Any],
        signature_digest: str,
    ):
        """Retire an out-of-band witness after any final-binding failure."""
        try:
            with self._repo.transaction() as cur:
                yield cur
        except Exception:
            try:
                # The transaction above has rolled back before this separate
                # authority call, so it cannot hold the child/advisory locks.
                invalidate_terra_receipt_attestation(
                    attestation_id=attestation_id,
                    run_id=str(receipt_payload["run_id"]),
                    child_id=str(receipt_payload["child_id"]),
                    attempt_number=int(receipt_payload["attempt_number"]),
                    signature_digest=signature_digest,
                )
            except Exception as invalidation_exc:
                raise IntegrityFailureError(
                    "Terra receipt failed after attestation issuance and its witness "
                    "could not be retired"
                ) from invalidation_exc
            raise

    def store_terra_receipt(
        self,
        *,
        child_id: str,
        expected_version: int,
        attempt_number: int,
        reviewer: str,
        decision: str,
        evidence_chain_head: str,
        terra_auth_token: str,
        parent_attempt_id: str,
        fence_token: int,
        controller_epoch: int,
        run_id: str,
        authority_signature: str | None = None,
    ) -> dict[str, Any]:
        if decision not in {"approved", "rejected"}:
            raise ValueError("invalid terra decision")
        receipt_id = uuid.uuid4().hex
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            context = self._load_terra_receipt_context(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                evidence_chain_head=evidence_chain_head,
                terra_auth_token=terra_auth_token,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
                run_id=run_id,
                controller_epoch=controller_epoch,
                for_update=False,
            )
        authority = context["authority"]
        child = context["child"]
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
            "controller_epoch": controller_epoch,
            "tree_sha": authority["tree_sha"],
            "source_digest": authority["source_digest"],
            "request_digest": child["request_digest"],
            "migration_head": CANONICAL_ALEMBIC_HEAD,
            "authority_version": int(authority["config_version"]),
            "evidence_digest": context["auditor_evidence_digest"],
            "result_digest": context["execution_result_digest"],
        }
        if not verify_terra_receipt_signature(receipt_payload, authority_signature):
            raise PermissionError("Terra receipt external authority signature is not verified")
        # The external signer supplies only the Ed25519 envelope.  The
        # database must append its own gateway proof from PostgreSQL's
        # canonical JSONB representation; accepting a caller-supplied third
        # segment would let the workflow choose the proof value.
        if authority_signature.count(":") != 1:
            raise PermissionError("Terra receipt gateway proof must be database-generated")
        external_signature = authority_signature
        signature_digest = hashlib.sha256(
            external_signature.split(":", 1)[1].encode("utf-8")
        ).hexdigest()
        attestation_id, gateway_mac = request_terra_receipt_attestation(
            receipt_payload=receipt_payload,
            external_signature=external_signature,
        )
        authority_signature = f"{authority_signature}:{gateway_mac}:{attestation_id}"
        with self._terra_receipt_transaction(
            attestation_id, receipt_payload, signature_digest
        ) as cur:
            current = self._load_terra_receipt_context(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                evidence_chain_head=evidence_chain_head,
                terra_auth_token=terra_auth_token,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
                run_id=run_id,
                controller_epoch=controller_epoch,
                for_update=True,
            )
            # The final admission check must run after the run/child locks and
            # child row lock are held, so a concurrent epoch bump or rollback
            # cannot invalidate the check between validation and append.
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            current_authority = current["authority"]
            current_child = current["child"]
            current_payload = {
                "child_id": child_id,
                "attempt_number": attempt_number,
                "reviewer": reviewer,
                "decision": decision,
                "evidence_chain_head": evidence_chain_head,
                "run_id": run_id,
                "task_id": current_child["task_id"],
                "reviewed_sha": current_authority["reviewed_sha"],
                "fence_token": int(current_child["fence_token"]),
                "controller_epoch": controller_epoch,
                "tree_sha": current_authority["tree_sha"],
                "source_digest": current_authority["source_digest"],
                "request_digest": current_child["request_digest"],
                "migration_head": CANONICAL_ALEMBIC_HEAD,
                "authority_version": int(current_authority["config_version"]),
                "evidence_digest": current["auditor_evidence_digest"],
                "result_digest": current["execution_result_digest"],
            }
            if current_payload != receipt_payload:
                raise PermissionError("Terra receipt inputs changed during attestation")
            cur.execute(
                """
                SELECT receipt_id FROM longspan_auditor_receipts
                WHERE child_id = %s AND attempt_number = %s AND verdict = 'pass'
                """,
                (child_id, attempt_number),
            )
            if cur.fetchone() is None:
                raise PermissionError("terra review requires an auditor pass receipt")
            cur.execute(
                """
                SELECT longspan_append_terra_receipt(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    receipt_id,
                    child_id,
                    attempt_number,
                    reviewer,
                    decision,
                    evidence_chain_head,
                    None,
                    run_id,
                    current_child["task_id"],
                    current_authority["reviewed_sha"],
                    current_child.get("fence_token"),
                    controller_epoch,
                    current_authority["tree_sha"],
                    current_authority["source_digest"],
                    current_child.get("request_digest"),
                    CANONICAL_ALEMBIC_HEAD,
                    current_authority.get("config_version"),
                    current["auditor_evidence_digest"],
                    current["execution_result_digest"],
                    authority_signature,
                    terra_auth_token,
                ),
            )
            receipt_row = cur.fetchone()
            if receipt_row is None or not receipt_row.get("longspan_append_terra_receipt"):
                raise PermissionError("terra receipt digest was not returned by the database")
            receipt_digest = receipt_row["longspan_append_terra_receipt"]
            next_state = "terra_approved" if decision == "approved" else "terra_rejected"
            child = self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state=next_state,
            )
            self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                event_type="terra_review",
                producer_role="terra",
                payload_digest=receipt_digest,
                run_id=run_id,
                capability_token=terra_auth_token,
            )
            return child

    def get_terra_receipt(self, child_id: str, attempt_number: int) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT receipt_id, child_id, attempt_number, reviewer, decision,
                       evidence_chain_head, receipt_digest, run_id, task_id, reviewed_sha,
                       fence_token, controller_epoch, tree_sha, source_digest,
                       request_digest, migration_head, authority_version,
                       evidence_digest, result_digest, signature,
                       authority_signature, created_at
                FROM longspan_terra_receipts
                WHERE child_id = %s AND attempt_number = %s
                """,
                (child_id, attempt_number),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError((child_id, attempt_number))
            return row_to_dict(row)

    def require_approved_terra_receipt(
        self,
        *,
        child_id: str,
        attempt_number: int,
        evidence_chain_head: str,
    ) -> dict[str, Any]:
        child = self.get_child(child_id)
        if child["state"] != "terra_approved":
            raise PermissionError("approved terra receipt is required")
        if int(child["attempt_number"]) != attempt_number:
            raise PermissionError("stale terra review attempt")
        receipt = self.get_terra_receipt(child_id, attempt_number)
        if receipt["decision"] != "approved":
            raise PermissionError("terra review was not approved")
        if not verify_terra_receipt_signature(
            receipt, receipt.get("authority_signature")
        ):
            raise IntegrityFailureError(
                "terra receipt external authority signature is invalid"
            )
        signature_components = terra_receipt_signature_components(
            receipt.get("authority_signature")
        )
        if signature_components is None:
            raise IntegrityFailureError(
                "terra receipt gateway MAC and attestation binding are missing"
            )
        _external_signature, _stored_gateway_mac, _attestation_id = signature_components
        try:
            verify_terra_receipt_gateway_binding(
                receipt=receipt,
                authority_signature=receipt["authority_signature"],
            )
        except (AuthorityServiceCapacityError, AuthorityServiceUnavailableError):
            raise
        except (AuthorizationFailureError, OSError, TypeError, ValueError) as exc:
            raise IntegrityFailureError(
                "terra receipt gateway proof could not be revalidated by authority"
            ) from exc
        if receipt["evidence_chain_head"] != evidence_chain_head:
            raise IntegrityFailureError("terra receipt evidence head mismatch")
        if not receipt.get("run_id"):
            raise IntegrityFailureError("terra receipt run binding is missing")
        if receipt["run_id"] != child["run_id"]:
            raise IntegrityFailureError("terra receipt run scope mismatch")
        if not receipt.get("task_id"):
            raise IntegrityFailureError("terra receipt task binding is missing")
        if receipt["task_id"] != child["task_id"]:
            raise IntegrityFailureError("terra receipt task scope mismatch")
        if not receipt.get("reviewed_sha"):
            raise IntegrityFailureError("terra receipt reviewed_sha binding is missing")
        authority = self.get_authority_config(child["run_id"])
        if receipt["reviewed_sha"] != authority["reviewed_sha"]:
            raise IntegrityFailureError("terra receipt reviewed_sha mismatch")
        if receipt.get("authority_version") is None:
            raise IntegrityFailureError("terra receipt authority version is missing")
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT reviewed_sha, tree_sha, source_digest
                FROM longspan_authority_history
                WHERE run_id = %s AND config_version = %s
                """,
                (child["run_id"], int(receipt["authority_version"])),
            )
            historical = cur.fetchone()
        if historical is None:
            raise IntegrityFailureError("terra receipt authority history binding is missing")
        for field in ("reviewed_sha", "tree_sha", "source_digest"):
            if receipt.get(field) != historical[field]:
                raise IntegrityFailureError(
                    f"terra receipt {field} does not match its authority history version"
                )
        if receipt.get("migration_head") != CANONICAL_ALEMBIC_HEAD:
            raise IntegrityFailureError("terra receipt migration head is not canonical")
        auditor = self.get_auditor_receipt(child_id, attempt_number)
        execution = self.get_execution_result(child_id, attempt_number)
        if receipt.get("evidence_digest") != auditor.get("evidence_digest"):
            raise IntegrityFailureError("terra receipt evidence digest mismatch")
        if receipt.get("result_digest") != execution.get("result_digest"):
            raise IntegrityFailureError("terra receipt result digest mismatch")
        # Re-read the live bindings after the receipt has been fetched.  A
        # receipt that was valid for an earlier attempt, fence, controller
        # epoch, or request must not become a release credential merely
        # because the child currently carries the terra_approved state.
        with self._repo.transaction() as cur:
            fresh_child = self._fetch_child(cur, child_id)
            cur.execute(
                "SELECT current_epoch FROM controller_control WHERE run_id = %s",
                (fresh_child["run_id"],),
            )
            controller = cur.fetchone()
            cur.execute(
                """
                SELECT 1
                FROM parent_tasks AS parent
                JOIN task_attempts AS attempt
                  ON attempt.attempt_id = parent.active_attempt_id
                 AND attempt.task_id = parent.task_id
                 AND attempt.run_id = parent.run_id
                WHERE parent.task_id = %s
                  AND parent.run_id = %s
                  AND parent.active_attempt_id = %s
                  AND attempt.fence_token = %s
                  AND attempt.controller_epoch = %s
                  AND attempt.status = 'running'
                  AND attempt.lease_expires_at > clock_timestamp()
                """,
                (
                    fresh_child["task_id"],
                    fresh_child["run_id"],
                    fresh_child["parent_attempt_id"],
                    fresh_child["fence_token"],
                    receipt["controller_epoch"],
                ),
            )
            live_parent = cur.fetchone()
        if receipt["fence_token"] != fresh_child["fence_token"]:
            raise IntegrityFailureError("terra receipt fence token is stale")
        if controller is None or receipt["controller_epoch"] != controller["current_epoch"]:
            raise IntegrityFailureError("terra receipt controller epoch is stale")
        if receipt.get("request_digest") != fresh_child["request_digest"]:
            raise IntegrityFailureError("terra receipt request digest mismatch")
        if live_parent is None:
            raise IntegrityFailureError("terra receipt is not bound to the live parent fence")
        return receipt

    def mark_parent_returned(
        self,
        *,
        child_id: str,
        expected_version: int,
        attempt_number: int,
        controller_epoch: int,
        run_id: str,
        parent_attempt_id: str,
        fence_token: int,
    ) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
            )
            if child["state"] != "terra_approved":
                raise PermissionError("parent return requires terra approval")
            if int(child["attempt_number"]) != attempt_number:
                raise PermissionError("stale parent return attempt")
            cur.execute(
                """
                SELECT receipt_id FROM longspan_auditor_receipts
                WHERE child_id = %s AND attempt_number = %s AND verdict = 'pass'
                """,
                (child_id, attempt_number),
            )
            if cur.fetchone() is None:
                raise PermissionError("parent return requires auditor receipt")
            cur.execute(
                """
                SELECT receipt_id FROM longspan_terra_receipts
                WHERE child_id = %s AND attempt_number = %s AND decision = 'approved'
                """,
                (child_id, attempt_number),
            )
            if cur.fetchone() is None:
                raise PermissionError("parent return requires terra receipt")
            child = self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state="parent_returned",
            )
            envelope_digest = digest_payload(
                {
                    "child_id": child_id,
                    "attempt_number": attempt_number,
                    "parent_task_id": child["task_id"],
                }
            )
            self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                event_type="parent_return",
                producer_role="parent",
                payload_digest=envelope_digest,
                run_id=run_id,
            )
            return child

    def atomic_parent_return_and_complete(
        self,
        *,
        child_id: str,
        expected_version: int,
        attempt_number: int,
        controller_epoch: int,
        run_id: str,
        task_id: str,
        parent_attempt_id: str,
        fence_token: int,
        parent_generation: str,
        terminal_state: str = "verified",
    ) -> dict[str, Any]:
        if terminal_state not in {"verified", "parked", "blocked", "failed"}:
            raise ValueError("invalid parent terminal state")
        expected_generation = generation_for_fence_token(int(fence_token))
        if parent_generation != expected_generation:
            raise PermissionError("stale parent task generation for return")
        with self._repo.transaction() as cur:
            # A replay after a successful atomic return is read-only.  It must
            # not reopen the workflow mutation scope: completion deliberately
            # closes that scope and invalidates further writes with the same
            # fence.  Validate the current epoch/scheduling state and the
            # child/parent bindings directly, then return the already-terminal
            # result without appending another ledger event.
            snapshot = self._fetch_child(cur, child_id)
            self._assert_parent_fence(
                snapshot,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
            )
            if int(snapshot["attempt_number"]) != attempt_number:
                raise PermissionError("stale parent return attempt")
            if snapshot["state"] == "parent_returned":
                cur.execute(
                    """
                    SELECT current_epoch, scheduling_enabled
                    FROM controller_control
                    WHERE run_id = %s
                    """,
                    (run_id,),
                )
                controller_state = cur.fetchone()
                if controller_state is None or int(controller_state["current_epoch"]) != controller_epoch:
                    raise StaleFenceError("stale controller epoch for parent-return replay")
                if not controller_state["scheduling_enabled"]:
                    raise PermissionError("scheduling disabled for parent-return replay")
                cur.execute(
                    """
                    SELECT state
                    FROM parent_tasks
                    WHERE task_id = %s AND run_id = %s AND active_attempt_id = %s
                    """,
                    (task_id, run_id, parent_attempt_id),
                )
                parent = cur.fetchone()
                if parent is None:
                    raise PermissionError("parent task missing for idempotent return")
                if parent["state"] == terminal_state:
                    return snapshot
                raise PermissionError("parent return terminal state mismatch")
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
            )
            if int(child["attempt_number"]) != attempt_number:
                raise PermissionError("stale parent return attempt")
            if child["state"] != "terra_approved":
                raise PermissionError("parent return requires terra approval")
            cur.execute(
                """
                SELECT receipt_id FROM longspan_auditor_receipts
                WHERE child_id = %s AND attempt_number = %s AND verdict = 'pass'
                """,
                (child_id, attempt_number),
            )
            if cur.fetchone() is None:
                raise PermissionError("parent return requires auditor receipt")
            cur.execute(
                """
                SELECT receipt_id FROM longspan_terra_receipts
                WHERE child_id = %s AND attempt_number = %s AND decision = 'approved'
                """,
                (child_id, attempt_number),
            )
            if cur.fetchone() is None:
                raise PermissionError("parent return requires terra receipt")
            child = self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state="parent_returned",
            )
            envelope_digest = digest_payload(
                {
                    "child_id": child_id,
                    "attempt_number": attempt_number,
                    "parent_task_id": task_id,
                }
            )
            self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                event_type="parent_return",
                producer_role="parent",
                payload_digest=envelope_digest,
                run_id=run_id,
            )
            self._repo.complete_attempt_in_transaction(
                cur,
                run_id=run_id,
                task_id=task_id,
                attempt_id=parent_attempt_id,
                fence_token=fence_token,
                controller_epoch=controller_epoch,
                terminal_state=terminal_state,
                event_type="task_completed",
                event_detail={"task_id": task_id, "state": terminal_state, "child_id": child_id},
            )
            return child

    def atomic_park_child_and_parent(
        self,
        *,
        child_id: str,
        expected_version: int,
        controller_epoch: int,
        run_id: str,
        task_id: str,
        parent_attempt_id: str,
        fence_token: int,
        reason: str,
    ) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            if child["state"] in {"parent_returned", "parked", "cancelled"}:
                return child
            self._assert_parent_fence(
                child,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
            )
            child = self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state="parked",
                clear_capabilities=True,
            )
            self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=int(child["attempt_number"]),
                event_type="authorization_failure",
                producer_role="parent",
                payload_digest=digest_payload(
                    {"reason": reason, "failure_type": "authorization_or_integrity"}
                ),
                run_id=run_id,
            )
            self._repo.complete_attempt_in_transaction(
                cur,
                run_id=run_id,
                task_id=task_id,
                attempt_id=parent_attempt_id,
                fence_token=fence_token,
                controller_epoch=controller_epoch,
                terminal_state="parked",
                event_type="task_parked",
                event_detail={"task_id": task_id, "reason": reason, "child_id": child_id},
            )
            return child

    def append_ledger_entry(
        self,
        *,
        child_id: str,
        attempt_number: int,
        event_type: str,
        producer_role: str,
        payload_digest: str,
        controller_epoch: int,
        run_id: str,
        capability_token: str | None = None,
        fence_token: int,
    ) -> str:
        if producer_role == "parent":
            raise IntegrityFailureError(
                "parent ledger append must use the fenced recovery API"
            )
        if producer_role not in {"manager", "executor", "auditor", "terra"}:
            raise ValueError("invalid ledger producer role")
        if not capability_token:
            raise IntegrityFailureError(
                "direct ledger append requires the producer capability token"
            )
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            self._fetch_child(cur, child_id, for_update=True)
            return self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                event_type=event_type,
                producer_role=producer_role,
                payload_digest=payload_digest,
                run_id=run_id,
                capability_token=capability_token,
            )

    def append_parent_ledger_entry(
        self,
        *,
        child_id: str,
        attempt_number: int,
        event_type: str,
        payload_digest: str,
        controller_epoch: int,
        run_id: str,
        parent_attempt_id: str,
        fence_token: int,
    ) -> str:
        """Append only the small, fenced parent-recovery event set.

        Parent evidence is not a generic write capability.  Recovery callers
        must prove the live parent fence and may emit only events describing
        retry recovery; manager/executor/auditor/Terra writes use their own
        capability-bound API above.
        """
        if event_type not in PARENT_LEDGER_EVENT_TYPES:
            raise IntegrityFailureError(
                "parent ledger append event is outside the recovery contract"
            )
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child,
                parent_attempt_id=parent_attempt_id,
                fence_token=fence_token,
            )
            return self._append_ledger_in_transaction(
                cur,
                child_id=child_id,
                attempt_number=attempt_number,
                event_type=event_type,
                producer_role="parent",
                payload_digest=payload_digest,
                run_id=run_id,
            )

    def ledger_entries(self, child_id: str) -> list[dict[str, Any]]:
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT entry_id, child_id, attempt_number, sequence_number, event_type,
                       producer_role, payload_digest, previous_entry_hash, entry_hash,
                       base_digest, mac_key_version, created_at
                FROM longspan_evidence_ledger
                WHERE child_id = %s
                ORDER BY sequence_number
                """,
                (child_id,),
            )
            return [row_to_dict(row) for row in cur.fetchall()]

    def verify_ledger_chain(self, child_id: str) -> tuple[bool, list[str]]:
        entries = self.ledger_entries(child_id)
        issues: list[str] = []
        previous: str | None = None
        expected_sequence = 1
        saw_unkeyed = False
        saw_keyed = False
        if entries:
            child = self.get_child(child_id)
        for entry in entries:
            if int(entry["sequence_number"]) != expected_sequence:
                issues.append(f"sequence-gap:{entry['entry_id']}")
            hash_kwargs = {
                "child_id": entry["child_id"],
                "attempt_number": int(entry["attempt_number"]),
                "event_type": entry["event_type"],
                "producer_role": entry["producer_role"],
                "payload_digest": entry["payload_digest"],
                "previous_entry_hash": previous,
            }
            base_digest = compute_ledger_entry_hash(**hash_kwargs, mac_key=None)
            with self._repo.transaction() as cur:
                cur.execute(
                    """
                    SELECT longspan_verify_ledger_entry(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        entry["child_id"],
                        int(entry["attempt_number"]),
                        entry["event_type"],
                        entry["producer_role"],
                        entry["payload_digest"],
                        previous,
                        base_digest,
                        entry["entry_hash"],
                        child["run_id"],
                    ),
                )
                verification_row = cur.fetchone()
                if verification_row is None:
                    valid_hash = False
                elif isinstance(verification_row, dict):
                    valid_hash = bool(next(iter(verification_row.values())))
                else:
                    valid_hash = bool(verification_row[0])
            if not valid_hash:
                issues.append(f"hash-mismatch:{entry['entry_id']}")
            if entry.get("mac_key_version") is None:
                saw_unkeyed = True
                issues.append(f"legacy-unkeyed:{entry['entry_id']}")
            else:
                saw_keyed = True
            if saw_unkeyed and saw_keyed:
                issues.append(f"mixed-keyed-chain:{child_id}")
            if entry["previous_entry_hash"] != previous:
                issues.append(f"broken-chain:{entry['entry_id']}")
            previous = entry["entry_hash"]
            expected_sequence += 1
        return len(issues) == 0, issues

    def create_experiment(
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
        controller_epoch: int,
    ) -> dict[str, Any]:
        if classification not in EXPERIMENT_CLASSIFICATIONS:
            raise ValueError("invalid experiment classification")
        assert_comms01_entrypoint(scope=scope)
        targets = self._derive_protected_targets(
            classification=classification,
            hypothesis=hypothesis,
            scope=scope,
            baseline=baseline,
        )
        if set(targets) & PROTECTED_AUTHORITY_TARGETS:
            raise PermissionError(
                "experiments may not target authority, acceptance criteria, "
                "model routing, release gates, or policy without operator approval"
            )
        if classification == "policy":
            raise PermissionError("policy experiments require explicit operator approval")
        experiment_id = uuid.uuid4().hex
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur,
                run_id,
                controller_epoch,
                controller_scope=True,
            )
            cur.execute(
                """
                INSERT INTO longspan_experiments
                    (experiment_id, child_id, run_id, hypothesis, baseline, scope,
                     predicted_benefit, rollback_plan, classification, state,
                     protected_targets_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'proposed', %s)
                RETURNING experiment_id, child_id, run_id, hypothesis, baseline, scope,
                          predicted_benefit, rollback_plan, classification, state,
                          protected_targets_json, evidence_digest, auditor_verdict,
                          adoption_decision, operator_approval_digest, auditor_receipt_id,
                          created_at, updated_at
                """,
                (
                    experiment_id,
                    child_id,
                    run_id,
                    hypothesis,
                    baseline,
                    scope,
                    predicted_benefit,
                    rollback_plan,
                    classification,
                    json.dumps(targets, sort_keys=True),
                ),
            )
            row = row_to_dict(cur.fetchone())
            row["protected_targets"] = json.loads(row.pop("protected_targets_json"))
            return row

    def authorize_experiment_for_local_test(
        self,
        *,
        experiment_id: str,
        operator_auth_token: str,
        run_id: str,
        controller_epoch: int,
    ) -> dict[str, Any]:
        if not operator_auth_token:
            raise ValueError("operator auth token is required")
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, controller_scope=True
            )
            authority = self._load_authority_config(cur, run_id)
            if not verify_capability_hash(operator_auth_token, authority["operator_auth_hash"]):
                raise PermissionError("operator auth token is not verified")
            operator_approval_digest = hash_capability_token(operator_auth_token)
            cur.execute(
                """
                UPDATE longspan_experiments
                SET state = 'authorized-for-local-test',
                    operator_approval_digest = %s,
                    updated_at = clock_timestamp()
                WHERE experiment_id = %s AND state = 'proposed'
                RETURNING experiment_id, child_id, run_id, hypothesis, baseline, scope,
                          predicted_benefit, rollback_plan, classification, state,
                          protected_targets_json, evidence_digest, auditor_verdict,
                          adoption_decision, operator_approval_digest, auditor_receipt_id,
                          created_at, updated_at
                """,
                (operator_approval_digest, experiment_id),
            )
            row = cur.fetchone()
            if row is None:
                raise PermissionError("experiment is not eligible for local authorization")
            item = row_to_dict(row)
            item["protected_targets"] = json.loads(item.pop("protected_targets_json"))
            return item

    def adopt_experiment(
        self,
        *,
        experiment_id: str,
        evidence_digest: str,
        auditor_receipt_id: str,
        operator_auth_token: str,
        adoption_decision: str,
        state: str,
        run_id: str,
        controller_epoch: int,
    ) -> dict[str, Any]:
        if state not in {"accepted", "rejected", "superseded"}:
            raise ValueError("invalid experiment adoption state")
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, controller_scope=True
            )
            authority = self._load_authority_config(cur, run_id)
            cur.execute(
                """
                SELECT experiment_id, child_id, run_id, classification, state,
                       operator_approval_digest, protected_targets_json
                FROM longspan_experiments WHERE experiment_id = %s FOR UPDATE
                """,
                (experiment_id,),
            )
            experiment = cur.fetchone()
            if experiment is None:
                raise KeyError(experiment_id)
            if experiment["run_id"] != run_id:
                raise PermissionError("experiment run scope mismatch")
            if experiment["state"] not in {"authorized-for-local-test"}:
                raise PermissionError("experiment is not ready for adoption")
            protected = json.loads(experiment["protected_targets_json"])
            if "operator_approval_required" in protected or experiment["classification"] in OPERATOR_APPROVAL_CLASSIFICATIONS:
                if not operator_auth_token:
                    raise PermissionError("operator approval is required for adoption")
                if not verify_capability_hash(operator_auth_token, authority["operator_auth_hash"]):
                    raise PermissionError("operator auth token is not verified")
                approval_digest = hash_capability_token(operator_auth_token)
                if (
                    experiment["operator_approval_digest"]
                    and experiment["operator_approval_digest"] != approval_digest
                ):
                    raise PermissionError("operator approval digest mismatch")
            else:
                approval_digest = experiment["operator_approval_digest"]
            cur.execute(
                """
                SELECT receipt.receipt_id, receipt.verdict, child.run_id, child.child_id
                FROM longspan_auditor_receipts AS receipt
                INNER JOIN longspan_children AS child ON child.child_id = receipt.child_id
                WHERE receipt.receipt_id = %s
                """,
                (auditor_receipt_id,),
            )
            receipt = cur.fetchone()
            if receipt is None or receipt["verdict"] != "pass":
                raise PermissionError("adoption requires a verified auditor pass receipt")
            if experiment["child_id"] and receipt["child_id"] != experiment["child_id"]:
                raise PermissionError("auditor receipt child does not match experiment")
            if receipt["run_id"] != run_id:
                raise PermissionError("auditor receipt run does not match experiment")
            cur.execute(
                """
                UPDATE longspan_experiments
                SET evidence_digest = %s,
                    auditor_verdict = %s,
                    adoption_decision = %s,
                    state = %s,
                    auditor_receipt_id = %s,
                    operator_approval_digest = COALESCE(operator_approval_digest, %s),
                    updated_at = clock_timestamp()
                WHERE experiment_id = %s
                RETURNING experiment_id, child_id, run_id, hypothesis, baseline, scope,
                          predicted_benefit, rollback_plan, classification, state,
                          protected_targets_json, evidence_digest, auditor_verdict,
                          adoption_decision, operator_approval_digest, auditor_receipt_id,
                          created_at, updated_at
                """,
                (
                    evidence_digest,
                    "pass",
                    adoption_decision,
                    state,
                    auditor_receipt_id,
                    approval_digest,
                    experiment_id,
                ),
            )
            row = row_to_dict(cur.fetchone())
            row["protected_targets"] = json.loads(row.pop("protected_targets_json"))
            return row

    def park_children_for_run(self, run_id: str, controller_epoch: int) -> int:
        if not self._repo.controller_owner:
            raise PermissionError("child parking requires a pinned controller owner")
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_current_controller_fence(%s, %s, %s)
                """,
                (run_id, controller_epoch, self._repo.controller_owner),
            )
            control = cur.fetchone()
            if control is None:
                raise StaleFenceError("controller maintenance fence is unavailable")
            expected_fence = int(next(iter(control.values())))
            cur.execute(
                """
                SELECT longspan_park_children(%s, %s, %s, %s)
                """,
                (
                    run_id,
                    controller_epoch,
                    self._repo.controller_owner,
                    expected_fence,
                ),
            )
            row = cur.fetchone()
            return int(next(iter(row.values())) if isinstance(row, dict) else row[0])

    def expire_stale_children(
        self,
        run_id: str,
        controller_epoch: int,
    ) -> list[str]:
        if not self._repo.controller_owner:
            raise PermissionError("stale-child expiry requires a pinned controller owner")
        expired: list[str] = []
        with self._repo.transaction() as cur:
            cur.execute(
                """
                SELECT longspan_current_controller_fence(%s, %s, %s)
                """,
                (run_id, controller_epoch, self._repo.controller_owner),
            )
            control = cur.fetchone()
            if control is None:
                raise StaleFenceError("controller maintenance fence is unavailable")
            expected_fence = int(next(iter(control.values())))
            cur.execute(
                """
                SELECT longspan_expire_stale_children(%s, %s, %s, %s)
                """,
                (
                    run_id,
                    controller_epoch,
                    self._repo.controller_owner,
                    expected_fence,
                ),
            )
            row = cur.fetchone()
            if row is None:
                return expired
            value = next(iter(row.values())) if isinstance(row, dict) else row[0]
            return list(value or [])

    def _append_ledger_in_transaction(
        self,
        cur: Any,
        *,
        child_id: str,
        attempt_number: int,
        event_type: str,
        producer_role: str,
        payload_digest: str,
        run_id: str,
        request_digest: str | None = None,
        capability_token: str | None = None,
    ) -> str:
        child = self._fetch_child(cur, child_id, for_update=True)
        if child["run_id"] != run_id:
            raise AuthorizationFailureError("ledger append run scope mismatch")
        try:
            self._load_authority_config(cur, run_id)
            authority_active = True
        except AuthorizationFailureError:
            authority_active = False
        if not authority_active:
            raise IntegrityFailureError(
                "ledger append blocked: run authority is required before the first evidence entry"
            )
        entry_id = uuid.uuid4().hex
        signed_payload = payload_digest
        if request_digest:
            signed_payload = digest_payload(
                {"payload_digest": payload_digest, "request_digest": request_digest}
            )
        cur.execute(
            """
            SELECT COALESCE(MAX(sequence_number), 0) AS max_seq
            FROM longspan_evidence_ledger
            WHERE child_id = %s
            """,
            (child_id,),
        )
        sequence_number = int(cur.fetchone()["max_seq"]) + 1
        previous_entry_hash = None
        if sequence_number > 1:
            cur.execute(
                """
                SELECT entry_hash FROM longspan_evidence_ledger
                WHERE child_id = %s AND sequence_number = %s
                """,
                (child_id, sequence_number - 1),
            )
            head = cur.fetchone()
            if head is None:
                raise PermissionError("ledger head is missing")
            previous_entry_hash = head["entry_hash"]
        base_digest = compute_ledger_entry_hash(
            child_id=child_id,
            attempt_number=attempt_number,
            event_type=event_type,
            producer_role=producer_role,
            payload_digest=signed_payload,
            previous_entry_hash=previous_entry_hash,
            mac_key=None,
        )
        cur.execute(
            """
            SELECT longspan_append_evidence_ledger(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                entry_id,
                child_id,
                attempt_number,
                event_type,
                producer_role,
                signed_payload,
                run_id,
                None,
                previous_entry_hash,
                sequence_number,
                base_digest,
                capability_token,
            ),
        )
        return entry_id

    def renew_lease(
        self,
        *,
        child_id: str,
        expected_version: int,
        role: str,
        capability_token: str,
        lease_seconds: float,
        controller_epoch: int,
        run_id: str,
        parent_attempt_id: str,
        fence_token: int,
    ) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
            )
            self.verify_capability_token(child, role, capability_token)
            cur.execute(
                """
                UPDATE longspan_children
                SET lease_expires_at = clock_timestamp() + (%s || ' seconds')::interval,
                    updated_at = clock_timestamp(),
                    version = version + 1
                WHERE child_id = %s
                  AND version = %s
                  AND parent_attempt_id = %s
                  AND fence_token = %s
                  AND state IN ('ready', 'planned', 'executing', 'executed', 'auditing')
                RETURNING child_id, task_id, run_id, parent_attempt_id, fence_token,
                          state, idempotency_key, request_digest, attempt_number, version,
                          lease_token_hash, lease_expires_at, manager_capability_hash,
                          executor_capability_hash, auditor_capability_hash,
                          created_at, updated_at
                """,
                (
                    lease_seconds,
                    child_id,
                    expected_version,
                    parent_attempt_id,
                    fence_token,
                ),
            )
            row = cur.fetchone()
            if row is None:
                raise PermissionError("stale longspan lease renewal")
            return row_to_dict(row)

    def transition_child_state(
        self,
        *,
        child_id: str,
        expected_version: int,
        new_state: str,
        controller_epoch: int,
        run_id: str,
        parent_attempt_id: str,
        fence_token: int,
        clear_capabilities: bool = False,
        bump_attempt: bool = False,
    ) -> dict[str, Any]:
        if new_state != "retry_wait" or not clear_capabilities:
            raise AuthorizationFailureError(
                "generic child state transitions are disabled; use a capability-bound transition"
            )
        with self._repo.transaction() as cur:
            self._assert_longspan_writes_allowed(
                cur, run_id, controller_epoch, fence_token=fence_token
            )
            child = self._fetch_child(cur, child_id, for_update=True)
            self._assert_parent_fence(
                child, parent_attempt_id=parent_attempt_id, fence_token=fence_token
            )
            return self._transition_child(
                cur,
                child_id=child_id,
                expected_version=expected_version,
                new_state=new_state,
                clear_capabilities=clear_capabilities,
                bump_attempt=bump_attempt,
            )
