"""Authorize blocked-to-queued recovery under workflow scope.

Revision ID: 014_requeue_blocked_parent_task
Revises: 013_cleanup_expired_attempt

Candidate migration. Do not apply to top_delivery_control_p1 from the
local-delivery remediation envelope. Activation must pin source provenance
before any live upgrade.
"""

from __future__ import annotations

from alembic import op
from authority_pins import (
    MIGRATION_SOURCE_PROVENANCE_PATH,
    WORKFLOW_DATABASE_ROLE,
)
from migration_catalog import assert_migration_catalog
from migration_source_anchor import verify_migration_source_anchor

revision = "014_requeue_blocked_parent_task"
down_revision = "013_cleanup_expired_attempt"
branch_labels = None
depends_on = None

MIGRATION_ROLE = "top_delivery_migration"
WORKFLOW_ROLE = WORKFLOW_DATABASE_ROLE

UPGRADE_SQL = r"""
-- Fail closed unless the installed cleanup function matches canonical f2658c3
-- 013 (`current_epoch < p_controller_epoch` plus the unexpired-epoch guard).
-- The live hybrid body (IS DISTINCT FROM plus the newer unexpired guard) is
-- not a canonical parent. Do not apply to top_delivery_control_p1 from this
-- envelope.
DO $td014pred$
DECLARE
  def text;
BEGIN
  BEGIN
    def := pg_get_functiondef(
      'public.longspan_cleanup_expired_parent_attempt(text, text, integer, integer)'::regprocedure
    );
  EXCEPTION WHEN undefined_function THEN
    RAISE EXCEPTION '014 refuses to apply: canonical 013 cleanup predecessor is missing';
  END;
  IF position('current_epoch < p_controller_epoch' in def) = 0
     OR position('current_epoch IS DISTINCT FROM p_controller_epoch' in def) > 0
     OR position('attempt_row.controller_epoch = p_controller_epoch' in def) = 0 THEN
    RAISE EXCEPTION '014 refuses unknown or non-canonical 013 cleanup predecessor body';
  END IF;
END
$td014pred$;

-- Candidate workflow function. Apply only to disposable test databases in this
-- envelope. Do not apply to top_delivery_control_p1 from this envelope.
CREATE OR REPLACE FUNCTION longspan_requeue_blocked_parent_task(
    p_run_id TEXT,
    p_task_id TEXT,
    p_attempt_id TEXT,
    p_controller_epoch INTEGER,
    p_owner TEXT,
    p_max_retries INTEGER
) RETURNS JSONB AS $$
DECLARE
    control_row controller_control%ROWTYPE;
    parent_row parent_tasks%ROWTYPE;
    attempt_row task_attempts%ROWTYPE;
    mac_key TEXT;
    scope_payload JSONB;
    scope_signature TEXT;
    next_attempt INTEGER;
    v_retry_key TEXT;
BEGIN
    IF session_user <> 'top_delivery_workflow' THEN
        RAISE EXCEPTION 'blocked-task requeue requires the workflow principal';
    END IF;
    IF p_max_retries IS NULL OR p_max_retries < 1 THEN
        RAISE EXCEPTION 'blocked-task requeue requires a positive retry ceiling';
    END IF;
    IF p_owner IS NULL OR btrim(p_owner) = '' THEN
        RAISE EXCEPTION 'blocked-task requeue requires the pinned owner';
    END IF;
    SELECT * INTO control_row
    FROM controller_control
    WHERE run_id = p_run_id
    FOR UPDATE;
    IF NOT FOUND
       OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
       OR control_row.owner IS DISTINCT FROM p_owner
       OR NOT control_row.scheduling_enabled
       OR control_row.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'blocked-task requeue is not bound to the live controller lease';
    END IF;
    SELECT * INTO parent_row
    FROM parent_tasks
    WHERE run_id = p_run_id AND task_id = p_task_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'blocked-task requeue target task is missing';
    END IF;
    IF parent_row.state = 'queued' AND parent_row.active_attempt_id IS NULL THEN
        RETURN jsonb_build_object(
            'requeued', false,
            'reason', 'already_queued',
            'task_id', parent_row.task_id,
            'attempt', parent_row.attempt,
            'state', parent_row.state
        );
    END IF;
    IF parent_row.state IS DISTINCT FROM 'blocked'
       OR parent_row.active_attempt_id IS DISTINCT FROM p_attempt_id THEN
        RAISE EXCEPTION 'blocked-task requeue requires the named blocked attempt';
    END IF;
    SELECT * INTO attempt_row
    FROM task_attempts
    WHERE attempt_id = p_attempt_id AND run_id = p_run_id AND task_id = p_task_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'blocked-task requeue attempt is missing';
    END IF;
    IF attempt_row.status IS DISTINCT FROM 'blocked' THEN
        RAISE EXCEPTION 'blocked-task requeue requires a terminal blocked attempt';
    END IF;
    IF attempt_row.lease_expires_at > clock_timestamp() THEN
        RAISE EXCEPTION 'blocked-task requeue refuses a live attempt lease';
    END IF;
    IF parent_row.attempt >= p_max_retries THEN
        RAISE EXCEPTION 'blocked-task requeue would exceed the retry ceiling';
    END IF;
    next_attempt := parent_row.attempt + 1;
    SELECT material.mac_key INTO mac_key
    FROM longspan_mac_material AS material
    WHERE material.material_id = 'ledger';
    IF mac_key IS NULL THEN
        RAISE EXCEPTION 'blocked-task requeue MAC material is unavailable';
    END IF;
    scope_payload := jsonb_build_object(
        'scope_kind', 'workflow',
        'run_id', p_run_id,
        'task_id', p_task_id,
        'controller_epoch', attempt_row.controller_epoch,
        'fence_token', attempt_row.fence_token,
        'operation', 'requeue_blocked_parent_task',
        'attempt_id', p_attempt_id,
        'owner', p_owner,
        'next_attempt', next_attempt
    );
    scope_signature := encode(
        hmac(
            convert_to(
                'top_delivery:workflow_scope:v1:' || scope_payload::TEXT,
                'UTF8'
            ),
            convert_to(mac_key, 'UTF8'),
            'sha256'
        ),
        'hex'
    );
    PERFORM set_config('top_delivery.mutation_scope_payload', scope_payload::TEXT, true);
    PERFORM set_config('top_delivery.mutation_scope_signature', scope_signature, true);
    UPDATE parent_tasks
    SET state = 'queued',
        available_at = clock_timestamp(),
        attempt = next_attempt,
        active_attempt_id = NULL,
        updated_at = clock_timestamp()
    WHERE task_id = p_task_id
      AND run_id = p_run_id
      AND active_attempt_id = p_attempt_id
      AND state = 'blocked';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'blocked-task requeue lost the task fence';
    END IF;
    UPDATE task_attempts
    SET lease_expires_at = LEAST(lease_expires_at, clock_timestamp()),
        ended_at = COALESCE(ended_at, clock_timestamp())
    WHERE attempt_id = p_attempt_id
      AND status = 'blocked';
    v_retry_key := 'retry:' || p_run_id || ':' || p_task_id || ':attempt:' || next_attempt::TEXT;
    INSERT INTO retry_queue
        (retry_key, run_id, task_id, available_at, attempt, reason, state)
    VALUES (
        v_retry_key, p_run_id, p_task_id, clock_timestamp(), next_attempt,
        'operator_requeue_blocked', 'queued'
    )
    ON CONFLICT ON CONSTRAINT retry_queue_pkey DO NOTHING;
    PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
    PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
    RETURN jsonb_build_object(
        'requeued', true,
        'reason', 'requeued_blocked',
        'task_id', p_task_id,
        'attempt', next_attempt,
        'state', 'queued',
        'prior_attempt_id', p_attempt_id
    );
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
    PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
    RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

REVOKE ALL ON FUNCTION longspan_requeue_blocked_parent_task(TEXT, TEXT, TEXT, INTEGER, TEXT, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION longspan_requeue_blocked_parent_task(TEXT, TEXT, TEXT, INTEGER, TEXT, INTEGER)
    TO top_delivery_workflow;

-- Candidate trigger replacement. Apply only to disposable test databases in
-- this envelope. Do not apply to top_delivery_control_p1 and do not add Alembic
-- 014 in this envelope. Production remains at 013_cleanup_expired_attempt.
CREATE OR REPLACE FUNCTION public.require_longspan_mutation_scope()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public'
AS $function$
        DECLARE
            scope_payload JSONB;
            scope_signature TEXT;
            mac_key TEXT;
            row_data JSONB;
            row_run_id TEXT;
            expected_signature TEXT;
        BEGIN
            -- Failure-injection setup is permitted only for the signed,
            -- disposable test databases. The production control database
            -- can never satisfy this database-name boundary.
            IF session_user = '{WORKFLOW_ROLE}'
               AND (current_database() ~ '^td_test_'
                    OR current_database() ~ '^td_downgrade_')
               AND current_setting('top_delivery.disposable_test_mutation', true) = '1' THEN
                RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
            END IF;
            scope_payload := NULLIF(
                current_setting('top_delivery.mutation_scope_payload', true), ''
            )::JSONB;
            scope_signature := NULLIF(
                current_setting('top_delivery.mutation_scope_signature', true), ''
            );
            IF scope_payload IS NULL OR scope_signature IS NULL THEN
                RAISE EXCEPTION 'workflow mutation requires a database-owned mutation scope';
            END IF;
            IF scope_payload->>'scope_kind' = 'signal'
               AND TG_TABLE_NAME <> 'signal_status' THEN
                RAISE EXCEPTION 'signal mutation scope is limited to signal_status';
            END IF;
            IF scope_payload->>'scope_kind' IS DISTINCT FROM 'signal'
               AND scope_payload->>'scope_kind' IS DISTINCT FROM 'workflow'
               AND scope_payload->>'scope_kind' IS DISTINCT FROM 'controller' THEN
                RAISE EXCEPTION 'unknown workflow mutation scope kind';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') = 'general'
               AND TG_TABLE_NAME NOT IN (
                   'controller_control', 'supervisor_runs', 'parent_tasks',
                   'task_attempts', 'retry_queue', 'supervisor_events',
                   'notifications', 'signal_status', 'evidence_index',
                   'manifest_submissions', 'provenance_records',
                   'required_manifest_entries', 'longspan_experiments'
               ) THEN
                RAISE EXCEPTION
                    'general controller scope table is not in the explicit controller allowlist';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            expected_signature := encode(
                hmac(
                    convert_to(
                        CASE
                            WHEN scope_payload->>'scope_kind' = 'workflow'
                                THEN 'top_delivery:workflow_scope:v1:'
                            WHEN scope_payload->>'scope_kind' = 'signal'
                                AND COALESCE(scope_payload->>'rollback', 'false') = 'true'
                                THEN 'top_delivery:signal_rollback_scope:v1:'
                            WHEN scope_payload->>'scope_kind' = 'signal'
                                THEN 'top_delivery:signal_scope:v1:'
                            WHEN scope_payload->>'scope_kind' = 'controller'
                                AND COALESCE(scope_payload->>'operation', 'general') IN
                                    ('park_children', 'expire_stale_children')
                                THEN 'top_delivery:controller_maintenance_scope:v1:'
                            ELSE 'top_delivery:controller_scope:v1:'
                        END || scope_payload::TEXT,
                        'UTF8'
                    ),
                    convert_to(mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
            IF mac_key IS NULL OR scope_signature IS DISTINCT FROM expected_signature THEN
                RAISE EXCEPTION 'workflow mutation scope signature is invalid';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') <> 'register_run'
               AND scope_payload->>'controller_epoch' IS DISTINCT FROM (
                   SELECT current_epoch::TEXT FROM controller_control
                   WHERE run_id = scope_payload->>'run_id'
               ) THEN
                RAISE EXCEPTION 'workflow mutation scope epoch is stale';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') = 'acquire_controller'
               AND NOT EXISTS (
                   SELECT 1
                   FROM controller_control
                   WHERE run_id = scope_payload->>'run_id'
                     AND current_epoch = (scope_payload->>'controller_epoch')::INTEGER
                     AND controller_fence_token =
                         (scope_payload->>'controller_fence_token')::BIGINT
                     AND scheduling_enabled
               ) THEN
                RAISE EXCEPTION 'controller acquisition scope is stale';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') NOT IN
                   ('register_run', 'acquire_controller')
               AND NOT EXISTS (
                   SELECT 1
                   FROM controller_control
                   WHERE run_id = scope_payload->>'run_id'
                     AND current_epoch = (scope_payload->>'controller_epoch')::INTEGER
                     AND owner = scope_payload->>'owner'
                     AND controller_fence_token =
                         (scope_payload->>'controller_fence_token')::BIGINT
                     AND scheduling_enabled
                     AND lease_expires_at > clock_timestamp()
               ) THEN
                RAISE EXCEPTION 'controller mutation scope fence is stale';
            END IF;
            row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
            row_run_id := row_data->>'run_id';
            IF row_run_id IS NULL AND row_data ? 'child_id' THEN
                SELECT child.run_id INTO row_run_id
                FROM longspan_children AS child
                WHERE child.child_id = row_data->>'child_id';
            END IF;
            IF row_run_id IS DISTINCT FROM scope_payload->>'run_id' THEN
                RAISE EXCEPTION 'workflow mutation row is outside the scoped run';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'register_run'
               AND (TG_OP <> 'INSERT' OR TG_TABLE_NAME NOT IN (
                   'supervisor_runs', 'controller_control'
               )) THEN
                RAISE EXCEPTION 'run registration scope is limited to bootstrap inserts';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'acquire_controller'
               AND (TG_OP <> 'UPDATE' OR TG_TABLE_NAME <> 'controller_control') THEN
                RAISE EXCEPTION 'controller acquisition scope is limited to controller lease updates';
            END IF;

            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'schedule_goal_task'
               AND (TG_OP <> 'INSERT' OR TG_TABLE_NAME <> 'parent_tasks') THEN
                RAISE EXCEPTION 'schedule_goal_task scope is limited to parent task inserts';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'schedule_goal_task'
               AND TG_TABLE_NAME = 'parent_tasks'
               AND (
                   TG_OP <> 'INSERT'
                   OR (row_data->>'state') IS DISTINCT FROM 'queued'
                   OR COALESCE((row_data->>'attempt')::INTEGER, 0) IS DISTINCT FROM 0
               ) THEN
                RAISE EXCEPTION 'schedule_goal_task scope only permits queued parent inserts';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND TG_TABLE_NAME IN (
                   'parent_tasks', 'task_attempts', 'retry_queue', 'longspan_children',
                   'longspan_plans', 'longspan_execution_results',
                   'longspan_execution_audits', 'longspan_auditor_receipts',
                   'longspan_terra_receipts', 'longspan_evidence_ledger'
               )
               AND COALESCE(scope_payload->>'operation', 'general') NOT IN
                   ('park_children', 'expire_stale_children', 'schedule_goal_task') THEN
                RAISE EXCEPTION
                    'controller scope cannot directly mutate task or evidence rows';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' IN ('park_children', 'expire_stale_children')
               AND TG_TABLE_NAME NOT IN ('longspan_children', 'longspan_evidence_ledger') THEN
                RAISE EXCEPTION
                    'controller maintenance scope is limited to child and ledger rows';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'park_children'
               AND TG_TABLE_NAME = 'longspan_children'
               AND (TG_OP <> 'UPDATE' OR (row_data->>'state') IS DISTINCT FROM 'parked') THEN
                RAISE EXCEPTION 'park_children scope only permits parking child rows';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'expire_stale_children'
               AND TG_TABLE_NAME = 'longspan_children'
               AND (TG_OP <> 'UPDATE' OR (row_data->>'state') IS DISTINCT FROM 'retry_wait') THEN
                RAISE EXCEPTION 'expire_stale_children scope only permits retry-wait child rows';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' IN ('park_children', 'expire_stale_children')
               AND TG_TABLE_NAME = 'longspan_evidence_ledger'
               AND (
                   TG_OP <> 'INSERT'
                   OR (row_data->>'event_type') IS DISTINCT FROM CASE
                       WHEN scope_payload->>'operation' = 'park_children'
                       THEN 'controller_parked'
                       ELSE 'lease_expired'
                   END
               ) THEN
                RAISE EXCEPTION 'controller maintenance scope only permits its ledger event';
            END IF;
            -- A run-level scope is not sufficient for task mutations.  Bind
            -- every task/child/retry row to the exact live parent fence and
            -- task identity carried by the row; otherwise a valid worker
            -- could update an unrelated same-run task.
            IF scope_payload->>'scope_kind' = 'workflow'
               AND TG_TABLE_NAME IN (
                   'parent_tasks', 'task_attempts', 'retry_queue', 'longspan_children'
               ) THEN

                IF scope_payload->>'operation' = 'cleanup_expired_attempt' THEN
                    IF scope_payload->>'attempt_id' IS NULL THEN
                        RAISE EXCEPTION 'cleanup scope requires attempt_id';
                    END IF;
                    IF TG_TABLE_NAME = 'task_attempts' THEN
                        IF row_data->>'attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'cleanup attempt mismatch';
                        END IF;
                        IF TG_OP <> 'UPDATE'
                           OR (row_data->>'status') NOT IN ('stale', 'failed') THEN
                            RAISE EXCEPTION
                                'cleanup scope only permits stale or failed attempt terminalization';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'parent_tasks' THEN
                        IF (
                            CASE
                                WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD)->>'active_attempt_id'
                                ELSE row_data->>'active_attempt_id'
                            END
                        ) IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'cleanup parent attempt mismatch';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                        IF TG_OP <> 'INSERT' THEN
                            RAISE EXCEPTION 'cleanup retry scope only permits inserts';
                        END IF;
                    ELSE
                        RAISE EXCEPTION 'cleanup scope is limited to parent, attempt, and retry rows';
                    END IF;
                    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
                END IF;
                IF scope_payload->>'operation' = 'requeue_blocked_parent_task' THEN
                    IF scope_payload->>'attempt_id' IS NULL THEN
                        RAISE EXCEPTION 'requeue scope requires attempt_id';
                    END IF;
                    IF TG_TABLE_NAME = 'parent_tasks' THEN
                        IF TG_OP <> 'UPDATE' THEN
                            RAISE EXCEPTION 'requeue parent scope only permits updates';
                        END IF;
                        IF to_jsonb(OLD)->>'active_attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'requeue parent attempt mismatch';
                        END IF;
                        IF (row_data->>'state') IS DISTINCT FROM 'queued'
                           OR (row_data->>'active_attempt_id') IS NOT NULL
                           OR (row_data->>'task_id') IS DISTINCT FROM scope_payload->>'task_id'
                           OR (row_data->>'run_id') IS DISTINCT FROM scope_payload->>'run_id'
                           OR (row_data->>'attempt') IS DISTINCT FROM scope_payload->>'next_attempt'
                           OR (row_data->>'objective') IS DISTINCT FROM to_jsonb(OLD)->>'objective'
                           OR (row_data->>'priority') IS DISTINCT FROM to_jsonb(OLD)->>'priority' THEN
                            RAISE EXCEPTION
                                'requeue scope only permits queued parent rows with no active attempt';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'task_attempts' THEN
                        IF row_data->>'attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'requeue attempt mismatch';
                        END IF;
                        IF TG_OP <> 'UPDATE'
                           OR (row_data->>'status') IS DISTINCT FROM 'blocked' THEN
                            RAISE EXCEPTION
                                'requeue scope only permits blocked attempt terminalization';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                        IF TG_OP <> 'INSERT' THEN
                            RAISE EXCEPTION 'requeue retry scope only permits inserts';
                        END IF;
                        IF (row_data->>'reason') IS DISTINCT FROM 'operator_requeue_blocked'
                           OR (row_data->>'state') IS DISTINCT FROM 'queued'
                           OR (row_data->>'task_id') IS DISTINCT FROM scope_payload->>'task_id'
                           OR (row_data->>'run_id') IS DISTINCT FROM scope_payload->>'run_id'
                           OR (row_data->>'attempt') IS DISTINCT FROM scope_payload->>'next_attempt' THEN
                            RAISE EXCEPTION 'requeue retry row is outside the scoped parent fence';
                        END IF;
                    ELSE
                        RAISE EXCEPTION 'requeue scope is limited to parent, attempt, and retry rows';
                    END IF;
                    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
                END IF;
                IF TG_TABLE_NAME = 'task_attempts' THEN
                    IF row_data->>'fence_token' IS DISTINCT FROM scope_payload->>'fence_token'
                       OR row_data->>'controller_epoch' IS DISTINCT FROM scope_payload->>'controller_epoch'
                       OR (
                           TG_OP = 'INSERT'
                           AND row_data->>'status' IS DISTINCT FROM 'running'
                       ) THEN
                        RAISE EXCEPTION
                            'workflow mutation task attempt is outside the scoped parent fence';
                    END IF;
                ELSIF TG_TABLE_NAME = 'longspan_children' THEN
                    IF row_data->>'fence_token' IS DISTINCT FROM scope_payload->>'fence_token'
                       OR NOT EXISTS (
                           SELECT 1
                           FROM task_attempts AS attempt
                           WHERE attempt.attempt_id = row_data->>'parent_attempt_id'
                             AND attempt.task_id = row_data->>'task_id'
                             AND attempt.run_id = scope_payload->>'run_id'
                             AND attempt.fence_token = (scope_payload->>'fence_token')::BIGINT
                             AND attempt.controller_epoch = (scope_payload->>'controller_epoch')::BIGINT
                             AND attempt.status = 'running'
                             AND attempt.lease_expires_at > clock_timestamp()
                       ) THEN
                        RAISE EXCEPTION
                            'workflow mutation child is outside the scoped parent fence';
                    END IF;
                ELSIF TG_TABLE_NAME = 'parent_tasks' THEN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM task_attempts AS attempt
                        WHERE attempt.attempt_id = COALESCE(
                            row_data->>'active_attempt_id',
                            (
                                SELECT parent.active_attempt_id
                                FROM parent_tasks AS parent
                                WHERE parent.task_id = row_data->>'task_id'
                                  AND parent.run_id = scope_payload->>'run_id'
                            )
                        )
                          AND attempt.task_id = row_data->>'task_id'
                          AND attempt.run_id = scope_payload->>'run_id'
                          AND attempt.fence_token = (scope_payload->>'fence_token')::BIGINT
                          AND attempt.controller_epoch = (scope_payload->>'controller_epoch')::BIGINT
                          AND attempt.status = 'running'
                          AND attempt.lease_expires_at > clock_timestamp()
                    ) THEN
                        RAISE EXCEPTION
                            'workflow mutation task row is outside the scoped parent fence';
                    END IF;
                ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM parent_tasks AS parent
                        JOIN task_attempts AS attempt
                          ON attempt.attempt_id = parent.active_attempt_id
                         AND attempt.task_id = parent.task_id
                         AND attempt.run_id = parent.run_id
                        WHERE parent.task_id = row_data->>'task_id'
                          AND parent.run_id = scope_payload->>'run_id'
                          AND attempt.fence_token = (scope_payload->>'fence_token')::BIGINT
                          AND attempt.controller_epoch = (scope_payload->>'controller_epoch')::BIGINT
                          AND attempt.status = 'running'
                          AND attempt.lease_expires_at > clock_timestamp()
                    ) THEN
                        RAISE EXCEPTION
                            'workflow mutation retry row is outside the scoped parent fence';
                    END IF;
                END IF;
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END;
        $function$
"""

DOWNGRADE_SQL = r"""

DROP FUNCTION IF EXISTS longspan_requeue_blocked_parent_task(TEXT, TEXT, TEXT, INTEGER, TEXT, INTEGER);
CREATE OR REPLACE FUNCTION public.require_longspan_mutation_scope()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public'
AS $function$
        DECLARE
            scope_payload JSONB;
            scope_signature TEXT;
            mac_key TEXT;
            row_data JSONB;
            row_run_id TEXT;
            expected_signature TEXT;
        BEGIN
            -- Failure-injection setup is permitted only for the signed,
            -- disposable test databases. The production control database
            -- can never satisfy this database-name boundary.
            IF session_user = '{WORKFLOW_ROLE}'
               AND (current_database() ~ '^td_test_'
                    OR current_database() ~ '^td_downgrade_')
               AND current_setting('top_delivery.disposable_test_mutation', true) = '1' THEN
                RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
            END IF;
            scope_payload := NULLIF(
                current_setting('top_delivery.mutation_scope_payload', true), ''
            )::JSONB;
            scope_signature := NULLIF(
                current_setting('top_delivery.mutation_scope_signature', true), ''
            );
            IF scope_payload IS NULL OR scope_signature IS NULL THEN
                RAISE EXCEPTION 'workflow mutation requires a database-owned mutation scope';
            END IF;
            IF scope_payload->>'scope_kind' = 'signal'
               AND TG_TABLE_NAME <> 'signal_status' THEN
                RAISE EXCEPTION 'signal mutation scope is limited to signal_status';
            END IF;
            IF scope_payload->>'scope_kind' IS DISTINCT FROM 'signal'
               AND scope_payload->>'scope_kind' IS DISTINCT FROM 'workflow'
               AND scope_payload->>'scope_kind' IS DISTINCT FROM 'controller' THEN
                RAISE EXCEPTION 'unknown workflow mutation scope kind';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') = 'general'
               AND TG_TABLE_NAME NOT IN (
                   'controller_control', 'supervisor_runs', 'parent_tasks',
                   'task_attempts', 'retry_queue', 'supervisor_events',
                   'notifications', 'signal_status', 'evidence_index',
                   'manifest_submissions', 'provenance_records',
                   'required_manifest_entries', 'longspan_experiments'
               ) THEN
                RAISE EXCEPTION
                    'general controller scope table is not in the explicit controller allowlist';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            expected_signature := encode(
                hmac(
                    convert_to(
                        CASE
                            WHEN scope_payload->>'scope_kind' = 'workflow'
                                THEN 'top_delivery:workflow_scope:v1:'
                            WHEN scope_payload->>'scope_kind' = 'signal'
                                AND COALESCE(scope_payload->>'rollback', 'false') = 'true'
                                THEN 'top_delivery:signal_rollback_scope:v1:'
                            WHEN scope_payload->>'scope_kind' = 'signal'
                                THEN 'top_delivery:signal_scope:v1:'
                            WHEN scope_payload->>'scope_kind' = 'controller'
                                AND COALESCE(scope_payload->>'operation', 'general') IN
                                    ('park_children', 'expire_stale_children')
                                THEN 'top_delivery:controller_maintenance_scope:v1:'
                            ELSE 'top_delivery:controller_scope:v1:'
                        END || scope_payload::TEXT,
                        'UTF8'
                    ),
                    convert_to(mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
            IF mac_key IS NULL OR scope_signature IS DISTINCT FROM expected_signature THEN
                RAISE EXCEPTION 'workflow mutation scope signature is invalid';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') <> 'register_run'
               AND scope_payload->>'controller_epoch' IS DISTINCT FROM (
                   SELECT current_epoch::TEXT FROM controller_control
                   WHERE run_id = scope_payload->>'run_id'
               ) THEN
                RAISE EXCEPTION 'workflow mutation scope epoch is stale';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') = 'acquire_controller'
               AND NOT EXISTS (
                   SELECT 1
                   FROM controller_control
                   WHERE run_id = scope_payload->>'run_id'
                     AND current_epoch = (scope_payload->>'controller_epoch')::INTEGER
                     AND controller_fence_token =
                         (scope_payload->>'controller_fence_token')::BIGINT
                     AND scheduling_enabled
               ) THEN
                RAISE EXCEPTION 'controller acquisition scope is stale';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') NOT IN
                   ('register_run', 'acquire_controller')
               AND NOT EXISTS (
                   SELECT 1
                   FROM controller_control
                   WHERE run_id = scope_payload->>'run_id'
                     AND current_epoch = (scope_payload->>'controller_epoch')::INTEGER
                     AND owner = scope_payload->>'owner'
                     AND controller_fence_token =
                         (scope_payload->>'controller_fence_token')::BIGINT
                     AND scheduling_enabled
                     AND lease_expires_at > clock_timestamp()
               ) THEN
                RAISE EXCEPTION 'controller mutation scope fence is stale';
            END IF;
            row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
            row_run_id := row_data->>'run_id';
            IF row_run_id IS NULL AND row_data ? 'child_id' THEN
                SELECT child.run_id INTO row_run_id
                FROM longspan_children AS child
                WHERE child.child_id = row_data->>'child_id';
            END IF;
            IF row_run_id IS DISTINCT FROM scope_payload->>'run_id' THEN
                RAISE EXCEPTION 'workflow mutation row is outside the scoped run';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'register_run'
               AND (TG_OP <> 'INSERT' OR TG_TABLE_NAME NOT IN (
                   'supervisor_runs', 'controller_control'
               )) THEN
                RAISE EXCEPTION 'run registration scope is limited to bootstrap inserts';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'acquire_controller'
               AND (TG_OP <> 'UPDATE' OR TG_TABLE_NAME <> 'controller_control') THEN
                RAISE EXCEPTION 'controller acquisition scope is limited to controller lease updates';
            END IF;

            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'schedule_goal_task'
               AND (TG_OP <> 'INSERT' OR TG_TABLE_NAME <> 'parent_tasks') THEN
                RAISE EXCEPTION 'schedule_goal_task scope is limited to parent task inserts';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'schedule_goal_task'
               AND TG_TABLE_NAME = 'parent_tasks'
               AND (
                   TG_OP <> 'INSERT'
                   OR (row_data->>'state') IS DISTINCT FROM 'queued'
                   OR COALESCE((row_data->>'attempt')::INTEGER, 0) IS DISTINCT FROM 0
               ) THEN
                RAISE EXCEPTION 'schedule_goal_task scope only permits queued parent inserts';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND TG_TABLE_NAME IN (
                   'parent_tasks', 'task_attempts', 'retry_queue', 'longspan_children',
                   'longspan_plans', 'longspan_execution_results',
                   'longspan_execution_audits', 'longspan_auditor_receipts',
                   'longspan_terra_receipts', 'longspan_evidence_ledger'
               )
               AND COALESCE(scope_payload->>'operation', 'general') NOT IN
                   ('park_children', 'expire_stale_children', 'schedule_goal_task') THEN
                RAISE EXCEPTION
                    'controller scope cannot directly mutate task or evidence rows';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' IN ('park_children', 'expire_stale_children')
               AND TG_TABLE_NAME NOT IN ('longspan_children', 'longspan_evidence_ledger') THEN
                RAISE EXCEPTION
                    'controller maintenance scope is limited to child and ledger rows';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'park_children'
               AND TG_TABLE_NAME = 'longspan_children'
               AND (TG_OP <> 'UPDATE' OR (row_data->>'state') IS DISTINCT FROM 'parked') THEN
                RAISE EXCEPTION 'park_children scope only permits parking child rows';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'expire_stale_children'
               AND TG_TABLE_NAME = 'longspan_children'
               AND (TG_OP <> 'UPDATE' OR (row_data->>'state') IS DISTINCT FROM 'retry_wait') THEN
                RAISE EXCEPTION 'expire_stale_children scope only permits retry-wait child rows';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' IN ('park_children', 'expire_stale_children')
               AND TG_TABLE_NAME = 'longspan_evidence_ledger'
               AND (
                   TG_OP <> 'INSERT'
                   OR (row_data->>'event_type') IS DISTINCT FROM CASE
                       WHEN scope_payload->>'operation' = 'park_children'
                       THEN 'controller_parked'
                       ELSE 'lease_expired'
                   END
               ) THEN
                RAISE EXCEPTION 'controller maintenance scope only permits its ledger event';
            END IF;
            -- A run-level scope is not sufficient for task mutations.  Bind
            -- every task/child/retry row to the exact live parent fence and
            -- task identity carried by the row; otherwise a valid worker
            -- could update an unrelated same-run task.
            IF scope_payload->>'scope_kind' = 'workflow'
               AND TG_TABLE_NAME IN (
                   'parent_tasks', 'task_attempts', 'retry_queue', 'longspan_children'
               ) THEN

                IF scope_payload->>'operation' = 'cleanup_expired_attempt' THEN
                    IF scope_payload->>'attempt_id' IS NULL THEN
                        RAISE EXCEPTION 'cleanup scope requires attempt_id';
                    END IF;
                    IF TG_TABLE_NAME = 'task_attempts' THEN
                        IF row_data->>'attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'cleanup attempt mismatch';
                        END IF;
                        IF TG_OP <> 'UPDATE'
                           OR (row_data->>'status') NOT IN ('stale', 'failed') THEN
                            RAISE EXCEPTION
                                'cleanup scope only permits stale or failed attempt terminalization';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'parent_tasks' THEN
                        IF (
                            CASE
                                WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD)->>'active_attempt_id'
                                ELSE row_data->>'active_attempt_id'
                            END
                        ) IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'cleanup parent attempt mismatch';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                        IF TG_OP <> 'INSERT' THEN
                            RAISE EXCEPTION 'cleanup retry scope only permits inserts';
                        END IF;
                    ELSE
                        RAISE EXCEPTION 'cleanup scope is limited to parent, attempt, and retry rows';
                    END IF;
                    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
                END IF;
                IF TG_TABLE_NAME = 'task_attempts' THEN
                    IF row_data->>'fence_token' IS DISTINCT FROM scope_payload->>'fence_token'
                       OR row_data->>'controller_epoch' IS DISTINCT FROM scope_payload->>'controller_epoch'
                       OR (
                           TG_OP = 'INSERT'
                           AND row_data->>'status' IS DISTINCT FROM 'running'
                       ) THEN
                        RAISE EXCEPTION
                            'workflow mutation task attempt is outside the scoped parent fence';
                    END IF;
                ELSIF TG_TABLE_NAME = 'longspan_children' THEN
                    IF row_data->>'fence_token' IS DISTINCT FROM scope_payload->>'fence_token'
                       OR NOT EXISTS (
                           SELECT 1
                           FROM task_attempts AS attempt
                           WHERE attempt.attempt_id = row_data->>'parent_attempt_id'
                             AND attempt.task_id = row_data->>'task_id'
                             AND attempt.run_id = scope_payload->>'run_id'
                             AND attempt.fence_token = (scope_payload->>'fence_token')::BIGINT
                             AND attempt.controller_epoch = (scope_payload->>'controller_epoch')::BIGINT
                             AND attempt.status = 'running'
                             AND attempt.lease_expires_at > clock_timestamp()
                       ) THEN
                        RAISE EXCEPTION
                            'workflow mutation child is outside the scoped parent fence';
                    END IF;
                ELSIF TG_TABLE_NAME = 'parent_tasks' THEN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM task_attempts AS attempt
                        WHERE attempt.attempt_id = COALESCE(
                            row_data->>'active_attempt_id',
                            (
                                SELECT parent.active_attempt_id
                                FROM parent_tasks AS parent
                                WHERE parent.task_id = row_data->>'task_id'
                                  AND parent.run_id = scope_payload->>'run_id'
                            )
                        )
                          AND attempt.task_id = row_data->>'task_id'
                          AND attempt.run_id = scope_payload->>'run_id'
                          AND attempt.fence_token = (scope_payload->>'fence_token')::BIGINT
                          AND attempt.controller_epoch = (scope_payload->>'controller_epoch')::BIGINT
                          AND attempt.status = 'running'
                          AND attempt.lease_expires_at > clock_timestamp()
                    ) THEN
                        RAISE EXCEPTION
                            'workflow mutation task row is outside the scoped parent fence';
                    END IF;
                ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM parent_tasks AS parent
                        JOIN task_attempts AS attempt
                          ON attempt.attempt_id = parent.active_attempt_id
                         AND attempt.task_id = parent.task_id
                         AND attempt.run_id = parent.run_id
                        WHERE parent.task_id = row_data->>'task_id'
                          AND parent.run_id = scope_payload->>'run_id'
                          AND attempt.fence_token = (scope_payload->>'fence_token')::BIGINT
                          AND attempt.controller_epoch = (scope_payload->>'controller_epoch')::BIGINT
                          AND attempt.status = 'running'
                          AND attempt.lease_expires_at > clock_timestamp()
                    ) THEN
                        RAISE EXCEPTION
                            'workflow mutation retry row is outside the scoped parent fence';
                    END IF;
                END IF;
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END;
        $function$
"""


def upgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(UPGRADE_SQL.replace("{WORKFLOW_ROLE}", WORKFLOW_ROLE))


def downgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(DOWNGRADE_SQL.replace("{WORKFLOW_ROLE}", WORKFLOW_ROLE))
