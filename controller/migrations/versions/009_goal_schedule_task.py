"""Authorize goal task scheduling through a database-owned controller scope.

Revision ID: 009_goal_schedule_task
Revises: 008_longspan_authority_repair
"""

from __future__ import annotations

from alembic import op
from authority_pins import (
    AUTHORITY_DATABASE_ROLE,
    MIGRATION_DATABASE_ROLE,
    MIGRATION_SOURCE_PROVENANCE_PATH,
    WORKFLOW_DATABASE_ROLE,
)
from migration_catalog import assert_migration_catalog
from migration_source_anchor import verify_migration_source_anchor

revision = "009_goal_schedule_task"
down_revision = "008_longspan_authority_repair"
branch_labels = None
depends_on = None

MIGRATION_ROLE = MIGRATION_DATABASE_ROLE
WORKFLOW_ROLE = WORKFLOW_DATABASE_ROLE
AUTHORITY_ROLE = AUTHORITY_DATABASE_ROLE


def upgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(
        f"""
        
        CREATE OR REPLACE FUNCTION longspan_schedule_goal_task(
            p_run_id TEXT,
            p_task_id TEXT,
            p_objective TEXT,
            p_priority INTEGER,
            p_available_at TIMESTAMPTZ,
            p_controller_epoch INTEGER,
            p_owner TEXT,
            p_expected_controller_fence BIGINT
        ) RETURNS JSONB AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
            inserted BOOLEAN;
            task_row parent_tasks%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'goal task scheduling requires the workflow principal';
            END IF;
            IF p_task_id IS NULL OR btrim(p_task_id) = '' THEN
                RAISE EXCEPTION 'task id is required';
            END IF;
            IF p_objective IS NULL OR btrim(p_objective) = '' THEN
                RAISE EXCEPTION 'objective is required';
            END IF;
            IF p_owner IS NULL OR btrim(p_owner) = '' THEN
                RAISE EXCEPTION 'goal task scheduling requires a fenced owner';
            END IF;
            IF p_expected_controller_fence IS NULL OR p_expected_controller_fence <= 0 THEN
                RAISE EXCEPTION 'goal task scheduling requires a positive expected controller fence';
            END IF;
            SELECT * INTO control_row
            FROM controller_control
            WHERE run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR control_row.owner IS DISTINCT FROM p_owner
               OR control_row.controller_fence_token IS DISTINCT FROM p_expected_controller_fence
               OR control_row.controller_fence_token IS NULL
               OR control_row.controller_fence_token <= 0
               OR NOT control_row.scheduling_enabled
               OR control_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'goal task scheduling is not bound to the live controller lease';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'goal task scheduling mutation MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'controller',
                'run_id', p_run_id,
                'controller_epoch', p_controller_epoch,
                'controller_fence_token', p_expected_controller_fence,
                'owner', p_owner,
                'operation', 'schedule_goal_task'
            );
            scope_signature := encode(
                hmac(
                    convert_to(
                        'top_delivery:controller_scope:v1:' || scope_payload::TEXT,
                        'UTF8'
                    ),
                    convert_to(mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
            PERFORM set_config('top_delivery.mutation_scope_payload', scope_payload::TEXT, true);
            PERFORM set_config('top_delivery.mutation_scope_signature', scope_signature, true);
            INSERT INTO parent_tasks
                (task_id, run_id, objective, state, priority, available_at, attempt, updated_at)
            VALUES (
                p_task_id,
                p_run_id,
                p_objective,
                'queued',
                COALESCE(p_priority, 0),
                COALESCE(p_available_at, clock_timestamp()),
                0,
                clock_timestamp()
            )
            ON CONFLICT (task_id) DO NOTHING
            RETURNING * INTO task_row;
            inserted := FOUND;
            IF NOT inserted THEN
                SELECT * INTO task_row
                FROM parent_tasks
                WHERE task_id = p_task_id;
            END IF;
            IF task_row.run_id IS DISTINCT FROM p_run_id
               OR task_row.objective IS DISTINCT FROM p_objective THEN
                RAISE EXCEPTION 'task_id is already owned by another run or objective';
            END IF;
            PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
            PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
            RETURN jsonb_build_object(
                'created', inserted,
                'task_id', task_row.task_id,
                'run_id', task_row.run_id,
                'objective', task_row.objective,
                'state', task_row.state,
                'priority', task_row.priority,
                'available_at', task_row.available_at,
                'attempt', task_row.attempt,
                'active_attempt_id', task_row.active_attempt_id,
                'updated_at', task_row.updated_at
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        """
    )
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION require_longspan_mutation_scope()
        RETURNS trigger AS $$
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
                ELSIF TG_TABLE_NAME IN ('parent_tasks', 'retry_queue') THEN
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
                            'workflow mutation task or retry row is outside the scoped parent fence';
                    END IF;
                END IF;
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;
        """
    )
    op.execute(
        f"""
        ALTER FUNCTION longspan_schedule_goal_task(
            TEXT, TEXT, TEXT, INTEGER, TIMESTAMPTZ, INTEGER, TEXT, BIGINT
        ) OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON FUNCTION longspan_schedule_goal_task(
            TEXT, TEXT, TEXT, INTEGER, TIMESTAMPTZ, INTEGER, TEXT, BIGINT
        ) FROM PUBLIC, {AUTHORITY_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_schedule_goal_task(
            TEXT, TEXT, TEXT, INTEGER, TIMESTAMPTZ, INTEGER, TEXT, BIGINT
        ) TO {WORKFLOW_ROLE};
        ALTER FUNCTION require_longspan_mutation_scope() OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON FUNCTION require_longspan_mutation_scope() FROM PUBLIC;
        """
    )


def downgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute("DROP FUNCTION IF EXISTS longspan_schedule_goal_task(TEXT, TEXT, TEXT, INTEGER, TIMESTAMPTZ, INTEGER, TEXT, BIGINT);")
