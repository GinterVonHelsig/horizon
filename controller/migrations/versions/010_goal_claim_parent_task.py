"""Authorize worker parent-task claims through a database-owned workflow scope.

Revision ID: 010_goal_claim_parent_task
Revises: 009_goal_schedule_task
"""

from __future__ import annotations

from alembic import op
from authority_pins import (
    AUTHORITY_DATABASE_ROLE,
    MIGRATION_SOURCE_PROVENANCE_PATH,
    WORKFLOW_DATABASE_ROLE,
)
from migration_catalog import assert_migration_catalog
from migration_source_anchor import verify_migration_source_anchor

revision = "010_goal_claim_parent_task"
down_revision = "009_goal_schedule_task"
branch_labels = None
depends_on = None

MIGRATION_ROLE = "top_delivery_migration"
WORKFLOW_ROLE = WORKFLOW_DATABASE_ROLE
AUTHORITY_ROLE = AUTHORITY_DATABASE_ROLE


def upgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION longspan_claim_next_parent_task(
            p_run_id TEXT,
            p_owner TEXT,
            p_controller_epoch INTEGER,
            p_lease_seconds DOUBLE PRECISION
        ) RETURNS JSONB AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            task_row parent_tasks%ROWTYPE;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
            attempt_id TEXT;
            next_fence_token BIGINT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'parent task claim requires the workflow principal';
            END IF;
            IF p_owner IS NULL OR btrim(p_owner) = '' THEN
                RAISE EXCEPTION 'parent task claim requires an owner';
            END IF;
            IF p_lease_seconds IS NULL OR p_lease_seconds <= 0 THEN
                RAISE EXCEPTION 'parent task claim requires a positive lease duration';
            END IF;
            SELECT * INTO control_row
            FROM controller_control
            WHERE run_id = p_run_id;
            IF NOT FOUND
               OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR NOT control_row.scheduling_enabled
               OR control_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'parent task claim is not bound to a live controller lease';
            END IF;
            SELECT * INTO task_row
            FROM parent_tasks
            WHERE run_id = p_run_id
              AND state = 'queued'
              AND available_at <= clock_timestamp()
            ORDER BY priority DESC, available_at, task_id
            FOR UPDATE SKIP LOCKED
            LIMIT 1;
            IF NOT FOUND THEN
                RETURN NULL;
            END IF;
            attempt_id := replace(gen_random_uuid()::TEXT, '-', '');
            SELECT COALESCE(MAX(ta.fence_token), 0) + 1 INTO next_fence_token
            FROM task_attempts AS ta
            WHERE ta.task_id = task_row.task_id;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'parent task claim mutation MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'workflow',
                'run_id', p_run_id,
                'controller_epoch', p_controller_epoch,
                'fence_token', next_fence_token
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
            INSERT INTO task_attempts
                (attempt_id, task_id, run_id, fence_token, controller_epoch, owner,
                 status, heartbeat_at, lease_expires_at)
            VALUES (
                attempt_id,
                task_row.task_id,
                p_run_id,
                next_fence_token,
                p_controller_epoch,
                p_owner,
                'running',
                clock_timestamp(),
                clock_timestamp() + (p_lease_seconds || ' seconds')::interval
            );
            UPDATE parent_tasks
            SET state = 'leased',
                active_attempt_id = attempt_id,
                updated_at = clock_timestamp()
            WHERE task_id = task_row.task_id;
            PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
            PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
            RETURN jsonb_build_object(
                'task_id', task_row.task_id,
                'run_id', p_run_id,
                'objective', task_row.objective,
                'state', 'leased',
                'priority', task_row.priority,
                'available_at', task_row.available_at,
                'attempt', task_row.attempt,
                'active_attempt_id', attempt_id,
                'updated_at', clock_timestamp(),
                'attempt_id', attempt_id,
                'fence_token', next_fence_token,
                'owner', p_owner,
                'status', 'running',
                'lease_expires_at', clock_timestamp() + (p_lease_seconds || ' seconds')::interval
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        ALTER FUNCTION longspan_claim_next_parent_task(TEXT, TEXT, INTEGER, DOUBLE PRECISION)
            OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON FUNCTION longspan_claim_next_parent_task(TEXT, TEXT, INTEGER, DOUBLE PRECISION)
            FROM PUBLIC, {AUTHORITY_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_claim_next_parent_task(TEXT, TEXT, INTEGER, DOUBLE PRECISION)
            TO {WORKFLOW_ROLE};
        """
    )


def downgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(
        "DROP FUNCTION IF EXISTS longspan_claim_next_parent_task(TEXT, TEXT, INTEGER, DOUBLE PRECISION);"
    )
