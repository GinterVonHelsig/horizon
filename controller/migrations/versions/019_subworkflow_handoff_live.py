"""Live-stack horizon migration above 018_horizon_project_ledger_live.

Revision ID: 019_subworkflow_handoff_live
Revises: 018_horizon_project_ledger_live
"""

from __future__ import annotations

from alembic import op
from authority_pins import MIGRATION_SOURCE_PROVENANCE_PATH, WORKFLOW_DATABASE_ROLE
from migration_catalog import assert_migration_catalog
from migration_source_anchor import verify_migration_source_anchor

revision = "019_subworkflow_handoff_live"
down_revision = "018_horizon_project_ledger_live"
branch_labels = None
depends_on = None

MIGRATION_ROLE = "top_delivery_migration"
WORKFLOW_ROLE = WORKFLOW_DATABASE_ROLE


def _assert_apply_target() -> None:
    bind = op.get_bind()
    database = bind.exec_driver_sql("SELECT current_database()").scalar_one()
    name = str(database)
    if name.startswith("td_test_") or name == "top_delivery_control_p1":
        return
    raise RuntimeError(
        "019_subworkflow_handoff_live may apply only on disposable td_test_* clones or live top_delivery_control_p1"
    )


def upgrade() -> None:
    _assert_apply_target()
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(
        f"""
        CREATE TABLE IF NOT EXISTS subworkflow_handoffs (
            handoff_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            parent_task_id TEXT NOT NULL REFERENCES parent_tasks(task_id),
            parent_attempt_id TEXT NOT NULL,
            provider_task_id TEXT NOT NULL REFERENCES parent_tasks(task_id),
            failure_code TEXT NOT NULL,
            provider_key TEXT NOT NULL,
            product_contract TEXT NOT NULL,
            request_json JSONB NOT NULL,
            request_digest TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('created','dispatched','running','completed','rejected','expired','failed')),
            provider_attempt INTEGER NOT NULL DEFAULT 0,
            product_json JSONB,
            product_digest TEXT,
            last_error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            completed_at TIMESTAMPTZ,
            UNIQUE (run_id, parent_task_id, request_digest),
            UNIQUE (provider_task_id)
        );
        CREATE INDEX IF NOT EXISTS subworkflow_handoffs_parent_idx
            ON subworkflow_handoffs (run_id, parent_task_id, state, updated_at);
        CREATE INDEX IF NOT EXISTS subworkflow_handoffs_expiry_idx
            ON subworkflow_handoffs (state, updated_at);

        CREATE OR REPLACE FUNCTION longspan_create_subworkflow_handoff(
            p_run_id TEXT,
            p_parent_task_id TEXT,
            p_parent_attempt_id TEXT,
            p_parent_fence_token BIGINT,
            p_controller_epoch INTEGER,
            p_handoff_id TEXT,
            p_provider_task_id TEXT,
            p_failure_code TEXT,
            p_provider_key TEXT,
            p_product_contract TEXT,
            p_request_json JSONB,
            p_request_digest TEXT,
            p_provider_objective TEXT,
            p_provider_priority INTEGER
        ) RETURNS JSONB AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            parent_row parent_tasks%ROWTYPE;
            attempt_row task_attempts%ROWTYPE;
            existing_row subworkflow_handoffs%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'subworkflow handoff requires the workflow principal';
            END IF;
            SELECT * INTO control_row
            FROM controller_control
            WHERE run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR NOT control_row.scheduling_enabled
               OR control_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'subworkflow handoff is not bound to a live controller lease';
            END IF;
            SELECT * INTO existing_row
            FROM subworkflow_handoffs
            WHERE run_id = p_run_id
              AND parent_task_id = p_parent_task_id
              AND request_digest = p_request_digest
              AND state NOT IN ('completed','rejected','expired','failed')
            FOR UPDATE;
            IF FOUND THEN
                RETURN jsonb_build_object(
                    'handoff_id', existing_row.handoff_id,
                    'provider_task_id', existing_row.provider_task_id,
                    'state', existing_row.state,
                    'created', false
                );
            END IF;
            SELECT * INTO parent_row
            FROM parent_tasks
            WHERE task_id = p_parent_task_id AND run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND OR parent_row.state <> 'leased' OR parent_row.active_attempt_id <> p_parent_attempt_id THEN
                RAISE EXCEPTION 'subworkflow parent task is not the active fenced attempt';
            END IF;
            SELECT * INTO attempt_row
            FROM task_attempts
            WHERE attempt_id = p_parent_attempt_id
              AND task_id = p_parent_task_id
              AND run_id = p_run_id
              AND fence_token = p_parent_fence_token
              AND controller_epoch = p_controller_epoch
              AND status = 'running'
            FOR UPDATE;
            IF NOT FOUND OR attempt_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'subworkflow parent attempt is not live';
            END IF;
            INSERT INTO parent_tasks(task_id, run_id, objective, state, priority, available_at, attempt)
            VALUES (p_provider_task_id, p_run_id, p_provider_objective, 'queued', p_provider_priority, clock_timestamp(), 0)
            ON CONFLICT (task_id) DO NOTHING;
            INSERT INTO subworkflow_handoffs(
                handoff_id, run_id, parent_task_id, parent_attempt_id,
                provider_task_id, failure_code, provider_key, product_contract,
                request_json, request_digest, state
            ) VALUES (
                p_handoff_id, p_run_id, p_parent_task_id, p_parent_attempt_id,
                p_provider_task_id, p_failure_code, p_provider_key, p_product_contract,
                p_request_json, p_request_digest, 'dispatched'
            );
            UPDATE task_attempts
            SET status = 'handoff_waiting', ended_at = clock_timestamp()
            WHERE attempt_id = p_parent_attempt_id
              AND task_id = p_parent_task_id
              AND run_id = p_run_id
              AND fence_token = p_parent_fence_token
              AND controller_epoch = p_controller_epoch
              AND status = 'running';
            IF NOT FOUND THEN
                RAISE EXCEPTION 'subworkflow parent attempt transition lost the fence';
            END IF;
            UPDATE parent_tasks
            SET state = 'parked', active_attempt_id = NULL, updated_at = clock_timestamp()
            WHERE task_id = p_parent_task_id AND run_id = p_run_id
              AND active_attempt_id = p_parent_attempt_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'subworkflow parent park lost the fence';
            END IF;
            RETURN jsonb_build_object(
                'handoff_id', p_handoff_id,
                'provider_task_id', p_provider_task_id,
                'state', 'dispatched',
                'created', true
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_complete_subworkflow_handoff(
            p_handoff_id TEXT,
            p_run_id TEXT,
            p_provider_task_id TEXT,
            p_provider_attempt_id TEXT,
            p_provider_fence_token BIGINT,
            p_controller_epoch INTEGER,
            p_product_json JSONB,
            p_product_digest TEXT
        ) RETURNS JSONB AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            handoff_row subworkflow_handoffs%ROWTYPE;
            provider_row parent_tasks%ROWTYPE;
            parent_row parent_tasks%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'subworkflow completion requires the workflow principal';
            END IF;
            SELECT * INTO control_row FROM controller_control WHERE run_id = p_run_id FOR UPDATE;
            IF NOT FOUND OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR NOT control_row.scheduling_enabled OR control_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'subworkflow completion is not bound to a live controller lease';
            END IF;
            SELECT * INTO handoff_row FROM subworkflow_handoffs
            WHERE handoff_id = p_handoff_id AND run_id = p_run_id FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'subworkflow handoff is unknown';
            END IF;
            IF handoff_row.state = 'completed' THEN
                RETURN jsonb_build_object('handoff_id', p_handoff_id, 'state', 'completed', 'resumed', false);
            END IF;
            IF handoff_row.state NOT IN ('dispatched','running')
               OR handoff_row.provider_task_id <> p_provider_task_id THEN
                RAISE EXCEPTION 'subworkflow handoff is not completable';
            END IF;
            SELECT * INTO provider_row FROM parent_tasks
            WHERE task_id = p_provider_task_id AND run_id = p_run_id FOR UPDATE;
            IF NOT FOUND OR provider_row.state <> 'leased' OR provider_row.active_attempt_id <> p_provider_attempt_id THEN
                RAISE EXCEPTION 'subworkflow provider task is not the active attempt';
            END IF;
            UPDATE task_attempts
            SET status = 'verified', ended_at = clock_timestamp()
            WHERE attempt_id = p_provider_attempt_id AND task_id = p_provider_task_id
              AND run_id = p_run_id AND fence_token = p_provider_fence_token
              AND controller_epoch = p_controller_epoch AND status = 'running'
              AND lease_expires_at > clock_timestamp();
            IF NOT FOUND THEN
                RAISE EXCEPTION 'subworkflow provider attempt fence is invalid';
            END IF;
            UPDATE parent_tasks
            SET state = 'verified', active_attempt_id = NULL, updated_at = clock_timestamp()
            WHERE task_id = p_provider_task_id AND run_id = p_run_id
              AND active_attempt_id = p_provider_attempt_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'subworkflow provider completion lost the fence';
            END IF;
            SELECT * INTO parent_row FROM parent_tasks
            WHERE task_id = handoff_row.parent_task_id AND run_id = p_run_id FOR UPDATE;
            IF NOT FOUND OR parent_row.state <> 'parked' OR parent_row.active_attempt_id IS NOT NULL THEN
                RAISE EXCEPTION 'subworkflow parent is not parked';
            END IF;
            UPDATE parent_tasks
            SET state = 'queued', available_at = clock_timestamp(), updated_at = clock_timestamp()
            WHERE task_id = handoff_row.parent_task_id AND run_id = p_run_id AND state = 'parked';
            UPDATE subworkflow_handoffs
            SET state = 'completed', provider_attempt = provider_attempt + 1,
                product_json = p_product_json, product_digest = p_product_digest,
                updated_at = clock_timestamp(), completed_at = clock_timestamp()
            WHERE handoff_id = p_handoff_id AND run_id = p_run_id AND state IN ('dispatched','running');
            RETURN jsonb_build_object('handoff_id', p_handoff_id, 'state', 'completed', 'resumed', true);
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_expire_subworkflow_handoff(
            p_handoff_id TEXT,
            p_run_id TEXT,
            p_controller_epoch INTEGER,
            p_reason TEXT
        ) RETURNS JSONB AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            handoff_row subworkflow_handoffs%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'subworkflow expiry requires the workflow principal';
            END IF;
            SELECT * INTO control_row FROM controller_control WHERE run_id = p_run_id FOR UPDATE;
            IF NOT FOUND OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR NOT control_row.scheduling_enabled OR control_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'subworkflow expiry is not bound to a live controller lease';
            END IF;
            SELECT * INTO handoff_row FROM subworkflow_handoffs
            WHERE handoff_id = p_handoff_id AND run_id = p_run_id FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'subworkflow handoff is unknown';
            END IF;
            IF handoff_row.state IN ('completed','rejected','expired','failed') THEN
                RETURN jsonb_build_object('handoff_id', p_handoff_id, 'state', handoff_row.state, 'resumed', false);
            END IF;
            UPDATE subworkflow_handoffs
            SET state = 'expired', last_error = left(p_reason, 240), updated_at = clock_timestamp()
            WHERE handoff_id = p_handoff_id AND run_id = p_run_id;
            RETURN jsonb_build_object('handoff_id', p_handoff_id, 'state', 'expired', 'resumed', false);
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        GRANT SELECT, INSERT, UPDATE ON TABLE subworkflow_handoffs TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_create_subworkflow_handoff(TEXT,TEXT,TEXT,BIGINT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,JSONB,TEXT,TEXT,INTEGER) TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_complete_subworkflow_handoff(TEXT,TEXT,TEXT,TEXT,BIGINT,INTEGER,JSONB,TEXT) TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_expire_subworkflow_handoff(TEXT,TEXT,INTEGER,TEXT) TO {WORKFLOW_ROLE};
        """
    )


def downgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(
        f"""
        DROP FUNCTION IF EXISTS longspan_expire_subworkflow_handoff(TEXT,TEXT,INTEGER,TEXT);
        DROP FUNCTION IF EXISTS longspan_complete_subworkflow_handoff(TEXT,TEXT,TEXT,TEXT,BIGINT,INTEGER,JSONB,TEXT);
        DROP FUNCTION IF EXISTS longspan_create_subworkflow_handoff(TEXT,TEXT,TEXT,BIGINT,INTEGER,TEXT,TEXT,TEXT,TEXT,TEXT,JSONB,TEXT,TEXT,INTEGER);
        DROP TABLE IF EXISTS subworkflow_handoffs;
        """
    )
