"""Initial control database schema.

Revision ID: 001_initial
Revises:
Create Date: 2026-08-11
"""

from __future__ import annotations

from alembic import op

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE supervisor_runs (
            run_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );

        CREATE TABLE controller_control (
            run_id TEXT PRIMARY KEY REFERENCES supervisor_runs(run_id),
            current_epoch BIGINT NOT NULL DEFAULT 0,
            owner TEXT,
            lease_expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            scheduling_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );

        CREATE TABLE parent_tasks (
            task_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            objective TEXT NOT NULL,
            state TEXT NOT NULL CHECK (
                state IN ('queued','leased','verified','parked','blocked','failed')
            ),
            priority INTEGER NOT NULL DEFAULT 0,
            available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            attempt INTEGER NOT NULL DEFAULT 0,
            active_attempt_id TEXT,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        CREATE INDEX parent_tasks_due_idx
            ON parent_tasks (run_id, state, available_at, priority DESC, task_id);

        CREATE TABLE task_attempts (
            attempt_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL REFERENCES parent_tasks(task_id),
            run_id TEXT NOT NULL,
            fence_token BIGINT NOT NULL,
            controller_epoch BIGINT NOT NULL,
            owner TEXT NOT NULL,
            status TEXT NOT NULL,
            heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            lease_expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            ended_at TIMESTAMPTZ,
            UNIQUE (task_id, fence_token)
        );
        CREATE INDEX task_attempts_active_idx
            ON task_attempts (task_id, status, lease_expires_at);

        CREATE TABLE retry_queue (
            retry_key TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            available_at TIMESTAMPTZ NOT NULL,
            attempt INTEGER NOT NULL,
            reason TEXT NOT NULL,
            state TEXT NOT NULL
        );

        CREATE TABLE supervisor_events (
            event_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            controller_epoch BIGINT NOT NULL DEFAULT 0,
            event_type TEXT NOT NULL,
            occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            detail_json TEXT NOT NULL
        );
        CREATE INDEX supervisor_events_run_idx ON supervisor_events (run_id, occurred_at);

        CREATE TABLE notifications (
            notification_key TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            sent_at TIMESTAMPTZ,
            state TEXT NOT NULL
        );

        CREATE TABLE evidence_index (
            evidence_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            task_id TEXT,
            attempt_id TEXT,
            fence_token BIGINT,
            artifact_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            byte_count BIGINT NOT NULL,
            producer TEXT NOT NULL,
            result TEXT NOT NULL CHECK (result IN ('pass', 'fail')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        CREATE INDEX evidence_index_run_idx ON evidence_index (run_id, artifact_path);

        CREATE TABLE required_manifest_entries (
            entry_id TEXT PRIMARY KEY,
            artifact_path TEXT NOT NULL,
            expected_sha256 TEXT,
            producer TEXT NOT NULL
        );

        CREATE TABLE manifest_submissions (
            submission_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            entry_id TEXT NOT NULL REFERENCES required_manifest_entries(entry_id),
            artifact_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            producer TEXT NOT NULL,
            result TEXT NOT NULL CHECK (result IN ('pass', 'fail')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (run_id, entry_id, submission_id)
        );
        CREATE INDEX manifest_submissions_run_idx ON manifest_submissions (run_id, entry_id);

        CREATE TABLE signal_status (
            run_id TEXT PRIMARY KEY,
            status_json TEXT NOT NULL,
            readiness TEXT NOT NULL,
            last_event_seq BIGINT NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );

        CREATE TABLE provenance_records (
            run_id TEXT PRIMARY KEY,
            reviewed_sha TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            tree_sha TEXT NOT NULL,
            build_sha TEXT,
            activation_sha TEXT,
            verified BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );

        CREATE OR REPLACE FUNCTION reject_evidence_index_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'evidence_index is append-only';
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER evidence_index_no_update
            BEFORE UPDATE OR DELETE ON evidence_index
            FOR EACH ROW EXECUTE FUNCTION reject_evidence_index_mutation();
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TRIGGER IF EXISTS evidence_index_no_update ON evidence_index;
        DROP FUNCTION IF EXISTS reject_evidence_index_mutation();
        DROP TABLE IF EXISTS provenance_records;
        DROP TABLE IF EXISTS signal_status;
        DROP TABLE IF EXISTS manifest_submissions;
        DROP TABLE IF EXISTS required_manifest_entries;
        DROP TABLE IF EXISTS evidence_index;
        DROP TABLE IF EXISTS notifications;
        DROP TABLE IF EXISTS supervisor_events;
        DROP TABLE IF EXISTS retry_queue;
        DROP TABLE IF EXISTS task_attempts;
        DROP TABLE IF EXISTS parent_tasks;
        DROP TABLE IF EXISTS controller_control;
        DROP TABLE IF EXISTS supervisor_runs;
        """
    )
