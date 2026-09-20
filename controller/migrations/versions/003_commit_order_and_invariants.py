"""Make event cursors per-run commit ordered and add task invariants.

Revision ID: 003_commit_order_and_invariants
Revises: 002_event_sequence
Create Date: 2026-08-12
"""

from __future__ import annotations

from alembic import op


revision = "003_commit_order_and_invariants"
down_revision = "002_event_sequence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE controller_control
            ADD COLUMN IF NOT EXISTS event_seq_counter BIGINT NOT NULL DEFAULT 0;
        DROP INDEX IF EXISTS supervisor_events_event_seq_uq;

        WITH numbered AS (
            SELECT event_id,
                   row_number() OVER (PARTITION BY run_id ORDER BY occurred_at, event_id) AS seq
            FROM supervisor_events
        )
        UPDATE supervisor_events AS events
        SET event_seq = numbered.seq
        FROM numbered
        WHERE events.event_id = numbered.event_id;

        UPDATE controller_control AS controls
        SET event_seq_counter = COALESCE(
            (SELECT MAX(events.event_seq)
             FROM supervisor_events AS events
             WHERE events.run_id = controls.run_id),
            0
        );

        ALTER TABLE supervisor_events ALTER COLUMN event_seq DROP DEFAULT;
        ALTER SEQUENCE supervisor_events_event_seq_seq OWNED BY NONE;
        CREATE UNIQUE INDEX IF NOT EXISTS supervisor_events_run_seq_uq
            ON supervisor_events (run_id, event_seq);

        ALTER TABLE parent_tasks
            ADD CONSTRAINT parent_tasks_task_run_uq UNIQUE (task_id, run_id);
        ALTER TABLE task_attempts
            ADD CONSTRAINT task_attempts_run_fk
            FOREIGN KEY (run_id) REFERENCES supervisor_runs(run_id);
        ALTER TABLE task_attempts
            ADD CONSTRAINT task_attempts_parent_run_fk
            FOREIGN KEY (task_id, run_id) REFERENCES parent_tasks(task_id, run_id);
        ALTER TABLE task_attempts
            ADD CONSTRAINT task_attempts_attempt_task_run_uq
            UNIQUE (attempt_id, task_id, run_id);
        CREATE UNIQUE INDEX task_attempts_one_running_uq
            ON task_attempts (task_id) WHERE status = 'running';
        ALTER TABLE parent_tasks
            ADD CONSTRAINT parent_tasks_active_attempt_fk
            FOREIGN KEY (active_attempt_id, task_id, run_id)
            REFERENCES task_attempts(attempt_id, task_id, run_id);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE parent_tasks DROP CONSTRAINT IF EXISTS parent_tasks_active_attempt_fk;
        DROP INDEX IF EXISTS task_attempts_one_running_uq;
        ALTER TABLE task_attempts
            DROP CONSTRAINT IF EXISTS task_attempts_attempt_task_run_uq;
        ALTER TABLE task_attempts DROP CONSTRAINT IF EXISTS task_attempts_parent_run_fk;
        ALTER TABLE task_attempts DROP CONSTRAINT IF EXISTS task_attempts_run_fk;
        ALTER TABLE parent_tasks DROP CONSTRAINT IF EXISTS parent_tasks_task_run_uq;

        DROP INDEX IF EXISTS supervisor_events_run_seq_uq;
        WITH numbered AS (
            SELECT event_id,
                   row_number() OVER (ORDER BY occurred_at, event_id) AS seq
            FROM supervisor_events
        )
        UPDATE supervisor_events AS events
        SET event_seq = numbered.seq
        FROM numbered
        WHERE events.event_id = numbered.event_id;
        CREATE UNIQUE INDEX IF NOT EXISTS supervisor_events_event_seq_uq
            ON supervisor_events (event_seq);
        ALTER SEQUENCE supervisor_events_event_seq_seq OWNED BY supervisor_events.event_seq;
        ALTER TABLE supervisor_events
            ALTER COLUMN event_seq SET DEFAULT nextval('supervisor_events_event_seq_seq');
        ALTER TABLE controller_control DROP COLUMN IF EXISTS event_seq_counter;
        """
    )
