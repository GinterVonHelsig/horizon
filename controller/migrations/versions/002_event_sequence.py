"""Add a durable monotonic sequence for controller events.

Revision ID: 002_event_sequence
Revises: 001_initial
Create Date: 2026-08-12
"""

from __future__ import annotations

from alembic import op


revision = "002_event_sequence"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'supervisor_events' AND column_name = 'event_seq'
            ) THEN
                ALTER TABLE supervisor_events ADD COLUMN event_seq BIGINT;
            END IF;
        END $$;

        CREATE SEQUENCE IF NOT EXISTS supervisor_events_event_seq_seq;
        DO $$
        DECLARE table_owner NAME;
        BEGIN
            SELECT c.relowner::regrole::text
            INTO table_owner
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE c.relname = 'supervisor_events' AND n.nspname = current_schema();
            EXECUTE format(
                'ALTER SEQUENCE supervisor_events_event_seq_seq OWNER TO %I',
                table_owner
            );
        END $$;
        ALTER SEQUENCE supervisor_events_event_seq_seq OWNED BY supervisor_events.event_seq;
        ALTER TABLE supervisor_events
            ALTER COLUMN event_seq SET DEFAULT nextval('supervisor_events_event_seq_seq');

        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'topdelivery') THEN
                GRANT USAGE, SELECT ON SEQUENCE supervisor_events_event_seq_seq TO topdelivery;
            END IF;
        END $$;

        WITH numbered AS (
            SELECT event_id,
                   row_number() OVER (ORDER BY occurred_at, event_id) AS seq
            FROM supervisor_events
        )
        UPDATE supervisor_events AS events
        SET event_seq = numbered.seq
        FROM numbered
        WHERE events.event_id = numbered.event_id AND events.event_seq IS NULL;

        SELECT setval(
            'supervisor_events_event_seq_seq',
            GREATEST(COALESCE((SELECT MAX(event_seq) FROM supervisor_events), 0), 1),
            COALESCE((SELECT MAX(event_seq) FROM supervisor_events), 0) > 0
        );
        ALTER TABLE supervisor_events ALTER COLUMN event_seq SET NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS supervisor_events_event_seq_uq
            ON supervisor_events (event_seq);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS supervisor_events_event_seq_uq;
        ALTER TABLE supervisor_events ALTER COLUMN event_seq DROP DEFAULT;
        ALTER TABLE supervisor_events DROP COLUMN IF EXISTS event_seq;
        DROP SEQUENCE IF EXISTS supervisor_events_event_seq_seq;
        """
    )
