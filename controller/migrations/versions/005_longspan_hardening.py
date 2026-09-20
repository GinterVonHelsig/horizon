"""Harden Longspan role separation, ledger ordering, and immutability.

Revision ID: 005_longspan_hardening
Revises: 004_longspan_workflow
Create Date: 2026-08-12
"""

from __future__ import annotations

from alembic import op
from authority_pins import MIGRATION_SOURCE_PROVENANCE_PATH
from migration_source_anchor import verify_migration_source_anchor


revision = "005_longspan_hardening"
down_revision = "004_longspan_workflow"
branch_labels = None
depends_on = None


def upgrade() -> None:
    verify_migration_source_anchor(
        revision,
        source_path=__file__,
        anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH,
    )
    op.execute(
        """
        ALTER TABLE longspan_children
            ADD COLUMN IF NOT EXISTS manager_capability_hash TEXT,
            ADD COLUMN IF NOT EXISTS executor_capability_hash TEXT,
            ADD COLUMN IF NOT EXISTS auditor_capability_hash TEXT;

        UPDATE longspan_children
        SET state = 'retry_wait',
            manager_capability_hash = NULL,
            executor_capability_hash = NULL,
            auditor_capability_hash = NULL,
            lease_token_hash = NULL,
            lease_expires_at = NULL,
            version = version + 1,
            updated_at = clock_timestamp()
        WHERE state NOT IN ('parent_returned', 'parked', 'cancelled', 'retry_wait')
          AND (
              lease_token_hash IS NOT NULL
              OR manager_capability_hash IS NULL
              OR executor_capability_hash IS NULL
              OR auditor_capability_hash IS NULL
          );

        ALTER TABLE longspan_plans
            ADD COLUMN IF NOT EXISTS attempt_number INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE longspan_plans DROP CONSTRAINT IF EXISTS longspan_plans_child_id_key;
        DROP INDEX IF EXISTS longspan_plans_child_id_key;
        CREATE UNIQUE INDEX IF NOT EXISTS longspan_plans_child_attempt_uq
            ON longspan_plans (child_id, attempt_number);

        ALTER TABLE longspan_terra_receipts
            ADD COLUMN IF NOT EXISTS attempt_number INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE longspan_terra_receipts DROP CONSTRAINT IF EXISTS longspan_terra_receipts_child_id_key;
        DROP INDEX IF EXISTS longspan_terra_receipts_child_id_key;
        CREATE UNIQUE INDEX IF NOT EXISTS longspan_terra_receipts_child_attempt_uq
            ON longspan_terra_receipts (child_id, attempt_number);

        ALTER TABLE longspan_evidence_ledger
            ADD COLUMN IF NOT EXISTS sequence_number BIGINT;

        ALTER TABLE longspan_evidence_ledger DISABLE TRIGGER longspan_evidence_no_update;

        WITH RECURSIVE chain AS (
            SELECT entry_id, child_id, entry_hash, 1 AS seq
            FROM longspan_evidence_ledger
            WHERE previous_entry_hash IS NULL
            UNION ALL
            SELECT next.entry_id, next.child_id, next.entry_hash, chain.seq + 1
            FROM longspan_evidence_ledger AS next
            INNER JOIN chain
                ON next.child_id = chain.child_id
               AND next.previous_entry_hash = chain.entry_hash
        )
        UPDATE longspan_evidence_ledger AS ledger
        SET sequence_number = chain.seq
        FROM chain
        WHERE ledger.entry_id = chain.entry_id
          AND ledger.sequence_number IS NULL;

        UPDATE longspan_evidence_ledger
        SET sequence_number = 1
        WHERE sequence_number IS NULL;

        ALTER TABLE longspan_evidence_ledger
            ALTER COLUMN sequence_number SET NOT NULL;

        ALTER TABLE longspan_evidence_ledger ENABLE TRIGGER longspan_evidence_no_update;

        CREATE UNIQUE INDEX IF NOT EXISTS longspan_evidence_ledger_child_seq_uq
            ON longspan_evidence_ledger (child_id, sequence_number);
        CREATE UNIQUE INDEX IF NOT EXISTS longspan_evidence_ledger_child_prev_uq
            ON longspan_evidence_ledger (child_id, previous_entry_hash)
            WHERE previous_entry_hash IS NOT NULL;

        ALTER TABLE longspan_experiments
            ADD COLUMN IF NOT EXISTS protected_targets_json TEXT NOT NULL DEFAULT '[]',
            ADD COLUMN IF NOT EXISTS operator_approval_digest TEXT,
            ADD COLUMN IF NOT EXISTS auditor_receipt_id TEXT;

        CREATE OR REPLACE FUNCTION reject_longspan_evidence_truncate()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'longspan_evidence_ledger truncate is forbidden';
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS longspan_evidence_no_truncate ON longspan_evidence_ledger;
        CREATE TRIGGER longspan_evidence_no_truncate
            BEFORE TRUNCATE ON longspan_evidence_ledger
            FOR EACH STATEMENT EXECUTE FUNCTION reject_longspan_evidence_truncate();

        CREATE OR REPLACE FUNCTION reject_longspan_auditor_truncate()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'longspan_auditor_receipts truncate is forbidden';
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS longspan_auditor_no_truncate ON longspan_auditor_receipts;
        CREATE TRIGGER longspan_auditor_no_truncate
            BEFORE TRUNCATE ON longspan_auditor_receipts
            FOR EACH STATEMENT EXECUTE FUNCTION reject_longspan_auditor_truncate();

        CREATE OR REPLACE FUNCTION reject_longspan_terra_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'longspan_terra_receipts is append-only';
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS longspan_terra_no_update ON longspan_terra_receipts;
        CREATE TRIGGER longspan_terra_no_update
            BEFORE UPDATE OR DELETE ON longspan_terra_receipts
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_terra_mutation();

        CREATE OR REPLACE FUNCTION reject_longspan_terra_truncate()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'longspan_terra_receipts truncate is forbidden';
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS longspan_terra_no_truncate ON longspan_terra_receipts;
        CREATE TRIGGER longspan_terra_no_truncate
            BEFORE TRUNCATE ON longspan_terra_receipts
            FOR EACH STATEMENT EXECUTE FUNCTION reject_longspan_terra_truncate();
        """
    )


def downgrade() -> None:
    # This historical leg is still destructive.  Keep its safety check in
    # the revision itself so a caller cannot authorize it merely by setting a
    # process environment variable or bypassing env.py's wrapper.
    verify_migration_source_anchor(
        revision,
        source_path=__file__,
        anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH,
    )
    from disposable_capability import require_connected_migration_downgrade

    require_connected_migration_downgrade(revision=revision)
    op.execute(
        """
        DO $guard$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM longspan_terra_receipts
                GROUP BY child_id HAVING COUNT(DISTINCT attempt_number) > 1
            ) THEN
                RAISE EXCEPTION '005 downgrade blocked: multi-attempt terra receipts exist';
            END IF;
            IF EXISTS (
                SELECT 1 FROM longspan_plans
                GROUP BY child_id HAVING COUNT(DISTINCT attempt_number) > 1
            ) THEN
                RAISE EXCEPTION '005 downgrade blocked: multi-attempt plans exist';
            END IF;
        END
        $guard$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS longspan_terra_no_truncate ON longspan_terra_receipts;
        DROP TRIGGER IF EXISTS longspan_terra_no_update ON longspan_terra_receipts;
        DROP FUNCTION IF EXISTS reject_longspan_terra_truncate();
        DROP FUNCTION IF EXISTS reject_longspan_terra_mutation();
        DROP TRIGGER IF EXISTS longspan_auditor_no_truncate ON longspan_auditor_receipts;
        DROP FUNCTION IF EXISTS reject_longspan_auditor_truncate();
        DROP TRIGGER IF EXISTS longspan_evidence_no_truncate ON longspan_evidence_ledger;
        DROP FUNCTION IF EXISTS reject_longspan_evidence_truncate();

        ALTER TABLE longspan_experiments
            DROP COLUMN IF EXISTS auditor_receipt_id,
            DROP COLUMN IF EXISTS operator_approval_digest,
            DROP COLUMN IF EXISTS protected_targets_json;

        DROP INDEX IF EXISTS longspan_evidence_ledger_child_prev_uq;
        DROP INDEX IF EXISTS longspan_evidence_ledger_child_seq_uq;
        ALTER TABLE longspan_evidence_ledger DROP COLUMN IF EXISTS sequence_number;

        DROP INDEX IF EXISTS longspan_terra_receipts_child_attempt_uq;
        ALTER TABLE longspan_terra_receipts DROP COLUMN IF EXISTS attempt_number;
        DROP INDEX IF EXISTS longspan_terra_receipts_child_id_key;
        CREATE UNIQUE INDEX IF NOT EXISTS longspan_terra_receipts_child_id_key
            ON longspan_terra_receipts (child_id);

        DROP INDEX IF EXISTS longspan_plans_child_attempt_uq;
        ALTER TABLE longspan_plans DROP COLUMN IF EXISTS attempt_number;
        DROP INDEX IF EXISTS longspan_plans_child_id_key;
        CREATE UNIQUE INDEX IF NOT EXISTS longspan_plans_child_id_key
            ON longspan_plans (child_id);

        ALTER TABLE longspan_children
            DROP COLUMN IF EXISTS auditor_capability_hash,
            DROP COLUMN IF EXISTS executor_capability_hash,
            DROP COLUMN IF EXISTS manager_capability_hash;
        """
    )
