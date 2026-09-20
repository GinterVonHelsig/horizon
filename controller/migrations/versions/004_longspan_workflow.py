"""Longspan child workflow, experiment ledger, and hash-linked evidence.

Revision ID: 004_longspan_workflow
Revises: 003_commit_order_and_invariants
Create Date: 2026-08-12
"""

from __future__ import annotations

from alembic import op
from authority_pins import MIGRATION_SOURCE_PROVENANCE_PATH
from migration_source_anchor import verify_migration_source_anchor


revision = "004_longspan_workflow"
down_revision = "003_commit_order_and_invariants"
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
        CREATE TABLE longspan_children (
            child_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            parent_attempt_id TEXT NOT NULL,
            fence_token BIGINT NOT NULL,
            state TEXT NOT NULL CHECK (
                state IN (
                    'ready', 'planned', 'executing', 'executed', 'auditing',
                    'needs_remediation', 'verified', 'terra_pending',
                    'terra_approved', 'terra_rejected', 'retry_wait',
                    'parent_returned', 'parked', 'cancelled', 'expired'
                )
            ),
            idempotency_key TEXT NOT NULL UNIQUE,
            request_digest TEXT NOT NULL,
            attempt_number INTEGER NOT NULL DEFAULT 0,
            version BIGINT NOT NULL DEFAULT 0,
            lease_token_hash TEXT,
            lease_expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (task_id, parent_attempt_id),
            FOREIGN KEY (task_id, run_id) REFERENCES parent_tasks(task_id, run_id)
        );
        CREATE INDEX longspan_children_run_state_idx
            ON longspan_children (run_id, state, updated_at);

        CREATE TABLE longspan_plans (
            plan_id TEXT PRIMARY KEY,
            child_id TEXT NOT NULL REFERENCES longspan_children(child_id),
            objective TEXT NOT NULL,
            acceptance_criteria_json TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'comms-01',
            plan_digest TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (child_id)
        );

        CREATE TABLE longspan_execution_results (
            result_id TEXT PRIMARY KEY,
            child_id TEXT NOT NULL REFERENCES longspan_children(child_id),
            attempt_number INTEGER NOT NULL,
            outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'retryable')),
            result_digest TEXT NOT NULL,
            artifact_refs_json TEXT NOT NULL DEFAULT '[]',
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (child_id, attempt_number)
        );

        CREATE TABLE longspan_auditor_receipts (
            receipt_id TEXT PRIMARY KEY,
            child_id TEXT NOT NULL REFERENCES longspan_children(child_id),
            attempt_number INTEGER NOT NULL DEFAULT 0,
            verdict TEXT NOT NULL CHECK (verdict IN ('pass', 'fail')),
            reasons_json TEXT NOT NULL,
            inspector_digest TEXT NOT NULL,
            receipt_digest TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (child_id, attempt_number)
        );

        CREATE TABLE longspan_terra_receipts (
            receipt_id TEXT PRIMARY KEY,
            child_id TEXT NOT NULL REFERENCES longspan_children(child_id),
            reviewer TEXT NOT NULL,
            decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
            evidence_chain_head TEXT NOT NULL,
            receipt_digest TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (child_id)
        );

        CREATE TABLE longspan_experiments (
            experiment_id TEXT PRIMARY KEY,
            child_id TEXT REFERENCES longspan_children(child_id),
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            hypothesis TEXT NOT NULL,
            baseline TEXT NOT NULL,
            scope TEXT NOT NULL,
            predicted_benefit TEXT NOT NULL,
            rollback_plan TEXT NOT NULL,
            classification TEXT NOT NULL CHECK (
                classification IN (
                    'observation', 'playbook', 'workflow', 'code', 'policy'
                )
            ),
            state TEXT NOT NULL CHECK (
                state IN (
                    'proposed', 'authorized-for-local-test', 'evaluated',
                    'accepted', 'rejected', 'superseded'
                )
            ),
            evidence_digest TEXT,
            auditor_verdict TEXT,
            adoption_decision TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        CREATE INDEX longspan_experiments_run_idx
            ON longspan_experiments (run_id, state);

        CREATE TABLE longspan_evidence_ledger (
            entry_id TEXT PRIMARY KEY,
            child_id TEXT NOT NULL REFERENCES longspan_children(child_id),
            attempt_number INTEGER NOT NULL DEFAULT 0,
            event_type TEXT NOT NULL,
            producer_role TEXT NOT NULL CHECK (
                producer_role IN ('manager', 'executor', 'auditor', 'terra', 'parent')
            ),
            payload_digest TEXT NOT NULL,
            previous_entry_hash TEXT,
            entry_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        CREATE INDEX longspan_evidence_ledger_child_idx
            ON longspan_evidence_ledger (child_id, created_at, entry_id);

        CREATE OR REPLACE FUNCTION reject_longspan_evidence_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'longspan_evidence_ledger is append-only';
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER longspan_evidence_no_update
            BEFORE UPDATE OR DELETE ON longspan_evidence_ledger
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_evidence_mutation();

        CREATE OR REPLACE FUNCTION reject_longspan_auditor_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'longspan_auditor_receipts is append-only';
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER longspan_auditor_no_update
            BEFORE UPDATE OR DELETE ON longspan_auditor_receipts
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_auditor_mutation();
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
        DROP TRIGGER IF EXISTS longspan_auditor_no_update ON longspan_auditor_receipts;
        DROP FUNCTION IF EXISTS reject_longspan_auditor_mutation();
        DROP TRIGGER IF EXISTS longspan_evidence_no_update ON longspan_evidence_ledger;
        DROP FUNCTION IF EXISTS reject_longspan_evidence_mutation();
        DROP TABLE IF EXISTS longspan_evidence_ledger;
        DROP TABLE IF EXISTS longspan_experiments;
        DROP TABLE IF EXISTS longspan_terra_receipts;
        DROP TABLE IF EXISTS longspan_auditor_receipts;
        DROP TABLE IF EXISTS longspan_execution_results;
        DROP TABLE IF EXISTS longspan_plans;
        DROP TABLE IF EXISTS longspan_children;
        """
    )
