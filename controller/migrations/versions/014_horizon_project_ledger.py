"""Add durable Horizon project ledger tables and ingest/query routines.

Revision ID: 014_horizon_project_ledger
Revises: 013_cleanup_expired_attempt
"""

from __future__ import annotations

from alembic import op
from authority_pins import (
    MIGRATION_SOURCE_PROVENANCE_PATH,
    WORKFLOW_DATABASE_ROLE,
)
from migration_catalog import assert_migration_catalog
from migration_source_anchor import verify_migration_source_anchor

revision = "014_horizon_project_ledger"
down_revision = "013_cleanup_expired_attempt"
branch_labels = None
depends_on = None

MIGRATION_ROLE = "top_delivery_migration"
WORKFLOW_ROLE = WORKFLOW_DATABASE_ROLE


def upgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(
        f"""
        CREATE TABLE horizon_projects (
            ledger_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_id TEXT NOT NULL,
            project_version TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            program_digest TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (project_id, project_version)
        );

        CREATE TABLE horizon_project_nodes (
            ledger_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            project_ledger_id UUID NOT NULL REFERENCES horizon_projects(ledger_id),
            node_id TEXT NOT NULL,
            parent_node_id TEXT,
            project_version TEXT NOT NULL,
            acceptance_criteria_version TEXT NOT NULL,
            node_digest TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (project_ledger_id, node_id)
        );
        CREATE INDEX horizon_project_nodes_node_idx
            ON horizon_project_nodes (node_id);

        CREATE OR REPLACE FUNCTION longspan_ingest_project_program(
            p_project_id TEXT,
            p_project_version TEXT,
            p_schema_version TEXT,
            p_program_digest TEXT,
            p_nodes JSONB
        ) RETURNS JSONB AS $$
        DECLARE
            project_row horizon_projects%ROWTYPE;
            node_item JSONB;
            node_ledger_ids JSONB := '{{}}'::JSONB;
            node_ledger_id TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'project program ingest requires the workflow principal';
            END IF;
            IF p_project_id IS NULL OR btrim(p_project_id) = '' THEN
                RAISE EXCEPTION 'project_id is required';
            END IF;
            IF p_project_version IS NULL OR btrim(p_project_version) = '' THEN
                RAISE EXCEPTION 'project_version is required';
            END IF;
            IF p_schema_version IS NULL OR btrim(p_schema_version) = '' THEN
                RAISE EXCEPTION 'schema_version is required';
            END IF;
            IF p_program_digest IS NULL OR btrim(p_program_digest) = '' THEN
                RAISE EXCEPTION 'program_digest is required';
            END IF;
            IF p_nodes IS NULL OR jsonb_typeof(p_nodes) <> 'array' THEN
                RAISE EXCEPTION 'project nodes payload must be a JSON array';
            END IF;

            INSERT INTO horizon_projects
                (project_id, project_version, schema_version, program_digest)
            VALUES (p_project_id, p_project_version, p_schema_version, p_program_digest)
            ON CONFLICT (project_id, project_version) DO UPDATE
                SET schema_version = EXCLUDED.schema_version,
                    program_digest = EXCLUDED.program_digest,
                    updated_at = clock_timestamp()
            RETURNING * INTO project_row;

            FOR node_item IN SELECT value FROM jsonb_array_elements(p_nodes) AS value LOOP
                IF node_item->>'node_id' IS NULL OR btrim(node_item->>'node_id') = '' THEN
                    RAISE EXCEPTION 'project node_id is required';
                END IF;
                IF node_item->>'acceptance_criteria_version' IS NULL
                   OR btrim(node_item->>'acceptance_criteria_version') = '' THEN
                    RAISE EXCEPTION 'acceptance_criteria_version is required for %',
                        node_item->>'node_id';
                END IF;
                IF node_item->>'node_digest' IS NULL OR btrim(node_item->>'node_digest') = '' THEN
                    RAISE EXCEPTION 'node_digest is required for %', node_item->>'node_id';
                END IF;
                INSERT INTO horizon_project_nodes
                    (
                        project_ledger_id,
                        node_id,
                        parent_node_id,
                        project_version,
                        acceptance_criteria_version,
                        node_digest
                    )
                VALUES (
                    project_row.ledger_id,
                    node_item->>'node_id',
                    NULLIF(node_item->>'parent_node_id', ''),
                    COALESCE(NULLIF(node_item->>'project_version', ''), p_project_version),
                    node_item->>'acceptance_criteria_version',
                    node_item->>'node_digest'
                )
                ON CONFLICT (project_ledger_id, node_id) DO UPDATE
                    SET parent_node_id = EXCLUDED.parent_node_id,
                        project_version = EXCLUDED.project_version,
                        acceptance_criteria_version = EXCLUDED.acceptance_criteria_version,
                        node_digest = EXCLUDED.node_digest,
                        updated_at = clock_timestamp()
                RETURNING ledger_id::TEXT INTO node_ledger_id;
                node_ledger_ids := node_ledger_ids
                    || jsonb_build_object(node_item->>'node_id', node_ledger_id);
            END LOOP;

            RETURN jsonb_build_object(
                'project_ledger_id', project_row.ledger_id::TEXT,
                'project_id', project_row.project_id,
                'project_version', project_row.project_version,
                'schema_version', project_row.schema_version,
                'program_digest', project_row.program_digest,
                'node_ledger_ids', node_ledger_ids
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_get_project_node_ledger(
            p_project_id TEXT,
            p_project_version TEXT,
            p_node_id TEXT
        ) RETURNS JSONB AS $$
        DECLARE
            node_row horizon_project_nodes%ROWTYPE;
            project_row horizon_projects%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'project node ledger query requires the workflow principal';
            END IF;
            SELECT * INTO project_row
            FROM horizon_projects
            WHERE project_id = p_project_id
              AND project_version = p_project_version;
            IF NOT FOUND THEN
                RETURN NULL;
            END IF;
            SELECT * INTO node_row
            FROM horizon_project_nodes
            WHERE project_ledger_id = project_row.ledger_id
              AND node_id = p_node_id;
            IF NOT FOUND THEN
                RETURN NULL;
            END IF;
            RETURN jsonb_build_object(
                'project_ledger_id', project_row.ledger_id::TEXT,
                'node_ledger_id', node_row.ledger_id::TEXT,
                'project_id', project_row.project_id,
                'project_version', project_row.project_version,
                'node_id', node_row.node_id,
                'parent_node_id', node_row.parent_node_id,
                'acceptance_criteria_version', node_row.acceptance_criteria_version,
                'node_digest', node_row.node_digest
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        GRANT SELECT, INSERT, UPDATE ON horizon_projects TO {WORKFLOW_ROLE};
        GRANT SELECT, INSERT, UPDATE ON horizon_project_nodes TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_ingest_project_program(TEXT, TEXT, TEXT, TEXT, JSONB)
            TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_get_project_node_ledger(TEXT, TEXT, TEXT)
            TO {WORKFLOW_ROLE};
        """
    )


def downgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(
        """
        DROP FUNCTION IF EXISTS longspan_get_project_node_ledger(TEXT, TEXT, TEXT);
        DROP FUNCTION IF EXISTS longspan_ingest_project_program(TEXT, TEXT, TEXT, TEXT, JSONB);
        DROP TABLE IF EXISTS horizon_project_nodes;
        DROP TABLE IF EXISTS horizon_projects;
        """
    )
