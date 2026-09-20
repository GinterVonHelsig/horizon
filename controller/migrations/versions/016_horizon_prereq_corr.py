"""Add Horizon prerequisite orchestration and ATS-COM-001 correlation store.

Revision ID: 016_horizon_prereq_corr
Revises: 015_subworkflow_handoff
"""

from __future__ import annotations

from alembic import op
from authority_pins import MIGRATION_SOURCE_PROVENANCE_PATH, WORKFLOW_DATABASE_ROLE
from migration_catalog import assert_migration_catalog
from migration_source_anchor import verify_migration_source_anchor

revision = "016_horizon_prereq_corr"
down_revision = "015_subworkflow_handoff"
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
        ALTER TABLE horizon_project_nodes
            ADD COLUMN IF NOT EXISTS dependencies JSONB NOT NULL DEFAULT '[]'::JSONB;

        CREATE TABLE IF NOT EXISTS horizon_prerequisite_decisions (
            decision_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            target_node_id TEXT NOT NULL,
            prerequisite_node_id TEXT NOT NULL,
            reused BOOLEAN NOT NULL,
            delivered_by TEXT,
            reason TEXT NOT NULL,
            artifact_digest TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            handoff_id TEXT REFERENCES subworkflow_handoffs(handoff_id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (run_id, target_node_id, prerequisite_node_id, request_digest)
        );
        CREATE INDEX IF NOT EXISTS horizon_prerequisite_decisions_run_idx
            ON horizon_prerequisite_decisions (run_id, target_node_id);

        CREATE TABLE IF NOT EXISTS horizon_correlation_qa (
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            request_id TEXT NOT NULL,
            question_kind TEXT NOT NULL,
            question_json JSONB NOT NULL,
            question_digest TEXT NOT NULL,
            answer_json JSONB NOT NULL,
            answer_digest TEXT NOT NULL,
            replay_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (run_id, request_id)
        );

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
            node_dependencies JSONB;
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
                node_dependencies := COALESCE(node_item->'dependencies', '[]'::JSONB);
                IF jsonb_typeof(node_dependencies) <> 'array' THEN
                    RAISE EXCEPTION 'dependencies for % must be a JSON array', node_item->>'node_id';
                END IF;
                INSERT INTO horizon_project_nodes
                    (
                        project_ledger_id,
                        node_id,
                        parent_node_id,
                        project_version,
                        acceptance_criteria_version,
                        node_digest,
                        dependencies
                    )
                VALUES (
                    project_row.ledger_id,
                    node_item->>'node_id',
                    NULLIF(node_item->>'parent_node_id', ''),
                    COALESCE(NULLIF(node_item->>'project_version', ''), p_project_version),
                    node_item->>'acceptance_criteria_version',
                    node_item->>'node_digest',
                    node_dependencies
                )
                ON CONFLICT (project_ledger_id, node_id) DO UPDATE
                    SET parent_node_id = EXCLUDED.parent_node_id,
                        project_version = EXCLUDED.project_version,
                        acceptance_criteria_version = EXCLUDED.acceptance_criteria_version,
                        node_digest = EXCLUDED.node_digest,
                        dependencies = EXCLUDED.dependencies,
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
                'node_digest', node_row.node_digest,
                'dependencies', COALESCE(node_row.dependencies, '[]'::JSONB)
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_detect_missing_prerequisites(
            p_project_id TEXT,
            p_project_version TEXT,
            p_node_id TEXT,
            p_satisfied_nodes JSONB
        ) RETURNS JSONB AS $$
        DECLARE
            node_row horizon_project_nodes%ROWTYPE;
            project_row horizon_projects%ROWTYPE;
            dependency_item JSONB;
            missing JSONB := '[]'::JSONB;
            dependency_id TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'missing prerequisite detection requires the workflow principal';
            END IF;
            IF p_satisfied_nodes IS NULL OR jsonb_typeof(p_satisfied_nodes) <> 'array' THEN
                RAISE EXCEPTION 'satisfied_nodes must be a JSON array';
            END IF;
            SELECT * INTO project_row
            FROM horizon_projects
            WHERE project_id = p_project_id
              AND project_version = p_project_version;
            IF NOT FOUND THEN
                RETURN jsonb_build_object('node_id', p_node_id, 'missing', missing);
            END IF;
            SELECT * INTO node_row
            FROM horizon_project_nodes
            WHERE project_ledger_id = project_row.ledger_id
              AND node_id = p_node_id;
            IF NOT FOUND THEN
                RETURN jsonb_build_object('node_id', p_node_id, 'missing', missing);
            END IF;
            FOR dependency_item IN
                SELECT value FROM jsonb_array_elements(COALESCE(node_row.dependencies, '[]'::JSONB)) AS value
            LOOP
                dependency_id := dependency_item #>> '{{}}';
                IF dependency_id IS NULL OR btrim(dependency_id) = '' THEN
                    CONTINUE;
                END IF;
                IF EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements_text(p_satisfied_nodes) AS satisfied(value)
                    WHERE satisfied.value = dependency_id
                ) THEN
                    CONTINUE;
                END IF;
                missing := missing || jsonb_build_array(dependency_id);
            END LOOP;
            RETURN jsonb_build_object(
                'project_id', p_project_id,
                'project_version', p_project_version,
                'node_id', p_node_id,
                'missing', missing
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_record_prerequisite_decision(
            p_run_id TEXT,
            p_target_node_id TEXT,
            p_prerequisite_node_id TEXT,
            p_request_digest TEXT,
            p_reused BOOLEAN,
            p_delivered_by TEXT,
            p_reason TEXT,
            p_artifact_digest TEXT,
            p_handoff_id TEXT
        ) RETURNS JSONB AS $$
        DECLARE
            existing_row horizon_prerequisite_decisions%ROWTYPE;
            inserted_row horizon_prerequisite_decisions%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'prerequisite decision recording requires the workflow principal';
            END IF;
            SELECT * INTO existing_row
            FROM horizon_prerequisite_decisions
            WHERE run_id = p_run_id
              AND target_node_id = p_target_node_id
              AND prerequisite_node_id = p_prerequisite_node_id
              AND request_digest = p_request_digest;
            IF FOUND THEN
                RETURN jsonb_build_object(
                    'decision_id', existing_row.decision_id::TEXT,
                    'run_id', existing_row.run_id,
                    'target_node_id', existing_row.target_node_id,
                    'prerequisite_node_id', existing_row.prerequisite_node_id,
                    'reused', existing_row.reused,
                    'delivered_by', existing_row.delivered_by,
                    'reason', existing_row.reason,
                    'artifact_digest', existing_row.artifact_digest,
                    'request_digest', existing_row.request_digest,
                    'handoff_id', existing_row.handoff_id,
                    'created', false
                );
            END IF;
            INSERT INTO horizon_prerequisite_decisions(
                run_id, target_node_id, prerequisite_node_id, request_digest,
                reused, delivered_by, reason, artifact_digest, handoff_id
            ) VALUES (
                p_run_id, p_target_node_id, p_prerequisite_node_id, p_request_digest,
                p_reused, NULLIF(p_delivered_by, ''), p_reason, p_artifact_digest, NULLIF(p_handoff_id, '')
            )
            RETURNING * INTO inserted_row;
            RETURN jsonb_build_object(
                'decision_id', inserted_row.decision_id::TEXT,
                'run_id', inserted_row.run_id,
                'target_node_id', inserted_row.target_node_id,
                'prerequisite_node_id', inserted_row.prerequisite_node_id,
                'reused', inserted_row.reused,
                'delivered_by', inserted_row.delivered_by,
                'reason', inserted_row.reason,
                'artifact_digest', inserted_row.artifact_digest,
                'request_digest', inserted_row.request_digest,
                'handoff_id', inserted_row.handoff_id,
                'created', true
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_record_correlation_qa(
            p_run_id TEXT,
            p_request_id TEXT,
            p_question_kind TEXT,
            p_question_json JSONB,
            p_question_digest TEXT,
            p_answer_json JSONB,
            p_answer_digest TEXT
        ) RETURNS JSONB AS $$
        DECLARE
            existing_row horizon_correlation_qa%ROWTYPE;
            inserted_row horizon_correlation_qa%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'correlation recording requires the workflow principal';
            END IF;
            SELECT * INTO existing_row
            FROM horizon_correlation_qa
            WHERE run_id = p_run_id
              AND request_id = p_request_id;
            IF FOUND THEN
                UPDATE horizon_correlation_qa
                SET replay_count = replay_count + 1,
                    updated_at = clock_timestamp()
                WHERE run_id = p_run_id
                  AND request_id = p_request_id
                RETURNING * INTO existing_row;
                RETURN jsonb_build_object(
                    'run_id', existing_row.run_id,
                    'request_id', existing_row.request_id,
                    'question_kind', existing_row.question_kind,
                    'question_digest', existing_row.question_digest,
                    'answer_json', existing_row.answer_json,
                    'answer_digest', existing_row.answer_digest,
                    'replay_count', existing_row.replay_count,
                    'replayed', true
                );
            END IF;
            INSERT INTO horizon_correlation_qa(
                run_id, request_id, question_kind, question_json, question_digest,
                answer_json, answer_digest
            ) VALUES (
                p_run_id, p_request_id, p_question_kind, p_question_json, p_question_digest,
                p_answer_json, p_answer_digest
            )
            RETURNING * INTO inserted_row;
            RETURN jsonb_build_object(
                'run_id', inserted_row.run_id,
                'request_id', inserted_row.request_id,
                'question_kind', inserted_row.question_kind,
                'question_digest', inserted_row.question_digest,
                'answer_json', inserted_row.answer_json,
                'answer_digest', inserted_row.answer_digest,
                'replay_count', inserted_row.replay_count,
                'replayed', false
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_get_correlation_answer(
            p_run_id TEXT,
            p_request_id TEXT
        ) RETURNS JSONB AS $$
        DECLARE
            existing_row horizon_correlation_qa%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'correlation lookup requires the workflow principal';
            END IF;
            SELECT * INTO existing_row
            FROM horizon_correlation_qa
            WHERE run_id = p_run_id
              AND request_id = p_request_id;
            IF NOT FOUND THEN
                RETURN NULL;
            END IF;
            RETURN jsonb_build_object(
                'run_id', existing_row.run_id,
                'request_id', existing_row.request_id,
                'question_kind', existing_row.question_kind,
                'question_digest', existing_row.question_digest,
                'answer_json', existing_row.answer_json,
                'answer_digest', existing_row.answer_digest,
                'replay_count', existing_row.replay_count,
                'created_at', existing_row.created_at,
                'updated_at', existing_row.updated_at
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        GRANT SELECT, INSERT, UPDATE ON horizon_prerequisite_decisions TO {WORKFLOW_ROLE};
        GRANT SELECT, INSERT, UPDATE ON horizon_correlation_qa TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_detect_missing_prerequisites(TEXT, TEXT, TEXT, JSONB) TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_record_prerequisite_decision(TEXT, TEXT, TEXT, TEXT, BOOLEAN, TEXT, TEXT, TEXT, TEXT) TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_record_correlation_qa(TEXT, TEXT, TEXT, JSONB, TEXT, JSONB, TEXT) TO {WORKFLOW_ROLE};
        GRANT EXECUTE ON FUNCTION longspan_get_correlation_answer(TEXT, TEXT) TO {WORKFLOW_ROLE};
        """
    )


def downgrade() -> None:
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    assert_migration_catalog(revision)
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    op.execute(
        """
        DROP FUNCTION IF EXISTS longspan_get_correlation_answer(TEXT, TEXT);
        DROP FUNCTION IF EXISTS longspan_record_correlation_qa(TEXT, TEXT, TEXT, JSONB, TEXT, JSONB, TEXT);
        DROP FUNCTION IF EXISTS longspan_record_prerequisite_decision(TEXT, TEXT, TEXT, TEXT, BOOLEAN, TEXT, TEXT, TEXT, TEXT);
        DROP FUNCTION IF EXISTS longspan_detect_missing_prerequisites(TEXT, TEXT, TEXT, JSONB);
        DROP TABLE IF EXISTS horizon_correlation_qa;
        DROP TABLE IF EXISTS horizon_prerequisite_decisions;
        ALTER TABLE horizon_project_nodes DROP COLUMN IF EXISTS dependencies;
        """
    )
