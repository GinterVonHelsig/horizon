"""Authority separation, evidence enforcement, and least-privilege LOGIN roles.

Revision ID: 007_longspan_authority_hardening
Revises: 006_longspan_authority
Create Date: 2026-08-12

Lineage: 004_longspan_workflow -> 005_longspan_hardening -> 006_longspan_authority
         -> 007_longspan_authority_hardening (head).

Prerequisite: distinct workflow, authority, and migration roles must be
pre-provisioned out of band before upgrade. The attacker role is additionally
required only in disposable test databases. If any required role is absent or
unsafe, upgrade aborts before schema mutation.
"""

from __future__ import annotations

from alembic import op
from authority_pins import MIGRATION_SOURCE_PROVENANCE_PATH
from migration_catalog import assert_migration_catalog
from migration_source_anchor import verify_migration_source_anchor

revision = "007_longspan_authority_hardening"
down_revision = "006_longspan_authority"
branch_labels = None
depends_on = None

MIGRATION_ROLE = "top_delivery_migration"
WORKFLOW_ROLE = "top_delivery_workflow"
AUTHORITY_ROLE = "top_delivery_authority"
ATTACKER_ROLE = "top_delivery_attacker"
CONTROLLER_SERVICE = "top-delivery-controller"


def upgrade() -> None:
    verify_migration_source_anchor(
        revision,
        source_path=__file__,
        anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH,
    )
    assert_migration_catalog(revision)
    # Fail closed before any schema mutation if required roles are absent or unsafe.
    op.execute(
        f"""
        DO $prereq$
        DECLARE
            role_rec RECORD;
            member_name TEXT;
            required_roles TEXT[];
        BEGIN
            IF current_user <> '{MIGRATION_ROLE}'
               OR session_user NOT IN ('root', 'postgres') THEN
                RAISE EXCEPTION
                    '007 prerequisite failed: connected migration identity % is not an approved migration principal',
                    current_user;
            END IF;
            IF current_user IN ('{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}') THEN
                RAISE EXCEPTION
                    '007 prerequisite failed: migration identity % must not be workflow or authority role',
                    current_user;
            END IF;
            IF NOT has_schema_privilege(current_user, 'public', 'USAGE')
               OR NOT has_schema_privilege(current_user, 'public', 'CREATE') THEN
                RAISE EXCEPTION
                    '007 prerequisite failed: migration role % must have explicit USAGE and CREATE on public',
                    current_user;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
            ) THEN
                RAISE EXCEPTION
                    '007 prerequisite failed: pgcrypto must be installed out of band before migration';
            END IF;
            IF current_database() ~ '^td_test_'
               OR current_database() ~ '^td_downgrade_' THEN
                required_roles := ARRAY[
                    '{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}', '{ATTACKER_ROLE}', '{MIGRATION_ROLE}'
                ];
            ELSE
                required_roles := ARRAY[
                    '{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}', '{MIGRATION_ROLE}'
                ];
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ATTACKER_ROLE}') THEN
                    RAISE EXCEPTION
                        '007 prerequisite failed: test-only attacker role exists on a non-disposable database';
                END IF;
            END IF;
            FOREACH member_name IN ARRAY required_roles LOOP
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = member_name) THEN
                    RAISE EXCEPTION
                        '007 prerequisite failed: required role % is absent; pre-provision out of band',
                        member_name;
                END IF;
            END LOOP;
            FOR role_rec IN
                SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolcanlogin
                FROM pg_roles
                WHERE rolname = ANY(required_roles)
            LOOP
                IF role_rec.rolsuper OR role_rec.rolcreatedb OR role_rec.rolcreaterole THEN
                    RAISE EXCEPTION
                        '007 prerequisite failed: role % has forbidden superuser/createdb/createrole capability',
                        role_rec.rolname;
                END IF;
                IF role_rec.rolname IN ('{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}')
                   OR (role_rec.rolname = '{ATTACKER_ROLE}'
                       AND (current_database() ~ '^td_test_'
                            OR current_database() ~ '^td_downgrade_')) THEN
                    IF role_rec.rolcanlogin IS DISTINCT FROM TRUE THEN
                        RAISE EXCEPTION
                            '007 prerequisite failed: role % must be LOGIN-enabled',
                            role_rec.rolname;
                    END IF;
                END IF;
                IF role_rec.rolname = '{MIGRATION_ROLE}'
                   AND role_rec.rolcanlogin IS DISTINCT FROM FALSE THEN
                    RAISE EXCEPTION
                        '007 prerequisite failed: migration role % must be NOLOGIN',
                        role_rec.rolname;
                END IF;
            END LOOP;
            IF EXISTS (
                WITH RECURSIVE role_members(member_oid, role_oid) AS (
                    SELECT member, roleid FROM pg_auth_members
                    UNION
                    SELECT graph.member_oid, membership.roleid
                    FROM role_members AS graph
                    JOIN pg_auth_members AS membership
                      ON membership.member = graph.role_oid
                )
                SELECT 1
                FROM role_members AS graph
                JOIN pg_roles AS member_role ON member_role.oid = graph.member_oid
                JOIN pg_roles AS granted_role ON granted_role.oid = graph.role_oid
                WHERE member_role.rolname = ANY(required_roles)
                   OR granted_role.rolname = ANY(required_roles)
            ) THEN
                RAISE EXCEPTION
                    '007 prerequisite failed: required runtime roles have forbidden direct or transitive membership';
            END IF;
            IF pg_has_role('{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}', 'member')
               OR pg_has_role('{AUTHORITY_ROLE}', '{WORKFLOW_ROLE}', 'member') THEN
                RAISE EXCEPTION
                    '007 prerequisite failed: workflow and authority roles must not be mutually grantable';
            END IF;
        END
        $prereq$ LANGUAGE plpgsql;
        """
    )

    op.execute(
        f"""
        -- Extend 006 authority config with provenance binding columns.
        ALTER TABLE longspan_authority_config
            ADD COLUMN IF NOT EXISTS tree_sha TEXT,
            ADD COLUMN IF NOT EXISTS source_digest TEXT,
            ADD COLUMN IF NOT EXISTS config_version INTEGER,
            ADD COLUMN IF NOT EXISTS approval_receipt_digest TEXT;

        UPDATE longspan_authority_config
        SET config_version = 1
        WHERE config_version IS NULL;

        DO $legacy_authority$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM longspan_authority_config
                WHERE terra_auth_hash IS NULL
                   OR btrim(terra_auth_hash) = ''
                   OR operator_auth_hash IS NULL
                   OR btrim(operator_auth_hash) = ''
                   OR reviewed_sha IS NULL
                   OR btrim(reviewed_sha) = ''
                   OR tree_sha IS NULL
                   OR btrim(tree_sha) = ''
                   OR source_digest IS NULL
                   OR btrim(source_digest) = ''
                   OR approval_receipt_digest IS NULL
                   OR btrim(approval_receipt_digest) = ''
                   OR config_version IS NULL
                   OR config_version < 1
            ) THEN
                RAISE EXCEPTION
                    '007 upgrade blocked: legacy authority rows require controlled re-provisioning';
            END IF;
        END
        $legacy_authority$ LANGUAGE plpgsql;

        ALTER TABLE longspan_authority_config
            ALTER COLUMN tree_sha SET NOT NULL,
            ALTER COLUMN source_digest SET NOT NULL,
            ALTER COLUMN config_version SET NOT NULL,
            ALTER COLUMN approval_receipt_digest SET NOT NULL;

        ALTER TABLE longspan_authority_config
            DROP CONSTRAINT IF EXISTS longspan_authority_config_nonempty_chk;
        ALTER TABLE longspan_authority_config
            ADD CONSTRAINT longspan_authority_config_nonempty_chk CHECK (
                btrim(terra_auth_hash) <> ''
                AND btrim(operator_auth_hash) <> ''
                AND btrim(reviewed_sha) <> ''
                AND btrim(tree_sha) <> ''
                AND btrim(source_digest) <> ''
                AND btrim(approval_receipt_digest) <> ''
                AND config_version > 0
            );

        CREATE TABLE IF NOT EXISTS longspan_authority_history (
            history_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            config_version INTEGER NOT NULL,
            terra_auth_hash TEXT NOT NULL,
            operator_auth_hash TEXT NOT NULL,
            reviewed_sha TEXT NOT NULL,
            tree_sha TEXT NOT NULL,
            source_digest TEXT NOT NULL,
            approval_receipt_digest TEXT NOT NULL,
            approval_id TEXT,
            operator_identity TEXT,
            controller_epoch INTEGER,
            challenge_epoch INTEGER,
            receipt_id TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (run_id, config_version),
            CHECK (config_version > 0),
            CHECK (btrim(reviewed_sha) <> ''),
            CHECK (btrim(tree_sha) <> ''),
            CHECK (btrim(source_digest) <> ''),
            CHECK (btrim(approval_receipt_digest) <> '')
        );

        CREATE TABLE IF NOT EXISTS longspan_execution_audits (
            audit_id TEXT PRIMARY KEY,
            child_id TEXT NOT NULL REFERENCES longspan_children(child_id),
            attempt_number INTEGER NOT NULL,
            request_digest TEXT NOT NULL,
            evidence_digest TEXT NOT NULL,
            result_digest TEXT NOT NULL,
            validation_outcome TEXT NOT NULL,
            raw_result_ref TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (child_id, attempt_number),
            CHECK (attempt_number >= 0),
            CHECK (btrim(request_digest) <> ''),
            CHECK (btrim(evidence_digest) <> ''),
            CHECK (btrim(result_digest) <> ''),
            CHECK (btrim(validation_outcome) <> '')
        );

        -- 007 is also safe when applied to a database that already has the
        -- audit table from a partially rehearsed candidate.  Do not invent an
        -- evidence binding for populated historical rows; require the caller
        -- to restore/rebuild that disposable database instead.
        ALTER TABLE longspan_execution_audits
            ADD COLUMN IF NOT EXISTS evidence_digest TEXT;
        DO $execution_audit_binding$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM longspan_execution_audits
                WHERE evidence_digest IS NULL OR btrim(evidence_digest) = ''
            ) THEN
                RAISE EXCEPTION
                    '007 upgrade blocked: execution audits lack immutable evidence digests';
            END IF;
        END
        $execution_audit_binding$ LANGUAGE plpgsql;
        ALTER TABLE longspan_execution_audits
            ALTER COLUMN evidence_digest SET NOT NULL;

        -- Persist the exact canonical evidence bytes before the executor
        -- result/audit transaction completes.  The auditor reloads this row
        -- from PostgreSQL and recomputes its digest; it never treats an
        -- executor-supplied in-memory tuple as the authority.
        CREATE TABLE IF NOT EXISTS longspan_execution_evidence (
            evidence_id TEXT PRIMARY KEY,
            child_id TEXT NOT NULL REFERENCES longspan_children(child_id),
            attempt_number INTEGER NOT NULL,
            evidence_json TEXT NOT NULL,
            evidence_digest TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (child_id, attempt_number),
            CHECK (attempt_number >= 0),
            CHECK (btrim(evidence_json) <> ''),
            CHECK (btrim(evidence_digest) <> '')
        );
        ALTER TABLE longspan_execution_evidence OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON longspan_execution_evidence FROM PUBLIC;

        ALTER TABLE longspan_auditor_receipts
            ADD COLUMN IF NOT EXISTS evidence_digest TEXT;
        DO $auditor_receipt_binding$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM longspan_auditor_receipts
                WHERE evidence_digest IS NULL OR btrim(evidence_digest) = ''
            ) THEN
                RAISE EXCEPTION
                    '007 upgrade blocked: auditor receipts lack immutable evidence digests';
            END IF;
        END
        $auditor_receipt_binding$ LANGUAGE plpgsql;
        ALTER TABLE longspan_auditor_receipts
            ALTER COLUMN evidence_digest SET NOT NULL;

        CREATE TABLE IF NOT EXISTS longspan_operator_challenges (
            approval_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            action_type TEXT NOT NULL,
            action_digest TEXT NOT NULL,
            operator_identity TEXT NOT NULL,
            nonce TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            key_version INTEGER NOT NULL,
            challenge_digest TEXT NOT NULL,
            controller_epoch INTEGER,
            config_version INTEGER,
            challenge_epoch INTEGER,
            write_binding_digest TEXT,
            write_credential_digest TEXT,
            consumed_at TIMESTAMPTZ,
            write_applied_at TIMESTAMPTZ,
            write_applied_txid BIGINT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            CHECK (key_version > 0),
            CHECK (btrim(action_type) <> ''),
            CHECK (btrim(action_digest) <> ''),
            CHECK (btrim(operator_identity) <> ''),
            CHECK (btrim(nonce) <> ''),
            CHECK (btrim(challenge_digest) <> '')
        );

        -- Some pre-007 control databases were created from an intermediate
        -- candidate whose CREATE TABLE omitted the run FK.  Reassert the
        -- relationship here, after supervisor_runs exists, and fail closed on
        -- any orphan rather than silently weakening challenge provenance.
        DO $challenge_run_binding$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM longspan_operator_challenges AS challenge
                LEFT JOIN supervisor_runs AS run ON run.run_id = challenge.run_id
                WHERE run.run_id IS NULL
            ) THEN
                RAISE EXCEPTION
                    '007 upgrade blocked: operator challenges contain an unknown run_id';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint AS constraint_row
                WHERE constraint_row.conrelid =
                      'public.longspan_operator_challenges'::regclass
                  AND constraint_row.contype = 'f'
                  AND pg_get_constraintdef(constraint_row.oid) LIKE
                      'FOREIGN KEY (run_id) REFERENCES supervisor_runs(run_id)%'
            ) THEN
                ALTER TABLE longspan_operator_challenges
                    ADD CONSTRAINT longspan_operator_challenges_run_id_supervisor_fk
                    FOREIGN KEY (run_id) REFERENCES supervisor_runs(run_id);
            END IF;
        END
        $challenge_run_binding$ LANGUAGE plpgsql;

        ALTER TABLE longspan_operator_challenges
            ADD COLUMN IF NOT EXISTS write_applied_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS write_applied_txid BIGINT;

        ALTER TABLE longspan_evidence_ledger
            ADD COLUMN IF NOT EXISTS sequence_number INTEGER;

        -- 005 protects legacy rows with a BEFORE UPDATE trigger. Disable it
        -- only for this transactional migration backfill; 007 reinstalls its
        -- stronger append-only trigger below before the migration commits.
        ALTER TABLE longspan_evidence_ledger DISABLE TRIGGER longspan_evidence_no_update;

        UPDATE longspan_evidence_ledger AS ledger
        SET sequence_number = ranked.seq
        FROM (
            SELECT entry_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY child_id ORDER BY created_at, entry_id
                   ) AS seq
            FROM longspan_evidence_ledger
        ) AS ranked
        WHERE ledger.entry_id = ranked.entry_id
          AND ledger.sequence_number IS NULL;

        ALTER TABLE longspan_evidence_ledger
            ALTER COLUMN sequence_number SET NOT NULL;

        ALTER TABLE longspan_evidence_ledger
            ADD COLUMN IF NOT EXISTS base_digest TEXT,
            ADD COLUMN IF NOT EXISTS mac_key_version INTEGER,
            ADD COLUMN IF NOT EXISTS legacy_unkeyed BOOLEAN NOT NULL DEFAULT FALSE;

        UPDATE longspan_evidence_ledger
        SET base_digest = entry_hash,
            mac_key_version = NULL,
            legacy_unkeyed = TRUE
        WHERE base_digest IS NULL;

        ALTER TABLE longspan_evidence_ledger
            ALTER COLUMN base_digest SET NOT NULL;

        ALTER TABLE longspan_evidence_ledger ENABLE TRIGGER longspan_evidence_no_update;

        CREATE UNIQUE INDEX IF NOT EXISTS longspan_evidence_ledger_child_seq_uq
            ON longspan_evidence_ledger (child_id, sequence_number);

        CREATE UNIQUE INDEX IF NOT EXISTS longspan_auditor_receipts_child_attempt_uq
            ON longspan_auditor_receipts (child_id, attempt_number);

        DO $unbound_receipts$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM longspan_terra_receipts AS receipt
                LEFT JOIN longspan_children AS child
                    ON child.child_id = receipt.child_id
                WHERE receipt.run_id IS NULL
                   OR receipt.task_id IS NULL
                   OR receipt.reviewed_sha IS NULL
                   OR btrim(receipt.reviewed_sha) = ''
                   OR child.child_id IS NULL
            ) THEN
                RAISE EXCEPTION
                    '007 upgrade blocked: terra receipts cannot be bound to authority provenance';
            END IF;
        END
        $unbound_receipts$ LANGUAGE plpgsql;

        ALTER TABLE longspan_terra_receipts
            ALTER COLUMN run_id SET NOT NULL,
            ALTER COLUMN task_id SET NOT NULL,
            ALTER COLUMN reviewed_sha SET NOT NULL;

        ALTER TABLE longspan_terra_receipts
            DROP CONSTRAINT IF EXISTS longspan_terra_receipts_binding_chk;
        ALTER TABLE longspan_terra_receipts
            ADD CONSTRAINT longspan_terra_receipts_binding_chk CHECK (
                btrim(run_id) <> ''
                AND btrim(task_id) <> ''
                AND btrim(reviewed_sha) <> ''
            );

        ALTER TABLE longspan_terra_receipts
            ADD COLUMN IF NOT EXISTS attempt_number INTEGER,
            ADD COLUMN IF NOT EXISTS fence_token BIGINT,
            ADD COLUMN IF NOT EXISTS controller_epoch INTEGER,
            ADD COLUMN IF NOT EXISTS lease_token_hash TEXT,
            ADD COLUMN IF NOT EXISTS tree_sha TEXT,
            ADD COLUMN IF NOT EXISTS source_digest TEXT,
            ADD COLUMN IF NOT EXISTS request_digest TEXT,
            ADD COLUMN IF NOT EXISTS migration_head TEXT,
            ADD COLUMN IF NOT EXISTS authority_version INTEGER,
            ADD COLUMN IF NOT EXISTS evidence_digest TEXT,
            ADD COLUMN IF NOT EXISTS result_digest TEXT,
            ADD COLUMN IF NOT EXISTS signature TEXT,
            ADD COLUMN IF NOT EXISTS authority_signature TEXT;

        CREATE TABLE IF NOT EXISTS longspan_mac_material (
            material_id TEXT PRIMARY KEY DEFAULT 'ledger',
            mac_key TEXT NOT NULL,
            key_version INTEGER NOT NULL DEFAULT 1,
            installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            CHECK (material_id IN ('ledger', 'terra_gateway')),
            CHECK (key_version > 0),
            CHECK (btrim(mac_key) <> '')
        );

        CREATE TABLE IF NOT EXISTS longspan_mac_key_history (
            material_id TEXT NOT NULL DEFAULT 'ledger',
            key_version INTEGER NOT NULL,
            mac_key TEXT NOT NULL,
            installed_at TIMESTAMPTZ NOT NULL,
            retired_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (material_id, key_version),
            CHECK (material_id IN ('ledger', 'terra_gateway')),
            CHECK (key_version > 0),
            CHECK (btrim(mac_key) <> '')
        );

        CREATE TABLE IF NOT EXISTS longspan_ledger_legacy_attestations (
            child_id TEXT PRIMARY KEY REFERENCES longspan_children(child_id),
            legacy_row_count INTEGER NOT NULL,
            legacy_last_sequence INTEGER NOT NULL,
            legacy_head_hash TEXT NOT NULL,
            legacy_chain_digest TEXT NOT NULL,
            attestation_digest TEXT NOT NULL,
            mac_key_version INTEGER NOT NULL,
            attestation_revision TEXT NOT NULL DEFAULT '007_longspan_authority_hardening',
            attested_by TEXT NOT NULL DEFAULT 'top_delivery_authority',
            legacy_origin TEXT NOT NULL DEFAULT 'pre_007_unkeyed',
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            CHECK (legacy_row_count > 0),
            CHECK (legacy_last_sequence > 0),
            CHECK (btrim(legacy_head_hash) <> ''),
            CHECK (btrim(legacy_chain_digest) <> ''),
            CHECK (btrim(attestation_digest) <> ''),
            CHECK (mac_key_version > 0),
            CHECK (btrim(attestation_revision) <> ''),
            CHECK (btrim(attested_by) <> ''),
            CHECK (legacy_origin = 'pre_007_unkeyed')
        );

        ALTER TABLE longspan_ledger_legacy_attestations
            ADD COLUMN IF NOT EXISTS attestation_revision TEXT
                NOT NULL DEFAULT '007_longspan_authority_hardening',
            ADD COLUMN IF NOT EXISTS attested_by TEXT
                NOT NULL DEFAULT 'top_delivery_authority',
            ADD COLUMN IF NOT EXISTS legacy_origin TEXT
                NOT NULL DEFAULT 'pre_007_unkeyed';

        -- These columns were added with ALTER TABLE for databases that
        -- already existed before 007.  Reassert the same invariants there;
        -- a NOT NULL/default clause alone does not prove the legacy origin.
        DO $legacy_constraints$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'legacy_attestation_revision_nonempty'
                  AND conrelid = 'longspan_ledger_legacy_attestations'::regclass
            ) THEN
                ALTER TABLE longspan_ledger_legacy_attestations
                    ADD CONSTRAINT legacy_attestation_revision_nonempty
                    CHECK (btrim(attestation_revision) <> '');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'legacy_attested_by_nonempty'
                  AND conrelid = 'longspan_ledger_legacy_attestations'::regclass
            ) THEN
                ALTER TABLE longspan_ledger_legacy_attestations
                    ADD CONSTRAINT legacy_attested_by_nonempty
                    CHECK (btrim(attested_by) <> '');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'legacy_origin_allowed'
                  AND conrelid = 'longspan_ledger_legacy_attestations'::regclass
            ) THEN
                ALTER TABLE longspan_ledger_legacy_attestations
                    ADD CONSTRAINT legacy_origin_allowed
                    CHECK (legacy_origin = 'pre_007_unkeyed');
            END IF;
        END
        $legacy_constraints$;

        ALTER TABLE longspan_mac_material
            ADD COLUMN IF NOT EXISTS key_version INTEGER NOT NULL DEFAULT 1;

        CREATE TABLE IF NOT EXISTS longspan_authority_receipts (
            receipt_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
            action_type TEXT NOT NULL,
            config_version INTEGER NOT NULL,
            approval_id TEXT NOT NULL,
            result_digest TEXT NOT NULL,
            reviewed_sha TEXT NOT NULL,
            tree_sha TEXT NOT NULL,
            source_digest TEXT NOT NULL,
            migration_head TEXT NOT NULL,
            controller_epoch INTEGER NOT NULL,
            signature TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            CHECK (config_version > 0),
            CHECK (btrim(result_digest) <> ''),
            CHECK (btrim(signature) <> '')
        );

        -- The Ed25519 Terra signature is verified by the out-of-band
        -- authority service.  This table is the database-side, one-shot
        -- witness that binds that verification to the exact persisted receipt
        -- facts.  The workflow can consume a witness, but cannot issue one.
        CREATE TABLE IF NOT EXISTS longspan_terra_receipt_attestations (
            attestation_id TEXT PRIMARY KEY,
            -- Deliberately no foreign-key lock: the workflow may hold the
            -- child fence while the authority socket issues this witness.
            -- The SECURITY DEFINER issuer verifies the child/run binding
            -- before insertion, and the workflow consumes it under its lock.
            child_id TEXT NOT NULL,
            attempt_number INTEGER NOT NULL,
            run_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            receipt_digest TEXT NOT NULL,
            signature_digest TEXT NOT NULL,
            reviewer TEXT NOT NULL,
            decision TEXT NOT NULL,
            evidence_chain_head TEXT NOT NULL,
            reviewed_sha TEXT NOT NULL,
            fence_token BIGINT NOT NULL,
            controller_epoch INTEGER NOT NULL,
            tree_sha TEXT NOT NULL,
            source_digest TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            migration_head TEXT NOT NULL,
            authority_version INTEGER NOT NULL,
            evidence_digest TEXT NOT NULL,
            result_digest TEXT NOT NULL,
            issued_by TEXT NOT NULL DEFAULT '{AUTHORITY_ROLE}',
            issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            consumed_at TIMESTAMPTZ,
            UNIQUE (child_id, attempt_number, receipt_digest),
            CHECK (attempt_number >= 0),
            CHECK (decision IN ('approved', 'rejected')),
            CHECK (btrim(receipt_digest) <> ''),
            CHECK (signature_digest ~ '^[0-9a-f]{{64}}$'),
            CHECK (btrim(reviewer) <> ''),
            CHECK (btrim(evidence_chain_head) <> ''),
            CHECK (btrim(reviewed_sha) <> ''),
            CHECK (btrim(tree_sha) <> ''),
            CHECK (btrim(source_digest) <> ''),
            CHECK (btrim(request_digest) <> ''),
            CHECK (migration_head = '007_longspan_authority_hardening'),
            CHECK (authority_version > 0),
            CHECK (btrim(evidence_digest) <> ''),
            CHECK (btrim(result_digest) <> ''),
            CHECK (issued_by = '{AUTHORITY_ROLE}')
        );

        -- Roles are pre-provisioned out of band; enforce separation only.
        DO $roles$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{WORKFLOW_ROLE}' AND rolcanlogin) THEN
                RAISE EXCEPTION 'workflow role must be a pre-provisioned LOGIN role';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{AUTHORITY_ROLE}' AND rolcanlogin) THEN
                RAISE EXCEPTION 'authority role must be a pre-provisioned LOGIN role';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATION_ROLE}') THEN
                RAISE EXCEPTION 'migration role must be pre-provisioned out of band';
            END IF;
            -- The single required_roles graph check above is the source of
            -- truth.  Do not repeat it with a divergent literal role array.
            IF EXISTS (
                SELECT 1
                FROM pg_class AS class
                JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
                WHERE namespace.nspname = 'public'
                  AND class.relname IN (
                      'controller_control', 'parent_tasks', 'task_attempts', 'retry_queue',
                      'longspan_children', 'longspan_plans', 'longspan_execution_results',
                      'longspan_evidence_ledger', 'longspan_authority_config',
                      'longspan_authority_history', 'longspan_operator_challenges',
                      'longspan_execution_audits', 'longspan_auditor_receipts',
                      'longspan_terra_receipts', 'longspan_authority_receipts',
                      'longspan_terra_receipt_attestations',
                      'longspan_mac_material', 'longspan_mac_key_history',
                      'longspan_ledger_legacy_attestations',
                      'top_delivery_downgrade_capabilities'
                  )
                  AND pg_get_userbyid(class.relowner) IN (
                      '{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}', '{ATTACKER_ROLE}'
                  )
            ) THEN
                RAISE EXCEPTION 'runtime role may not own protected controller tables';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM pg_proc AS procedure
                JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
                WHERE namespace.nspname = 'public'
                  AND pg_get_userbyid(procedure.proowner) IN (
                      '{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}', '{ATTACKER_ROLE}'
                  )
            ) THEN
                RAISE EXCEPTION 'runtime role may not own controller routines';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM pg_namespace AS namespace
                WHERE namespace.nspname = 'public'
                  AND pg_get_userbyid(namespace.nspowner) IN (
                      '{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}', '{ATTACKER_ROLE}'
                  )
            ) THEN
                RAISE EXCEPTION 'runtime role may not own the controller schema';
            END IF;
            -- Role membership is an out-of-band cluster prerequisite.  The
            -- migration principal is deliberately NOCREATEROLE and may not
            -- mutate pg_auth_members.  The membership audit above rejects
            -- unsafe grants before any schema mutation; test/bootstrap role
            -- provisioning must remove them with the cluster administrator.
        END
        $roles$ LANGUAGE plpgsql;

        ALTER TABLE controller_control
            ADD COLUMN IF NOT EXISTS controller_fence_token BIGINT NOT NULL DEFAULT 1;

        CREATE TABLE IF NOT EXISTS top_delivery_downgrade_capabilities (
            nonce TEXT PRIMARY KEY,
            operation TEXT NOT NULL,
            database_name TEXT NOT NULL,
            database_role TEXT NOT NULL,
            transport_database_role TEXT NOT NULL,
            controller_service TEXT NOT NULL,
            migration_revision TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            consumed_at TIMESTAMPTZ,
            consumed_steps TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[]
            ,CHECK (btrim(operation) <> '')
            ,CHECK (btrim(database_name) <> '')
            ,CHECK (btrim(database_role) <> '')
            ,CHECK (btrim(controller_service) <> '')
            ,CHECK (btrim(migration_revision) <> '')
            ,CHECK (expires_at > issued_at)
        );
        DO $downgrade_constraints$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'downgrade_capability_operation_nonempty'
                  AND conrelid = 'top_delivery_downgrade_capabilities'::regclass
            ) THEN
                ALTER TABLE top_delivery_downgrade_capabilities
                    ADD CONSTRAINT downgrade_capability_operation_nonempty
                    CHECK (btrim(operation) <> '');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'downgrade_capability_database_nonempty'
                  AND conrelid = 'top_delivery_downgrade_capabilities'::regclass
            ) THEN
                ALTER TABLE top_delivery_downgrade_capabilities
                    ADD CONSTRAINT downgrade_capability_database_nonempty
                    CHECK (btrim(database_name) <> '');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'downgrade_capability_role_nonempty'
                  AND conrelid = 'top_delivery_downgrade_capabilities'::regclass
            ) THEN
                ALTER TABLE top_delivery_downgrade_capabilities
                    ADD CONSTRAINT downgrade_capability_role_nonempty
                    CHECK (btrim(database_role) <> '');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'downgrade_capability_service_nonempty'
                  AND conrelid = 'top_delivery_downgrade_capabilities'::regclass
            ) THEN
                ALTER TABLE top_delivery_downgrade_capabilities
                    ADD CONSTRAINT downgrade_capability_service_nonempty
                    CHECK (btrim(controller_service) <> '');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'downgrade_capability_revision_nonempty'
                  AND conrelid = 'top_delivery_downgrade_capabilities'::regclass
            ) THEN
                ALTER TABLE top_delivery_downgrade_capabilities
                    ADD CONSTRAINT downgrade_capability_revision_nonempty
                    CHECK (btrim(migration_revision) <> '');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'downgrade_capability_expiry_after_issue'
                  AND conrelid = 'top_delivery_downgrade_capabilities'::regclass
            ) THEN
                ALTER TABLE top_delivery_downgrade_capabilities
                    ADD CONSTRAINT downgrade_capability_expiry_after_issue
                    CHECK (expires_at > issued_at);
            END IF;
        END
        $downgrade_constraints$;
        ALTER TABLE top_delivery_downgrade_capabilities
            ADD COLUMN IF NOT EXISTS consumed_steps TEXT[]
                NOT NULL DEFAULT ARRAY[]::TEXT[],
            ALTER COLUMN consumed_steps SET DEFAULT ARRAY[]::TEXT[];
        ALTER TABLE top_delivery_downgrade_capabilities
            ADD COLUMN IF NOT EXISTS transport_database_role TEXT;
        UPDATE top_delivery_downgrade_capabilities
        SET transport_database_role = database_role
        WHERE transport_database_role IS NULL;
        ALTER TABLE top_delivery_downgrade_capabilities
            ALTER COLUMN transport_database_role SET NOT NULL;
        ALTER TABLE top_delivery_downgrade_capabilities
            OWNER TO {MIGRATION_ROLE};
        ALTER TABLE longspan_terra_receipt_attestations
            OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON top_delivery_downgrade_capabilities FROM PUBLIC,
            {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        GRANT SELECT, INSERT, UPDATE ON top_delivery_downgrade_capabilities
            TO {MIGRATION_ROLE};

        GRANT USAGE ON SCHEMA public TO {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        -- SECURITY DEFINER routines use pg_catalog, public only for stable
        -- object resolution. Runtime principals must not create shadow objects
        -- in that schema; the dedicated NOLOGIN migration role is the only
        -- principal granted schema CREATE for migrations.
        REVOKE CREATE ON SCHEMA public FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        GRANT CREATE ON SCHEMA public TO {MIGRATION_ROLE};
        REVOKE ALL ON longspan_ledger_legacy_attestations FROM PUBLIC;
        REVOKE ALL ON longspan_terra_receipt_attestations FROM PUBLIC,
            {WORKFLOW_ROLE}, {AUTHORITY_ROLE};

        -- Explicit operational grants (no ALL TABLES).
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            evidence_index,
            longspan_children,
            longspan_plans,
            longspan_execution_results,
            longspan_experiments,
            manifest_submissions,
            notifications,
            parent_tasks,
            provenance_records,
            required_manifest_entries,
            retry_queue,
            signal_status,
            supervisor_events,
            task_attempts
            TO {WORKFLOW_ROLE};

        -- Controller state is readable by the workflow role, but its rows are
        -- created and changed only through database-owned routines and scope
        -- triggers below.
        GRANT SELECT ON supervisor_runs, controller_control TO {WORKFLOW_ROLE};

        GRANT SELECT ON
            longspan_authority_config,
            longspan_authority_history,
            longspan_operator_challenges,
            longspan_authority_receipts,
            longspan_evidence_ledger,
            longspan_ledger_legacy_attestations,
            longspan_execution_audits,
            longspan_execution_evidence,
            longspan_auditor_receipts,
            longspan_terra_receipts,
            alembic_version
            TO {WORKFLOW_ROLE};

        GRANT SELECT ON
            longspan_authority_config,
            longspan_authority_history,
            longspan_operator_challenges,
            longspan_authority_receipts,
            longspan_evidence_ledger,
            longspan_ledger_legacy_attestations,
            longspan_execution_audits,
            longspan_execution_evidence,
            longspan_auditor_receipts,
            longspan_terra_receipts,
            longspan_children,
            supervisor_runs,
            controller_control,
            alembic_version
            TO {AUTHORITY_ROLE};

        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
            TO {WORKFLOW_ROLE}, {AUTHORITY_ROLE};

        -- Authority mutation triggers: versioned rotation only.
        CREATE OR REPLACE FUNCTION reject_longspan_authority_mutation()
        RETURNS trigger AS $$
        BEGIN
            IF current_setting('top_delivery.authority_routine', true) IS DISTINCT FROM '1' THEN
                RAISE EXCEPTION 'longspan_authority_config may only be mutated via owned routines';
            END IF;
            IF TG_OP = 'INSERT' THEN
                RETURN NEW;
            ELSIF TG_OP = 'UPDATE' THEN
                IF NEW.terra_auth_hash IS DISTINCT FROM OLD.terra_auth_hash
                   OR NEW.operator_auth_hash IS DISTINCT FROM OLD.operator_auth_hash
                   OR NEW.reviewed_sha IS DISTINCT FROM OLD.reviewed_sha
                   OR NEW.tree_sha IS DISTINCT FROM OLD.tree_sha
                   OR NEW.source_digest IS DISTINCT FROM OLD.source_digest
                   OR NEW.approval_receipt_digest IS DISTINCT FROM OLD.approval_receipt_digest THEN
                    IF NEW.config_version <= OLD.config_version THEN
                        RAISE EXCEPTION 'authority rotation requires config_version increment';
                    END IF;
                ELSIF NEW.config_version IS DISTINCT FROM OLD.config_version THEN
                    RAISE EXCEPTION 'authority config_version-only mutation is forbidden';
                END IF;
            ELSIF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'longspan_authority_config is immutable except via versioned rotation';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE OR REPLACE FUNCTION reject_longspan_authority_history_mutation()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF current_setting('top_delivery.authority_routine', true) IS DISTINCT FROM '1' THEN
                    RAISE EXCEPTION 'longspan_authority_history may only be mutated via owned routines';
                END IF;
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'longspan_authority_history is append-only';
        END;
        $$ LANGUAGE plpgsql;

        CREATE OR REPLACE FUNCTION reject_longspan_append_only_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
        END;
        $$ LANGUAGE plpgsql;

        CREATE OR REPLACE FUNCTION reject_longspan_terra_attestation_mutation()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'INSERT'
               AND session_user = '{AUTHORITY_ROLE}'
               AND current_setting('top_delivery.authority_routine', true) = '1' THEN
                RETURN NEW;
            END IF;
            IF TG_OP = 'UPDATE'
               AND session_user = '{WORKFLOW_ROLE}'
               AND current_setting('top_delivery.attestation_routine', true) = '1'
               AND NEW.attestation_id IS NOT DISTINCT FROM OLD.attestation_id
               AND NEW.consumed_at IS NOT NULL
               AND OLD.consumed_at IS NULL
               AND NEW.child_id IS NOT DISTINCT FROM OLD.child_id
               AND NEW.receipt_digest IS NOT DISTINCT FROM OLD.receipt_digest
               AND NEW.signature_digest IS NOT DISTINCT FROM OLD.signature_digest THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'Terra receipt attestations are authority-issued and one-shot';
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION reject_longspan_legacy_watermark()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'INSERT' AND NEW.legacy_unkeyed IS TRUE THEN
                RAISE EXCEPTION 'new evidence entries may not be marked legacy_unkeyed';
            END IF;
            IF TG_OP = 'UPDATE'
               AND NEW.legacy_unkeyed IS DISTINCT FROM OLD.legacy_unkeyed THEN
                RAISE EXCEPTION 'evidence legacy watermark is immutable';
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION reject_longspan_legacy_attestation_mutation()
        RETURNS trigger AS $$
        BEGIN
            IF session_user <> '{AUTHORITY_ROLE}'
               OR current_setting('top_delivery.authority_routine', true) IS DISTINCT FROM '1' THEN
                RAISE EXCEPTION 'legacy ledger attestations may only be mutated via the authority routine';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'legacy ledger attestations are immutable';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION reject_challenge_direct_mutation()
        RETURNS trigger AS $$
        BEGIN
            -- Direct DML path: only consume/bind through owned routines (session GUC).
            IF current_setting('top_delivery.authority_routine', true) IS DISTINCT FROM '1' THEN
                RAISE EXCEPTION 'longspan_operator_challenges may only be mutated via owned routines';
            END IF;
            IF TG_OP = 'UPDATE' THEN
                IF NEW.approval_id IS DISTINCT FROM OLD.approval_id
                   OR NEW.run_id IS DISTINCT FROM OLD.run_id
                   OR NEW.action_type IS DISTINCT FROM OLD.action_type
                   OR NEW.action_digest IS DISTINCT FROM OLD.action_digest
                   OR NEW.operator_identity IS DISTINCT FROM OLD.operator_identity
                   OR NEW.nonce IS DISTINCT FROM OLD.nonce
                   OR NEW.challenge_digest IS DISTINCT FROM OLD.challenge_digest
                   OR NEW.key_version IS DISTINCT FROM OLD.key_version THEN
                    RAISE EXCEPTION 'operator challenge identity fields are immutable';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS longspan_authority_no_delete ON longspan_authority_config;
        CREATE TRIGGER longspan_authority_no_delete
            BEFORE INSERT OR UPDATE OR DELETE ON longspan_authority_config
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_authority_mutation();

        DROP TRIGGER IF EXISTS longspan_authority_history_no_update ON longspan_authority_history;
        CREATE TRIGGER longspan_authority_history_no_update
            BEFORE INSERT OR UPDATE OR DELETE ON longspan_authority_history
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_authority_history_mutation();

        DROP TRIGGER IF EXISTS longspan_evidence_ledger_append_only ON longspan_evidence_ledger;
        CREATE TRIGGER longspan_evidence_ledger_append_only
            BEFORE UPDATE OR DELETE ON longspan_evidence_ledger
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_append_only_mutation();

        DROP TRIGGER IF EXISTS longspan_evidence_legacy_watermark ON longspan_evidence_ledger;
        CREATE TRIGGER longspan_evidence_legacy_watermark
            BEFORE INSERT OR UPDATE ON longspan_evidence_ledger
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_legacy_watermark();

        DROP TRIGGER IF EXISTS longspan_legacy_attestation_guard
            ON longspan_ledger_legacy_attestations;
        CREATE TRIGGER longspan_legacy_attestation_guard
            BEFORE INSERT OR UPDATE OR DELETE ON longspan_ledger_legacy_attestations
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_legacy_attestation_mutation();

        DROP TRIGGER IF EXISTS longspan_execution_audits_append_only ON longspan_execution_audits;
        DROP TRIGGER IF EXISTS longspan_execution_evidence_append_only
            ON longspan_execution_evidence;
        CREATE TRIGGER longspan_execution_audits_append_only
            BEFORE UPDATE OR DELETE ON longspan_execution_audits
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_append_only_mutation();

        DROP TRIGGER IF EXISTS longspan_execution_evidence_append_only
            ON longspan_execution_evidence;
        CREATE TRIGGER longspan_execution_evidence_append_only
            BEFORE UPDATE OR DELETE ON longspan_execution_evidence
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_append_only_mutation();

        DROP TRIGGER IF EXISTS longspan_auditor_receipts_append_only ON longspan_auditor_receipts;
        CREATE TRIGGER longspan_auditor_receipts_append_only
            BEFORE UPDATE OR DELETE ON longspan_auditor_receipts
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_append_only_mutation();

        DROP TRIGGER IF EXISTS longspan_terra_receipts_append_only ON longspan_terra_receipts;
        CREATE TRIGGER longspan_terra_receipts_append_only
            BEFORE UPDATE OR DELETE ON longspan_terra_receipts
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_append_only_mutation();

        DROP TRIGGER IF EXISTS longspan_authority_receipts_append_only ON longspan_authority_receipts;
        CREATE TRIGGER longspan_authority_receipts_append_only
            BEFORE UPDATE OR DELETE ON longspan_authority_receipts
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_append_only_mutation();

        DROP TRIGGER IF EXISTS longspan_terra_attestation_guard
            ON longspan_terra_receipt_attestations;
        CREATE TRIGGER longspan_terra_attestation_guard
            BEFORE INSERT OR UPDATE OR DELETE ON longspan_terra_receipt_attestations
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_terra_attestation_mutation();

        DROP TRIGGER IF EXISTS longspan_operator_challenges_guard ON longspan_operator_challenges;
        CREATE TRIGGER longspan_operator_challenges_guard
            BEFORE UPDATE OR DELETE ON longspan_operator_challenges
            FOR EACH ROW EXECUTE FUNCTION reject_challenge_direct_mutation();

        -- Owned routines for authority/challenge/evidence boundaries.
        CREATE OR REPLACE FUNCTION longspan_create_operator_challenge(
            p_approval_id TEXT,
            p_run_id TEXT,
            p_action_type TEXT,
            p_action_digest TEXT,
            p_operator_identity TEXT,
            p_nonce TEXT,
            p_expires_at TIMESTAMPTZ,
            p_key_version INTEGER,
            p_challenge_digest TEXT,
            p_controller_epoch INTEGER,
            p_config_version INTEGER,
            p_challenge_epoch INTEGER
        ) RETURNS VOID AS $$
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'operator challenges may only be created by the workflow principal';
            END IF;
            IF p_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'operator challenge already expired';
            END IF;
            IF p_expires_at > clock_timestamp() + interval '15 minutes' THEN
                RAISE EXCEPTION 'operator challenge TTL exceeds bound';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM supervisor_runs WHERE run_id = p_run_id
            ) THEN
                RAISE EXCEPTION 'operator challenge run is unknown';
            END IF;
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            INSERT INTO longspan_operator_challenges
                (approval_id, run_id, action_type, action_digest, operator_identity,
                 nonce, expires_at, key_version, challenge_digest, controller_epoch,
                 config_version, challenge_epoch)
            VALUES (
                p_approval_id, p_run_id, p_action_type, p_action_digest, p_operator_identity,
                p_nonce, p_expires_at, p_key_version, p_challenge_digest, p_controller_epoch,
                p_config_version, p_challenge_epoch
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_bind_and_consume_challenge(
            p_approval_id TEXT,
            p_write_binding_digest TEXT,
            p_write_credential_digest TEXT
        ) RETURNS VOID AS $$
        DECLARE
            row_challenge longspan_operator_challenges%ROWTYPE;
        BEGIN
            IF session_user <> '{AUTHORITY_ROLE}' THEN
                RAISE EXCEPTION 'operator challenges may only be consumed by the authority principal';
            END IF;
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            SELECT * INTO row_challenge
            FROM longspan_operator_challenges
            WHERE approval_id = p_approval_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'operator challenge is unknown';
            END IF;
            IF row_challenge.consumed_at IS NOT NULL THEN
                RAISE EXCEPTION 'operator challenge already consumed';
            END IF;
            IF row_challenge.expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'operator challenge expired';
            END IF;
            UPDATE longspan_operator_challenges
            SET write_binding_digest = p_write_binding_digest,
                write_credential_digest = p_write_credential_digest,
                consumed_at = clock_timestamp()
            WHERE approval_id = p_approval_id AND consumed_at IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'operator challenge consumption lost the race';
            END IF;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

    CREATE OR REPLACE FUNCTION longspan_install_ledger_mac_key(p_mac_key TEXT)
    RETURNS VOID AS $$
        DECLARE
            current_key longspan_mac_material%ROWTYPE;
            legacy_row RECORD;
            legacy_payload TEXT;
            legacy_attestation TEXT;
            next_version INTEGER;
        BEGIN
            IF session_user <> '{AUTHORITY_ROLE}' THEN
                RAISE EXCEPTION 'ledger MAC material may only be installed by the authority service';
            END IF;
            IF btrim(p_mac_key) = '' THEN
                RAISE EXCEPTION 'ledger MAC key must be non-empty';
            END IF;
            SELECT * INTO current_key
            FROM longspan_mac_material
            WHERE material_id = 'ledger'
            FOR UPDATE;
            IF FOUND THEN
                IF current_key.mac_key IS DISTINCT FROM p_mac_key THEN
                    RAISE EXCEPTION
                        'ledger MAC key rotation requires the signed 2FA authority-rotation path';
                END IF;
                next_version := current_key.key_version;
            ELSE
                next_version := 1;
            END IF;
            INSERT INTO longspan_mac_material (material_id, mac_key, key_version)
            VALUES ('ledger', p_mac_key, next_version)
            ON CONFLICT (material_id) DO NOTHING;
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            FOR legacy_row IN
                SELECT child_id,
                       COUNT(*)::INTEGER AS legacy_row_count,
                       MAX(sequence_number)::INTEGER AS legacy_last_sequence,
                       (ARRAY_AGG(entry_hash ORDER BY sequence_number DESC))[1] AS legacy_head_hash,
                       encode(
                           digest(
                               convert_to(
                                   STRING_AGG(base_digest, ':' ORDER BY sequence_number),
                                   'UTF8'
                               ),
                               'sha256'
                           ),
                           'hex'
                       ) AS legacy_chain_digest
                FROM longspan_evidence_ledger
                WHERE legacy_unkeyed IS TRUE
                GROUP BY child_id
            LOOP
                legacy_payload := jsonb_build_object(
                    'attestation_revision', '007_longspan_authority_hardening',
                    'attested_by', 'top_delivery_authority',
                    'legacy_origin', 'pre_007_unkeyed',
                    'child_id', legacy_row.child_id,
                    'legacy_row_count', legacy_row.legacy_row_count,
                    'legacy_last_sequence', legacy_row.legacy_last_sequence,
                    'legacy_head_hash', legacy_row.legacy_head_hash,
                    'legacy_chain_digest', legacy_row.legacy_chain_digest
                )::TEXT;
                legacy_attestation := encode(
                    hmac(
                        convert_to(legacy_payload, 'UTF8'),
                        convert_to(p_mac_key, 'UTF8'),
                        'sha256'
                    ),
                    'hex'
                );
                INSERT INTO longspan_ledger_legacy_attestations
                    (child_id, legacy_row_count, legacy_last_sequence,
                     legacy_head_hash, legacy_chain_digest, attestation_digest,
                     mac_key_version, attestation_revision, attested_by, legacy_origin)
                VALUES (
                    legacy_row.child_id, legacy_row.legacy_row_count,
                    legacy_row.legacy_last_sequence, legacy_row.legacy_head_hash,
                    legacy_row.legacy_chain_digest, legacy_attestation, next_version,
                    '007_longspan_authority_hardening', 'top_delivery_authority',
                    'pre_007_unkeyed'
                )
                ON CONFLICT (child_id) DO UPDATE
                SET legacy_row_count = EXCLUDED.legacy_row_count,
                    legacy_last_sequence = EXCLUDED.legacy_last_sequence,
                    legacy_head_hash = EXCLUDED.legacy_head_hash,
                    legacy_chain_digest = EXCLUDED.legacy_chain_digest,
                    attestation_digest = EXCLUDED.attestation_digest,
                    mac_key_version = EXCLUDED.mac_key_version,
                    attestation_revision = EXCLUDED.attestation_revision,
                    attested_by = EXCLUDED.attested_by,
                    legacy_origin = EXCLUDED.legacy_origin,
                    created_at = clock_timestamp();
            END LOOP;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_install_terra_gateway_mac_key(p_mac_key TEXT)
        RETURNS VOID AS $terra_gateway_key_install$
        DECLARE
            current_key longspan_mac_material%ROWTYPE;
            next_version INTEGER;
        BEGIN
            IF session_user <> '{AUTHORITY_ROLE}' THEN
                RAISE EXCEPTION 'Terra gateway MAC material may only be installed by the authority service';
            END IF;
            IF btrim(p_mac_key) = '' THEN
                RAISE EXCEPTION 'Terra gateway MAC key must be non-empty';
            END IF;
            SELECT * INTO current_key
            FROM longspan_mac_material
            WHERE material_id = 'terra_gateway'
            FOR UPDATE;
            IF FOUND THEN
                IF current_key.mac_key IS DISTINCT FROM p_mac_key THEN
                    RAISE EXCEPTION
                        'Terra gateway MAC key rotation requires the signed 2FA authority-rotation path';
                END IF;
                next_version := current_key.key_version;
            ELSE
                next_version := 1;
            END IF;
            INSERT INTO longspan_mac_material (material_id, mac_key, key_version)
            VALUES ('terra_gateway', p_mac_key, next_version)
            ON CONFLICT (material_id) DO NOTHING;
            PERFORM set_config('top_delivery.authority_routine', '1', true);
        END;
        $terra_gateway_key_install$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_assert_child_capability(
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_producer_role TEXT,
            p_capability_token TEXT
        ) RETURNS VOID AS $$
        DECLARE
            child_row longspan_children%ROWTYPE;
            stored_hash TEXT;
            expected_controller_epoch INTEGER;
            authority_hash TEXT;
            scope_payload JSONB;
        BEGIN
            SELECT * INTO child_row
            FROM longspan_children
            WHERE child_id = p_child_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'capability child not found';
            END IF;
            IF child_row.attempt_number <> p_attempt_number THEN
                RAISE EXCEPTION 'capability attempt mismatch';
            END IF;
            IF p_producer_role <> 'parent'
               AND (child_row.lease_expires_at IS NULL
                    OR child_row.lease_expires_at <= clock_timestamp()) THEN
                RAISE EXCEPTION 'capability lease is expired';
            END IF;
            IF p_producer_role = 'manager' THEN
                stored_hash := child_row.manager_capability_hash;
                IF child_row.state <> 'planned' THEN
                    RAISE EXCEPTION 'manager evidence is outside the planned state';
                END IF;
            ELSIF p_producer_role = 'executor' THEN
                stored_hash := child_row.executor_capability_hash;
                IF child_row.state NOT IN ('executing', 'executed') THEN
                    RAISE EXCEPTION 'executor evidence is outside the execution state';
                END IF;
            ELSIF p_producer_role = 'auditor' THEN
                stored_hash := child_row.auditor_capability_hash;
                IF child_row.state NOT IN ('executed', 'terra_pending', 'needs_remediation') THEN
                    RAISE EXCEPTION 'auditor evidence is outside the executed state';
                END IF;
            ELSIF p_producer_role = 'terra' THEN
                SELECT terra_auth_hash INTO authority_hash
                FROM longspan_authority_config
                WHERE run_id = child_row.run_id;
                stored_hash := authority_hash;
                IF child_row.state NOT IN ('terra_pending', 'terra_approved', 'terra_rejected') THEN
                    RAISE EXCEPTION 'terra evidence is outside the Terra review state';
                END IF;
            ELSIF p_producer_role = 'parent' THEN
                IF p_capability_token IS NULL OR btrim(p_capability_token) = '' THEN
                    scope_payload := NULLIF(
                        current_setting('top_delivery.mutation_scope_payload', true), ''
                    )::JSONB;
                END IF;
                IF (p_capability_token IS NULL OR btrim(p_capability_token) = '')
                   AND scope_payload->>'scope_kind' = 'controller'
                   AND scope_payload->>'operation' IN (
                       'park_children', 'expire_stale_children'
                   ) THEN
                    -- Controller maintenance routines append their own
                    -- lease-expired/authorization-failure evidence.  A
                    -- parent capability is intentionally unavailable after
                    -- the child lease has expired, so require the signed
                    -- database-owned maintenance scope instead.
                    PERFORM longspan_assert_controller_maintenance_scope(
                        child_row.run_id,
                        scope_payload->>'operation'
                    );
                    RETURN;
                END IF;
                expected_controller_epoch := NULLIF(
                    current_setting('top_delivery.controller_epoch', true), ''
                )::INTEGER;
                IF expected_controller_epoch IS NULL OR NOT EXISTS (
                    SELECT 1
                    FROM parent_tasks AS parent
                    JOIN task_attempts AS attempt
                      ON attempt.attempt_id = parent.active_attempt_id
                     AND attempt.task_id = parent.task_id
                     AND attempt.run_id = parent.run_id
                    WHERE parent.task_id = child_row.task_id
                      AND parent.run_id = child_row.run_id
                      AND parent.active_attempt_id = child_row.parent_attempt_id
                      AND attempt.fence_token = child_row.fence_token
                      AND attempt.controller_epoch = expected_controller_epoch
                      AND attempt.status = 'running'
                      AND attempt.lease_expires_at > clock_timestamp()
                ) THEN
                    RAISE EXCEPTION 'parent capability is not bound to a live fenced attempt';
                END IF;
                RETURN;
            ELSE
                RAISE EXCEPTION 'unknown capability producer role %', p_producer_role;
            END IF;
            IF p_capability_token IS NULL OR btrim(p_capability_token) = ''
               OR stored_hash IS NULL
               OR encode(digest(convert_to(p_capability_token, 'UTF8'), 'sha256'), 'hex')
                    IS DISTINCT FROM stored_hash THEN
                RAISE EXCEPTION '% capability token is not bound to this child attempt', p_producer_role;
            END IF;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_assert_controller_maintenance_scope(
            p_run_id TEXT,
            p_operation TEXT
        ) RETURNS VOID AS $$
        DECLARE
            scope_payload JSONB;
            scope_signature TEXT;
            mac_key TEXT;
            expected_signature TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'controller maintenance scope requires the workflow principal';
            END IF;
            IF p_operation NOT IN ('park_children', 'expire_stale_children') THEN
                RAISE EXCEPTION 'unsupported controller maintenance operation';
            END IF;
            scope_payload := NULLIF(
                current_setting('top_delivery.mutation_scope_payload', true), ''
            )::JSONB;
            scope_signature := NULLIF(
                current_setting('top_delivery.mutation_scope_signature', true), ''
            );
            IF scope_payload IS NULL OR scope_signature IS NULL
               OR scope_payload->>'scope_kind' IS DISTINCT FROM 'controller'
               OR scope_payload->>'operation' IS DISTINCT FROM p_operation
               OR scope_payload->>'run_id' IS DISTINCT FROM p_run_id THEN
                RAISE EXCEPTION 'controller maintenance scope is absent or mismatched';
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
                RAISE EXCEPTION 'controller maintenance scope signature is invalid';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM controller_control
                WHERE run_id = p_run_id
                  AND current_epoch = (scope_payload->>'controller_epoch')::INTEGER
                  AND owner = scope_payload->>'owner'
                  AND controller_fence_token =
                      (scope_payload->>'controller_fence_token')::BIGINT
                  AND scheduling_enabled
                  AND lease_expires_at > clock_timestamp()
            ) THEN
                RAISE EXCEPTION 'controller maintenance scope fence is stale';
            END IF;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_authority_content_digest(
            p_operation TEXT,
            p_run_id TEXT,
            p_terra_auth_hash TEXT,
            p_operator_auth_hash TEXT,
            p_reviewed_sha TEXT,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_expected_config_version INTEGER,
            p_config_version INTEGER,
            p_approval_receipt_digest TEXT
        ) RETURNS TEXT AS $$
        DECLARE
            canonical_payload TEXT;
        BEGIN
            IF p_operation LIKE '%' || chr(31) || '%'
               OR p_run_id LIKE '%' || chr(31) || '%'
               OR p_terra_auth_hash LIKE '%' || chr(31) || '%'
               OR p_operator_auth_hash LIKE '%' || chr(31) || '%'
               OR p_reviewed_sha LIKE '%' || chr(31) || '%'
               OR p_tree_sha LIKE '%' || chr(31) || '%'
               OR p_source_digest LIKE '%' || chr(31) || '%'
               OR p_approval_receipt_digest LIKE '%' || chr(31) || '%' THEN
                RAISE EXCEPTION 'authority content contains the reserved digest delimiter';
            END IF;
            canonical_payload := concat_ws(
                chr(31), p_operation, p_run_id, p_terra_auth_hash,
                p_operator_auth_hash, p_reviewed_sha, p_tree_sha,
                p_source_digest, p_expected_config_version::TEXT,
                p_config_version::TEXT, p_approval_receipt_digest
            );
            RETURN encode(
                digest(convert_to(canonical_payload, 'UTF8'), 'sha256'),
                'hex'
            );
        END
        $$ LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER
           SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_assert_authority_write(
            p_run_id TEXT,
            p_approval_id TEXT,
            p_action_digest TEXT,
            p_write_binding_digest TEXT,
            p_config_version INTEGER
        ) RETURNS VOID AS $$
        DECLARE
            challenge_row longspan_operator_challenges%ROWTYPE;
        BEGIN
            IF session_user <> '{AUTHORITY_ROLE}' THEN
                RAISE EXCEPTION 'authority writes require the authority service principal';
            END IF;
            SELECT * INTO challenge_row
            FROM longspan_operator_challenges
            WHERE approval_id = p_approval_id
              AND run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'authority write requires a known operator challenge';
            END IF;
            IF challenge_row.consumed_at IS NULL THEN
                RAISE EXCEPTION 'authority write requires a consumed operator challenge';
            END IF;
            IF challenge_row.expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'authority write challenge has expired';
            END IF;
            IF challenge_row.action_digest IS DISTINCT FROM p_action_digest
               OR challenge_row.write_binding_digest IS DISTINCT FROM p_write_binding_digest
               OR challenge_row.config_version IS DISTINCT FROM p_config_version
               OR challenge_row.write_credential_digest IS NULL
               OR btrim(challenge_row.write_credential_digest) = '' THEN
                RAISE EXCEPTION 'authority write is not bound to the consumed operator challenge';
            END IF;
            IF challenge_row.write_applied_at IS NOT NULL
               AND challenge_row.write_applied_txid IS DISTINCT FROM txid_current() THEN
                RAISE EXCEPTION 'authority write challenge has already been applied';
            END IF;
            UPDATE longspan_operator_challenges
            SET write_applied_at = COALESCE(write_applied_at, clock_timestamp()),
                write_applied_txid = txid_current()
            WHERE approval_id = p_approval_id
              AND run_id = p_run_id
              AND (write_applied_at IS NULL OR write_applied_txid = txid_current());
            IF NOT FOUND THEN
                RAISE EXCEPTION 'authority write challenge could not be consumed';
            END IF;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_append_evidence_ledger(
            p_entry_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_event_type TEXT,
            p_producer_role TEXT,
            p_payload_digest TEXT,
            p_run_id TEXT,
            p_entry_hash TEXT,
            p_previous_entry_hash TEXT,
            p_sequence_number INTEGER,
            p_base_digest TEXT,
            p_capability_token TEXT
        ) RETURNS TEXT AS $$
        DECLARE
            child_row longspan_children%ROWTYPE;
            authority_exists BOOLEAN;
            mac_present BOOLEAN;
            expected_prev TEXT;
            expected_seq INTEGER;
            expected_entry_hash TEXT;
            computed_base_digest TEXT;
            canonical_base TEXT;
            ledger_mac_key TEXT;
            current_key_version INTEGER;
        BEGIN
            SELECT * INTO child_row FROM longspan_children WHERE child_id = p_child_id FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'ledger child not found';
            END IF;
            IF child_row.run_id <> p_run_id THEN
                RAISE EXCEPTION 'ledger append run scope mismatch';
            END IF;
            IF child_row.attempt_number IS DISTINCT FROM p_attempt_number THEN
                RAISE EXCEPTION 'ledger append attempt does not match child attempt';
            END IF;
            PERFORM longspan_assert_child_capability(
                p_child_id, p_attempt_number, p_producer_role, p_capability_token
            );
            SELECT COALESCE(MAX(sequence_number), 0) + 1 INTO expected_seq
            FROM longspan_evidence_ledger WHERE child_id = p_child_id;
            SELECT EXISTS(
                SELECT 1 FROM longspan_authority_config WHERE run_id = p_run_id
            ) INTO authority_exists;
            SELECT EXISTS(SELECT 1 FROM longspan_mac_material WHERE material_id = 'ledger')
                INTO mac_present;
            IF NOT authority_exists THEN
                RAISE EXCEPTION 'ledger append requires authority configuration before the first evidence entry';
            END IF;
            IF NOT mac_present THEN
                RAISE EXCEPTION 'ledger MAC material is required before evidence append';
            END IF;
            IF p_sequence_number <> expected_seq THEN
                RAISE EXCEPTION 'ledger sequence mismatch';
            END IF;
            IF expected_seq > 1 THEN
                SELECT entry_hash INTO expected_prev
                FROM longspan_evidence_ledger
                WHERE child_id = p_child_id AND sequence_number = expected_seq - 1;
                IF expected_prev IS DISTINCT FROM p_previous_entry_hash THEN
                    RAISE EXCEPTION 'ledger predecessor hash mismatch';
                END IF;
            ELSIF p_previous_entry_hash IS NOT NULL THEN
                RAISE EXCEPTION 'ledger first entry must not carry predecessor';
            END IF;
            IF btrim(p_payload_digest) = '' OR btrim(p_base_digest) = '' THEN
                RAISE EXCEPTION 'ledger base digest and payload digest are required';
            END IF;
            canonical_base := format(
                '{{"attempt_number":%s,"child_id":%s,"event_type":%s,"payload_digest":%s,"previous_entry_hash":%s,"producer_role":%s}}',
                p_attempt_number,
                to_json(p_child_id)::TEXT,
                to_json(p_event_type)::TEXT,
                to_json(p_payload_digest)::TEXT,
                COALESCE(to_json(p_previous_entry_hash)::TEXT, 'null'),
                to_json(p_producer_role)::TEXT
            );
            computed_base_digest := encode(
                digest(convert_to(canonical_base, 'UTF8'), 'sha256'),
                'hex'
            );
            IF p_base_digest IS DISTINCT FROM computed_base_digest THEN
                RAISE EXCEPTION 'ledger base digest is not bound to canonical persisted content';
            END IF;
            SELECT mac_key, key_version INTO ledger_mac_key, current_key_version
            FROM longspan_mac_material
            WHERE material_id = 'ledger';
            expected_entry_hash := encode(
                hmac(
                    convert_to(
                        'top_delivery:ledger_entry:v1:' || computed_base_digest,
                        'UTF8'
                    ),
                    convert_to(ledger_mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
            IF p_entry_hash IS NOT NULL
               AND p_entry_hash IS DISTINCT FROM expected_entry_hash THEN
                RAISE EXCEPTION 'ledger entry hash is not bound to authority MAC material';
            END IF;
            INSERT INTO longspan_evidence_ledger
                (entry_id, child_id, attempt_number, sequence_number, event_type,
                 producer_role, payload_digest, previous_entry_hash, entry_hash,
                 base_digest, mac_key_version, legacy_unkeyed)
            VALUES (
                p_entry_id, p_child_id, p_attempt_number, p_sequence_number, p_event_type,
                p_producer_role, p_payload_digest, p_previous_entry_hash, expected_entry_hash,
                computed_base_digest, current_key_version, FALSE
            );
            RETURN p_entry_id;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_verify_ledger_entry(
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_event_type TEXT,
            p_producer_role TEXT,
            p_payload_digest TEXT,
            p_previous_entry_hash TEXT,
            p_base_digest TEXT,
            p_entry_hash TEXT,
            p_run_id TEXT
        ) RETURNS BOOLEAN AS $$
        DECLARE
            child_run_id TEXT;
            mac_key TEXT;
            stored_base_digest TEXT;
            computed_base_digest TEXT;
            canonical_base TEXT;
            stored_key_version INTEGER;
            stored_legacy_unkeyed BOOLEAN;
            stored_sequence_number INTEGER;
            legacy_row_count INTEGER;
            legacy_last_sequence INTEGER;
            legacy_head_hash TEXT;
            legacy_chain_digest TEXT;
            legacy_attestation_digest TEXT;
            legacy_attestation_key_version INTEGER;
            legacy_attestation_revision TEXT;
            legacy_attested_by TEXT;
            legacy_origin TEXT;
            legacy_key TEXT;
            legacy_payload TEXT;
            expected_legacy_attestation TEXT;
            expected_hash TEXT;
        BEGIN
            SELECT run_id INTO child_run_id
            FROM longspan_children
            WHERE child_id = p_child_id;
            IF child_run_id IS NULL OR child_run_id <> p_run_id THEN
                RAISE EXCEPTION 'ledger verification run scope mismatch';
            END IF;
            SELECT ledger.base_digest, ledger.mac_key_version, ledger.legacy_unkeyed,
                   ledger.sequence_number
              INTO stored_base_digest, stored_key_version, stored_legacy_unkeyed,
                   stored_sequence_number
            FROM longspan_evidence_ledger AS ledger
            WHERE ledger.child_id = p_child_id
              AND ledger.attempt_number = p_attempt_number
              AND ledger.event_type = p_event_type
              AND ledger.producer_role = p_producer_role
              AND ledger.payload_digest = p_payload_digest
              AND ledger.previous_entry_hash IS NOT DISTINCT FROM p_previous_entry_hash
              AND ledger.entry_hash = p_entry_hash
            ORDER BY ledger.sequence_number DESC
            LIMIT 1;
            IF stored_base_digest IS NULL THEN
                RETURN FALSE;
            END IF;
            canonical_base := format(
                '{{"attempt_number":%s,"child_id":%s,"event_type":%s,"payload_digest":%s,"previous_entry_hash":%s,"producer_role":%s}}',
                p_attempt_number,
                to_json(p_child_id)::TEXT,
                to_json(p_event_type)::TEXT,
                to_json(p_payload_digest)::TEXT,
                COALESCE(to_json(p_previous_entry_hash)::TEXT, 'null'),
                to_json(p_producer_role)::TEXT
            );
            computed_base_digest := encode(
                digest(convert_to(canonical_base, 'UTF8'), 'sha256'),
                'hex'
            );
            IF p_base_digest IS DISTINCT FROM computed_base_digest
               OR stored_base_digest IS DISTINCT FROM computed_base_digest THEN
                RETURN FALSE;
            END IF;
            IF stored_key_version IS NULL THEN
                IF stored_legacy_unkeyed IS DISTINCT FROM TRUE THEN
                    RETURN FALSE;
                END IF;
                SELECT legacy.legacy_row_count,
                       legacy.legacy_last_sequence,
                       legacy.legacy_head_hash,
                       legacy.legacy_chain_digest,
                       legacy.attestation_digest,
                       legacy.mac_key_version,
                       legacy.attestation_revision,
                       legacy.attested_by,
                       legacy.legacy_origin
                  INTO legacy_row_count, legacy_last_sequence, legacy_head_hash,
                       legacy_chain_digest, legacy_attestation_digest,
                       legacy_attestation_key_version, legacy_attestation_revision,
                       legacy_attested_by, legacy_origin
                FROM longspan_ledger_legacy_attestations AS legacy
                WHERE legacy.child_id = p_child_id;
                IF legacy_row_count IS NULL
                   OR legacy_row_count <= 0
                   OR legacy_last_sequence IS NULL
                   OR stored_sequence_number > legacy_last_sequence THEN
                    RETURN FALSE;
                END IF;
                SELECT COUNT(*)::INTEGER,
                       MAX(sequence_number)::INTEGER,
                       (ARRAY_AGG(entry_hash ORDER BY sequence_number DESC))[1],
                       encode(
                           digest(
                               convert_to(
                                   STRING_AGG(base_digest, ':' ORDER BY sequence_number),
                                   'UTF8'
                               ),
                               'sha256'
                           ),
                           'hex'
                       )
                  INTO legacy_row_count, legacy_last_sequence, legacy_head_hash,
                       legacy_chain_digest
                FROM longspan_evidence_ledger
                WHERE child_id = p_child_id AND legacy_unkeyed IS TRUE;
                IF legacy_row_count IS NULL
                   OR legacy_row_count <= 0
                   OR legacy_row_count IS DISTINCT FROM (
                       SELECT att.legacy_row_count
                       FROM longspan_ledger_legacy_attestations AS att
                       WHERE att.child_id = p_child_id)
                   OR legacy_last_sequence IS DISTINCT FROM (
                       SELECT att.legacy_last_sequence
                       FROM longspan_ledger_legacy_attestations AS att
                       WHERE att.child_id = p_child_id)
                   OR legacy_head_hash IS DISTINCT FROM (
                       SELECT att.legacy_head_hash
                       FROM longspan_ledger_legacy_attestations AS att
                       WHERE att.child_id = p_child_id)
                   OR legacy_chain_digest IS DISTINCT FROM (
                       SELECT att.legacy_chain_digest
                       FROM longspan_ledger_legacy_attestations AS att
                       WHERE att.child_id = p_child_id)
                   OR legacy_attestation_revision IS DISTINCT FROM '007_longspan_authority_hardening'
                   OR legacy_attested_by IS DISTINCT FROM 'top_delivery_authority'
                   OR legacy_origin IS DISTINCT FROM 'pre_007_unkeyed' THEN
                    RETURN FALSE;
                END IF;
                legacy_payload := jsonb_build_object(
                    'attestation_revision', legacy_attestation_revision,
                    'attested_by', legacy_attested_by,
                    'legacy_origin', legacy_origin,
                    'child_id', p_child_id,
                    'legacy_row_count', legacy_row_count,
                    'legacy_last_sequence', legacy_last_sequence,
                    'legacy_head_hash', legacy_head_hash,
                    'legacy_chain_digest', legacy_chain_digest
                )::TEXT;
                SELECT key.mac_key INTO legacy_key
                FROM (
                    SELECT history.mac_key
                    FROM longspan_mac_key_history AS history
                    WHERE history.material_id = 'ledger'
                      AND history.key_version = legacy_attestation_key_version
                    UNION ALL
                    SELECT material.mac_key
                    FROM longspan_mac_material AS material
                    WHERE material.material_id = 'ledger'
                      AND material.key_version = legacy_attestation_key_version
                ) AS key
                LIMIT 1;
                IF legacy_key IS NULL THEN
                    RETURN FALSE;
                END IF;
                expected_legacy_attestation := encode(
                    hmac(
                        convert_to(legacy_payload, 'UTF8'),
                        convert_to(legacy_key, 'UTF8'),
                        'sha256'
                    ),
                    'hex'
                );
                RETURN p_entry_hash = computed_base_digest
                   AND legacy_attestation_digest = expected_legacy_attestation;
            END IF;
            SELECT key.mac_key INTO mac_key
            FROM (
                SELECT history.mac_key
                FROM longspan_mac_key_history AS history
                WHERE history.material_id = 'ledger'
                  AND history.key_version = stored_key_version
                UNION ALL
                SELECT material.mac_key
                FROM longspan_mac_material AS material
                WHERE material.material_id = 'ledger'
                  AND material.key_version = stored_key_version
            ) AS key
            LIMIT 1;
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'ledger verification MAC material version is unavailable';
            END IF;
            expected_hash := encode(
                hmac(
                    convert_to(
                        'top_delivery:ledger_entry:v1:' || computed_base_digest,
                        'UTF8'
                    ),
                    convert_to(mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
            RETURN p_entry_hash = expected_hash;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_store_execution_evidence(
            p_evidence_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_evidence_json TEXT,
            p_evidence_digest TEXT,
            p_executor_capability_token TEXT
        ) RETURNS VOID AS $$
        DECLARE
            child_row longspan_children%ROWTYPE;
            computed_digest TEXT;
        BEGIN
            -- The workflow transaction may already hold the child fence while
            -- it requests this out-of-band witness.  Read the committed facts
            -- here and let the workflow append path revalidate under its
            -- exclusive child lock; taking a second lock would deadlock the
            -- authority socket round trip.
            SELECT * INTO child_row
            FROM longspan_children
            WHERE child_id = p_child_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'execution evidence child not found';
            END IF;
            IF child_row.attempt_number IS DISTINCT FROM p_attempt_number THEN
                RAISE EXCEPTION 'execution evidence attempt does not match child';
            END IF;
            IF child_row.state <> 'executing' THEN
                RAISE EXCEPTION 'execution evidence requires an executing child';
            END IF;
            PERFORM longspan_assert_child_capability(
                p_child_id, p_attempt_number, 'executor', p_executor_capability_token
            );
            IF btrim(p_evidence_json) = '' OR btrim(p_evidence_digest) = '' THEN
                RAISE EXCEPTION 'execution evidence bytes and digest are required';
            END IF;
            computed_digest := encode(
                digest(convert_to(p_evidence_json, 'UTF8'), 'sha256'),
                'hex'
            );
            IF computed_digest IS DISTINCT FROM p_evidence_digest THEN
                RAISE EXCEPTION 'execution evidence digest does not match persisted bytes';
            END IF;
            INSERT INTO longspan_execution_evidence
                (evidence_id, child_id, attempt_number, evidence_json, evidence_digest)
            VALUES
                (p_evidence_id, p_child_id, p_attempt_number, p_evidence_json, p_evidence_digest);
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        DROP FUNCTION IF EXISTS longspan_append_execution_audit(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT
        );
        CREATE OR REPLACE FUNCTION longspan_append_execution_audit(
            p_audit_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_request_digest TEXT,
            p_evidence_digest TEXT,
            p_result_digest TEXT,
            p_validation_outcome TEXT,
            p_raw_result_ref TEXT,
            p_executor_capability_token TEXT
        ) RETURNS VOID AS $$
        DECLARE
            child_row longspan_children%ROWTYPE;
            stored_result_digest TEXT;
            stored_evidence_digest TEXT;
        BEGIN
            SELECT * INTO child_row FROM longspan_children WHERE child_id = p_child_id FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'execution audit child not found';
            END IF;
            IF child_row.attempt_number IS DISTINCT FROM p_attempt_number THEN
                RAISE EXCEPTION 'execution audit attempt does not match child attempt';
            END IF;
            PERFORM longspan_assert_child_capability(
                p_child_id, p_attempt_number, 'executor', p_executor_capability_token
            );
            IF btrim(p_request_digest) = ''
               OR btrim(p_evidence_digest) = ''
               OR btrim(p_result_digest) = '' THEN
                RAISE EXCEPTION 'execution audit digests are required';
            END IF;
            IF p_request_digest IS DISTINCT FROM child_row.request_digest THEN
                RAISE EXCEPTION
                    'execution audit request digest is not bound to the persisted child request';
            END IF;
            SELECT result_digest INTO stored_result_digest
            FROM longspan_execution_results
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number;
            IF stored_result_digest IS NULL OR stored_result_digest IS DISTINCT FROM p_result_digest THEN
                RAISE EXCEPTION
                    'execution audit result digest is not bound to the persisted execution result';
            END IF;
            SELECT evidence_digest INTO stored_evidence_digest
            FROM longspan_execution_evidence
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number;
            IF stored_evidence_digest IS NULL
               OR stored_evidence_digest IS DISTINCT FROM p_evidence_digest THEN
                RAISE EXCEPTION
                    'execution audit evidence digest is not bound to persisted evidence bytes';
            END IF;
            IF EXISTS (
                SELECT 1 FROM longspan_execution_audits
                WHERE child_id = p_child_id AND attempt_number = p_attempt_number
            ) THEN
                RAISE EXCEPTION 'execution audit already recorded';
            END IF;
            INSERT INTO longspan_execution_audits
                (audit_id, child_id, attempt_number, request_digest, evidence_digest, result_digest,
                 validation_outcome, raw_result_ref)
            VALUES (
                p_audit_id, p_child_id, p_attempt_number, p_request_digest, p_evidence_digest,
                p_result_digest,
                p_validation_outcome, p_raw_result_ref
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_insert_execution_result(
            p_result_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_outcome TEXT,
            p_result_digest TEXT,
            p_artifact_refs_json TEXT,
            p_executor_capability_token TEXT
        ) RETURNS VOID AS $$
        DECLARE
            child_row longspan_children%ROWTYPE;
        BEGIN
            SELECT * INTO child_row
            FROM longspan_children
            WHERE child_id = p_child_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'execution result child not found';
            END IF;
            IF child_row.state <> 'executing' THEN
                RAISE EXCEPTION 'execution result requires an executing child';
            END IF;
            PERFORM longspan_assert_child_capability(
                p_child_id, p_attempt_number, 'executor', p_executor_capability_token
            );
            IF p_outcome NOT IN ('success', 'failure', 'retryable') THEN
                RAISE EXCEPTION 'execution result outcome invalid';
            END IF;
            IF btrim(p_result_digest) = '' THEN
                RAISE EXCEPTION 'execution result digest is required';
            END IF;
            INSERT INTO longspan_execution_results
                (result_id, child_id, attempt_number, outcome, result_digest, artifact_refs_json)
            VALUES (
                p_result_id, p_child_id, p_attempt_number, p_outcome,
                p_result_digest, p_artifact_refs_json
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        -- Replace the legacy 8-argument routine rather than leaving an
        -- overload that bypasses the immutable evidence digest.  A partially
        -- rehearsed 007 database may still carry the historical signature.
        DROP FUNCTION IF EXISTS longspan_append_auditor_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_append_auditor_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        );
        CREATE OR REPLACE FUNCTION longspan_append_auditor_receipt(
            p_receipt_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_verdict TEXT,
            p_reasons_json TEXT,
            p_inspector_digest TEXT,
            p_evidence_digest TEXT,
            p_receipt_digest TEXT,
            p_auditor_capability_token TEXT
        ) RETURNS VOID AS $$
        DECLARE
            child_row longspan_children%ROWTYPE;
        BEGIN
            SELECT * INTO child_row FROM longspan_children WHERE child_id = p_child_id FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'auditor receipt child not found';
            END IF;
            IF child_row.attempt_number <> p_attempt_number THEN
                RAISE EXCEPTION 'auditor receipt attempt mismatch';
            END IF;
            PERFORM longspan_assert_child_capability(
                p_child_id, p_attempt_number, 'auditor', p_auditor_capability_token
            );
            IF p_verdict NOT IN ('pass', 'fail') THEN
                RAISE EXCEPTION 'auditor receipt verdict invalid';
            END IF;
            IF btrim(p_inspector_digest) = ''
               OR btrim(p_evidence_digest) = ''
               OR btrim(p_receipt_digest) = '' THEN
                RAISE EXCEPTION 'auditor receipt digests are required';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM longspan_execution_audits
                WHERE child_id = p_child_id
                  AND attempt_number = p_attempt_number
                  AND evidence_digest = p_evidence_digest
            ) THEN
                RAISE EXCEPTION
                    'auditor receipt evidence digest is not bound to the execution audit';
            END IF;
            IF EXISTS (
                SELECT 1 FROM longspan_auditor_receipts
                WHERE child_id = p_child_id AND attempt_number = p_attempt_number
            ) THEN
                RAISE EXCEPTION 'auditor receipt already recorded';
            END IF;
            INSERT INTO longspan_auditor_receipts
                (receipt_id, child_id, attempt_number, verdict, reasons_json,
                 inspector_digest, evidence_digest, receipt_digest)
            VALUES (
                p_receipt_id, p_child_id, p_attempt_number, p_verdict, p_reasons_json,
                p_inspector_digest, p_evidence_digest, p_receipt_digest
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        -- The authority service calls this routine after independently
        -- verifying Terra's Ed25519 signature.  It re-derives the exact
        -- receipt digest from database facts and creates a one-shot witness
        -- that the workflow role can consume but can never mint.
        CREATE OR REPLACE FUNCTION longspan_issue_terra_receipt_attestation(
            p_attestation_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_reviewer TEXT,
            p_decision TEXT,
            p_evidence_chain_head TEXT,
            p_receipt_digest TEXT,
            p_run_id TEXT,
            p_task_id TEXT,
            p_reviewed_sha TEXT,
            p_fence_token BIGINT,
            p_controller_epoch INTEGER,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_request_digest TEXT,
            p_migration_head TEXT,
            p_authority_version INTEGER,
            p_evidence_digest TEXT,
            p_result_digest TEXT,
            p_external_signature TEXT
        ) RETURNS TEXT AS $terra_attestation_issue$
        DECLARE
            child_row longspan_children%ROWTYPE;
            authority_row longspan_authority_config%ROWTYPE;
            actual_head TEXT;
            stored_result_digest TEXT;
            stored_evidence_digest TEXT;
            canonical_receipt JSONB;
            computed_receipt_digest TEXT;
            signature_digest TEXT;
            existing_attestation longspan_terra_receipt_attestations%ROWTYPE;
        BEGIN
            IF session_user <> '{AUTHORITY_ROLE}' THEN
                RAISE EXCEPTION 'Terra receipt attestations may only be issued by the authority principal';
            END IF;
            IF p_attestation_id IS NULL OR btrim(p_attestation_id) = '' THEN
                RAISE EXCEPTION 'Terra receipt attestation id is required';
            END IF;
            IF p_migration_head IS DISTINCT FROM '007_longspan_authority_hardening' THEN
                RAISE EXCEPTION 'Terra receipt attestation migration head is not canonical';
            END IF;
            IF p_decision NOT IN ('approved', 'rejected') THEN
                RAISE EXCEPTION 'Terra receipt attestation decision is invalid';
            END IF;
            IF p_external_signature IS NULL
               OR split_part(p_external_signature, ':', 1) <> 'v1'
               OR btrim(split_part(p_external_signature, ':', 2)) = ''
               OR array_length(string_to_array(p_external_signature, ':'), 1) <> 2 THEN
                RAISE EXCEPTION 'Terra receipt attestation requires a verified external signature envelope';
            END IF;
            -- The workflow transaction may already hold the child fence while
            -- it requests this out-of-band witness.  Read committed facts here
            -- and let the workflow append path revalidate under its exclusive
            -- child lock; taking a second lock would deadlock the round trip.
            SELECT * INTO child_row
            FROM longspan_children
            WHERE child_id = p_child_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Terra receipt attestation child not found';
            END IF;
            IF child_row.run_id IS DISTINCT FROM p_run_id
               OR child_row.task_id IS DISTINCT FROM p_task_id
               OR child_row.attempt_number IS DISTINCT FROM p_attempt_number
               OR child_row.fence_token IS DISTINCT FROM p_fence_token
               OR child_row.request_digest IS DISTINCT FROM p_request_digest THEN
                RAISE EXCEPTION 'Terra receipt attestation child binding mismatch';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM parent_tasks AS parent
                JOIN task_attempts AS attempt
                  ON attempt.attempt_id = parent.active_attempt_id
                 AND attempt.task_id = parent.task_id
                 AND attempt.run_id = parent.run_id
                WHERE parent.task_id = child_row.task_id
                  AND parent.run_id = child_row.run_id
                  AND parent.active_attempt_id = child_row.parent_attempt_id
                  AND attempt.fence_token = child_row.fence_token
                  AND attempt.controller_epoch = p_controller_epoch
                  AND attempt.status = 'running'
                  AND attempt.lease_expires_at > clock_timestamp()
            ) THEN
                RAISE EXCEPTION 'Terra receipt attestation parent fence is stale';
            END IF;
            SELECT * INTO authority_row
            FROM longspan_authority_config
            WHERE run_id = p_run_id;
            IF NOT FOUND
               OR authority_row.reviewed_sha IS DISTINCT FROM p_reviewed_sha
               OR authority_row.tree_sha IS DISTINCT FROM p_tree_sha
               OR authority_row.source_digest IS DISTINCT FROM p_source_digest
               OR authority_row.config_version IS DISTINCT FROM p_authority_version THEN
                RAISE EXCEPTION 'Terra receipt attestation provenance mismatch';
            END IF;
            SELECT entry_hash INTO actual_head
            FROM longspan_evidence_ledger
            WHERE child_id = p_child_id
            ORDER BY sequence_number DESC
            LIMIT 1;
            IF actual_head IS NULL OR actual_head IS DISTINCT FROM p_evidence_chain_head THEN
                RAISE EXCEPTION 'Terra receipt attestation evidence head mismatch';
            END IF;
            SELECT result_digest INTO stored_result_digest
            FROM longspan_execution_results
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number;
            IF stored_result_digest IS NULL OR stored_result_digest IS DISTINCT FROM p_result_digest THEN
                RAISE EXCEPTION 'Terra receipt attestation result mismatch';
            END IF;
            SELECT evidence_digest INTO stored_evidence_digest
            FROM longspan_auditor_receipts
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number
              AND verdict = 'pass';
            IF stored_evidence_digest IS NULL OR stored_evidence_digest IS DISTINCT FROM p_evidence_digest THEN
                RAISE EXCEPTION 'Terra receipt attestation evidence mismatch';
            END IF;
            canonical_receipt := jsonb_build_object(
                'child_id', p_child_id,
                'attempt_number', p_attempt_number,
                'reviewer', p_reviewer,
                'decision', p_decision,
                'evidence_chain_head', p_evidence_chain_head,
                'run_id', p_run_id,
                'task_id', p_task_id,
                'reviewed_sha', p_reviewed_sha,
                'fence_token', p_fence_token,
                'controller_epoch', p_controller_epoch,
                'tree_sha', p_tree_sha,
                'source_digest', p_source_digest,
                'request_digest', child_row.request_digest,
                'migration_head', p_migration_head,
                'authority_version', p_authority_version,
                'evidence_digest', stored_evidence_digest,
                'result_digest', stored_result_digest
            );
            computed_receipt_digest := encode(
                digest(convert_to(canonical_receipt::TEXT, 'UTF8'), 'sha256'),
                'hex'
            );
            IF p_receipt_digest IS NOT NULL
               AND btrim(p_receipt_digest) <> ''
               AND p_receipt_digest IS DISTINCT FROM computed_receipt_digest THEN
                RAISE EXCEPTION 'Terra receipt attestation digest is not database-derived';
            END IF;
            signature_digest := encode(
                digest(convert_to(split_part(p_external_signature, ':', 2), 'UTF8'), 'sha256'),
                'hex'
            );
            -- Authority issuance is committed separately from workflow
            -- consumption.  If the workflow loses its connection after this
            -- commit, retry the identical binding instead of wedging the
            -- attempt behind the unique key.  A conflicting binding is still
            -- rejected rather than silently reusing a witness.
            SELECT * INTO existing_attestation
            FROM longspan_terra_receipt_attestations
            WHERE child_id = p_child_id
              AND attempt_number = p_attempt_number
              AND receipt_digest = computed_receipt_digest
              AND consumed_at IS NULL
            FOR UPDATE;
            IF FOUND THEN
                IF existing_attestation.signature_digest IS DISTINCT FROM signature_digest
                   OR existing_attestation.run_id IS DISTINCT FROM p_run_id
                   OR existing_attestation.task_id IS DISTINCT FROM p_task_id
                   OR existing_attestation.reviewer IS DISTINCT FROM p_reviewer
                   OR existing_attestation.decision IS DISTINCT FROM p_decision
                   OR existing_attestation.evidence_chain_head IS DISTINCT FROM p_evidence_chain_head
                   OR existing_attestation.reviewed_sha IS DISTINCT FROM p_reviewed_sha
                   OR existing_attestation.fence_token IS DISTINCT FROM p_fence_token
                   OR existing_attestation.controller_epoch IS DISTINCT FROM p_controller_epoch
                   OR existing_attestation.tree_sha IS DISTINCT FROM p_tree_sha
                   OR existing_attestation.source_digest IS DISTINCT FROM p_source_digest
                   OR existing_attestation.request_digest IS DISTINCT FROM p_request_digest
                   OR existing_attestation.migration_head IS DISTINCT FROM p_migration_head
                   OR existing_attestation.authority_version IS DISTINCT FROM p_authority_version
                   OR existing_attestation.evidence_digest IS DISTINCT FROM stored_evidence_digest
                   OR existing_attestation.result_digest IS DISTINCT FROM stored_result_digest THEN
                    RAISE EXCEPTION 'Terra receipt attestation binding conflicts with an existing witness';
                END IF;
                RETURN existing_attestation.attestation_id;
            END IF;
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            INSERT INTO longspan_terra_receipt_attestations (
                attestation_id, child_id, attempt_number, run_id, task_id,
                receipt_digest, signature_digest, reviewer, decision,
                evidence_chain_head, reviewed_sha, fence_token, controller_epoch,
                tree_sha, source_digest, request_digest, migration_head,
                authority_version, evidence_digest, result_digest
            ) VALUES (
                p_attestation_id, p_child_id, p_attempt_number, p_run_id, p_task_id,
                computed_receipt_digest, signature_digest, p_reviewer, p_decision,
                p_evidence_chain_head, p_reviewed_sha, p_fence_token, p_controller_epoch,
                p_tree_sha, p_source_digest, child_row.request_digest, p_migration_head,
                p_authority_version, stored_evidence_digest, stored_result_digest
            );
            RETURN p_attestation_id;
        END;
        $terra_attestation_issue$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_consume_terra_receipt_attestation(
            p_attestation_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_reviewer TEXT,
            p_decision TEXT,
            p_evidence_chain_head TEXT,
            p_receipt_digest TEXT,
            p_run_id TEXT,
            p_task_id TEXT,
            p_reviewed_sha TEXT,
            p_fence_token BIGINT,
            p_controller_epoch INTEGER,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_request_digest TEXT,
            p_migration_head TEXT,
            p_authority_version INTEGER,
            p_evidence_digest TEXT,
            p_result_digest TEXT,
            p_external_signature TEXT
        ) RETURNS VOID AS $terra_attestation_consume$
        DECLARE
            row_attestation longspan_terra_receipt_attestations%ROWTYPE;
            child_row longspan_children%ROWTYPE;
            actual_head TEXT;
            stored_result_digest TEXT;
            stored_evidence_digest TEXT;
            signature_digest TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'Terra receipt attestations may only be consumed by the workflow principal';
            END IF;
            SELECT * INTO row_attestation
            FROM longspan_terra_receipt_attestations
            WHERE attestation_id = p_attestation_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Terra receipt attestation is unknown';
            END IF;
            IF row_attestation.consumed_at IS NOT NULL THEN
                RAISE EXCEPTION 'Terra receipt attestation was already consumed';
            END IF;
            -- Issuance intentionally reads committed facts without taking the
            -- child lock because the workflow may hold that lock while making
            -- the authority socket round trip.  Consumption is the
            -- serialization point: lock the child now and revalidate every
            -- mutable binding before consuming the one-shot witness.
            SELECT * INTO child_row
            FROM longspan_children
            WHERE child_id = p_child_id
            FOR UPDATE;
            IF NOT FOUND
               OR child_row.run_id IS DISTINCT FROM p_run_id
               OR child_row.task_id IS DISTINCT FROM p_task_id
               OR child_row.attempt_number IS DISTINCT FROM p_attempt_number
               OR child_row.fence_token IS DISTINCT FROM p_fence_token
               OR child_row.request_digest IS DISTINCT FROM p_request_digest
               OR child_row.state IS DISTINCT FROM 'terra_pending' THEN
                RAISE EXCEPTION 'Terra receipt attestation child state or binding changed';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM parent_tasks AS parent
                JOIN task_attempts AS attempt
                  ON attempt.attempt_id = parent.active_attempt_id
                 AND attempt.task_id = parent.task_id
                 AND attempt.run_id = parent.run_id
                WHERE parent.task_id = child_row.task_id
                  AND parent.run_id = child_row.run_id
                  AND parent.active_attempt_id = child_row.parent_attempt_id
                  AND attempt.fence_token = child_row.fence_token
                  AND attempt.controller_epoch = p_controller_epoch
                  AND attempt.status = 'running'
                  AND attempt.lease_expires_at > clock_timestamp()
            ) THEN
                RAISE EXCEPTION 'Terra receipt attestation parent fence changed';
            END IF;
            SELECT entry_hash INTO actual_head
            FROM longspan_evidence_ledger
            WHERE child_id = p_child_id
            ORDER BY sequence_number DESC
            LIMIT 1;
            IF actual_head IS DISTINCT FROM p_evidence_chain_head THEN
                RAISE EXCEPTION 'Terra receipt attestation evidence head changed';
            END IF;
            SELECT result_digest INTO stored_result_digest
            FROM longspan_execution_results
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number;
            SELECT evidence_digest INTO stored_evidence_digest
            FROM longspan_auditor_receipts
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number
              AND verdict = 'pass';
            IF stored_result_digest IS DISTINCT FROM p_result_digest
               OR stored_evidence_digest IS DISTINCT FROM p_evidence_digest THEN
                RAISE EXCEPTION 'Terra receipt attestation evidence or result changed';
            END IF;
            signature_digest := encode(
                digest(convert_to(split_part(p_external_signature, ':', 2), 'UTF8'), 'sha256'),
                'hex'
            );
            IF row_attestation.child_id IS DISTINCT FROM p_child_id
               OR row_attestation.attempt_number IS DISTINCT FROM p_attempt_number
               OR row_attestation.reviewer IS DISTINCT FROM p_reviewer
               OR row_attestation.decision IS DISTINCT FROM p_decision
               OR row_attestation.evidence_chain_head IS DISTINCT FROM p_evidence_chain_head
               OR row_attestation.receipt_digest IS DISTINCT FROM p_receipt_digest
               OR row_attestation.run_id IS DISTINCT FROM p_run_id
               OR row_attestation.task_id IS DISTINCT FROM p_task_id
               OR row_attestation.reviewed_sha IS DISTINCT FROM p_reviewed_sha
               OR row_attestation.fence_token IS DISTINCT FROM p_fence_token
               OR row_attestation.controller_epoch IS DISTINCT FROM p_controller_epoch
               OR row_attestation.tree_sha IS DISTINCT FROM p_tree_sha
               OR row_attestation.source_digest IS DISTINCT FROM p_source_digest
               OR row_attestation.request_digest IS DISTINCT FROM p_request_digest
               OR row_attestation.migration_head IS DISTINCT FROM p_migration_head
               OR row_attestation.authority_version IS DISTINCT FROM p_authority_version
               OR row_attestation.evidence_digest IS DISTINCT FROM p_evidence_digest
               OR row_attestation.result_digest IS DISTINCT FROM p_result_digest
               OR row_attestation.signature_digest IS DISTINCT FROM signature_digest THEN
                RAISE EXCEPTION 'Terra receipt attestation binding mismatch';
            END IF;
            PERFORM set_config('top_delivery.attestation_routine', '1', true);
            UPDATE longspan_terra_receipt_attestations
            SET consumed_at = clock_timestamp()
            WHERE attestation_id = p_attestation_id AND consumed_at IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Terra receipt attestation consumption lost the race';
            END IF;
        END;
        $terra_attestation_consume$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

        -- A partially rehearsed database may contain the historical VOID
        -- return signature.  PostgreSQL cannot replace a function when only
        -- its return type differs, so remove the exact old signature before
        -- creating the canonical TEXT-returning routine.
        DROP FUNCTION IF EXISTS longspan_append_terra_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        );

        -- The external Terra attestation is verified by the application, but
        -- the workflow principal must not be able to choose the database
        -- gateway proof.  PostgreSQL JSONB text canonicalization is the
        -- authority for this proof, so expose only a capability-bound MAC
        -- calculation that reloads and validates every persisted fact.
        DROP FUNCTION IF EXISTS longspan_terra_gateway_mac(
            TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER,
            TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_terra_gateway_mac_for_attestation(TEXT);
        CREATE OR REPLACE FUNCTION longspan_terra_gateway_mac(
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_reviewer TEXT,
            p_decision TEXT,
            p_evidence_chain_head TEXT,
            p_run_id TEXT,
            p_task_id TEXT,
            p_reviewed_sha TEXT,
            p_fence_token BIGINT,
            p_controller_epoch INTEGER,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_request_digest TEXT,
            p_migration_head TEXT,
            p_authority_version INTEGER,
            p_evidence_digest TEXT,
            p_result_digest TEXT,
            p_terra_auth_token TEXT
        ) RETURNS TEXT AS $$
        DECLARE
            child_row longspan_children%ROWTYPE;
            authority_row longspan_authority_config%ROWTYPE;
            expected_epoch INTEGER;
            actual_head TEXT;
            stored_result_digest TEXT;
            stored_evidence_digest TEXT;
            terra_gateway_mac_key TEXT;
            canonical_receipt JSONB;
            computed_receipt_digest TEXT;
        BEGIN
            -- This is deliberately a narrow read/proof operation.  A caller
            -- must possess the current Terra capability and the live parent
            -- fence, and every signed field must match persisted state.
            PERFORM longspan_assert_child_capability(
                p_child_id, p_attempt_number, 'terra', p_terra_auth_token
            );
            SELECT * INTO child_row
            FROM longspan_children
            WHERE child_id = p_child_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'terra gateway child not found';
            END IF;
            IF child_row.run_id IS DISTINCT FROM p_run_id
               OR child_row.task_id IS DISTINCT FROM p_task_id
               OR child_row.attempt_number IS DISTINCT FROM p_attempt_number
               OR child_row.fence_token IS DISTINCT FROM p_fence_token
               OR child_row.request_digest IS DISTINCT FROM p_request_digest THEN
                RAISE EXCEPTION 'terra gateway payload is not bound to the child attempt';
            END IF;
            expected_epoch := NULLIF(
                current_setting('top_delivery.controller_epoch', true), ''
            )::INTEGER;
            IF expected_epoch IS NULL OR expected_epoch IS DISTINCT FROM p_controller_epoch
               OR NOT EXISTS (
                   SELECT 1
                   FROM parent_tasks AS parent
                   JOIN task_attempts AS attempt
                     ON attempt.attempt_id = parent.active_attempt_id
                    AND attempt.task_id = parent.task_id
                    AND attempt.run_id = parent.run_id
                   WHERE parent.task_id = child_row.task_id
                     AND parent.run_id = child_row.run_id
                     AND parent.active_attempt_id = child_row.parent_attempt_id
                     AND attempt.fence_token = child_row.fence_token
                     AND attempt.controller_epoch = p_controller_epoch
                     AND attempt.status = 'running'
                     AND attempt.lease_expires_at > clock_timestamp()
               ) THEN
                RAISE EXCEPTION 'terra gateway proof is not bound to a live parent fence';
            END IF;
            IF p_decision NOT IN ('approved', 'rejected') THEN
                RAISE EXCEPTION 'terra gateway decision invalid';
            END IF;
            IF p_migration_head IS DISTINCT FROM '007_longspan_authority_hardening' THEN
                RAISE EXCEPTION 'terra gateway migration head is not canonical';
            END IF;
            SELECT * INTO authority_row
            FROM longspan_authority_config
            WHERE run_id = p_run_id;
            IF NOT FOUND
               OR authority_row.reviewed_sha IS DISTINCT FROM p_reviewed_sha
               OR authority_row.tree_sha IS DISTINCT FROM p_tree_sha
               OR authority_row.source_digest IS DISTINCT FROM p_source_digest
               OR authority_row.config_version IS DISTINCT FROM p_authority_version THEN
                RAISE EXCEPTION 'terra gateway provenance binding mismatch';
            END IF;
            SELECT entry_hash INTO actual_head
            FROM longspan_evidence_ledger
            WHERE child_id = p_child_id
            ORDER BY sequence_number DESC
            LIMIT 1;
            IF actual_head IS NULL OR actual_head IS DISTINCT FROM p_evidence_chain_head THEN
                RAISE EXCEPTION 'terra gateway evidence head mismatch';
            END IF;
            SELECT result_digest INTO stored_result_digest
            FROM longspan_execution_results
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number;
            IF stored_result_digest IS NULL OR stored_result_digest IS DISTINCT FROM p_result_digest THEN
                RAISE EXCEPTION 'terra gateway result digest mismatch';
            END IF;
            SELECT evidence_digest INTO stored_evidence_digest
            FROM longspan_auditor_receipts
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number
              AND verdict = 'pass';
            IF stored_evidence_digest IS NULL OR stored_evidence_digest IS DISTINCT FROM p_evidence_digest THEN
                RAISE EXCEPTION 'terra gateway evidence digest mismatch';
            END IF;
            SELECT mac_key INTO terra_gateway_mac_key
            FROM longspan_mac_material
            WHERE material_id = 'terra_gateway';
            IF terra_gateway_mac_key IS NULL THEN
                RAISE EXCEPTION 'terra gateway MAC material is unavailable';
            END IF;
            canonical_receipt := jsonb_build_object(
                'child_id', p_child_id,
                'attempt_number', p_attempt_number,
                'reviewer', p_reviewer,
                'decision', p_decision,
                'evidence_chain_head', p_evidence_chain_head,
                'run_id', p_run_id,
                'task_id', p_task_id,
                'reviewed_sha', p_reviewed_sha,
                'fence_token', p_fence_token,
                'controller_epoch', p_controller_epoch,
                'tree_sha', p_tree_sha,
                'source_digest', p_source_digest,
                'request_digest', child_row.request_digest,
                'migration_head', p_migration_head,
                'authority_version', p_authority_version,
                'evidence_digest', stored_evidence_digest,
                'result_digest', stored_result_digest
            );
            computed_receipt_digest := encode(
                digest(convert_to(canonical_receipt::TEXT, 'UTF8'), 'sha256'),
                'hex'
            );
            RETURN encode(
                hmac(
                    convert_to(
                        'top_delivery:terra_receipt:v1:' || computed_receipt_digest,
                        'UTF8'
                    ),
                    convert_to(terra_gateway_mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        -- The workflow must not compute the gateway proof.  The authority
        -- service obtains this value only after the one-shot attestation is
        -- issued, using the database-derived receipt digest and the
        -- authority-only gateway key.
        CREATE OR REPLACE FUNCTION longspan_terra_gateway_mac_for_attestation(
            p_attestation_id TEXT
        ) RETURNS TEXT AS $terra_attestation_gateway_mac$
        DECLARE
            attestation_row longspan_terra_receipt_attestations%ROWTYPE;
            terra_gateway_mac_key TEXT;
        BEGIN
            IF session_user <> '{AUTHORITY_ROLE}' THEN
                RAISE EXCEPTION
                    'Terra gateway proof retrieval requires the authority principal';
            END IF;
            SELECT * INTO attestation_row
            FROM longspan_terra_receipt_attestations
            WHERE attestation_id = p_attestation_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Terra receipt attestation is unknown';
            END IF;
            IF attestation_row.consumed_at IS NOT NULL THEN
                RAISE EXCEPTION 'Terra receipt attestation was already consumed';
            END IF;
            SELECT mac_key INTO terra_gateway_mac_key
            FROM longspan_mac_material
            WHERE material_id = 'terra_gateway';
            IF terra_gateway_mac_key IS NULL THEN
                RAISE EXCEPTION 'Terra gateway MAC material is unavailable';
            END IF;
            RETURN encode(
                hmac(
                    convert_to(
                        'top_delivery:terra_receipt:v1:' || attestation_row.receipt_digest,
                        'UTF8'
                    ),
                    convert_to(terra_gateway_mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
        END;
        $terra_attestation_gateway_mac$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_append_terra_receipt(
            p_receipt_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_reviewer TEXT,
            p_decision TEXT,
            p_evidence_chain_head TEXT,
            p_receipt_digest TEXT,
            p_run_id TEXT,
            p_task_id TEXT,
            p_reviewed_sha TEXT,
            p_fence_token BIGINT,
            p_controller_epoch INTEGER,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_request_digest TEXT,
            p_migration_head TEXT,
            p_authority_version INTEGER,
            p_evidence_digest TEXT,
            p_result_digest TEXT,
            p_signature TEXT,
            p_terra_auth_token TEXT
        ) RETURNS TEXT AS $$
        DECLARE
            child_row longspan_children%ROWTYPE;
            authority_row longspan_authority_config%ROWTYPE;
            actual_head TEXT;
            expected_epoch INTEGER;
            stored_request_digest TEXT;
            stored_result_digest TEXT;
            stored_evidence_digest TEXT;
            canonical_receipt JSONB;
            computed_receipt_digest TEXT;
            computed_receipt_signature TEXT;
            attestation_id TEXT;
        BEGIN
            SELECT * INTO child_row FROM longspan_children WHERE child_id = p_child_id FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'terra receipt child not found';
            END IF;
            IF child_row.run_id <> p_run_id OR child_row.task_id <> p_task_id THEN
                RAISE EXCEPTION 'terra receipt run/task scope mismatch';
            END IF;
            IF child_row.attempt_number <> p_attempt_number THEN
                RAISE EXCEPTION 'terra receipt attempt mismatch';
            END IF;
            IF child_row.fence_token IS DISTINCT FROM p_fence_token THEN
                RAISE EXCEPTION 'terra receipt fence mismatch';
            END IF;
            expected_epoch := NULLIF(
                current_setting('top_delivery.controller_epoch', true), ''
            )::INTEGER;
            IF expected_epoch IS NULL OR expected_epoch IS DISTINCT FROM p_controller_epoch
               OR NOT EXISTS (
                   SELECT 1
                   FROM parent_tasks AS parent
                   JOIN task_attempts AS attempt
                     ON attempt.attempt_id = parent.active_attempt_id
                    AND attempt.task_id = parent.task_id
                    AND attempt.run_id = parent.run_id
                   WHERE parent.task_id = child_row.task_id
                     AND parent.run_id = child_row.run_id
                     AND parent.active_attempt_id = child_row.parent_attempt_id
                     AND attempt.fence_token = child_row.fence_token
                     AND attempt.controller_epoch = p_controller_epoch
                     AND attempt.status = 'running'
                     AND attempt.lease_expires_at > clock_timestamp()
               ) THEN
                RAISE EXCEPTION 'terra receipt is not bound to a live parent fence';
            END IF;
            PERFORM longspan_assert_child_capability(
                p_child_id, p_attempt_number, 'terra', p_terra_auth_token
            );
            IF p_request_digest IS DISTINCT FROM child_row.request_digest THEN
                RAISE EXCEPTION
                    'terra receipt request digest is not bound to the persisted child request';
            END IF;
            IF p_decision NOT IN ('approved', 'rejected') THEN
                RAISE EXCEPTION 'terra receipt decision invalid';
            END IF;
            SELECT * INTO authority_row FROM longspan_authority_config WHERE run_id = p_run_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'terra receipt requires authority configuration';
            END IF;
            IF authority_row.reviewed_sha IS DISTINCT FROM p_reviewed_sha
               OR authority_row.tree_sha IS DISTINCT FROM p_tree_sha
               OR authority_row.source_digest IS DISTINCT FROM p_source_digest THEN
                RAISE EXCEPTION 'terra receipt provenance binding mismatch';
            END IF;
            IF p_authority_version IS NOT NULL
               AND authority_row.config_version IS DISTINCT FROM p_authority_version THEN
                RAISE EXCEPTION 'terra receipt authority version mismatch';
            END IF;
            IF p_migration_head IS DISTINCT FROM '007_longspan_authority_hardening' THEN
                RAISE EXCEPTION 'terra receipt migration head is not the canonical 007 head';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM longspan_auditor_receipts
                WHERE child_id = p_child_id AND attempt_number = p_attempt_number
                  AND verdict = 'pass'
            ) THEN
                RAISE EXCEPTION 'terra receipt requires auditor pass';
            END IF;
            SELECT entry_hash INTO actual_head
            FROM longspan_evidence_ledger
            WHERE child_id = p_child_id
            ORDER BY sequence_number DESC
            LIMIT 1;
            IF actual_head IS NULL OR actual_head IS DISTINCT FROM p_evidence_chain_head THEN
                RAISE EXCEPTION 'terra receipt evidence chain head is not the persisted ledger head';
            END IF;
            SELECT result_digest INTO stored_result_digest
            FROM longspan_execution_results
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number;
            IF stored_result_digest IS NULL OR stored_result_digest IS DISTINCT FROM p_result_digest THEN
                RAISE EXCEPTION 'terra receipt result digest is not bound to the persisted execution result';
            END IF;
            SELECT evidence_digest INTO stored_evidence_digest
            FROM longspan_auditor_receipts
            WHERE child_id = p_child_id AND attempt_number = p_attempt_number
              AND verdict = 'pass';
            IF stored_evidence_digest IS NULL OR stored_evidence_digest IS DISTINCT FROM p_evidence_digest THEN
                RAISE EXCEPTION 'terra receipt evidence digest is not bound to the auditor receipt';
            END IF;
            IF EXISTS (
                SELECT 1 FROM longspan_terra_receipts
                WHERE child_id = p_child_id AND attempt_number = p_attempt_number
            ) THEN
                RAISE EXCEPTION 'terra receipt already recorded';
            END IF;
            IF btrim(p_evidence_chain_head) = '' THEN
                RAISE EXCEPTION 'terra receipt evidence chain head is required';
            END IF;
            -- The database derives its own receipt digest and MAC signature.
            -- The separate authority signature is produced out-of-band by
            -- Terra and is verified by the repository and again on read; it
            -- must never be empty or silently replaced by database material.
            IF p_receipt_digest IS NOT NULL AND btrim(p_receipt_digest) <> '' THEN
                RAISE EXCEPTION 'terra receipt digest must be database-derived';
            END IF;
            IF p_signature IS NULL OR btrim(p_signature) = '' THEN
                RAISE EXCEPTION 'terra receipt external authority signature is required';
            END IF;
            IF array_length(string_to_array(p_signature, ':'), 1) <> 4
               OR split_part(p_signature, ':', 1) <> 'v1'
               OR btrim(split_part(p_signature, ':', 2)) = ''
               OR length(split_part(p_signature, ':', 3)) <> 64
               OR split_part(p_signature, ':', 3) !~ '^[0-9a-f]+$'
               OR btrim(split_part(p_signature, ':', 4)) = '' THEN
                RAISE EXCEPTION
                    'terra receipt authority signature must include external signature, gateway MAC, and attestation id';
            END IF;
            attestation_id := split_part(p_signature, ':', 4);
            stored_request_digest := child_row.request_digest;
            canonical_receipt := jsonb_build_object(
                'child_id', p_child_id,
                'attempt_number', p_attempt_number,
                'reviewer', p_reviewer,
                'decision', p_decision,
                'evidence_chain_head', p_evidence_chain_head,
                'run_id', p_run_id,
                'task_id', p_task_id,
                'reviewed_sha', p_reviewed_sha,
                'fence_token', p_fence_token,
                'controller_epoch', p_controller_epoch,
                'tree_sha', p_tree_sha,
                'source_digest', p_source_digest,
                'request_digest', stored_request_digest,
                'migration_head', p_migration_head,
                'authority_version', p_authority_version,
                'evidence_digest', stored_evidence_digest,
                'result_digest', stored_result_digest
            );
            computed_receipt_digest := encode(
                digest(convert_to(canonical_receipt::TEXT, 'UTF8'), 'sha256'),
                'hex'
            );
            computed_receipt_signature := longspan_terra_gateway_mac(
                p_child_id, p_attempt_number, p_reviewer, p_decision,
                p_evidence_chain_head, p_run_id, p_task_id, p_reviewed_sha,
                p_fence_token, p_controller_epoch, p_tree_sha, p_source_digest,
                p_request_digest, p_migration_head, p_authority_version,
                p_evidence_digest, p_result_digest, p_terra_auth_token
            );
            IF split_part(p_signature, ':', 3) IS DISTINCT FROM computed_receipt_signature THEN
                RAISE EXCEPTION
                    'terra receipt gateway proof is not verified by the authority boundary';
            END IF;
            PERFORM longspan_consume_terra_receipt_attestation(
                attestation_id, p_child_id, p_attempt_number, p_reviewer, p_decision,
                p_evidence_chain_head, computed_receipt_digest, p_run_id, p_task_id,
                p_reviewed_sha, p_fence_token, p_controller_epoch, p_tree_sha,
                p_source_digest, stored_request_digest, p_migration_head,
                p_authority_version, stored_evidence_digest, stored_result_digest,
                'v1:' || split_part(p_signature, ':', 2)
            );
            INSERT INTO longspan_terra_receipts
                (receipt_id, child_id, attempt_number, reviewer, decision,
                 evidence_chain_head, receipt_digest, run_id, task_id, reviewed_sha,
                 fence_token, controller_epoch, tree_sha, source_digest, request_digest,
                 migration_head, authority_version, evidence_digest, result_digest,
                 signature, authority_signature)
            VALUES (
                p_receipt_id, p_child_id, p_attempt_number, p_reviewer, p_decision,
                p_evidence_chain_head, computed_receipt_digest, p_run_id, p_task_id, p_reviewed_sha,
                p_fence_token, p_controller_epoch, p_tree_sha, p_source_digest, stored_request_digest,
                p_migration_head, p_authority_version, stored_evidence_digest, stored_result_digest,
                computed_receipt_signature, p_signature
            );
            RETURN computed_receipt_digest;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_insert_authority_config(
            p_run_id TEXT,
            p_terra_auth_hash TEXT,
            p_operator_auth_hash TEXT,
            p_reviewed_sha TEXT,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_config_version INTEGER,
            p_approval_receipt_digest TEXT,
            p_approval_id TEXT,
            p_action_digest TEXT,
            p_write_binding_digest TEXT
        ) RETURNS TABLE (
            run_id TEXT,
            terra_auth_hash TEXT,
            operator_auth_hash TEXT,
            reviewed_sha TEXT,
            tree_sha TEXT,
            source_digest TEXT,
            config_version INTEGER,
            approval_receipt_digest TEXT,
            updated_at TIMESTAMPTZ
        ) AS $$
        DECLARE
            actual_content_digest TEXT;
        BEGIN
            actual_content_digest := longspan_authority_content_digest(
                'initial_provision', p_run_id, p_terra_auth_hash, p_operator_auth_hash,
                p_reviewed_sha, p_tree_sha, p_source_digest, 0, p_config_version,
                p_approval_receipt_digest
            );
            IF p_write_binding_digest IS DISTINCT FROM actual_content_digest THEN
                RAISE EXCEPTION 'authority write content digest does not match the row payload';
            END IF;
            PERFORM longspan_assert_authority_write(
                p_run_id, p_approval_id, p_action_digest, actual_content_digest, p_config_version
            );
            IF p_approval_receipt_digest IS DISTINCT FROM p_action_digest THEN
                RAISE EXCEPTION 'authority receipt digest must match the approved action digest';
            END IF;
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            RETURN QUERY
            INSERT INTO longspan_authority_config
                (run_id, terra_auth_hash, operator_auth_hash, reviewed_sha,
                 tree_sha, source_digest, config_version, approval_receipt_digest)
            VALUES (
                p_run_id, p_terra_auth_hash, p_operator_auth_hash, p_reviewed_sha,
                p_tree_sha, p_source_digest, p_config_version, p_approval_receipt_digest
            )
            RETURNING longspan_authority_config.run_id,
                      longspan_authority_config.terra_auth_hash,
                      longspan_authority_config.operator_auth_hash,
                      longspan_authority_config.reviewed_sha,
                      longspan_authority_config.tree_sha,
                      longspan_authority_config.source_digest,
                      longspan_authority_config.config_version,
                      longspan_authority_config.approval_receipt_digest,
                      longspan_authority_config.updated_at;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_rotate_authority_config(
            p_run_id TEXT,
            p_terra_auth_hash TEXT,
            p_operator_auth_hash TEXT,
            p_reviewed_sha TEXT,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_expected_config_version INTEGER,
            p_next_config_version INTEGER,
            p_approval_receipt_digest TEXT,
            p_approval_id TEXT,
            p_action_digest TEXT,
            p_write_binding_digest TEXT
        ) RETURNS TABLE (
            run_id TEXT,
            terra_auth_hash TEXT,
            operator_auth_hash TEXT,
            reviewed_sha TEXT,
            tree_sha TEXT,
            source_digest TEXT,
            config_version INTEGER,
            approval_receipt_digest TEXT,
            updated_at TIMESTAMPTZ
        ) AS $$
        DECLARE
            actual_content_digest TEXT;
        BEGIN
            actual_content_digest := longspan_authority_content_digest(
                'rotate_authority', p_run_id, p_terra_auth_hash, p_operator_auth_hash,
                p_reviewed_sha, p_tree_sha, p_source_digest,
                p_expected_config_version, p_next_config_version,
                p_approval_receipt_digest
            );
            IF p_write_binding_digest IS DISTINCT FROM actual_content_digest THEN
                RAISE EXCEPTION 'authority write content digest does not match the row payload';
            END IF;
            PERFORM longspan_assert_authority_write(
                p_run_id, p_approval_id, p_action_digest, actual_content_digest, p_next_config_version
            );
            IF p_approval_receipt_digest IS DISTINCT FROM p_action_digest THEN
                RAISE EXCEPTION 'authority receipt digest must match the approved action digest';
            END IF;
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            RETURN QUERY
            UPDATE longspan_authority_config
            SET terra_auth_hash = p_terra_auth_hash,
                operator_auth_hash = p_operator_auth_hash,
                reviewed_sha = p_reviewed_sha,
                tree_sha = p_tree_sha,
                source_digest = p_source_digest,
                config_version = p_next_config_version,
                approval_receipt_digest = p_approval_receipt_digest,
                updated_at = clock_timestamp()
            WHERE run_id = p_run_id AND config_version = p_expected_config_version
            RETURNING longspan_authority_config.run_id,
                      longspan_authority_config.terra_auth_hash,
                      longspan_authority_config.operator_auth_hash,
                      longspan_authority_config.reviewed_sha,
                      longspan_authority_config.tree_sha,
                      longspan_authority_config.source_digest,
                      longspan_authority_config.config_version,
                      longspan_authority_config.approval_receipt_digest,
                      longspan_authority_config.updated_at;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_append_authority_history(
            p_history_id TEXT,
            p_run_id TEXT,
            p_config_version INTEGER,
            p_terra_auth_hash TEXT,
            p_operator_auth_hash TEXT,
            p_reviewed_sha TEXT,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_approval_receipt_digest TEXT,
            p_approval_id TEXT,
            p_operator_identity TEXT,
            p_controller_epoch INTEGER,
            p_challenge_epoch INTEGER,
            p_receipt_id TEXT,
            p_action_digest TEXT,
            p_write_binding_digest TEXT
        ) RETURNS VOID AS $$
        DECLARE
            actual_content_digest TEXT;
        BEGIN
            actual_content_digest := longspan_authority_content_digest(
                CASE WHEN p_config_version = 1 THEN 'initial_provision'
                     ELSE 'rotate_authority' END,
                p_run_id, p_terra_auth_hash, p_operator_auth_hash,
                p_reviewed_sha, p_tree_sha, p_source_digest,
                CASE WHEN p_config_version = 1 THEN 0 ELSE p_config_version - 1 END,
                p_config_version, p_approval_receipt_digest
            );
            IF p_write_binding_digest IS DISTINCT FROM actual_content_digest THEN
                RAISE EXCEPTION 'authority history content digest does not match the config payload';
            END IF;
            PERFORM longspan_assert_authority_write(
                p_run_id, p_approval_id, p_action_digest, actual_content_digest, p_config_version
            );
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            INSERT INTO longspan_authority_history
                (history_id, run_id, config_version, terra_auth_hash, operator_auth_hash,
                 reviewed_sha, tree_sha, source_digest, approval_receipt_digest,
                 approval_id, operator_identity, controller_epoch, challenge_epoch, receipt_id)
            VALUES (
                p_history_id, p_run_id, p_config_version, p_terra_auth_hash, p_operator_auth_hash,
                p_reviewed_sha, p_tree_sha, p_source_digest, p_approval_receipt_digest,
                p_approval_id, p_operator_identity, p_controller_epoch, p_challenge_epoch,
                p_receipt_id
            );
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        REVOKE ALL ON FUNCTION longspan_create_operator_challenge(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER, TEXT, INTEGER, INTEGER, INTEGER
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_create_operator_challenge(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER, TEXT, INTEGER, INTEGER, INTEGER
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_bind_and_consume_challenge(TEXT, TEXT, TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_bind_and_consume_challenge(TEXT, TEXT, TEXT)
            TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_install_ledger_mac_key(TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_install_ledger_mac_key(TEXT) TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_install_terra_gateway_mac_key(TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_install_terra_gateway_mac_key(TEXT)
            TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_issue_terra_receipt_attestation(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_issue_terra_receipt_attestation(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        ) TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_consume_terra_receipt_attestation(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_consume_terra_receipt_attestation(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_append_evidence_ledger(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_append_evidence_ledger(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_verify_ledger_entry(
            TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_verify_ledger_entry(
            TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_store_execution_evidence(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_store_execution_evidence(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_append_execution_audit(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_append_execution_audit(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_insert_execution_result(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_insert_execution_result(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_append_auditor_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_append_auditor_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_terra_gateway_mac(
            TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER,
            TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_terra_gateway_mac(
            TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER,
            TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        ) TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_terra_gateway_mac_for_attestation(TEXT)
            FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_terra_gateway_mac_for_attestation(TEXT)
            TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_append_terra_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_append_terra_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};

        REVOKE ALL ON FUNCTION longspan_insert_authority_config(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_insert_authority_config(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_rotate_authority_config(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_rotate_authority_config(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_append_authority_history(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_append_authority_history(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT
        ) TO {AUTHORITY_ROLE};

        REVOKE ALL ON FUNCTION longspan_assert_authority_write(TEXT, TEXT, TEXT, TEXT, INTEGER) FROM PUBLIC;

        -- Explicitly deny authority/evidence/audit/receipt direct writes for workflow.
        REVOKE INSERT, UPDATE, DELETE ON longspan_authority_config FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_authority_history FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_operator_challenges FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_authority_receipts FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_evidence_ledger FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
            ON longspan_ledger_legacy_attestations FROM {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_execution_audits FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_execution_results FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
            ON longspan_execution_evidence FROM {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_auditor_receipts FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_terra_receipts FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
            ON longspan_terra_receipt_attestations FROM {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        -- Run/bootstrap rows are created only by the database-owned registration
        -- routine; the workflow role may not manufacture controller rows with
        -- direct SQL.
        REVOKE INSERT, UPDATE, DELETE ON supervisor_runs FROM {WORKFLOW_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON controller_control FROM {WORKFLOW_ROLE};
        REVOKE ALL ON longspan_mac_material FROM {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        DO $mac_acl$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ATTACKER_ROLE}') THEN
                EXECUTE 'REVOKE ALL ON longspan_mac_material FROM {ATTACKER_ROLE}';
            END IF;
        END
        $mac_acl$ LANGUAGE plpgsql;
        DO $legacy_attestation_acl$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ATTACKER_ROLE}') THEN
                EXECUTE 'REVOKE ALL ON longspan_ledger_legacy_attestations FROM {ATTACKER_ROLE}';
            END IF;
        END
        $legacy_attestation_acl$ LANGUAGE plpgsql;

        -- Authority may not raw-INSERT evidence/receipts; use routines / service.
        REVOKE INSERT, UPDATE, DELETE ON longspan_evidence_ledger FROM {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_execution_audits FROM {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_execution_evidence FROM {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_auditor_receipts FROM {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_terra_receipts FROM {AUTHORITY_ROLE};

        -- Authority config/history/receipts/challenges: no direct DML for any runtime principal.
        REVOKE INSERT, UPDATE, DELETE ON longspan_authority_config FROM {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_authority_history FROM {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_authority_receipts FROM {AUTHORITY_ROLE};
        REVOKE INSERT, UPDATE, DELETE ON longspan_operator_challenges FROM {AUTHORITY_ROLE};

        -- Every workflow-role DML statement must first obtain a database-owned,
        -- transaction-local mutation scope.  The scope is HMAC-bound to the
        -- live controller epoch and cannot be forged by setting a custom GUC.
        CREATE OR REPLACE FUNCTION longspan_open_mutation_scope(
            p_run_id TEXT,
            p_controller_epoch INTEGER,
            p_fence_token BIGINT
        ) RETURNS VOID AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}'
               AND NOT (
                   (current_database() ~ '^td_test_'
                    OR current_database() ~ '^td_downgrade_')
                   AND current_setting('top_delivery.disposable_test_mutation', true) = '1'
               ) THEN
                RAISE EXCEPTION 'workflow mutation scope requires the workflow principal';
            END IF;
            SELECT * INTO control_row
            FROM controller_control
            WHERE run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR NOT control_row.scheduling_enabled
               OR control_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'workflow mutation scope is not bound to a live controller';
            END IF;
            IF p_fence_token IS NULL OR p_fence_token <= 0 THEN
                RAISE EXCEPTION 'workflow mutation scope requires a positive fence token';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM task_attempts
                WHERE run_id = p_run_id
                  AND fence_token = p_fence_token
                  AND controller_epoch = p_controller_epoch
                  AND status = 'running'
                  AND lease_expires_at > clock_timestamp()
            ) THEN
                RAISE EXCEPTION 'workflow mutation scope fence is stale';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'workflow mutation scope MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'workflow',
                'run_id', p_run_id,
                'controller_epoch', p_controller_epoch,
                'fence_token', p_fence_token
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
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        -- Controller mutations use a distinct routine and an explicit scope
        -- kind.  A controller fence token is never accepted by the workflow
        -- routine, so task and controller fence namespaces cannot collide.
        CREATE OR REPLACE FUNCTION longspan_open_controller_mutation_scope(
            p_run_id TEXT,
            p_controller_epoch INTEGER,
            p_controller_fence_token BIGINT,
            p_owner TEXT,
            p_operation TEXT
        ) RETURNS VOID AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'controller mutation scope requires the workflow principal';
            END IF;
            IF p_controller_fence_token IS NULL OR p_controller_fence_token <= 0
               OR p_owner IS NULL OR btrim(p_owner) = '' THEN
                RAISE EXCEPTION 'controller mutation scope requires a positive fenced owner';
            END IF;
            IF p_operation <> 'general' THEN
                RAISE EXCEPTION
                    'controller maintenance scopes require a dedicated database routine';
            END IF;
            SELECT * INTO control_row
            FROM controller_control
            WHERE run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR control_row.owner IS DISTINCT FROM p_owner
               OR control_row.controller_fence_token IS DISTINCT FROM p_controller_fence_token
               OR NOT control_row.scheduling_enabled
               OR control_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'controller mutation scope is not bound to the live lease owner';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'controller mutation scope MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'controller',
                'run_id', p_run_id,
                'controller_epoch', p_controller_epoch,
                'controller_fence_token', p_controller_fence_token,
                'owner', p_owner,
                'operation', p_operation
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
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        -- Remove the legacy four-argument generic wrapper.  It obscures the
        -- operation contract and must not remain callable by the workflow
        -- principal; all generic callers use the explicit five-argument form.
        DROP FUNCTION IF EXISTS longspan_open_controller_mutation_scope(
            TEXT, INTEGER, BIGINT, TEXT
        );

        -- Maintenance operations are deliberately exposed as narrowly shaped
        -- database-owned routines.  The workflow principal must not be able
        -- to open a broad controller maintenance scope and then choose which
        -- child columns or rows to rewrite.  These routines bind the complete
        -- operation to the live controller lease and supply every mutated
        -- value themselves.
        CREATE OR REPLACE FUNCTION longspan_current_controller_fence(
            p_run_id TEXT,
            p_controller_epoch INTEGER,
            p_owner TEXT
        ) RETURNS BIGINT AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'controller fence lookup requires the workflow principal';
            END IF;
            IF p_owner IS NULL OR btrim(p_owner) = '' THEN
                RAISE EXCEPTION 'controller fence lookup requires a fenced owner';
            END IF;
            SELECT * INTO control_row
            FROM controller_control
            WHERE run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR control_row.owner IS DISTINCT FROM p_owner
               OR control_row.controller_fence_token IS NULL
               OR control_row.controller_fence_token <= 0
               OR NOT control_row.scheduling_enabled
               OR control_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'controller fence lookup is not bound to the live controller lease';
            END IF;
            RETURN control_row.controller_fence_token;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        DROP FUNCTION IF EXISTS longspan_park_children(TEXT, INTEGER, TEXT);
        DROP FUNCTION IF EXISTS longspan_park_children(TEXT, INTEGER, TEXT, BIGINT);
        CREATE OR REPLACE FUNCTION longspan_park_children(
            p_run_id TEXT,
            p_controller_epoch INTEGER,
            p_owner TEXT,
            p_expected_controller_fence BIGINT
        ) RETURNS INTEGER AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
            child_row RECORD;
            parked_count INTEGER;
            remaining_count INTEGER;
            sequence_number INTEGER;
            previous_entry_hash TEXT;
            signed_payload TEXT;
            base_digest TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'child parking requires the workflow principal';
            END IF;
            IF p_owner IS NULL OR btrim(p_owner) = '' THEN
                RAISE EXCEPTION 'child parking requires a fenced owner';
            END IF;
            IF p_expected_controller_fence IS NULL OR p_expected_controller_fence <= 0 THEN
                RAISE EXCEPTION 'child parking requires a positive expected controller fence';
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
                RAISE EXCEPTION 'child parking is not bound to the live controller lease';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'child parking mutation MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'controller',
                'run_id', p_run_id,
                'controller_epoch', p_controller_epoch,
                'controller_fence_token', p_expected_controller_fence,
                'owner', p_owner,
                'operation', 'park_children'
            );
            scope_signature := encode(
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
            PERFORM set_config('top_delivery.mutation_scope_payload', scope_payload::TEXT, true);
            PERFORM set_config('top_delivery.mutation_scope_signature', scope_signature, true);
            parked_count := 0;
            FOR child_row IN
                UPDATE longspan_children
                SET state = 'parked',
                    updated_at = clock_timestamp(),
                    version = version + 1,
                    manager_capability_hash = NULL,
                    executor_capability_hash = NULL,
                    auditor_capability_hash = NULL,
                    lease_token_hash = NULL,
                    lease_expires_at = NULL
                WHERE run_id = p_run_id
                  AND state NOT IN ('parent_returned', 'parked', 'cancelled')
                RETURNING child_id, attempt_number
            LOOP
                parked_count := parked_count + 1;
                signed_payload := encode(
                    digest(
                        convert_to(
                            format(
                                '{{"child_id":%s,"reason":%s}}',
                                to_json(child_row.child_id)::TEXT,
                                to_json('controller_parked'::TEXT)::TEXT
                            ),
                            'UTF8'
                        ),
                        'sha256'
                    ),
                    'hex'
                );
                SELECT COALESCE(MAX(ledger.sequence_number), 0) + 1
                    INTO sequence_number
                FROM longspan_evidence_ledger AS ledger
                WHERE ledger.child_id = child_row.child_id;
                previous_entry_hash := NULL;
                IF sequence_number > 1 THEN
                    SELECT entry_hash INTO previous_entry_hash
                    FROM longspan_evidence_ledger AS ledger
                    WHERE ledger.child_id = child_row.child_id
                      AND ledger.sequence_number = sequence_number - 1;
                    IF previous_entry_hash IS NULL THEN
                        RAISE EXCEPTION 'child parking ledger predecessor is missing';
                    END IF;
                END IF;
                base_digest := encode(
                    digest(
                        convert_to(
                            format(
                                '{{"attempt_number":%s,"child_id":%s,"event_type":%s,"payload_digest":%s,"previous_entry_hash":%s,"producer_role":%s}}',
                                child_row.attempt_number,
                                to_json(child_row.child_id)::TEXT,
                                to_json('controller_parked'::TEXT)::TEXT,
                                to_json(signed_payload)::TEXT,
                                COALESCE(to_json(previous_entry_hash)::TEXT, 'null'),
                                to_json('parent'::TEXT)::TEXT
                            ),
                            'UTF8'
                        ),
                        'sha256'
                    ),
                    'hex'
                );
                PERFORM longspan_append_evidence_ledger(
                    gen_random_uuid()::TEXT,
                    child_row.child_id,
                    child_row.attempt_number,
                    'controller_parked',
                    'parent',
                    signed_payload,
                    p_run_id,
                    NULL,
                    previous_entry_hash,
                    sequence_number,
                    base_digest,
                    NULL
                );
            END LOOP;
            SELECT COUNT(*)::INTEGER INTO remaining_count
            FROM longspan_children
            WHERE run_id = p_run_id
              AND state NOT IN ('parent_returned', 'parked', 'cancelled');
            IF remaining_count <> 0 THEN
                RAISE EXCEPTION 'child parking did not reach a terminal state';
            END IF;
            -- The signed maintenance scope is one-shot.  Do not leave a
            -- valid controller scope in the caller's transaction where a
            -- subsequent generic routine could reuse it for a caller-shaped
            -- same-run child or ledger mutation.
            PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
            PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
            RETURN parked_count;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        DROP FUNCTION IF EXISTS longspan_expire_stale_children(TEXT, INTEGER, TEXT);
        DROP FUNCTION IF EXISTS longspan_expire_stale_children(TEXT, INTEGER, TEXT, BIGINT);
        CREATE OR REPLACE FUNCTION longspan_expire_stale_children(
            p_run_id TEXT,
            p_controller_epoch INTEGER,
            p_owner TEXT,
            p_expected_controller_fence BIGINT
        ) RETURNS TEXT[] AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
            child_row RECORD;
            expired_ids TEXT[] := ARRAY[]::TEXT[];
            next_attempt INTEGER;
            signed_payload TEXT;
            previous_entry_hash TEXT;
            sequence_number INTEGER;
            base_digest TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'stale-child expiry requires the workflow principal';
            END IF;
            IF p_owner IS NULL OR btrim(p_owner) = '' THEN
                RAISE EXCEPTION 'stale-child expiry requires a fenced owner';
            END IF;
            IF p_expected_controller_fence IS NULL OR p_expected_controller_fence <= 0 THEN
                RAISE EXCEPTION 'stale-child expiry requires a positive expected controller fence';
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
                RAISE EXCEPTION 'stale-child expiry is not bound to the live controller lease';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'stale-child expiry mutation MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'controller',
                'run_id', p_run_id,
                'controller_epoch', p_controller_epoch,
                'controller_fence_token', p_expected_controller_fence,
                'owner', p_owner,
                'operation', 'expire_stale_children'
            );
            scope_signature := encode(
                hmac(
                    convert_to(
                        'top_delivery:controller_maintenance_scope:v1:'
                        || scope_payload::TEXT,
                        'UTF8'
                    ),
                    convert_to(mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
            PERFORM set_config('top_delivery.mutation_scope_payload', scope_payload::TEXT, true);
            PERFORM set_config('top_delivery.mutation_scope_signature', scope_signature, true);
            FOR child_row IN
                SELECT child_id, attempt_number, version
                FROM longspan_children
                WHERE run_id = p_run_id
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= clock_timestamp()
                  AND state IN ('ready', 'planned', 'executing', 'executed')
                FOR UPDATE
            LOOP
                next_attempt := child_row.attempt_number + 1;
                UPDATE longspan_children
                SET state = 'retry_wait',
                    version = version + 1,
                    manager_capability_hash = NULL,
                    executor_capability_hash = NULL,
                    auditor_capability_hash = NULL,
                    lease_token_hash = NULL,
                    lease_expires_at = NULL,
                    attempt_number = next_attempt,
                    idempotency_key = encode(
                        digest(
                            convert_to(
                                concat_ws(
                                    ':', child_row.child_id, next_attempt::TEXT,
                                    p_run_id, gen_random_uuid()::TEXT
                                ),
                                'UTF8'
                            ),
                            'sha256'
                        ),
                        'hex'
                    ),
                    updated_at = clock_timestamp()
                WHERE child_id = child_row.child_id
                  AND version = child_row.version
                  AND state IN ('ready', 'planned', 'executing', 'executed');
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'stale-child expiry lost the child row race';
                END IF;
                expired_ids := array_append(expired_ids, child_row.child_id);
                signed_payload := encode(
                    digest(
                        convert_to(
                            format(
                                '{{"child_id":%s,"reason":%s}}',
                                to_json(child_row.child_id)::TEXT,
                                to_json('lease_expired'::TEXT)::TEXT
                            ),
                            'UTF8'
                        ),
                        'sha256'
                    ),
                    'hex'
                );
                SELECT COALESCE(MAX(ledger.sequence_number), 0) + 1
                    INTO sequence_number
                FROM longspan_evidence_ledger AS ledger
                WHERE ledger.child_id = child_row.child_id;
                previous_entry_hash := NULL;
                IF sequence_number > 1 THEN
                    SELECT entry_hash INTO previous_entry_hash
                    FROM longspan_evidence_ledger AS ledger
                    WHERE ledger.child_id = child_row.child_id
                      AND ledger.sequence_number = sequence_number - 1;
                    IF previous_entry_hash IS NULL THEN
                        RAISE EXCEPTION 'stale-child expiry ledger predecessor is missing';
                    END IF;
                END IF;
                base_digest := encode(
                    digest(
                        convert_to(
                            format(
                                '{{"attempt_number":%s,"child_id":%s,"event_type":%s,"payload_digest":%s,"previous_entry_hash":%s,"producer_role":%s}}',
                                next_attempt,
                                to_json(child_row.child_id)::TEXT,
                                to_json('lease_expired'::TEXT)::TEXT,
                                to_json(signed_payload)::TEXT,
                                COALESCE(to_json(previous_entry_hash)::TEXT, 'null'),
                                to_json('parent'::TEXT)::TEXT
                            ),
                            'UTF8'
                        ),
                        'sha256'
                    ),
                    'hex'
                );
                PERFORM longspan_append_evidence_ledger(
                    gen_random_uuid()::TEXT,
                    child_row.child_id,
                    next_attempt,
                    'lease_expired',
                    'parent',
                    signed_payload,
                    p_run_id,
                    NULL,
                    previous_entry_hash,
                    sequence_number,
                    base_digest,
                    NULL
                );
            END LOOP;
            -- The signed maintenance scope is one-shot and must not remain
            -- available after the database-owned expiry operation returns.
            PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
            PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
            RETURN expired_ids;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_open_signal_scope(
            p_run_id TEXT,
            p_controller_epoch INTEGER
        ) RETURNS VOID AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'signal mutation scope requires the workflow principal';
            END IF;
            SELECT * INTO control_row
            FROM controller_control
            WHERE run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR NOT control_row.scheduling_enabled
               OR (
                   control_row.lease_expires_at <= clock_timestamp()
               ) THEN
                RAISE EXCEPTION 'signal mutation scope is not bound to a live controller epoch';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'signal mutation scope MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'signal',
                'run_id', p_run_id,
                'controller_epoch', p_controller_epoch,
                'fence_token', 0
            );
            scope_signature := encode(
                hmac(
                    convert_to(
                        'top_delivery:signal_scope:v1:' || scope_payload::TEXT,
                        'UTF8'
                    ),
                    convert_to(mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
            PERFORM set_config('top_delivery.mutation_scope_payload', scope_payload::TEXT, true);
            PERFORM set_config('top_delivery.mutation_scope_signature', scope_signature, true);
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_open_rollback_signal_scope(
            p_run_id TEXT,
            p_controller_epoch INTEGER
        ) RETURNS VOID AS $$
        DECLARE
            control_row controller_control%ROWTYPE;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}' THEN
                RAISE EXCEPTION 'rollback signal scope requires the workflow principal';
            END IF;
            SELECT * INTO control_row
            FROM controller_control
            WHERE run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
               OR control_row.scheduling_enabled
               OR control_row.owner IS NOT NULL
               OR control_row.lease_expires_at > clock_timestamp() THEN
                RAISE EXCEPTION 'rollback signal scope is not bound to a disabled fenced controller';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'rollback signal scope MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'signal',
                'run_id', p_run_id,
                'controller_epoch', p_controller_epoch,
                'fence_token', 0,
                'rollback', TRUE
            );
            scope_signature := encode(
                hmac(
                    convert_to(
                        'top_delivery:signal_rollback_scope:v1:' || scope_payload::TEXT,
                        'UTF8'
                    ),
                    convert_to(mac_key, 'UTF8'),
                    'sha256'
                ),
                'hex'
            );
            PERFORM set_config('top_delivery.mutation_scope_payload', scope_payload::TEXT, true);
            PERFORM set_config('top_delivery.mutation_scope_signature', scope_signature, true);
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_register_run(
            p_run_id TEXT,
            p_state TEXT
        ) RETURNS TEXT AS $$
        DECLARE
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}'
               AND NOT (
                   (current_database() ~ '^td_test_'
                    OR current_database() ~ '^td_downgrade_')
                   AND current_setting('top_delivery.disposable_test_mutation', true) = '1'
               ) THEN
                RAISE EXCEPTION 'run registration requires the workflow principal';
            END IF;
            IF btrim(p_run_id) = '' THEN
                RAISE EXCEPTION 'run id is required';
            END IF;
            IF p_state NOT IN ('active', 'paused', 'completed', 'blocked', 'failed') THEN
                RAISE EXCEPTION 'run state is invalid';
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'run registration mutation MAC material is unavailable';
            END IF;
            scope_payload := jsonb_build_object(
                'scope_kind', 'controller',
                'run_id', p_run_id,
                'controller_epoch', 0,
                'controller_fence_token', 0,
                'owner', 'bootstrap',
                'operation', 'register_run'
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
            INSERT INTO supervisor_runs (run_id, state, updated_at)
            VALUES (p_run_id, p_state, clock_timestamp())
            ON CONFLICT (run_id) DO NOTHING;
            INSERT INTO controller_control (run_id, current_epoch, lease_expires_at)
            VALUES (p_run_id, 0, clock_timestamp())
            ON CONFLICT (run_id) DO NOTHING;
            -- Registration scope is bootstrap-only and must not survive the
            -- routine return in the caller's transaction.
            PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
            PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
            RETURN p_run_id;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_next_event_seq(
            p_run_id TEXT,
            p_controller_epoch BIGINT
        ) RETURNS BIGINT AS $$
        DECLARE
            next_sequence BIGINT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}'
               AND NOT (
                   (current_database() ~ '^td_test_'
                    OR current_database() ~ '^td_downgrade_')
                   AND current_setting('top_delivery.disposable_test_mutation', true) = '1'
               ) THEN
                RAISE EXCEPTION 'event sequence allocation requires the workflow principal';
            END IF;
            SELECT event_seq_counter + 1 INTO next_sequence
            FROM controller_control
            WHERE run_id = p_run_id AND current_epoch = p_controller_epoch
            FOR UPDATE;
            IF next_sequence IS NULL THEN
                RAISE EXCEPTION 'event sequence allocation lost the controller epoch';
            END IF;
            UPDATE controller_control
            SET event_seq_counter = next_sequence,
                updated_at = clock_timestamp()
            WHERE run_id = p_run_id AND current_epoch = p_controller_epoch;
            RETURN next_sequence;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_disable_controller(
            p_run_id TEXT,
            p_expected_epoch BIGINT
        ) RETURNS BIGINT AS $$
        DECLARE
            next_epoch BIGINT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}'
               AND NOT (
                   (current_database() ~ '^td_test_'
                    OR current_database() ~ '^td_downgrade_')
                   AND current_setting('top_delivery.disposable_test_mutation', true) = '1'
               ) THEN
                RAISE EXCEPTION 'controller disable requires the workflow principal';
            END IF;
            SELECT current_epoch + 1 INTO next_epoch
            FROM controller_control
            WHERE run_id = p_run_id AND current_epoch = p_expected_epoch
            FOR UPDATE;
            IF next_epoch IS NULL THEN
                RAISE EXCEPTION 'controller disable lost the controller epoch';
            END IF;
            UPDATE controller_control
            SET scheduling_enabled = FALSE,
                current_epoch = next_epoch,
                controller_fence_token = controller_fence_token + 1,
                owner = NULL,
                lease_expires_at = clock_timestamp(),
                updated_at = clock_timestamp()
            WHERE run_id = p_run_id AND current_epoch = p_expected_epoch;
            RETURN next_epoch;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_test_expire_controller_lease(
            p_run_id TEXT
        ) RETURNS VOID AS $$
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}'
               OR current_database() !~ '^td_test_'
               OR current_setting('top_delivery.disposable_test_mutation', true) IS DISTINCT FROM '1' THEN
                RAISE EXCEPTION 'controller lease injection is disposable-test-only';
            END IF;
            UPDATE controller_control
            SET lease_expires_at = clock_timestamp() - interval '1 second',
                updated_at = clock_timestamp()
            WHERE run_id = p_run_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'controller run is unknown';
            END IF;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        CREATE OR REPLACE FUNCTION longspan_acquire_controller(
            p_run_id TEXT,
            p_owner TEXT,
            p_lease_seconds DOUBLE PRECISION,
            p_expected_epoch BIGINT,
            p_force_takeover BOOLEAN
        ) RETURNS BIGINT AS $$
        DECLARE
            row_control controller_control%ROWTYPE;
            next_epoch BIGINT;
            mac_key TEXT;
            scope_payload JSONB;
            scope_signature TEXT;
            scope_owner TEXT;
        BEGIN
            IF session_user <> '{WORKFLOW_ROLE}'
               AND NOT (
                   (current_database() ~ '^td_test_'
                    OR current_database() ~ '^td_downgrade_')
                   AND current_setting('top_delivery.disposable_test_mutation', true) = '1'
               ) THEN
                RAISE EXCEPTION 'controller acquisition requires the workflow principal';
            END IF;
            SELECT * INTO row_control
            FROM controller_control
            WHERE run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'controller run is unknown';
            END IF;
            IF NOT row_control.scheduling_enabled THEN
                RAISE EXCEPTION 'scheduling disabled';
            END IF;
            IF p_expected_epoch IS NOT NULL
               AND p_expected_epoch IS DISTINCT FROM row_control.current_epoch THEN
                RAISE EXCEPTION 'stale controller epoch';
            END IF;
            IF row_control.owner IS NOT NULL
               AND row_control.owner <> p_owner
               AND row_control.lease_expires_at > clock_timestamp() THEN
                RAISE EXCEPTION 'controller lease held by another owner';
            END IF;
            next_epoch := row_control.current_epoch;
            IF row_control.lease_expires_at <= clock_timestamp()
               OR row_control.owner IS DISTINCT FROM p_owner THEN
                next_epoch := row_control.current_epoch + 1;
            END IF;
            SELECT material.mac_key INTO mac_key
            FROM longspan_mac_material AS material
            WHERE material.material_id = 'ledger';
            IF mac_key IS NULL THEN
                RAISE EXCEPTION 'controller acquisition mutation MAC material is unavailable';
            END IF;
            scope_owner := COALESCE(row_control.owner, p_owner);
            scope_payload := jsonb_build_object(
                'scope_kind', 'controller',
                'run_id', p_run_id,
                'controller_epoch', row_control.current_epoch,
                'controller_fence_token', row_control.controller_fence_token,
                'owner', scope_owner,
                'operation', 'acquire_controller'
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
            UPDATE controller_control
            SET current_epoch = next_epoch,
                controller_fence_token = controller_fence_token + 1,
                owner = p_owner,
                lease_expires_at = clock_timestamp() + (p_lease_seconds || ' seconds')::INTERVAL,
                updated_at = clock_timestamp()
            WHERE run_id = p_run_id;
            -- Acquisition scope is single-use; subsequent writes must obtain
            -- a fresh database-owned scope and cannot reuse this lease proof.
            PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
            PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
            RETURN next_epoch;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

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
               AND TG_TABLE_NAME IN (
                   'parent_tasks', 'task_attempts', 'retry_queue', 'longspan_children',
                   'longspan_plans', 'longspan_execution_results',
                   'longspan_execution_audits', 'longspan_auditor_receipts',
                   'longspan_terra_receipts', 'longspan_evidence_ledger'
               )
               AND COALESCE(scope_payload->>'operation', 'general') NOT IN
                   ('park_children', 'expire_stale_children') THEN
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

        DROP TRIGGER IF EXISTS supervisor_run_scope_guard ON supervisor_runs;
        CREATE TRIGGER supervisor_run_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON supervisor_runs
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS controller_scope_guard ON controller_control;
        CREATE TRIGGER controller_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON controller_control
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS parent_task_scope_guard ON parent_tasks;
        CREATE TRIGGER parent_task_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON parent_tasks
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS task_attempt_scope_guard ON task_attempts;
        CREATE TRIGGER task_attempt_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON task_attempts
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS retry_queue_scope_guard ON retry_queue;
        CREATE TRIGGER retry_queue_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON retry_queue
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS supervisor_event_scope_guard ON supervisor_events;
        CREATE TRIGGER supervisor_event_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON supervisor_events
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS longspan_child_scope_guard ON longspan_children;
        CREATE TRIGGER longspan_child_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON longspan_children
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS longspan_plan_scope_guard ON longspan_plans;
        CREATE TRIGGER longspan_plan_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON longspan_plans
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS longspan_result_scope_guard ON longspan_execution_results;
        CREATE TRIGGER longspan_result_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON longspan_execution_results
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS longspan_experiment_scope_guard ON longspan_experiments;
        CREATE TRIGGER longspan_experiment_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON longspan_experiments
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS evidence_index_scope_guard ON evidence_index;
        CREATE TRIGGER evidence_index_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON evidence_index
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS manifest_submission_scope_guard ON manifest_submissions;
        CREATE TRIGGER manifest_submission_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON manifest_submissions
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS signal_status_scope_guard ON signal_status;
        CREATE TRIGGER signal_status_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON signal_status
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS provenance_scope_guard ON provenance_records;
        CREATE TRIGGER provenance_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON provenance_records
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();
        DROP TRIGGER IF EXISTS notification_scope_guard ON notifications;
        CREATE TRIGGER notification_scope_guard
            BEFORE INSERT OR UPDATE OR DELETE ON notifications
            FOR EACH ROW EXECUTE FUNCTION require_longspan_mutation_scope();

        REVOKE ALL ON FUNCTION longspan_open_mutation_scope(TEXT, INTEGER, BIGINT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_open_mutation_scope(TEXT, INTEGER, BIGINT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_open_controller_mutation_scope(TEXT, INTEGER, BIGINT, TEXT, TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_open_controller_mutation_scope(TEXT, INTEGER, BIGINT, TEXT, TEXT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_current_controller_fence(TEXT, INTEGER, TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_current_controller_fence(TEXT, INTEGER, TEXT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_park_children(TEXT, INTEGER, TEXT, BIGINT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_park_children(TEXT, INTEGER, TEXT, BIGINT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_expire_stale_children(TEXT, INTEGER, TEXT, BIGINT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_expire_stale_children(TEXT, INTEGER, TEXT, BIGINT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_open_signal_scope(TEXT, INTEGER) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_open_signal_scope(TEXT, INTEGER)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_open_rollback_signal_scope(TEXT, INTEGER) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_open_rollback_signal_scope(TEXT, INTEGER)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_register_run(TEXT, TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_register_run(TEXT, TEXT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_next_event_seq(TEXT, BIGINT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_next_event_seq(TEXT, BIGINT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_disable_controller(TEXT, BIGINT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_disable_controller(TEXT, BIGINT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_test_expire_controller_lease(TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_test_expire_controller_lease(TEXT)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION longspan_acquire_controller(TEXT, TEXT, DOUBLE PRECISION, BIGINT, BOOLEAN) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_acquire_controller(TEXT, TEXT, DOUBLE PRECISION, BIGINT, BOOLEAN)
            TO {WORKFLOW_ROLE};
        REVOKE ALL ON FUNCTION require_longspan_mutation_scope() FROM PUBLIC;

        -- Keep SECURITY DEFINER execution explicit.  PUBLIC and the opposite
        -- runtime principal may not call any control-plane routine, and the
        -- disposable attacker role is revoked when it exists.  The existing
        -- GRANTs above remain the only intended runtime entry points.
        DO $routine_acl$
        DECLARE
            routine_signature TEXT;
            workflow_routines CONSTANT TEXT[] := ARRAY[
                'longspan_create_operator_challenge(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER, TEXT, INTEGER, INTEGER, INTEGER)',
                'longspan_append_evidence_ledger(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT)',
                'longspan_verify_ledger_entry(TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)',
                'longspan_store_execution_evidence(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)',
                'longspan_append_execution_audit(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)',
                'longspan_insert_execution_result(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)',
                'longspan_append_auditor_receipt(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)',
                'longspan_append_terra_receipt(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)',
                'longspan_open_mutation_scope(TEXT, INTEGER, BIGINT)',
                'longspan_open_controller_mutation_scope(TEXT, INTEGER, BIGINT, TEXT, TEXT)',
                'longspan_current_controller_fence(TEXT, INTEGER, TEXT)',
                'longspan_park_children(TEXT, INTEGER, TEXT, BIGINT)',
                'longspan_expire_stale_children(TEXT, INTEGER, TEXT, BIGINT)',
                'longspan_open_signal_scope(TEXT, INTEGER)',
                'longspan_open_rollback_signal_scope(TEXT, INTEGER)',
                'longspan_register_run(TEXT, TEXT)',
                'longspan_next_event_seq(TEXT, BIGINT)',
                'longspan_disable_controller(TEXT, BIGINT)',
                'longspan_test_expire_controller_lease(TEXT)',
                'longspan_acquire_controller(TEXT, TEXT, DOUBLE PRECISION, BIGINT, BOOLEAN)'
            ];
            authority_routines CONSTANT TEXT[] := ARRAY[
                'longspan_bind_and_consume_challenge(TEXT, TEXT, TEXT)',
                'longspan_install_ledger_mac_key(TEXT)',
                'longspan_install_terra_gateway_mac_key(TEXT)',
                'longspan_terra_gateway_mac(TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)',
                'longspan_terra_gateway_mac_for_attestation(TEXT)',
                'longspan_insert_authority_config(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)',
                'longspan_rotate_authority_config(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT, TEXT)',
                'longspan_append_authority_history(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT)'
            ];
            private_routines CONSTANT TEXT[] := ARRAY[
                'reject_longspan_authority_mutation()',
                'reject_longspan_authority_history_mutation()',
                'reject_longspan_append_only_mutation()',
                'reject_longspan_terra_attestation_mutation()',
                'reject_longspan_legacy_watermark()',
                'reject_longspan_legacy_attestation_mutation()',
                'reject_challenge_direct_mutation()',
                'longspan_assert_child_capability(TEXT, INTEGER, TEXT, TEXT)',
                'longspan_assert_controller_maintenance_scope(TEXT, TEXT)',
                'longspan_authority_content_digest(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT)',
                'longspan_assert_authority_write(TEXT, TEXT, TEXT, TEXT, INTEGER)',
                'require_longspan_mutation_scope()'
            ];
        BEGIN
            FOREACH routine_signature IN ARRAY workflow_routines LOOP
                EXECUTE format(
                    'ALTER FUNCTION %s OWNER TO %I',
                    routine_signature, '{MIGRATION_ROLE}'
                );
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, %I', routine_signature, '{AUTHORITY_ROLE}');
            END LOOP;
            FOREACH routine_signature IN ARRAY authority_routines LOOP
                EXECUTE format(
                    'ALTER FUNCTION %s OWNER TO %I',
                    routine_signature, '{MIGRATION_ROLE}'
                );
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, %I', routine_signature, '{WORKFLOW_ROLE}');
            END LOOP;
            FOREACH routine_signature IN ARRAY private_routines LOOP
                EXECUTE format(
                    'ALTER FUNCTION %s OWNER TO %I',
                    routine_signature, '{MIGRATION_ROLE}'
                );
                EXECUTE format(
                    'REVOKE ALL ON FUNCTION %s FROM PUBLIC, %I, %I',
                    routine_signature, '{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}'
                );
            END LOOP;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ATTACKER_ROLE}') THEN
                FOREACH routine_signature IN ARRAY workflow_routines LOOP
                    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', routine_signature, '{ATTACKER_ROLE}');
                END LOOP;
                FOREACH routine_signature IN ARRAY authority_routines LOOP
                    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', routine_signature, '{ATTACKER_ROLE}');
                END LOOP;
                FOREACH routine_signature IN ARRAY private_routines LOOP
                    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', routine_signature, '{ATTACKER_ROLE}');
                END LOOP;
            END IF;
        END
        $routine_acl$ LANGUAGE plpgsql;

        -- Normalize only the reviewed controller catalog.  Never infer
        -- ownership from a prefix: a caller could plant an unrelated public
        -- relation or SECURITY DEFINER routine named longspan_* and have this
        -- migration silently adopt it.
        DO $routine_owner$
        DECLARE
            routine_row RECORD;
            table_row RECORD;
            sequence_row RECORD;
            allowed_table_names CONSTANT TEXT[] := ARRAY[
                'controller_control', 'supervisor_runs', 'parent_tasks', 'task_attempts',
                'retry_queue', 'supervisor_events', 'evidence_index',
                'manifest_submissions', 'required_manifest_entries', 'signal_status',
                'provenance_records', 'notifications', 'alembic_version',
                'top_delivery_downgrade_capabilities',
                'longspan_children', 'longspan_plans',
                'longspan_execution_results', 'longspan_auditor_receipts',
                'longspan_terra_receipts', 'longspan_experiments',
                'longspan_evidence_ledger', 'longspan_authority_config',
                'longspan_authority_history', 'longspan_operator_challenges',
                'longspan_authority_receipts', 'longspan_terra_receipt_attestations',
                'longspan_execution_audits', 'longspan_execution_evidence',
                'longspan_ledger_legacy_attestations',
                'longspan_mac_material', 'longspan_mac_key_history',
                'longspan_migration_provenance',
                'longspan_migration_provenance_008_state'
            ];
            allowed_sequence_names CONSTANT TEXT[] := ARRAY[
                'supervisor_events_event_seq_seq'
            ];
            provenance_relation_names CONSTANT TEXT[] := ARRAY[
                'longspan_migration_provenance',
                'longspan_migration_provenance_008_state'
            ];
            allowed_routine_signatures CONSTANT TEXT[] := ARRAY[
                'reject_evidence_index_mutation()',
                'reject_longspan_evidence_mutation()',
                'reject_longspan_auditor_mutation()',
                'reject_longspan_evidence_truncate()',
                'reject_longspan_auditor_truncate()',
                'reject_longspan_terra_mutation()',
                'reject_longspan_terra_truncate()',
                'reject_longspan_authority_mutation()',
                'reject_longspan_authority_history_mutation()',
                'reject_longspan_append_only_mutation()',
                'reject_longspan_terra_attestation_mutation()',
                'reject_longspan_legacy_watermark()',
                'reject_longspan_legacy_attestation_mutation()',
                'reject_longspan_execution_audit_mutation()',
                'reject_challenge_direct_mutation()',
                'longspan_create_operator_challenge(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER, TEXT, INTEGER, INTEGER, INTEGER)',
                'longspan_bind_and_consume_challenge(TEXT, TEXT, TEXT)',
                'longspan_install_ledger_mac_key(TEXT)',
                'longspan_install_terra_gateway_mac_key(TEXT)',
                'longspan_assert_child_capability(TEXT, INTEGER, TEXT, TEXT)',
                'longspan_assert_controller_maintenance_scope(TEXT, TEXT)',
                'longspan_authority_content_digest(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT)',
                'longspan_assert_authority_write(TEXT, TEXT, TEXT, TEXT, INTEGER)',
                'longspan_append_evidence_ledger(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT)',
                'longspan_verify_ledger_entry(TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)',
                'longspan_store_execution_evidence(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)',
                'longspan_append_execution_audit(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)',
                'longspan_insert_execution_result(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)',
                'longspan_append_auditor_receipt(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)',
                'longspan_issue_terra_receipt_attestation(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)',
                'longspan_consume_terra_receipt_attestation(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)',
                'longspan_terra_gateway_mac(TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT)',
                'longspan_terra_gateway_mac_for_attestation(TEXT)',
                'longspan_append_terra_receipt(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)',
                'longspan_insert_authority_config(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT)',
                'longspan_rotate_authority_config(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT, TEXT)',
                'longspan_append_authority_history(TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT)',
                'longspan_open_mutation_scope(TEXT, INTEGER, BIGINT)',
                'longspan_open_controller_mutation_scope(TEXT, INTEGER, BIGINT, TEXT, TEXT)',
                'longspan_current_controller_fence(TEXT, INTEGER, TEXT)',
                'longspan_park_children(TEXT, INTEGER, TEXT, BIGINT)',
                'longspan_expire_stale_children(TEXT, INTEGER, TEXT, BIGINT)',
                'longspan_open_signal_scope(TEXT, INTEGER)',
                'longspan_open_rollback_signal_scope(TEXT, INTEGER)',
                'longspan_register_run(TEXT, TEXT)',
                'longspan_next_event_seq(TEXT, BIGINT)',
                'longspan_disable_controller(TEXT, BIGINT)',
                'longspan_test_expire_controller_lease(TEXT)',
                'longspan_acquire_controller(TEXT, TEXT, DOUBLE PRECISION, BIGINT, BOOLEAN)',
                'reject_longspan_migration_provenance_008_archive_mutation()',
                'require_longspan_mutation_scope()'
            ];
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                  AND c.relname <> ALL(allowed_table_names)
            ) THEN
                RAISE EXCEPTION
                    '007 owner normalization blocked: unexpected public relation exists';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind = 'S'
                  AND c.relname <> ALL(allowed_sequence_names)
            ) THEN
                RAISE EXCEPTION
                    '007 owner normalization blocked: unexpected public sequence exists';
            END IF;
            -- Provenance is authority data, not a compatibility object to
            -- adopt. Validate its owner, ACL, columns, nullability and
            -- primary key before any ownership normalization can run.
            IF EXISTS (
                SELECT 1
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_roles AS owner_role ON owner_role.oid = c.relowner
                WHERE n.nspname = 'public'
                  AND c.relname = ANY(provenance_relation_names)
                  AND (
                      owner_role.rolname <> '{MIGRATION_ROLE}'
                      OR (
                          c.relacl IS NOT NULL
                          AND EXISTS (
                              SELECT 1
                              FROM aclexplode(c.relacl) AS acl
                              WHERE NOT (
                                  acl.grantee = c.relowner
                                  OR (
                                      c.relname = 'longspan_migration_provenance'
                                      AND acl.grantee IN (
                                          (SELECT oid FROM pg_roles
                                           WHERE rolname = '{WORKFLOW_ROLE}'),
                                          (SELECT oid FROM pg_roles
                                           WHERE rolname = '{AUTHORITY_ROLE}')
                                      )
                                      AND acl.privilege_type = 'SELECT'
                                  )
                              )
                          )
                      )
                  )
            ) THEN
                RAISE EXCEPTION
                    '007 owner normalization blocked: provenance relation owner or ACL is unsafe';
            END IF;
            IF to_regclass('public.longspan_migration_provenance') IS NOT NULL
               AND (
                   EXISTS (
                       SELECT 1
                       FROM pg_attribute AS a
                       WHERE a.attrelid = to_regclass('public.longspan_migration_provenance')
                         AND a.attnum > 0 AND NOT a.attisdropped
                         AND a.attname <> ALL(ARRAY[
                             'revision', 'source_digest', 'algorithm',
                             'normalization_version', 'applied_at'
                         ]::TEXT[])
                   )
                   OR EXISTS (
                       SELECT 1
                       FROM unnest(ARRAY[
                           'revision', 'source_digest', 'algorithm',
                           'normalization_version', 'applied_at'
                       ]::TEXT[]) AS expected(name)
                       WHERE NOT EXISTS (
                           SELECT 1
                           FROM pg_attribute AS a
                           WHERE a.attrelid = to_regclass('public.longspan_migration_provenance')
                             AND a.attnum > 0 AND NOT a.attisdropped
                             AND a.attname = expected.name
                       )
                   )
                   OR EXISTS (
                       SELECT 1
                       FROM pg_attribute AS a
                       WHERE a.attrelid = to_regclass('public.longspan_migration_provenance')
                         AND a.attname = ANY(ARRAY[
                             'revision', 'source_digest', 'algorithm',
                             'normalization_version', 'applied_at'
                         ]::TEXT[])
                         AND a.attnotnull IS DISTINCT FROM TRUE
                   )
                   OR NOT EXISTS (
                       SELECT 1
                       FROM pg_constraint AS constraint_row
                       WHERE constraint_row.conrelid =
                             to_regclass('public.longspan_migration_provenance')
                         AND constraint_row.contype = 'p'
                         AND pg_get_constraintdef(constraint_row.oid) =
                             'PRIMARY KEY (revision)'
                   )
               ) THEN
                RAISE EXCEPTION
                    '007 owner normalization blocked: provenance table contract is not the reviewed contract';
            END IF;
            IF to_regclass('public.longspan_migration_provenance_008_state') IS NOT NULL
               AND (
                   EXISTS (
                       SELECT 1
                       FROM pg_attribute AS a
                       WHERE a.attrelid = to_regclass('public.longspan_migration_provenance_008_state')
                         AND a.attnum > 0 AND NOT a.attisdropped
                         AND a.attname <> ALL(ARRAY[
                             'singleton', 'provenance_table_preexisting', 'recorded_at'
                         ]::TEXT[])
                   )
                   OR EXISTS (
                       SELECT 1
                       FROM unnest(ARRAY[
                           'singleton', 'provenance_table_preexisting', 'recorded_at'
                       ]::TEXT[]) AS expected(name)
                       WHERE NOT EXISTS (
                           SELECT 1
                           FROM pg_attribute AS a
                           WHERE a.attrelid = to_regclass('public.longspan_migration_provenance_008_state')
                             AND a.attnum > 0 AND NOT a.attisdropped
                             AND a.attname = expected.name
                       )
                   )
                   OR NOT EXISTS (
                       SELECT 1
                       FROM pg_constraint AS constraint_row
                       WHERE constraint_row.conrelid =
                             to_regclass('public.longspan_migration_provenance_008_state')
                         AND constraint_row.contype = 'p'
                         AND pg_get_constraintdef(constraint_row.oid) =
                             'PRIMARY KEY (singleton)'
                   )
               ) THEN
                RAISE EXCEPTION
                    '007 owner normalization blocked: provenance state contract is not the reviewed contract';
            END IF;
            FOR table_row IN
                SELECT format('%I.%I', n.nspname, c.relname) AS qualified_name
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p')
                  AND c.relname = ANY(allowed_table_names)
                  AND c.relname <> ALL(provenance_relation_names)
            LOOP
                EXECUTE format(
                    'ALTER TABLE %s OWNER TO %I',
                    table_row.qualified_name, '{MIGRATION_ROLE}'
                );
            END LOOP;
            FOR sequence_row IN
                SELECT format('%I.%I', n.nspname, c.relname) AS qualified_name
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind = 'S'
                  AND c.relname = ANY(allowed_sequence_names)
            LOOP
                EXECUTE format(
                    'ALTER SEQUENCE %s OWNER TO %I',
                    sequence_row.qualified_name, '{MIGRATION_ROLE}'
                );
            END LOOP;
            IF EXISTS (
                SELECT 1
                FROM pg_proc AS p
                JOIN pg_namespace AS n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public'
                  AND p.prosecdef
                  AND NOT EXISTS (
                      SELECT 1
                      FROM unnest(allowed_routine_signatures) AS signature
                      WHERE to_regprocedure(signature) = p.oid
                  )
            ) THEN
                RAISE EXCEPTION
                    '007 owner normalization blocked: unexpected SECURITY DEFINER routine exists';
            END IF;
            FOR routine_row IN
                SELECT p.oid::regprocedure AS signature,
                       owner_role.rolname AS owner_name
                FROM pg_proc AS p
                JOIN pg_namespace AS n ON n.oid = p.pronamespace
                JOIN pg_roles AS owner_role ON owner_role.oid = p.proowner
                WHERE n.nspname = 'public'
                  AND EXISTS (
                      SELECT 1
                      FROM unnest(allowed_routine_signatures) AS signature
                      WHERE to_regprocedure(signature) = p.oid
                  )
            LOOP
                IF routine_row.owner_name <> '{MIGRATION_ROLE}' THEN
                    EXECUTE format(
                        'ALTER FUNCTION %s OWNER TO %I',
                        routine_row.signature, '{MIGRATION_ROLE}'
                    );
                END IF;
            END LOOP;
        END
        $routine_owner$ LANGUAGE plpgsql;

        -- Catalog-level drift tripwire: every public SECURITY DEFINER routine
        -- must be in the same explicit reviewed allowlist.
        DO $catalog_acl$
        DECLARE
            routine_row RECORD;
            table_row RECORD;
            allowed_routine_signatures CONSTANT TEXT[] := ARRAY[
                'reject_evidence_index_mutation()',
                'reject_longspan_evidence_mutation()',
                'reject_longspan_auditor_mutation()',
                'reject_longspan_evidence_truncate()',
                'reject_longspan_auditor_truncate()',
                'reject_longspan_terra_mutation()',
                'reject_longspan_terra_truncate()',
                'reject_longspan_authority_mutation()',
                'reject_longspan_authority_history_mutation()',
                'reject_longspan_append_only_mutation()',
                'reject_longspan_terra_attestation_mutation()',
                'reject_longspan_legacy_watermark()',
                'reject_longspan_legacy_attestation_mutation()',
                'reject_longspan_execution_audit_mutation()',
                'reject_longspan_migration_provenance_008_archive_mutation()',
                'reject_challenge_direct_mutation()',
                'require_longspan_mutation_scope()'
            ];
        BEGIN
            FOR routine_row IN
                SELECT p.oid::regprocedure AS signature,
                       owner_role.rolname AS owner_name
                FROM pg_proc AS p
                JOIN pg_namespace AS n ON n.oid = p.pronamespace
                JOIN pg_roles AS owner_role ON owner_role.oid = p.proowner
                WHERE n.nspname = 'public'
                  AND p.prosecdef
                  AND EXISTS (
                      SELECT 1
                      FROM unnest(allowed_routine_signatures) AS signature
                      WHERE to_regprocedure(signature) = p.oid
                  )
            LOOP
                IF routine_row.owner_name <> '{MIGRATION_ROLE}' THEN
                    RAISE EXCEPTION
                        '007 owner audit failed: SECURITY DEFINER routine % is owned by %',
                        routine_row.signature, routine_row.owner_name;
                END IF;
                IF has_function_privilege('public', routine_row.signature, 'EXECUTE') THEN
                    RAISE EXCEPTION
                        '007 ACL audit failed: SECURITY DEFINER routine % is executable by PUBLIC',
                        routine_row.signature;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ATTACKER_ROLE}')
                   AND has_function_privilege('{ATTACKER_ROLE}', routine_row.signature, 'EXECUTE') THEN
                    RAISE EXCEPTION
                        '007 ACL audit failed: SECURITY DEFINER routine % is executable by attacker role',
                        routine_row.signature;
                END IF;
            END LOOP;
            FOR table_row IN
                SELECT format('%I.%I', n.nspname, c.relname) AS qualified_name
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p')
                  AND (
                      c.relname IN (
                          'controller_control', 'supervisor_runs', 'parent_tasks',
                          'task_attempts', 'retry_queue', 'supervisor_events',
                          'longspan_children', 'longspan_plans',
                          'longspan_execution_results', 'longspan_experiments',
                          'evidence_index', 'manifest_submissions', 'signal_status',
                          'provenance_records', 'notifications',
                          'longspan_authority_config', 'longspan_authority_history',
                          'longspan_operator_challenges', 'longspan_authority_receipts',
                          'longspan_terra_receipt_attestations',
                          'longspan_evidence_ledger', 'longspan_execution_audits',
                          'longspan_execution_evidence',
                          'longspan_auditor_receipts', 'longspan_terra_receipts',
                          'longspan_ledger_legacy_attestations',
                          'longspan_mac_material', 'longspan_mac_key_history'
                      )
                  )
            LOOP
                IF has_table_privilege('public', table_row.qualified_name, 'INSERT')
                   OR has_table_privilege('public', table_row.qualified_name, 'UPDATE')
                   OR has_table_privilege('public', table_row.qualified_name, 'DELETE') THEN
                    RAISE EXCEPTION
                        '007 ACL audit failed: protected table % is writable by PUBLIC',
                        table_row.qualified_name;
                END IF;
            END LOOP;
        END
        $catalog_acl$ LANGUAGE plpgsql;
        """
    )


def downgrade() -> None:
    verify_migration_source_anchor(
        revision,
        source_path=__file__,
        anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH,
    )
    assert_migration_catalog(revision)
    from disposable_capability import require_connected_migration_downgrade

    require_connected_migration_downgrade(revision=revision)
    op.execute(
        f"""
        DO $guard$
        DECLARE
            db_name TEXT;
            capability_nonce TEXT;
            capability_database_name TEXT;
            capability_database_role TEXT;
            capability_transport_database_role TEXT;
            capability_controller_service TEXT;
            capability_operation TEXT;
            capability_migration_revision TEXT;
        BEGIN
            SELECT current_database() INTO db_name;
            IF db_name !~ '^td_test_' AND db_name !~ '^td_downgrade_' THEN
                RAISE EXCEPTION '007 downgrade blocked: database % is not disposable', db_name;
            END IF;
            IF to_regclass('public.top_delivery_downgrade_capabilities') IS NULL THEN
                RAISE EXCEPTION '007 downgrade blocked: signed disposable capability sentinel/witness is missing';
            END IF;
            SELECT nonce, database_name, database_role, transport_database_role,
                   controller_service,
                   operation, migration_revision
            INTO capability_nonce, capability_database_name,
                 capability_database_role, capability_transport_database_role,
                 capability_controller_service,
                 capability_operation, capability_migration_revision
            FROM top_delivery_downgrade_capabilities
            WHERE database_name = current_database()
              AND database_role = current_user
              AND controller_service = '{CONTROLLER_SERVICE}'
              AND operation IN ('migration_downgrade', 'disposable_downgrade')
              AND migration_revision IN (
                  '006_longspan_authority', '005_longspan_hardening',
                  '004_longspan_workflow'
              )
              AND expires_at > clock_timestamp()
              AND NOT ('007_longspan_authority_hardening' = ANY(consumed_steps))
            ORDER BY issued_at DESC
            LIMIT 1
            FOR UPDATE;
            IF capability_nonce IS NULL
               OR capability_database_name IS DISTINCT FROM db_name
               OR capability_database_role IS DISTINCT FROM current_user
               OR capability_transport_database_role IS DISTINCT FROM session_user
               OR capability_transport_database_role NOT IN ('root', 'postgres', '{MIGRATION_ROLE}')
               OR capability_controller_service IS DISTINCT FROM '{CONTROLLER_SERVICE}'
               OR capability_operation NOT IN ('migration_downgrade', 'disposable_downgrade')
               OR capability_migration_revision NOT IN (
                   '006_longspan_authority', '005_longspan_hardening',
                   '004_longspan_workflow'
               ) THEN
                RAISE EXCEPTION '007 downgrade blocked: signed disposable capability sentinel/witness is invalid';
            END IF;
            UPDATE top_delivery_downgrade_capabilities
            SET consumed_at = clock_timestamp(),
                consumed_steps = array_append(
                    consumed_steps, '007_longspan_authority_hardening'
                )
            WHERE nonce = capability_nonce
              AND database_name = db_name
              AND database_role = current_user
              AND transport_database_role = session_user
              AND controller_service = '{CONTROLLER_SERVICE}'
              AND operation = capability_operation
              AND migration_revision = capability_migration_revision
              AND NOT ('007_longspan_authority_hardening' = ANY(consumed_steps));
            -- Root is not an approved migration principal.  A root peer-auth
            -- session is accepted only when the exact signed capability row
            -- selected above binds the current disposable target and user.
            IF current_user NOT IN ('{MIGRATION_ROLE}', 'postgres') THEN
                RAISE EXCEPTION
                    '007 downgrade blocked: connected principal is not an approved migration role';
            END IF;
            -- The transport session must have explicitly entered the pinned
            -- migration role before this guard is reached.  A postgres/root
            -- peer session is not allowed to satisfy the effective-role gate.
            IF current_user <> '{MIGRATION_ROLE}' THEN
                RAISE EXCEPTION
                    '007 downgrade blocked: connected principal is not an approved migration role';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_authority_config LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: authority configuration exists';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_authority_history LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: authority history exists';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_authority_receipts LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: authority receipts exist';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_operator_challenges LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: operator challenges exist';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_evidence_ledger LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: evidence ledger is populated';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_execution_audits LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: execution audits exist';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_execution_results LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: execution results exist';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_execution_evidence LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: execution evidence exists';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_auditor_receipts LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: auditor receipts exist';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_terra_receipts LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: terra receipts exist';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_terra_receipt_attestations LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: Terra receipt attestations exist';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_mac_material LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: current MAC material exists';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_mac_key_history LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: historical MAC material exists';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_ledger_legacy_attestations LIMIT 1) THEN
                RAISE EXCEPTION '007 downgrade blocked: legacy ledger attestations exist';
            END IF;
        END
        $guard$ LANGUAGE plpgsql;

        DROP FUNCTION IF EXISTS longspan_append_authority_history(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_rotate_authority_config(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_insert_authority_config(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_assert_authority_write(TEXT, TEXT, TEXT, TEXT, INTEGER);
        DROP FUNCTION IF EXISTS longspan_authority_content_digest(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, INTEGER, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_assert_child_capability(TEXT, INTEGER, TEXT, TEXT);
        DROP FUNCTION IF EXISTS longspan_assert_controller_maintenance_scope(TEXT, TEXT);
        DROP FUNCTION IF EXISTS longspan_verify_ledger_entry(
            TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_append_terra_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_terra_gateway_mac(
            TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER,
            TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_terra_gateway_mac_for_attestation(TEXT);
        DROP FUNCTION IF EXISTS longspan_append_auditor_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_store_execution_evidence(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_insert_execution_result(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_append_execution_audit(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_append_evidence_ledger(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_install_ledger_mac_key(TEXT);
        DROP FUNCTION IF EXISTS longspan_install_terra_gateway_mac_key(TEXT);
        DROP FUNCTION IF EXISTS longspan_issue_terra_receipt_attestation(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_consume_terra_receipt_attestation(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_bind_and_consume_challenge(TEXT, TEXT, TEXT);
        DROP FUNCTION IF EXISTS longspan_create_operator_challenge(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER, TEXT, INTEGER, INTEGER, INTEGER
        );
        DROP FUNCTION IF EXISTS longspan_acquire_controller(TEXT, TEXT, DOUBLE PRECISION, BIGINT, BOOLEAN);
        DROP FUNCTION IF EXISTS longspan_open_mutation_scope(TEXT, INTEGER, BIGINT);
        DROP FUNCTION IF EXISTS longspan_open_controller_mutation_scope(TEXT, INTEGER, BIGINT, TEXT, TEXT);
        DROP FUNCTION IF EXISTS longspan_open_controller_mutation_scope(TEXT, INTEGER, BIGINT, TEXT);
        DROP FUNCTION IF EXISTS longspan_current_controller_fence(TEXT, INTEGER, TEXT);
        DROP FUNCTION IF EXISTS longspan_park_children(TEXT, INTEGER, TEXT);
        DROP FUNCTION IF EXISTS longspan_park_children(TEXT, INTEGER, TEXT, BIGINT);
        DROP FUNCTION IF EXISTS longspan_expire_stale_children(TEXT, INTEGER, TEXT);
        DROP FUNCTION IF EXISTS longspan_expire_stale_children(TEXT, INTEGER, TEXT, BIGINT);
        DROP FUNCTION IF EXISTS longspan_open_signal_scope(TEXT, INTEGER);
        DROP FUNCTION IF EXISTS longspan_open_rollback_signal_scope(TEXT, INTEGER);
        DROP FUNCTION IF EXISTS longspan_register_run(TEXT, TEXT);
        DROP FUNCTION IF EXISTS longspan_next_event_seq(TEXT, BIGINT);
        DROP FUNCTION IF EXISTS longspan_disable_controller(TEXT, BIGINT);
        DROP FUNCTION IF EXISTS longspan_test_expire_controller_lease(TEXT);

        DROP TRIGGER IF EXISTS longspan_operator_challenges_guard ON longspan_operator_challenges;
        DROP TRIGGER IF EXISTS longspan_authority_receipts_append_only ON longspan_authority_receipts;
        DROP TRIGGER IF EXISTS longspan_terra_attestation_guard
            ON longspan_terra_receipt_attestations;
        DROP TRIGGER IF EXISTS longspan_terra_receipts_append_only ON longspan_terra_receipts;
        DROP TRIGGER IF EXISTS longspan_auditor_receipts_append_only ON longspan_auditor_receipts;
        DROP TRIGGER IF EXISTS longspan_execution_audits_append_only ON longspan_execution_audits;
        DROP TRIGGER IF EXISTS longspan_execution_evidence_append_only
            ON longspan_execution_evidence;
        DROP TRIGGER IF EXISTS longspan_evidence_ledger_append_only ON longspan_evidence_ledger;
        DROP TRIGGER IF EXISTS longspan_evidence_legacy_watermark ON longspan_evidence_ledger;
        DROP TRIGGER IF EXISTS longspan_legacy_attestation_guard
            ON longspan_ledger_legacy_attestations;
        DROP TRIGGER IF EXISTS supervisor_run_scope_guard ON supervisor_runs;
        DROP TRIGGER IF EXISTS controller_scope_guard ON controller_control;
        DROP TRIGGER IF EXISTS parent_task_scope_guard ON parent_tasks;
        DROP TRIGGER IF EXISTS task_attempt_scope_guard ON task_attempts;
        DROP TRIGGER IF EXISTS retry_queue_scope_guard ON retry_queue;
        DROP TRIGGER IF EXISTS supervisor_event_scope_guard ON supervisor_events;
        DROP TRIGGER IF EXISTS longspan_child_scope_guard ON longspan_children;
        DROP TRIGGER IF EXISTS longspan_plan_scope_guard ON longspan_plans;
        DROP TRIGGER IF EXISTS longspan_result_scope_guard ON longspan_execution_results;
        DROP TRIGGER IF EXISTS longspan_experiment_scope_guard ON longspan_experiments;
        DROP TRIGGER IF EXISTS evidence_index_scope_guard ON evidence_index;
        DROP TRIGGER IF EXISTS manifest_submission_scope_guard ON manifest_submissions;
        DROP TRIGGER IF EXISTS signal_status_scope_guard ON signal_status;
        DROP TRIGGER IF EXISTS provenance_scope_guard ON provenance_records;
        DROP TRIGGER IF EXISTS notification_scope_guard ON notifications;
        DROP TRIGGER IF EXISTS longspan_authority_history_no_update ON longspan_authority_history;
        DROP TRIGGER IF EXISTS longspan_authority_no_delete ON longspan_authority_config;

        -- Scope triggers must be removed before their trigger function.
        DROP TRIGGER IF EXISTS controller_scope_guard ON controller_control;
        DROP TRIGGER IF EXISTS parent_task_scope_guard ON parent_tasks;
        DROP TRIGGER IF EXISTS task_attempt_scope_guard ON task_attempts;
        DROP TRIGGER IF EXISTS retry_queue_scope_guard ON retry_queue;
        DROP TRIGGER IF EXISTS supervisor_event_scope_guard ON supervisor_events;
        DROP TRIGGER IF EXISTS longspan_child_scope_guard ON longspan_children;
        DROP TRIGGER IF EXISTS longspan_plan_scope_guard ON longspan_plans;
        DROP TRIGGER IF EXISTS longspan_result_scope_guard ON longspan_execution_results;
        DROP TRIGGER IF EXISTS longspan_experiment_scope_guard ON longspan_experiments;
        DROP TRIGGER IF EXISTS evidence_index_scope_guard ON evidence_index;
        DROP TRIGGER IF EXISTS manifest_submission_scope_guard ON manifest_submissions;
        DROP TRIGGER IF EXISTS signal_status_scope_guard ON signal_status;
        DROP TRIGGER IF EXISTS provenance_scope_guard ON provenance_records;
        DROP TRIGGER IF EXISTS notification_scope_guard ON notifications;
        DROP FUNCTION IF EXISTS require_longspan_mutation_scope();

        DROP FUNCTION IF EXISTS reject_challenge_direct_mutation();
        DROP FUNCTION IF EXISTS reject_longspan_append_only_mutation();
        DROP FUNCTION IF EXISTS reject_longspan_terra_attestation_mutation();
        DROP FUNCTION IF EXISTS reject_longspan_legacy_watermark();
        DROP FUNCTION IF EXISTS reject_longspan_legacy_attestation_mutation();
        DROP FUNCTION IF EXISTS reject_longspan_authority_history_mutation();
        DROP FUNCTION IF EXISTS reject_longspan_authority_mutation();

        DROP TABLE IF EXISTS longspan_mac_material;
        DROP TABLE IF EXISTS longspan_mac_key_history;
        DROP TABLE IF EXISTS longspan_ledger_legacy_attestations;
        DROP TABLE IF EXISTS longspan_authority_receipts;
        DROP TABLE IF EXISTS longspan_terra_receipt_attestations;
        DROP INDEX IF EXISTS longspan_evidence_ledger_child_seq_uq;
        DROP INDEX IF EXISTS longspan_auditor_receipts_child_attempt_uq;

        ALTER TABLE longspan_terra_receipts
            DROP CONSTRAINT IF EXISTS longspan_terra_receipts_binding_chk,
            ALTER COLUMN reviewed_sha DROP NOT NULL,
            ALTER COLUMN task_id DROP NOT NULL,
            ALTER COLUMN run_id DROP NOT NULL,
            DROP COLUMN IF EXISTS signature,
            DROP COLUMN IF EXISTS authority_signature,
            DROP COLUMN IF EXISTS result_digest,
            DROP COLUMN IF EXISTS evidence_digest,
            DROP COLUMN IF EXISTS authority_version,
            DROP COLUMN IF EXISTS migration_head,
            DROP COLUMN IF EXISTS request_digest,
            DROP COLUMN IF EXISTS source_digest,
            DROP COLUMN IF EXISTS tree_sha,
            DROP COLUMN IF EXISTS lease_token_hash,
            DROP COLUMN IF EXISTS controller_epoch,
            DROP COLUMN IF EXISTS fence_token;
        -- attempt_number remains: owned by 005_longspan_hardening

        DROP TABLE IF EXISTS longspan_operator_challenges;
        DROP TABLE IF EXISTS longspan_execution_evidence;
        DROP TABLE IF EXISTS longspan_execution_audits;
        -- The 006 compatibility boundary retains the legacy execution-audit
        -- contract.  007's evidence-bound audit table is empty by the guard
        -- above, so rebuilding it here cannot discard rows.
        CREATE TABLE longspan_execution_audits (
            audit_id TEXT PRIMARY KEY,
            child_id TEXT NOT NULL REFERENCES longspan_children(child_id),
            attempt_number INTEGER NOT NULL,
            request_digest TEXT NOT NULL,
            result_digest TEXT NOT NULL,
            validation_outcome TEXT NOT NULL,
            raw_result_ref TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (child_id, attempt_number),
            CHECK (attempt_number >= 0),
            CHECK (btrim(request_digest) <> ''),
            CHECK (btrim(result_digest) <> ''),
            CHECK (btrim(validation_outcome) <> '')
        );
        ALTER TABLE longspan_execution_audits OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON longspan_execution_audits FROM PUBLIC;
        CREATE OR REPLACE FUNCTION reject_longspan_execution_audit_mutation()
        RETURNS trigger AS $legacy_execution_audit_guard$
        BEGIN
            RAISE EXCEPTION 'longspan_execution_audits is append-only';
        END;
        $legacy_execution_audit_guard$ LANGUAGE plpgsql;
        DROP TRIGGER IF EXISTS longspan_execution_audits_append_only
            ON longspan_execution_audits;
        CREATE TRIGGER longspan_execution_audits_append_only
            BEFORE UPDATE OR DELETE ON longspan_execution_audits
            FOR EACH ROW EXECUTE FUNCTION reject_longspan_execution_audit_mutation();
        DROP TABLE IF EXISTS longspan_authority_history;

        ALTER TABLE longspan_authority_config
            DROP CONSTRAINT IF EXISTS longspan_authority_config_nonempty_chk,
            DROP COLUMN IF EXISTS approval_receipt_digest,
            DROP COLUMN IF EXISTS config_version,
            DROP COLUMN IF EXISTS source_digest,
            DROP COLUMN IF EXISTS tree_sha;

        ALTER TABLE longspan_evidence_ledger
            DROP COLUMN IF EXISTS mac_key_version,
            DROP COLUMN IF EXISTS legacy_unkeyed,
            DROP COLUMN IF EXISTS base_digest,
            DROP COLUMN IF EXISTS sequence_number;

        ALTER TABLE longspan_auditor_receipts
            DROP COLUMN IF EXISTS evidence_digest;

        -- Restore the complete legacy 006 execution-audit contract.  These
        -- routines intentionally use only 004-006 catalog objects because a
        -- downgrade must leave the recorded 006 revision executable and must
        -- not retain references to 007-only evidence or authority columns.
        CREATE OR REPLACE FUNCTION longspan_append_execution_audit(
            p_audit_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_request_digest TEXT,
            p_result_digest TEXT,
            p_validation_outcome TEXT,
            p_raw_result_ref TEXT,
            p_executor_capability_token TEXT
        ) RETURNS VOID AS $legacy_execution_audit$
        DECLARE
            child_attempt INTEGER;
            child_state TEXT;
            lease_expires_at TIMESTAMPTZ;
            stored_hash TEXT;
            supplied_hash TEXT;
            already_exists BOOLEAN;
        BEGIN
            EXECUTE 'SELECT attempt_number, state, lease_expires_at, executor_capability_hash '
                    'FROM longspan_children WHERE child_id = $1 FOR UPDATE'
                INTO child_attempt, child_state, lease_expires_at, stored_hash
                USING p_child_id;
            IF child_attempt IS NULL THEN
                RAISE EXCEPTION 'execution audit child not found';
            END IF;
            IF child_attempt <> p_attempt_number THEN
                RAISE EXCEPTION 'execution audit attempt does not match child attempt';
            END IF;
            IF child_state NOT IN ('executing', 'executed') THEN
                RAISE EXCEPTION 'execution audit is outside the execution state';
            END IF;
            IF lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'capability lease is expired';
            END IF;
            IF btrim(p_request_digest) = '' OR btrim(p_result_digest) = '' THEN
                RAISE EXCEPTION 'execution audit digests are required';
            END IF;
            EXECUTE 'SELECT encode(digest(convert_to($1, ''UTF8''), ''sha256''), ''hex'')'
                INTO supplied_hash
                USING p_executor_capability_token;
            IF p_executor_capability_token IS NULL
               OR btrim(p_executor_capability_token) = ''
               OR stored_hash IS NULL
               OR supplied_hash IS DISTINCT FROM stored_hash THEN
                RAISE EXCEPTION 'executor capability token is not bound to this child attempt';
            END IF;
            EXECUTE 'SELECT EXISTS (SELECT 1 FROM longspan_execution_audits '
                    'WHERE child_id = $1 AND attempt_number = $2)'
                INTO already_exists
                USING p_child_id, p_attempt_number;
            IF already_exists THEN
                RAISE EXCEPTION 'execution audit already recorded';
            END IF;
            EXECUTE 'INSERT INTO longspan_execution_audits '
                    '(audit_id, child_id, attempt_number, request_digest, result_digest, '
                    ' validation_outcome, raw_result_ref) '
                    'VALUES ($1, $2, $3, $4, $5, $6, $7)'
                USING p_audit_id, p_child_id, p_attempt_number, p_request_digest,
                      p_result_digest, p_validation_outcome, p_raw_result_ref;
        END;
        $legacy_execution_audit$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

        -- 006 exposed a VOID-returning Terra receipt routine.  Keep the
        -- complete 21-argument call signature so a 006 application cannot
        -- accidentally bind to a 007-only overload.  Only the columns and
        -- contracts that exist at the 006 boundary are consulted here.
        CREATE OR REPLACE FUNCTION longspan_append_terra_receipt(
            p_receipt_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_reviewer TEXT,
            p_decision TEXT,
            p_evidence_chain_head TEXT,
            p_receipt_digest TEXT,
            p_run_id TEXT,
            p_task_id TEXT,
            p_reviewed_sha TEXT,
            p_fence_token BIGINT,
            p_controller_epoch INTEGER,
            p_tree_sha TEXT,
            p_source_digest TEXT,
            p_request_digest TEXT,
            p_migration_head TEXT,
            p_authority_version INTEGER,
            p_evidence_digest TEXT,
            p_result_digest TEXT,
            p_signature TEXT,
            p_terra_auth_token TEXT
        ) RETURNS VOID AS $legacy_terra_receipt$
        DECLARE
            child_run TEXT;
            child_task TEXT;
            child_attempt INTEGER;
            child_state TEXT;
            child_fence BIGINT;
            lease_expires_at TIMESTAMPTZ;
            authority_reviewed_sha TEXT;
            authority_hash TEXT;
            supplied_hash TEXT;
            expected_epoch INTEGER;
            actual_head TEXT;
            already_exists BOOLEAN;
        BEGIN
            EXECUTE 'SELECT run_id, task_id, attempt_number, state, fence_token, lease_expires_at '
                    'FROM longspan_children WHERE child_id = $1 FOR UPDATE'
                INTO child_run, child_task, child_attempt, child_state,
                     child_fence, lease_expires_at
                USING p_child_id;
            IF child_run IS NULL THEN
                RAISE EXCEPTION 'terra receipt child not found';
            END IF;
            IF child_run IS DISTINCT FROM p_run_id OR child_task IS DISTINCT FROM p_task_id THEN
                RAISE EXCEPTION 'terra receipt run/task scope mismatch';
            END IF;
            IF child_attempt IS DISTINCT FROM p_attempt_number THEN
                RAISE EXCEPTION 'terra receipt attempt mismatch';
            END IF;
            IF child_fence IS DISTINCT FROM p_fence_token THEN
                RAISE EXCEPTION 'terra receipt fence mismatch';
            END IF;
            IF child_state NOT IN ('terra_pending', 'terra_approved', 'terra_rejected') THEN
                RAISE EXCEPTION 'terra receipt is outside the Terra review state';
            END IF;
            IF lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'capability lease is expired';
            END IF;
            expected_epoch := NULLIF(
                current_setting('top_delivery.controller_epoch', true), ''
            )::INTEGER;
            IF expected_epoch IS NULL OR expected_epoch IS DISTINCT FROM p_controller_epoch THEN
                RAISE EXCEPTION 'terra receipt controller epoch mismatch';
            END IF;
            SELECT terra_auth_hash, reviewed_sha
                INTO authority_hash, authority_reviewed_sha
            FROM longspan_authority_config
            WHERE run_id = p_run_id;
            IF authority_hash IS NULL THEN
                RAISE EXCEPTION 'terra receipt requires authority configuration';
            END IF;
            IF authority_reviewed_sha IS DISTINCT FROM p_reviewed_sha THEN
                RAISE EXCEPTION 'terra receipt reviewed-SHA provenance mismatch';
            END IF;
            EXECUTE 'SELECT encode(digest(convert_to($1, ''UTF8''), ''sha256''), ''hex'')'
                INTO supplied_hash
                USING p_terra_auth_token;
            IF p_terra_auth_token IS NULL OR btrim(p_terra_auth_token) = ''
               OR supplied_hash IS DISTINCT FROM authority_hash THEN
                RAISE EXCEPTION 'terra capability token is not bound to this run';
            END IF;
            IF p_decision NOT IN ('approved', 'rejected') THEN
                RAISE EXCEPTION 'terra receipt decision invalid';
            END IF;
            IF btrim(p_evidence_chain_head) = '' OR btrim(p_receipt_digest) = '' THEN
                RAISE EXCEPTION 'terra receipt digests are required';
            END IF;
            IF p_migration_head IS DISTINCT FROM '006_longspan_authority' THEN
                RAISE EXCEPTION 'terra receipt migration head is not the 006 head';
            END IF;
            EXECUTE 'SELECT entry_hash FROM longspan_evidence_ledger '
                    'WHERE child_id = $1 ORDER BY created_at DESC, entry_id DESC LIMIT 1'
                INTO actual_head
                USING p_child_id;
            IF actual_head IS NULL OR actual_head IS DISTINCT FROM p_evidence_chain_head THEN
                RAISE EXCEPTION 'terra receipt evidence chain head is not persisted';
            END IF;
            EXECUTE 'SELECT EXISTS (SELECT 1 FROM longspan_auditor_receipts '
                    'WHERE child_id = $1 AND attempt_number = $2 AND verdict = ''pass'')'
                INTO already_exists
                USING p_child_id, p_attempt_number;
            IF NOT already_exists THEN
                RAISE EXCEPTION 'terra receipt requires auditor pass';
            END IF;
            EXECUTE 'SELECT EXISTS (SELECT 1 FROM longspan_terra_receipts '
                    'WHERE child_id = $1 AND attempt_number = $2)'
                INTO already_exists
                USING p_child_id, p_attempt_number;
            IF already_exists THEN
                RAISE EXCEPTION 'terra receipt already recorded';
            END IF;
            EXECUTE 'INSERT INTO longspan_terra_receipts '
                    '(receipt_id, child_id, attempt_number, reviewer, decision, '
                    ' evidence_chain_head, receipt_digest, run_id, task_id, reviewed_sha) '
                    'VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)'
                USING p_receipt_id, p_child_id, p_attempt_number, p_reviewer,
                      p_decision, p_evidence_chain_head, p_receipt_digest,
                      p_run_id, p_task_id, p_reviewed_sha;
        END;
        $legacy_terra_receipt$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

        -- 006-compatible auditor receipt contract.  The 007 evidence-bound
        -- nine-argument routine is gone at this point; restore the legacy
        -- eight-argument routine and its capability check so a downgrade
        -- never leaves a callable 007-only overload behind.
        CREATE OR REPLACE FUNCTION longspan_append_auditor_receipt(
            p_receipt_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_verdict TEXT,
            p_reasons_json TEXT,
            p_inspector_digest TEXT,
            p_receipt_digest TEXT,
            p_auditor_capability_token TEXT
        ) RETURNS VOID AS $$
        DECLARE
            child_attempt INTEGER;
            child_state TEXT;
            lease_expires_at TIMESTAMPTZ;
            stored_hash TEXT;
            supplied_hash TEXT;
            already_exists BOOLEAN;
        BEGIN
            -- Dynamic SQL deliberately keeps this compatibility routine
            -- independent of 007-only catalog dependencies.  It is valid at
            -- the 006 schema boundary and can therefore be removed cleanly
            -- by a subsequent 006->005/004 downgrade.
            EXECUTE 'SELECT attempt_number, state, lease_expires_at, auditor_capability_hash '
                    'FROM longspan_children WHERE child_id = $1 FOR UPDATE'
                INTO child_attempt, child_state, lease_expires_at, stored_hash
                USING p_child_id;
            IF child_attempt IS NULL THEN
                RAISE EXCEPTION 'auditor receipt child not found';
            END IF;
            IF child_attempt <> p_attempt_number THEN
                RAISE EXCEPTION 'auditor receipt attempt mismatch';
            END IF;
            IF child_state NOT IN ('executed', 'terra_pending', 'needs_remediation') THEN
                RAISE EXCEPTION 'auditor evidence is outside the executed state';
            END IF;
            IF lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'capability lease is expired';
            END IF;
            EXECUTE 'SELECT encode(digest(convert_to($1, ''UTF8''), ''sha256''), ''hex'')'
                INTO supplied_hash
                USING p_auditor_capability_token;
            IF p_auditor_capability_token IS NULL OR btrim(p_auditor_capability_token) = ''
               OR stored_hash IS NULL OR supplied_hash IS DISTINCT FROM stored_hash THEN
                RAISE EXCEPTION 'auditor capability token is not bound to this child attempt';
            END IF;
            IF p_verdict NOT IN ('pass', 'fail') THEN
                RAISE EXCEPTION 'auditor receipt verdict invalid';
            END IF;
            IF btrim(p_inspector_digest) = '' OR btrim(p_receipt_digest) = '' THEN
                RAISE EXCEPTION 'auditor receipt digests are required';
            END IF;
            EXECUTE 'SELECT EXISTS (SELECT 1 FROM longspan_auditor_receipts '
                    'WHERE child_id = $1 AND attempt_number = $2)'
                INTO already_exists
                USING p_child_id, p_attempt_number;
            IF already_exists THEN
                RAISE EXCEPTION 'auditor receipt already recorded';
            END IF;
            EXECUTE 'INSERT INTO longspan_auditor_receipts '
                    '(receipt_id, child_id, attempt_number, verdict, reasons_json, '
                    ' inspector_digest, receipt_digest) '
                    'VALUES ($1, $2, $3, $4, $5, $6, $7)'
                USING p_receipt_id, p_child_id, p_attempt_number, p_verdict,
                      p_reasons_json, p_inspector_digest, p_receipt_digest;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        DO $attacker_table_acl$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ATTACKER_ROLE}') THEN
                EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {ATTACKER_ROLE}';
            END IF;
        END
        $attacker_table_acl$ LANGUAGE plpgsql;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        REVOKE USAGE ON SCHEMA public FROM {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        REVOKE ALL ON FUNCTION longspan_append_auditor_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION longspan_append_execution_audit(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION longspan_append_terra_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION reject_longspan_execution_audit_mutation() FROM PUBLIC;
        REVOKE INSERT, UPDATE, DELETE ON longspan_execution_audits
            FROM {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        """
    )
