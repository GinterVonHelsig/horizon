"""Persist Longspan Terra/operator authority and bind terra receipts.

Revision ID: 006_longspan_authority
Revises: 005_longspan_hardening
Create Date: 2026-08-12
"""

from __future__ import annotations

from alembic import op
from migration_catalog import assert_migration_catalog
from authority_pins import (
    ATTACKER_DATABASE_ROLE,
    AUTHORITY_DATABASE_ROLE,
    MIGRATION_DATABASE_ROLE,
    MIGRATION_SOURCE_PROVENANCE_PATH,
    WORKFLOW_DATABASE_ROLE,
)
from migration_source_anchor import verify_migration_source_anchor


revision = "006_longspan_authority"
down_revision = "005_longspan_hardening"
branch_labels = None
depends_on = None

MIGRATION_ROLE = MIGRATION_DATABASE_ROLE
WORKFLOW_ROLE = WORKFLOW_DATABASE_ROLE
AUTHORITY_ROLE = AUTHORITY_DATABASE_ROLE
ATTACKER_ROLE = ATTACKER_DATABASE_ROLE
CONTROLLER_SERVICE = "top-delivery-controller"
LEGACY_UNBOUND_TRANSPORT_ROLE = "__legacy_unbound__"


def upgrade() -> None:
    verify_migration_source_anchor(
        revision,
        source_path=__file__,
        anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH,
    )
    assert_migration_catalog(revision)
    op.execute(
        f"""
        CREATE TABLE IF NOT EXISTS longspan_authority_config (
            run_id TEXT PRIMARY KEY REFERENCES supervisor_runs(run_id),
            terra_auth_hash TEXT NOT NULL,
            operator_auth_hash TEXT NOT NULL,
            reviewed_sha TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );

        -- Database-owned downgrade capability ledger.  env.py inserts a
        -- verified, connected capability before a downgrade; the SQL guards
        -- consume the row transactionally.  Runtime roles have no privileges.
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
        ALTER TABLE top_delivery_downgrade_capabilities
            OWNER TO {MIGRATION_ROLE};
        ALTER TABLE top_delivery_downgrade_capabilities
            ADD COLUMN IF NOT EXISTS consumed_steps TEXT[]
                NOT NULL DEFAULT ARRAY[]::TEXT[];
        ALTER TABLE top_delivery_downgrade_capabilities
            ADD COLUMN IF NOT EXISTS transport_database_role TEXT;
        UPDATE top_delivery_downgrade_capabilities
        SET transport_database_role = '{LEGACY_UNBOUND_TRANSPORT_ROLE}'
        WHERE transport_database_role IS NULL;
        ALTER TABLE top_delivery_downgrade_capabilities
            ALTER COLUMN transport_database_role SET NOT NULL;
        -- Historical rows created before transport binding may retain the
        -- sentinel, but NOT VALID still rejects that sentinel for every new
        -- capability or update.  A caller can never issue a fresh
        -- self-authorized capability with an unbound transport role.
        DO $transport_role_constraint$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conrelid = 'top_delivery_downgrade_capabilities'::regclass
                  AND conname = 'downgrade_capability_transport_role_bound'
            ) THEN
                ALTER TABLE top_delivery_downgrade_capabilities
                    ADD CONSTRAINT downgrade_capability_transport_role_bound
                    CHECK (transport_database_role <> '__legacy_unbound__') NOT VALID;
            END IF;
        END
        $transport_role_constraint$;
        REVOKE ALL ON top_delivery_downgrade_capabilities FROM PUBLIC;
        GRANT SELECT, INSERT, UPDATE ON top_delivery_downgrade_capabilities
            TO {MIGRATION_ROLE};

        ALTER TABLE longspan_terra_receipts
            ADD COLUMN IF NOT EXISTS run_id TEXT,
            ADD COLUMN IF NOT EXISTS task_id TEXT,
            ADD COLUMN IF NOT EXISTS reviewed_sha TEXT;

        UPDATE longspan_terra_receipts AS receipt
        SET run_id = child.run_id,
            task_id = child.task_id,
            reviewed_sha = COALESCE(config.reviewed_sha, '')
        FROM longspan_children AS child
        LEFT JOIN longspan_authority_config AS config
            ON config.run_id = child.run_id
        WHERE receipt.child_id = child.child_id
          AND receipt.run_id IS NULL;

        -- The connected downgrade guard executes under the pinned migration
        -- role.  Bind every 006-owned relation it reads, alters, or drops to
        -- that role while the administrative transport still has authority;
        -- otherwise a valid signed downgrade would fail on the first legacy
        -- table created by 005.
        ALTER TABLE IF EXISTS longspan_authority_config
            OWNER TO {MIGRATION_ROLE};
        ALTER TABLE IF EXISTS longspan_terra_receipts
            OWNER TO {MIGRATION_ROLE};
        ALTER TABLE IF EXISTS longspan_children
            OWNER TO {MIGRATION_ROLE};
        ALTER TABLE IF EXISTS longspan_execution_audits
            OWNER TO {MIGRATION_ROLE};

        -- Normalize the complete controller catalog before a later connected
        -- downgrade guard probes legacy evidence under the migration role.
        -- This is deliberately limited to the controller database's public
        -- application relations and Longspan routines; it does not grant any
        -- runtime principal schema or DDL authority.
        DO $migration_owner$
        DECLARE
            relation_row RECORD;
            routine_row RECORD;
            allowed_table_names CONSTANT TEXT[] := ARRAY[
                'controller_control', 'supervisor_runs', 'parent_tasks', 'task_attempts',
                'retry_queue', 'supervisor_events', 'evidence_index',
                'manifest_submissions', 'required_manifest_entries', 'signal_status',
                'provenance_records', 'notifications', 'alembic_version',
                'top_delivery_downgrade_capabilities',
                'longspan_children', 'longspan_plans', 'longspan_execution_results',
                'longspan_auditor_receipts', 'longspan_terra_receipts',
                'longspan_experiments', 'longspan_evidence_ledger',
                'longspan_authority_config', 'longspan_authority_history',
                'longspan_operator_challenges', 'longspan_terra_receipt_attestations',
                'longspan_execution_audits', 'longspan_execution_evidence',
                'longspan_ledger_legacy_attestations', 'longspan_mac_material',
                'longspan_mac_key_history', 'longspan_migration_provenance',
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
                'reject_longspan_terra_truncate()'
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
                    '006 owner normalization blocked: unexpected public relation(s): %',
                    (
                        SELECT string_agg(format('%I.%I', n2.nspname, c2.relname), ', ')
                        FROM pg_class AS c2
                        JOIN pg_namespace AS n2 ON n2.oid = c2.relnamespace
                        WHERE n2.nspname = 'public'
                          AND c2.relkind IN ('r', 'p', 'v', 'm', 'f')
                          AND c2.relname <> ALL(allowed_table_names)
                    );
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
                    '006 owner normalization blocked: unexpected public sequence(s): %',
                    (
                        SELECT string_agg(format('%I.%I', n2.nspname, c2.relname), ', ')
                        FROM pg_class AS c2
                        JOIN pg_namespace AS n2 ON n2.oid = c2.relnamespace
                        WHERE n2.nspname = 'public'
                          AND c2.relkind = 'S'
                          AND c2.relname <> ALL(allowed_sequence_names)
                    );
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
                    '006 owner normalization blocked: provenance relation owner or ACL is unsafe';
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
                    '006 owner normalization blocked: provenance table contract is not the reviewed contract';
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
                    '006 owner normalization blocked: provenance state contract is not the reviewed contract';
            END IF;
            FOR relation_row IN
                SELECT format('%I.%I', n.nspname, c.relname) AS qualified_name,
                       c.relkind
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND (
                          c.relkind IN ('r', 'p')
                      AND c.relname = ANY(allowed_table_names)
                      AND c.relname <> ALL(provenance_relation_names)
                      OR c.relkind = 'S'
                      AND c.relname = ANY(allowed_sequence_names)
                  )
            LOOP
                IF relation_row.relkind = 'S' THEN
                    EXECUTE format(
                        'ALTER SEQUENCE %s OWNER TO %I',
                        relation_row.qualified_name, '{MIGRATION_ROLE}'
                    );
                ELSE
                    EXECUTE format(
                        'ALTER TABLE %s OWNER TO %I',
                        relation_row.qualified_name, '{MIGRATION_ROLE}'
                    );
                END IF;
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
                    '006 owner normalization blocked: unexpected SECURITY DEFINER routine exists';
            END IF;
            FOR routine_row IN
                SELECT p.oid::regprocedure AS signature
                FROM pg_proc AS p
                JOIN pg_namespace AS n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public'
                  AND EXISTS (
                      SELECT 1
                      FROM unnest(allowed_routine_signatures) AS signature
                      WHERE to_regprocedure(signature) = p.oid
                  )
            LOOP
                EXECUTE format(
                    'ALTER FUNCTION %s OWNER TO %I',
                    routine_row.signature, '{MIGRATION_ROLE}'
                );
            END LOOP;
        END
        $migration_owner$ LANGUAGE plpgsql;
        """
    )
    # 005 and 006 share the same detached event-sequence contract.  State it
    # explicitly on both upgrade and downgrade so an intermediate migration
    # cannot accidentally reattach the sequence through ownership metadata.
    op.execute(
        "ALTER SEQUENCE IF EXISTS supervisor_events_event_seq_seq OWNED BY NONE"
    )


def downgrade() -> None:
    verify_migration_source_anchor(
        revision,
        source_path=__file__,
        anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH,
    )
    assert_migration_catalog(revision)
    from disposable_capability import require_connected_migration_downgrade

    # 006 is the first revision that stores authority provenance.  A direct
    # downgrade must therefore be subject to the same connected, signed,
    # disposable-target gate as 007; otherwise raw Alembic could drop the
    # authority table while leaving no recoverable provenance.
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
                RAISE EXCEPTION '006 downgrade blocked: database % is not disposable', db_name;
            END IF;
            IF to_regclass('public.top_delivery_downgrade_capabilities') IS NULL THEN
                RAISE EXCEPTION '006 downgrade blocked: signed disposable capability sentinel/witness is missing';
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
                  '005_longspan_hardening', '004_longspan_workflow'
              )
              AND expires_at > clock_timestamp()
              AND NOT ('006_longspan_authority' = ANY(consumed_steps))
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
                   '005_longspan_hardening', '004_longspan_workflow'
               ) THEN
                RAISE EXCEPTION '006 downgrade blocked: signed disposable capability sentinel/witness is invalid';
            END IF;
            UPDATE top_delivery_downgrade_capabilities
            SET consumed_at = clock_timestamp(),
                consumed_steps = array_append(consumed_steps, '006_longspan_authority')
            WHERE nonce = capability_nonce
              AND database_name = db_name
              AND database_role = current_user
              AND transport_database_role = session_user
              AND controller_service = '{CONTROLLER_SERVICE}'
              AND operation = capability_operation
              AND migration_revision = capability_migration_revision
              AND NOT ('006_longspan_authority' = ANY(consumed_steps));
            -- A peer-auth root connection is not a migration principal.  It
            -- is accepted only when this exact connected database/current
            -- user/target is bound to the signed capability row selected
            -- above; the capability is the out-of-band harness witness.
            IF current_user NOT IN ('{MIGRATION_ROLE}', 'postgres') THEN
                RAISE EXCEPTION
                    '006 downgrade blocked: connected principal is not an approved migration role';
            END IF;
            -- The transport session must have explicitly entered the pinned
            -- migration role before this guard is reached.  A postgres/root
            -- peer session is not allowed to satisfy the effective-role gate.
            IF current_user <> '{MIGRATION_ROLE}' THEN
                RAISE EXCEPTION
                    '006 downgrade blocked: connected principal is not an approved migration role';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_authority_config LIMIT 1) THEN
                RAISE EXCEPTION '006 downgrade blocked: authority configuration exists';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_terra_receipts LIMIT 1) THEN
                RAISE EXCEPTION '006 downgrade blocked: terra receipt rows exist';
            END IF;
            IF to_regclass('public.longspan_execution_audits') IS NOT NULL THEN
                IF EXISTS (SELECT 1 FROM longspan_execution_audits LIMIT 1) THEN
                    RAISE EXCEPTION '006 downgrade blocked: execution audit rows exist';
                END IF;
            END IF;
            -- These are the complete set of columns introduced by 006.  Keep
            -- each check explicit so a future partial/relative downgrade cannot
            -- accidentally treat one provenance column as absent.
            IF EXISTS (SELECT 1 FROM longspan_terra_receipts WHERE run_id IS NOT NULL) THEN
                RAISE EXCEPTION '006 downgrade blocked: terra receipt run provenance exists';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_terra_receipts WHERE task_id IS NOT NULL) THEN
                RAISE EXCEPTION '006 downgrade blocked: terra receipt task provenance exists';
            END IF;
            IF EXISTS (SELECT 1 FROM longspan_terra_receipts WHERE reviewed_sha IS NOT NULL) THEN
                RAISE EXCEPTION '006 downgrade blocked: terra receipt reviewed-SHA provenance exists';
            END IF;
        END
        $guard$ LANGUAGE plpgsql;

        ALTER TABLE longspan_terra_receipts
            DROP COLUMN IF EXISTS reviewed_sha,
            DROP COLUMN IF EXISTS task_id,
            DROP COLUMN IF EXISTS run_id;

        -- 005 deliberately detached this sequence from the event column.
        -- 006 must restore that exact dependency state before returning to
        -- 005; ownership and dependency are separate catalog properties.
            ALTER SEQUENCE IF EXISTS supervisor_events_event_seq_seq
            OWNED BY NONE;

        -- 008's provenance archive must survive a downgrade without becoming
        -- an unowned public object that an older migration could adopt. Move
        -- the complete archive catalog into a private recovery schema before
        -- crossing the 006 -> 005 boundary. It remains available for an
        -- explicit restore/re-upgrade path, while the historical 005/006/007
        -- public contracts remain schema-equivalent and closed.
        DO $preserve_008_archive$
        DECLARE
            archive_owner TEXT;
            archive_owner_oid OID;
            recovery_owner TEXT;
            recovery_public_access BOOLEAN;
            archive_has_unexpected_acl BOOLEAN;
            archive_has_unexpected_column_acl BOOLEAN;
            archive_has_unexpected_default_acl BOOLEAN;
            archive_unexpected_default_role TEXT;
            archive_unexpected_default_objtype TEXT;
        BEGIN
            IF to_regclass('public.longspan_migration_provenance_008_archive') IS NOT NULL THEN
                IF to_regnamespace('top_delivery_recovery') IS NULL THEN
                    RAISE EXCEPTION
                        '006 downgrade blocked: private provenance recovery schema was not provisioned by administrative transport';
                END IF;
                SELECT pg_get_userbyid(n.nspowner),
                       EXISTS (
                           SELECT 1
                           FROM aclexplode(
                               COALESCE(n.nspacl, acldefault('n', n.nspowner))
                           ) AS acl
                           WHERE acl.grantee = 0
                             AND acl.privilege_type IN ('USAGE', 'CREATE')
                       )
                  INTO recovery_owner, recovery_public_access
                FROM pg_namespace AS n
                WHERE n.nspname = 'top_delivery_recovery';
                IF recovery_owner IS DISTINCT FROM '{MIGRATION_ROLE}'
                   OR recovery_public_access THEN
                    RAISE EXCEPTION
                        '006 downgrade blocked: private provenance recovery schema owner or PUBLIC ACL is unsafe';
                END IF;
                IF to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive') IS NOT NULL
                   OR to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq') IS NOT NULL
                   OR to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq') IS NOT NULL
                   OR to_regprocedure(
                       'top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation()'
                   ) IS NOT NULL THEN
                    RAISE EXCEPTION
                        '006 downgrade blocked: private provenance recovery objects already exist';
                END IF;
                SELECT c.relowner, pg_get_userbyid(c.relowner)
                  INTO archive_owner_oid, archive_owner
                FROM pg_class AS c
                WHERE c.oid = 'public.longspan_migration_provenance_008_archive'::regclass;
                IF archive_owner IS DISTINCT FROM '{MIGRATION_ROLE}' THEN
                    RAISE EXCEPTION
                        '006 downgrade blocked: public provenance archive owner is %',
                        archive_owner;
                END IF;
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_class AS archive_class
                    WHERE archive_class.oid =
                          'public.longspan_migration_provenance_008_archive'::regclass
                      AND EXISTS (
                          SELECT 1
                          FROM aclexplode(
                              COALESCE(
                                  archive_class.relacl,
                                  acldefault('r', archive_class.relowner)
                              )
                          ) AS acl
                          WHERE acl.grantee <> archive_class.relowner
                            AND NOT (
                                acl.grantee IN (
                                    (SELECT oid FROM pg_roles
                                     WHERE rolname = '{WORKFLOW_ROLE}'),
                                    (SELECT oid FROM pg_roles
                                     WHERE rolname = '{AUTHORITY_ROLE}')
                                )
                                AND acl.privilege_type = 'SELECT'
                            )
                      )
                ) INTO archive_has_unexpected_acl;
                IF archive_has_unexpected_acl THEN
                    RAISE EXCEPTION
                        '006 downgrade blocked: public provenance archive has an unexpected ACL';
                END IF;
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_attribute AS attribute
                    WHERE attribute.attrelid =
                          'public.longspan_migration_provenance_008_archive'::regclass
                      AND attribute.attnum > 0
                      AND NOT attribute.attisdropped
                      AND attribute.attacl IS NOT NULL
                      AND EXISTS (
                          SELECT 1
                          FROM aclexplode(attribute.attacl) AS acl
                          WHERE acl.grantee <> archive_owner_oid
                            AND NOT (
                                acl.grantee IN (
                                    (SELECT oid FROM pg_roles
                                     WHERE rolname = '{WORKFLOW_ROLE}'),
                                    (SELECT oid FROM pg_roles
                                     WHERE rolname = '{AUTHORITY_ROLE}')
                                )
                                AND acl.privilege_type = 'SELECT'
                            )
                      )
                ) INTO archive_has_unexpected_column_acl;
                IF archive_has_unexpected_column_acl THEN
                    RAISE EXCEPTION
                        '006 downgrade blocked: public provenance archive has an unexpected column ACL';
                END IF;
                SELECT pg_get_userbyid(defaults.defaclrole), defaults.defaclobjtype::TEXT
                  INTO archive_unexpected_default_role,
                       archive_unexpected_default_objtype
                FROM pg_default_acl AS defaults
                WHERE defaults.defaclnamespace = 'public'::regnamespace
                  AND defaults.defaclrole = archive_owner_oid
                  AND defaults.defaclobjtype IN ('r', 'S')
                  AND defaults.defaclacl IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM aclexplode(defaults.defaclacl) AS acl
                      WHERE acl.grantee <> defaults.defaclrole
                        AND NOT (
                            defaults.defaclobjtype = 'r'
                            AND acl.grantee IN (
                                (SELECT oid FROM pg_roles
                                 WHERE rolname = '{WORKFLOW_ROLE}'),
                                (SELECT oid FROM pg_roles
                                 WHERE rolname = '{AUTHORITY_ROLE}')
                            )
                            AND acl.privilege_type = 'SELECT'
                        )
                  )
                LIMIT 1;
                archive_has_unexpected_default_acl :=
                    archive_unexpected_default_role IS NOT NULL;
                IF archive_has_unexpected_default_acl THEN
                    RAISE EXCEPTION
                        '006 downgrade blocked: public provenance archive has an unexpected default ACL for role % and object type %',
                        archive_unexpected_default_role,
                        archive_unexpected_default_objtype;
                END IF;
                ALTER TABLE public.longspan_migration_provenance_008_archive
                    SET SCHEMA top_delivery_recovery;
                ALTER TABLE top_delivery_recovery.longspan_migration_provenance_008_archive
                    OWNER TO {MIGRATION_ROLE};
                REVOKE ALL ON TABLE top_delivery_recovery.longspan_migration_provenance_008_archive
                    FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
                IF to_regclass('public.longspan_migration_provenance_008_archive_id_seq') IS NOT NULL THEN
                    ALTER SEQUENCE public.longspan_migration_provenance_008_archive_id_seq
                        SET SCHEMA top_delivery_recovery;
                    ALTER SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq
                        OWNER TO {MIGRATION_ROLE};
                    REVOKE ALL ON SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq
                        FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
                END IF;
                IF to_regclass('public.longspan_migration_provenance_008_archive_archive_id_seq') IS NOT NULL THEN
                    ALTER SEQUENCE public.longspan_migration_provenance_008_archive_archive_id_seq
                        SET SCHEMA top_delivery_recovery;
                    ALTER SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq
                        OWNER TO {MIGRATION_ROLE};
                    REVOKE ALL ON SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq
                        FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
                END IF;
                IF to_regprocedure(
                    'public.reject_longspan_migration_provenance_008_archive_mutation()'
                ) IS NOT NULL THEN
                    ALTER FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                        SET SCHEMA top_delivery_recovery;
                    ALTER FUNCTION top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation()
                        OWNER TO {MIGRATION_ROLE};
                    REVOKE ALL ON FUNCTION top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation()
                        FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
                END IF;
            END IF;
        END
        $preserve_008_archive$;

        DROP TABLE IF EXISTS longspan_authority_config;
        DROP TRIGGER IF EXISTS longspan_execution_audits_append_only
            ON longspan_execution_audits;
        DROP FUNCTION IF EXISTS reject_longspan_execution_audit_mutation();
        DROP FUNCTION IF EXISTS longspan_append_execution_audit(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT
        );
        -- 007 -> 006 recreates the legacy auditor contract so the recorded
        -- 006 schema remains executable.  It is 007 downgrade compatibility
        -- state and must not survive the next 006 -> 005 boundary.
        DROP FUNCTION IF EXISTS longspan_append_auditor_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT
        );
        DROP FUNCTION IF EXISTS longspan_append_terra_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        );
        DROP TABLE IF EXISTS longspan_execution_audits;
        -- The capability ledger belongs to 006 and must not survive a
        -- successful 006 -> 005 schema downgrade.  Its row was consumed by
        -- the guard above before this point.
        DROP TABLE IF EXISTS top_delivery_downgrade_capabilities;
        """
    )
