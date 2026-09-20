"""Forward repair for databases that already recorded revision 007.

Revision 007 was published once with an incomplete provenance boundary.  This
revision is intentionally forward-only: it repairs targets at 007, records
the exact 008 source digest, and installs the runtime contracts needed by the
current controller.  It never rewinds or destroys authority/evidence data.
"""

from __future__ import annotations

from pathlib import Path

from alembic import op
from authority_pins import MIGRATION_SOURCE_PROVENANCE_PATH
from exceptions import ProvenanceMismatchError
from migration_catalog import assert_migration_catalog
from migration_source_anchor import normalized_source_digest
from pinned_trust import read_json_file, read_verified_source_bytes

revision = "008_longspan_authority_repair"
down_revision = "007_longspan_authority_hardening"
branch_labels = None
depends_on = None

MIGRATION_ROLE = "top_delivery_migration"
WORKFLOW_ROLE = "top_delivery_workflow"
AUTHORITY_ROLE = "top_delivery_authority"
MIGRATION_SOURCE_PROVENANCE_DIGEST = "38ec94c702a8f85fd261d3539fd3899cb4955fff428c2282870aca2a13d92101"
MIGRATION_SOURCE_PROVENANCE_ALGORITHM = "sha256"
MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION = 1

def _assert_source_provenance() -> None:
    """Require both source self-consistency and an out-of-band digest pin."""
    source = read_verified_source_bytes(str(Path(__file__).resolve()))
    try:
        calculated = normalized_source_digest(source)
    except ProvenanceMismatchError as exc:
        raise RuntimeError(str(exc)) from exc
    if calculated != MIGRATION_SOURCE_PROVENANCE_DIGEST:
        raise RuntimeError("008 source provenance digest does not match its source")
    anchor = read_json_file(
        MIGRATION_SOURCE_PROVENANCE_PATH,
        strict_owner=True,
        require_root_owner=True,
    )
    if (
        anchor.get("revision") != revision
        or anchor.get("algorithm") != MIGRATION_SOURCE_PROVENANCE_ALGORITHM
        or anchor.get("normalization_version")
        != MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION
        or anchor.get("source_digest") != calculated
    ):
        raise RuntimeError("008 source provenance digest does not match the pinned trust anchor")


def upgrade() -> None:
    _assert_source_provenance()
    assert_migration_catalog(revision)
    # Enter the pinned NOLOGIN migration role before the first SQL statement
    # below.  The environment normally performs this transport step too, but
    # the revision must establish its own principal before any recovery
    # inspection, prerequisite function, or cross-schema DDL can run.
    op.execute(f"SET LOCAL ROLE {MIGRATION_ROLE}")
    # The environment gate validates the namespace inventory before entering
    # the migration role. If an archive is present, validate its exact table,
    # trigger, sequence and SECURITY DEFINER guard body before adopting any
    # object into public. A catalog-resident attacker object is never adopted.
    op.execute(
        f"""
        DO $validate_008_recovery$
        DECLARE
            archive_oid OID := to_regclass(
                'top_delivery_recovery.longspan_migration_provenance_008_archive'
            );
            guard_oid OID := to_regprocedure(
                'top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation()'
            );
            archive_owner TEXT;
            guard_owner TEXT;
            guard_source TEXT;
            recovery_owner TEXT;
            recovery_public_access BOOLEAN;
        BEGIN
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
            IF recovery_owner IS NOT NULL
               AND (
                   recovery_owner IS DISTINCT FROM '{MIGRATION_ROLE}'
                   OR recovery_public_access
               ) THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: recovery schema owner or PUBLIC ACL is unsafe';
            END IF;
            IF archive_oid IS NULL THEN
                IF to_regclass(
                       'top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq'
                   ) IS NOT NULL
                   OR to_regclass(
                       'top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq'
                   ) IS NOT NULL
                   OR guard_oid IS NOT NULL THEN
                    RAISE EXCEPTION
                        '008 archive restore blocked: orphaned private archive residue exists';
                END IF;
                RETURN;
            END IF;
            SELECT pg_get_userbyid(c.relowner)
              INTO archive_owner
            FROM pg_class AS c
            WHERE c.oid = archive_oid;
            IF archive_owner IS DISTINCT FROM '{MIGRATION_ROLE}' THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: private archive owner is %',
                    archive_owner;
            END IF;
            IF EXISTS (
                SELECT 1
                FROM pg_class AS c
                WHERE c.oid = archive_oid
                  AND c.relacl IS NOT NULL
                  AND EXISTS (
                      SELECT 1
                      FROM aclexplode(c.relacl) AS acl
                      WHERE acl.grantee <> c.relowner
                  )
            ) THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: private archive has a non-owner ACL';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM pg_attribute AS a
                WHERE a.attrelid = archive_oid
                  AND a.attnum > 0
                  AND NOT a.attisdropped
                  AND a.attname <> ALL(ARRAY[
                      'archive_id', 'revision', 'source_digest', 'algorithm',
                      'normalization_version', 'applied_at', 'application_count',
                      'last_seen_at', 'provenance_table_preexisting'
                  ]::TEXT[])
            ) OR EXISTS (
                SELECT 1
                FROM unnest(ARRAY[
                    'archive_id', 'revision', 'source_digest', 'algorithm',
                    'normalization_version', 'applied_at', 'application_count',
                    'last_seen_at', 'provenance_table_preexisting'
                ]::TEXT[]) AS expected(name)
                WHERE NOT EXISTS (
                    SELECT 1 FROM pg_attribute AS a
                    WHERE a.attrelid = archive_oid
                      AND a.attnum > 0
                      AND NOT a.attisdropped
                      AND a.attname = expected.name
                )
            ) THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: private archive columns are not the reviewed contract';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conrelid = archive_oid
                  AND contype = 'p'
                  AND pg_get_constraintdef(oid) = 'PRIMARY KEY (archive_id)'
            ) THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: private archive primary key is not the reviewed contract';
            END IF;
            IF guard_oid IS NULL THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: private archive guard routine is missing';
            END IF;
            SELECT pg_get_userbyid(p.proowner),
                   btrim(regexp_replace(p.prosrc, '[[:space:]]+', ' ', 'g'))
              INTO guard_owner, guard_source
            FROM pg_proc AS p
            WHERE p.oid = guard_oid;
            IF guard_owner IS DISTINCT FROM '{MIGRATION_ROLE}'
               OR guard_source IS DISTINCT FROM
                  'BEGIN RAISE EXCEPTION ''008 migration provenance archive is append-only''; END;' THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: private archive guard routine is not the reviewed SECURITY DEFINER body';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM pg_trigger
                WHERE tgrelid = archive_oid
                  AND tgname = 'longspan_migration_provenance_008_archive_append_only'
                  AND NOT tgisinternal
            ) THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: private archive append-only trigger is missing';
            END IF;
        END
        $validate_008_recovery$;
        """
    )
    # A 006 -> 005 downgrade parks the append-only provenance archive in a
    # private recovery schema.  Restore it before the 008 catalog checks so a
    # downgrade/re-upgrade cycle is deterministic and cannot silently lose an
    # observation.  Existing public/private copies are merged by content and
    # conflicting definitions fail closed.
    op.execute(
        f"""
        DO $restore_008_archive$
        DECLARE
            private_table REGCLASS := to_regclass(
                'top_delivery_recovery.longspan_migration_provenance_008_archive'
            );
            public_table REGCLASS := to_regclass(
                'public.longspan_migration_provenance_008_archive'
            );
            private_sequence REGCLASS := to_regclass(
                'top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq'
            );
            public_sequence REGCLASS := to_regclass(
                'public.longspan_migration_provenance_008_archive_id_seq'
            );
            private_legacy_sequence REGCLASS := to_regclass(
                'top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq'
            );
            public_legacy_sequence REGCLASS := to_regclass(
                'public.longspan_migration_provenance_008_archive_archive_id_seq'
            );
            private_function REGPROCEDURE := to_regprocedure(
                'top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation()'
            );
            public_function REGPROCEDURE := to_regprocedure(
                'public.reject_longspan_migration_provenance_008_archive_mutation()'
            );
            private_owner TEXT;
            recovery_owner TEXT;
            recovery_public_access BOOLEAN;
        BEGIN
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
            IF recovery_owner IS NOT NULL
               AND (
                   recovery_owner IS DISTINCT FROM '{MIGRATION_ROLE}'
                   OR recovery_public_access
               ) THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: recovery schema owner or PUBLIC ACL is unsafe';
            END IF;
            IF private_table IS NULL THEN
                IF private_sequence IS NOT NULL
                   OR private_legacy_sequence IS NOT NULL
                   OR private_function IS NOT NULL THEN
                    RAISE EXCEPTION
                        '008 archive restore blocked: orphaned private archive residue exists';
                END IF;
                RETURN;
            END IF;
            SELECT pg_get_userbyid(c.relowner)
              INTO private_owner
            FROM pg_class AS c
            WHERE c.oid = private_table;
            IF private_owner <> '{MIGRATION_ROLE}' THEN
                RAISE EXCEPTION
                    '008 archive restore blocked: private archive owner is %',
                    private_owner;
            END IF;
            IF public_table IS NULL THEN
                IF public_sequence IS NOT NULL OR public_legacy_sequence IS NOT NULL THEN
                    RAISE EXCEPTION
                        '008 archive restore blocked: public sequence exists without public archive';
                END IF;
                IF private_function IS NOT NULL THEN
                    -- Recreate the reviewed trigger routine from this
                    -- migration's source instead of adopting a catalog
                    -- object across schemas.
                    CREATE OR REPLACE FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                    RETURNS trigger AS $archive_guard$
                    BEGIN
                        RAISE EXCEPTION '008 migration provenance archive is append-only';
                    END;
                    $archive_guard$ LANGUAGE plpgsql SECURITY DEFINER
                        SET search_path = pg_catalog, public;
                    ALTER FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                        OWNER TO top_delivery_migration;
                    REVOKE ALL ON FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                        FROM PUBLIC, top_delivery_workflow, top_delivery_authority;
                    GRANT EXECUTE ON FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                        TO top_delivery_migration;
                    DROP TRIGGER IF EXISTS longspan_migration_provenance_008_archive_append_only
                        ON top_delivery_recovery.longspan_migration_provenance_008_archive;
                    DROP FUNCTION top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation();
                END IF;
                IF private_sequence IS NOT NULL THEN
                    ALTER SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq
                        OWNED BY NONE;
                    ALTER SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq
                        SET SCHEMA public;
                END IF;
                IF private_legacy_sequence IS NOT NULL THEN
                    ALTER SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq
                        OWNED BY NONE;
                    DROP SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq;
                END IF;
                ALTER TABLE top_delivery_recovery.longspan_migration_provenance_008_archive
                    SET SCHEMA public;
                ALTER TABLE public.longspan_migration_provenance_008_archive
                    OWNER TO {MIGRATION_ROLE};
                REVOKE ALL ON public.longspan_migration_provenance_008_archive
                    FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
                GRANT SELECT ON public.longspan_migration_provenance_008_archive
                    TO {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
                DROP TRIGGER IF EXISTS longspan_migration_provenance_008_archive_append_only
                    ON public.longspan_migration_provenance_008_archive;
                CREATE TRIGGER longspan_migration_provenance_008_archive_append_only
                    BEFORE UPDATE OR DELETE ON public.longspan_migration_provenance_008_archive
                    FOR EACH ROW
                    EXECUTE FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation();
                IF private_sequence IS NOT NULL THEN
                    ALTER SEQUENCE public.longspan_migration_provenance_008_archive_id_seq
                        OWNED BY public.longspan_migration_provenance_008_archive.archive_id;
                END IF;
                RETURN;
            END IF;
            -- A partially completed repair may leave both copies. Preserve
            -- every archive identity; identical payloads with different IDs
            -- are separate observations, while a same-ID payload conflict
            -- fails closed.
            INSERT INTO public.longspan_migration_provenance_008_archive (
                archive_id, revision, source_digest, algorithm, normalization_version,
                applied_at, application_count, last_seen_at,
                provenance_table_preexisting
            )
            SELECT source_row.archive_id, source_row.revision, source_row.source_digest,
                   source_row.algorithm, source_row.normalization_version,
                   source_row.applied_at, source_row.application_count,
                   source_row.last_seen_at, source_row.provenance_table_preexisting
            FROM top_delivery_recovery.longspan_migration_provenance_008_archive
                AS source_row
            WHERE NOT EXISTS (
                SELECT 1
                FROM public.longspan_migration_provenance_008_archive AS target_row
                WHERE target_row.archive_id = source_row.archive_id
            );
            IF EXISTS (
                SELECT 1
                FROM top_delivery_recovery.longspan_migration_provenance_008_archive AS source_row
                JOIN public.longspan_migration_provenance_008_archive AS target_row
                  ON target_row.archive_id = source_row.archive_id
                WHERE target_row.revision IS DISTINCT FROM source_row.revision
                   OR target_row.source_digest IS DISTINCT FROM source_row.source_digest
                   OR target_row.algorithm IS DISTINCT FROM source_row.algorithm
                   OR target_row.normalization_version IS DISTINCT FROM source_row.normalization_version
                   OR target_row.applied_at IS DISTINCT FROM source_row.applied_at
                   OR target_row.application_count IS DISTINCT FROM source_row.application_count
                   OR target_row.last_seen_at IS DISTINCT FROM source_row.last_seen_at
                   OR target_row.provenance_table_preexisting IS DISTINCT FROM source_row.provenance_table_preexisting
            ) THEN
                RAISE EXCEPTION '008 archive restore blocked: archive identity conflict';
            END IF;
            IF private_function IS NOT NULL THEN
                -- Recreate the reviewed trigger routine even if a public
                -- same-signature object already exists; never adopt either
                -- catalog body as release authority.
                CREATE OR REPLACE FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                RETURNS trigger AS $archive_guard$
                BEGIN
                    RAISE EXCEPTION '008 migration provenance archive is append-only';
                END;
                $archive_guard$ LANGUAGE plpgsql SECURITY DEFINER
                    SET search_path = pg_catalog, public;
                ALTER FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                    OWNER TO top_delivery_migration;
                REVOKE ALL ON FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                    FROM PUBLIC, top_delivery_workflow, top_delivery_authority;
                GRANT EXECUTE ON FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation()
                    TO top_delivery_migration;
                DROP TRIGGER IF EXISTS longspan_migration_provenance_008_archive_append_only
                    ON top_delivery_recovery.longspan_migration_provenance_008_archive;
                DROP FUNCTION top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation();
            END IF;
            IF private_sequence IS NOT NULL THEN
                ALTER SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq
                    OWNED BY NONE;
                IF public_sequence IS NULL THEN
                    ALTER SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq
                        SET SCHEMA public;
                ELSE
                    DROP SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq;
                END IF;
            END IF;
            IF private_legacy_sequence IS NOT NULL THEN
                ALTER SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq
                    OWNED BY NONE;
                DROP SEQUENCE top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq;
            END IF;
            IF public_legacy_sequence IS NOT NULL THEN
                ALTER SEQUENCE public.longspan_migration_provenance_008_archive_archive_id_seq
                    OWNED BY NONE;
                DROP SEQUENCE public.longspan_migration_provenance_008_archive_archive_id_seq;
            END IF;
            DROP TABLE top_delivery_recovery.longspan_migration_provenance_008_archive;
            ALTER TABLE public.longspan_migration_provenance_008_archive
                OWNER TO {MIGRATION_ROLE};
            REVOKE ALL ON public.longspan_migration_provenance_008_archive
                FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
            GRANT SELECT ON public.longspan_migration_provenance_008_archive
                TO {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
            DROP TRIGGER IF EXISTS longspan_migration_provenance_008_archive_append_only
                ON public.longspan_migration_provenance_008_archive;
            CREATE TRIGGER longspan_migration_provenance_008_archive_append_only
                BEFORE UPDATE OR DELETE ON public.longspan_migration_provenance_008_archive
                FOR EACH ROW
                EXECUTE FUNCTION public.reject_longspan_migration_provenance_008_archive_mutation();
            IF to_regclass('public.longspan_migration_provenance_008_archive_id_seq') IS NOT NULL THEN
                ALTER SEQUENCE public.longspan_migration_provenance_008_archive_id_seq
                    OWNED BY public.longspan_migration_provenance_008_archive.archive_id;
                PERFORM setval(
                    'public.longspan_migration_provenance_008_archive_id_seq',
                    GREATEST(
                        COALESCE(
                            (SELECT MAX(archive_id)
                             FROM public.longspan_migration_provenance_008_archive),
                            1
                        ),
                        1
                    ),
                    TRUE
                );
            END IF;
        END
        $restore_008_archive$;
        """
    )
    # 006 historically allowed rows with an unbound transport sentinel.  A
    # database already at 007 must receive the same forward-only constraint
    # from this head revision; editing 006 alone cannot repair an applied DB.
    op.execute(
        """
        DO $transport_role_constraint_008$
        BEGIN
            IF to_regclass('public.top_delivery_downgrade_capabilities') IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1
                   FROM pg_constraint
                   WHERE conrelid = 'public.top_delivery_downgrade_capabilities'::regclass
                     AND conname = 'downgrade_capability_transport_role_bound'
               ) THEN
                ALTER TABLE public.top_delivery_downgrade_capabilities
                    ADD CONSTRAINT downgrade_capability_transport_role_bound
                    CHECK (transport_database_role <> '__legacy_unbound__') NOT VALID;
            END IF;
        END
        $transport_role_constraint_008$;
        """
    )
    # Assert the 007 object contract while the administrative transport still
    # owns the session. A 007 database may have been rehearsed by root/postgres;
    # ownership repair is an explicit out-of-band operation, never an implicit
    # migration side effect. This is a closed catalog, not prefix adoption.
    op.execute(
        f"""
        DO $assert_008_transport_owners$
        DECLARE
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
                'longspan_ledger_legacy_attestations', 'longspan_mac_material',
                'longspan_mac_key_history',
                'longspan_migration_provenance',
                'longspan_migration_provenance_008_state',
                'longspan_migration_provenance_008_archive'
            ];
            allowed_sequence_names CONSTANT TEXT[] := ARRAY[
                'supervisor_events_event_seq_seq',
                'longspan_migration_provenance_008_archive_id_seq',
                'longspan_migration_provenance_008_archive_archive_id_seq'
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
                'require_longspan_mutation_scope()',
                'reject_longspan_migration_provenance_008_archive_mutation()'
            ];
        BEGIN
            IF current_user <> '{MIGRATION_ROLE}'
               OR session_user NOT IN ('root', 'postgres') THEN
                RAISE EXCEPTION
                    '008 prerequisite failed: pinned migration identity is required, got %',
                    current_user;
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                  AND c.relname <> ALL(allowed_table_names)
            ) THEN
                RAISE EXCEPTION
                    '008 prerequisite failed: unexpected public relation exists';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind = 'S'
                  AND c.relname <> ALL(allowed_sequence_names)
            ) THEN
                RAISE EXCEPTION
                    '008 prerequisite failed: unexpected public sequence exists';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_proc AS p
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
                    '008 prerequisite failed: unexpected SECURITY DEFINER routine exists';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'S')
                  AND c.relname = ANY(allowed_table_names || allowed_sequence_names)
                  AND r.rolname <> '{MIGRATION_ROLE}'
            ) OR EXISTS (
                SELECT 1 FROM pg_proc AS p
                JOIN pg_namespace AS n ON n.oid = p.pronamespace
                JOIN pg_roles AS r ON r.oid = p.proowner
                WHERE n.nspname = 'public'
                  AND EXISTS (
                      SELECT 1
                      FROM unnest(allowed_routine_signatures) AS signature
                      WHERE to_regprocedure(signature) = p.oid
                  )
                  AND r.rolname <> '{MIGRATION_ROLE}'
            ) THEN
                RAISE EXCEPTION
                    '008 prerequisite failed: protected object is not owned by pinned migration role';
            END IF;
        END
        $assert_008_transport_owners$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        f"""
        DO $repair_prereq$
        BEGIN
            IF current_user <> '{MIGRATION_ROLE}' THEN
                RAISE EXCEPTION
                    '008 prerequisite failed: connected identity % is not an approved migration principal',
                    current_user;
            END IF;
            IF current_user IN ('{WORKFLOW_ROLE}', '{AUTHORITY_ROLE}') THEN
                RAISE EXCEPTION
                    '008 prerequisite failed: runtime roles may not execute migrations';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
            ) THEN
                RAISE EXCEPTION
                    '008 prerequisite failed: pgcrypto must be installed out of band';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = '{WORKFLOW_ROLE}'
            ) OR NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = '{AUTHORITY_ROLE}'
            ) THEN
                RAISE EXCEPTION
                    '008 prerequisite failed: workflow and authority roles are absent';
            END IF;
        END
        $repair_prereq$ LANGUAGE plpgsql;

        -- Capture whether the provenance relation existed before 008.  A
        -- downgrade may remove only the row/relation created by 008; if the
        -- relation pre-dated this repair it must remain intact.
        CREATE TABLE IF NOT EXISTS longspan_migration_provenance_008_state (
            singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
            provenance_table_preexisting BOOLEAN NOT NULL,
            recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        INSERT INTO longspan_migration_provenance_008_state
            (singleton, provenance_table_preexisting)
        VALUES (
            TRUE,
            to_regclass('public.longspan_migration_provenance') IS NOT NULL
        )
        ON CONFLICT (singleton) DO NOTHING;

        -- 007 databases may have either the old table (no table at all) or
        -- the first candidate table whose revision check only admitted 007.
        -- Widen that check before adding the immutable 008 record.
        CREATE TABLE IF NOT EXISTS longspan_migration_provenance (
            revision TEXT PRIMARY KEY,
            source_digest TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            normalization_version INTEGER NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        ALTER TABLE longspan_migration_provenance
            ADD COLUMN IF NOT EXISTS algorithm TEXT,
            ADD COLUMN IF NOT EXISTS normalization_version INTEGER;
        ALTER TABLE longspan_migration_provenance
            DROP CONSTRAINT IF EXISTS longspan_migration_provenance_revision_chk,
            DROP CONSTRAINT IF EXISTS longspan_migration_provenance_digest_chk,
            DROP CONSTRAINT IF EXISTS longspan_migration_provenance_algorithm_chk,
            DROP CONSTRAINT IF EXISTS longspan_migration_provenance_normalization_chk;
        ALTER TABLE longspan_migration_provenance
            ADD CONSTRAINT longspan_migration_provenance_revision_chk
                CHECK (revision ~ '^[0-9]{{3}}_[a-z0-9_]+$'),
            ADD CONSTRAINT longspan_migration_provenance_digest_chk
                CHECK (source_digest ~ '^[0-9a-f]{{64}}$'),
            ADD CONSTRAINT longspan_migration_provenance_algorithm_chk
                CHECK (algorithm = '{MIGRATION_SOURCE_PROVENANCE_ALGORITHM}'),
            ADD CONSTRAINT longspan_migration_provenance_normalization_chk
                CHECK (normalization_version = {MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION});
        ALTER TABLE longspan_migration_provenance
            ALTER COLUMN algorithm SET NOT NULL,
            ALTER COLUMN normalization_version SET NOT NULL,
            OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON longspan_migration_provenance
            FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        GRANT SELECT ON longspan_migration_provenance
            TO {WORKFLOW_ROLE}, {AUTHORITY_ROLE};

        DO $repair_provenance$
        DECLARE
            prior_digest TEXT;
            prior_algorithm TEXT;
            prior_normalization_version INTEGER;
        BEGIN
            SELECT source_digest, algorithm, normalization_version
              INTO prior_digest, prior_algorithm, prior_normalization_version
            FROM longspan_migration_provenance
            WHERE revision = '{revision}'
            FOR UPDATE;
            IF prior_digest IS NOT NULL
               AND (
                   prior_digest IS DISTINCT FROM '{MIGRATION_SOURCE_PROVENANCE_DIGEST}'
                   OR prior_algorithm IS DISTINCT FROM '{MIGRATION_SOURCE_PROVENANCE_ALGORITHM}'
                   OR prior_normalization_version IS DISTINCT FROM {MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION}
               ) THEN
                RAISE EXCEPTION
                    '008 provenance mismatch: existing source record is not this release';
            END IF;
            INSERT INTO longspan_migration_provenance
                (revision, source_digest, algorithm, normalization_version)
            VALUES (
                '{revision}', '{MIGRATION_SOURCE_PROVENANCE_DIGEST}',
                '{MIGRATION_SOURCE_PROVENANCE_ALGORITHM}',
                {MIGRATION_SOURCE_PROVENANCE_NORMALIZATION_VERSION}
            )
            ON CONFLICT (revision) DO NOTHING;
        END
        $repair_provenance$ LANGUAGE plpgsql;

        -- Existing 007 databases retain historical receipt rows at 007;
        -- new 008 receipts use the repaired contract.  This compatibility
        -- constraint is explicit and data-preserving, not catalog-derived.
        ALTER TABLE longspan_terra_receipt_attestations
            DROP CONSTRAINT IF EXISTS longspan_terra_receipt_attestations_migration_head_check;
        ALTER TABLE longspan_terra_receipt_attestations
            DROP CONSTRAINT IF EXISTS longspan_terra_receipt_attestations_migration_head_008_chk;
        ALTER TABLE longspan_terra_receipt_attestations
            ADD CONSTRAINT longspan_terra_receipt_attestations_migration_head_008_chk
            CHECK (migration_head IN ('007_longspan_authority_hardening', '008_longspan_authority_repair'));
        ALTER TABLE longspan_terra_receipt_attestations
            ADD COLUMN IF NOT EXISTS invalidated_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS invalidation_reason TEXT;
        DO $invalidation_constraints$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'longspan_terra_receipt_attestations'::regclass
                  AND conname = 'longspan_terra_receipt_attestations_invalidation_reason_chk'
            ) THEN
                ALTER TABLE longspan_terra_receipt_attestations
                    ADD CONSTRAINT longspan_terra_receipt_attestations_invalidation_reason_chk
                    CHECK (invalidation_reason IS NULL OR btrim(invalidation_reason) <> '');
            END IF;
        END
        $invalidation_constraints$ LANGUAGE plpgsql;

        -- The authority role may call the narrowly scoped SECURITY DEFINER
        -- routines below, but it must never update or insert the witness
        -- table directly, even if a session GUC is supplied by a caller.
        ALTER TABLE longspan_terra_receipt_attestations OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON longspan_terra_receipt_attestations
            FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        -- The authority service may read one persisted witness by its
        -- attestation id.  It still has no direct DML rights; issuance,
        -- consumption and invalidation remain restricted to the reviewed
        -- SECURITY DEFINER routines below.
        GRANT SELECT ON longspan_terra_receipt_attestations
            TO {AUTHORITY_ROLE};

        -- Recreate every routine changed by the 008 forward repair from
        -- reviewed source text.  No definition is read from PostgreSQL
        -- catalogs and no catalog-derived definition text is EXECUTEd.
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
            -- All result/evidence/auditor writers share this child-scoped
            -- advisory key.  The Python workflow acquires it before its
            -- child row lock, preventing a direct SECURITY DEFINER caller
            -- from racing the workflow transaction or creating lock-order
            -- deadlocks.
            PERFORM pg_advisory_xact_lock(8101, hashtext(p_child_id));
            -- The workflow transaction acquires this same child-scoped key
            -- before its child row lock.  PostgreSQL advisory locks are
            -- re-entrant for one session, so the routine remains safe when
            -- called through that transaction and serialized for every other
            -- writer.
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
            PERFORM pg_advisory_xact_lock(8101, hashtext(p_child_id));
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
            PERFORM pg_advisory_xact_lock(8101, hashtext(p_child_id));
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
            PERFORM pg_advisory_xact_lock(8101, hashtext(p_child_id));
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
            IF p_migration_head IS DISTINCT FROM '008_longspan_authority_repair' THEN
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
            -- Serialize witness issuance for one child attempt before the
            -- active-witness check and insert.  This is intentionally inside
            -- the authority transaction, so distinct concurrent payloads
            -- cannot both pass the one-live-witness invariant.
            PERFORM pg_advisory_xact_lock(
                8101, hashtext(p_child_id || ':' || p_attempt_number::TEXT)
            );
            -- A witness is short-lived and there may be at most one live
            -- witness for a child attempt.  This bounds orphaned witnesses
            -- when the workflow loses its connection between issuance and
            -- consumption, while allowing a later retry after expiry.
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            UPDATE longspan_terra_receipt_attestations
            SET invalidated_at = clock_timestamp(),
                invalidation_reason = 'expired'
            WHERE child_id = p_child_id
               AND attempt_number = p_attempt_number
               AND consumed_at IS NULL
               AND invalidated_at IS NULL
               AND issued_at <= clock_timestamp() - interval '5 minutes';
            IF EXISTS (
                SELECT 1
                FROM longspan_terra_receipt_attestations
                WHERE child_id = p_child_id
                  AND attempt_number = p_attempt_number
                  AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                  AND receipt_digest IS DISTINCT FROM computed_receipt_digest
            ) THEN
                RAISE EXCEPTION
                    'an unconsumed Terra receipt attestation already exists for this attempt';
            END IF;
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
                  AND invalidated_at IS NULL
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
            IF row_attestation.invalidated_at IS NOT NULL THEN
                RAISE EXCEPTION 'Terra receipt attestation was invalidated';
            END IF;
            IF row_attestation.issued_at <= clock_timestamp() - interval '5 minutes' THEN
                RAISE EXCEPTION 'Terra receipt attestation has expired';
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
            WHERE attestation_id = p_attestation_id
              AND consumed_at IS NULL
              AND invalidated_at IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Terra receipt attestation consumption lost the race';
            END IF;
        END;
        $terra_attestation_consume$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

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
            IF p_migration_head IS DISTINCT FROM '008_longspan_authority_repair' THEN
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
            IF attestation_row.invalidated_at IS NOT NULL THEN
                RAISE EXCEPTION 'Terra receipt attestation was invalidated';
            END IF;
            IF attestation_row.issued_at <= clock_timestamp() - interval '5 minutes' THEN
                RAISE EXCEPTION 'Terra receipt attestation has expired';
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
            IF p_migration_head IS DISTINCT FROM '008_longspan_authority_repair' THEN
                RAISE EXCEPTION 'terra receipt migration head is not the canonical 008 head';
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
            controller_state controller_control%ROWTYPE;
            challenge_controller_epoch INTEGER;
        BEGIN
            -- Serialize authority configuration changes with the final
            -- workflow receipt transaction.  The workflow role cannot take
            -- FOR SHARE on this table without UPDATE privilege, so the
            -- shared advisory key is the least-privilege lock boundary.
            PERFORM pg_advisory_xact_lock(8102, hashtext(p_run_id));
            SELECT * INTO controller_state
            FROM controller_control
            WHERE controller_control.run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR controller_state.scheduling_enabled IS DISTINCT FROM TRUE
               OR controller_state.owner IS NULL
               OR controller_state.lease_expires_at <= clock_timestamp()
               OR controller_state.controller_fence_token IS NULL
               OR controller_state.controller_fence_token <= 0 THEN
                RAISE EXCEPTION 'authority write lost controller fence';
            END IF;
            SELECT controller_epoch INTO challenge_controller_epoch
            FROM longspan_operator_challenges
            WHERE longspan_operator_challenges.approval_id = p_approval_id
              AND longspan_operator_challenges.run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR challenge_controller_epoch IS DISTINCT FROM controller_state.current_epoch THEN
                RAISE EXCEPTION 'authority write challenge is stale after controller fencing';
            END IF;
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
            controller_state controller_control%ROWTYPE;
            challenge_controller_epoch INTEGER;
        BEGIN
            PERFORM pg_advisory_xact_lock(8102, hashtext(p_run_id));
            SELECT * INTO controller_state
            FROM controller_control
            WHERE controller_control.run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR controller_state.scheduling_enabled IS DISTINCT FROM TRUE
               OR controller_state.owner IS NULL
               OR controller_state.lease_expires_at <= clock_timestamp()
               OR controller_state.controller_fence_token IS NULL
               OR controller_state.controller_fence_token <= 0 THEN
                RAISE EXCEPTION 'authority write lost controller fence';
            END IF;
            SELECT controller_epoch INTO challenge_controller_epoch
            FROM longspan_operator_challenges
            WHERE longspan_operator_challenges.approval_id = p_approval_id
              AND longspan_operator_challenges.run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR challenge_controller_epoch IS DISTINCT FROM controller_state.current_epoch THEN
                RAISE EXCEPTION 'authority write challenge is stale after controller fencing';
            END IF;
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
            controller_state controller_control%ROWTYPE;
            challenge_controller_epoch INTEGER;
            config_state longspan_authority_config%ROWTYPE;
        BEGIN
            PERFORM pg_advisory_xact_lock(8102, hashtext(p_run_id));
            SELECT * INTO controller_state
            FROM controller_control
            WHERE controller_control.run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR controller_state.scheduling_enabled IS DISTINCT FROM TRUE
               OR controller_state.owner IS NULL
               OR controller_state.lease_expires_at <= clock_timestamp()
               OR controller_state.controller_fence_token IS NULL
               OR controller_state.controller_fence_token <= 0 THEN
                RAISE EXCEPTION 'authority history lost controller fence';
            END IF;
            SELECT controller_epoch INTO challenge_controller_epoch
            FROM longspan_operator_challenges
            WHERE longspan_operator_challenges.approval_id = p_approval_id
              AND longspan_operator_challenges.run_id = p_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR challenge_controller_epoch IS DISTINCT FROM controller_state.current_epoch
               OR p_challenge_epoch IS DISTINCT FROM controller_state.current_epoch THEN
                RAISE EXCEPTION 'authority history challenge is stale after controller fencing';
            END IF;
            SELECT * INTO config_state
            FROM longspan_authority_config
            WHERE longspan_authority_config.run_id = p_run_id
              AND longspan_authority_config.config_version = p_config_version
            FOR UPDATE;
            IF NOT FOUND
               OR config_state.terra_auth_hash IS DISTINCT FROM p_terra_auth_hash
               OR config_state.operator_auth_hash IS DISTINCT FROM p_operator_auth_hash
               OR config_state.reviewed_sha IS DISTINCT FROM p_reviewed_sha
               OR config_state.tree_sha IS DISTINCT FROM p_tree_sha
               OR config_state.source_digest IS DISTINCT FROM p_source_digest
               OR config_state.approval_receipt_digest IS DISTINCT FROM p_approval_receipt_digest THEN
                RAISE EXCEPTION 'authority history payload does not match persisted config';
            END IF;
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

        -- The append-only trigger must permit only the exact authority-owned
        -- transition from unconsumed to consumed.  Older 007 databases did
        -- not bind all receipt fields in this exception path.
        CREATE OR REPLACE FUNCTION reject_longspan_terra_attestation_mutation()
        RETURNS trigger AS $terra_attestation_guard$
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
               AND (to_jsonb(NEW) - 'consumed_at')
                   IS NOT DISTINCT FROM (to_jsonb(OLD) - 'consumed_at') THEN
                RETURN NEW;
            END IF;
            IF TG_OP = 'UPDATE'
               AND session_user = '{AUTHORITY_ROLE}'
               AND current_setting('top_delivery.authority_routine', true) = '1'
               AND NEW.attestation_id IS NOT DISTINCT FROM OLD.attestation_id
               AND NEW.consumed_at IS NOT DISTINCT FROM OLD.consumed_at
               AND NEW.invalidated_at IS NOT NULL
               AND OLD.invalidated_at IS NULL
               AND NEW.invalidation_reason IS NOT NULL
               AND (to_jsonb(NEW) - 'invalidated_at' - 'invalidation_reason')
                   IS NOT DISTINCT FROM (
                       to_jsonb(OLD) - 'invalidated_at' - 'invalidation_reason'
                   ) THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'Terra receipt attestations are authority-issued and one-shot';
        END;
        $terra_attestation_guard$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

        -- Context is mandatory so a stale or cross-attempt authority response
        -- cannot invalidate another child''s witness.
        DROP FUNCTION IF EXISTS longspan_invalidate_terra_receipt_attestation(TEXT);
        CREATE OR REPLACE FUNCTION longspan_invalidate_terra_receipt_attestation(
            p_attestation_id TEXT,
            p_run_id TEXT,
            p_child_id TEXT,
            p_attempt_number INTEGER,
            p_signature_digest TEXT
        ) RETURNS VOID AS $terra_attestation_invalidate$
        DECLARE
            attestation_run TEXT;
            attestation_child TEXT;
            attestation_attempt INTEGER;
            attestation_consumed_at TIMESTAMPTZ;
            attestation_invalidated_at TIMESTAMPTZ;
        BEGIN
            IF session_user <> '{AUTHORITY_ROLE}' THEN
                RAISE EXCEPTION
                    'Terra receipt attestation invalidation requires the authority principal';
            END IF;
            IF p_attestation_id IS NULL OR btrim(p_attestation_id) = ''
               OR p_run_id IS NULL OR btrim(p_run_id) = ''
               OR p_child_id IS NULL OR btrim(p_child_id) = ''
               OR p_attempt_number IS NULL OR p_attempt_number < 0
               OR p_signature_digest !~ '^[0-9a-f]{{64}}$' THEN
                RAISE EXCEPTION 'Terra receipt attestation invalidation context is required';
            END IF;
            PERFORM pg_advisory_xact_lock(
                8101, hashtext(p_child_id || ':' || p_attempt_number::TEXT)
            );
            SELECT run_id, child_id, attempt_number, consumed_at, invalidated_at
              INTO attestation_run, attestation_child, attestation_attempt,
                   attestation_consumed_at, attestation_invalidated_at
            FROM longspan_terra_receipt_attestations
            WHERE attestation_id = p_attestation_id
            FOR UPDATE;
            IF attestation_run IS NULL THEN
                RAISE EXCEPTION 'Terra receipt attestation was not found';
            END IF;
            IF attestation_run IS DISTINCT FROM p_run_id
               OR attestation_child IS DISTINCT FROM p_child_id
               OR attestation_attempt IS DISTINCT FROM p_attempt_number THEN
                RAISE EXCEPTION 'Terra receipt attestation invalidation scope mismatch';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM longspan_terra_receipt_attestations
                WHERE attestation_id = p_attestation_id
                  AND signature_digest = p_signature_digest
            ) THEN
                RAISE EXCEPTION 'Terra receipt attestation invalidation proof mismatch';
            END IF;
            -- Retiring the same witness twice is safe and idempotent after
            -- the exact binding/proof checks above. A consumed witness is a
            -- different terminal state and must never be silently reused.
            IF attestation_invalidated_at IS NOT NULL THEN
                RETURN;
            END IF;
            IF attestation_consumed_at IS NOT NULL THEN
                RAISE EXCEPTION 'Terra receipt attestation was already consumed';
            END IF;
            PERFORM set_config('top_delivery.authority_routine', '1', true);
            UPDATE longspan_terra_receipt_attestations
            SET invalidated_at = clock_timestamp(),
                invalidation_reason = 'workflow_binding_failure'
            WHERE attestation_id = p_attestation_id
              AND consumed_at IS NULL
              AND invalidated_at IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Terra receipt attestation was already retired';
            END IF;
        END;
        $terra_attestation_invalidate$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;

        REVOKE ALL ON FUNCTION longspan_invalidate_terra_receipt_attestation(
            TEXT, TEXT, TEXT, INTEGER, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_invalidate_terra_receipt_attestation(
            TEXT, TEXT, TEXT, INTEGER, TEXT
        ) TO {AUTHORITY_ROLE};

        -- Keep the complete reviewed controller catalog under the non-login
        -- migration owner. This list is intentionally explicit; a future
        -- public longspan_* object must not be silently adopted or repaired
        -- by the migration.
        DO $assert_008_owners$
        DECLARE
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
                'longspan_ledger_legacy_attestations', 'longspan_mac_material',
                'longspan_mac_key_history', 'longspan_migration_provenance',
                'longspan_migration_provenance_008_state',
                'longspan_migration_provenance_008_archive'
            ];
            allowed_sequence_names CONSTANT TEXT[] := ARRAY[
                'supervisor_events_event_seq_seq',
                'longspan_migration_provenance_008_archive_id_seq',
                'longspan_migration_provenance_008_archive_archive_id_seq'
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
                'reject_longspan_migration_provenance_008_archive_mutation()',
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
                'longspan_invalidate_terra_receipt_attestation(TEXT, TEXT, TEXT, INTEGER, TEXT)',
                'require_longspan_mutation_scope()'
            ];
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                  AND c.relname <> ALL(allowed_table_names)
            ) THEN
                RAISE EXCEPTION
                    '008 owner normalization blocked: unexpected public relation exists';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind = 'S'
                  AND c.relname <> ALL(allowed_sequence_names)
            ) THEN
                RAISE EXCEPTION
                    '008 owner normalization blocked: unexpected public sequence exists';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_proc AS p
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
                    '008 owner normalization blocked: unexpected SECURITY DEFINER routine exists';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_roles AS owner_role ON owner_role.oid = c.relowner
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'S')
                  AND c.relname = ANY(allowed_table_names || allowed_sequence_names)
                  AND owner_role.rolname <> '{MIGRATION_ROLE}'
            ) OR EXISTS (
                SELECT 1
                FROM pg_proc AS p
                JOIN pg_namespace AS n ON n.oid = p.pronamespace
                JOIN pg_roles AS owner_role ON owner_role.oid = p.proowner
                WHERE n.nspname = 'public'
                  AND EXISTS (
                      SELECT 1
                      FROM unnest(allowed_routine_signatures) AS signature
                      WHERE to_regprocedure(signature) = p.oid
                  )
                  AND owner_role.rolname <> '{MIGRATION_ROLE}'
            ) THEN
                RAISE EXCEPTION
                    '008 owner assertion blocked: protected object is not owned by pinned migration role';
            END IF;
        END
        $assert_008_owners$;
        """
    )


def downgrade() -> None:
    # Verify the root-owned source anchor before any capability lookup or
    # destructive downgrade SQL. A modified 008 downgrade must not be able to
    # reach the database-side guards with a forged migration body.
    _assert_source_provenance()
    assert_migration_catalog(revision)
    from disposable_capability import require_connected_migration_downgrade

    # 008 is reversible only on an independently signed, disposable target
    # whose protected authority/evidence tables are empty.  The controller
    # verifies the connected identity and capability in env.py; this migration
    # performs a second database-side witness check before any DDL.
    require_connected_migration_downgrade(revision=revision)
    op.execute(
        f"""
        DO $controlled_repair_downgrade$
        DECLARE
            capability_nonce TEXT;
            capability_operation TEXT;
            capability_revision TEXT;
            capability_transport_database_role TEXT;
        BEGIN
            IF current_database() !~ '^td_(test|downgrade)_'
               OR current_user <> '{MIGRATION_ROLE}' THEN
                RAISE EXCEPTION
                    '008 downgrade requires the verified disposable migration boundary';
            END IF;
            IF to_regclass('public.top_delivery_downgrade_capabilities') IS NULL THEN
                RAISE EXCEPTION
                    '008 downgrade requires the signed disposable capability ledger';
            END IF;
            SELECT nonce, operation, migration_revision, transport_database_role
              INTO capability_nonce, capability_operation, capability_revision,
                   capability_transport_database_role
            FROM top_delivery_downgrade_capabilities
            WHERE database_name = current_database()
              AND database_role = current_user
              AND transport_database_role = session_user
              AND controller_service = 'top-delivery-controller'
              AND operation IN ('migration_downgrade', 'disposable_downgrade')
              AND migration_revision IN (
                  '007_longspan_authority_hardening',
                  '006_longspan_authority',
                  '005_longspan_hardening',
                  '004_longspan_workflow'
              )
              AND expires_at > clock_timestamp()
              AND NOT ('008_longspan_authority_repair' = ANY(consumed_steps))
            ORDER BY issued_at DESC
            LIMIT 1
            FOR UPDATE;
            IF capability_nonce IS NULL
               OR capability_operation NOT IN ('migration_downgrade', 'disposable_downgrade')
               OR capability_transport_database_role IS DISTINCT FROM session_user
               OR capability_transport_database_role NOT IN ('root', 'postgres', '{MIGRATION_ROLE}')
               OR capability_revision NOT IN (
                   '007_longspan_authority_hardening',
                   '006_longspan_authority',
                   '005_longspan_hardening',
                   '004_longspan_workflow'
               ) THEN
                RAISE EXCEPTION
                    '008 downgrade requires the exact connected signed capability witness';
            END IF;
            UPDATE top_delivery_downgrade_capabilities
            SET consumed_at = clock_timestamp(),
                consumed_steps = array_append(
                    consumed_steps, '008_longspan_authority_repair'
                )
            WHERE nonce = capability_nonce
              AND database_name = current_database()
              AND database_role = current_user
              AND transport_database_role = session_user
              AND controller_service = 'top-delivery-controller'
              AND operation = capability_operation
              AND migration_revision = capability_revision
              AND expires_at > clock_timestamp()
              AND NOT ('008_longspan_authority_repair' = ANY(consumed_steps));
            IF NOT FOUND THEN
                RAISE EXCEPTION
                    '008 downgrade could not consume the exact signed capability witness';
            END IF;
            -- Never destructively downgrade a populated control plane.  The
            -- only supported rollback for populated 008 is restore from a
            -- verified backup/PITR artifact.
            IF to_regclass('public.longspan_terra_receipt_attestations') IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM longspan_terra_receipt_attestations
                   WHERE invalidated_at IS NOT NULL
                   LIMIT 1
               ) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: invalidated Terra attestations are populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_terra_receipt_attestations') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_terra_receipt_attestations LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: Terra attestations are populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_authority_config') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_authority_config LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: authority configuration is populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_authority_history') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_authority_history LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: authority history is populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_execution_evidence') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_execution_evidence LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: execution evidence is populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_execution_audits') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_execution_audits LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: execution audits are populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_execution_results') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_execution_results LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: execution results are populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_auditor_receipts') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_auditor_receipts LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: auditor receipts are populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_evidence_ledger') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_evidence_ledger LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: evidence ledger is populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_terra_receipts') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_terra_receipts LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: Terra receipts are populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_operator_challenges') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_operator_challenges LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: operator challenges are populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_mac_material') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_mac_material LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: MAC material is populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_mac_key_history') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_mac_key_history LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: MAC key history is populated; restore a disposable backup';
            END IF;
            IF to_regclass('public.longspan_ledger_legacy_attestations') IS NOT NULL
               AND EXISTS (SELECT 1 FROM longspan_ledger_legacy_attestations LIMIT 1) THEN
                RAISE EXCEPTION
                    '008 downgrade blocked: legacy ledger attestations are populated; restore a disposable backup';
            END IF;
        END
        $controlled_repair_downgrade$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        f"""
        -- Restore the exact published 007 routine bodies from static reviewed
        -- source.  No PostgreSQL catalog text is executed.
        ALTER TABLE longspan_terra_receipt_attestations
            DROP CONSTRAINT IF EXISTS longspan_terra_receipt_attestations_migration_head_008_chk,
            DROP CONSTRAINT IF EXISTS longspan_terra_receipt_attestations_migration_head_check;
        ALTER TABLE longspan_terra_receipt_attestations
            ADD CONSTRAINT longspan_terra_receipt_attestations_migration_head_check
            CHECK (migration_head = '007_longspan_authority_hardening');

        ALTER TABLE longspan_terra_receipt_attestations
            DROP COLUMN IF EXISTS invalidated_at,
            DROP COLUMN IF EXISTS invalidation_reason;

        -- Restore the exact 007 table owner and ACL explicitly. This is
        -- repeated even though 008 upgrade applies the same policy, so a
        -- 008 -> 007 rehearsal cannot inherit release privileges.
        ALTER TABLE longspan_terra_receipt_attestations
            OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON longspan_terra_receipt_attestations
            FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};

        DROP FUNCTION IF EXISTS longspan_invalidate_terra_receipt_attestation(TEXT);
        DROP FUNCTION IF EXISTS longspan_invalidate_terra_receipt_attestation(
            TEXT, TEXT, TEXT, INTEGER, TEXT
        );

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

        -- The historical 007 objects are restored under the pinned migration
        -- owner. The downgrade guard may use SET ROLE, so never derive an
        -- owner from session_user or the transport account.
        DO $restore_007_function_owners$
        BEGIN
            ALTER FUNCTION public.longspan_append_terra_receipt(
                TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
                BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
            ) OWNER TO {MIGRATION_ROLE};
            ALTER FUNCTION public.longspan_terra_gateway_mac(
                TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER,
                TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT
            ) OWNER TO {MIGRATION_ROLE};
            ALTER FUNCTION public.longspan_terra_gateway_mac_for_attestation(TEXT)
                OWNER TO {MIGRATION_ROLE};
        END
        $restore_007_function_owners$;

        -- Restore the published 007 execution ACLs explicitly.  CREATE OR
        -- REPLACE does not remove PUBLIC EXECUTE from a routine that existed
        -- on a partially rehearsed target.
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
        REVOKE ALL ON FUNCTION longspan_append_terra_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_append_terra_receipt(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            BIGINT, INTEGER, TEXT, TEXT, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT
        ) TO {WORKFLOW_ROLE};
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
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            INTEGER, INTEGER, TEXT, TEXT, TEXT
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION longspan_append_authority_history(
            TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT,
            INTEGER, INTEGER, TEXT, TEXT, TEXT
        ) TO {AUTHORITY_ROLE};

        -- Keep every 008 provenance observation as an immutable archive. A
        -- downgrade/re-upgrade rehearsal appends an event; it never updates
        -- or deletes an earlier archive row.
        CREATE TABLE IF NOT EXISTS longspan_migration_provenance_008_archive (
            archive_id BIGINT PRIMARY KEY,
            revision TEXT NOT NULL,
            source_digest TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            normalization_version INTEGER NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL,
            application_count BIGINT NOT NULL DEFAULT 1,
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            provenance_table_preexisting BOOLEAN NOT NULL
        );
        ALTER TABLE longspan_migration_provenance_008_archive
            ADD COLUMN IF NOT EXISTS archive_id BIGINT,
            ADD COLUMN IF NOT EXISTS provenance_table_preexisting BOOLEAN
                NOT NULL DEFAULT TRUE;
        CREATE SEQUENCE IF NOT EXISTS longspan_migration_provenance_008_archive_id_seq;
        ALTER TABLE longspan_migration_provenance_008_archive
            ALTER COLUMN archive_id DROP DEFAULT;
        DO $archive_sequence_contract$
        BEGIN
            -- Older rehearsals created BIGSERIAL's implicit sequence before
            -- the explicit canonical sequence was introduced.  Remove that
            -- unused legacy sequence before binding the one authoritative
            -- allocator, so restore/re-upgrade cannot produce two owners.
            IF to_regclass('public.longspan_migration_provenance_008_archive_archive_id_seq')
                IS NOT NULL THEN
                ALTER SEQUENCE public.longspan_migration_provenance_008_archive_archive_id_seq
                    OWNED BY NONE;
                DROP SEQUENCE public.longspan_migration_provenance_008_archive_archive_id_seq;
            END IF;
        END
        $archive_sequence_contract$;
        ALTER SEQUENCE longspan_migration_provenance_008_archive_id_seq
            OWNED BY longspan_migration_provenance_008_archive.archive_id;
        UPDATE longspan_migration_provenance_008_archive
           SET archive_id = nextval('longspan_migration_provenance_008_archive_id_seq')
         WHERE archive_id IS NULL;
        ALTER TABLE longspan_migration_provenance_008_archive
            ALTER COLUMN archive_id SET DEFAULT nextval('longspan_migration_provenance_008_archive_id_seq'),
            ALTER COLUMN archive_id SET NOT NULL,
            ALTER COLUMN provenance_table_preexisting SET NOT NULL;
        SELECT setval(
            'longspan_migration_provenance_008_archive_id_seq',
            COALESCE((SELECT MAX(archive_id)
                      FROM longspan_migration_provenance_008_archive), 1),
            EXISTS (SELECT 1 FROM longspan_migration_provenance_008_archive)
        );
        ALTER TABLE longspan_migration_provenance_008_archive
            DROP CONSTRAINT IF EXISTS longspan_migration_provenance_008_archive_pkey;
        ALTER TABLE longspan_migration_provenance_008_archive
            ADD CONSTRAINT longspan_migration_provenance_008_archive_pkey PRIMARY KEY (archive_id);
        ALTER TABLE longspan_migration_provenance_008_archive
            ALTER COLUMN application_count SET DEFAULT 1,
            ALTER COLUMN last_seen_at SET DEFAULT clock_timestamp();
        ALTER TABLE longspan_migration_provenance_008_archive
            OWNER TO {MIGRATION_ROLE};
        REVOKE ALL ON longspan_migration_provenance_008_archive
            FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        GRANT SELECT ON longspan_migration_provenance_008_archive
            TO {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        CREATE OR REPLACE FUNCTION reject_longspan_migration_provenance_008_archive_mutation()
        RETURNS trigger AS $archive_guard$
        BEGIN
            RAISE EXCEPTION '008 migration provenance archive is append-only';
        END;
        $archive_guard$ LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public;
        DROP TRIGGER IF EXISTS longspan_migration_provenance_008_archive_append_only
            ON longspan_migration_provenance_008_archive;
        CREATE TRIGGER longspan_migration_provenance_008_archive_append_only
            BEFORE UPDATE OR DELETE ON longspan_migration_provenance_008_archive
            FOR EACH ROW
            EXECUTE FUNCTION reject_longspan_migration_provenance_008_archive_mutation();
        REVOKE ALL ON FUNCTION reject_longspan_migration_provenance_008_archive_mutation()
            FROM PUBLIC, {WORKFLOW_ROLE}, {AUTHORITY_ROLE};
        GRANT EXECUTE ON FUNCTION reject_longspan_migration_provenance_008_archive_mutation()
            TO {MIGRATION_ROLE};
        DO $archive_provenance$
        DECLARE
            source_row RECORD;
            provenance_table_preexisting BOOLEAN;
        BEGIN
            IF to_regclass('public.longspan_migration_provenance') IS NULL THEN
                RAISE EXCEPTION '008 downgrade provenance table is missing';
            END IF;
            SELECT COALESCE(state_row.provenance_table_preexisting, TRUE)
              INTO provenance_table_preexisting
            FROM longspan_migration_provenance_008_state AS state_row
            WHERE state_row.singleton;
            FOR source_row IN
                SELECT revision, source_digest, algorithm,
                       normalization_version, applied_at
                FROM longspan_migration_provenance
            LOOP
                IF EXISTS (
                    SELECT 1
                    FROM longspan_migration_provenance_008_archive
                    WHERE revision = source_row.revision
                      AND (
                          source_digest IS DISTINCT FROM source_row.source_digest
                          OR algorithm IS DISTINCT FROM source_row.algorithm
                          OR normalization_version IS DISTINCT FROM source_row.normalization_version
                      )
                ) THEN
                    RAISE EXCEPTION
                        '008 downgrade provenance archive conflicts for revision %',
                        source_row.revision;
                END IF;
                INSERT INTO longspan_migration_provenance_008_archive
                    (revision, source_digest, algorithm, normalization_version,
                     applied_at, application_count, last_seen_at,
                     provenance_table_preexisting)
                VALUES (
                    source_row.revision, source_row.source_digest, source_row.algorithm,
                    source_row.normalization_version, source_row.applied_at, 1,
                    clock_timestamp(), COALESCE(provenance_table_preexisting, TRUE)
                );
            END LOOP;
        END
        $archive_provenance$ LANGUAGE plpgsql;
        DO $restore_provenance_contract$
        DECLARE
            provenance_table_preexisting BOOLEAN;
        BEGIN
            SELECT COALESCE(state_row.provenance_table_preexisting, TRUE)
              INTO provenance_table_preexisting
            FROM longspan_migration_provenance_008_state AS state_row
            WHERE state_row.singleton;
            DELETE FROM longspan_migration_provenance
             WHERE revision = '008_longspan_authority_repair';
            IF NOT provenance_table_preexisting
               AND NOT EXISTS (SELECT 1 FROM longspan_migration_provenance) THEN
                DROP TABLE longspan_migration_provenance;
            END IF;
            DROP TABLE longspan_migration_provenance_008_state;
        END
        $restore_provenance_contract$ LANGUAGE plpgsql;

        """
    )
    # The 008 downgrade is the only step that creates the immutable archive.
    # Park it before Alembic invokes the 007/006 compatibility legs for any
    # target below 008.  Leaving it public would make the older closed
    # catalogs reject the database (or, worse, adopt an authority relation).
    # The administrative env gate provisions and validates this private
    # namespace before the migration role is entered; the migration role then
    # performs only the object moves below.
    op.execute(
        f"""
        DO $park_008_archive$
        DECLARE
            capability_nonce TEXT;
            witness_count BIGINT;
            target_revision TEXT;
            archive_owner TEXT;
            archive_owner_oid OID;
            recovery_owner TEXT;
            recovery_public_access BOOLEAN;
            archive_has_unexpected_acl BOOLEAN;
            archive_has_unexpected_column_acl BOOLEAN;
            archive_has_unexpected_default_acl BOOLEAN;
            archive_unexpected_default_role TEXT;
            archive_unexpected_default_objtype TEXT;
            archive_has_unexpected_sequence_acl BOOLEAN;
            archive_has_unexpected_guard_acl BOOLEAN;
        BEGIN
            -- Re-read the capability ledger row that the first guard updated
            -- in this same transaction.  xmin is xid (32-bit), while
            -- pg_current_xact_id() is xid8; the explicit cast and age check
            -- are a type-correct same-transaction proof.  The age check also
            -- makes the intended wraparound behavior explicit: only a row
            -- written by this transaction can witness the park.  A
            -- caller-created TEMP object or session GUC cannot authorize it.
            SELECT COUNT(*)::BIGINT, MAX(nonce), MAX(migration_revision)
              INTO witness_count, capability_nonce, target_revision
            FROM top_delivery_downgrade_capabilities
            WHERE database_name = current_database()
              AND database_role = current_user
              AND transport_database_role = session_user
              AND controller_service = 'top-delivery-controller'
              AND operation IN ('migration_downgrade', 'disposable_downgrade')
              AND '008_longspan_authority_repair' = ANY(consumed_steps)
              AND consumed_at >= transaction_timestamp()
              AND xmin = pg_current_xact_id()::xid
              AND age(xmin) = 0;
            IF witness_count <> 1
               OR capability_nonce IS NULL
               OR capability_nonce = '' THEN
                RAISE EXCEPTION
                    '008 archive park blocked: exactly one consumed capability witness is required';
            END IF;
            IF target_revision IS NULL
               OR target_revision NOT IN (
                   '007_longspan_authority_hardening',
                   '006_longspan_authority',
                   '005_longspan_hardening',
                   '004_longspan_workflow'
               ) THEN
                RAISE EXCEPTION
                    '008 archive park blocked: downgrade target is not an explicit historical revision';
            END IF;
            IF to_regclass('public.longspan_migration_provenance_008_archive') IS NULL THEN
                RAISE EXCEPTION '008 archive park blocked: archive table is missing';
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
                    '008 archive park blocked: recovery schema owner or PUBLIC ACL is unsafe';
            END IF;
            IF to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive') IS NOT NULL
               OR to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive_id_seq') IS NOT NULL
               OR to_regclass('top_delivery_recovery.longspan_migration_provenance_008_archive_archive_id_seq') IS NOT NULL
               OR to_regprocedure(
                   'top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation()'
               ) IS NOT NULL THEN
                RAISE EXCEPTION
                    '008 archive park blocked: recovery archive already exists';
            END IF;
            SELECT c.relowner, pg_get_userbyid(c.relowner)
              INTO archive_owner_oid, archive_owner
            FROM pg_class AS c
            WHERE c.oid = 'public.longspan_migration_provenance_008_archive'::regclass;
            IF archive_owner IS DISTINCT FROM '{MIGRATION_ROLE}' THEN
                RAISE EXCEPTION
                    '008 archive park blocked: archive owner is %', archive_owner;
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
                    '008 archive park blocked: archive has an unexpected ACL';
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
                    '008 archive park blocked: archive has an unexpected column ACL';
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
                    '008 archive park blocked: unsafe public default ACL for role % and object type %',
                    archive_unexpected_default_role,
                    archive_unexpected_default_objtype;
            END IF;
            SELECT EXISTS (
                SELECT 1
                FROM pg_class AS sequence_class
                WHERE sequence_class.oid IN (
                          to_regclass('public.longspan_migration_provenance_008_archive_id_seq'),
                          to_regclass('public.longspan_migration_provenance_008_archive_archive_id_seq')
                      )
                  AND EXISTS (
                      SELECT 1
                      FROM aclexplode(
                          COALESCE(
                              sequence_class.relacl,
                              acldefault('S', sequence_class.relowner)
                          )
                      ) AS acl
                      WHERE acl.grantee <> sequence_class.relowner
                  )
            ) INTO archive_has_unexpected_sequence_acl;
            IF archive_has_unexpected_sequence_acl THEN
                RAISE EXCEPTION
                    '008 archive park blocked: archive sequence has an unexpected ACL';
            END IF;
            SELECT EXISTS (
                SELECT 1
                FROM pg_proc AS routine
                WHERE routine.oid = to_regprocedure(
                          'public.reject_longspan_migration_provenance_008_archive_mutation()'
                      )
                  AND EXISTS (
                      SELECT 1
                      FROM aclexplode(
                          COALESCE(
                              routine.proacl,
                              acldefault('f', routine.proowner)
                          )
                      ) AS acl
                      WHERE acl.grantee <> routine.proowner
                  )
            ) INTO archive_has_unexpected_guard_acl;
            IF archive_has_unexpected_guard_acl THEN
                RAISE EXCEPTION
                    '008 archive park blocked: archive guard routine has an unexpected ACL';
            END IF;
            ALTER TABLE public.longspan_migration_provenance_008_archive
                SET SCHEMA top_delivery_recovery;
            ALTER TABLE top_delivery_recovery.longspan_migration_provenance_008_archive
                OWNER TO {MIGRATION_ROLE};
            REVOKE ALL ON top_delivery_recovery.longspan_migration_provenance_008_archive
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
                GRANT EXECUTE ON FUNCTION top_delivery_recovery.reject_longspan_migration_provenance_008_archive_mutation()
                    TO {MIGRATION_ROLE};
            END IF;
        END
        $park_008_archive$ LANGUAGE plpgsql;
        """
    )
