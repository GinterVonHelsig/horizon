DROP FUNCTION IF EXISTS longspan_park_disabled_parent_retries(TEXT, INTEGER, BIGINT, TEXT);
CREATE OR REPLACE FUNCTION public.require_longspan_mutation_scope()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public'
AS $function$
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
            IF session_user = 'top_delivery_workflow'
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
               AND scope_payload->>'operation' = 'schedule_goal_task'
               AND (TG_OP <> 'INSERT' OR TG_TABLE_NAME <> 'parent_tasks') THEN
                RAISE EXCEPTION 'schedule_goal_task scope is limited to parent task inserts';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'schedule_goal_task'
               AND TG_TABLE_NAME = 'parent_tasks'
               AND (
                   TG_OP <> 'INSERT'
                   OR (row_data->>'state') IS DISTINCT FROM 'queued'
                   OR COALESCE((row_data->>'attempt')::INTEGER, 0) IS DISTINCT FROM 0
               ) THEN
                RAISE EXCEPTION 'schedule_goal_task scope only permits queued parent inserts';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND TG_TABLE_NAME IN (
                   'parent_tasks', 'task_attempts', 'retry_queue', 'longspan_children',
                   'longspan_plans', 'longspan_execution_results',
                   'longspan_execution_audits', 'longspan_auditor_receipts',
                   'longspan_terra_receipts', 'longspan_evidence_ledger'
               )
               AND COALESCE(scope_payload->>'operation', 'general') NOT IN
                   ('park_children', 'expire_stale_children', 'schedule_goal_task') THEN
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

                IF scope_payload->>'operation' = 'cleanup_expired_attempt' THEN
                    IF scope_payload->>'attempt_id' IS NULL THEN
                        RAISE EXCEPTION 'cleanup scope requires attempt_id';
                    END IF;
                    IF TG_TABLE_NAME = 'task_attempts' THEN
                        IF row_data->>'attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'cleanup attempt mismatch';
                        END IF;
                        IF TG_OP <> 'UPDATE'
                           OR (row_data->>'status') NOT IN ('stale', 'failed') THEN
                            RAISE EXCEPTION
                                'cleanup scope only permits stale or failed attempt terminalization';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'parent_tasks' THEN
                        IF (
                            CASE
                                WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD)->>'active_attempt_id'
                                ELSE row_data->>'active_attempt_id'
                            END
                        ) IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'cleanup parent attempt mismatch';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                        IF TG_OP <> 'INSERT' THEN
                            RAISE EXCEPTION 'cleanup retry scope only permits inserts';
                        END IF;
                    ELSE
                        RAISE EXCEPTION 'cleanup scope is limited to parent, attempt, and retry rows';
                    END IF;
                    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
                END IF;
                IF scope_payload->>'operation' = 'requeue_blocked_parent_task' THEN
                    IF scope_payload->>'attempt_id' IS NULL THEN
                        RAISE EXCEPTION 'requeue scope requires attempt_id';
                    END IF;
                    IF TG_TABLE_NAME = 'parent_tasks' THEN
                        IF TG_OP <> 'UPDATE' THEN
                            RAISE EXCEPTION 'requeue parent scope only permits updates';
                        END IF;
                        IF to_jsonb(OLD)->>'active_attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'requeue parent attempt mismatch';
                        END IF;
                        IF (row_data->>'state') IS DISTINCT FROM 'queued'
                           OR (row_data->>'active_attempt_id') IS NOT NULL
                           OR (row_data->>'task_id') IS DISTINCT FROM scope_payload->>'task_id'
                           OR (row_data->>'run_id') IS DISTINCT FROM scope_payload->>'run_id'
                           OR (row_data->>'attempt') IS DISTINCT FROM scope_payload->>'next_attempt'
                           OR (row_data->>'objective') IS DISTINCT FROM to_jsonb(OLD)->>'objective'
                           OR (row_data->>'priority') IS DISTINCT FROM to_jsonb(OLD)->>'priority' THEN
                            RAISE EXCEPTION
                                'requeue scope only permits queued parent rows with no active attempt';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'task_attempts' THEN
                        IF row_data->>'attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'requeue attempt mismatch';
                        END IF;
                        IF TG_OP <> 'UPDATE'
                           OR (row_data->>'status') IS DISTINCT FROM 'blocked' THEN
                            RAISE EXCEPTION
                                'requeue scope only permits blocked attempt terminalization';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                        IF TG_OP <> 'INSERT' THEN
                            RAISE EXCEPTION 'requeue retry scope only permits inserts';
                        END IF;
                        IF (row_data->>'reason') IS DISTINCT FROM 'operator_requeue_blocked'
                           OR (row_data->>'state') IS DISTINCT FROM 'queued'
                           OR (row_data->>'task_id') IS DISTINCT FROM scope_payload->>'task_id'
                           OR (row_data->>'run_id') IS DISTINCT FROM scope_payload->>'run_id'
                           OR (row_data->>'attempt') IS DISTINCT FROM scope_payload->>'next_attempt' THEN
                            RAISE EXCEPTION 'requeue retry row is outside the scoped parent fence';
                        END IF;
                    ELSE
                        RAISE EXCEPTION 'requeue scope is limited to parent, attempt, and retry rows';
                    END IF;
                    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
                END IF;
                IF scope_payload->>'operation' = 'recover_executor_contract_failure' THEN
                    IF scope_payload->>'attempt_id' IS NULL THEN
                        RAISE EXCEPTION 'recover scope requires attempt_id';
                    END IF;
                    IF scope_payload->>'failure_class' IS DISTINCT FROM 'malformed_structured_output' THEN
                        RAISE EXCEPTION 'recover scope only permits malformed_structured_output';
                    END IF;
                    IF TG_TABLE_NAME = 'parent_tasks' THEN
                        IF TG_OP <> 'UPDATE' THEN
                            RAISE EXCEPTION 'recover parent scope only permits updates';
                        END IF;
                        IF (row_data->>'task_id') IS DISTINCT FROM scope_payload->>'task_id'
                           OR (row_data->>'run_id') IS DISTINCT FROM scope_payload->>'run_id'
                           OR (row_data->>'objective') IS DISTINCT FROM to_jsonb(OLD)->>'objective'
                           OR (row_data->>'priority') IS DISTINCT FROM to_jsonb(OLD)->>'priority'
                           OR (to_jsonb(OLD)->>'attempt') IS DISTINCT FROM scope_payload->>'expected_attempt' THEN
                            RAISE EXCEPTION 'recover parent identity is outside the scoped fence';
                        END IF;
                        IF to_jsonb(OLD)->>'active_attempt_id' IS NOT NULL
                           AND to_jsonb(OLD)->>'active_attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'recover parent attempt mismatch';
                        END IF;
                        IF scope_payload->>'outcome' = 'requeue' THEN
                            IF (row_data->>'state') IS DISTINCT FROM 'queued'
                               OR (row_data->>'active_attempt_id') IS NOT NULL
                               OR (row_data->>'attempt') IS DISTINCT FROM scope_payload->>'next_attempt' THEN
                                RAISE EXCEPTION
                                    'recover scope only permits queued parent rows with no active attempt';
                            END IF;
                        ELSIF scope_payload->>'outcome' = 'exhaust' THEN
                            IF (row_data->>'state') IS DISTINCT FROM 'failed'
                               OR (row_data->>'active_attempt_id') IS NOT NULL
                               OR (row_data->>'attempt') IS DISTINCT FROM scope_payload->>'expected_attempt' THEN
                                RAISE EXCEPTION
                                    'recover exhaust scope only permits failed parent rows without retry increment';
                            END IF;
                        ELSE
                            RAISE EXCEPTION 'recover scope requires a requeue or exhaust outcome';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'task_attempts' THEN
                        IF scope_payload->>'bridge_expire' = 'true'
                           AND TG_OP = 'UPDATE'
                           AND row_data->>'attempt_id' IS NOT DISTINCT FROM scope_payload->>'attempt_id'
                           AND to_jsonb(OLD)->>'status' = 'running'
                           AND (row_data->>'status') IN ('failed', 'stale')
                           AND (row_data->>'lease_expires_at')::timestamptz <= clock_timestamp() THEN
                            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
                        END IF;
                        IF row_data->>'attempt_id' IS DISTINCT FROM scope_payload->>'attempt_id' THEN
                            RAISE EXCEPTION 'recover attempt mismatch';
                        END IF;
                        IF TG_OP <> 'UPDATE'
                           OR (row_data->>'status') NOT IN ('failed', 'stale')
                           OR (row_data->>'lease_expires_at')::timestamptz > clock_timestamp() THEN
                            RAISE EXCEPTION
                                'recover scope only permits terminal non-live attempt rows';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                        IF scope_payload->>'outcome' IS DISTINCT FROM 'requeue' THEN
                            RAISE EXCEPTION 'recover exhaust scope does not permit retry_queue rows';
                        END IF;
                        IF TG_OP <> 'INSERT' THEN
                            RAISE EXCEPTION 'recover retry scope only permits inserts';
                        END IF;
                        IF (row_data->>'reason') IS DISTINCT FROM 'recover_executor_contract_failure'
                           OR (row_data->>'state') IS DISTINCT FROM 'queued'
                           OR (row_data->>'task_id') IS DISTINCT FROM scope_payload->>'task_id'
                           OR (row_data->>'run_id') IS DISTINCT FROM scope_payload->>'run_id'
                           OR (row_data->>'attempt') IS DISTINCT FROM scope_payload->>'next_attempt' THEN
                            RAISE EXCEPTION 'recover retry row is outside the scoped parent fence';
                        END IF;
                    ELSE
                        RAISE EXCEPTION 'recover scope is limited to parent, attempt, and retry rows';
                    END IF;
                    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
                END IF;
                IF scope_payload->>'operation' = 'recover_exhausted_executor_contract_once' THEN
                    IF scope_payload->>'attempt_id' IS NULL THEN
                        RAISE EXCEPTION 'post-exhaust recover scope requires attempt_id';
                    END IF;
                    IF scope_payload->>'failure_class' IS DISTINCT FROM 'malformed_structured_output' THEN
                        RAISE EXCEPTION 'post-exhaust recover scope only permits malformed_structured_output';
                    END IF;
                    IF TG_TABLE_NAME = 'parent_tasks' THEN
                        IF TG_OP <> 'UPDATE' THEN
                            RAISE EXCEPTION 'post-exhaust recover parent scope only permits updates';
                        END IF;
                        IF (row_data->>'task_id') IS DISTINCT FROM scope_payload->>'task_id'
                           OR (row_data->>'run_id') IS DISTINCT FROM scope_payload->>'run_id'
                           OR (row_data->>'objective') IS DISTINCT FROM to_jsonb(OLD)->>'objective'
                           OR (row_data->>'priority') IS DISTINCT FROM to_jsonb(OLD)->>'priority'
                           OR (to_jsonb(OLD)->>'attempt') IS DISTINCT FROM scope_payload->>'expected_attempt' THEN
                            RAISE EXCEPTION 'post-exhaust recover parent identity is outside the scoped fence';
                        END IF;
                        IF to_jsonb(OLD)->>'active_attempt_id' IS NOT NULL THEN
                            RAISE EXCEPTION 'post-exhaust recover parent requires no active attempt';
                        END IF;
                        IF (row_data->>'state') IS DISTINCT FROM 'queued'
                           OR (row_data->>'active_attempt_id') IS NOT NULL
                           OR (row_data->>'attempt') IS DISTINCT FROM scope_payload->>'next_attempt' THEN
                            RAISE EXCEPTION
                                'post-exhaust recover scope only permits queued parent rows at next attempt';
                        END IF;
                    ELSIF TG_TABLE_NAME = 'task_attempts' THEN
                        RAISE EXCEPTION 'post-exhaust recover scope does not mutate task_attempts';
                    ELSIF TG_TABLE_NAME = 'retry_queue' THEN
                        IF scope_payload->>'outcome' IS DISTINCT FROM 'requeue' THEN
                            RAISE EXCEPTION 'post-exhaust recover scope requires requeue outcome';
                        END IF;
                        IF (row_data->>'reason') IS DISTINCT FROM 'recover_exhausted_executor_contract_once'
                           OR (row_data->>'attempt')::INTEGER IS DISTINCT FROM (scope_payload->>'next_attempt')::INTEGER THEN
                            RAISE EXCEPTION 'post-exhaust recover retry row is outside the scoped fence';
                        END IF;
                    END IF;
                    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
                END IF;
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
                ELSIF TG_TABLE_NAME = 'parent_tasks' THEN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM task_attempts AS attempt
                        WHERE attempt.attempt_id = COALESCE(
                            row_data->>'active_attempt_id',
                            (
                                SELECT parent.active_attempt_id
                                FROM parent_tasks AS parent
                                WHERE parent.task_id = row_data->>'task_id'
                                  AND parent.run_id = scope_payload->>'run_id'
                            )
                        )
                          AND attempt.task_id = row_data->>'task_id'
                          AND attempt.run_id = scope_payload->>'run_id'
                          AND attempt.fence_token = (scope_payload->>'fence_token')::BIGINT
                          AND attempt.controller_epoch = (scope_payload->>'controller_epoch')::BIGINT
                          AND attempt.status = 'running'
                          AND attempt.lease_expires_at > clock_timestamp()
                    ) THEN
                        RAISE EXCEPTION
                            'workflow mutation task row is outside the scoped parent fence';
                    END IF;
                ELSIF TG_TABLE_NAME = 'retry_queue' THEN
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
                            'workflow mutation retry row is outside the scoped parent fence';
                    END IF;
                END IF;
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END;
        $function$
;
