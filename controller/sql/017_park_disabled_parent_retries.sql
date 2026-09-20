DO $td017preflight$
DECLARE
  live_def text;
  live_sha text;
  expected_sha text := 'e74705db62ce82431620009904710495eb1095832d9c0e16599b8ed5ec4c34c2';
BEGIN
  BEGIN
    live_def := pg_get_functiondef(
      'public.require_longspan_mutation_scope()'::regprocedure
    );
  EXCEPTION WHEN undefined_function THEN
    RAISE EXCEPTION '017 refuses to apply: require_longspan_mutation_scope is missing';
  END;
  live_sha := encode(digest(convert_to(live_def, 'UTF8'), 'sha256'), 'hex');
  IF live_sha IS DISTINCT FROM expected_sha THEN
    RAISE EXCEPTION '017 refuses to replace require_longspan_mutation_scope: body hash % does not match embedded 016 dump hash %', live_sha, expected_sha;
  END IF;
END
$td017preflight$;
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
                            WHEN scope_payload->>'scope_kind' = 'controller'
                                AND COALESCE(scope_payload->>'operation', 'general') =
                                    'park_disabled_parent_retries'
                                THEN 'top_delivery:controller_disabled_retry_park_scope:v1:'
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
                   ('register_run', 'acquire_controller', 'park_disabled_parent_retries')
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

            IF scope_payload->>'scope_kind' = 'controller'
               AND COALESCE(scope_payload->>'operation', 'general') = 'park_disabled_parent_retries'
               AND NOT EXISTS (
                   SELECT 1
                   FROM controller_control
                   WHERE run_id = scope_payload->>'run_id'
                     AND current_epoch = (scope_payload->>'controller_epoch')::INTEGER
                     AND controller_fence_token =
                         (scope_payload->>'controller_fence_token')::BIGINT
                     AND owner IS NOT DISTINCT FROM NULLIF(scope_payload->>'owner', '')
                     AND NOT scheduling_enabled
                     AND lease_expires_at <= clock_timestamp()
               ) THEN
                RAISE EXCEPTION 'disabled-parent retry park scope is stale';
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
                   ('park_children', 'expire_stale_children', 'schedule_goal_task',
                    'park_disabled_parent_retries') THEN
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

            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'park_disabled_parent_retries'
               AND TG_TABLE_NAME NOT IN ('retry_queue', 'supervisor_events', 'controller_control') THEN
                RAISE EXCEPTION 'park_disabled_parent_retries scope table is outside the exact allowlist';
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'park_disabled_parent_retries'
               AND TG_TABLE_NAME = 'retry_queue' THEN
                IF TG_OP <> 'UPDATE'
                   OR OLD.state IS DISTINCT FROM 'queued'
                   OR NEW.state IS DISTINCT FROM 'parked'
                   OR NEW.run_id IS DISTINCT FROM scope_payload->>'run_id'
                   OR to_jsonb(NEW) - 'state' IS DISTINCT FROM to_jsonb(OLD) - 'state' THEN
                    RAISE EXCEPTION 'park_disabled_parent_retries retry transition is invalid';
                END IF;
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'park_disabled_parent_retries'
               AND TG_TABLE_NAME = 'supervisor_events' THEN
                IF TG_OP <> 'INSERT'
                   OR NEW.event_type IS DISTINCT FROM 'disabled_parent_retries_parked'
                   OR NEW.run_id IS DISTINCT FROM scope_payload->>'run_id' THEN
                    RAISE EXCEPTION 'park_disabled_parent_retries event transition is invalid';
                END IF;
            END IF;
            IF scope_payload->>'scope_kind' = 'controller'
               AND scope_payload->>'operation' = 'park_disabled_parent_retries'
               AND TG_TABLE_NAME = 'controller_control' THEN
                IF TG_OP <> 'UPDATE'
                   OR NEW.scheduling_enabled
                   OR NEW.owner IS NOT NULL
                   OR to_jsonb(NEW) - ARRAY['event_seq_counter', 'updated_at']
                      IS DISTINCT FROM to_jsonb(OLD) - ARRAY['event_seq_counter', 'updated_at'] THEN
                    RAISE EXCEPTION 'park_disabled_parent_retries cannot mutate controller identity, scheduling, owner, epoch, fence, or lease';
                END IF;
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

DROP FUNCTION IF EXISTS longspan_park_disabled_parent_retries(TEXT, INTEGER, BIGINT, TEXT);
CREATE OR REPLACE FUNCTION longspan_park_disabled_parent_retries(
    p_run_id TEXT,
    p_controller_epoch INTEGER,
    p_expected_controller_fence BIGINT,
    p_claimed_owner TEXT DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    control_row controller_control%ROWTYPE;
    mac_key TEXT;
    scope_payload JSONB;
    scope_signature TEXT;
    parked_count INTEGER;
    sequence_number BIGINT;
    claimed TEXT;
BEGIN
    IF session_user <> 'top_delivery_workflow' THEN
        RAISE EXCEPTION 'disabled-parent retry park requires the workflow principal';
    END IF;
    IF p_run_id IS NULL OR btrim(p_run_id) = '' THEN
        RAISE EXCEPTION 'disabled-parent retry park run id is required';
    END IF;
    IF p_expected_controller_fence IS NULL OR p_expected_controller_fence <= 0 THEN
        RAISE EXCEPTION 'disabled-parent retry park requires a positive expected controller fence';
    END IF;
    claimed := NULLIF(btrim(COALESCE(p_claimed_owner, '')), '');
    SELECT * INTO control_row
    FROM controller_control
    WHERE run_id = p_run_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'disabled-parent retry park target run is unknown';
    END IF;
    IF control_row.current_epoch IS DISTINCT FROM p_controller_epoch THEN
        RAISE EXCEPTION 'disabled-parent retry park epoch is stale';
    END IF;
    IF control_row.controller_fence_token IS DISTINCT FROM p_expected_controller_fence THEN
        RAISE EXCEPTION 'disabled-parent retry park fence is stale';
    END IF;
    IF control_row.owner IS DISTINCT FROM claimed THEN
        RAISE EXCEPTION 'disabled-parent retry park owner is stale';
    END IF;
    IF control_row.scheduling_enabled THEN
        RAISE EXCEPTION 'disabled-parent retry park requires scheduling to already be disabled';
    END IF;
    IF control_row.lease_expires_at > clock_timestamp() THEN
        RAISE EXCEPTION 'disabled-parent retry park requires an inactive controller lease';
    END IF;
    SELECT material.mac_key INTO mac_key
    FROM longspan_mac_material AS material
    WHERE material.material_id = 'ledger';
    IF mac_key IS NULL THEN
        RAISE EXCEPTION 'disabled-parent retry park mutation MAC material is unavailable';
    END IF;
    scope_payload := jsonb_strip_nulls(jsonb_build_object(
        'scope_kind', 'controller',
        'run_id', p_run_id,
        'controller_epoch', p_controller_epoch,
        'controller_fence_token', p_expected_controller_fence,
        'owner', claimed,
        'operation', 'park_disabled_parent_retries'
    ));
    scope_signature := encode(
        hmac(
            convert_to(
                'top_delivery:controller_disabled_retry_park_scope:v1:' || scope_payload::TEXT,
                'UTF8'
            ),
            convert_to(mac_key, 'UTF8'),
            'sha256'
        ),
        'hex'
    );
    PERFORM set_config('top_delivery.mutation_scope_payload', scope_payload::TEXT, true);
    PERFORM set_config('top_delivery.mutation_scope_signature', scope_signature, true);
    -- R3: re-read the locked controller_control row before mutations.
    SELECT * INTO control_row
    FROM controller_control
    WHERE run_id = p_run_id;
    IF NOT FOUND
       OR control_row.scheduling_enabled
       OR control_row.lease_expires_at > clock_timestamp()
       OR control_row.owner IS DISTINCT FROM claimed
       OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
       OR control_row.controller_fence_token IS DISTINCT FROM p_expected_controller_fence THEN
        RAISE EXCEPTION 'disabled-parent retry park lost the disabled fence after lock';
    END IF;
    UPDATE retry_queue
    SET state = 'parked'
    WHERE run_id = p_run_id AND state = 'queued';
    GET DIAGNOSTICS parked_count = ROW_COUNT;
    IF current_database() ~ '^td_test_'
       AND current_setting('top_delivery.force_park_disabled_abort', true) = '1' THEN
        RAISE EXCEPTION 'injected abort after retry park';
    END IF;
    SELECT longspan_next_event_seq(p_run_id, p_controller_epoch)
      INTO sequence_number;
    IF sequence_number IS NULL THEN
        RAISE EXCEPTION 'disabled-parent retry park event sequence allocation failed';
    END IF;
    INSERT INTO supervisor_events
        (event_id, event_seq, run_id, controller_epoch, event_type, occurred_at, detail_json)
    VALUES
        (replace(gen_random_uuid()::TEXT, '-', ''), sequence_number, p_run_id,
         p_controller_epoch, 'disabled_parent_retries_parked', clock_timestamp(),
         jsonb_build_object('parked_count', parked_count, 'scheduling_enabled', false)::TEXT);
    PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
    PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
    RETURN parked_count;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
    PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
    RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;
ALTER FUNCTION longspan_park_disabled_parent_retries(TEXT, INTEGER, BIGINT, TEXT)
    OWNER TO top_delivery_migration;
REVOKE ALL ON FUNCTION longspan_park_disabled_parent_retries(TEXT, INTEGER, BIGINT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION longspan_park_disabled_parent_retries(TEXT, INTEGER, BIGINT, TEXT)
    TO top_delivery_workflow;
