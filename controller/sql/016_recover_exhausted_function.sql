-- Candidate 016 one-time post-exhaust recovery for the documented activation target.
-- Do not apply to top_delivery_control_p1 except through the 016 activation envelope.
CREATE OR REPLACE FUNCTION public.longspan_recover_exhausted_executor_contract_once(
    p_run_id TEXT,
    p_task_id TEXT,
    p_attempt_id TEXT,
    p_controller_epoch INTEGER,
    p_owner TEXT,
    p_fence_token BIGINT,
    p_failure_class TEXT
) RETURNS JSONB AS $$
DECLARE
    control_row public.controller_control%ROWTYPE;
    parent_row public.parent_tasks%ROWTYPE;
    attempt_row public.task_attempts%ROWTYPE;
    mac_key TEXT;
    scope_payload JSONB;
    scope_signature TEXT;
    v_retry_key TEXT;
    v_retry_row public.retry_queue%ROWTYPE;
    v_inserted INTEGER;
    v_auth_run CONSTANT TEXT := 'goal-e0c31abe91a34414';
    v_auth_task CONSTANT TEXT := 'goal-e0c31abe91a34414-ws-01';
    v_auth_attempt CONSTANT TEXT := '9e2610d369ca4f458d8a852f7007709f';
    v_from_attempt CONSTANT INTEGER := 5;
    v_to_attempt CONSTANT INTEGER := 6;
BEGIN
    IF session_user <> 'top_delivery_workflow' THEN
        RAISE EXCEPTION 'post-exhaust recovery requires the workflow principal';
    END IF;
    IF p_run_id IS DISTINCT FROM v_auth_run
       OR p_task_id IS DISTINCT FROM v_auth_task
       OR p_attempt_id IS DISTINCT FROM v_auth_attempt THEN
        RAISE EXCEPTION '016 recovery is fenced to the documented activation target';
    END IF;
    IF p_owner IS NULL OR btrim(p_owner) = '' THEN
        RAISE EXCEPTION 'post-exhaust recovery requires the pinned owner';
    END IF;
    IF p_fence_token IS NULL OR p_fence_token < 1 THEN
        RAISE EXCEPTION 'post-exhaust recovery requires the fence token';
    END IF;
    IF p_failure_class IS DISTINCT FROM 'malformed_structured_output' THEN
        RAISE EXCEPTION 'post-exhaust recovery accepts only malformed_structured_output';
    END IF;
    SELECT * INTO control_row
    FROM public.controller_control
    WHERE run_id = p_run_id
    FOR UPDATE;
    IF NOT FOUND
       OR control_row.current_epoch IS DISTINCT FROM p_controller_epoch
       OR control_row.owner IS DISTINCT FROM p_owner
       OR NOT control_row.scheduling_enabled
       OR control_row.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'post-exhaust recovery is not bound to the live controller lease';
    END IF;
    SELECT * INTO parent_row
    FROM public.parent_tasks
    WHERE run_id = p_run_id AND task_id = p_task_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'post-exhaust recovery target task is missing';
    END IF;
    IF parent_row.state = 'queued'
       AND parent_row.active_attempt_id IS NULL
       AND parent_row.attempt = v_to_attempt THEN
        v_retry_key := 'retry:' || p_run_id || ':' || p_task_id || ':attempt:' || v_to_attempt::TEXT;
        SELECT * INTO v_retry_row FROM public.retry_queue WHERE retry_key = v_retry_key;
        IF FOUND
           AND v_retry_row.reason = 'recover_exhausted_executor_contract_once'
           AND v_retry_row.state = 'queued' THEN
            RETURN jsonb_build_object(
                'recovered', false,
                'reason', 'already_queued',
                'disposition', 'ALREADY_QUEUED',
                'task_id', parent_row.task_id,
                'attempt', parent_row.attempt,
                'state', parent_row.state,
                'prior_attempt_id', p_attempt_id
            );
        END IF;
    END IF;
    IF parent_row.state IS DISTINCT FROM 'failed'
       OR parent_row.attempt IS DISTINCT FROM v_from_attempt
       OR parent_row.active_attempt_id IS NOT NULL THEN
        RAISE EXCEPTION 'post-exhaust recovery requires failed|5| with no active attempt';
    END IF;
    SELECT * INTO attempt_row
    FROM public.task_attempts
    WHERE attempt_id = p_attempt_id AND run_id = p_run_id AND task_id = p_task_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'post-exhaust recovery historical attempt is missing';
    END IF;
    IF attempt_row.status IS DISTINCT FROM 'stale'
       OR attempt_row.ended_at IS NULL
       OR attempt_row.lease_expires_at > clock_timestamp() THEN
        RAISE EXCEPTION 'post-exhaust recovery requires a terminal stale historical attempt';
    END IF;
    IF attempt_row.fence_token IS DISTINCT FROM p_fence_token THEN
        RAISE EXCEPTION 'post-exhaust recovery fence token mismatch';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM public.task_attempts AS other
        WHERE other.run_id = p_run_id
          AND other.task_id = p_task_id
          AND other.fence_token > attempt_row.fence_token
    ) THEN
        RAISE EXCEPTION 'post-exhaust recovery historical attempt is not the highest fence';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM public.task_attempts AS live
        WHERE live.run_id = p_run_id
          AND live.task_id = p_task_id
          AND live.status = 'running'
          AND live.lease_expires_at > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'post-exhaust recovery refuses while a live attempt lease exists';
    END IF;
    SELECT material.mac_key INTO mac_key
    FROM public.longspan_mac_material AS material
    WHERE material.material_id = 'ledger';
    IF mac_key IS NULL THEN
        RAISE EXCEPTION 'post-exhaust recovery MAC material is unavailable';
    END IF;
    scope_payload := jsonb_build_object(
        'scope_kind', 'workflow',
        'run_id', p_run_id,
        'task_id', p_task_id,
        'controller_epoch', attempt_row.controller_epoch,
        'fence_token', attempt_row.fence_token,
        'operation', 'recover_exhausted_executor_contract_once',
        'attempt_id', p_attempt_id,
        'owner', p_owner,
        'expected_attempt', v_from_attempt,
        'next_attempt', v_to_attempt,
        'failure_class', p_failure_class,
        'outcome', 'requeue'
    );
    scope_signature := encode(
        public.hmac(
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
    UPDATE public.parent_tasks
    SET state = 'queued',
        available_at = clock_timestamp(),
        attempt = v_to_attempt,
        active_attempt_id = NULL,
        updated_at = clock_timestamp()
    WHERE task_id = p_task_id
      AND run_id = p_run_id
      AND state = 'failed'
      AND attempt = v_from_attempt
      AND active_attempt_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'post-exhaust recovery lost the task fence';
    END IF;
    v_retry_key := 'retry:' || p_run_id || ':' || p_task_id || ':attempt:' || v_to_attempt::TEXT;
    INSERT INTO public.retry_queue
        (retry_key, run_id, task_id, available_at, attempt, reason, state)
    VALUES (
        v_retry_key, p_run_id, p_task_id, clock_timestamp(), v_to_attempt,
        'recover_exhausted_executor_contract_once', 'queued'
    )
    ON CONFLICT ON CONSTRAINT retry_queue_pkey DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted = 0 THEN
        SELECT * INTO v_retry_row FROM public.retry_queue WHERE retry_key = v_retry_key;
        IF NOT FOUND
           OR v_retry_row.reason IS DISTINCT FROM 'recover_exhausted_executor_contract_once'
           OR v_retry_row.state IS DISTINCT FROM 'queued' THEN
            RAISE EXCEPTION 'post-exhaust recovery retry row conflict';
        END IF;
    END IF;
    PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
    PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
    RETURN jsonb_build_object(
        'recovered', true,
        'reason', 'recovered_contract_failure',
        'disposition', 'RECOVERED_CONTRACT_FAILURE',
        'task_id', p_task_id,
        'attempt', v_to_attempt,
        'state', 'queued',
        'prior_attempt_id', p_attempt_id
    );
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('top_delivery.mutation_scope_payload', '', true);
    PERFORM set_config('top_delivery.mutation_scope_signature', '', true);
    RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp;

REVOKE ALL ON FUNCTION public.longspan_recover_exhausted_executor_contract_once(
    TEXT, TEXT, TEXT, INTEGER, TEXT, BIGINT, TEXT
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.longspan_recover_exhausted_executor_contract_once(
    TEXT, TEXT, TEXT, INTEGER, TEXT, BIGINT, TEXT
) TO top_delivery_workflow;
