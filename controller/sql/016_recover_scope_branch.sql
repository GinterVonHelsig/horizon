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
