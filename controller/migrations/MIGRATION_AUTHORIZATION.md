# Migration authorization (010–013)

This repository explicitly authorizes workflow-scope migrations **010–013** required for live parent-task claim, scope-guard fixes, and expired-attempt cleanup. See also `.superpowers/sdd/top-delivery-goal-runner-cefab4aa.plan/task-6-migration-authorization-appendix.md`.

## Authorized by plan/brief

- **009 `longspan_schedule_goal_task`**: controller-scope INSERT on `parent_tasks` for `schedule_goal_task` only.

## Applied to unblock live claim/cleanup (010–013)

| Revision | Workflow routines | Controller allowlist change |
|----------|-------------------|-----------------------------|
| **010** `longspan_claim_next_parent_task` | Claim queued parent → leased + running attempt | **None** |
| **011** fence-token fix for claim MAC scope | Same | **None** |
| **012** trigger: parent `active_attempt_id` bind under workflow scope | Trigger only | **None** |
| **013** `longspan_cleanup_expired_parent_attempt` | Expired/superseded attempt cleanup | **None** |
| **014** `longspan_ingest_project_program` / `longspan_get_project_node_ledger` | Horizon project ledger ingest/query | **None** (adds `horizon_projects`, `horizon_project_nodes`) |

Do **not** revert 010–014; claim/cleanup/ledger on Comms-01 depends on them.
