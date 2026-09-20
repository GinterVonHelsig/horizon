# TOP-DELIVERY implementation specification

## Objective

Provide durable, remote-visible project management for the complete trading
platform while preserving one authoritative delivery/release controller.

## Responsibilities

### TOP-DELIVERY owns

- project objective and acceptance tree;
- roadmap, workstreams, dependencies and priority calculation;
- operator questions and decision requests;
- queueable remediation classification;
- child task leases and retry budgets;
- checkpoints, parked branches and resumptions;
- evidence references and status reconciliation;
- next-outcome recommendations;
- lifecycle cleanup of terminal child agents.

### TERRA-DELIVERY owns

- phase manifest and authority envelope;
- sanitized model routing;
- implementation/review/test/QA sequencing;
- exact source and parent verification;
- PostgreSQL target and migration identity;
- backup, restore, WAL/PITR and rollback gates;
- broker flatness/order-safety gates;
- merge, deployment and final acceptance.

### LONGSPAN owns

- one isolated queueable task at a time;
- fresh context per task attempt;
- task-local Manager/Executor/Auditor loop;
- local tests, diagnostics and remediation;
- append-only task evidence;
- no production release authority.

## Model assignment and local execution boundary

- The TOP-DELIVERY parent Manager/coordinator is Terra xhigh through
  OpenRouter. It owns project decomposition, dependencies, priority and the
  next-outcome decision.
- Qwen3.8-27B Q4_K_M on Comms-01 is the default Longspan Executor for bounded
  mechanical tasks, artifact and log summaries, test-failure classification,
  review-packet compression, documentation, evidence indexing and browser
  inspection.
- KAT-Coder V2.5 Q4 on Comms-02 is the paired implementation lane for bounded
  code changes, mechanical refactors and focused test generation. The two
  models operate as one local Executor team: Qwen prepares a persisted task
  packet, KAT implements it in an isolated fresh-context worktree, Qwen may
  perform a mechanical consistency check, and Terra independently audits the
  result.
- The local team uses separate worktree leases and never permits concurrent
  writes to the same worktree. Both local models are prohibited from changing
  authority, acceptance criteria, migrations, production databases, brokers,
  ledger or strategy state, network policy, or release decisions.
- Cursor Composer is the Executor fallback for complex or ambiguous source
  changes. A local-model response is never accepted as a release-capable
  implementation without the normal independent review.
- Terra is the primary independent Auditor. Claude Opus 5 and Claude Fable 5
  are configured reviewer fallbacks; an Executor may never audit its own
  output.
- The deterministic controller, not a model, owns leases, retry attempt
  numbers, evidence hashes, child lifecycle and terminal status. Terra retains
  migration, broker, provenance, rollback, merge, deployment and acceptance
  authority.
- Local Qwen output must be persisted and content-hashed before audit. It may
  not alter authority, 2FA, acceptance criteria, production databases, broker
  state, ledger state, network configuration or release decisions.

## State machine

```text
PROPOSED → READY → LEASED → EXECUTING → AUDITING
                              ↑             ↓
                         RETRY_QUEUE ← NEEDS_REMEDIATION
                              ↓             ↓
                           PARKED       VERIFIED
                                             ↓
                                      RETURN_TO_PARENT
```

Terminal states are `VERIFIED`, `PARKED`, `BLOCKED`, `CANCELLED`, and
`EXPIRED`. A child cannot set the parent outcome to complete. Only
TERRA-DELIVERY receipts can satisfy release assertions.

## Required records

- `projects`: objective, owner, status, acceptance version;
- `outcomes`: desired result, dependencies, current next step;
- `tasks`: scope, capability, priority, state, attempt count;
- `task_leases`: owner, expiry, heartbeat, fencing generation;
- `attempts`: immutable command/prompt hashes, runner, start/end, result;
- `evidence`: artifact path, SHA-256, type, producer, parent reference;
- `findings`: severity, disposition, linked evidence, remediation task;
- `decisions`: question, options, operator response, expiry;
- `checkpoints`: state snapshot, rollback reference, resume token;
- `notifications`: channel, recipient, delivery status, idempotency key.

PostgreSQL is the durable source of truth. Redis, if used on comms-01, is
ephemeral transport/cache/lease acceleration only and is never authoritative.

## Safety invariants

1. One parent outcome ID maps to one TERRA delivery run ID.
2. Every child has a lease and fencing generation.
3. Retries are idempotent by task/attempt/action key.
4. Ambiguous side effects are quarantined, not repeated blindly.
5. Raw evidence is append-only and hash-linked; summaries never replace it.
6. The parent may retry queueable work but cannot weaken a hard gate.
7. Remote messages are untrusted intents until authenticated and authorized.
8. No message transport can place broker orders or mutate production directly.
9. A missing reviewer is incomplete; it is never silently substituted.
10. Completed child agents are closed and removed from the active registry.

## Queueable versus parent-owned gates

Queueable: dependency installation, test repair, disposable VM provisioning,
fixture setup, report regeneration, scanner retries, browser retries, evidence
indexing, and transport preparation.

Parent-owned: wrong database or broker target, unknown broker side effects,
credential publication, failed backup/restore, failed rollback, untrusted
provenance, dirty deployment checkout, exact-SHA mismatch, and unauthorized
scope expansion. Children may repair evidence for these gates but cannot pass
them.

## Comms-01 control-plane design

- dedicated VM on home05 with resource limits and separate service account;
- PostgreSQL database/schema separate from production, or a dedicated control
  database on the existing PostgreSQL host;
- Redis namespace separate from all trading coordination;
- no broker credentials and no production `DATABASE_URL`;
- outbound access limited to approved model APIs and Telegram/Signal endpoints;
- inbound access through a private authenticated channel only;
- systemd services: `top-delivery-controller`, `top-delivery-worker`, and
  `top-delivery-notifier`;
- encrypted backups to Synology with restore rehearsal;
- health, readiness, queue-depth, lease and notification metrics.

Telegram/Signal commands should be limited to `status`, `next`, `question`,
`pause`, `resume`, and `show evidence`. High-impact actions create a decision
record and are forwarded to the existing delivery authority; they never become
chat-level overrides.

## Rollout sequence

1. Build the controller in an isolated worktree.
2. Create a disposable PostgreSQL/Redis target and run migrations/upgrades/
   downgrades and lease-failure tests.
3. Provision comms-01 with no production credentials.
4. Run read-only import of historical run manifests from `/root/.codex/sol-runs`.
5. Verify evidence hashes and status reconciliation.
6. Run Telegram/Signal in receive-disabled test mode.
7. Enable authenticated read-only status queries.
8. Enable task-intent submission with audit logging.
9. Run failure-injection, restart, duplicate-message and restore drills.
10. Only then connect it to new TERRA delivery runs.

No production deployment or broker-facing action is part of this design phase.
