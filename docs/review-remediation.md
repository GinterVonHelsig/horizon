# Independent review remediation (September 20)

Starting point: `6b14f0fb9c3abdc8e2dccedad60e188660078f3c` in
GinterVonHelsig/horizon, PR #1. The independent Cursor/Grok 4.6 High review
requested changes. This document records the dispositions, not another approval.

## Confirmed findings

**HR-INTENT-RETRY.** `_handle_failure` previously queued transport/process failures
after `_run_claimed_task` had fsynced a per-logical-task execution intent. The next
attempt then blocked on that intent. Both executor and auditor fault-injection
regressions reproduced `retry_queued` instead of a truthful blocked result.
Queueable failures now consult that durable intent and return
`blocked:execution_outcome_requires_review` immediately. Existing queued attempts
still cannot replay an intent. Pre-intent failures retain ordinary bounded retry;
authentication failures retain their parked disposition. No intent is deleted or
re-keyed by attempt. A failure after executor success never replays its effects.
Recovery of an uncertain effect requires explicit reconciliation, not restart.

**HR-UNIT-GENERATOR.** `build_worker_unit` omitted three worker-health directives
and `RestartPreventExitStatus=78` although the tracked unit contained them. The
generator now includes the same private StateDirectory, mode 0700, health path and
terminal exit handling. A regression checks both representations. No generated
unit has been installed and no systemd command changing state is part of tests.

**HR-VERDICT-UNENFORCED.** Phase 1.6 previously required only a phase 1.5 identity;
its selection path never called the existing verdict gate. Routing records now
carry an optional completed verdict; newly selected/planned records have none.
The next required seat requires exactly one prior record with an allowed passing
verdict. Missing, duplicate, rejected, transport-failed, timed-out and malformed
records stop. Batch planning never invents completed reviews. The old test wrapper
no longer silently inserts history; positive tests explicitly label simulated
passing completion. Callers must supply trusted completed evidence: a record is
not a cryptographic attestation, and this library does not invent one.

**HR-SELECTOR-NO-CALLSITES.** The production `worker_cli` now loads the bundled
September v3 policy and passes registry configuration for preflight. TaskWorker
gates its explicitly selected pair as the phase-4 task review before effects and
again before review, using the executor adapter's identity rather than claimed
workstream author metadata. It uses only the selected registered reviewer as its
candidate inventory, validates that selected pair's availability, and checks the
returned execution identities against the authorized adapters. No replacement
adapter, transport or model is silently selected. Tests cover the real worker
path, CLI wiring, unavailable/conflicting reviewers and result-identity mismatch.

This is the single-task executor/auditor path, not the missing Gateway workflow.
Dependency-injected library workers may omit phase policy for legacy/test use;
the production CLI always supplies it. The external installed
`host_openrouter_review.py` still reads phase entries directly; it is not owned
by this checkout, has not been edited, and must not be considered integrated.
Cross-phase author/reviewer history and verdict evidence must be wired into that
external consumer in a separately reviewable source change before activation.
Thus HR-SELECTOR-NO-CALLSITES is repaired for Horizon's worker entry point but
remains an external integration blocker, not a claimed full Gateway repair.

## Adjacent evidence and compatibility

The two baseline adapter failures were incomplete stream fixtures: Codex lacked
`turn.completed`; Claude lacked a successful terminal `result`. Fixtures now
provide actual terminal events; stream-completeness enforcement is unchanged.
These are simulated CLI adapters, not live subscription or Gateway validation.
The required sequence API now intentionally rejects identity-only history.
Configured reviewer pairs outside September phase-4 routes now stop in the
production worker rather than proceeding under identity-only checks.

No PostgreSQL schema change or live migration is introduced. Execution intents,
worker-health SQLite state, controller ownership, epoch fencing and parked states
remain intact. The activation/rollback procedure is `recovery-activation.md`;
both generated and static units must preserve exit 78 and the private health path.

## Remaining gates

The fresh independent Cursor/Grok review of
`3645f4f663b65bf85d17c335fbd4fb99b653397e` approved the four original fixes for the
claimed Horizon scope, but identified **HR-PREFLIGHT-UNCAUGHT**. A separate local
diagnostic independently reproduced that exception escaping the CLI. This pass
also fixes it: a rejected selected-route preflight finishes any claimed task as
blocked; WorkerLoop persists a permanent `adapter_preflight` health block; CLI
returns 78. Regression tests inject rejection before claim, after claim and
before auditor, then restart against the same health store. No retry, second
effect, private remote response in persisted state, or leaked active lease is
accepted. Clearing the health block remains an explicit recovery acknowledgment.

Other review observations remain distinguished from these confirmed repairs:
batch routing is a planning API, not an adversarial execution chain, and must
not fabricate completed history. Generic caller-supplied routing records remain
a provenance obligation for the missing external consumer. The reported VM9201
provenance asymmetry is real (no explicit full request-digest echo), but is not
absence of request binding: `build_handoff_request` derives its handoff ID from
the immutable request digest and `validate_product` requires that exact ID.
Full digest/scope echo parity is defense-in-depth, not permission to invent VM
evidence for Horizon. The generic `permission_or_ownership` reason covers lease
and queue authorization failures without claiming every case is a filesystem
denial; more granular classification remains diagnostic debt. No spending cap
is inferred from estimated token costs, and expired handoffs never become success.

The PostgreSQL17 two-cluster spoofed-port/search-path test subsequently passed
on the exact 3645f4f source with `P43_DISPOSABLE_PG=1` inside the disposable
namespace. It was supplementary to that review's intake, not reviewer-run proof.

- Missing `gateway-delivery` and `openrouter-independent-review` executable
  bindings; installed skill identity alone is not an executable implementation.
- External launcher's selector/history integration, including passing prior
  verdicts and qualified author-aware availability, remains unvalidated.
- No tiny live file-creation/independent-review integration has been demonstrated.
  Cursor/Grok subscription code review is independent review, not Gateway
  validation. No OpenRouter calls or metered overages are authorized in this pass.
- Hosted privilege-dependent checks still skip where prerequisites are absent;
  local root-owned-source tests and the explicit two-cluster rehearsal cover
  those checks. Test evidence must name skips; simulated success is not live proof.

Production activation remains prohibited. Comms-01's
`top-delivery-controller.service` stays inactive; `top-delivery-worker.service`
stays stopped/failed; the f10c88295daec8bc45f636c4fbac41ad67209475-goal-runner
release and `/opt/top-delivery-auth` remain unchanged. No parked goal was resumed.
