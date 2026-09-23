# Bounded Gateway Delivery provider — implementation contract

Authorized 2026-09-20. This is direct Codex development on Comms-01, not a
submission to a delivery controller. Comms Relay communications integration is
separate. Installed files, services, parked goals and Quant are out of scope.

## Interface and acceptance recorded before implementation

The first supported profile is `gateway-delivery-disposable-file.v1`: deliver
one explicitly specified UTF-8 file inside a fresh disposable task workspace.
It is deliberately not a general release/deployment workflow. Unsupported
profiles fail; this does not claim full Gateway Delivery phases 0–7.5.
The operator-approved specification supplies filename and expected content;
its digest must appear in the immutable prerequisite handoff context alongside
the prerequisite node ID. No executable test commands or production targets
are accepted by this profile.

Sequence: validate request/spec/scope/routes -> durable execution intent ->
Cursor implementation -> deterministic exact-file acceptance -> independent
read-only Cursor review of bound evidence -> deterministic product/receipt ->
Horizon fenced handoff finalization. No self-authored PASS product substitutes
for independent review. No model fallback, automatic remediation or second
execution after an uncertain outcome. Horizon retains claim, lease, epoch,
intent and cleanup ownership; no nested parent submission is used.

Executable IDs after independent review: `gateway-delivery-disposable-file`
(bounded provider implementation, not the generic workflow slot or host submission
command) and `cursor-independent-review` (explicit Cursor
transport). Existing legacy OpenRouter-named requests remain legacy and are
not silently interpreted as Cursor. New profile selection is digest-bound.

Required tests: valid end-to-end task/product/finalization; absent route,
wrong profile/spec/digest, wrong-provider product, reviewer-author collision,
rejection/malformed result, artifact mutation, paused run, duplicate execution,
worker death/uncertain outcome and restart; truthful terminal state and bounded
timeouts. Model calls in deterministic tests must be labeled simulated.
Live proof requires separately recorded included-subscription calls, with
On-Demand disabled as confirmed by the operator; no OpenRouter calls.

Review history must derive from actual execution identity and persisted result
digests. An uncompleted or rejected review cannot authorize product publication.
The existing full workflow's prior-review gate remains intact; this profile
has one required code-review seat, not fabricated proposal review approvals.

The profile has its own product contract,
`gateway-delivery-disposable-file-product.v1`, and disposition
`PASS_DISPOSABLE_FILE_VERIFIED`. It states exact-file comparison succeeded and
`general_test_suite_run: false`; it cannot stand for a general prerequisite repair
or a passed software test suite. Legacy Horizon/VM contracts and `gateway-delivery`
remain distinct and can coexist in the same registry. Prototype profile receipts
from f57d2ca are not reinterpreted as this revised contract; they were never deployed.

Independent approval must cite the actual deliverable SHA-256 for every criterion.
The review receives observed and expected content; copied questions in an acceptance
report do not constitute proof. Finalization rechecks content and its hash after
review. Product, scope and request digests remain bound by the existing handoff
validator. The selected reviewer is catalog-checked before effects, including when
its route differs from the registry defaults.

Two claims permit a bounded pre-intent reclaim, not two implementation calls.
The 600-second deadline is measured from durable handoff creation, not worker
start; remaining time is passed to each call and checked again before review,
product publication and completion. An uncertain effect requires reconciliation.
The stored attempt counter is zero-based; the budget includes the initial claim.
A further reclaimed lease is blocked before any model execution. Permanent child
failure closes the handoff using the existing fenced `expired` transition, with
`provider_terminal_failure:<reason>` distinguishing revocation from elapsed-time
expiry. The parent remains parked. Reserved evidence filename `rollback.txt` is
rejected at admission, not after a model has already created it.

## Independent review and qualification record

Cursor/Grok's separate read-only review of f57d2ca requested changes: overbroad
product/disposition, occupied generic executor ID, question-based evidence binding,
stale discovery prose and billing-flag semantics. The code now implements distinct
contracts/IDs and direct source-hash binding; prose is dated explicitly. An author
diagnostic additionally reproduced acceptance after the durable deadline, repaired
with queue/execution/review boundary regressions. The review's contention that no
validation occurred is narrower than the evidence: exact-content comparison did
run. Nevertheless, it was not a general software test suite and must not carry that
broader success meaning; the contract correction is accepted, not disputed away.

The real f57d2ca exercise used Composer 2.5 and a separate Cursor/Grok 4.6 High
session and recorded handoff completion. That prototype's broader product was
subsequently rejected by code review. It is evidence of actual adapter/orchestration
execution, **not live qualification of the revised product/review contract**.
No second live task is automatically launched under the one-task/no-retry grant.
The revised contract has deterministic model-simulated integration coverage;
fresh exact-commit independent code review is a separate acceptance gate.

## Billing, activation and rollback

`subscription_only` and `on_demand_disabled` record operator attestation, not
programmatic billing enforcement. The receipt labels this explicitly. Actual
included-only enforcement is the Cursor account setting the operator confirmed;
the configuration boolean does not change it. Never infer a metered spending cap
from those flags, model availability or estimated token costs. No OpenRouter route
or fallback is part of this profile.

No activation is performed. Before a future operator-approved activation, stage
the reviewed exact source in a new immutable release directory, preserve current,
and render the example registry with an explicit disposable root and approved
specification. Retain worker-health state/exit78, task fencing, controller leases
and execution intents. Qualify the final contract before enabling any production
controller. Generic Gateway prerequisite/release execution remains unsupported by
this one-file profile; do not install it under the generic adapter ID.

Rollback code, registry and profile policy together to captured prior hashes; no
schema change is introduced. Preserve legacy route IDs, durable intents and parked
state. Do not clear an uncertain execution or resume a parked goal as rollback.
Installed submission correction and naming compatibility follow
[Comms Relay migration](comms-relay-migration.md), under separate activation authority.

## Naming inventory (before edits)

- Shared communications role: `Communications gateway + auth` in maintained
  program fixture; canonical new name **Comms Relay**, technical `comms-relay`.
- Submission transport: `top-delivery-host-gateway` command/service/socket and
  separate `top-delivery-submit` are compatibility interfaces, retained.
- `gateway-delivery`, `gateway-subworkflow-*`, provider keys and product schemas
  describe the delivery workflow, not communications; retained.
- `terra_gateway_mac` and `192.168.0.1` describe the network gateway; retained.
- Historical artifacts, source hashes, prior diagnosis and quoted architecture
  names remain evidence. Maintained documentation gets an explicit mapping,
  not a retrospective rewrite of those records.
- Local Delivery/local-delivery and Horizon are unchanged. No Comms-02 host
  mutation or unified Comms Relay implementation is authorized.

Deployment remains prohibited; compatibility/migration instructions will be
recorded separately. New source defaults are not installed configuration.
