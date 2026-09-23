# Consolidated bounded repair acceptance checklist

Exact tested/reviewed SHA, current CI and review findings belong in the final PR
receipt; this file does not confer approval on later commits. Production is not
activated. Task completion is not whole-goal completion.

## Source implementation

| Component | Implemented scope / source status |
|---|---|
| Provider contracts/routes | Provider-specific validation, unknown/missing routes rejected before scheduling; no silent substitutions |
| Submission recovery | Immutable submission identity, reconcile artifacts/registration/scheduling; preserve disabled runs/ownership/fencing |
| Worker recovery | Persistent permission circuit breaker, exit78/service health, leases and uncertain execution-intent protection |
| Parent and goal completion | Immutable prerequisites, validated one-time adoption, fenced durable graph/successor reconciliation and evidence-backed outcome |
| Bounded providers | One-file profile and restricted integer-function source/test recipe, independent review and bounded terminal behavior |
| External reviewer package | Relocatable canonical command/legacy argv shim, explicit Cursor transport, pinned configuration, actual identity/history, passing verdicts, no non-review-seat bypass |
| Submission transport package | Both direct/socket paths, one pinned release/config/journal, peer/prompt checks, bounded dispatch and truthful receipt/exit, safe partial-failure handling |
| Qualification interfaces | Immutable prerequisite forwarding; explicit Cursor-only parent-review CLI profile with author independence; September default unchanged |
| Qualification runner | Durable five-session broker, separate short private runtime socket with pre-ledger bind admission, confined subprocesses, timeout/orphan/uncertain-state handling; separate live opt-in not invoked by ordinary CI |

No known source work remains in these **bounded** implementations apart from any
findings recorded by the fresh exact-commit review. Unknown-effect reconciliation
intentionally stops for operator review; no automatic intent-clearing path is missing.
General gateway-delivery workflow engine/binding and unified Comms Relay integration
remain unfinished **outside this scope**, not silently satisfied by these packages.

## Original acceptance and evidence class

| Original check | Evidence / remaining validation |
|---|---|
| 1 Normal task with independent review | Actual orchestration/disposable persistence with simulated adapters; prior one-file live result at4a5312d only, not current-tip qualification |
| 2 Repeated/concurrent submission | Durable persistence regressions plus packaged cross-path/same-journal concurrency tests |
| 3 Artifact-before-registration failure | Actual disposable GoalSubmitter fault injection |
| 4 Registration-before-scheduling failure | Actual disposable recovery; dry-run promotion and immutable conflict cases |
| 5 Worker death after claim | Simulated execution with leases/fencing/intents; transport death also stops unknown effects without replay |
| 6 Permanent permission failure bounded | Persistent worker block and sanitized reason regressions |
| 7 Restart cannot reset budget | Durable worker health/circuit-breaker tests; transport retains intents across process death |
| 8 Missing adapter rejected | Configuration admission tests; generic rejection is not successful generic Gateway integration |
| 9 Valid versus forged/wrong-provider handoff | Provider-specific simulated contract and integration tests |
| 10 Auditor rejection not success/unlimited repair | Review/transport rejection, nonzero exit, bounded attempt/no-replay tests |
| 11 Paused/stopped preservation | Application recovery tests; historical schema tests cover paused/failed/active, with failed NOT equated to stopped |
| 12 Truthful durable completion and CLI exits | Complete simulated parent→prerequisite→handoff→continuation→whole-goal chain, missing successors/concurrent finalizers/outage/uncertain-effect tests |

Small transport-only tests use fake systemd-run/receipts. The additional packaged
qualification suite uses **actual goal/worker CLI subprocesses and private
PostgreSQL through021**, with simulated models and pytest-only systemd identity;
it does not prove production service attestation.
Packaged reviewer consumers use fake Cursor subprocesses. A separate genuine
Cursor/Grok **source review** is not a live delivery task or adapter integration
qualification. Record those distinct evidence classes in the final receipt.
The full simulated chain consumes four durable broker sessions; the standalone
packaged reviewer consumes the fifth as a separately labeled launcher boundary.
See qualification-interfaces.md for isolation, timeout evidence and live opt-in.

Reconstructed-source016/017→021 upgrade/recovery tests preserve synthetic state.
Read-only production metadata inspection observed020 with matching inspected
definitions and the source-supported legacy sequence grant. Neither that inspection
nor reconstruction is successful production migration or data-dependent compatibility.

## Intentionally deferred deployment and live validation

- Operator-approved immutable release/runtime selection, both submission wrapper/
  service corrections, reviewer installation and consumer cutover. Source packages
  and simulated consumer tests now exist; installed-file changes are deployment.
- Actual service-identity filesystem/attestation checks and approved rendered UID,
  GID, executable/adapter/routing/source-provenance pins. Templates remain disabled.
- Guarded migration021, consistent backup/restore plan and code/database-aware
  rollback. Old code must not process graph-enabled runs; pointer reversal cannot
  undo021. Preserve legacy sequence grant and all durable intents/audit state.
- Separately authorized current-tip live qualification if required for activation;
  no live delivery task was authorized by the packaging/review pass.

No parked goal is an activation probe. Keep controller/supervisor inactive and
worker unstarted; preserve installed services, authentication, release pointers,
Quant and background Cursor. See recovery-activation.md and both package runbooks.
