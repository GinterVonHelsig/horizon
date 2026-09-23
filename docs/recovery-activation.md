# Combined repair: preparation, operator activation and rollback — Comms-01

The staged-only qualification interfaces and five-session isolated runner are
documented in [qualification-interfaces.md](qualification-interfaces.md). Keep
`qualification_profile` absent in production; no installation, schema change or
activation is implied by preparation of that separately authorized disposable run.

This procedure covers the **entire combined repair**, not only the last
admission-only patch. It is not deployment authority. Source preparation, passing
simulated tests and schema metadata inspection do not permit installation,
migration, service starts or live tasks. No parked goal may be used as a canary.
Preserve GinterVonHelsig/TOP-DELIVERY, parked trading/Quant infrastructure,
authentication services and the operator's background Cursor session.

## Captured baseline and evidence limits

At the 2026-09-20 read-only assessment:

- `/opt/top-delivery-p1/current` on Comms-01 points to
  `/opt/top-delivery-p1/f10c88295daec8bc45f636c4fbac41ad67209475-goal-runner`.
- top-delivery-controller.service and top-delivery-supervisor.service are inactive;
  top-delivery-worker.service is failed/stopped. Preserve that state throughout
  preparation. top-delivery-host-gateway.service and top-delivery-auth.service
  remain active. `/opt/top-delivery-auth` is not part of this rollout.
- Database management revision is **020_horizon_prereq_corr_live**. The inspected
  existing 375 columns, 172 constraints, 74 indexes, 34 triggers and 66 routines
  match the source-reconstructed 020 catalog at f25eb0f10c9f86b13c6015177be9caff1f78cb45.
  One extra sequence SELECT/USAGE grant to topdelivery is consistent with the
  conditional grant in migration 002; preserve it. No permission change is needed
  by this repair. Metadata capture did not read application rows or qualify a
  production migration, data invariants, locks or runtime behavior.

Before a separate activation, reverify these observations rather than treating
them as perpetual guarantees. The previous controller pin
TOP_DELIVERY_RUN_ID=goal-3eb7b972ec15809e and old artifact-root run
goal-874cc8a163f733a3 must not be inherited by a new canary. Do not resume P49 or
any previously stopped goal. Record an explicit new run ID and matching paths.

## Source preparation (no installed changes)

1. Review the exact candidate in GinterVonHelsig/horizon on
   codex/repair-horizon-recovery, PR 1, and merge to main only under separate merge
   authority after required checks and fresh independent review. Record full SHA,
   tree hash, package manifest hash, test commands and qualified scope. Prior
   exact-SHA review does not cover later packaging changes. No model calls are
   authorized by this procedure.
2. Reproduce required and disposable checks with scripts/test-recovery-isolated.sh.
   Privileged tests must verify private database and submission-store isolation;
   never bypass that with environment flags. Historical bootstrap sources are
   **test-only**, with original014 replay restriction preserved. Do not install
   the bootstrap, stamp migrations, replay historical production 014, weaken
   source guards or replace authoritative installed pins to make tests pass.
3. Stage the reviewer with tools/host_review/package.py from the exact committed
   inputs. Test both relocated commands and rendered consumer config with fake
   transports. Provision its explicit Python/PyYAML runtime separately; see
   reviewer-release-package.md. This step writes only new staging files, not
   /opt/operator-harness/bin/openrouter-review or its installed library.
4. Prepare one code/config/schema manifest: approved Horizon release; reviewer
   package/runtime; source-anchor entries for the exact migration; adapter registry
   and routing hashes; unit/drop-in definitions; runtime state/artifact ownership;
   both submission entry points; backup/restore and stop conditions. Capture old
   hashes without putting credentials, production data or sensitive evidence in Git.

## Required configuration and submission corrections

The two existing submission paths serve submission, **not delivery execution**:

| Path | Observed source selection | Required activation correction |
|---|---|---|
| top-delivery-host-gateway.service, `/usr/local/lib/top_delivery_host_gateway/server.py`, client `/opt/operator-harness/bin/top-delivery-host-gateway`, socket `/run/top-delivery-host-gateway/gateway.sock` | `/opt/top-delivery-p1/current/controller/goal_cli.py` | Bind/reverify against the approved release and consistent run/artifact configuration; test inspect/reject/submit argv in staging |
| `/usr/local/sbin/top-delivery-submit` importing `/usr/local/lib/top-delivery/comms01_submit_gateway.py` | old d7305d4f41ccb7ca451873a5ebe3ece89636fbc5 controller pin | Prepare a reviewed version-controlled wrapper/module correction pointing at the same approved release manifest; no old pin or arbitrary checkout fallback |

The source-owned transport package and fake systemd-run/goal_cli consumer tests
now exist; see submission-release-package.md. Both paths select one pinned release
and share a durable no-replay journal. Installation and real consumer cutover remain
deferred deployment. Simulated children do not certify the host systemd attestation
boundary or live execution. Preserve peer credentials, prompt allowlist,
digest/attestation gates, service/socket/API/readiness compatibility and ownership.
The readiness enabled flag alone is not execution readiness. Do not rename deployed
communications resources. Comms Relay naming migration is described separately in
comms-relay-migration.md; unified communications integration is out of scope.

Render explicit supported adapter IDs and allowed disposable roots. The bounded
providers are gateway-delivery-disposable-file and gateway-delivery-source-test
(restricted integer-function recipe), with cursor-independent-review. They do not
implement generic gateway-delivery, arbitrary repository repair or a universal
workflow engine. Missing routes fail before scheduling. Do not map an OpenRouter
route to Cursor or register the host submission service as an executor.

Preserve September routing v3 and author-aware selection, actual author/reviewer
identity history and passing prior verdict requirements. The reviewer package
contains unchanged policy, not blanket approval for every Cursor seat. Render
and approve the intended explicit consumer policy and harness hash; leave the
template disabled otherwise. Retarget callers only after their required context
forwarding is demonstrated. Preserve installed compatibility commands until all
consumers are accounted for; no implicit retries or fallbacks.

Provision worker state via reviewed units: StateDirectory=top-delivery/worker-health,
StateDirectoryMode=0700 and RestartPreventExitStatus=78. Keep artifact roots
writable under ProtectSystem=strict through exact writable-path declarations,
without broad permissions, ownership or lease-fencing exceptions. Preserve durable
health counters and intent/history paths across version changes. Reconcile queued
retries with existing intents; uncertain effects require review, never intent deletion.
Provision the submission-journal directory0700 using the staged service template
with approved paths and resolved UID/GID. Retain it during cutover and rollback.

## Separately authorized migration and activation sequence

This section is an operator checklist, **not a command to execute now**.

1. Capture exact release, unit/drop-in/configuration and launcher hashes; record
   schema revision and source-provenance anchors. Establish an operator-approved
   consistent backup/restore point for the database and matching durable artifact,
   intent, health and review history stores. Do not export that data into Git or
   disposable tests. A restoration procedure needs its own exact target/authority.
2. Confirm controller, supervisor and worker remain inactive. Quiesce all submission
   and execution consumers for the migration/cutover window under separate service
   authority; do not alter authentication. No background consumer may create an
   old-format run while code/config/schema cut over. Capture and preserve parked
   states and existing ownership/fencing; do not reactivate them.
3. Independently approve/install the exact guarded **021_goal_completion** source
   anchor and use the normal production migration runner as the authorized migration
   identity. Starting revision must be 020; if otherwise, stop for assessment.
   Verify target identity, backup, provenance and role checks first. 021 adds
   horizon_goal_graphs, horizon_prerequisite_adoptions and three fenced routines;
   workflow receives SELECT/EXECUTE, not direct writes. No automatic downgrade is
   provided. Never use 017_goal_completion_disposable on production.
4. Verify committed 021 revision, object definitions, owners/ACLs and retained
   existing grants (including topdelivery's sequence grant). Do not infer successful
   migration from a pointer switch or matching metadata alone. If execution failed
   or outcome is uncertain, inspect durable migration outcome under operator
   authority; do not blindly retry, stamp or start services.
5. Install/select the approved immutable Horizon and reviewer releases, matching
   runtime/config/units and separately reviewed submission corrections. Do not
   replace authentication or Comms Relay services as collateral changes. Recheck
   executable pins, imports, paths, filesystem restrictions, adapter capabilities
   and author-aware availability from the actual service identity. Keep the
   services inactive until the activation receipt explicitly authorizes them.
6. Only under a separate live-task/billing and service-start grant, use a **new**
   disposable canary ID, immutable prerequisites and matching artifact root.
   Verify parent → prerequisite → validated handoff → adopted product → parent
   continuation → durable whole-goal completion with independent review. Check
   hashes, no concurrent ownership, no duplicate effects and truthful status/exit.
   `worker --once`, idle, a provider PASS or a completed child alone is not goal
   completion. Inspect `goal_cli.py status` plus retained evidence/outcome.

The previous one-file live qualification at 4a5312d458a90912169e6e012d29a0933c9bce78
does not qualify this combined candidate. Simulated tests and reconstructed-source
upgrades are useful evidence but do not waive an explicitly required current-tip
live gate. General Gateway and unified Comms Relay remain outside bounded scope.

## Rollback: code and database are separate decisions

On an activation gate failure, first stop only the separately authorized
top-delivery-worker.service, top-delivery-controller.service and
top-delivery-supervisor.service on Comms-01, and quiesce the relevant submission
consumers. Verify no active execution remains before switching source/config.
Preserve intents, health state, review history, graph outcomes, adoptions and
all canary evidence. Do not reset an epoch, clear an intent or resume a goal.

| Database state at rollback | Safe immediate action | Permission to execute old code |
|---|---|---|
| Migration not attempted; still verified 020 | Restore captured Horizon/reviewer/runtime/consumer/unit configuration together; keep services inactive | Existing 020 compatibility is only the pre-activation baseline, not permission to resume parked goals |
| 021 committed, no new run/effects | Restore old code/config while retaining additive 021 objects and audit state; keep services inactive | Requires explicit compatibility assessment of the exact old executable and schema guards against 021 before **any** old runtime use |
| 021 committed and graph-enabled runs or external effects exist | Stop and retain database plus artifacts; prefer forward repair using the approved 021-capable release | Old code must not claim, schedule, retry or finalize new graph-enabled runs; it does not enforce these contracts |
| Failed/unknown migration outcome, drift, corruption, or old exact-schema guards reject 021 | Keep services inactive, resolve durable revision/schema outcome; use an independently reviewed preservation/restore procedure if needed | No automatic restart, downgrade, historical replay or presumed compatibility |

**Restoring `/opt/top-delivery-p1/current` does not reverse 021.** At source level
021 is additive and existing inspected 020 routines are unchanged, but no old
release execution against a populated 021 database is qualified by that fact.
The old f10c88295daec8bc45f636c4fbac41ad67209475 release may remain installed/inactive;
this repair makes **no claim that it can safely run database-connected workloads
against 021**. Old entry points' schema/capability guards and selection of queued
work must be assessed before allowing even legacy-run execution.
Read-only inspection of that installed release's controller/migration_target.py
confirms its canonical target list ends at020 and `upgrade head` resolves to020;
an explicit021 target is rejected. Do not use its migration tooling to manage021.
This source observation is not a demonstration that its workers refuse new work.

If return to strict 020 is necessary (for example an old release's exact schema
guard cannot admit 021), restoration requires the captured consistent pre-021
database and matching durable stores, maintenance authority and a reviewed data/
effect reconciliation plan. If any post-backup external effects occurred, restoring
older database/intent state can replay them: do not restore until reconciled, or
choose forward repair instead. Any proposed selective removal/preservation of 021
objects needs separate review; automatic downgrade deliberately raises an error.
Retain post-cutover audit evidence even when restoring a pre-cutover snapshot.
Never revoke the observed legacy sequence grant merely to match a fixture.

Restore reviewer package/runtime/config/shims as one unit. Retain no-replay markers
even if old code does not consume them; that is a reason to keep it inactive, not
delete the markers. Restore submission wrappers to captured old hashes only as
part of an explicitly inactive rollback. Code rollback authorizes no submissions.

After a repaired filesystem cause, the approved new worker's explicit
`--recover-block --recovery-reason filesystem_cause_repaired` transition may clear
only the health circuit breaker under separate operational authority. It does not
resolve unknown effects, change a lease/epoch or reactivate a parked run. If the
cause persists, the next poll blocks again; a restart does not reset the budget.
