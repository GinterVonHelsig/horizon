# Parent continuation and whole-goal completion — source repair

Baseline: GinterVonHelsig/horizon 4a5312d458a90912169e6e012d29a0933c9bce78.
Direct Codex on Comms-01. No installed release, service, parked goal or Quant change.

## Interfaces and outcomes

GoalSubmitter accepts a prerequisite specification map keyed by workstream number;
goal_cli submit exposes --prerequisites-json. Specifications are copied into the
immutable goal graph and validated against explicit provider configuration before
scheduling. The graph is pinned in PostgreSQL; conflicting replay fails. Existing
untracked runs are not silently adopted or resumed. Existing-parent bundles are
separate graphs and cannot by themselves complete an unrelated parent.

TaskWorker gates known prerequisites before the parent's execution intent. The
existing fenced handoff transaction parks the parent and schedules the provider.
On completion the parent is requeued; its next attempt verifies product/request/
artifact digests and retained execution/review evidence, then adopts the exact
product once in PostgreSQL. Adopted product paths and digests enter the parent's
execution context. No intent is removed/rekeyed; post-effect ambiguity remains
blocked. This supports declared pre-execution prerequisites, not arbitrary
automatic replay of adapters that discover missing capability after effects.

Graph reconciliation runs before/after worker execution, including multi-run
polling. It reconstructs missing eligible successors from the immutable graph,
not queue contents. Completion requires every expected node verified, no running
attempt, passing intact executor/auditor evidence, completed handoffs and declared
prerequisite adoption. PostgreSQL stores one immutable outcome per graph under
controller epoch/lease fencing. Historical active_attempt_id pointers do not
mean an attempt is running; its durable status is checked separately.

`goal_cli.py status --run-id ... --artifact-root ...` reports whole-goal status:
0 complete; 2 incomplete/untracked; 78 blocked/paused/stopped. Database failure
is a CLI failure, not success. Worker --once remains task-level, not goal-level.
Status revalidates retained evidence rather than treating an old receipt as proof
that subsequently corrupted artifacts remain valid. COMPLETE_WITH_RESIDUALS is
not manufactured: required failures remain blockers. Pause writes are fsynced and
serialized with reconciliation via the same run-directory lock. SQL separately
checks durable scheduling/run state, lease and epoch.
New graph binding also takes the pause lock and refuses a filesystem-paused run.
SQL independently requires both verified executor and auditor evidence index rows;
the Python boundary additionally checks the retained file bytes.

## External review source ownership

tools/host_review/host_review.py is a provenance-recorded copy of the installed
launcher, not a modification to its installed counterpart. Its executable path
requires a source/run-bound context and digest-verified actual author/result
history, calls the shared model selector, and allows one explicit Cursor review
without retry/fallback. It persists a no-replay intent and normalized review
result/history; a rejected verdict cannot authorize the next required seat.
Read-only Cursor execution uses Ask mode and sandboxing, no force flag; actual
stream-init model identity must match. No smoke bypass is allowed.

The September phase policy is unchanged. If its configured phase has no eligible
Cursor route, this entry point stops rather than translating OpenRouter/OpenAI
names. Additional explicitly approved route configurations are a dependency for
any such phase. No source test or independent code review invokes this installed
launcher, and no OpenRouter call is made by this repair.
After independent review, the source-owned launcher removes inherited non-Cursor
transports/credential loading entirely, retains the actual stream-init model in
history, and binds the transmitted review packet to the subject digest. The
installed original and Git history retain provenance; this is not a deployed
command rename or a claim that all September seats have eligible Cursor routes.

## Bounded source-and-test provider: exact supported subset

New explicit ID gateway-delivery-source-test and profile
gateway-delivery-source-test.v1. The initial recipe is
python-integer-function.v1: one solution.py, one named one-argument integer
function with a single return expression using bounded constants, its argument,
addition/subtraction/multiplication and unary minus. Up to 32 operator-supplied
input/expected cases are actually evaluated by a restricted AST interpreter.
Imports, calls, loops, attributes, defaults, decorators, arbitrary shell and
unrestricted Python execution are rejected. Source size/depth/integer bounds
apply. Neither model-reported PASS nor exact-source-string comparison stands in
for these tests. Independent review binds to actual source bytes; finalization
reruns the recipe and checks artifact integrity.

This is deliberately a restricted source/test profile, NOT arbitrary repository
patching, a general Python test suite or the full Gateway engine. Product
gateway-delivery-source-test-product.v1 uses PASS_BOUNDED_SOURCE_TEST_VERIFIED,
recipe_tests_passed:true, general_test_suite_run:false. The original one-file
contract remains distinct. Generic gateway-delivery/general Horizon prerequisite
binding remains unavailable rather than silently routed to either narrow profile.
General source-and-test work beyond this safe recipe still requires a confined
validation runner and supported immutable repository/base/test-recipe interface;
it is not claimed complete here. Unified Comms Relay remains separate.

## Schema/deployment and rollback — not installed

Historical-source lineage is now recovered and packaged test-only; see
historical-upgrade-tests.md for exact hashes, archived provenance and reproduction.
Both standalone017 and full016→021 upgrades are exercised with populated synthetic
state. The maintained014 placeholder still refuses fresh replay, proved by an
explicit negative test. Reconstructed-source evidence is not qualification of the
production data or an actual production migration. A later read-only catalog
assessment found installed020 definitions matching reconstructed020 except the
source-supported optional topdelivery sequence grant; see recovery-activation.md.
Do not stamp past the guard, replace installed
historical pins or deploy the test-only runner. Production compatibility remains
an activation blocker; no additional baseline information is requested.

New 021_goal_completion follows the live 020 stack. A disposable-only
017_goal_completion_disposable projects the identical pinned schema above the
legacy 016 test stack. Upgrade targets are explicit and both new sources are
independently hash-pinned in migration admission/test trust fixtures. No historical
migration was edited. New tables store immutable graph specs/outcomes and unique
prerequisite adoptions; workflow gets read access and fenced function execution,
not direct table writes. No migration has run against a live database.

Before a separately authorized activation: review the exact code/schema/config
manifest, stage an immutable release, provision its reviewed source-anchor entries,
rehearse the exact live-stack migration on a source-reconstructed disposable
database (not a production-data clone), configure explicit supported routes and
keep controller services inactive until acceptance. Installed submission-path and
review-launcher deployment corrections remain deferred. The reviewer package now
exists with relocated simulated CLI/consumer tests; the submission transport
package is a separate remaining preparation item. Do not
retarget current as part of this source repair.

Rollback code/config/launcher packaging as a unit to the captured previous pin;
retain execution intents, worker health, review histories, graph outcomes and
adoptions. New migrations deliberately refuse automatic destructive downgrade.
Use an independently reviewed preservation procedure if SQL removal is ever
needed. Old code must not operate new graph-enabled runs without a compatibility
assessment; parked goals remain parked. No rollback implies controller activation.

## Updated original acceptance checklist

1 Normal durable task + independent review: simulated; earlier 4a5312d one-file
  live proof remains baseline-only, not qualification of new code.
2 Duplicate/concurrent submission: simulated actual persistence.
3 Artifact-before-registration recovery: simulated fault injection.
4 Registration-before-scheduling recovery/dry-run promotion: simulated.
5 Worker death/fencing/no replay: existing SIGKILL tests plus graph transition
  exception/lost-response tests; no new live faults.
6 Persistent permission block: simulated, retained.
7 Restart preserves failure budget: simulated, retained.
8 Missing routes/spec/capability rejected: simulated, including prerequisite
  admission. Generic route rejection is not successful general integration.
9 Provider-specific valid/forged products: simulated for legacy, one-file and
  source/test contracts. Products are not interchangeable.
10 Auditor rejection and bounded terminal behavior: simulated, no repair chain.
11 Pause/stop preservation: simulated; production parked goals untouched.
12 Task/provider versus whole-goal status: new full-chain and CLI simulated tests,
  actual PostgreSQL graph outcomes, concurrent finalizers and lost responses.

Additional upgrade/isolation acceptance: reconstructed historical source with
paused/failed/active run rows, a queued task and controller owner/epoch/fence is
preserved across both upgrade paths. Failed is NOT stopped. These cases and the
original host-store-escape regression are now maintained CI tests; privileged
fixtures fail closed without verified private storage and PostgreSQL. Production
data-dependent migration compatibility and new-tip live integration are still
unverified; the read-only020 catalog comparison is narrower evidence.

Release-packaging acceptance: explicit cursor-independent-review entry point and
legacy argv shim run after relocation, without checkout/PYTHONPATH imports, with
pinned consumer config and simulated Cursor processes. Rejected reviews exit
nonzero; no replay across either command. These are required CI tests, not fresh
independent review or live qualification. Python/PyYAML runtime provisioning and
installed consumer cutover remain operator deployment work.

Required/expanded suite counts and exact reviewed/tested SHA belong in the PR
evidence for the final candidate, not a self-referential source commit. All model
execution in these new suites is simulated. Fresh independent Cursor/Grok source
review is required; prior exact-SHA approval does not cover this patch.

## Independent-review follow-up

The first exact-candidate Grok source review approved 5433fe7 with eight residual
observations. This follow-up adds actual child-only submission/completion coverage,
raw Cursor identity retention and explicit rejected-prior-verdict cases; SQL now
requires executor evidence too, with a direct-function rejection test. Pause blocks
new graph binding, and default disposable tests check forbidden table writes.
The acceptance helper parameter now says profile; unused non-Cursor transports
and the unbound smoke implementation were removed. Concurrent finalizers race on
the first outcome insert, not merely an already-completed receipt.

The child-bundle test also exposed a missing mount in the test wrapper. Its two
synthetic host-store bundles were moved to the local repair evidence directory;
existing bundles were untouched. The wrapper now mounts a private tmpfs on the
submission-bundle store, and CI provisions that mount point on its disposable VM.
No installed source/service/release pointer or parked goal was changed. Final
test counts and fresh follow-up source verdict must identify the new exact SHA.
