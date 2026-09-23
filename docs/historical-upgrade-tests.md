# Reconstructed historical upgrade — test-only package

Repository: GinterVonHelsig/horizon, codex/repair-horizon-recovery. Discovery base:
e8a4be767ad6b9c288a3ca69a0bda3579b62c786. Final tested/reviewed SHA and test counts
are attached to PR1; do not put a self-referential commit hash in this document.

## Provenance and scope

`controller/test_only/historical/manifest.json` records exact SHA-256, original
source location and repository path for every one of the 37 runner dependencies.
Identical maintained sources are referenced with exact hashes; divergent recovered
files are retained byte-for-byte under `source/`. They are NOT on the production
Alembic versions path. No old worktree, installed file, database dump or network
access is required to reproduce the package. Hash drift fails before copying.

`base-source-provenance.json` records all 001–013 Git blob identities matching
GinterVonHelsig/TOP-DELIVERY f2658c33c9f881be59f25608038f4f585641e0a5.
Its comparison_at_repair_sha names the discovery snapshot, not a claim about the
current tip. A regression computes the Git blob identities from current bytes and
compares all thirteen against that historical record, without needing network refs.
Original 014 was found in BOTH Comms-01 worktrees:

- /opt/operator-harness/worktrees/20260826T-local-delivery-integration/goal-runner/controller/migrations/versions/014_requeue_blocked_parent_task.py
- /opt/operator-harness/worktrees/20260827T-executor-contract-recovery/goal-runner/controller/migrations/versions/014_requeue_blocked_parent_task.py

Both hash to `be05d24299ae93dc3d0c5244d9a10266c2b098327a644adbf575dde954ee672c`.
The archived `/opt/operator-harness/artifacts/20260827T-child-openrouter-activation/migration-014-activation.json`
records this pin, canonical 013 before/014 after and successful upgrade; its
`phase_apply_014.py` names that source. The earlier
`20260827T-comms01-canonicalize-013-stage-014/migration-014-lineage.json` agrees.
These receipts are provenance evidence, not instructions to execute archived
scripts or independently verified signed attestations.

Canonical 013 SHA-256 is
`911d718a54a36148d1b4410fbce75e1107f569dde99dfcf7c9c1711e32fc4e7b`.
Original 014 requires cleanup function `(text,text,integer,integer)` containing
`current_epoch < p_controller_epoch` and
`attempt_row.controller_epoch = p_controller_epoch`. Its SQL rejects the old
hybrid `current_epoch IS DISTINCT FROM p_controller_epoch` body.

015/016 candidates were recovered from the second worktree above. Exact module
hashes are respectively
`c14a8f9b43c1410abc0d9e1ac3637f8e42377306a9beaa9c902a6bc79040f225` and
`83ea3e9d957df81cc961896973a7a1925bd7270c1af06dee8cb260b894730113`.
Their four SQL file hashes are in the manifest. Provenance receipts under
`/opt/operator-harness/artifacts/` are
`20260828T-executor-recovery-lineage-review/migration-lineage.json` and
`20260828T-cursor-contract-016-activation/{016-source-manifest.json,phase_apply_015_016.py,migration-015-activation.json,migration-016-activation.json}`.
Original candidate modules retain their disposable-name guard and transactional
revision compare-and-set. They run as postgres, matching the archived installer;
014 and guarded 017+ run as the migration role. Ownership is asserted, not assumed.

017 module SHA-256 is
`30ae5700613aabc5f4c40788e78ad5290cacba2335aca9a474d3b61f6394e103`;
SQL SHA-256 is
`083198476db4dc4504c811516061afefd20024655c0fcd7dae74e69822e4cb2e`.
Both match `20260906T-top-delivery-live-apply-017-park-bbd863-retries-20260906/overlay-registration.json`
and the adjacent `PASS_017_LIVE_BBD863_RETRIES_PARKED.json` receipt.

## Reproduce without touching host services

Requirements: a root-owned, non-group/world-writable checkout, Python test
dependencies from CI, PostgreSQL binaries, postgres OS user, iproute2 and permission
to create private mount/network/PID namespaces. The two mount points
`/etc/top-delivery` and `/var/lib/top-delivery-submission-bundles` must already exist
on Comms-01; CI creates them only on its disposable runner. Do not change installed
files to satisfy a failed preflight. From the checkout run:

```sh
rtk proxy bash scripts/test-recovery-isolated.sh -q -ra --tb=short \
  controller/test_historical_upgrade.py controller/test_fixture_isolation.py \
  tests/test_privileged_isolation.py tests/test_migration_target_paths.py
```

Every wrapper entry invokes kernel unshare; the setup body is passed on stdin to
the new process and has no public --inside entry point. Forged namespace environment
variables cannot skip unshare or authorize a host overmount. Tests use harmless
mount/unshare tripwires to prove refusal before setup. The wrapper additionally
compares outer/current namespace IDs before setup, then creates private
tmpfs mounts, private loopback PostgreSQL and generated test trust material. The
privileged session independently verifies mounts, namespace separation, loopback
transport, private PostgreSQL data directory and matching postmaster PID/network
namespace BEFORE lock creation, trust snapshots or role writes. No opt-out flag
exists. Direct pytest without this isolation fails; namespace verification is not
merely an environment variable authorizing a write. Tests recreate the original
exposed-store pattern with a nested bind mount of a disposable directory and prove
the actual child-submission test refuses setup without altering its sentinel.

The materializer checks isolation and every source hash before writing a private
runner beneath `/etc/top-delivery/historical-test-*` (hidden tmpfs, not installed
files). Original 014 executes using its historical Alembic environment/catalog/
source verifier. Private trust metadata selects its original pin and measured
historical hostname fingerprint, then is restored in finally. Both private files
are restored even if measuring that fingerprint fails, covered by injection.
Installed production pins remain unchanged. 015/016 execute their guarded original modules. Current
Alembic then upgrades directly 016→017→018→019→020→021, or separately 016→017 and
017→021. No guard disabling, source substitution into installed versions, manual
stamp over unapplied SQL, or production database copy is used.

Historical synthetic run states tested: **paused, failed, active**. A queued task,
controller owner, epoch and fence are created through historical SQL APIs. Complete
row snapshots must remain identical after upgrade. The historical register API
does not accept literal `stopped`; **failed is not a stopped-state test**. Existing
application pause/stop regressions remain separate evidence.

The same actual worker/persistence/handoff/finalization paths run with simulated
executor/auditor adapters. Coverage includes whole-goal completion, missing
successors, concurrent finalizers, stale epochs, lost responses, adoption exactly
once, uncertain execution intents, DB outage, tampered evidence, child-versus-parent
completion, pause refusal and SQL evidence/privilege checks. Test-generated state
and function-owner reports are retained in pytest's private temporary directory
for the process lifetime; JUnit can be written to an operator-selected artifact
path. No production runtime artifacts or credentials belong in Git.

## Admission repair and deliberate restrictions

Previously standalone 017 was admitted by name but lacked a source-path entry;
it raised KeyError before DDL. Intermediate live paths now derive from the existing
full chain, and the same map controls admission. Tests verify exact predecessor
coverage and exercise both upgrade paths. No admitted target gains unpinned SQL.

The maintained production 014 placeholder remains byte-identical and still refuses
fresh replay. Its SHA-256 is
`07b5a02e7ffb22e08b38947629396a96ab80235c9fd7bf0a7ce55c8955e6f73e`.
An explicit passing negative test proves that refusal; it replaces the obsolete
strict-xfail assertion that historical sources were unavailable. Positive full-chain
and denied-table-write assertions now run against the recovered lineage.

## Deployment / rollback / acceptance implications

This is reconstructed-source upgrade evidence, NOT production-schema compatibility,
production data-dependent rehearsal, installed packaging validation or live model
integration. No production DB was inspected. Operator activation still requires
an independently authorized compatibility check against the actual deployed
schema/provenance and explicit configuration of supported routes. Do not use this
test package to bootstrap or stamp a production database.

Deployable source change is migration target admission only; no schema body changed
in this pass. Keep the test package out of any live migration discovery path.
Before separate activation record code/config/source pins, verify starting revision
and canonical predecessor definitions, and retain the controller/supervisor stopped
until compatibility and existing acceptance gaps are resolved. Existing source-owned
021 remains a separate proposed schema addition, not a live migration performed here.

Rollback this pass's code/config to the captured prior release if necessary; do not
run a database downgrade for an admission-map change. If 021 is activated later,
preserve graph outcomes, adoptions, execution intents, review histories and worker
health; destructive schema rollback remains deliberately refused and needs a
separate reviewed preservation plan. No code rollback authorizes old workers to
consume new graph-enabled runs or resumes parked goals.

The original 12-check matrix in parent-completion-repair.md remains scoped to
simulated execution except the old one-file proof at 4a5312d. This pass adds
historical-source upgrade evidence and isolated-test safety; general Gateway,
installed external launcher, new-tip live qualification and production-schema
compatibility remain outstanding. Unified Comms Relay remains outside scope.
