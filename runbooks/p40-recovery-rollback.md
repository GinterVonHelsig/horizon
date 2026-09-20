# P40 parent-bound recovery rollback boundary

Host: Comms-01. Repository: GinterVonHelsig/TOP-DELIVERY.
Parent: goal-3eb7b972ec15809e. Source predecessor:
1027a8e24d5f2af6a32ba1fb4342ff53bb4a2d15-goal-runner.

P44 supersedes the earlier two-unit lifecycle: use the reviewed
`recovery_lifecycle.stop_declared()` helper to check reverse
propagation and stop top-delivery-worker.service, top-delivery-signal-adapter.service,
top-delivery-hermes.service, then top-delivery-controller.service. Prove there are no active child attempts
before source/config switching. Preserve the exact old worker/controller drop-ins,
dual-exec launcher, current symlink target, source hashes, and scoped database
task/attempt snapshot. Do not alter pin/skip/auth/readiness policy or database rows.

## Root-held submission authority

Before a recovered task runs, both `top-delivery-worker.service` and
`top-delivery-controller.service` must have the root-installed environment setting
`TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS=1`. It selects the trusted store even if
an executor changes an artifact ancestor into a symlink and a caller resolves that
path outside `/var/lib/top-delivery/runs`. Canonical runtime paths also select the
trusted store without the flag. Missing or unreadable trusted data fails closed;
there is no runtime fallback to a writable artifact copy.

The root Comms Relay host submission/recovery coordinator (legacy host gateway) publishes original reviewed bytes to
`/var/lib/top-delivery-submission-bundles/runs/<parent>/submissions/<submission>/`.
This is deliberately a sibling of `/var/lib/top-delivery`: that existing directory
is service-owned, so putting trusted data beneath it would allow ancestor
replacement. Do not change the existing directory's owner or contents. The new
store and all created subdirectories are root-owned mode 0555; binding, prompt,
and spec files are root-owned mode 0444. Every directory through `/var/lib` and
`/` is checked for root ownership and absence of group/world write permissions.
Do not grant the worker a `ReadWritePaths` exception for the trusted store.

Use `recover_parent_bound_submission_bundle()` with the independently reviewed
original spec and prompt SHA-256 values. Its root-held `binding.json` retains the
exact spec digest, including adapter routes and working-directory fields, for
every runtime read. Executor-controlled replicas or recomputed replica hashes
cannot replace this authority. Root is the trusted administrator/publisher; this
boundary does not claim to protect against an administrator replacing reviewed
files and their pins.

Ordinary `GoalSubmitter` submissions capture the complete spec digest from the
coordinator-generated prompt and routing before making source files service-owned.
Publication and replay must match that captured digest. A modified existing spec
requires explicitly pinned recovery; it cannot acquire root-held authority merely
because its original prompt digest still matches.

Durable existing-parent submission explicitly requires protected publication,
regardless of a custom runtime artifact root or an unset service environment.
Recovery always requires protected publication too, including when passed the
protected store root itself. Only the generic publisher's disposable/dry-run
mode may use local bundles. A privileged submitter also requires a root-controlled
invocation ancestor chain before creating new source snapshots; root-owned sticky
temporary ancestors are allowed only with every subsequent ancestor root-owned.
Service-owned or replaceable ancestors and symlinks are rejected before writes.
Do not change ownership of existing service runtime trees to satisfy this rule;
use an appropriate coordinator-controlled invocation root instead. New source
files use exclusive no-follow descriptors, and ownership is assigned only to
those newly created descriptors, never a recursively discovered tree. An empty
precreated/incomplete submission directory now stops for explicit recovery rather
than silently adopting it. Newly created protected directories are fchmod'd0555
through verified descriptors so restrictive publisher umasks do not hide bundles
from the service user.

Readers open each directory and file with `O_NOFOLLOW`, verify root ownership and
modes on the open descriptors, and read each artifact once. Hashes, JSON parsing,
and prompt graph validation use those same captured bytes. Worker and scheduler
consume the returned validated object; they never reopen a checked path. Local
non-runtime stores remain available for disposable/dry-run work and have no
privileged authority guarantee. Tests inject roots only inside exclusive,
root-owned temporary directories and never publish to the live trusted store.

## Before the first recovered task transition

Restoring the saved source paths/drop-ins and controller launcher is reversible.
Keep top-delivery-worker.service stopped: the predecessor cannot discover P35/P40
submission bundles. A source rollback does NOT authorize restarting an incompatible
worker. The bounded rollback now leaves BOTH controller and worker stopped even
before a transition. Availability restoration requires a separately verified
compatible roll-forward; no unconditional predecessor restart. Preserve bundles/evidence.

## After any recovered task transition

If an attempt was created, a task state/attempt changed, or a successor was queued,
both predecessor worker AND controller must remain stopped. Do not reset tasks, delete successors, erase
attempts, or restore the control database to manufacture a preclaim state.
Preserve both before/after snapshots and every submission bundle. Resume only a
reviewed source revision supporting the SAME bundle schema, task namespaces,
executor sidecar location, and dependency graph. A compatible roll-forward is the
normal recovery; a deliberate paused worker is the safe fallback if validation
fails. Systemd active status alone is never rollback acceptance.

## Mechanical acceptance

P45 uses controller/recovery_lifecycle.py to verify the actual LOADED reverse
stop/reactivation graph BEFORE the first stop and before each subsequent stop. Unknown
RequiredBy/BoundBy/ConsistsOf/RequisiteOf/PropagatesStopTo edges, unexpected handlers,
or UpheldBy/TriggeredBy reactivation fail closed. Loaded ExecStop/ExecStopPost arrays
must be proven empty through typed read-only D-Bus properties, and kill/timeout/
power-action settings must match the reviewed safe values. The reverse closure is
rechecked after those settings. This stop gate does NOT read restorable unit/source/
env files or require forward START readiness: their failure must not prevent a safe
pause. Strict adapter/Signal/auth/config/source hashes and forward dependency checks
remain activation gates. A corrupt review anchor still fails source integrity.
The declared four
services must reach inactive/PID0 before any saved configuration is restored.
The coordinator then
restores the saved source/config paths while they are stopped, then daemon-reloads.
It issues NO start or restart after restoring predecessor source. A failed restore
or comparison leaves all four services stopped; preserve history for compatible roll-forward.
Never start an adapter after paused rollback: its Requires could restart the
incompatible old controller. Pending approved source-file edits are not loaded
by stop_declared; it checks the currently loaded stop graph, restores while paused,
and only reloads after saved-file comparison succeeds.

P45's final cycle uses Manager.ListUnits and typed Unit/Service object properties
for EVERY stop-path observation, including final inactive/PID/job verification.
Use invocation-ID object paths from protected /run/systemd/units runtime links,
NEVER name-encoded object paths: systemd257 can load the latter after GC. Its
invocation-ID lookup is in-memory-only and cannot recreate a vanished unit.
ListUnits-confirmed inactive/dead/no-job units, like absent units, are already
quiescent and are not queried/stopped or loaded from changed files. Their
redundant stop branches are pruned; external edges from actionable units remain
hard stops. No service reference-holder process or new dependency is installed.
It never calls systemctl show-by-name, LoadUnit, ListUnitsByNames or the loading
Manager.StopUnit API on that path. An absent in-memory unit is already quiescent:
only that unit and its removed anchor references are pruned, never external edges.
SendSIGHUP must be explicitly false alongside the SIGTERM/SIGKILL settings.

The production call is stop_declared() with no injected test runner. It invokes
Stop on the existing Unit object, then polls the non-loading state for up to
120 seconds (each D-Bus call independently bounded). This exceeds the pinned
90-second systemd stop timeout. A unit disappearing between object lookup and
property/method access is accepted only if a fresh non-loading inventory proves
it quiescent; otherwise it fails closed without reloading or retargeting.
A stop deadline leaves the actual pending job/state intact, issues no later
stops or starts and does not report the four-unit boundary paused.

P46 first creates a fixed, root-controlled accepted-source.json OUTSIDE Git under
/opt/operator-harness/artifacts/20260913T-p46-horizon-runtime-minor-closure-and-existing-task-activation-NOT_AUTHORIZED/.
It binds the frozen candidate/tree, packet, two passing review hashes, exact-head
passing GitHub CI metadata and job log hashes, host,
parent and P46 prompt. Root publishes it only after both independent seats and
the P46 risk-based findings disposition accept. Both remaining runtime findings
must be fixed; a minor severity label does not waive correctness.
The candidate's tree is never compiled into itself. An alternate consistent Git
commit/main ref cannot substitute for this independent acceptance record.

P46 removes stop_declared's runner argument; tests mock stop_loaded_unit instead.
Its final stage observation uses ListUnits, active invocation-ID property reads
and Manager.GetUnitFileState, never show-by-name. A target disappearing before
start is denied. The disabled standalone may be GC-unloaded with no process/job;
do not reload it just for status. The last supervisor-identity reads are also
non-loading. Earlier full PID checks plus unchanged inactive/dead/no-job state
prove paused targets; final receipts distinguish that proof from direct PID reads.
Record the first real Unit.Stop job and polling result during the authorized
four-service pause before source/config/current switching. Failure preserves the
actual state and prevents source switching; no extra service is created for a test.

Use the frozen reviewed coordinator helper (verified clean candidate checkout),
not an unverified installed script, to bootstrap validation of the installed archive.
The root interpreter must use -B so imports cannot introduce untracked bytecode.
After normal exact-head merge, require the merged main tree to equal the accepted
candidate tree; install a clean archive with root:root ownership, directories0755,
regular files0644 or0755 exactly as Git specifies, no extra entries or special nodes.
Do not remove mismatches to manufacture a passing inventory; preserve and rebuild
a fresh versioned archive if installation fails.

While ALL FOUR declared services remain stopped, the pre-controller command is:

    /usr/bin/python3 -B <frozen-reviewed-checkout>/controller/recovery_start.py --repo <isolated-repo> --release /opt/top-delivery-p1/<merged-sha>-goal-runner --accepted-sha <merged-sha> --accepted-tree <reviewed-tree> --expected-task goal-3fa391ad04eedbc8-ws-01 --controller-stage --start

This verifies independent acceptance, every installed file/directory/link, real
service readability and installed unit/config bytes BEFORE daemon-reload. It then
checks effective units while both remain stopped, and the exact database identity
and queue, before starting ONLY top-delivery-controller.service. A controller-start
receipt is not runtime acceptance. Allow its normal child processes and lease to
appear; verify their actual environments before starting a worker. BOTH start
stages require top-delivery-supervisor.service disabled/inactive/dead/PID0, with
no control PID or pending job. A worker additionally requires a recent completed
tick event whose parent, owner and epoch match the current database lease and
whose boot ID, PID/start ticks and systemd invocation match the running supervisor.
The event is emitted after the normal tick; no manual lease edits or requirement
to extend the normal fixed expiry on every tick. Process identity is rechecked
after the database and dependency probes immediately before start.
After the controller and bundles pass, --adapters-stage --start uses the same
runtime/source/lease gate to restore ONLY the two declared unchanged adapters.
It cannot incidentally start an inactive controller, auth service or Signal daemon.
The stage guard runs before daemon-reload and again before start: all four paused
for controller activation, controller active with both adapters and worker paused
for adapter activation, then controller and both adapters active/stable with worker
paused for worker activation. State/PID/invocation snapshots must not change across
the DB probes. After the final complete lifecycle/job guard, fast standalone,
four-unit stage and exact controller/child identity checks run directly before
start, followed only by pure captured-event freshness validation. No further DB,
graph or source inventory call follows those last process checks. These reads and
systemctl are not atomic; the actual worker transaction still enforces its fence.
It scans every forward dependency, including behind active units, for pending
jobs; a conservative systemd257 redundant-job/orphan projection must retain only
the selected stage's start jobs. Any retained external job or uncertain cycle
fails closed. It does not start unrelated boot services to make this check pass.
The static and runtime gates additionally compare the protected pre-install
systemd activation graph. Requires/Wants/BindsTo/Upholds, failure/success handlers
and trigger edges are followed transitively; ordering and reverse trigger edges
are pinned for the controller and worker. A new .wants/.requires link or indirect
worker activation edge therefore fails after reload but BEFORE any service start.

The only worker activation command is the same reviewed root coordinator CLI:

    /usr/bin/python3 -B <frozen-reviewed-checkout>/controller/recovery_start.py --repo <isolated-repo> --release /opt/top-delivery-p1/<merged-sha>-goal-runner --accepted-sha <merged-sha> --accepted-tree <reviewed-tree> --expected-task <exact-task> --start

Only goal-3fa391ad04eedbc8-ws-01 and goal-ad220af074326a0e-ws-01 are accepted.
The gate verifies source and all ancestors, the pinned pre-install service/config
fingerprints, database/adapter/auth inputs, real running controller environments,
and BOTH preserved root tasks plus P35 successor as topdelivery. Its exact temporary
proof drop-in requires --once, explicit --run-id and --expected-task-id, Restart=no.
It reloads and checks effective systemd state and queue/lease before EACH start;
expected-task checking repeats inside the actual claim transaction.
Database probes use cleared PG environments, explicit endpoint/port/role/database,
schema-qualified tables and a protected PostgreSQL system-identifier anchor. A
read-only connection through the protected application target is cross-checked
against that same server's postmaster start time and database OID. Credentials
remain private process input, never command arguments or evidence output.
Capture the before/after task snapshot
and report transitions even if execution later fails. Tests must cover a P35
ws-01 completion scheduling only its original ws-02 and show that missing bundle
metadata cannot fall back to the parent graph. The operational receipt must record
worker-stopped on any incompatible rollback. No production or trading data is
involved in this recovery.
