# Conditional activation and rollback — Comms-01 only

This is a procedure for a separate operator decision, not activation authority.
Do not execute it while CI, review, routing policy, or live-adapter validation is
unresolved. Do not resume P49, goal-3eb7b972ec15809e, or any previously stopped goal.

## Preconditions and preparation

1. Review and merge the exact candidate from GinterVonHelsig/horizon
   codex/repair-horizon-recovery into main only after required checks and independent
   review pass. Record the approved full SHA and its tree hash. Preserve
   GinterVonHelsig/TOP-DELIVERY and all trading repositories and infrastructure.
2. Re-run the disposable test command in recovery-repair.md on that exact SHA.
   Establish an explicit budget and finish the tiny real-adapter smoke. The
   missing gateway-delivery/openrouter-independent-review registrations must be
   resolved with the actual supported implementation, or prerequisite delivery
   must remain explicitly unavailable. Do not alias these names to unrelated code.
3. On Comms-01 record `readlink -f /opt/top-delivery-p1/current`, hashes and copies
   of the two units and their drop-ins, the selected adapter configuration, and
   service state. The expected inactive baseline is
   /opt/top-delivery-p1/f10c88295daec8bc45f636c4fbac41ad67209475-goal-runner;
   top-delivery-controller.service inactive and top-delivery-worker.service failed.
   Controller pin is TOP_DELIVERY_RUN_ID=goal-3eb7b972ec15809e; it must not be reused
   for the activation canary. The configured artifact root names a different old
   run (goal-874cc8a163f733a3); do not carry that mismatch into new configuration.

## Separate authorized activation

Stage the approved Horizon SHA in a new immutable release directory. Validate
source provenance, executable pins, Python imports, registry routes, permissions,
and systemd filesystem restrictions against that directory before selecting it.
No PostgreSQL schema migration is needed for this patch. Never migrate or copy
production database contents as part of the disposable check.

Provision the worker's private state directory through the reviewed unit:
StateDirectory=top-delivery/worker-health, StateDirectoryMode=0700. Preserve
RestartPreventExitStatus=78. Keep the configured artifact root writable under
ProtectSystem=strict; do not broaden ownership, trusted paths, or write access.
Use a new, separately authorized disposable canary run and consistent artifact
root. Start only the exact units explicitly authorized for that canary. A
separately authorized production selection of /opt/top-delivery-p1/current and
service starts must identify the new SHA and pin; this document does not supply
that authorization.

Verify the canary's durable task state, executor and independent auditor evidence,
handoff result if applicable, worker exit status, and absence of competing active
attempts. `idle`, `awaiting_controller`, `preserved_disabled`, or a provider PASS
file alone is not completed-work evidence. Never use an old parked goal as the
activation probe.

## Rollback / stop procedure

On any failed activation gate, stop top-delivery-worker.service and
top-delivery-controller.service on Comms-01 and verify both are inactive before
restoring source/configuration. Preserve all task state, SQLite poll health,
execution-intent files, and canary evidence. Do not delete an intent to make the
old worker replay an operation with unknown effects.

Restore the recorded release selection, exact unit/drop-in files and adapter
configuration; reload systemd definitions while leaving both services inactive.
The prior release is f10c88295daec8bc45f636c4fbac41ad67209475-goal-runner unless the
pre-activation evidence proves a different baseline. No PostgreSQL downgrade or
live data restore is required. Keep the new SQLite files intact even though the
old code does not consume them. Code rollback does not authorize task resumption.

For a repaired permission/configuration cause, explicitly acknowledge a worker
block under the worker identity with the approved release's worker_cli.py:

```sh
rtk proxy python3 /APPROVED/RELEASE/controller/worker_cli.py \
  --run-id NEW_AUTHORIZED_RUN_ID \
  --health-dir /var/lib/top-delivery/worker-health \
  --recover-block --recovery-reason filesystem_cause_repaired
```

Replace placeholders from the separate activation receipt. This command clears
only the poll circuit breaker and records the reason; it does not execute tasks,
change a controller epoch, reactivate a run, or reconcile unknown external effects.
If the cause remains, the next poll blocks again. Restarting the service without
this transition cannot clear a persisted block.
