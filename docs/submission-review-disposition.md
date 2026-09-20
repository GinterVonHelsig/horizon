# Submission package review disposition

Independent Cursor Grok 4.6 High reviewed cad7ae0c41a216e7f18d801530ad050f32ba7b72
in session c29376d2-5368-47e9-86b4-fc5441b9e356. Verdict: CHANGES_REQUIRED.
The read-only source review did not independently execute tests or qualify a live
consumer. Its two findings were reproduced before remediation.

* P0, first submission: artifact_root was passed to GoalSubmitter without creating
  it. Both entry points now create and validate the bound private directory before
  recording dispatch intent. A denied mkdir leaves no execution intent and can be
  retried after repair. The simulated child now constructs the actual packaged
  GoalSubmitter. The service template includes the configured runs directory as a
  writable path; rendering and installing it remain operator deployment work.
* P1, orphaned fixed-name unit: a process-local lock could disappear before its
  unit finished. A durable global dispatch fence now retains the immutable owner
  identity. Different requests stop before writing their own intent while the
  owner has no validated durable receipt. Process restart cannot reset this fence.
  A receipt persisted after synchronous child exit reconciles the fence for the
  next request; per-request execution intents are never removed. Uncertain outcomes
  require operator reconciliation, not automatic unit replay or deletion of state.

Tests cover a killed wrapper with its fake child still running, a distinct blocked
request, restart, same-request no replay, validated-receipt release, and failure
before artifact creation. These are simulated systemd transports, not live delivery.

Hosted CI 35539972112 exposed a separate fixture defect: the setup-python executable
did not satisfy production executable trust admission. The fixture now supplies an
owned 0755 dummy child executable (the fake systemd transport does not execute it).
A 0775 executable regression confirms admission still fails before any child call.
No production permissions, installed binaries, migration guards, or legacy sequence
grants were changed. Migration 021 and rollback requirements remain in the combined
activation documentation; a release-pointer rollback does not undo schema changes.
