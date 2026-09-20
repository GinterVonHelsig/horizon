# Both host submission paths — source package and consumer contract

Preparation only: no installed wrapper, socket, service, configuration, release
pointer or database was changed. This is not a delivery executor, universal Gateway
engine or unified Comms Relay. Installed-source hashes and intentional interface
differences are in tools/submission_transport/PROVENANCE.md.

## Interfaces and acceptance

Both commands share one pinned immutable release, configuration and durable journal.
`top-delivery-submit --config FILE [--inspect|--dry-run] PROMPT` is the direct host
path. `top-delivery-host-gateway --config FILE health|inspect|submit` is the Unix
socket path; inspect/submit take --prompt, and submit preserves --artifact-root and
--existing-parent. The server is `top-delivery-host-gateway-server --config FILE`.
The configuration argument is mandatory: migrate old callers explicitly, never
silently redirect them. Existing socket/service names remain compatibility endpoints.

Required gates: peer/service identity, allowlisted regular prompt and exact digest,
host-only rejection, bound artifact paths, immutable release/runtime/adapter pins,
truthful child exit and receipt validation, no duplicate dispatch across paths,
concurrent clients and restarts. Negative tests prove rejection before dispatch.
Health/inspect do not register runs. Direct --dry-run retains its inspect-only
meaning, not goal_cli's artifact-writing dry-run. Historical execute-recovery is
recognized but always blocked: packaging cannot revive archived recovery authority.
Blocked/denied exits78, not zero. Submission status=ok includes the canonical
submission_status=created/existing; preserved_disabled/awaiting_controller stays
blocked. Health reports configured readiness, not proof of active production.

## Package and configuration

```
python3 tools/submission_transport/package.py --output /NEW/STAGING/PARENT/submission-release
```

Use exact committed inputs and a nonexistent output. The manifest records full
commit/per-file hashes. It packages maintained transport source/templates and the
tracked Horizon controller Python runtime/migrations, requirements, Alembic config
and routing YAML. Tests/test_only historical bootstrap, production config/data and
credentials are excluded. Original014 replay restrictions remain unchanged.
--allow-uncommitted is TEST_ONLY development output; rebuild committed inputs before
review/installation. The fake systemd-run is never packaged. No model is called.

The package is relocatable; render consumer.example.json outside it after choosing
the immutable path. It imports packaged controller code, never a development
checkout. Provision Python>=3.11 and goal_cli dependencies from an approved runtime/
wheelhouse separately. Transport/inspection use the standard library. No runtime
dependency installation occurs. Keep the consumer disabled pending activation.

- release_root must equal the invoked package root; commit/manifest hashes must
  match. No current symlink, stale d7305d4 pin, env fallback or caller release override.
- Explicit prompt/runs/journal/socket roots. Journal directory is service-owned0700
  and shared by both paths. Preserve it, locks and receipts through release changes.
  Symlinks and dot-dot traversal are rejected.
- Explicit service UID, allowed peer UIDs and socket GID. Resolve actual topdelivery
  identities at activation; template999 is not discovery evidence. SO_PEERCRED must
  exist; both client and server identity checks remain enabled.
- Pin canonical absolute systemd-run/Python executables and adapter config hashes.
  Reference the environment file by path; do not export its credentials into Git,
  packages or tests. Canonicalize approved executable aliases before pinning.

JSON is not a general shell interface: extra flags/fields are rejected. The child
retains the attested top-delivery-entrypoint@top-delivery-controller unit and
EnvironmentFile boundary and calls exact packaged goal_cli.py with explicit adapter,
artifact and parent runtime-artifact arguments. It never invokes workers or weakens
database/attestation/source guards. The staged service template keeps existing
socket/group interfaces and adds a private journal StateDirectory; it is not installed.

## Partial failures and recovery

Key: immutable prompt digest plus existing-parent identity. Artifact destination,
release manifest and full consumer config bind on first submission. Changes conflict,
not create another dispatch. The child reads a durable immutable prompt snapshot.

| Boundary | Repeated explicit submission |
|---|---|
| Before intent: interrupted snapshot or busy attested unit | Complete the same preparation and dispatch once, unchanged binding |
| Same request, concurrent direct/socket clients | Per-request lock, same retained receipt, one dispatch |
| Different request while fixed unit is busy | Nonblocking global lock returns pre-effect blocked; no automatic retry |
| Child may have run; timeout/death/nonzero/malformed/mismatched receipt | Retain intent; outcome_unknown stops without blind replay |
| Valid receipt durable; final marker or response lost | Validate and return receipt, no dispatch |
| Paused/stopped/awaiting-controller outcome | Preserve blocked state, no takeover/reactivation |

Unknown outcomes require separately authorized reconciliation of database/artifact
evidence; no intent-deletion/replay command exists. If no trustworthy receipt can be
recovered, stop for review. GoalSubmitter partial-registration/scheduling recovery
has separate actual disposable PostgreSQL coverage; transport uncertainty does not
authorize automatically invoking it again. Not every partial outcome is autonomously
repaired: explicit terminal behavior is intentional.

## Validation and deployment limits

tests/test_submission_release_package.py runs the actual packaged direct command,
server and socket client after staging away from the checkout. A pinned **fake
systemd-run supplies simulated goal_cli receipts/effects**. Tests cover both paths,
repetition/concurrency, partial journal writes, death/lost response, parent/config
forwarding, path escapes, failed/disabled/malformed results and identity/config pins.
Reviewer package tests separately prove explicit Cursor configuration, actual
transport/model attribution and pre-dispatch rejection of OpenRouter configuration
under either reviewer command name. These checks run in required CI.

These are not real host systemd attestation, production migration, live model or
live Gateway qualification. Existing actual orchestration/disposable persistence
suites are distinct evidence. Exact source review and operator deployment remain
required. No installed consumer was invoked in these tests.

After separate activation authority: stage the matching Horizon/submission runtime
and reviewer package; render consumer files/service template; verify hashes,
imports and filesystem restrictions under the actual service identity. Change both
installed submission wrappers/module/service source selection together; no stale
d7305d4 path may coexist with a different current-selected runtime. Preserve legacy
socket/service names, authentication and the observed legacy sequence grant.

Rollback code/wrappers/config/runtime/unit definitions together with execution and
submission consumers quiescent. Retain journals/intents/receipts and Horizon graph,
adoption/review/health state. Reconcile bound in-flight requests before changing
configuration: conflict detection is intentional. Old wrappers ignoring the journal
must not be permitted to resubmit. Code rollback cannot undo021; see
recovery-activation.md for database restoration/effect-reconciliation conditions.
