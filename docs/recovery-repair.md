# Recovery repair — direct Codex session, Comms-01

## Initial diagnosis (2026-09-20)

Base: GinterVonHelsig/horizon main e6c0b131184869c720f8d180f36ddc48b8a774af.
Isolated branch: codex/repair-horizon-recovery. No controller submission authorized.
Comms-01 current resolves to /opt/top-delivery-p1/f10c88295daec8bc45f636c4fbac41ad67209475-goal-runner.
This deployed directory has no Git metadata; its directory name is not independent
proof of source revision. worker.py and goal_submitter.py are byte-identical to base.
top-delivery-controller.service is inactive/dead; top-delivery-worker.service is
failed/failed. No service, live database, deployed source, or auth pin was changed.

Confirmed code defects: provider validation and worker criteria hard-code VM9201;
submission skips registration when artifacts exist; ParentController.register_run
can force-take over another controller; continuous PermissionError polling is
unbounded and one-shot reports success even for an unsuccessful task result.

Runtime evidence (sanitized journal): older attempts on source 777c3e4 fail first
at worker._task_context with missing workstream metadata, then dependency loading
fails because the goal spec is missing. Later one-shot invocations report
PermissionError (errno absent, then 13). The sanitized log does not establish the
precise denied path; a filesystem diagnosis must not be inferred from errno alone.
Controller writable paths cover an older artifact directory; worker writable paths
cover /var/lib/top-delivery/runs and /opt/operator-harness. Configuration pins
goal-3eb7b972ec15809e but includes that same run in the worker skip list. These
are observations, not authorization to repair parked run state.

Gateway Delivery is a coordinator skill at
/opt/operator-harness/homes/.codex/skills/gateway-delivery/SKILL.md, SHA256
1f1bbbfe162a19afb43d940f1bb8d646a0701a020b630bc74d3ed11b6d388af8.
Its directory is outside a Git checkout. It describes a multistage workflow, not
a HarnessAdapter executable. /etc/top-delivery/adapters.json registers cursor-cli
and openrouter-claude-auditor defaults (effective models composer-2.5 and
openai/gpt-5.6-sol), but neither gateway-delivery nor
openrouter-independent-review. No replacement or silent alias is authorized.
The host submission gateway is not the delivery coordinator adapter.

Path: prompt parser -> immutable submission artifacts -> run registration ->
controller epoch/lease -> root scheduling -> fenced task claim -> task context ->
executor evidence -> independently bound auditor evidence -> provider product or
verified completion -> successor scheduling. Stale attempts enter fenced cleanup.

## Acceptance checklist

All model execution in deterministic tests must be labeled simulated.

- [x] Normal durable task, independent review, evidence, verified completion.
- [x] Duplicate/concurrent submission: one run/task graph, immutable content.
- [x] Recover artifacts-before-registration failure.
- [x] Recover registration-before-scheduling failure; dry-run promotion.
- [x] Worker death after claim: fencing and no duplicate effects.
- [x] Permanent permission failure reaches persistent inspectable block.
- [x] Worker restart preserves block; explicit recovery after repair.
- [x] Missing route/capability rejected before executable scheduling.
- [x] Provider-specific valid and invalid handoff products; forged binding rejected.
- [x] Auditor rejection never succeeds or creates unlimited children.
- [x] Paused/stopped states survive submission and worker restarts.
- [x] CLI status/exit code agrees with durable result.
- [ ] Required CI checks and disposable integration suite pass.
- [ ] Review branch pushed, review recorded, activation/rollback documented.
- [ ] Real-adapter smoke, if supported by existing route and spending authority.

## Hypothesis / evidence log and checkpoint

Each signature gets at most three unsuccessful diagnostics/repairs before reassessment.
1. CONTRACT_VM_ONLY: earliest boundary product validation; both providers share
   VM-specific code and worker criteria. Confirmed by source inspection; no edit yet.
2. ROUTE_MISSING: earliest boundary provider scheduling; runtime registry lacks the
   requested IDs. Confirmed; dependency must fail before a provider task is created.
3. SUBMIT_ARTIFACT_ONLY: earliest boundary registration; existing spec skips it.
   Confirmed; reconcile registration without resetting state or taking a lease.
4. POLL_PERMISSION: earliest boundary pre-claim/claim; while-loop never exhausts.
   Confirmed; persist a fail-closed block outside the potentially unwritable run root.
5. UNKNOWN_EXECUTION_OUTCOME: inspect stale cleanup before allowing replay.

## Findings and repair disposition

The six relevant deployed files (subworkflow_handoff.py, goal_submitter.py,
worker.py, parent_controller.py, repository.py, harness_adapters/registry.py) are
byte-identical to the review snapshot. The deployed tree additionally contains two
source modules omitted from Git by `*secret*`: authority_socket_secrets.py and
comms01_authority_secrets.py. Restored source contains loaders, not key material.
GinterVonHelsig/TOP-DELIVERY at /opt/operator-harness/work/TOP-DELIVERY is
20a85e0f119bc87fe7b4638ca2dc529cc978dd04 and was not modified. The installed
Gateway skill has no independently verifiable Git version; its digest above is
the available version identity. It is not interchangeable with
/opt/operator-harness/bin/top-delivery-host-gateway (submission transport).

| Stable signature / earliest boundary | Targeted change and evidence |
| --- | --- |
| CONTRACT_VM_ONLY / provider validation | Request, worker criteria, and product use the registered provider's disposition. Horizon binds prerequisite node, repository, isolated scope, source/test/rollback artifact digests and request/scope provenance. VM9201 requirements remain VM-specific. Both providers pass valid and reject invalid simulated end-to-end products. |
| ROUTE_MISSING / before scheduling | Validate explicit registered routes, distinct effective identities and workspace-execution capability. No production aliases were added. Missing Gateway IDs produce a precise error before creating a provider task. |
| SUBMIT_ARTIFACT_ONLY / registration | Lock publication, publish complete artifacts atomically, compare immutable content on retry, reconcile database rows every time, never force takeover. Passive submitters report awaiting_controller. Paused/terminal runs remain preserved. |
| POLL_PERMISSION / worker poll | Permission and ownership failures block immediately (budget one). PostgreSQL connection failures have three attempts with persisted backoff. Private SQLite poll health survives restart. Explicit recovery records a reason without starting work. Exit 78 prevents systemd restart loops. |
| UNKNOWN_EXECUTION_OUTCOME / executor dispatch | Fsync an exclusive logical-task execution intent before effects. A lost or malformed result blocks for reconciliation; retry cannot rerun the executor. SIGKILL before dispatch recovers normally; SIGKILL after effect blocks with exactly one effect. |
| HANDOFF_ID_PARSE / context lookup | Resolve and validate durable provider requests before applying ordinary goal task-ID parsing. This was the earliest failure of the first complete provider-worker test. |
| OWNER_LABEL_RECLAIM / claim | Shared owner labels no longer return a live attempt to another process. Expired attempts are cleaned under the current epoch regardless of old owner name. |
| AUDITOR_BIND_UNUSED / review | Wire the repository's existing criterion/evidence-bound auditor implementation into the worker. Bare approve is insufficient; tampered evidence is rejected. Auditor rejection is durably blocked, with no remediation chain. |
| SOURCE_MODULE_OMITTED / import | Two ignored source loaders restored, with exact filename exceptions in .gitignore. Fresh-checkout tests now import the actual authority implementation. |

The first database harness failures were distinct setup boundaries: missing source
modules, an empty trust directory rejected by its guard, default writable tmpfs
mode, and a legacy libpq query-string URL rejected by existing target policy.
Each was diagnosed before changing its specific input. The final harness uses
private mount/network/PID namespaces, an empty root-owned 0755 trust tmpfs, an
explicit disposable attestation fixture, and a fresh PostgreSQL cluster at a
canonical URL. It never connects to host PostgreSQL or installs live trust files.

One early host-safe unit run created a new empty poll-health SQLite schema in
/var/lib/top-delivery/worker-health. It was moved to
/opt/operator-harness/artifacts/20260920-horizon-recovery/unit-test-worker-health.
Tests now isolate that path using tmp_path. No existing runtime data was replaced.

## Compatibility and limits

- Existing provider requests lacking required_disposition or failing the immutable
  request contract are rejected. Do not rewrite parked request artifacts in place.
- Durable submission requires an explicit valid registry. Artifact-only submission
  is not evidence of scheduling; awaiting_controller requires a separate active
  controller lease and a retry of the same immutable submission.
- Claims may not be resumed merely by reusing an owner string. Wait for expiry and
  fenced cleanup. Externally ambiguous effects require operator reconciliation;
  this repair deliberately offers no automatic deletion of execution intents.
- Auditor outputs must satisfy the existing evidence-bound schema. A bare verdict
  is no longer accepted. Provider requests have a fixed 1800-second overall budget,
  five-attempt ceiling, and cannot create nested prerequisite repairs.
- No PostgreSQL migration is proposed. Poll health is a new private SQLite file;
  execution intents are new durable artifact files. Both must survive rollback.
- Submission reconciliation assumes the same canonical artifact root and prompt
  source path on replay. Cross-root relocation is not a supported recovery action.

## Validation and remaining blockers

Run from the isolated checkout on Comms-01:

```sh
rtk proxy bash scripts/test-recovery-isolated.sh -q --tb=short \
  controller/test_recovery_acceptance.py \
  controller/test_subworkflow_handoff.py \
  controller/test_subworkflow_handoff_integration.py \
  tests/test_worker.py tests/test_worker_cleanup.py \
  tests/test_worker_integration.py tests/test_worker_service.py \
  tests/test_goal_submitter.py
```

The legacy six-workstream test now uses a self-contained fixture instead of an
external /home/trading prompt. Its six-task/dependency assertions are unchanged.
The new CI job runs the PostgreSQL acceptance and both provider suites in isolation.
The existing focused CI command is preserved in .github/workflows/ci.yml.

All new adapters in test_only/recovery_fakes.py are SIMULATED. They are not a
replacement Gateway implementation. They exercise actual parsing, PostgreSQL
registration, lease fencing, claims, worker execution, evidence persistence,
independent review validation, provider handoff, and task finalization.

Five required model-routing tests fail unchanged at the original base and the
repair candidate: phases 0/1/2, 4, 6, a fallback provider, and phase 1.6 fallback
expectations conflict with architecture/model-routing.yaml. The base reproduction
is 5 failed / 4 passed in tests/test_model_routing.py. No model substitutions or
test relaxations were made. Operator policy must select the intended routing
contract before a separately scoped reconciliation can make CI green.

Read-only real-adapter preflight passed on Comms-01 for cursor-cli/composer-2.5
and openrouter-claude-auditor/openai/gpt-5.6-sol, including relay health. No real
model task ran: the Gateway identifiers are absent, and the remaining shared
monthly spending authorization for an isolated model call was not established.
Configured limits of $5/run and $50/month are not evidence of remaining allowance.
Required next validation is one explicitly budgeted disposable file-write plus
independent review using approved real routes; live Gateway validation additionally
requires the actual supported executable integration and its version.

The patch received a local source review against the acceptance checklist,
fencing, immutable evidence, process restart, and exit-code boundaries. It has
not received an external independent code-review verdict; the draft PR is for
that review. Production activation remains forbidden by this repair envelope.

See recovery-activation.md for the conditional activation and rollback procedure.
