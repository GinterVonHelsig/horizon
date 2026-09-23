# Explicit disposable qualification — not production activation

Both packaged submission commands now accept `--prerequisites-json PATH` with
`--prerequisites-sha256 SHA256`. Admission validates specifications/routes, journals
the exact immutable bytes and forwards that snapshot to canonical submission.
Same prompt/parent with omitted or changed prerequisites conflicts; canonical
graph identity independently binds the parsed specifications.

Registry `qualification_profile: cursor-disposable-v1` requires matching
`--qualification-profile cursor-disposable-v1` in the real worker and submit CLIs.
The packaged consumer forwards its pinned registry's declaration. Only explicit
Composer2.5 authors and read-only Cursor/Grok4.6 high reviewers are admitted.
Author-aware independence remains mandatory; no fallback/provider translation.
The September production YAML is unchanged: this profile copies policy in memory
for this disposable invocation only. The td_test_/loopback name check is additional
admission, **not isolation proof**; privileged fixtures verify actual namespaces,
mounts, submission store and the private postmaster before writes.

## Demonstrated boundaries

`controller/test_packaged_qualification.py` exercises each actual packaged
CLI/socket as first durable submitter and repeats across the other path. A
simulated systemd dispatcher runs the actual packaged goal CLI, not fake receipts.
Worker CLI subprocesses then use real orchestration/persistence on the recovered
historical016 schema upgraded through021. Initial handoff_waiting exits1; child
delivery/review/handoff does not complete the goal. One-time product adoption,
parent acknowledgement of its digest and verified parent review precede durable
whole-goal status/exit0. Both orderings pass with simulated model subprocesses.

The first four sessions are child Composer/Grok and parent Composer/Grok. A fifth
uses the separate packaged reviewer with the actual parent's harness result and
content-bound evidence. This is **standalone launcher adapter validation**, not
the worker auditor, general Gateway integration or installed-service attestation.
Other package tests cover the legacy command name's explicit Cursor requirement,
actual transport/model receipts and rejection of incompatible OpenRouter config.

### Socket inventory and the missed live boundary

The bounded chain creates four pathname sockets. Preparation binds the first two
paths and their encoded lengths in `prepared.json`; the isolated runner creates
the other two at fixed short paths:

| Producer | Consumers | Path and namespace |
|---|---|---|
| Session broker | packaged worker adapter and standalone reviewer clients | `/opt/horizon-q/<prepared-token>/b.sock`, broker on the Comms-01 host and clients inside the isolated qualification |
| Packaged submission server | direct/socket submission CLI | `/opt/horizon-q/<prepared-token>/g.sock`, inside the isolated qualification but on the host-visible `/opt` tree |
| Disposable PostgreSQL | migrations and orchestration fixtures | `/run/postgresql/.s.PGSQL.5432`, private qualification mount/network namespace only |
| Disposable authority service | orchestration clients | `/run/top-delivery/comms01-authority.sock`, private qualification mount namespace only |

The parent-controller, Signal and Hermes listeners are not started by this
qualification and are therefore not claimed by its evidence. Before the first
durable submission, the packaged rehearsal validates every encoded path, verifies
each object is a socket, connects to all four from the dispatch namespace, and
runs the submission server's real health protocol without creating a journal.

The earlier complete simulation missed the live failure because its generic
submission fixture placed `socket_path` below pytest's ordinary `tmp_path`, which
was short enough, while the live opt-in supplied a much longer explicit
`--basetemp`. Only the broker path was replaced from the prepared receipt; the
submission listener continued to inherit the nested live pytest path. The
corrected fixture always generates broker and submission paths together in a
separate short private runtime root, while a regression runs the same packaged
commands, config generation, private namespaces, long artifact layout, actual
orchestration and persistence. The privileged regression explicitly sets
`HORIZON_TEST_SOCKET_BASE=/opt/horizon-q`, so its runtime layout matches the live
prepared root rather than silently shortening pytest's durable directory under
`/tmp`. Only the Cursor processes are simulated.

## Isolation and durable limits

`tools/qualification/session_gate.py` is a direct Unix-socket broker, not a
delivery controller. Its durable ledger remains under the immutable artifact
root, while its listener uses a separate private, root-owned short directory
under `/opt/horizon-q/<prepared-token>/b.sock`. The packaged submission listener
uses sibling `/opt/horizon-q/<prepared-token>/g.sock`; neither inherits the
durable artifact or pytest path. Unlike `/run`, this runtime-only
tree remains visible when the disposable worker replaces `/run` with private tmpfs.
Preparation and broker admission
validate the encoded Linux `sockaddr_un` length. The broker binds and listens
before it creates a ledger, so an overlong path, stale listener, ownership error
or collision fails without consuming durable state. The prepared receipt binds
both exact sockets and encoded lengths. Clean restart recreates only the ephemeral
listener and retains the same durable budget; reboot or an uncertain intent still
blocks rather than resetting the ledger.

Workers/PostgreSQL use scripts/test-recovery-isolated.sh's
private mount/network/PID namespaces and private trust/submission-store mounts.
For a future live run the broker sits outside that private network namespace;
only its socket is shared. Cursor gets a fresh mount/PID namespace and a
pivot-root jail that detaches the old root,
one task workspace, pinned public runtime, and a read-only authentication-file
bind. Existing homes/sessions, DB sockets, host submission store, broker ledger
and checkout are not mounted. Only system binaries/libraries and public TLS
certificates are mounted, never /etc/ssl/private or /usr/local. Jail scratch is
under the private qualification state root. Grok's workspace is read-only; capabilities are
dropped and no_new_privs enforced. Landlock ABI4+ denies TCP listeners and all
TCP connects except443. **This is port confinement, not domain filtering.**
Cursor's enabled tool sandbox and no-network/no-shell task instructions are
additional boundaries. Missing kernel confinement fails closed.

The root-controlled ledger fsyncs slot consumption before launch. Exactly five
ordered slots survive restart. Timeout, nonzero exit, malformed/wrong-model output
or death before finalization leaves uncertain/intent and blocks further dispatch.
No replay/reset/refund is permitted. A stale socket may be removed only after
confirming broker death and inspecting the preserved ledger; this never grants
another session. Killing the broker kills unshare, then its PID namespace and
daemonized children. Tests demonstrate real timeout/orphan cleanup and persistence.

Proposed limits:300seconds each for the first four sessions,900 for standalone,
2400 overall. The provider's existing600-second combined contract remains intact.
Observed4a5312d live timings were7.97seconds Composer and118.94seconds Grok;
300seconds gives the task reviewer about2.5x that observation. Prior source reviews
took438/462.6seconds;900 gives roughly2x for the larger standalone packet. These
are justified margins, not guarantees. Limit exhaustion stops uncertain, not retry.

## Preparation and later authorization

From the exact clean reviewed checkout onComms-01, preparation only:

```sh
python3 tools/qualification/prepare.py \
 --output /opt/operator-harness/artifacts/APPROVED-CANDIDATE/qualification-prepared \
 --runtime-source /opt/operator-harness/share/cursor-agent/versions/2026.08.11-e8db854 \
 --auth-file /root/.config/cursor/auth.json
```

Destination must be new. This stages both committed packages and hash-pinned
public runtime files selected by the committed vendor payload manifest; installed
`.running` markers are explicitly excluded without reading or altering them.
Frozen runtime inventory must match exactly; extra state/cache/files are rejected.
Authentication is only referenced, never copied. Preparation durably fsyncs the
gate and prepared receipt, which hash-binds gate bytes and canonical runtime
inventory, plus authentication reference and both package manifests. It emits
NOT_INVOKED prepared.json and SHA256. It launches no broker/model/migration/service.
Preparation also atomically reserves the receipt-bound private short socket root;
an existing directory or listener is collision evidence and is never reused.
The next authority prompt must pin that hash and the exact reviewed commit.

Future commands below are **not authorized by this source/test pass**:

```sh
python3 QUALIFICATION_ROOT/submission/tools/qualification/session_gate.py \
 --config QUALIFICATION_ROOT/gate.json --execute-authorized-live \
 --prepared QUALIFICATION_ROOT/prepared.json --prepared-sha256 PREPARED_JSON_SHA256
# Separate direct process; retain this broker's PID for bounded cleanup.
HORIZON_PREPARED_QUALIFICATION=QUALIFICATION_ROOT/prepared.json \
HORIZON_QUALIFICATION_AUTHORIZATION=operator-authorized:PREPARED_JSON_SHA256 \
bash scripts/test-recovery-isolated.sh -x -q -ra --tb=short \
 --basetemp=QUALIFICATION_ROOT/workspaces/NEW_UNIQUE_PYTEST_ROOT \
 controller/test_prepared_qualification_live.py
```

Never reuse an existing basetemp: pytest deletes it. The separate opt-in checks
clean exact source, committed package hashes and isolation. Default CI does not
invoke it. Initial submission is direct, repeat is socket; simulated coverage also
reverses the initial path. Live authentication/model availability and compatibility
with the new confinement remain unverified. On-Demand-disabled evidence is the
operator's account-setting confirmation, not programmatic billing attestation.
Both broker startup and the live opt-in verify the gate/runtime/auth binding.
Live evidence additionally requires actual init models and pinned runtime inventory
in each durable session record; an environment variable is not evidence of live execution.

Stop at the first failure, nonzero result except initial handoff_waiting, model
mismatch, missing evidence, failed verdict, uncertain intent or exceeded budget.
Preserve evidence/ledger; no new task, retries, fallbacks, remediation or cleared
intents. All five slots share this one qualification; standalone review is separate
from whole-goal completion. No OpenRouter transport is available.

## Deployment/rollback

No installed file, service, pointer, authentication or parked goal changes here.
Keep production's profile absent and September defaults intact. Installation,
consumer selection, migration021 and activation require separate operator authority
and recovery-activation.md's combined checklist. This pass adds no schema change.
Package rollback does not undo021: preserve graph-enabled runs/intents and the
legacy sequence grant. Old code must not process graph-enabled runs; restore the
coordinated DB/artifact backup when required by existing compatibility conditions.
General Gateway Delivery and unified Comms Relay remain outside this scope.

### Bounded child diagnostic enum

The qualification ledger stores only an allowlisted `child_diagnostic` code,
stderr byte count, and SHA-256; it never stores child stderr text. Current codes
are `network_dns_failure`, `network_tls_failure`, `network_transport_failure`,
`api_http_failure`, `filesystem_access_failure`,
`authentication_or_permission_failure`, `cursor_cli_argument_failure`,
`sandbox_setup_failure`, `confinement_startup_failure`,
`child_outcome_uncertain`, and the generic child-failure codes. Classification is
contextual and first-match ordered so CLI usage errors and pivot/confinement
errors cannot be relabeled by a generic `--sandbox` token. Any non-successful
classification remains uncertain and blocks replay.

The same ledger entry records `child_stdout_bytes` and an allowlisted
`output_validation_reason`: `child_exit_nonzero`, `malformed_stream_json`,
`malformed_event`, `missing_events`, `missing_or_duplicate_init`,
`identity_mismatch`, `invalid_terminal_result`, or `valid`. The broker may return
an empty stdout after an uncertain validation outcome, so the byte count describes
the child stream before that fail-closed response; the stream itself is never
persisted. These fields are diagnostic only and do not authorize replay or turn
an uncertain outcome into success.
