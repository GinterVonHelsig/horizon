# Comms-01 Section-0 mainline reconciliation

Status: reconciled against `origin/main` at the start of this candidate.

The accepted Comms-01 release `240baf0f` contained an alternate patch whose
revision `004_auditor_provenance` followed `003_commit_order_and_invariants`.
The current mainline uses revision `004_longspan_workflow` followed by
`005_longspan_hardening`, `006_longspan_authority`,
`007_longspan_authority_hardening`, and `008_longspan_authority_repair`.

The old revision is intentionally not copied, renamed, stamped, or replayed.
Its behavior is represented in mainline by the following stronger contracts:

| Accepted Section-0 behavior | Current mainline contract |
| --- | --- |
| Auditor may complete only after independent evidence | `LongspanAuditor.audit`, persisted execution evidence, auditor capability binding, and `longspan_append_auditor_receipt` |
| Auditor completion is fenced | `longspan_assert_child_capability`, controller epoch/fence checks, and `atomic_parent_return_and_complete` |
| Evidence is content-bound | canonical evidence bytes/digests, execution audit binding, append-only ledger, and `evidence_index_scope_guard` |
| Retries create fresh authority | `resume_retry_wait`, new request/capability hashes, monotonic attempt numbers, and retry ledger events |
| Parent return is atomic and replay-safe | `LongspanRepository.atomic_parent_return_and_complete` |
| Authority is not self-provisioned by workflow code | `LongspanWorkflow.provision_authority` rejects workflow provisioning; authority writes use the Comms-01 authority boundary |
| Migration provenance is immutable | migration source anchors, catalog checks, 006–008 ownership/ACL checks, and forward-only populated-data downgrade guards |

No new schema migration is required for the accepted Section-0 behavior. A
new migration must be added only if a future semantic inventory proves a
missing control; it must be a uniquely named revision after
`008_longspan_authority_repair`.

## Database bridge rule

An existing database stamped `004_auditor_provenance` is not a member of the
mainline migration graph. It must not be upgraded in place and its
`alembic_version` must not be relabelled. The safe bridge is:

1. keep the source database read-only and capture a verified logical backup;
2. create a fresh disposable database at `003_commit_order_and_invariants` and
   run the checked-in mainline migrations through `008` after the import;
3. import only the explicit, lossless common-row mapping in
   `controller/legacy_section0_bridge.py`;
4. require a verified local database identity after connection, an explicit
   local socket/loopback host and port, a repeatable-read source snapshot,
   complete source relation/table/column enumeration, and exact
   type/nullability compatibility before copying; non-system schemas, public
   foreign/materialized relations, and duplicate host/port parameters are
   rejected;
5. require a serializable, empty and sequence-pristine target transaction
   before importing; any unlisted table or column, even when empty, must be
   added to the reviewed source-controlled legacy-empty disposition allowlist
   before the bridge can proceed;
6. preserve old evidence producer/epoch fields with their values in a
   versioned legacy attestation, rather than silently mapping them to a
   different mainline authority contract;
7. resynchronize every target sequence after explicit-key inserts and prove a
   first post-bridge event write for every event-bearing run, including
   controller event-counter consistency, cannot collide with copied state;
8. compare identifiers, counts, relationships, hashes, retry history and
   provenance before and after the mainline upgrade; and
9. use restore/rebuild for cutover, never an in-place migration-ledger edit;
10. retain a machine-readable rollback rehearsal proving the retained backup
    restores the accepted `004_auditor_provenance` state and that the rebuilt
    mainline target reaches `008_longspan_authority_repair` without digest loss.

The repository integration test is opt-in and credential-free by default. A
delivery run supplies only independently verified disposable source and target
URLs; it then runs the bridge and rolled-back post-copy event insertions. The
checked-in `scripts/rehearse_section0_mainline.py` reproduces the bridge plus
the complete 004-to-008 upgrade on disposable PostgreSQL, compares every
pre-upgrade row digest against its preserved pre-existing columns after the
upgrade, and fails closed on unexpected new relations or sequence changes. The
checked-in `scripts/create_section0_backup_manifest.py` signs a fresh read-only
Comms-01 backup hash and the verified live release/tree. The checked-in
`scripts/verify_section0_rollback.py` requires that signed manifest, verifies a
pinned restore, compares every durable table/column/sequence snapshot, and
emits a self-verified signed rollback artifact. The live backup and its
digest-only snapshot are captured from one server-side repeatable-read,
read-only transaction: `pg_export_snapshot()` is held open while `pg_dump`
imports that snapshot, then the snapshot is measured before the transaction is
closed. The capture process uses only the pinned local PostgreSQL socket and
fixed database role; it does not accept a database URL or place credentials in
argv. It removes inherited `PG*` routing overrides before invoking `pg_dump`.
The snapshot is signed on Comms-01 with its root-owned dedicated signing key,
and the candidate carries the pinned public verification key. The backup
manifest binds the server-derived database identity,
accepted release/tree, service working directory, backup hash and snapshot
hash; the verifier also requires the pinned verify-key digest and an exact
manifest field set. Timestamp digests normalize timezone-aware values to UTC so
equivalent `timestamptz` values cannot fail restore comparison merely because
the live and disposable sessions use different display time zones. A fresh
cutover backup remains retained until rollback and post-deployment acceptance
finish. Bridge and rehearsal evidence are created atomically with mode `0600`;
the bridge evidence hash covers the complete emitted artifact except the
self-referential hash field itself, using canonical compact JSON, and the scope
is recorded in `evidence_hash_scope`. Evidence containing legacy raw values is
classified restricted operational evidence, must remain root-owned with mode
`0600`, and may be summarized by digest/count in shared review packets; it is
never published as a general project artifact. Every other public sequence must
have an explicit reviewed ownership mapping; the bridge fails closed rather than
resetting an unknown sequence.

The live Comms-01 database remains on its accepted release until this bridge
is independently rehearsed against a restored live backup and a new exact-SHA
release passes review, backup, rollback and acceptance gates.

## Release and role provenance

The live snapshot signer does not infer release identity from a deployment
directory name or from a caller-provided SHA. It derives the active systemd
unit and working directory, then verifies the root-owned, separately signed
`/etc/top-delivery/comms01-release-provenance.json` against the pinned review
public key. That record binds the accepted Git object, tree, working
directory, source kind, and a content digest of the deployed controller
files. The signer recomputes that digest from the active checkout (excluding
only runtime bytecode caches) and rejects any mismatch before producing a
live snapshot. This remains valid for a deployed checkout that does not
contain a `.git` directory.

The backup-reader grant proof is two-step: a `postgres` inspection session
captures role flags, schema privileges, and every public table privilege,
while the actual backup transport authenticates through the local peer
identity `top_delivery_backup_transport`. That LOGIN role is non-superuser,
cannot create roles or databases, is default-read-only, and is granted only
membership in the `NOLOGIN` `top_delivery_backup_reader` role. A root-only
signer signs the grant capture with the pinned live-snapshot key. The
artifact proves both the grant boundary and the transport identity; it is not
accepted from an Executor claim or a database URL supplied by a caller.

Rollback is verifier-performed. The verifier first proves the disposable
restore database is empty, rejects every restore endpoint except the pinned
local PostgreSQL Unix socket, performs `pg_restore --exit-on-error`, records
full stdout/stderr digests with a bounded stored excerpt, and computes the
`live_snapshot_equal` and
`table_digests_equal` results from the restored database. Those booleans are
evidence, not operator-supplied success flags. All signed artifacts use
schema-specific domain-separated messages, preventing a valid signature for
one artifact type from being replayed as another.

The repository copy of the live-snapshot public key is advisory only. The
root-owned Comms-01 copy is the operational anchor and must match its pinned
digest; verifier errors distinguish repository-copy drift from anchor-digest
failure.
