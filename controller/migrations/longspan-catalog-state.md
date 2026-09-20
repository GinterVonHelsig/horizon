# Longspan migration catalog/state matrix

The SQL allowlists in revisions 006, 007, and 008 are projections of the
immutable inventory in `controller/migration_catalog.py`.  The revision calls
`assert_migration_catalog()` before issuing DDL; duplicate or unknown catalog
entries fail before the database is touched.

| Revision boundary | Public controller/Longspan catalog | Archive state | Sequence contract |
| --- | --- | --- | --- |
| 006 | 001–005 controller tables plus the 006 authority/evidence relations; 008 archive relations are not public 006 objects | An 008 archive is admitted only through the private recovery contract during a controlled disposable downgrade | `supervisor_events_event_seq_seq` is explicitly `OWNED BY NONE`; archive sequences are recovery-only and never adopted by 006 |
| 007 | 006 catalog plus 007 authority receipts/attestations and hardening routines; 008 archive relations are not public 007 objects | An archive is preserved only in the reviewed private recovery namespace; 007 never adopts an archive by name | Same detached event sequence; archive sequences are recovery-only; no wildcard adoption |
| 008 | 007 catalog plus the provenance state/archive table, archive sequences, and append-only trigger | Only the archive table is admitted to private recovery; the state table remains public and is removed by the controlled 008 downgrade | Every archive identity is preserved; same-ID conflicts fail closed; the canonical archive sequence is re-owned by `archive_id` and the obsolete legacy sequence is retired deterministically |

The private recovery namespace is root-transport-created only for a signed
disposable downgrade, must be owned by `top_delivery_migration`, has no PUBLIC
USAGE/CREATE ACL, and may contain only the reviewed archive table, its known
sequences, primary-key index, and append-only trigger function. Every relation
and function is checked for owner and PUBLIC ACL before adoption. The Python
catalog parser rejects any SQL migration allowlist entry not present in the
reviewed catalog.

Catalog digest is emitted by `migration_catalog.MIGRATION_CATALOG_DIGEST` and
is recorded in the review packet for each candidate.  The matrix is evidence
of state transitions, not an authorization input; release and downgrade
authority remain pinned to the controller and the out-of-band capability
service.
