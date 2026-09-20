# Longspan 006 → 008 populated-database runbook

Migration `008_longspan_authority_repair` intentionally fails closed when a
006 database already contains execution audits or auditor/Terra evidence. The
migration must not invent an evidence digest or silently reinterpret legacy
rows. A populated 006 database therefore follows this operator-controlled
path; an ordinary application or Executor cannot enable it.

1. Take and independently restore a backup of the exact 006 database. Record
   the database name, connected role, PostgreSQL system identifier, Alembic
   revision, row counts, row digests, candidate SHA/tree, and backup digest.
2. Have the external Comms-01 authorization service issue a one-time,
   2FA-approved backfill receipt binding the exact source database, source
   revision `006_longspan_authority`, target revision, reviewed SHA/tree,
   backup digest, and operator signature. The workflow role cannot create or
   rotate this receipt.
3. On the restored disposable copy only, reconstruct every legacy execution
   audit and auditor receipt from its immutable raw artifact. Compute the
   canonical 007 evidence digest from the reconstructed bytes. If the raw
   artifact or its digest cannot be proven, leave the row at 006 and stop;
   deleting or guessing a digest is not an allowed migration.
4. Apply the signed backfill in one transaction, record the source-row digest,
   resulting 008-row digest, receipt ID, and migration head, then complete the
   008 forward repair. The upgrade itself remains fail-closed if any legacy
   row is still missing a proven digest.
5. Restore the copy to a second disposable instance, verify the 006→008 row
   counts and content digests, and re-upgrade it from the recorded backup.
   Only after both restore rehearsals and independent audit approval may a
   release workflow schedule the corresponding controlled target migration.

The runbook is a procedure specification, not a migration bypass. It does not
authorize production, broker, ledger, network, or release mutations, and no
008 downgrade is allowed to destroy populated evidence.

## Populated 008 rollback

An in-place `008 → 006` downgrade is intentionally rejected whenever any
authority, execution, auditor, Terra, ledger, MAC-material, or legacy-attestation
row exists. In particular, `longspan_mac_material` and its key history are
authority-controlled cryptographic state; dropping them would make the ledger
unverifiable and would not be a safe rollback.

The rollback for a populated 007 database is therefore **restore-from-backup**,
not a destructive downgrade:

1. Freeze the target through the existing controller fence and capture the
   exact target identity, Alembic head, WAL/backup digest, and release SHA.
2. Restore the last known-good 006 backup to a separately verified disposable
   PostgreSQL instance. Never restore over the live target during rehearsal.
3. Verify database identity, schema revision, authority provenance, row counts,
   ledger/MAC material, and application read-only connectivity. A PITR restore
   must replay to a timestamp before the 007 mutation and after the last
   accepted 006 checkpoint.
4. Have the external authority service sign the restore decision, bind it to the
   backup digest and target identity, and record the rollback receipt in the
   evidence ledger.
5. Promote the restored instance only through the normal release owner after
   the independent auditor and Terra review pass. The original 007 target is
   retained read-only until post-rollback acceptance completes.

The disposable test suite must prove both sides of this contract: an empty
008 schema can use the static, signed 008 → 007 inverse and re-upgrade with an
exact catalog/ACL match, while a populated 008 schema fails the downgrade
before any protected object is removed and remains restorable through the
backup/PITR path. The 008 provenance row is archived, never deleted.

The restore-fence directory is root-owned UID 0/GID 0 with mode `0700`; its
lock is host-local `flock`, not a cluster-wide lease. The Terra recovery
witness expires after five minutes and every retry requires a newly issued
witness.
