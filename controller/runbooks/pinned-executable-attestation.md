# Comms-01 pinned executable attestation

`controller/pinned-executables.json` is part of the reviewed source release.
It records the exact SHA-256 bytes and package/version evidence for every fixed
child command. Runtime code loads this manifest; it does not accept an
environment override or a caller-supplied executable path.

To repin after an intentional OS package upgrade:

1. Record the change request, target host, package name/version, executable
   path, and the old/new SHA-256 values in the run manifest.
2. On the isolated Comms-01 build host, verify ownership/mode and capture:
   `sha256sum <path>` and `dpkg-query -W -f='${Package} ${Version}\\n' <package>`.
3. Update the manifest in a reviewed branch, run the pinned-command and
   failure-injection tests, and obtain the independent review gates.
4. Merge and deploy the exact reviewed SHA. Never edit the manifest in place
   on Comms-01 or repin from a failed child process.

The release unit must install
`deploy/top-delivery-restore-fences.tmpfiles` and
`deploy/top-delivery-pinned-executables.tmpfiles` and
`deploy/top-delivery-trust-anchors.tmpfiles` before enabling restore
paths or either controller service. Git records only the executable bit, not
mode `0640`, so the release unit must apply the manifest mode after every clean
checkout. The manifest is root-owned and group-readable only by `topdelivery`;
its exception rejects group/other write bits and setuid/setgid, while
world-read and execute bits are tolerated for this non-secret manifest only.
The only other readable trust exception is the path-bound, non-secret
disposable capability verifier, which is root-owned `0640 root:59901`.
Private signing keys, consumed nonces, and other non-runtime secret trust
anchors remain root-owned and mode `0600`. Runtime inputs that the non-root
authority service must read are exact-path, root-owned `0640 root:59901`
contracts; they are not permitted to fall back to world-readable files. The
deployment must provision numeric GID `59901` as the `topdelivery` group before
applying the tmpfiles rule. The restore implementation rejects an absent, non-root-owned,
writable, or non-0700 fence directory; it does not silently create one.

Trust-anchor ownership is explicit and is tested as a release contract:

- `comms01_authority_secrets.py` consumes the operator and Terra public-key
  files plus the Comms-01 attestation as root-owned UID/GID `59901`, mode
  `0640`.
- `db.py` and `authority_service_server.py` consume the authority database
  target as root-owned UID/GID `59901`, mode `0640`; the workflow database
  target follows the same root-owned, service-group-readable runtime contract.
- `disposable_capability.py` reads the signed disposable harness capability as
  root-owned mode `0600 root:root`; it is intentionally not widened to the
  non-root service group because it gates every disposable database mutation.
  The public verifier key is a separate non-secret `0640 root:59901` input. The
  corresponding private signing key is root-owned mode `0600` and is used only
  by an out-of-band capability issuer; neither runtime role can read it.
- The migration-source provenance witness is the root-owned `0600 root:root`
  file `comms01-migration-source-provenance.json`; it contains the normalized
  008 digest plus an exact raw-byte digest map for historical 004–007
  revisions. It is read only by the migration gate and is never provisioned by
  the workflow. Every admitted historical downgrade verifies its own source
  entry before capability lookup or DDL.
- `ledger_mac.py` and `terra_gateway_mac.py` consume their authority-held
  keys as root-owned UID/GID `59901`, mode `0640`; the authority-write
  signing secret follows the same service-readable contract.
- The runner envelope public key is root-owned UID/GID `59901`, mode `0640`;
  the executable manifest and disposable verifier are the other non-secret
  trust files with a service-group read mode. Every exception is exact-path
  bound in code; the signed disposable harness capability is not an exception.
- The consumed-capability nonce store is the out-of-band root-owned
  `0600` file `comms01-disposable-consumed-nonces.json`; its parent is never
  created by runtime code, and the store is opened with `O_NOFOLLOW`.

The tmpfiles rules use numeric identities so a missing or renamed local group
cannot silently broaden access. They adjust existing files only; provisioning
the files and keys remains an out-of-band release prerequisite.

Restore-fence operational invariants:

- `/var/lib/top-delivery/restore-fences` is provisioned out of band as UID 0,
  GID 0, mode `0700`; the runtime never creates or broadens it.
- The restore path uses one permanent root-private host-local `flock` for the
  target operation and one permanent root-private host-local `flock` for
  rotation/clearance. They are not distributed locks and must not be treated
  as cluster fencing; the target lock is acquired before the rotation lock.
- Failure records are bounded to 32 per fence. One permanent root-private
  rotation lock serializes rotation, append, and clearance for every fence;
  there are no per-fence lock files to accumulate. The rotation state and
  malformed-state quarantine record dropped occurrences. After an authorized
  verified restore or snapshot recovery clears the fence, failure records,
  rotation state, and quarantined state files remain as durable incident
  evidence; only abandoned atomic-write temporary files are removed.
- Clearance records are bounded to 32 per fence identity. The oldest
  root-private records are rotated only while the rotation mutex is held;
  matching same-approval retries are idempotent and conflicting records fail
  closed.
- `MAX_RESTORE_FAILURE_STATE_QUARANTINES=4` bounds malformed rotation-state
  quarantine files. The `quarantined_occurrences` counter records discarded
  overflow in both the rotation state and its root-private
  `rotation-quarantine-count` sidecar; the retained newest four files remain
  evidence.
- Malformed drop/quarantine counter sidecars are renamed into bounded
  root-private quarantine files and reconstructed under the same mutex; a
  malformed counter never silently resets replay/failure accounting.
- A failure record that is not a root-private regular file is a deliberate
  fail-closed operator boundary: recording stops, the fence remains active,
  and an operator must inspect/quarantine the hostile entry out of band before
  retrying. The runtime never follows or deletes that untrusted path.
- Clearance is idempotent for one approval and snapshot digest: a retry accepts
  an existing matching root-private clearance record after validating its
  stable fields and timestamp, but rejects a conflicting pre-existing record.
- A recovery witness expires after five minutes. A retry must obtain a new
  signed witness; an expired witness is never reused.
- A populated 008 control database is rolled back by restoring a verified
  backup/PITR copy, not by an in-place destructive downgrade. An empty,
  independently signed disposable target may use the static 008 → 007 inverse.
- `longspan_migration_provenance_008_archive` intentionally persists after a
  disposable 008 → 007 rehearsal as an append-only recovery audit. It is not
  part of a pristine 007 schema; repeated cycles retain the first application
  record, increment `application_count`, update `last_seen_at`, and reject a
  conflicting source digest. The live provenance relation is deliberately
  dropped during the inverse; the archive is the retained recovery record.
