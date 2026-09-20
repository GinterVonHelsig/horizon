# Comms-01 operation contract

The control-plane VM has a technical target contract in
`comms01_operation_policy.py`:

- backups can target only `/var/lib/top-delivery/backups` or the pinned
  `/mnt/pve/synology/top-delivery` subtree;
- service status/restart requires an attested Comms-01 service name;
- restore and authority rotation require an external 2FA receipt;
- deployment is rejected from Comms-01 and remains Terra's release action;
- optional database and host arguments are checked against the Comms-01
  attestation before any operation is allowed.

The policy is a pre-side-effect gate, and
`comms01_operation_entrypoints.py` is the only in-tree side-effect adapter:

- `backup_bytes()` opens and writes an exact artifact through
  `open_pinned_backup_file()`, which walks the absolute path by directory file
  descriptor with `O_NOFOLLOW` and prevents intermediate symlink substitution.
  The adapter selects fixed create-exclusive backup or read-only restore modes;
  callers cannot supply truncation, append, or other open flags;
- `restore_bytes()` requires the signed 2FA receipt before reading the pinned
  backup, requires the approved SHA-256 and exact byte size, rejects non-regular
  or oversized files, and returns the verified bytes/digest to a future restore
  orchestrator. This is read-verification only: this contract does not claim to
  execute a database restore, replace a target, or prove post-restore
  application acceptance;
- `service_status()` and `service_restart()` invoke only fixed `systemctl`
  argv tuples after service-name validation; arbitrary shell commands are not
  accepted.

The authority socket invokes the same policy before authority rotation. No
other runner may open backup paths, restore a database, or execute service
commands directly. The ledger and Terra gateway MAC keys are separate pinned
authority materials; workflow code cannot read either key. Authority-socket
calls have a bounded timeout so a workflow transaction cannot hold a child
fence indefinitely while waiting on the authority service. Controller parking
emits a dedicated `controller_parked` ledger event, distinct from an
authorization failure. Future adapters must be added here with focused tests
and their own evidence/rollback records. Comms-01 cannot deploy a release.

Authority MAC bootstrap is idempotent for the already-pinned material. A
different key is rejected unless a future signed, 2FA-bound rotation path
explicitly authorizes it; ordinary attestation requests cannot grow key history.
