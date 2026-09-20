# Comms-01 attestation and database-port rollout

`database_port` is part of the pinned target identity. It is not an optional
runtime hint: a target with a missing, invalid, or mismatched port must fail
closed before opening a database connection.

When an existing Comms-01 installation is upgraded to a release that requires
this field, use this sequence:

1. Stop only the isolated Comms-01 controller/authority services and record
   their unit state, host fingerprint, target-file hashes, database revision,
   and rollback release.
2. On the Comms-01 host, verify the local PostgreSQL socket and intended port
   (`5432` unless the attested target explicitly says otherwise). Verify
   `current_database`, `session_user`, `current_user`, server address/socket,
   and effective port against the pinned target.
3. Have the external authorization service issue a versioned, 2FA-approved
   attestation update containing `database_endpoint`, `database_port`, the
   workflow and authority roles, controller service, host fingerprint, and
   previous-file digest. The workflow/Executor cannot create this update.
4. Write the new root-owned, mode-0600 target and attestation files atomically,
   fsync them, and record their hashes. Validate them with the same loader used
   by both services before starting either service.
5. Start the authority service first, then the controller. Verify the target,
   role, revision and socket identity read-only; roll back the files and release
   if any check fails.

The sequence is also the rollback procedure: restore the prior attested files
and exact release from the recorded hashes, then repeat the read-only checks.
This document does not authorize production, broker, ledger, network, or VM
mutation.
