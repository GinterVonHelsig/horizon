"""Pinned Comms-01 authority and attestation anchors (no runtime env override)."""

from __future__ import annotations

# Root-owned Unix socket for authority write operations.
AUTHORITY_SOCKET_PATH = "/run/top-delivery/comms01-authority.sock"

# Root-owned operator verification keys (public material only).
OPERATOR_PUBLIC_KEYS_PATH = "/etc/top-delivery/comms01-operator-keys.json"

# Separate root-owned Terra receipt verification keys.  This is deliberately
# distinct from the operator approval and ledger-MAC trust anchors: the
# workflow may verify a Terra receipt, but it may not provision or replace the
# key used to sign one.
TERRA_RECEIPT_PUBLIC_KEYS_PATH = "/etc/top-delivery/comms01-terra-receipt-keys.json"

# Root-owned Comms-01 scope attestation consumed by controller entry points.
COMMS01_ATTESTATION_PATH = "/etc/top-delivery/comms01-attestation.json"

# Disposable schema harness capability (out-of-band install for test/downgrade only).
DISPOSABLE_HARNESS_CAPABILITY_PATH = "/etc/top-delivery/comms01-disposable-harness.json"

# Out-of-band root-held signing key for issuing disposable capabilities. The
# workflow and authority service verify with the separate public key below;
# neither runtime role may read this private key.
DISPOSABLE_CAPABILITY_SIGNING_KEY_PATH = "/etc/top-delivery/comms01-disposable-signing-key"
DISPOSABLE_CAPABILITY_VERIFY_KEY_PATH = "/etc/top-delivery/comms01-disposable-verifier.pub"

# Dedicated PostgreSQL LOGIN roles enforced by migration 007.
WORKFLOW_DATABASE_ROLE = "top_delivery_workflow"
AUTHORITY_DATABASE_ROLE = "top_delivery_authority"
MIGRATION_DATABASE_ROLE = "top_delivery_migration"
ATTACKER_DATABASE_ROLE = "top_delivery_attacker"

# Controller trust anchors. These are never taken from a caller URL or a
# disposable capability, and every administrative target must agree with them.
COMMS01_DATABASE_ENDPOINTS = frozenset({"local", "localhost", "127.0.0.1", "::1"})
COMMS01_DATABASE_PORT = 5432

# Only out-of-band local PostgreSQL identities may perform disposable
# create/drop DDL. A capability must not elevate an arbitrary CREATEDB role.
ADMIN_DATABASE_ROLES = frozenset({"root", "postgres"})


def effective_migration_capability_role(database_role: str) -> str:
    """Map only approved administrative transport identities to the migration role."""

    role = str(database_role)
    if role in ADMIN_DATABASE_ROLES:
        return MIGRATION_DATABASE_ROLE
    return role

# Pinned authority service database target (no caller db_url substitution).
AUTHORITY_SERVICE_DATABASE_TARGET_PATH = "/etc/top-delivery/comms01-authority-db-target.json"

# Authority-socket signing material is provisioned out of band. The
# authority service reads it, but no workflow process may provision or replace
# it.
AUTHORITY_WRITE_SIGNING_SECRET_PATH = "/etc/top-delivery/comms01-authority-write-secret"

# Pinned workflow/controller database target (no caller db_url substitution).
WORKFLOW_DATABASE_TARGET_PATH = "/etc/top-delivery/comms01-workflow-db-target.json"

# Out-of-band source digest for the forward 008 migration.  The migration
# source carries a diagnostic marker, but release authority comes from this
# separately provisioned root-owned trust file.
MIGRATION_SOURCE_PROVENANCE_PATH = (
    "/etc/top-delivery/comms01-migration-source-provenance.json"
)

# Backup roots are explicit operation targets, never caller-selected paths.
COMMS01_BACKUP_ROOTS = (
    "/var/lib/top-delivery/backups",
    "/mnt/pve/synology/top-delivery",
)

# Root-owned durable restore fences and the permanent host-local restore mutex.
# This is deliberately separate from backup roots so a backup operator cannot
# clear a destructive restore fence by replacing or deleting a backup artifact.
RESTORE_FENCE_ROOT = "/var/lib/top-delivery/restore-fences"

# Authority-held ledger MAC material (never workflow-selected).
LEDGER_MAC_KEY_PATH = "/etc/top-delivery/comms01-ledger-mac.key"

# Separate authority-held Terra gateway proof material.  It is intentionally
# not the ledger MAC key, even though both are protected by the authority role.
TERRA_GATEWAY_MAC_KEY_PATH = "/etc/top-delivery/comms01-terra-gateway-mac.key"

# Controller-issued OpenRouter job envelope verification key (public material only).
RUNNER_ENVELOPE_PUBLIC_KEY_PATH = "/etc/top-delivery/comms01-runner-envelope.pub"

# Dedicated authority-service identity (never UID 0 in production).
AUTHORITY_SERVICE_UID = 59901
AUTHORITY_SERVICE_GID = 59901

# Controller client peer when connecting to the authority socket.
AUTHORITY_CLIENT_PEER_UID = 59902
AUTHORITY_CLIENT_PEER_GID = 59902

# Shared socket group for distinct client/server UIDs (mode 0660).
AUTHORITY_SOCKET_GID = 59900

# Server-side operator key version; receipts must match, never drive lookup.
CURRENT_OPERATOR_KEY_VERSION = 1

# External Terra receipt attestation key version.  The version is encoded in
# the stored signature envelope so key rotation cannot silently reinterpret an
# old receipt.
CURRENT_TERRA_RECEIPT_KEY_VERSION = 1
