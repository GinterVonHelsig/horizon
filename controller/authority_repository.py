"""Authority-service-only persistence; never import from workflow/controller paths."""

from __future__ import annotations

import uuid
import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from psycopg2 import errors as pg_errors

from authority_pins import AUTHORITY_DATABASE_ROLE
from authority_socket_secrets import authority_write_signing_secret
from db import row_to_dict
from exceptions import AuthorizationFailureError, IntegrityFailureError
from longspan_crypto import hash_capability_token, sign_payload
from repository import PostgresRepository


def authority_content_digest(
    *,
    operation: str,
    run_id: str,
    terra_auth_hash: str,
    operator_auth_hash: str,
    reviewed_sha: str,
    tree_sha: str,
    source_digest: str,
    expected_config_version: int,
    config_version: int,
    approval_receipt_digest: str,
) -> str:
    """Hash the exact authority row payload with a SQL-compatible encoding.

    PostgreSQL migration 007 recomputes this digest from the values it is
    about to write.  A control character is used as a delimiter so the
    representation is unambiguous for the digest inputs used by this schema.
    """
    values = (
        operation,
        run_id,
        terra_auth_hash,
        operator_auth_hash,
        reviewed_sha,
        tree_sha,
        source_digest,
        str(expected_config_version),
        str(config_version),
        approval_receipt_digest,
    )
    if any("\x1f" in value for value in values):
        raise ValueError("authority content contains the reserved digest delimiter")
    return hashlib.sha256("\x1f".join(values).encode("utf-8")).hexdigest()


class AuthorityRepository:
    """Distinct DB role for authority writes; only used by authority_service_server."""

    def __init__(self, repo: PostgresRepository) -> None:
        self._repo = repo

    @classmethod
    def from_url(cls, db_url: str) -> "AuthorityRepository":
        return cls(PostgresRepository(db_url, connection_mode="authority"))

    def close(self) -> None:
        self._repo.close()

    def _assert_authority_database_role(self, cur: Any) -> None:
        cur.execute("SELECT current_user")
        row = cur.fetchone()
        if row is None:
            raise AuthorizationFailureError("authority database role could not be resolved")
        actual_role = row[0] if not isinstance(row, dict) else row["current_user"]
        if actual_role == AUTHORITY_DATABASE_ROLE:
            return
        raise AuthorizationFailureError(
            f"authority repository requires role {AUTHORITY_DATABASE_ROLE!r}, connected as {actual_role!r}"
        )

    def _assert_controller_epoch_readonly(self, cur: Any, run_id: str, controller_epoch: int) -> None:
        cur.execute(
            "SELECT current_epoch FROM controller_control WHERE run_id = %s",
            (run_id,),
        )
        row = cur.fetchone()
        if row is None or int(row["current_epoch"]) != controller_epoch:
            raise AuthorizationFailureError("stale controller epoch for authority write")

    def _assert_longspan_writes_allowed(self, cur: Any, run_id: str, controller_epoch: int) -> None:
        self._assert_authority_database_role(cur)
        self._assert_controller_epoch_readonly(cur, run_id, controller_epoch)

    def _issue_write_token(self, binding_digest: str) -> str:
        return sign_payload(binding_digest, authority_write_signing_secret())

    def bind_operator_write_credential(
        self,
        *,
        approval_id: str,
        write_binding_digest: str,
        write_credential_digest: str,
    ) -> None:
        raise AuthorizationFailureError(
            "write credential binding must occur atomically with authority writes"
        )

    def _lock_and_bind_operator_challenge(
        self,
        cur: Any,
        *,
        challenge: dict[str, Any],
        controller_epoch: int,
        run_id: str,
        write_token: str,
        write_binding_digest: str,
    ) -> None:
        self._assert_longspan_writes_allowed(cur, run_id, controller_epoch)
        cur.execute(
            """
            SELECT approval_id, run_id, action_type, action_digest, operator_identity,
                   nonce, expires_at, key_version, challenge_digest, consumed_at,
                   controller_epoch, config_version, write_binding_digest, challenge_epoch
            FROM longspan_operator_challenges
            WHERE approval_id = %s
            """,
            (challenge["approval_id"],),
        )
        row = cur.fetchone()
        if row is None:
            raise AuthorizationFailureError("operator challenge is unknown")
        row = row_to_dict(row)
        if row["consumed_at"] is not None:
            raise AuthorizationFailureError("operator challenge already consumed")
        if row["expires_at"] <= datetime.now(timezone.utc):
            raise AuthorizationFailureError("operator challenge expired")
        for field in (
            "run_id",
            "action_type",
            "action_digest",
            "operator_identity",
            "nonce",
            "key_version",
            "challenge_digest",
            "controller_epoch",
            "config_version",
            "challenge_epoch",
        ):
            expected = challenge[field]
            actual = row[field]
            if field in {"key_version", "controller_epoch", "config_version", "challenge_epoch"}:
                if int(actual) != int(expected):
                    raise AuthorizationFailureError(f"operator challenge {field} mismatch")
            elif actual != expected:
                raise AuthorizationFailureError(f"operator challenge {field} mismatch")
        if not write_binding_digest:
            raise AuthorizationFailureError("authority write content digest is required")
        expected_token = self._issue_write_token(write_binding_digest)
        if write_token != expected_token:
            raise AuthorizationFailureError("authority write credential is not verified")
        if row["write_binding_digest"] is not None:
            if row["write_binding_digest"] != write_binding_digest:
                raise AuthorizationFailureError("operator challenge write binding already diverged")

    def _consume_operator_challenge_locked(
        self,
        cur: Any,
        *,
        challenge: dict[str, Any],
        controller_epoch: int,
        run_id: str,
        write_binding_digest: str,
        write_token: str,
    ) -> None:
        cur.execute(
            """
            SELECT longspan_bind_and_consume_challenge(%s, %s, %s)
            """,
            (
                challenge["approval_id"],
                write_binding_digest,
                hash_capability_token(write_token),
            ),
        )

    def _append_authority_history_locked(
        self,
        cur: Any,
        *,
        run_id: str,
        config_version: int,
        terra_auth_hash: str,
        operator_auth_hash: str,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        approval_receipt_digest: str,
        approval_id: str,
        operator_identity: str,
        controller_epoch: int,
        challenge_epoch: int,
        receipt_id: str,
        action_digest: str,
        write_binding_digest: str,
    ) -> None:
        cur.execute(
            """
            SELECT longspan_append_authority_history(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                uuid.uuid4().hex,
                run_id,
                config_version,
                terra_auth_hash,
                operator_auth_hash,
                reviewed_sha,
                tree_sha,
                source_digest,
                approval_receipt_digest,
                approval_id,
                operator_identity,
                controller_epoch,
                challenge_epoch,
                receipt_id,
                action_digest,
                write_binding_digest,
            ),
        )

    def insert_authority_config(
        self,
        *,
        run_id: str,
        terra_auth_hash: str,
        operator_auth_hash: str,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        controller_epoch: int,
        approval_receipt_digest: str,
        approval_id: str,
        operator_identity: str,
        config_version: int,
        operator_challenge: dict[str, Any],
        write_token: str,
        write_binding_digest: str,
        receipt_id: str,
    ) -> dict[str, Any]:
        if not terra_auth_hash or not operator_auth_hash or not reviewed_sha:
            raise ValueError("authority hashes and reviewed_sha are required")
        if not tree_sha or not source_digest or not approval_receipt_digest:
            raise ValueError("tree_sha, source_digest, and approval receipt are required")
        try:
            with self._repo.transaction() as cur:
                self._lock_and_bind_operator_challenge(
                    cur,
                    challenge=operator_challenge,
                    controller_epoch=controller_epoch,
                    run_id=run_id,
                    write_token=write_token,
                    write_binding_digest=write_binding_digest,
                )
                self._consume_operator_challenge_locked(
                    cur,
                    challenge=operator_challenge,
                    controller_epoch=controller_epoch,
                    run_id=run_id,
                    write_binding_digest=write_binding_digest,
                    write_token=write_token,
                )
                self._assert_longspan_writes_allowed(cur, run_id, controller_epoch)
                cur.execute(
                    """
                    SELECT run_id, terra_auth_hash, operator_auth_hash, reviewed_sha,
                           tree_sha, source_digest, config_version,
                           approval_receipt_digest, updated_at
                    FROM longspan_insert_authority_config(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        run_id,
                        terra_auth_hash,
                        operator_auth_hash,
                        reviewed_sha,
                        tree_sha,
                        source_digest,
                        config_version,
                        approval_receipt_digest,
                        approval_id,
                        approval_receipt_digest,
                        write_binding_digest,
                    ),
                )
                row = cur.fetchone()
                if row is None:
                    raise AuthorizationFailureError("authority insert did not return a row")
                self._append_authority_history_locked(
                    cur,
                    run_id=run_id,
                    config_version=config_version,
                    terra_auth_hash=terra_auth_hash,
                    operator_auth_hash=operator_auth_hash,
                    reviewed_sha=reviewed_sha,
                    tree_sha=tree_sha,
                    source_digest=source_digest,
                    approval_receipt_digest=approval_receipt_digest,
                    approval_id=approval_id,
                    operator_identity=operator_identity,
                    controller_epoch=controller_epoch,
                    challenge_epoch=int(operator_challenge["challenge_epoch"]),
                    receipt_id=receipt_id,
                    action_digest=approval_receipt_digest,
                    write_binding_digest=write_binding_digest,
                )
                return row_to_dict(row)
        except pg_errors.UniqueViolation:
            raise AuthorizationFailureError("authority is already provisioned for run") from None

    def rotate_authority_config(
        self,
        *,
        run_id: str,
        terra_auth_hash: str,
        operator_auth_hash: str,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
        controller_epoch: int,
        expected_config_version: int,
        approval_receipt_digest: str,
        approval_id: str,
        operator_identity: str,
        operator_challenge: dict[str, Any],
        write_token: str,
        write_binding_digest: str,
        receipt_id: str,
    ) -> dict[str, Any]:
        if not approval_receipt_digest:
            raise ValueError("approval receipt digest is required for rotation")
        with self._repo.transaction() as cur:
            self._lock_and_bind_operator_challenge(
                cur,
                challenge=operator_challenge,
                controller_epoch=controller_epoch,
                run_id=run_id,
                write_token=write_token,
                write_binding_digest=write_binding_digest,
            )
            self._consume_operator_challenge_locked(
                cur,
                challenge=operator_challenge,
                controller_epoch=controller_epoch,
                run_id=run_id,
                write_binding_digest=write_binding_digest,
                write_token=write_token,
            )
            self._assert_longspan_writes_allowed(cur, run_id, controller_epoch)
            current = self._load_authority_config(cur, run_id)
            if int(current["config_version"]) != expected_config_version:
                raise AuthorizationFailureError("authority rotation version mismatch")
            next_version = expected_config_version + 1
            cur.execute(
                """
                SELECT run_id, terra_auth_hash, operator_auth_hash, reviewed_sha,
                       tree_sha, source_digest, config_version,
                       approval_receipt_digest, updated_at
                    FROM longspan_rotate_authority_config(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                """,
                (
                    run_id,
                    terra_auth_hash,
                    operator_auth_hash,
                    reviewed_sha,
                    tree_sha,
                    source_digest,
                    expected_config_version,
                    next_version,
                    approval_receipt_digest,
                    approval_id,
                    approval_receipt_digest,
                    write_binding_digest,
                ),
            )
            row = cur.fetchone()
            if row is None:
                raise AuthorizationFailureError("authority rotation version mismatch")
            self._append_authority_history_locked(
                cur,
                run_id=run_id,
                config_version=next_version,
                terra_auth_hash=terra_auth_hash,
                operator_auth_hash=operator_auth_hash,
                reviewed_sha=reviewed_sha,
                tree_sha=tree_sha,
                source_digest=source_digest,
                approval_receipt_digest=approval_receipt_digest,
                approval_id=approval_id,
                operator_identity=operator_identity,
                controller_epoch=controller_epoch,
                challenge_epoch=int(operator_challenge["challenge_epoch"]),
                receipt_id=receipt_id,
                action_digest=approval_receipt_digest,
                write_binding_digest=write_binding_digest,
            )
            return row_to_dict(row)

    def _load_authority_config(self, cur: Any, run_id: str) -> dict[str, Any]:
        cur.execute(
            """
            SELECT run_id, terra_auth_hash, operator_auth_hash, reviewed_sha,
                   tree_sha, source_digest, config_version, approval_receipt_digest
            FROM longspan_authority_config
            WHERE run_id = %s
            """,
            (run_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise AuthorizationFailureError("longspan authority is not provisioned for run")
        return row_to_dict(row)

    def get_authority_config(self, run_id: str) -> dict[str, Any]:
        with self._repo.transaction() as cur:
            return self._load_authority_config(cur, run_id)

    def issue_terra_receipt_attestation(
        self,
        *,
        receipt_payload: dict[str, Any],
        external_signature: str,
    ) -> str:
        """Ask PostgreSQL to issue a one-shot witness for a verified Terra receipt."""
        required = (
            "child_id", "attempt_number", "reviewer", "decision",
            "evidence_chain_head", "run_id", "task_id", "reviewed_sha",
            "fence_token", "controller_epoch", "tree_sha", "source_digest",
            "request_digest", "migration_head", "authority_version",
            "evidence_digest", "result_digest",
        )
        missing = [field for field in required if receipt_payload.get(field) is None]
        if missing:
            raise AuthorizationFailureError(
                "Terra attestation payload is missing: " + ", ".join(missing)
            )
        attestation_id = uuid.uuid4().hex
        with self._repo.transaction() as cur:
            self._assert_authority_database_role(cur)
            cur.execute(
                """
                SELECT longspan_issue_terra_receipt_attestation(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    attestation_id,
                    receipt_payload["child_id"],
                    int(receipt_payload["attempt_number"]),
                    receipt_payload["reviewer"],
                    receipt_payload["decision"],
                    receipt_payload["evidence_chain_head"],
                    None,
                    receipt_payload["run_id"],
                    receipt_payload["task_id"],
                    receipt_payload["reviewed_sha"],
                    int(receipt_payload["fence_token"]),
                    int(receipt_payload["controller_epoch"]),
                    receipt_payload["tree_sha"],
                    receipt_payload["source_digest"],
                    receipt_payload["request_digest"],
                    receipt_payload["migration_head"],
                    int(receipt_payload["authority_version"]),
                    receipt_payload["evidence_digest"],
                    receipt_payload["result_digest"],
                    external_signature,
                ),
            )
            row = cur.fetchone()
            if row is None or not row.get("longspan_issue_terra_receipt_attestation"):
                raise AuthorizationFailureError(
                    "authority database did not issue the Terra attestation"
                )
            return str(row["longspan_issue_terra_receipt_attestation"])

    def get_terra_receipt_gateway_mac(self, attestation_id: str) -> str:
        """Get the authority-only gateway proof for one unconsumed witness."""
        with self._repo.transaction() as cur:
            self._assert_authority_database_role(cur)
            cur.execute(
                "SELECT longspan_terra_gateway_mac_for_attestation(%s)",
                (attestation_id,),
            )
            row = cur.fetchone()
            if row is None or not row.get("longspan_terra_gateway_mac_for_attestation"):
                raise AuthorizationFailureError(
                    "authority database did not return the Terra gateway proof"
                )
            return str(row["longspan_terra_gateway_mac_for_attestation"])

    def verify_terra_receipt_attestation_binding(
        self,
        *,
        attestation_id: str,
        binding: dict[str, Any],
        signature_digest: str,
    ) -> None:
        """Bind a stored receipt envelope to its consumed database witness.

        The workflow may present an envelope, but it cannot choose which
        attestation that envelope claims.  Reload the append-only witness as
        the authority role and compare every receipt-bound field, including
        the consumed/non-invalidated lifecycle state.
        """
        if (
            not isinstance(attestation_id, str)
            or not attestation_id
            or not isinstance(signature_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", signature_digest)
        ):
            raise AuthorizationFailureError(
                "Terra receipt attestation binding is malformed"
            )
        fields = (
            "child_id", "attempt_number", "run_id", "task_id", "receipt_digest",
            "reviewer", "decision", "evidence_chain_head", "reviewed_sha",
            "fence_token", "controller_epoch", "tree_sha", "source_digest",
            "request_digest", "migration_head", "authority_version",
            "evidence_digest", "result_digest",
        )
        missing = [field for field in fields if binding.get(field) is None]
        if missing:
            raise AuthorizationFailureError(
                "Terra receipt attestation binding is missing: " + ", ".join(missing)
            )
        with self._repo.transaction() as cur:
            self._assert_authority_database_role(cur)
            cur.execute(
                """
                SELECT child_id, attempt_number, run_id, task_id, receipt_digest,
                       signature_digest, reviewer, decision, evidence_chain_head,
                       reviewed_sha, fence_token, controller_epoch, tree_sha,
                       source_digest, request_digest, migration_head,
                       authority_version, evidence_digest, result_digest,
                       consumed_at, invalidated_at
                FROM longspan_terra_receipt_attestations
                WHERE attestation_id = %s
                """,
                (attestation_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise AuthorizationFailureError(
                    "Terra receipt attestation is not bound to a persisted witness"
                )
            stored = row_to_dict(row)
            if stored.get("consumed_at") is None or stored.get("invalidated_at") is not None:
                raise AuthorizationFailureError(
                    "Terra receipt attestation is not in a valid consumed state"
                )
            for field in fields:
                expected = binding[field]
                actual = stored.get(field)
                if field in {"attempt_number", "fence_token", "controller_epoch", "authority_version"}:
                    expected = int(expected)
                    actual = int(actual)
                if actual != expected:
                    raise AuthorizationFailureError(
                        f"Terra receipt attestation {field} binding mismatch"
                    )
            if stored.get("signature_digest") != signature_digest:
                raise AuthorizationFailureError(
                    "Terra receipt attestation signature binding mismatch"
                )

    def invalidate_terra_receipt_attestation(
        self,
        *,
        attestation_id: str,
        run_id: str,
        child_id: str,
        attempt_number: int,
        signature_digest: str,
    ) -> None:
        """Invalidate one unconsumed witness after a failed workflow binding."""
        if (
            not isinstance(attestation_id, str)
            or not attestation_id.strip()
            or not isinstance(run_id, str)
            or not run_id.strip()
            or not isinstance(child_id, str)
            or not child_id.strip()
            or type(attempt_number) is not int
            or attempt_number < 0
            or not isinstance(signature_digest, str)
            or len(signature_digest) != 64
            or any(character not in "0123456789abcdef" for character in signature_digest)
        ):
            raise AuthorizationFailureError(
                "Terra attestation invalidation requires the bound signature digest"
            )
        with self._repo.transaction() as cur:
            self._assert_authority_database_role(cur)
            cur.execute(
                "SELECT longspan_invalidate_terra_receipt_attestation(%s, %s, %s, %s, %s)",
                (attestation_id, run_id, child_id, attempt_number, signature_digest),
            )
