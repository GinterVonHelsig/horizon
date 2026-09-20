"""Authority service server: sole issuer of authority-table writes and write credentials."""

from __future__ import annotations

import json
import hashlib
import hmac
import logging
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from authority_pins import (
    ADMIN_DATABASE_ROLES,
    AUTHORITY_DATABASE_ROLE,
    AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
    AUTHORITY_SOCKET_PATH,
    CURRENT_OPERATOR_KEY_VERSION,
    MIGRATION_DATABASE_ROLE,
)
from authority_repository import AuthorityRepository, authority_content_digest
from authority_service_client import (
    AUTHORITY_SOCKET_TIMEOUT_SECONDS,
    peer_credentials,
    verify_authority_client_peer,
    verify_authority_server_peer,
)
from authority_socket_framing import MAX_FRAME_BYTES, recv_framed, send_framed
from authority_socket_path import chown_authority_socket, verify_authority_socket_path
from authority_test_seam import reject_runtime_test_seam_use
from attestation import (
    COMMS01_DATABASE_ENDPOINTS,
    COMMS01_DATABASE_NAME,
    load_comms01_attestation,
)
from comms01_scope import assert_effective_libpq_target
from comms01_authority import ExternalOperatorApprovalReceipt
from comms01_operation_policy import assert_comms01_operation
from comms01_authority_secrets import operator_verification_key
from db import CANONICAL_ALEMBIC_HEAD, current_database_revision
from disposable_capability import (
    DOWNGRADE_CAPABILITY_OPERATIONS,
    load_signed_disposable_capability,
)
from authority_socket_request import (
    SOCKET_REQUEST_TTL_SECONDS,
    bind_socket_response,
    validate_socket_request_envelope,
)
from exceptions import AuthorizationFailureError
from longspan_crypto import digest_payload, hash_capability_token, verify_capability_hash
from operator_asymmetric import challenge_signing_message, verify_message_signature
from pinned_trust import read_json_file
from provenance import capture_run_provenance, reject_provenance_drift
from ledger_mac import require_ledger_mac_key
from terra_gateway_mac import require_terra_gateway_mac_key
from terra_receipt_attestation import (
    terra_receipt_database_digest,
    terra_receipt_signature_components,
    verify_terra_receipt_signature,
)


logger = logging.getLogger(__name__)


def load_authority_service_database_target() -> dict[str, str | int]:
    payload = read_json_file(
        AUTHORITY_SERVICE_DATABASE_TARGET_PATH,
        strict_owner=True,
        require_root_owner=True,
    )
    required = (
        "database_url",
        "database_name",
        "database_role",
        "database_endpoint",
        "database_port",
    )
    missing = [field for field in required if not payload.get(field)]
    if missing:
        raise AuthorizationFailureError(
            f"authority service target missing fields: {', '.join(missing)}"
        )
    if str(payload["database_role"]) != AUTHORITY_DATABASE_ROLE:
        raise AuthorizationFailureError(
            "authority service target role must be the authority LOGIN principal"
        )
    database_name = str(payload["database_name"])
    endpoint = str(payload["database_endpoint"]).lower()
    parsed = urlsplit(str(payload["database_url"]))
    try:
        database_port = int(payload["database_port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorizationFailureError("authority service target port is invalid") from exc
    if not 1 <= database_port <= 65535:
        raise AuthorizationFailureError("authority service target port is outside valid range")
    if parsed.port != database_port:
        raise AuthorizationFailureError(
            "authority service target URL/port does not match pinned database_port"
        )
    assert_effective_libpq_target(str(payload["database_url"]))
    if database_name != COMMS01_DATABASE_NAME and not database_name.startswith(
        ("td_test_", "td_downgrade_")
    ):
        raise AuthorizationFailureError(
            "authority service target database is outside the Comms-01 control boundary"
        )
    if parsed.path.lstrip("/") != database_name:
        raise AuthorizationFailureError(
            "authority service target URL/database name mismatch"
        )
    if parsed.username != AUTHORITY_DATABASE_ROLE:
        raise AuthorizationFailureError(
            "authority service target URL/role mismatch"
        )
    if endpoint not in COMMS01_DATABASE_ENDPOINTS:
        raise AuthorizationFailureError(
            "authority service target endpoint is outside the Comms-01 allowlist"
        )
    if not parsed.hostname:
        raise AuthorizationFailureError(
            "authority service target URL must include an explicit pinned host"
        )
    if (parsed.hostname or "").lower() not in COMMS01_DATABASE_ENDPOINTS:
        raise AuthorizationFailureError(
            "authority service target URL host is outside the local Comms-01 endpoint"
        )
    return {
        "database_url": str(payload["database_url"]),
        "database_name": database_name,
        "database_role": str(payload["database_role"]),
        "database_endpoint": endpoint,
        "database_port": database_port,
        "authority_service": str(
            payload.get("authority_service") or "top-delivery-authority-service"
        ),
    }


class AuthorityServiceServer:
    SOCKET_REPLAY_CACHE_MAX = 4096
    SOCKET_REPLAY_CACHE_MAX_PER_PEER = 256

    def __init__(self, *, repo_root: Path, db_url: str | None = None) -> None:
        if db_url is not None:
            raise AuthorizationFailureError(
                "caller-supplied db_url is rejected; load pinned authority service target"
            )
        target = load_authority_service_database_target()
        self._db_url = target["database_url"]
        self._target = target
        self._repo = AuthorityRepository.from_url(self._db_url)
        self._repo_root = repo_root
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None
        # Replay protection must not become an unbounded process-memory leak.
        # Expiry is taken from the validated request envelope, and the hard
        # ceiling fails closed rather than evicting a still-live request.
        self._seen_socket_requests: dict[str, datetime] = {}
        self._socket_request_owners: dict[str, tuple[int, int]] = {}
        self._socket_peer_counts: dict[tuple[int, int], int] = {}
        self._socket_request_lock = threading.Lock()

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        self._repo.close()

    def start(self) -> None:
        reject_runtime_test_seam_use()
        socket_path = verify_authority_socket_path(AUTHORITY_SOCKET_PATH)
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        if socket_path.exists():
            socket_path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(socket_path))
        # Distinct client UID must connect: group-readable/writable, not world.
        socket_path.chmod(0o660)
        chown_authority_socket(socket_path)
        sock.listen(5)
        self._socket = sock
        self._thread = threading.Thread(target=self._serve, args=(sock,), daemon=True)
        self._thread.start()

    def _consume_socket_request(
        self,
        payload: dict[str, Any],
        *,
        peer_identity: tuple[int, ...] | None = None,
    ) -> dict[str, Any]:
        request_id = validate_socket_request_envelope(payload)
        if peer_identity is None:
            raise AuthorizationFailureError(
                "authority socket peer identity is required for replay admission"
            )
        if len(peer_identity) == 3:
            # Admission is per approved principal, not per process.  A
            # respawned PID must not bypass the per-peer replay quota.
            peer_key: tuple[int, int] = (
                int(peer_identity[1]),
                int(peer_identity[2]),
            )
        elif peer_identity and len(peer_identity) == 2:
            peer_key = (int(peer_identity[0]), int(peer_identity[1]))
        else:
            raise AuthorizationFailureError(
                "authority socket peer identity must contain uid and gid"
            )
        try:
            expires_at = datetime.fromisoformat(str(payload["socket_expires_at"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationFailureError(
                "authority socket request expiry is malformed"
            ) from exc
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        with self._socket_request_lock:
            # Take the time sample only after acquiring the replay lock. An
            # earlier sample could become stale while waiting for contention,
            # allowing an expired request to enter the cache.
            now = datetime.now(timezone.utc)
            if expires_at <= now:
                raise AuthorizationFailureError("authority socket request expired")
            if expires_at > now + timedelta(seconds=SOCKET_REQUEST_TTL_SECONDS):
                raise AuthorizationFailureError(
                    "authority socket request TTL exceeds server bound"
                )
            expired = [
                seen_id
                for seen_id, seen_expiry in self._seen_socket_requests.items()
                if seen_expiry <= now
            ]
            expired_owners: dict[str, tuple[int, int]] = {}
            expired_counts: dict[tuple[int, int], int] = {}
            for seen_id in expired:
                owner = self._socket_request_owners.get(seen_id)
                if (
                    not isinstance(owner, tuple)
                    or len(owner) != 2
                    or any(isinstance(value, bool) or not isinstance(value, int) for value in owner)
                ):
                    raise AuthorizationFailureError(
                        "authority socket replay accounting is inconsistent"
                    )
                expired_owners[seen_id] = owner
                expired_counts[owner] = expired_counts.get(owner, 0) + 1
            for owner, expired_count in expired_counts.items():
                owner_count = self._socket_peer_counts.get(owner)
                if (
                    isinstance(owner_count, bool)
                    or not isinstance(owner_count, int)
                    or owner_count < expired_count
                ):
                    raise AuthorizationFailureError(
                        "authority socket replay accounting is inconsistent"
                    )
            # Validate every owner before mutating either map.  A corrupt
            # entry therefore fails closed without leaving a half-evicted
            # replay cache that could miscount a peer's quota.
            for seen_id, owner in expired_owners.items():
                self._seen_socket_requests.pop(seen_id, None)
                self._socket_request_owners.pop(seen_id, None)
                remaining = self._socket_peer_counts[owner] - 1
                if remaining:
                    self._socket_peer_counts[owner] = remaining
                else:
                    self._socket_peer_counts.pop(owner, None)
            if request_id in self._seen_socket_requests:
                raise AuthorizationFailureError("authority socket request replay detected")
            counts = self._socket_peer_counts
            owners = self._socket_request_owners
            if counts.get(peer_key, 0) >= self.SOCKET_REPLAY_CACHE_MAX_PER_PEER:
                raise AuthorizationFailureError(
                    "authority socket replay quota is full for this peer"
                )
            if len(self._seen_socket_requests) >= self.SOCKET_REPLAY_CACHE_MAX:
                raise AuthorizationFailureError(
                    "authority socket replay cache is full; wait for request expiry"
                )
            self._seen_socket_requests[request_id] = expires_at
            owners[request_id] = peer_key
            counts[peer_key] = counts.get(peer_key, 0) + 1
            self._socket_peer_counts = counts
        return payload

    def _serve(self, sock: socket.socket) -> None:
        while True:
            try:
                conn, _addr = sock.accept()
            except OSError:
                return
            with conn:
                request_payload: dict[str, Any] | None = None
                try:
                    # The client-side timeout is not sufficient: an approved
                    # peer can connect and send only a partial frame.  Bound
                    # the server-side read before any framing or database
                    # work so the single accept loop remains available.
                    conn.settimeout(AUTHORITY_SOCKET_TIMEOUT_SECONDS)
                    verify_authority_client_peer(conn)
                    _pid, uid, gid = peer_credentials(conn)
                    payload = json.loads(
                        recv_framed(
                            conn,
                            deadline=time.monotonic() + AUTHORITY_SOCKET_TIMEOUT_SECONDS,
                        ).decode("utf-8")
                    )
                    request_payload = self._consume_socket_request(
                        payload, peer_identity=(uid, gid)
                    )
                    response = bind_socket_response(
                        request=request_payload,
                        response=self._handle(payload),
                    )
                except Exception as exc:
                    response = {"status": "error", "error": str(exc)[:512]}
                    if request_payload is not None:
                        response = bind_socket_response(request=request_payload, response=response)
                try:
                    encoded_response = json.dumps(response, sort_keys=True).encode("utf-8")
                    if len(encoded_response) > MAX_FRAME_BYTES:
                        encoded_response = json.dumps(
                            {
                                "status": "error",
                                "error": "authority response exceeded frame limit",
                            },
                            sort_keys=True,
                        ).encode("utf-8")
                    send_framed(
                        conn,
                        encoded_response,
                        deadline=time.monotonic() + AUTHORITY_SOCKET_TIMEOUT_SECONDS,
                    )
                except (OSError, socket.timeout, ValueError):
                    # A timed-out or already-closed peer must not terminate
                    # the service loop or prevent the next approved peer.
                    logger.warning("authority socket response could not be delivered")
                    continue

    def _verify_server_runtime(self) -> None:
        from comms01_scope import is_disposable_test_database, verify_connection_identity

        attestation = load_comms01_attestation()
        actual_database, actual_role = verify_connection_identity(
            database_url=self._db_url,
            connection=self._repo._repo._conn,
            expected_role=AUTHORITY_DATABASE_ROLE,
        )
        if actual_role != AUTHORITY_DATABASE_ROLE:
            raise AuthorizationFailureError(
                f"authority service requires role {AUTHORITY_DATABASE_ROLE!r}, connected as {actual_role!r}"
            )
        disposable = is_disposable_test_database(self._db_url)
        if disposable:
            harness = load_signed_disposable_capability()
            if harness is None:
                raise AuthorizationFailureError(
                    "authority service disposable database requires harness capability"
                )
            if harness.database_name != actual_database:
                raise AuthorizationFailureError(
                    "authority service disposable capability database does not match connected target"
                )
            if harness.database_endpoint.lower() != str(
                self._target["database_endpoint"]
            ).lower():
                raise AuthorizationFailureError(
                    "authority service disposable capability endpoint does not match connected target"
                )
            if int(harness.database_port) != int(self._target["database_port"]):
                raise AuthorizationFailureError(
                    "authority service disposable capability port does not match connected target"
                )
            expected_capability_roles = (
                {MIGRATION_DATABASE_ROLE}
                if harness.operation in DOWNGRADE_CAPABILITY_OPERATIONS
                else ADMIN_DATABASE_ROLES
            )
            if harness.database_role not in expected_capability_roles:
                raise AuthorizationFailureError(
                    "authority service disposable capability role is not authorized for its operation"
                )
        else:
            if self._target["database_name"] != attestation.database_name:
                raise AuthorizationFailureError(
                    "authority service target database is not bound to attestation"
                )
            if self._target["database_endpoint"].lower() != attestation.database_endpoint.lower():
                raise AuthorizationFailureError(
                    "authority service target endpoint is not bound to attestation"
                )
            if int(self._target["database_port"]) != attestation.database_port:
                raise AuthorizationFailureError(
                    "authority service target port is not bound to attestation"
                )
            if self._target["database_role"] != attestation.authority_database_role:
                raise AuthorizationFailureError(
                    "authority service target role is not bound to attestation"
                )
            if actual_database != attestation.database_name:
                raise AuthorizationFailureError(
                    "authority service database target does not match attestation"
                )
            if actual_role != attestation.authority_database_role:
                raise AuthorizationFailureError(
                    "authority service database role does not match attestation"
                )
            if attestation.authority_service != self._target["authority_service"]:
                raise AuthorizationFailureError("authority service identity mismatch")
        revision = current_database_revision(self._db_url, connection_mode="authority")
        if revision != CANONICAL_ALEMBIC_HEAD:
            raise AuthorizationFailureError(
                f"authority service requires migration head {CANONICAL_ALEMBIC_HEAD!r}"
            )
        url_database = urlsplit(self._db_url).path.lstrip("/")
        if url_database != actual_database or url_database != self._target["database_name"]:
            raise AuthorizationFailureError("authority service db target mismatch")
        ledger_key = require_ledger_mac_key()
        gateway_key = require_terra_gateway_mac_key()
        with self._repo._repo._conn.cursor() as cur:
            cur.execute("SELECT longspan_install_ledger_mac_key(%s)", (ledger_key,))
            cur.execute(
                "SELECT longspan_install_terra_gateway_mac_key(%s)",
                (gateway_key,),
            )
        self._repo._repo._conn.commit()

    def _capture_and_reject_provenance_drift(
        self,
        *,
        reviewed_sha: str,
        tree_sha: str,
        source_digest: str,
    ) -> None:
        captured = capture_run_provenance(
            self._repo_root,
            reviewed_sha=reviewed_sha,
            db_url=self._db_url,
            connection_mode="authority",
        )
        reject_provenance_drift(
            captured=captured,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            migration_revision=captured.migration_revision,
        )

    def _verify_operator_receipt(
        self,
        receipt: dict[str, Any],
        *,
        expected: dict[str, Any],
        challenge_epoch: int,
    ) -> None:
        for field, value in expected.items():
            if receipt.get(field) != value:
                raise AuthorizationFailureError(f"operator approval binding mismatch for {field}")
        if int(receipt["key_version"]) != CURRENT_OPERATOR_KEY_VERSION:
            raise AuthorizationFailureError("operator approval key version mismatch")
        payload = {
            "approval_id": receipt["approval_id"],
            "operator_identity": receipt["operator_identity"],
            "action_type": receipt["action_type"],
            "action_digest": receipt["action_digest"],
            "run_id": receipt["run_id"],
            "nonce": receipt["nonce"],
            "expires_at": receipt["expires_at"],
            "key_version": CURRENT_OPERATOR_KEY_VERSION,
            "controller_epoch": int(receipt["controller_epoch"]),
            "config_version": int(receipt["config_version"]),
            "challenge_epoch": challenge_epoch,
        }
        signing_message = challenge_signing_message(payload)
        public_key = operator_verification_key(key_version=CURRENT_OPERATOR_KEY_VERSION)
        if not verify_message_signature(signing_message, receipt["signature"], public_key):
            raise AuthorizationFailureError("operator approval signature is invalid")

    def _reject_substituted_db_url(self, payload: dict[str, Any]) -> None:
        if "db_url" in payload:
            raise AuthorizationFailureError("authority socket payload must not include db_url")

    def _handle(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._reject_substituted_db_url(payload)
        operation = payload.get("operation")
        if operation == "initial_provision":
            return self._handle_initial_provision(payload)
        if operation == "rotate_authority":
            return self._handle_rotate_authority(payload)
        if operation == "terra_receipt_attestation":
            return self._handle_terra_receipt_attestation(payload)
        if operation == "verify_terra_receipt_binding":
            return self._handle_verify_terra_receipt_binding(payload)
        if operation == "invalidate_terra_receipt_attestation":
            return self._handle_invalidate_terra_receipt_attestation(payload)
        raise AuthorizationFailureError(f"unsupported authority operation: {operation}")

    def _handle_terra_receipt_attestation(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Verify Terra externally, then ask the authority DB to bind one witness."""
        self._verify_server_runtime()
        receipt_payload = payload.get("receipt_payload")
        external_signature = payload.get("external_signature")
        if not isinstance(receipt_payload, dict) or not isinstance(external_signature, str):
            raise AuthorizationFailureError("Terra attestation request is malformed")
        if external_signature.count(":") != 1:
            raise AuthorizationFailureError(
                "Terra attestation requires the unbound external signature envelope"
            )
        if not verify_terra_receipt_signature(receipt_payload, external_signature):
            raise AuthorizationFailureError("Terra external signature is invalid")
        attestation_id = self._repo.issue_terra_receipt_attestation(
            receipt_payload=receipt_payload,
            external_signature=external_signature,
        )
        try:
            gateway_mac = self._repo.get_terra_receipt_gateway_mac(attestation_id)
        except Exception:
            self._repo.invalidate_terra_receipt_attestation(
                attestation_id=attestation_id,
                run_id=str(receipt_payload["run_id"]),
                child_id=str(receipt_payload["child_id"]),
                attempt_number=int(receipt_payload["attempt_number"]),
                signature_digest=hashlib.sha256(
                    external_signature.split(":", 1)[1].encode("utf-8")
                ).hexdigest(),
            )
            raise
        return {
            "status": "ok",
            "attestation_id": attestation_id,
            "gateway_mac": gateway_mac,
        }

    def _handle_verify_terra_receipt_binding(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Recheck a stored receipt without exposing authority MAC material."""
        self._verify_server_runtime()
        receipt = payload.get("receipt")
        authority_signature = payload.get("authority_signature")
        if not isinstance(receipt, dict) or not isinstance(authority_signature, str):
            raise AuthorizationFailureError(
                "Terra receipt binding verification request is malformed"
            )
        if not verify_terra_receipt_signature(receipt, authority_signature):
            raise AuthorizationFailureError(
                "Terra receipt binding external signature is invalid"
            )
        components = terra_receipt_signature_components(authority_signature)
        if components is None:
            raise AuthorizationFailureError(
                "Terra receipt binding gateway MAC or attestation id is invalid"
            )
        _external_signature, stored_gateway_mac, attestation_id = components
        receipt_digest = terra_receipt_database_digest(receipt)
        persisted_receipt_digest = receipt.get("receipt_digest")
        if persisted_receipt_digest != receipt_digest:
            raise AuthorizationFailureError(
                "Terra receipt binding digest is not the persisted database digest"
            )
        self._repo.verify_terra_receipt_attestation_binding(
            attestation_id=attestation_id,
            binding=receipt,
            signature_digest=hashlib.sha256(
                _external_signature.split(":", 1)[1].encode("utf-8")
            ).hexdigest(),
        )
        expected_gateway_mac = hmac.new(
            require_terra_gateway_mac_key().encode("utf-8"),
            f"top_delivery:terra_receipt:v1:{receipt_digest}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(stored_gateway_mac, expected_gateway_mac):
            raise AuthorizationFailureError(
                "Terra receipt binding gateway MAC does not match the database digest"
            )
        # The append routine has already consumed this one-shot witness under
        # the authority role and the receipt table is append-only.  The
        # authority boundary therefore revalidates the persisted digest/MAC
        # envelope here without giving the workflow process the MAC key.
        return {
            "status": "ok",
            "verified": True,
            "attestation_id": attestation_id,
            "receipt_digest": receipt_digest,
        }

    def _handle_invalidate_terra_receipt_attestation(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Retire a witness that could not reach the fenced append transaction."""
        self._verify_server_runtime()
        attestation_id = payload.get("attestation_id")
        run_id = payload.get("run_id")
        child_id = payload.get("child_id")
        attempt_number = payload.get("attempt_number")
        signature_digest = payload.get("signature_digest")
        if (
            not isinstance(attestation_id, str)
            or not attestation_id
            or not isinstance(run_id, str)
            or not run_id
            or not isinstance(child_id, str)
            or not child_id
            or type(attempt_number) is not int
            or attempt_number < 0
            or not isinstance(signature_digest, str)
            or len(signature_digest) != 64
            or any(character not in "0123456789abcdef" for character in signature_digest)
        ):
            raise AuthorizationFailureError(
                "Terra attestation invalidation requires the bound signature digest"
            )
        self._repo.invalidate_terra_receipt_attestation(
            attestation_id=attestation_id,
            run_id=run_id,
            child_id=child_id,
            attempt_number=attempt_number,
            signature_digest=signature_digest,
        )
        return {"status": "ok", "invalidated": True}

    def _handle_initial_provision(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._verify_server_runtime()
        run_id = payload["run_id"]
        reviewed_sha = payload["reviewed_sha"]
        tree_sha = payload["tree_sha"]
        source_digest = payload["source_digest"]
        controller_epoch = int(payload["controller_epoch"])
        operator_identity = payload["operator_identity"]
        terra_auth_token = payload["terra_auth_token"]
        operator_auth_token = payload["operator_auth_token"]
        receipt = payload["operator_approval_receipt"]
        challenge = payload["operator_challenge"]
        self._capture_and_reject_provenance_drift(
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
        )
        action_digest = digest_payload(
            {
                "action": "initial_provision",
                "run_id": run_id,
                "operator_identity": operator_identity,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "controller_epoch": controller_epoch,
                "config_version": 1,
                "terra_auth_hash": hash_capability_token(terra_auth_token),
                "operator_auth_hash": hash_capability_token(operator_auth_token),
            }
        )
        self._verify_operator_receipt(
            receipt,
            expected={
                "action_type": "initial_provision",
                "action_digest": action_digest,
                "run_id": run_id,
                "operator_identity": operator_identity,
                "controller_epoch": controller_epoch,
                "config_version": 1,
            },
            challenge_epoch=int(challenge["challenge_epoch"]),
        )
        # Initial authority establishment is a real Comms-01 side effect, not
        # merely a cryptographic check. Re-run the technical scope contract
        # against the same receipt and target payload used for the write, so a
        # caller cannot use the first provision to bypass host/service scope.
        assert_comms01_operation(
            operation="authority-provision",
            database_url=self._db_url,
            service_name=str(self._target["authority_service"]),
            operator_approval_receipt=ExternalOperatorApprovalReceipt(**receipt),
            rotation_target={
                "run_id": run_id,
                "operator_identity": operator_identity,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "controller_epoch": controller_epoch,
                "config_version": 1,
                "challenge_epoch": int(challenge["challenge_epoch"]),
                "terra_auth_token": terra_auth_token,
                "operator_auth_token": operator_auth_token,
            },
        )
        terra_auth_hash = hash_capability_token(terra_auth_token)
        operator_auth_hash = hash_capability_token(operator_auth_token)
        binding_digest = authority_content_digest(
            operation="initial_provision",
            run_id=run_id,
            terra_auth_hash=terra_auth_hash,
            operator_auth_hash=operator_auth_hash,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            expected_config_version=0,
            config_version=1,
            approval_receipt_digest=action_digest,
        )
        write_token = self._repo._issue_write_token(binding_digest)
        receipt_id = uuid.uuid4().hex
        row = self._repo.insert_authority_config(
            run_id=run_id,
            terra_auth_hash=terra_auth_hash,
            operator_auth_hash=operator_auth_hash,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            controller_epoch=controller_epoch,
            approval_receipt_digest=action_digest,
            approval_id=receipt["approval_id"],
            operator_identity=operator_identity,
            config_version=1,
            operator_challenge=challenge,
            write_token=write_token,
            write_binding_digest=binding_digest,
            receipt_id=receipt_id,
        )
        result_digest = digest_payload(
            {
                "receipt_id": receipt_id,
                "run_id": run_id,
                "action_type": "initial_provision",
                "config_version": int(row["config_version"]),
                "approval_id": receipt["approval_id"],
            }
        )
        return {
            "status": "ok",
            "receipt": {
                "receipt_id": receipt_id,
                "run_id": run_id,
                "action_type": "initial_provision",
                "config_version": int(row["config_version"]),
                "result_digest": result_digest,
                "approval_id": receipt["approval_id"],
            },
        }

    def _handle_rotate_authority(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._verify_server_runtime()
        run_id = payload["run_id"]
        reviewed_sha = payload["reviewed_sha"]
        tree_sha = payload["tree_sha"]
        source_digest = payload["source_digest"]
        controller_epoch = int(payload["controller_epoch"])
        operator_identity = payload["operator_identity"]
        existing_operator_auth_token = payload["existing_operator_auth_token"]
        new_terra_auth_token = payload["new_terra_auth_token"]
        new_operator_auth_token = payload["new_operator_auth_token"]
        receipt = payload["operator_approval_receipt"]
        challenge = payload["operator_challenge"]
        self._capture_and_reject_provenance_drift(
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
        )
        current = self._repo.get_authority_config(run_id)
        next_version = int(current["config_version"]) + 1
        if not verify_capability_hash(
            existing_operator_auth_token, current["operator_auth_hash"]
        ):
            raise AuthorizationFailureError("operator auth token is not verified for rotation")
        action_digest = digest_payload(
            {
                "action": "rotate_authority",
                "run_id": run_id,
                "operator_identity": operator_identity,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "controller_epoch": controller_epoch,
                "config_version": next_version,
                "terra_auth_hash": hash_capability_token(new_terra_auth_token),
                "operator_auth_hash": hash_capability_token(new_operator_auth_token),
            }
        )
        self._verify_operator_receipt(
            receipt,
            expected={
                "action_type": "rotate_authority",
                "action_digest": action_digest,
                "run_id": run_id,
                "operator_identity": operator_identity,
                "controller_epoch": controller_epoch,
                "config_version": next_version,
            },
            challenge_epoch=int(challenge["challenge_epoch"]),
        )
        # The authority socket is the real rotation entry point.  Re-run the
        # technical Comms-01 operation contract here, after the cryptographic
        # receipt has been checked, so policy is not merely a standalone test
        # helper that callers can forget to invoke.
        assert_comms01_operation(
            operation="authority-rotate",
            database_url=self._db_url,
            service_name=str(self._target["authority_service"]),
            operator_approval_receipt=ExternalOperatorApprovalReceipt(**receipt),
            rotation_target={
                "run_id": run_id,
                "operator_identity": operator_identity,
                "reviewed_sha": reviewed_sha,
                "tree_sha": tree_sha,
                "source_digest": source_digest,
                "controller_epoch": controller_epoch,
                "config_version": next_version,
                "challenge_epoch": int(challenge["challenge_epoch"]),
                "new_terra_auth_token": new_terra_auth_token,
                "new_operator_auth_token": new_operator_auth_token,
            },
        )
        terra_auth_hash = hash_capability_token(new_terra_auth_token)
        operator_auth_hash = hash_capability_token(new_operator_auth_token)
        binding_digest = authority_content_digest(
            operation="rotate_authority",
            run_id=run_id,
            terra_auth_hash=terra_auth_hash,
            operator_auth_hash=operator_auth_hash,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            expected_config_version=int(current["config_version"]),
            config_version=next_version,
            approval_receipt_digest=action_digest,
        )
        write_token = self._repo._issue_write_token(binding_digest)
        receipt_id = uuid.uuid4().hex
        row = self._repo.rotate_authority_config(
            run_id=run_id,
            terra_auth_hash=terra_auth_hash,
            operator_auth_hash=operator_auth_hash,
            reviewed_sha=reviewed_sha,
            tree_sha=tree_sha,
            source_digest=source_digest,
            controller_epoch=controller_epoch,
            expected_config_version=int(current["config_version"]),
            approval_receipt_digest=action_digest,
            approval_id=receipt["approval_id"],
            operator_identity=operator_identity,
            operator_challenge=challenge,
            write_token=write_token,
            write_binding_digest=binding_digest,
            receipt_id=receipt_id,
        )
        result_digest = digest_payload(
            {
                "receipt_id": receipt_id,
                "run_id": run_id,
                "action_type": "rotate_authority",
                "config_version": int(row["config_version"]),
                "approval_id": receipt["approval_id"],
            }
        )
        return {
            "status": "ok",
            "receipt": {
                "receipt_id": receipt_id,
                "run_id": run_id,
                "action_type": "rotate_authority",
                "config_version": int(row["config_version"]),
                "result_digest": result_digest,
                "approval_id": receipt["approval_id"],
            },
        }


def start_authority_service(*, repo_root: Path, db_url: str | None = None) -> AuthorityServiceServer:
    if db_url is not None:
        raise AuthorizationFailureError(
            "caller-supplied db_url is rejected; load pinned authority service target"
        )
    server = AuthorityServiceServer(repo_root=repo_root)
    server.start()
    return server
