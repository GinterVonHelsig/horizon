"""Authority service client over the pinned Unix socket."""

from __future__ import annotations

import json
import errno
import re
import socket
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from authority_pins import (
    AUTHORITY_CLIENT_PEER_UID,
    AUTHORITY_SERVICE_GID,
    AUTHORITY_SERVICE_UID,
    AUTHORITY_SOCKET_PATH,
)
from authority_socket_framing import recv_framed, send_framed
from authority_socket_path import verify_authority_socket_path
from authority_socket_request import build_socket_request_envelope
from exceptions import (
    AuthorityServiceCapacityError,
    AuthorityServiceUnavailableError,
    AuthorizationFailureError,
    ControlPlaneError,
)
from longspan_crypto import digest_payload


AUTHORITY_SOCKET_TIMEOUT_SECONDS = 30.0
_TRANSIENT_PEER_CREDENTIAL_ERRNOS = frozenset(
    {
        errno.EBADF,
        errno.ECONNRESET,
        errno.ENOTCONN,
        errno.ENOTSOCK,
        errno.EPIPE,
        errno.ESHUTDOWN,
    }
)


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"authority socket payload value is not JSON serializable: {type(value)!r}")


@dataclass(frozen=True)
class AuthorityServiceReceipt:
    receipt_id: str
    run_id: str
    action_type: str
    config_version: int
    result_digest: str
    approval_id: str | None = None


def peer_credentials(sock: socket.socket) -> tuple[int, int, int]:
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    except OSError as exc:
        if exc.errno in _TRANSIENT_PEER_CREDENTIAL_ERRNOS:
            raise AuthorityServiceUnavailableError(
                "authority socket peer credentials are temporarily unavailable"
            ) from exc
        raise AuthorizationFailureError("authority socket peer credentials unavailable") from exc
    return struct.unpack("3i", creds)


def verify_authority_client_peer(sock: socket.socket) -> None:
    """Server-side: client must be the approved controller UID."""
    from authority_socket_path import verify_authority_socket_peer as _verify_peer

    _pid, uid, gid = peer_credentials(sock)
    _verify_peer(uid, gid)


def verify_authority_server_peer(sock: socket.socket) -> None:
    """Client-side: server must be the pinned authority service UID/GID."""
    from authority_test_seam import allowed_test_owner_uids

    _pid, uid, gid = peer_credentials(sock)
    allowed_uids = {AUTHORITY_SERVICE_UID, *allowed_test_owner_uids()}
    allowed_gids = {AUTHORITY_SERVICE_GID, *allowed_test_owner_uids()}
    if uid not in allowed_uids:
        raise AuthorizationFailureError("authority server peer UID is not authorized")
    if gid not in allowed_gids and gid not in allowed_test_owner_uids():
        raise AuthorizationFailureError("authority server peer GID is not authorized")


def _request(payload: dict[str, Any]) -> dict[str, Any]:
    if "db_url" in payload:
        raise AuthorizationFailureError("authority socket payload must not include db_url")
    envelope = build_socket_request_envelope()
    request_payload = {**payload, **envelope}
    socket_path = verify_authority_socket_path(AUTHORITY_SOCKET_PATH)
    if not socket_path.exists():
        raise AuthorityServiceUnavailableError("authority socket is unavailable")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(AUTHORITY_SOCKET_TIMEOUT_SECONDS)
            client.connect(str(socket_path))
            verify_authority_server_peer(client)
            encoded = json.dumps(
                request_payload, sort_keys=True, default=_json_default
            ).encode("utf-8")
            send_framed(client, encoded)
            response = recv_framed(client)
    except ControlPlaneError:
        # Peer identity, framing policy, and other control-plane failures are
        # not transport outages. Preserve their fail-closed classification;
        # in particular, never retry an unauthorized authority peer.
        raise
    except (socket.timeout, ConnectionError, OSError) as exc:
        raise AuthorityServiceUnavailableError(
            "authority service transport is temporarily unavailable"
        ) from exc
    document = json.loads(response.decode("utf-8"))
    for field in ("socket_request_id", "socket_nonce", "socket_expires_at"):
        if document.get(field) != envelope[field]:
            raise AuthorizationFailureError(
                f"authority socket response is not bound to request field {field}"
            )
    if document.get("status") != "ok":
        message = str(document.get("error", "authority service rejected request"))
        if "replay quota" in message or "replay cache is full" in message:
            raise AuthorityServiceCapacityError(message)
        raise AuthorizationFailureError(message)
    return document


def verify_authority_service_receipt(
    receipt: AuthorityServiceReceipt,
    *,
    approval_id: str,
) -> None:
    expected = digest_payload(
        {
            "receipt_id": receipt.receipt_id,
            "run_id": receipt.run_id,
            "action_type": receipt.action_type,
            "config_version": receipt.config_version,
            "approval_id": approval_id,
        }
    )
    if receipt.result_digest != expected:
        raise AuthorizationFailureError("authority service receipt result binding mismatch")


def request_authority_operation(*, operation: str, body: dict[str, Any]) -> AuthorityServiceReceipt:
    if "db_url" in body:
        raise AuthorizationFailureError("authority socket payload must not include db_url")
    document = _request({"operation": operation, **body})
    receipt = document.get("receipt")
    if not isinstance(receipt, dict):
        raise AuthorizationFailureError("authority service returned an invalid receipt")
    for field in ("receipt_id", "run_id", "action_type", "config_version", "result_digest"):
        if not receipt.get(field):
            raise AuthorizationFailureError(f"authority receipt missing {field}")
    approval_id = receipt.get("approval_id")
    service_receipt = AuthorityServiceReceipt(
        receipt_id=str(receipt["receipt_id"]),
        run_id=str(receipt["run_id"]),
        action_type=str(receipt["action_type"]),
        config_version=int(receipt["config_version"]),
        result_digest=str(receipt["result_digest"]),
        approval_id=str(approval_id) if approval_id else None,
    )
    if approval_id:
        verify_authority_service_receipt(service_receipt, approval_id=str(approval_id))
    return service_receipt


def request_terra_receipt_attestation(
    *, receipt_payload: dict[str, Any], external_signature: str
) -> tuple[str, str]:
    """Obtain the DB witness and authority-only gateway proof for one Terra receipt."""
    if not isinstance(receipt_payload, dict) or not external_signature:
        raise AuthorizationFailureError("Terra attestation request is incomplete")
    document = _request(
        {
            "operation": "terra_receipt_attestation",
            "receipt_payload": receipt_payload,
            "external_signature": external_signature,
        }
    )
    attestation_id = document.get("attestation_id")
    if not isinstance(attestation_id, str) or not attestation_id:
        raise AuthorizationFailureError(
            "authority service returned no Terra attestation id"
        )
    gateway_mac = document.get("gateway_mac")
    if not isinstance(gateway_mac, str) or len(gateway_mac) != 64:
        raise AuthorizationFailureError(
            "authority service returned no valid Terra gateway proof"
        )
    return attestation_id, gateway_mac


def verify_terra_receipt_gateway_binding(
    *, receipt: dict[str, Any], authority_signature: str
) -> None:
    """Ask the authority service to recheck a persisted Terra receipt envelope."""
    if not isinstance(receipt, dict) or not isinstance(authority_signature, str):
        raise AuthorizationFailureError("Terra receipt binding request is incomplete")
    document = _request(
        {
            "operation": "verify_terra_receipt_binding",
            "receipt": receipt,
            "authority_signature": authority_signature,
        }
    )
    if document.get("verified") is not True:
        raise AuthorizationFailureError(
            "authority service did not verify the Terra receipt binding"
        )
    if not isinstance(document.get("attestation_id"), str):
        raise AuthorizationFailureError(
            "authority service returned no Terra attestation binding"
        )


def invalidate_terra_receipt_attestation(
    *,
    attestation_id: str,
    run_id: str,
    child_id: str,
    attempt_number: int,
    signature_digest: str,
) -> None:
    """Ask the authority service to retire a witness after a binding failure."""
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
        or not re.fullmatch(r"[0-9a-f]{64}", signature_digest)
    ):
        raise AuthorizationFailureError(
            "Terra attestation invalidation requires the bound signature digest"
        )
    _request(
        {
            "operation": "invalidate_terra_receipt_attestation",
            "attestation_id": attestation_id,
            "run_id": run_id,
            "child_id": child_id,
            "attempt_number": attempt_number,
            "signature_digest": signature_digest,
        }
    )


# Back-compat alias used by older server imports.
def verify_authority_socket_peer(sock: socket.socket) -> None:
    verify_authority_client_peer(sock)
