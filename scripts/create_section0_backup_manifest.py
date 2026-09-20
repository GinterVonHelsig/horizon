#!/usr/bin/env python3
"""Create a pinned, signed manifest for a read-only Comms-01 backup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

from legacy_section0_bridge import (  # noqa: E402
    REVIEW_SIGNING_PUBLIC_KEY_PATH,
    REVIEW_SIGNING_PRIVATE_KEY_PATH,
    _read_pinned_key,
)
from operator_asymmetric import sign_message, verify_message_signature  # noqa: E402
from artifact_signing import domain_separated_message  # noqa: E402
from live_snapshot_trust import CONTENT_DIGEST_SCOPE, read_pinned_live_snapshot_key  # noqa: E402


SHA1 = re.compile(r"^[0-9a-f]{40}$")
def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _backup_digest(path: Path) -> tuple[int, str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("backup must be a regular file")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077 or path.stat().st_uid != 0:
        raise ValueError("backup must be root-owned mode 0600")
    data = path.read_bytes()
    if not data:
        raise ValueError("backup must not be empty")
    return len(data), hashlib.sha256(data).hexdigest()


def _read_live_snapshot(path: Path) -> tuple[dict[str, object], str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("live snapshot must be a regular file")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077 or path.stat().st_uid != 0:
        raise ValueError("live snapshot must be root-owned mode 0600")
    payload = json.loads(path.read_text(encoding="utf-8"))
    identity = payload.get("database_identity") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("server_derived") is not True
        or payload.get("live_mutation") is not False
        or payload.get("status") != "passed"
        or not isinstance(identity, dict)
        or identity.get("current_schema") != "public"
        or identity.get("search_path") != "public"
        or identity.get("revision") != "004_auditor_provenance"
        or identity.get("transaction_isolation") != "repeatable read"
        or identity.get("transaction_read_only") != "on"
        or identity.get("session_user") != "top_delivery_backup_transport"
        or identity.get("current_user") != "top_delivery_backup_reader"
        or identity.get("transport_role") != "top_delivery_backup_transport"
        or identity.get("default_transaction_read_only") != "on"
        or not isinstance(identity.get("exported_snapshot_id"), str)
        or not identity.get("exported_snapshot_id")
        or not isinstance(payload.get("live_service"), dict)
        or not isinstance(payload.get("snapshot"), dict)
    ):
        raise ValueError("live snapshot is not a valid server-derived 004 capture")
    artifact_sha256 = payload.get("artifact_sha256")
    signature = payload.get("signature")
    service = payload.get("live_service")
    if (
        not isinstance(artifact_sha256, str)
        or not isinstance(signature, str)
        or not isinstance(service, dict)
        or payload.get("signature_algorithm")
        != "Ed25519 over domain-separated artifact_sha256"
    ):
        raise ValueError("live snapshot origin signature is missing")
    if (
        service.get("unit") != "top-delivery-section0-034b.service"
        or service.get("active_state") != "active"
        or service.get("sub_state") != "running"
        or not isinstance(service.get("working_directory"), str)
        or not isinstance(service.get("deployed_sha"), str)
        or not isinstance(service.get("deployed_tree_sha"), str)
        or not SHA1.fullmatch(service["deployed_sha"])
        or not SHA1.fullmatch(service["deployed_tree_sha"])
        or Path(service["working_directory"]).parent.name != service["deployed_sha"]
    ):
        raise ValueError("live snapshot service provenance is invalid")
    verify_key, verify_key_sha256 = read_pinned_live_snapshot_key()
    body = dict(payload)
    body.pop("artifact_sha256", None)
    body.pop("signature_algorithm", None)
    body.pop("signature", None)
    body.pop("verify_key_sha256", None)
    expected = hashlib.sha256(_canonical(body)).hexdigest()
    if payload.get("verify_key_sha256") != verify_key_sha256:
        raise ValueError("live snapshot verify-key anchor digest is invalid")
    if artifact_sha256 != expected or not verify_message_signature(
        domain_separated_message(str(payload["schema"]), artifact_sha256),
        signature,
        verify_key,
    ):
        raise ValueError("live snapshot origin signature is invalid")
    return payload, hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--live-snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    live_snapshot, live_snapshot_sha256 = _read_live_snapshot(args.live_snapshot)
    identity = live_snapshot["database_identity"]
    if not isinstance(identity, dict):
        raise SystemExit("live snapshot identity is malformed")
    service = live_snapshot.get("live_service")
    if not isinstance(service, dict):
        raise SystemExit("live snapshot service provenance is malformed")
    service_working_directory = service.get("working_directory")
    live_release_sha = service.get("deployed_sha")
    live_tree_sha = service.get("deployed_tree_sha")
    live_content_sha = service.get("deployed_content_sha256")
    live_content_scope = service.get("deployed_content_digest_scope")
    if (
        not isinstance(service_working_directory, str)
        or not isinstance(live_release_sha, str)
        or not isinstance(live_tree_sha, str)
        or not isinstance(live_content_sha, str)
        or not isinstance(live_content_scope, str)
        or live_content_scope != CONTENT_DIGEST_SCOPE
        or not SHA1.fullmatch(live_release_sha)
        or not SHA1.fullmatch(live_tree_sha)
        or len(live_content_sha) != 64
        or Path(service_working_directory).parent.name != live_release_sha
    ):
        raise SystemExit("live service provenance is not bound to its deployed Git object")
    backup_size, backup_sha256 = _backup_digest(args.backup)
    body: dict[str, object] = {
        "schema": "top-delivery/section0-live-backup-manifest/v1",
        "status": "passed",
        "scope": "comms01-live-read-only-backup",
        "live_mutation": False,
        "database_name": identity["current_database"],
        "backup_path": str(args.backup.resolve()),
        "backup_size": backup_size,
        "backup_sha256": backup_sha256,
        "live_snapshot_sha256": live_snapshot_sha256,
        "live_snapshot_path": str(args.live_snapshot.resolve()),
        "service_working_directory": service_working_directory,
        "live_release_sha": live_release_sha,
        "live_tree_sha": live_tree_sha,
        "live_content_sha256": live_content_sha,
        "live_content_digest_scope": live_content_scope,
        "source": "pinned Comms-01 PostgreSQL logical backup operator",
    }
    manifest_sha256 = hashlib.sha256(_canonical(body)).hexdigest()
    signing_key = _read_pinned_key(REVIEW_SIGNING_PRIVATE_KEY_PATH)
    verify_key = _read_pinned_key(REVIEW_SIGNING_PUBLIC_KEY_PATH)
    signature = sign_message(
        domain_separated_message(str(body["schema"]), manifest_sha256), signing_key
    )
    if not verify_message_signature(
        domain_separated_message(str(body["schema"]), manifest_sha256),
        signature,
        verify_key,
    ):
        raise RuntimeError("backup manifest signature failed pinned-key verification")
    payload = {
        **body,
        "manifest_sha256": manifest_sha256,
        "signature_algorithm": "Ed25519 over domain-separated manifest_sha256",
        "signature": signature,
        "verify_key_sha256": hashlib.sha256(verify_key.encode("ascii")).hexdigest(),
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
    except Exception:
        try:
            args.output.unlink()
        except FileNotFoundError:
            pass
        raise
    if stat.S_IMODE(args.output.stat().st_mode) != 0o600:
        raise RuntimeError("backup manifest must be mode 0600")
    print(json.dumps({"status": "passed", "manifest_sha256": manifest_sha256}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
