#!/usr/bin/env python3
"""Sign the postgres-captured Comms-01 backup-reader grant evidence as root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

from live_snapshot_trust import read_pinned_live_snapshot_key  # noqa: E402
from operator_asymmetric import sign_message, verify_message_signature  # noqa: E402
from artifact_signing import domain_separated_message  # noqa: E402


SIGNING_KEY = Path("/etc/top-delivery/comms01-live-snapshot-signing.key")


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        not args.input.is_file()
        or args.input.is_symlink()
        or args.input.stat().st_uid != 0
        or args.input.stat().st_mode & 0o077
    ):
        raise ValueError("unsigned grant capture must be root-owned mode 0600")
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != "top-delivery/comms01-backup-reader-grants/v1"
        or payload.get("status") != "passed"
        or payload.get("live_mutation") is not False
        or payload.get("writes_allowed") is not False
        or not isinstance(payload.get("transport_role"), dict)
        or not isinstance(payload.get("transport_membership"), dict)
        or payload["transport_role"].get("role") != "top_delivery_backup_transport"
        or payload["transport_role"].get("can_login") is not True
        or payload["transport_role"].get("superuser") is not False
        or payload["transport_role"].get("create_database") is not False
        or payload["transport_role"].get("create_role") is not False
        or payload["transport_membership"].get("is_member") is not True
        or payload.get("transport_schema_usage") is not True
        or payload.get("transport_schema_create") is not False
        or not isinstance(payload.get("column_privileges"), dict)
        or payload.get("column_privileges", {}).get("top_delivery_backup_reader") != 0
        or payload.get("column_privileges", {}).get("top_delivery_backup_transport") != 0
        or not isinstance(payload.get("sequences"), list)
        or not isinstance(payload.get("public_table_privileges"), list)
        or not isinstance(payload.get("public_sequence_privileges"), list)
        or not isinstance(payload.get("role_memberships"), list)
        or any(not isinstance(item, dict) for item in payload["public_table_privileges"])
        or any(not isinstance(item, dict) for item in payload["public_sequence_privileges"])
        or any(not isinstance(item, dict) for item in payload["role_memberships"])
        or any(item.get("privileges") for item in payload["public_table_privileges"])
        or any(item.get("privileges") for item in payload["public_sequence_privileges"])
        or {
            (item.get("member"), item.get("parent"), item.get("admin_option"))
            for item in payload["role_memberships"]
        }
        != {
            ("top_delivery_backup_transport", "top_delivery_backup_reader", False)
        }
        or any(
            table.get(field) is not False
            for table in payload.get("tables", [])
            for field in (
                "insert", "update", "delete", "truncate", "references", "trigger",
                "transport_insert", "transport_update", "transport_delete",
                "transport_truncate", "transport_references", "transport_trigger",
            )
        )
        or any(
            sequence.get(field) is not False
            for sequence in payload.get("sequences", [])
            for field in ("usage", "transport_usage", "update", "transport_update")
        )
        or any(field in payload for field in ("artifact_sha256", "signature", "verify_key_sha256"))
    ):
        raise ValueError("unsigned grant capture is invalid")
    body_digest = hashlib.sha256(_canonical(payload)).hexdigest()
    if (
        not SIGNING_KEY.is_file()
        or SIGNING_KEY.is_symlink()
        or SIGNING_KEY.stat().st_uid != 0
        or SIGNING_KEY.stat().st_mode & 0o077
    ):
        raise RuntimeError("grant signing key must be root-owned mode 0600")
    private = SIGNING_KEY.read_text(encoding="ascii").strip()
    verify_key, verify_key_sha256 = read_pinned_live_snapshot_key()
    signature = sign_message(
        domain_separated_message(str(payload["schema"]), body_digest), private
    )
    if not verify_message_signature(
        domain_separated_message(str(payload["schema"]), body_digest),
        signature,
        verify_key,
    ):
        raise RuntimeError("grant artifact signature failed self-verification")
    signed = {
        **payload,
        "artifact_sha256": body_digest,
        "signature_algorithm": "Ed25519 over domain-separated artifact_sha256",
        "signature": signature,
        "verify_key_sha256": verify_key_sha256,
    }
    encoded = (json.dumps(signed, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(encoded)
    if stat.S_IMODE(args.output.stat().st_mode) != 0o600:
        raise RuntimeError("signed grant artifact must be mode 0600")
    print(json.dumps({"status": "signed", "artifact_sha256": body_digest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
