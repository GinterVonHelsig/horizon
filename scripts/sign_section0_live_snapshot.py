#!/usr/bin/env python3
"""Sign one server-derived Comms-01 snapshot on the Comms-01 host.

The capture process runs as the pinned PostgreSQL read-only operator and cannot
read the root-held signing key. This root-only second step signs the exact
captured bytes without opening a database connection or changing the capture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

from operator_asymmetric import sign_message  # noqa: E402
from live_snapshot_trust import (  # noqa: E402
    CONTENT_DIGEST_SCOPE,
    deployed_content_digest,
    read_pinned_live_snapshot_key,
    read_signed_release_provenance,
)
from legacy_section0_bridge import SNAPSHOT_DIGEST_SCOPE  # noqa: E402
from artifact_signing import domain_separated_message  # noqa: E402


SIGNING_KEY = Path("/etc/top-delivery/comms01-live-snapshot-signing.key")
SERVICE_UNIT = "top-delivery-section0-034b.service"
SHA1 = re.compile(r"^[0-9a-f]{40}$")


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _read_private_key() -> str:
    if (
        not SIGNING_KEY.is_file()
        or SIGNING_KEY.is_symlink()
        or SIGNING_KEY.stat().st_uid != 0
        or SIGNING_KEY.stat().st_mode & 0o077
    ):
        raise RuntimeError("snapshot signing key must be root-owned mode 0600")
    return SIGNING_KEY.read_text(encoding="ascii").strip()


def _service_provenance() -> dict[str, object]:
    raw = subprocess.check_output(
        [
            "systemctl",
            "show",
            SERVICE_UNIT,
            "--property=ActiveState,SubState,WorkingDirectory,ExecStart,FragmentPath",
            "--no-pager",
        ],
        text=True,
    )
    values: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    if values.get("ActiveState") != "active" or values.get("SubState") != "running":
        raise RuntimeError("Comms-01 Section-0 service is not active and running")
    workdir = values.get("WorkingDirectory", "")
    fragment = values.get("FragmentPath", "")
    exec_start = values.get("ExecStart", "")
    if not workdir.startswith("/") or not fragment.startswith("/") or not exec_start:
        raise RuntimeError("Comms-01 service provenance is incomplete")
    release_name = Path(workdir).parent.name
    if not SHA1.fullmatch(release_name):
        raise RuntimeError("Comms-01 service checkout directory is not SHA-addressed")
    deployed_sha = release_name
    if not SHA1.fullmatch(deployed_sha):
        raise RuntimeError("Comms-01 service checkout directory is not SHA-addressed")
    try:
        release = read_signed_release_provenance(
            working_directory=workdir,
            deployed_sha=deployed_sha,
        )
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    deployed_tree_sha = release["deployed_tree_sha"]
    if not SHA1.fullmatch(deployed_tree_sha):
        raise RuntimeError("signed Comms-01 release tree provenance is malformed")
    if release["working_directory"] != workdir or release["deployed_sha"] != deployed_sha:
        raise RuntimeError("Comms-01 service checkout is not content-addressed by SHA")
    actual_content_sha = deployed_content_digest(workdir)
    if actual_content_sha != release["deployed_content_sha256"]:
        raise RuntimeError(
            "deployed Comms-01 checkout content does not match signed provenance"
        )
    return {
        "unit": SERVICE_UNIT,
        "active_state": values["ActiveState"],
        "sub_state": values["SubState"],
        "working_directory": workdir,
        "exec_start": exec_start,
        "fragment_path": fragment,
        "deployed_sha": deployed_sha,
        "deployed_tree_sha": deployed_tree_sha,
        "deployed_content_sha256": actual_content_sha,
        "deployed_content_digest_scope": CONTENT_DIGEST_SCOPE,
        "tree_source": "signed-out-of-band-git-provenance",
        "release_provenance_sha256": release["artifact_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.input.is_file() or args.input.is_symlink():
        raise ValueError("snapshot input must be a regular file")
    if args.input.stat().st_mode & 0o077:
        raise ValueError("snapshot input must be mode 0600")
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    identity = payload.get("database_identity") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != "top-delivery/section0-live-snapshot/v1"
        or payload.get("status") != "passed"
        or payload.get("server_derived") is not True
        or payload.get("live_mutation") is not False
        or payload.get("snapshot_digest_scope") != SNAPSHOT_DIGEST_SCOPE
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
        or not isinstance(payload.get("snapshot"), dict)
        or any(field in payload for field in ("artifact_sha256", "signature", "verify_key_sha256"))
    ):
        raise ValueError("input is not a valid unsigned server-derived snapshot")
    sequence_safety = payload.get("sequence_safety")
    sequence_record = (
        sequence_safety.get("supervisor_events_event_seq_seq")
        if isinstance(sequence_safety, dict)
        else None
    )
    if (
        not isinstance(sequence_record, dict)
        or sequence_record.get("status") not in {"active", "unused-after-003"}
        or not isinstance(sequence_record.get("safe_for_automatic_insert"), bool)
        or not isinstance(sequence_record.get("last_value"), int)
        or not isinstance(sequence_record.get("max_event_seq"), int)
        or not isinstance(sequence_record.get("event_row_count"), int)
        or sequence_record.get("consumer")
        not in {
            "controller-assigned-event-seq; runtime-nextval-forbidden",
            "database-default-nextval",
        }
        or (
            sequence_record["status"] == "unused-after-003"
            and (
                sequence_record["safe_for_automatic_insert"]
                or sequence_record.get("column_default") is not None
                or sequence_record.get("serial_binding") is not None
                or sequence_record.get("consumer")
                != "controller-assigned-event-seq; runtime-nextval-forbidden"
            )
        )
        or (
            sequence_record["status"] == "active"
            and sequence_record["last_value"] < sequence_record["max_event_seq"]
        )
    ):
        raise ValueError("sequence safety disposition is invalid")
    verify_key, verify_key_sha256 = read_pinned_live_snapshot_key()
    service = _service_provenance()
    unsigned = {**payload, "live_service": service}
    artifact_sha256 = hashlib.sha256(_canonical(unsigned)).hexdigest()
    signed = {
        **unsigned,
        "artifact_sha256": artifact_sha256,
        "signature_algorithm": "Ed25519 over domain-separated artifact_sha256",
        "signature": sign_message(
            domain_separated_message(str(unsigned["schema"]), artifact_sha256),
            _read_private_key(),
        ),
        "verify_key_sha256": verify_key_sha256,
    }
    encoded = (json.dumps(signed, indent=2, sort_keys=True) + "\n").encode("utf-8")
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
        raise RuntimeError("signed snapshot must be mode 0600")
    print(json.dumps({"status": "signed", "artifact_sha256": artifact_sha256}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
