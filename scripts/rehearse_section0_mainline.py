#!/usr/bin/env python3
"""Rehearse the Section-0 bridge and mainline upgrade on disposable PostgreSQL.

This command is deliberately incapable of selecting the live Comms-01
database: both URLs must identify local, explicitly disposable databases. The
target must already be an empty 003 baseline. It writes only machine-readable
evidence and never changes a non-disposable database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import psycopg2
from alembic import command
from alembic.config import Config

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

from legacy_section0_bridge import (  # noqa: E402
    REVIEW_SIGNING_PUBLIC_KEY_PATH,
    REVIEW_SIGNING_PRIVATE_KEY_PATH,
    _read_pinned_key,
    _assert_disposable,
    bridge,
)
from migration_bootstrap import bootstrap_migration_namespace  # noqa: E402
from operator_asymmetric import sign_message, verify_message_signature  # noqa: E402
from artifact_signing import domain_separated_message  # noqa: E402
from verify_section0_rollback import _table_digest, _table_snapshot  # noqa: E402


FINAL_REVISION = "008_longspan_authority_repair"
EXPECTED_NEW_TABLES = frozenset(
    {
        "longspan_auditor_receipts",
        "longspan_authority_config",
        "longspan_authority_history",
        "longspan_authority_receipts",
        "longspan_children",
        "longspan_evidence_ledger",
        "longspan_execution_audits",
        "longspan_execution_evidence",
        "longspan_execution_results",
        "longspan_experiments",
        "longspan_ledger_legacy_attestations",
        "longspan_mac_key_history",
        "longspan_mac_material",
        "longspan_migration_provenance",
        "longspan_migration_provenance_008_state",
        "longspan_operator_challenges",
        "longspan_plans",
        "longspan_terra_receipt_attestations",
        "longspan_terra_receipts",
        "top_delivery_downgrade_capabilities",
    }
)


def _verify_upgrade_preservation(
    database_url: str,
    before: dict[str, object],
    after: dict[str, object],
) -> dict[str, object]:
    before_tables = before["tables"]
    after_tables = after["tables"]
    if not isinstance(before_tables, dict) or not isinstance(after_tables, dict):
        raise RuntimeError("mainline snapshots have invalid table sections")
    new_tables = set(after_tables) - set(before_tables)
    if new_tables != EXPECTED_NEW_TABLES:
        raise RuntimeError(
            "mainline upgrade produced unexpected table transformation: "
            f"new={sorted(new_tables)} expected={sorted(EXPECTED_NEW_TABLES)}"
        )
    preserved: dict[str, object] = {}
    with psycopg2.connect(database_url) as connection:
        for table, before_record in before_tables.items():
            if table == "alembic_version":
                continue
            if not isinstance(before_record, dict):
                raise RuntimeError(f"invalid pre-upgrade table record: {table}")
            after_record = after_tables.get(table)
            if not isinstance(after_record, dict):
                raise RuntimeError(f"pre-upgrade table disappeared: {table}")
            before_columns = tuple(before_record["columns"])
            after_columns = set(after_record["columns"])
            if not set(before_columns).issubset(after_columns):
                raise RuntimeError(f"pre-upgrade columns disappeared: {table}")
            row_count, digest = _table_digest(connection, table, before_columns)
            if (
                row_count != before_record["row_count"]
                or digest != before_record["digest"]
            ):
                raise RuntimeError(f"pre-upgrade data changed in {table}")
            preserved[table] = {
                "columns": list(before_columns),
                "before_row_count": int(before_record["row_count"]),
                "after_row_count": row_count,
                "before_digest": str(before_record["digest"]),
                "after_digest": digest,
                "pre_existing_columns_preserved": True,
                "added_columns": sorted(after_columns - set(before_columns)),
            }
    before_sequences = before["sequences"]
    after_sequences = after["sequences"]
    if before_sequences != after_sequences:
        raise RuntimeError("mainline upgrade changed existing sequence state")
    return {
        "preservation_digest_scope": (
            "each common-table digest is computed twice using exactly the "
            "pre-upgrade column set; added migration columns are excluded"
        ),
        "expected_new_tables": sorted(EXPECTED_NEW_TABLES),
        "actual_new_tables": sorted(new_tables),
        "preserved_common_tables": preserved,
        "expected_new_sequences": [],
        "existing_sequences_preserved": True,
        "alembic_version_advance": [
            "003_commit_order_and_invariants",
            FINAL_REVISION,
        ],
    }


def _write_signed_json(path: Path, payload: dict[str, object]) -> str:
    private_key = _read_pinned_key(REVIEW_SIGNING_PRIVATE_KEY_PATH)
    verify_key = _read_pinned_key(REVIEW_SIGNING_PUBLIC_KEY_PATH)
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    signature = sign_message(domain_separated_message(str(payload["schema"]), digest), private_key)
    if not verify_message_signature(
        domain_separated_message(str(payload["schema"]), digest),
        signature,
        verify_key,
    ):
        raise RuntimeError("mainline rehearsal signature failed pinned-key verification")
    payload = {
        **payload,
        "artifact_sha256": digest,
        "signature_algorithm": "Ed25519 over domain-separated artifact_sha256",
        "signature": signature,
        "verify_key_sha256": hashlib.sha256(verify_key.encode("ascii")).hexdigest(),
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError("mainline rehearsal evidence must be mode 0600")
    return hashlib.sha256(encoded).hexdigest()


def _revision(database_url: str) -> str:
    with psycopg2.connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT version_num FROM public.alembic_version")
            row = cursor.fetchone()
    if row is None:
        raise RuntimeError("disposable target has no Alembic revision")
    return str(row[0])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--bridge-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", default=FINAL_REVISION)
    args = parser.parse_args()

    if args.revision != FINAL_REVISION:
        raise SystemExit("only the reviewed 008 mainline head is permitted")
    _assert_disposable(args.source_url, "source_url")
    _assert_disposable(args.target_url, "target_url")

    # Bootstrap is an explicit disposable-target operation. It does not alter
    # data and is separate from Alembic's migration environment.
    bootstrap_evidence = bootstrap_migration_namespace(args.target_url)
    bridge_result = bridge(args.source_url, args.target_url, args.bridge_evidence)
    before_upgrade = _table_snapshot(
        args.target_url, expected_revision="003_commit_order_and_invariants"
    )

    controller_dir = Path(__file__).resolve().parents[1] / "controller"
    config = Config(str(controller_dir / "alembic.ini"))
    config.set_main_option("script_location", str(controller_dir / "migrations"))
    config.cmd_opts = SimpleNamespace(revision=args.revision, cmd=None)
    previous_url = os.environ.get("TOP_DELIVERY_DATABASE_URL")
    os.environ["TOP_DELIVERY_DATABASE_URL"] = args.target_url
    try:
        command.upgrade(config, args.revision)
    finally:
        if previous_url is None:
            os.environ.pop("TOP_DELIVERY_DATABASE_URL", None)
        else:
            os.environ["TOP_DELIVERY_DATABASE_URL"] = previous_url

    actual_revision = _revision(args.target_url)
    if actual_revision != FINAL_REVISION:
        raise RuntimeError(
            f"disposable mainline rehearsal ended at {actual_revision}, "
            f"expected {FINAL_REVISION}"
        )
    after_upgrade = _table_snapshot(
        args.target_url, expected_revision=FINAL_REVISION
    )
    preservation = _verify_upgrade_preservation(
        args.target_url, before_upgrade, after_upgrade
    )
    output = {
        "schema": "top-delivery/section0-mainline-rehearsal/v1",
        "status": "passed",
        "scope": "disposable-local-postgresql-only",
        "live_mutation": False,
        "candidate_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=CONTROLLER.parent, text=True
        ).strip(),
        "tree_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=CONTROLLER.parent, text=True
        ).strip(),
        "source_revision": bridge_result["source"]["revision"],
        "target_revision_before": bridge_result["target"]["revision_before_mainline_upgrade"],
        "target_revision_after": actual_revision,
        "bootstrap": bootstrap_evidence,
        "upgrade_preservation": preservation,
        "bridge_evidence": {
            "path": str(args.bridge_evidence),
            "sha256": hashlib.sha256(args.bridge_evidence.read_bytes()).hexdigest(),
        },
        "migration_chain": [
            "004_longspan_workflow",
            "005_longspan_hardening",
            "006_longspan_authority",
            "007_longspan_authority_hardening",
            FINAL_REVISION,
        ],
    }
    output_sha256 = _write_signed_json(args.output, output)
    print(json.dumps({"status": "passed", "output_sha256": output_sha256}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
