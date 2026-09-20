#!/usr/bin/env python3
"""Verify a signed restore rehearsal for the accepted legacy release.

The restore itself is intentionally performed by the pinned PostgreSQL
restore operator. This verifier proves that the restored disposable database
matches the retained source snapshot and emits a signed, content-bound
rollback artifact. It accepts only local disposable databases.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import stat
import sys
from typing import TypedDict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import psycopg2
from psycopg2 import sql

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

from legacy_section0_bridge import (  # noqa: E402
    LEGACY_REVISION,
    REVIEW_SIGNING_PUBLIC_KEY_PATH,
    _assert_disposable,
    _base_tables,
    _column_metadata,
    _json_value,
    _revision,
)
from create_section0_backup_manifest import _read_live_snapshot  # noqa: E402
from live_snapshot_trust import CONTENT_DIGEST_SCOPE  # noqa: E402
from operator_asymmetric import sign_message, verify_message_signature  # noqa: E402
from artifact_signing import domain_separated_message  # noqa: E402

MAX_RESTORE_OUTPUT_BYTES = 64 * 1024


class RestoreManifestBinding(TypedDict):
    """Advisory static shape; runtime validation below is authoritative."""

    manifest_sha256: str
    backup_sha256: str
    verified: bool


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _bounded_restore_output(value: str) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= MAX_RESTORE_OUTPUT_BYTES:
        return value, False
    clipped = encoded[:MAX_RESTORE_OUTPUT_BYTES].decode("utf-8", errors="replace")
    return clipped, True


def _file_digest(path: Path) -> tuple[int, str]:
    if not path.is_file():
        raise ValueError("rollback source is not a regular file")
    data = path.read_bytes()
    if not data:
        raise ValueError("rollback source is empty")
    return len(data), hashlib.sha256(data).hexdigest()


def _assert_live_content_binding(
    manifest: dict[str, object], live_snapshot: dict[str, object]
) -> None:
    service = live_snapshot.get("live_service")
    if not isinstance(service, dict):
        raise ValueError("live snapshot service provenance is malformed")
    if (
        manifest.get("live_content_sha256")
        != service.get("deployed_content_sha256")
        or manifest.get("live_content_digest_scope")
        != service.get("deployed_content_digest_scope")
        or service.get("deployed_content_digest_scope") != CONTENT_DIGEST_SCOPE
    ):
        raise ValueError("backup manifest live content provenance does not match snapshot")


def _canonical_value(value: object) -> object:
    value = _json_value(value)
    if isinstance(value, dict):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


def _table_digest(
    connection, table: str, columns: tuple[str, ...]
) -> tuple[int, str]:
    query = sql.SQL("SELECT {columns} FROM public.{table}").format(
        columns=sql.SQL(", ").join(sql.Identifier(column) for column in columns),
        table=sql.Identifier(table),
    )
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = [
            {
                column: _canonical_value(value)
                for column, value in zip(columns, row)
            }
            for row in cursor.fetchall()
        ]
    rows.sort(
        key=lambda row: json.dumps(
            row, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    )
    return len(rows), hashlib.sha256(_canonical(rows)).hexdigest()


def _table_snapshot_from_connection(
    connection, *, expected_revision: str = LEGACY_REVISION
) -> dict[str, object]:
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_schema(), current_setting('search_path')")
        current_schema, search_path = cursor.fetchone()
    if current_schema != "public" or search_path != "public":
        raise ValueError("snapshot connection search_path is not public")
    if _revision(connection) != expected_revision:
        raise ValueError(f"database must remain at {expected_revision}")
    tables: dict[str, object] = {}
    for table in _base_tables(connection):
        columns = tuple(_column_metadata(connection, table))
        row_count, digest = _table_digest(connection, table, columns)
        tables[table] = {
            "columns": list(columns),
            "row_count": row_count,
            "digest": digest,
        }
    sequences: dict[str, object] = {}
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.relname
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'S'
            ORDER BY c.relname
            """
        )
        sequence_names = [str(row[0]) for row in cursor.fetchall()]
    for sequence_name in sequence_names:
        query = sql.SQL("SELECT last_value, is_called FROM public.{sequence}").format(
            sequence=sql.Identifier(sequence_name)
        )
        with connection.cursor() as cursor:
            cursor.execute(query)
            last_value, is_called = cursor.fetchone()
        sequences[sequence_name] = {
            "last_value": int(last_value),
            "is_called": bool(is_called),
        }
    return {"tables": tables, "sequences": sequences}


def _table_snapshot(
    database_url: str, *, expected_revision: str = LEGACY_REVISION
) -> dict[str, object]:
    with psycopg2.connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SET SESSION search_path TO public")
        return _table_snapshot_from_connection(
            connection, expected_revision=expected_revision
        )


def _read_key_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"signing key is not a regular file: {path}")
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077 or path.stat().st_uid != 0:
        raise ValueError(f"signing key must be root-owned mode 0600: {path}")
    return path.read_text(encoding="ascii").strip()


def _read_signed_backup_manifest(
    path: Path, backup: Path, live_snapshot_path: Path
) -> tuple[dict[str, object], dict[str, object]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("backup manifest must be a regular file")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("backup manifest must be a JSON object")
    expected_fields = {
        "schema",
        "status",
        "scope",
        "live_mutation",
        "database_name",
        "backup_path",
        "backup_size",
        "backup_sha256",
        "live_release_sha",
        "live_tree_sha",
        "live_snapshot_path",
        "live_snapshot_sha256",
        "live_content_sha256",
        "live_content_digest_scope",
        "service_working_directory",
        "source",
        "manifest_sha256",
        "signature_algorithm",
        "signature",
        "verify_key_sha256",
    }
    if set(payload) != expected_fields:
        raise ValueError("backup manifest fields are not the reviewed exact set")
    manifest_sha256 = payload.get("manifest_sha256")
    signature = payload.get("signature")
    if not isinstance(manifest_sha256, str) or not isinstance(signature, str):
        raise ValueError("backup manifest signature fields are missing")
    body = dict(payload)
    body.pop("manifest_sha256", None)
    if payload.get("signature_algorithm") != "Ed25519 over domain-separated manifest_sha256":
        raise ValueError("backup manifest signature algorithm is invalid")
    body.pop("signature_algorithm", None)
    body.pop("signature", None)
    body.pop("verify_key_sha256", None)
    expected = hashlib.sha256(_canonical(body)).hexdigest()
    verify_key = _read_key_file(REVIEW_SIGNING_PUBLIC_KEY_PATH)
    expected_verify_key_sha256 = hashlib.sha256(verify_key.encode("ascii")).hexdigest()
    if payload.get("verify_key_sha256") != expected_verify_key_sha256:
        raise ValueError("backup manifest verify-key anchor digest is invalid")
    if manifest_sha256 != expected or not verify_message_signature(
        domain_separated_message(str(payload["schema"]), manifest_sha256),
        signature,
        verify_key,
    ):
        raise ValueError("backup manifest failed pinned-key verification")
    if Path(str(payload.get("backup_path"))).resolve() != backup.resolve():
        raise ValueError("backup path does not match signed backup manifest")
    if Path(str(payload.get("live_snapshot_path"))).resolve() != live_snapshot_path.resolve():
        raise ValueError("live snapshot path does not match signed backup manifest")
    live_snapshot, live_snapshot_sha256 = _read_live_snapshot(live_snapshot_path)
    if payload.get("live_snapshot_sha256") != live_snapshot_sha256:
        raise ValueError("live snapshot does not match signed backup manifest")
    backup_size, backup_sha256 = _file_digest(backup)
    if (
        payload.get("backup_size") != backup_size
        or payload.get("backup_sha256") != backup_sha256
        or payload.get("scope") != "comms01-live-read-only-backup"
        or payload.get("live_mutation") is not False
    ):
        raise ValueError("backup does not match signed backup manifest")
    _assert_live_content_binding(payload, live_snapshot)
    return payload, live_snapshot


def _restore_backup_into_empty_target(
    restore_url: str, backup: Path, *, manifest_binding: RestoreManifestBinding
) -> dict[str, object]:
    """Restore the retained bytes into a pinned empty disposable database."""
    if (
        set(manifest_binding) != {"manifest_sha256", "backup_sha256", "verified"}
        or not isinstance(manifest_binding["manifest_sha256"], str)
        or not isinstance(manifest_binding["backup_sha256"], str)
        or manifest_binding["verified"] is not True
    ):
        raise ValueError("restore manifest binding must have typed boolean verification")
    target_name = _assert_disposable(restore_url, "restore_url")
    parsed = urlsplit(restore_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (
        parsed.hostname is not None
        or query.get("host") != ["/var/run/postgresql"]
        or query.get("port") != ["5432"]
        or (parsed.username or "root") != "root"
    ):
        raise ValueError(
            "restore_url must use the verified root PostgreSQL Unix socket endpoint"
        )
    connection = psycopg2.connect(restore_url)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET SESSION search_path TO public")
            cursor.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name
                """
            )
            tables = [str(row[0]) for row in cursor.fetchall()]
            cursor.execute(
                """
                SELECT c.relname
                FROM pg_class AS c
                JOIN pg_namespace AS n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind = 'S'
                ORDER BY c.relname
                """
            )
            sequences = [str(row[0]) for row in cursor.fetchall()]
    finally:
        connection.close()
    if tables or sequences:
        raise ValueError(
            "restore target must be an empty disposable database before pg_restore: "
            f"tables={tables}, sequences={sequences}"
        )
    env = {
        "PATH": "/usr/lib/postgresql/17/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "PGDATABASE": target_name,
        "PGUSER": parsed.username or "root",
        "PGHOST": "/var/run/postgresql",
        "PGPORT": "5432",
    }
    restore_process = subprocess.run(
        [
            "/usr/lib/postgresql/17/bin/pg_restore",
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--exit-on-error",
            f"--dbname={target_name}",
            str(backup),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=180.0,
        env=env,
    )
    bounded_stdout, stdout_truncated = _bounded_restore_output(restore_process.stdout)
    bounded_stderr, stderr_truncated = _bounded_restore_output(restore_process.stderr)
    restore_output = {
        "stdout": bounded_stdout,
        "stderr": bounded_stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "stdout_sha256": hashlib.sha256(
            restore_process.stdout.encode("utf-8")
        ).hexdigest(),
        "stderr_sha256": hashlib.sha256(
            restore_process.stderr.encode("utf-8")
        ).hexdigest(),
    }
    if restore_process.returncode != 0:
        raise RuntimeError(
            "pg_restore failed with --exit-on-error: "
            f"{restore_process.stderr[-2000:]}"
        )
    return {
        "performed": True,
        "operator": "pinned-local-restore-operator",
        "backup_sha256": hashlib.sha256(backup.read_bytes()).hexdigest(),
        "manifest_backup_binding": manifest_binding,
        "target_database": target_name,
        "target_endpoint": "local-postgresql-socket",
        "command": "pg_restore custom/no-owner/no-privileges/exit-on-error",
        "restore_output": restore_output,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--restore-url", required=True)
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--backup-manifest", required=True, type=Path)
    parser.add_argument("--live-snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--signing-key-file", required=True, type=Path)
    args = parser.parse_args()

    _assert_disposable(args.source_url, "source_url")
    _assert_disposable(args.restore_url, "restore_url")
    if args.source_url == args.restore_url:
        raise SystemExit("source and restore databases must be different")
    backup_manifest, live_snapshot = _read_signed_backup_manifest(
        args.backup_manifest, args.backup, args.live_snapshot
    )
    backup_size, backup_sha256 = _file_digest(args.backup)
    source_digest = _table_snapshot(args.source_url)
    restore_proof = _restore_backup_into_empty_target(
        args.restore_url,
        args.backup,
        manifest_binding={
            "manifest_sha256": str(backup_manifest["manifest_sha256"]),
            "backup_sha256": str(backup_manifest["backup_sha256"]),
            "verified": True,
        },
    )
    restore_digest = _table_snapshot(args.restore_url)
    table_digests_equal = source_digest == restore_digest
    live_snapshot_equal = live_snapshot.get("snapshot") == source_digest
    if not table_digests_equal:
        raise RuntimeError("restored database table digests differ from source")
    if not live_snapshot_equal:
        raise RuntimeError("live server snapshot differs from restored backup snapshot")

    body: dict[str, object] = {
        "schema": "top-delivery/section0-rollback-rehearsal/v1",
        "status": "passed",
        "scope": "disposable-local-postgresql-only",
        "live_mutation": False,
        "accepted_release_sha": backup_manifest["live_release_sha"],
        "accepted_release_tree": backup_manifest["live_tree_sha"],
        "live_database_name": backup_manifest["database_name"],
        "source_revision": LEGACY_REVISION,
        "restore_revision": LEGACY_REVISION,
        "backup_size": backup_size,
        "backup_sha256": backup_sha256,
        "backup_manifest_sha256": backup_manifest["manifest_sha256"],
        "source_table_digests": source_digest,
        "restore_table_digests": restore_digest,
        "table_digests_equal": table_digests_equal,
        "live_snapshot_equal": live_snapshot_equal,
        "live_snapshot_sha256": backup_manifest["live_snapshot_sha256"],
        "restore_strategy": "restore-retained-backup-into-disposable-target",
        "restore_proof": {
            **restore_proof,
            "performed": bool(restore_proof.get("performed")),
        },
    }
    body_digest = hashlib.sha256(_canonical(body)).hexdigest()
    signing_key = _read_key_file(args.signing_key_file)
    verify_key = _read_key_file(REVIEW_SIGNING_PUBLIC_KEY_PATH)
    signature = sign_message(
        domain_separated_message(str(body["schema"]), body_digest), signing_key
    )
    if not verify_message_signature(
        domain_separated_message(str(body["schema"]), body_digest),
        signature,
        verify_key,
    ):
        raise RuntimeError("rollback artifact signature failed self-verification")
    body.update(
        {
            "artifact_sha256": body_digest,
            "signature_algorithm": "Ed25519 over domain-separated artifact_sha256",
            "signature": signature,
            "verify_key_path": str(REVIEW_SIGNING_PUBLIC_KEY_PATH),
            "verify_key_sha256": hashlib.sha256(verify_key.encode("ascii")).hexdigest(),
        }
    )
    encoded = (json.dumps(body, indent=2, sort_keys=True) + "\n").encode()
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
        raise RuntimeError("rollback artifact must be mode 0600")
    print(json.dumps({"status": "passed", "output_sha256": hashlib.sha256(encoded).hexdigest()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
