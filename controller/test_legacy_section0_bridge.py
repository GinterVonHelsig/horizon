from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from legacy_section0_bridge import (
    BASELINE_REVISION,
    LEGACY_REVISION,
    _assert_disposable,
    _canonical_evidence_digest,
    _json_value,
    _per_run_sequence_checks,
)


def test_bridge_requires_disposable_local_databases() -> None:
    assert (
        _assert_disposable(
            "postgresql://root@/td_test_source?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
            "source",
        )
        == "td_test_source"
    )
    assert (
        _assert_disposable(
            "postgresql://root@/td_downgrade_target?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
            "target",
        )
        == "td_downgrade_target"
    )
    with pytest.raises(ValueError, match="loopback host or /var/run/postgresql"):
        _assert_disposable("postgresql://root@/td_test_source", "source")
    with pytest.raises(ValueError, match="td_test_\\* or td_downgrade_\\*"):
        _assert_disposable("postgresql://root@/top_delivery_control_p1", "source")
    with pytest.raises(ValueError, match="local PostgreSQL"):
        _assert_disposable("postgresql://root@192.168.0.91/td_test_source", "source")


@pytest.mark.parametrize(
    "url",
    (
        "postgresql://root@/td_test_source?hostaddr=192.0.2.44",
        "postgresql://root@/td_test_source?service=untrusted",
        "postgresql://root@/td_test_source?dbname=production_db",
        "postgresql://root@/td_test_source?unknown=redirect",
    ),
)
def test_bridge_rejects_libpq_redirect_parameters(url: str) -> None:
    with pytest.raises(ValueError, match="forbidden libpq target"):
        _assert_disposable(url, "source")


def test_bridge_rejects_authority_host_with_query_override() -> None:
    with pytest.raises(ValueError, match="combine an authority host"):
        _assert_disposable(
            "postgresql://root@127.0.0.1/td_test_source?host=/var/run/postgresql&port=5432",
            "source",
        )


class _SequenceCursor:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query):
        self.query = query

    def fetchall(self):
        return self.rows


class _SequenceConnection:
    def __init__(self, rows):
        self.rows = rows

    def cursor(self):
        return _SequenceCursor(self.rows)


def test_per_run_sequence_checks_are_content_bound_and_fail_closed() -> None:
    assert _per_run_sequence_checks(
        _SequenceConnection([("run-a", 4, 4), ("run-b", 7, 3)])
    )[0]["safe"] is True
    with pytest.raises(ValueError, match="trail copied events"):
        _per_run_sequence_checks(_SequenceConnection([("run-a", 3, 4)]))


def test_bridge_rejects_inherited_libpq_target_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PGSERVICE", "untrusted-service")
    with pytest.raises(ValueError, match="libpq target environment"):
        _assert_disposable(
            "postgresql://root@/td_test_source?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
            "source",
        )


def test_bridge_revisions_are_explicit() -> None:
    assert LEGACY_REVISION == "004_auditor_provenance"
    assert BASELINE_REVISION == "003_commit_order_and_invariants"


def test_evidence_digest_scope_is_self_verifiable() -> None:
    evidence = {
        "status": "passed",
        "evidence_hash_scope": "canonical-json-with-self-field-removed",
    }
    digest = _canonical_evidence_digest(evidence)
    evidence["evidence_sha256"] = digest
    assert _canonical_evidence_digest(evidence) == digest


def test_timestamp_digest_canonicalization_is_timezone_invariant() -> None:
    utc_value = datetime(2026, 8, 16, 3, 8, 44, 672493, tzinfo=timezone.utc)
    eastern_value = datetime(
        2026,
        8,
        15,
        23,
        8,
        44,
        672493,
        tzinfo=timezone(timedelta(hours=-4)),
    )
    assert _json_value(utc_value) == _json_value(eastern_value)
    assert _json_value(utc_value).endswith("+00:00")


def test_live_snapshot_requires_origin_signature(tmp_path) -> None:
    from create_section0_backup_manifest import _read_live_snapshot

    path = tmp_path / "live-snapshot.json"
    path.write_text(
        '{"database_identity":{"current_schema":"public",'
        '"revision":"004_auditor_provenance",'
            '"search_path":"public",'
            '"transaction_isolation":"repeatable read",'
            '"transaction_read_only":"on",'
            '"session_user":"top_delivery_backup_transport",'
            '"current_user":"top_delivery_backup_reader",'
            '"transport_role":"top_delivery_backup_transport",'
            '"default_transaction_read_only":"on",'
            '"exported_snapshot_id":"00000000-00000000-00000000"},'
            '"live_service":{"unit":"top-delivery-section0-034b.service",'
            '"active_state":"active","sub_state":"running",'
            '"working_directory":"/opt/top-delivery-p1/' + 'a' * 40 + '",'
            '"deployed_sha":"' + 'a' * 40 + '","deployed_tree_sha":"' + 'b' * 40 + '"},'
            '"live_mutation":false,"server_derived":true,"snapshot":{},'
        '"status":"passed"}\n',
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(ValueError, match="origin signature"):
        _read_live_snapshot(path)
