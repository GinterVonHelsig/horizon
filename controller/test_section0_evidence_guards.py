from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import live_snapshot_trust  # noqa: E402
from legacy_section0_bridge import (  # noqa: E402
    TABLES,
    _resynchronize_sequences,
    _shared_digest_cross_check,
)
from live_snapshot_trust import deployed_content_digest  # noqa: E402
from verify_section0_rollback import (  # noqa: E402
    MAX_RESTORE_OUTPUT_BYTES,
    _assert_live_content_binding,
    _bounded_restore_output,
    _restore_backup_into_empty_target,
)


def test_deployed_content_digest_rejects_symlink(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "controller.py").write_text("pass\n", encoding="utf-8")
    (checkout / "unexpected-link").symlink_to(checkout / "controller.py")

    with pytest.raises(ValueError, match="unexpected symlink"):
        deployed_content_digest(str(checkout))


def test_restore_output_is_bounded_but_content_hashed() -> None:
    value, truncated = _bounded_restore_output("x" * (MAX_RESTORE_OUTPUT_BYTES + 1))

    assert truncated is True
    assert len(value.encode("utf-8")) == MAX_RESTORE_OUTPUT_BYTES


def test_backup_manifest_rejects_live_content_scope_mismatch() -> None:
    manifest = {
        "live_content_sha256": "a" * 64,
        "live_content_digest_scope": "wrong-scope",
    }
    snapshot = {
        "live_service": {
            "deployed_content_sha256": "a" * 64,
            "deployed_content_digest_scope": "regular-files-v1",
        }
    }

    with pytest.raises(ValueError, match="live content provenance"):
        _assert_live_content_binding(manifest, snapshot)


def test_backup_manifest_rejects_live_content_digest_mismatch() -> None:
    manifest = {
        "live_content_sha256": "b" * 64,
        "live_content_digest_scope": "regular-files-v1",
    }
    snapshot = {
        "live_service": {
            "deployed_content_sha256": "a" * 64,
            "deployed_content_digest_scope": "regular-files-v1",
        }
    }

    with pytest.raises(ValueError, match="live content provenance"):
        _assert_live_content_binding(manifest, snapshot)


def test_release_provenance_rejects_content_scope_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = tmp_path / "release.pub"
    provenance = tmp_path / "release.json"
    key.write_text("test-key\n", encoding="ascii")
    key.chmod(0o600)
    payload = {
        "schema": "top-delivery/comms01-release-provenance/v1",
        "working_directory": str(tmp_path),
        "deployed_sha": "a" * 40,
        "deployed_tree_sha": "b" * 40,
        "deployed_content_sha256": "c" * 64,
        "deployed_content_digest_scope": "wrong-scope",
        "source": "test",
        "signature_algorithm": "Ed25519 over domain-separated artifact_sha256",
        "verify_key_sha256": hashlib.sha256(b"test-key").hexdigest(),
        "signature": "signature",
    }
    body = dict(payload)
    body.pop("signature")
    body.pop("signature_algorithm")
    body.pop("verify_key_sha256")
    payload["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    provenance.write_text(json.dumps(payload), encoding="utf-8")
    provenance.chmod(0o600)
    monkeypatch.setattr(live_snapshot_trust, "RELEASE_PROVENANCE", provenance)
    monkeypatch.setattr(live_snapshot_trust, "RELEASE_PROVENANCE_KEY", key)
    monkeypatch.setattr(
        live_snapshot_trust,
        "RELEASE_PROVENANCE_KEY_SHA256",
        hashlib.sha256(b"test-key").hexdigest(),
    )
    monkeypatch.setattr(
        live_snapshot_trust, "verify_message_signature", lambda *_args: True
    )

    with pytest.raises(
        ValueError, match="signed Comms-01 release provenance verification failed"
    ):
        live_snapshot_trust.read_signed_release_provenance(
            working_directory=str(tmp_path), deployed_sha="a" * 40
        )


def test_release_provenance_rejects_invalid_signature(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = tmp_path / "release.pub"
    provenance = tmp_path / "release.json"
    key.write_text("test-key\n", encoding="ascii")
    key.chmod(0o600)
    payload = {
        "schema": "top-delivery/comms01-release-provenance/v1",
        "working_directory": str(tmp_path),
        "deployed_sha": "a" * 40,
        "deployed_tree_sha": "b" * 40,
        "deployed_content_sha256": live_snapshot_trust.deployed_content_digest(
            str(tmp_path)
        ),
        "deployed_content_digest_scope": live_snapshot_trust.CONTENT_DIGEST_SCOPE,
        "source": "test",
        "signature_algorithm": "Ed25519 over domain-separated artifact_sha256",
        "verify_key_sha256": hashlib.sha256(b"test-key").hexdigest(),
        "signature": "invalid",
    }
    body = dict(payload)
    body.pop("signature")
    body.pop("signature_algorithm")
    body.pop("verify_key_sha256")
    payload["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    provenance.write_text(json.dumps(payload), encoding="utf-8")
    provenance.chmod(0o600)
    monkeypatch.setattr(live_snapshot_trust, "RELEASE_PROVENANCE", provenance)
    monkeypatch.setattr(live_snapshot_trust, "RELEASE_PROVENANCE_KEY", key)
    monkeypatch.setattr(
        live_snapshot_trust,
        "RELEASE_PROVENANCE_KEY_SHA256",
        hashlib.sha256(b"test-key").hexdigest(),
    )
    monkeypatch.setattr(live_snapshot_trust, "verify_message_signature", lambda *_args: False)

    with pytest.raises(
        ValueError, match="signed Comms-01 release provenance verification failed"
    ):
        live_snapshot_trust.read_signed_release_provenance(
            working_directory=str(tmp_path), deployed_sha="a" * 40
        )


class _SequenceCursor:
    def __init__(
        self,
        *,
        last_value: int = 1,
        is_called: bool = False,
        start_value: int = 1,
        column_default: str | None = None,
        serial_binding: str | None = None,
    ) -> None:
        self.query = ""
        self.last_value = last_value
        self.is_called = is_called
        self.start_value = start_value
        self.column_default = column_default
        self.serial_binding = serial_binding

    def __enter__(self) -> "_SequenceCursor":
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def execute(self, query: object, *_args: object) -> None:
        self.query = str(query)

    def fetchall(self) -> list[tuple[str, object, object]]:
        return [("supervisor_events_event_seq_seq", None, None)]

    def fetchone(self) -> tuple[object, ...]:
        if "last_value" in self.query:
            return (self.last_value, self.is_called)
        if "seqstart" in self.query:
            return (self.start_value,)
        if "column_default" in self.query:
            return (self.column_default,)
        if "pg_get_serial_sequence" in self.query:
            return (self.serial_binding,)
        raise AssertionError(f"unexpected query: {self.query}")


class _SequenceConnection:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    def cursor(self) -> _SequenceCursor:
        return _SequenceCursor(**self.kwargs)


def test_bridge_preserves_only_an_unbound_unused_supervisor_sequence() -> None:
    result = _resynchronize_sequences(_SequenceConnection())

    assert result == [
        {
            "sequence": "supervisor_events_event_seq_seq",
            "owned_by": None,
            "status": "unused-after-003",
            "consumer": "controller-assigned-event-seq; runtime-nextval-forbidden",
            "set_value": 1,
            "is_called": False,
            "start_value": 1,
            "column_default": None,
            "serial_binding": None,
            "disposition": "preserved; no nextval reconciliation for unbound legacy sequence",
        }
    ]


@pytest.mark.parametrize(
    ("last_value", "is_called", "start_value", "column_default", "serial_binding"),
    [
        (1, True, 1, None, None),
        (2, False, 1, None, None),
        (1, False, 1, "nextval(...)", None),
        (1, False, 1, None, "public.supervisor_events_event_seq_seq"),
    ],
)
def test_bridge_rejects_bound_or_consumed_supervisor_sequence(
    last_value: int,
    is_called: bool,
    start_value: int,
    column_default: str | None,
    serial_binding: str | None,
) -> None:
    with pytest.raises(ValueError, match="bound or consumed"):
        _resynchronize_sequences(
            _SequenceConnection(
                last_value=last_value,
                is_called=is_called,
                start_value=start_value,
                column_default=column_default,
                serial_binding=serial_binding,
            )
        )


def test_bridge_digest_cross_check_detects_divergent_shared_table() -> None:
    source = [
        {"table": table, "source_digest": "same"}
        for table, _keys, _columns in TABLES
    ]
    target = [
        {
            "table": table,
            "target_digest": "different" if table == "signal_status" else "same",
        }
        for table, _keys, _columns in TABLES
    ]

    assert _shared_digest_cross_check(source, target) is False


def test_bridge_digest_cross_check_rejects_missing_shared_table() -> None:
    with pytest.raises(ValueError, match="missing table evidence"):
        _shared_digest_cross_check(
            [{"table": "supervisor_runs", "source_digest": "same"}],
            [{"table": "supervisor_runs", "target_digest": "same"}],
        )


def test_restore_rejects_string_verified_binding_before_target_access(
    tmp_path: Path,
) -> None:
    backup = tmp_path / "backup.dump"
    backup.write_bytes(b"not-restored")

    with pytest.raises(ValueError, match="typed boolean verification"):
        _restore_backup_into_empty_target(
            "postgresql://root@/td_test_guard?host=/var/run/postgresql&port=5432",
            backup,
            manifest_binding={
                "manifest_sha256": "manifest",
                "backup_sha256": "backup",
                "verified": "true",
            },
        )


class _NonEmptyCursor:
    def __init__(self) -> None:
        self.query = ""

    def __enter__(self) -> "_NonEmptyCursor":
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def execute(self, query: object) -> None:
        self.query = str(query)

    def fetchall(self) -> list[tuple[str]]:
        if "information_schema.tables" in self.query:
            return [("unapproved_table",)]
        return []


class _NonEmptyConnection:
    def cursor(self) -> _NonEmptyCursor:
        return _NonEmptyCursor()

    def close(self) -> None:
        return None


def test_restore_rejects_nonempty_target_before_pg_restore(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import verify_section0_rollback as rollback

    monkeypatch.setattr(rollback.psycopg2, "connect", lambda _url: _NonEmptyConnection())
    backup = tmp_path / "backup.dump"
    backup.write_bytes(b"not-restored")

    with pytest.raises(ValueError, match="empty disposable database"):
        _restore_backup_into_empty_target(
            "postgresql://root@/td_test_guard?host=/var/run/postgresql&port=5432",
            backup,
            manifest_binding={
                "manifest_sha256": "manifest",
                "backup_sha256": "backup",
                "verified": True,
            },
        )
