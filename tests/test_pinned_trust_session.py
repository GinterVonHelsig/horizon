"""Host-safe tests for pytest trust-anchor snapshot/restore. Never write /etc/top-delivery."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from test_only.pinned_trust_session import (
    ALLOW_LIVE_TRUST_MUTATION_ENV,
    LIVE_HOST_FINGERPRINTS,
    PINNED_TRUST_SESSION_PATHS,
    PinnedTrustRestoreError,
    begin_pinned_trust_session,
    live_trust_mutation_forbidden,
    restore_pinned_trust_files,
    snapshot_pinned_trust_files,
)

_LIVE_ROOT = Path("/etc/top-delivery")


def _assert_not_live(path: Path) -> None:
    resolved = path.resolve()
    raw = str(path)
    if raw == str(_LIVE_ROOT) or raw.startswith(str(_LIVE_ROOT) + "/"):
        raise AssertionError(f"test path is under live trust root: {path}")
    if resolved == _LIVE_ROOT or _LIVE_ROOT in resolved.parents:
        raise AssertionError(f"resolved test path is under live trust root: {resolved}")


def test_suite_paths_are_not_live_trust_root(tmp_path: Path) -> None:
    _assert_not_live(tmp_path)
    _assert_not_live(tmp_path / "comms01-attestation.json")
    with pytest.raises(AssertionError):
        _assert_not_live(Path("/etc/top-delivery"))
    with pytest.raises(AssertionError):
        _assert_not_live(Path("/etc/top-delivery/comms01-attestation.json"))


def test_pinned_session_constants_are_under_documented_live_root() -> None:
    for raw in PINNED_TRUST_SESSION_PATHS:
        assert raw.startswith("/etc/top-delivery/")
    assert "comms01-comms-01" in LIVE_HOST_FINGERPRINTS


def test_restore_bytes_and_mode(tmp_path: Path) -> None:
    target = tmp_path / "keep.txt"
    _assert_not_live(target)
    target.write_text("original\n", encoding="utf-8")
    target.chmod(0o640)
    snapshot = snapshot_pinned_trust_files((str(target),))
    target.write_text("clobbered\n", encoding="utf-8")
    target.chmod(0o600)
    notes = restore_pinned_trust_files(snapshot)
    assert target.read_text(encoding="utf-8") == "original\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert isinstance(notes, tuple)


def test_restore_deletes_files_that_did_not_exist(tmp_path: Path) -> None:
    target = tmp_path / "created-during-session.txt"
    _assert_not_live(target)
    snapshot = snapshot_pinned_trust_files((str(target),))
    target.write_text("pytest leftover\n", encoding="utf-8")
    restore_pinned_trust_files(snapshot)
    assert not target.exists()


def test_restore_attempts_remaining_files_after_one_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / "good.txt"
    bad = tmp_path / "bad.txt"
    _assert_not_live(good)
    _assert_not_live(bad)
    good.write_text("keep-me\n", encoding="utf-8")
    bad.write_text("also-keep\n", encoding="utf-8")
    snapshot = snapshot_pinned_trust_files((str(bad), str(good)))
    good.write_text("clobbered-good\n", encoding="utf-8")
    bad.write_text("clobbered-bad\n", encoding="utf-8")

    original = Path.write_bytes

    def flaky_write(self: Path, data: bytes) -> int:
        if self.name == "bad.txt":
            raise OSError("injected restore failure")
        return original(self, data)

    monkeypatch.setattr(Path, "write_bytes", flaky_write)
    with pytest.raises(PinnedTrustRestoreError, match="bad.txt"):
        restore_pinned_trust_files(snapshot)
    assert good.read_text(encoding="utf-8") == "keep-me\n"


def test_live_fingerprint_forbidden_without_env(tmp_path: Path) -> None:
    attestation = tmp_path / "attestation.json"
    _assert_not_live(attestation)
    attestation.write_text(
        json.dumps({"host_fingerprint": "comms01-comms-01"}) + "\n",
        encoding="utf-8",
    )
    assert live_trust_mutation_forbidden(attestation, {}) is True
    assert live_trust_mutation_forbidden(
        attestation, {ALLOW_LIVE_TRUST_MUTATION_ENV: "1"}
    ) is False


def test_isolated_fingerprint_allowed(tmp_path: Path) -> None:
    attestation = tmp_path / "attestation.json"
    _assert_not_live(attestation)
    attestation.write_text(
        json.dumps({"host_fingerprint": "comms01-isolated-top-delivery-local"})
        + "\n",
        encoding="utf-8",
    )
    assert live_trust_mutation_forbidden(attestation, {}) is False


def test_missing_attestation_forbidden_when_trust_root_present(tmp_path: Path) -> None:
    root = tmp_path / "trust-root"
    root.mkdir()
    missing = root / "attestation.json"
    _assert_not_live(missing)
    assert missing.exists() is False
    assert live_trust_mutation_forbidden(missing, {}, trust_root=root) is True


def test_missing_attestation_allowed_when_trust_root_absent(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-dir" / "attestation.json"
    _assert_not_live(missing)
    assert missing.parent.exists() is False
    assert live_trust_mutation_forbidden(missing, {}) is False


def test_missing_host_fingerprint_key_forbidden(tmp_path: Path) -> None:
    attestation = tmp_path / "attestation.json"
    _assert_not_live(attestation)
    attestation.write_text(json.dumps({"scope": "comms-01"}) + "\n", encoding="utf-8")
    assert live_trust_mutation_forbidden(attestation, {}) is True


def test_corrupt_json_forbidden(tmp_path: Path) -> None:
    attestation = tmp_path / "attestation.json"
    _assert_not_live(attestation)
    attestation.write_text("{not-json", encoding="utf-8")
    assert live_trust_mutation_forbidden(attestation, {}) is True


def test_begin_session_refuses_before_any_write(tmp_path: Path) -> None:
    pinned = tmp_path / "operator-keys.json"
    attestation = tmp_path / "attestation.json"
    _assert_not_live(pinned)
    _assert_not_live(attestation)
    pinned.write_text("live-public-material\n", encoding="utf-8")
    before = pinned.read_bytes()
    attestation.write_text(
        json.dumps({"host_fingerprint": "comms01-comms-01"}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match=ALLOW_LIVE_TRUST_MUTATION_ENV):
        begin_pinned_trust_session((str(pinned),), attestation, {})
        pinned.write_text("pytest-should-not-run\n", encoding="utf-8")
    assert pinned.read_bytes() == before


def test_begin_session_warns_when_allow_env_on_live_fingerprint(
    tmp_path: Path,
) -> None:
    pinned = tmp_path / "operator-keys.json"
    attestation = tmp_path / "attestation.json"
    _assert_not_live(pinned)
    _assert_not_live(attestation)
    pinned.write_text("live-public-material\n", encoding="utf-8")
    attestation.write_text(
        json.dumps({"host_fingerprint": "comms01-comms-01"}) + "\n",
        encoding="utf-8",
    )
    with pytest.warns(RuntimeWarning, match=ALLOW_LIVE_TRUST_MUTATION_ENV):
        snapshot = begin_pinned_trust_session(
            (str(pinned),),
            attestation,
            {ALLOW_LIVE_TRUST_MUTATION_ENV: "1"},
        )
    assert snapshot[0].existed is True
    assert snapshot[0].data == b"live-public-material\n"


@pytest.mark.skipif(os.geteuid() != 0, reason="uid/gid restore requires root")
def test_restore_uid_gid_when_root(tmp_path: Path) -> None:
    target = tmp_path / "owned.txt"
    _assert_not_live(target)
    target.write_text("owned\n", encoding="utf-8")
    os.chown(target, 0, 0)
    snapshot = snapshot_pinned_trust_files((str(target),))
    target.write_text("clobbered\n", encoding="utf-8")
    restore_pinned_trust_files(snapshot)
    info = target.stat()
    assert info.st_uid == 0
    assert info.st_gid == 0
    assert target.read_text(encoding="utf-8") == "owned\n"
