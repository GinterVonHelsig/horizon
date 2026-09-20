"""Tests for artifact ownership on goal submit."""

from __future__ import annotations

import os
import pwd
from pathlib import Path

from artifact_owner import apply_artifact_owner


def test_apply_artifact_owner_chowns_tree_when_configured(tmp_path: Path, monkeypatch) -> None:
    owner = pwd.getpwuid(os.geteuid())
    run_dir = tmp_path / "runs" / "goal-test"
    run_dir.mkdir(parents=True)
    child = run_dir / "goal-spec.json"
    child.write_text("{}\n")
    monkeypatch.setenv("TOP_DELIVERY_ARTIFACT_OWNER", owner.pw_name)
    apply_artifact_owner(run_dir, recursive=True)
    stat = child.stat()
    assert stat.st_uid == owner.pw_uid
    assert stat.st_gid == owner.pw_gid
