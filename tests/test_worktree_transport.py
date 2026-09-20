"""Tests for clean worktree transport."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from worktree_transport import WorktreeTransport, WritingLeaseRequiredError


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _init_repo(path: Path) -> tuple[str, str]:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")
    (path / "README.md").write_text("base\n")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "base")
    base_sha = _git(path, "rev-parse", "HEAD")
    (path / "README.md").write_text("base\nfeature\n")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "feature")
    head_sha = _git(path, "rev-parse", "HEAD")
    return base_sha, head_sha


def test_dirty_user_checkout_is_not_mutated_and_attempt_uses_fresh_worktree(tmp_path: Path) -> None:
    source = tmp_path / "source"
    base_sha, _ = _init_repo(source)
    dirty = tmp_path / "dirty-checkout"
    subprocess.run(["cp", "-a", str(source) + "/.", str(dirty)], check=True)
    (dirty / "local-only.txt").write_text("do not transport\n")
    before_status = _git(dirty, "status", "--porcelain")

    transport = WorktreeTransport(mirror_root=tmp_path / "mirror", repo_name="demo")
    transport.initialize_mirror(source)
    evidence = transport.capture_dirty_checkout_evidence(dirty)
    attempt = transport.create_attempt_worktree(attempt_id="attempt-1", base_sha=base_sha)

    after_status = _git(dirty, "status", "--porcelain")
    assert evidence.dirty is True
    assert before_status == after_status
    assert Path(attempt.worktree_path).exists()
    assert _git(Path(attempt.worktree_path), "rev-parse", "HEAD") == base_sha


def test_conflict_regenerates_clean_candidate(tmp_path: Path) -> None:
    source = tmp_path / "source"
    base_sha, head_sha = _init_repo(source)
    transport = WorktreeTransport(mirror_root=tmp_path / "mirror", repo_name="demo")
    transport.initialize_mirror(source)
    patch = b"--- /dev/null\n+++ b/transport.txt\n@@ -0,0 +1 @@\n+transport\n"

    first = transport.regenerate_candidate_on_conflict(
        attempt_id="attempt-1",
        new_base_sha=base_sha,
        patch_bytes=patch,
        branch="transport/attempt-1",
        writing_agent="worker-1",
    )
    second = transport.regenerate_candidate_on_conflict(
        attempt_id="attempt-1",
        new_base_sha=head_sha,
        patch_bytes=patch,
        branch="transport/attempt-1",
        writing_agent="worker-1",
    )
    assert first.regenerated is True
    assert second.regenerated is True
    assert second.base_sha == head_sha
    assert second.candidate_sha != first.candidate_sha


def test_writing_agent_lease_serializes_writes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    base_sha, _ = _init_repo(source)
    transport = WorktreeTransport(mirror_root=tmp_path / "mirror", repo_name="demo")
    transport.initialize_mirror(source)
    transport.acquire_writing_lease("worker-1")
    with pytest.raises(WritingLeaseRequiredError):
        transport.acquire_writing_lease("worker-2")
