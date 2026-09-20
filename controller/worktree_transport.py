"""Controller-owned clean worktree transport with lease-gated writes."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

DEFAULT_MIRROR_ROOT = Path("/var/lib/top-delivery")


class GitCommandRunner(Protocol):
    def run(self, argv: list[str], *, cwd: Path | None = None) -> str: ...


def _default_git_runner(argv: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


@dataclass(frozen=True)
class DirtyCheckoutEvidence:
    path: str
    head_sha: str
    dirty: bool
    status_sha256: str


@dataclass(frozen=True)
class WorktreeAttempt:
    attempt_id: str
    base_sha: str
    worktree_path: str
    tree_sha: str


@dataclass(frozen=True)
class TransportReceipt:
    base_sha: str
    candidate_sha: str
    tree_sha: str
    patch_sha: str
    merge_sha: str | None
    branch: str
    regenerated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha,
            "tree_sha": self.tree_sha,
            "patch_sha": self.patch_sha,
            "merge_sha": self.merge_sha,
            "branch": self.branch,
            "regenerated": self.regenerated,
        }


class WritingLeaseRequiredError(PermissionError):
    pass


class WorktreeTransport:
  """Maintain a controller-owned mirror and fresh attempt worktrees."""

  def __init__(
      self,
      *,
      mirror_root: Path = DEFAULT_MIRROR_ROOT,
      repo_name: str,
      git_runner: Callable[..., str] | None = None,
  ) -> None:
      self._mirror_root = Path(mirror_root)
      self._repo_name = repo_name
      self._git = git_runner or _default_git_runner
      self._mirror_path = self._mirror_root / f"{repo_name}.git"
      self._worktrees_root = self._mirror_root / repo_name / "worktrees"
      self._writing_agent: str | None = None
      self._lease_path = self._mirror_root / repo_name / "writing-lease.json"

  @property
  def mirror_path(self) -> Path:
      return self._mirror_path

  def capture_dirty_checkout_evidence(self, checkout_path: Path) -> DirtyCheckoutEvidence:
      checkout = checkout_path.resolve()
      head = self._git(["git", "rev-parse", "HEAD"], cwd=checkout)
      status = self._git(["git", "status", "--porcelain"], cwd=checkout)
      dirty = bool(status.strip())
      digest = hashlib.sha256(status.encode("utf-8")).hexdigest()
      return DirtyCheckoutEvidence(
          path=str(checkout),
          head_sha=head,
          dirty=dirty,
          status_sha256=digest,
      )

  def initialize_mirror(self, source_repo: Path) -> None:
      self._mirror_root.mkdir(parents=True, exist_ok=True)
      if not self._mirror_path.exists():
          self._git(
              ["git", "clone", "--bare", str(source_repo.resolve()), str(self._mirror_path)]
          )
      self._worktrees_root.mkdir(parents=True, exist_ok=True)

  def refresh_authoritative_base(self, base_sha: str) -> str:
      self._git(["git", "fetch", "--all"], cwd=self._mirror_path)
      self._git(["git", "update-ref", "refs/heads/authoritative-base", base_sha], cwd=self._mirror_path)
      return base_sha

  def acquire_writing_lease(self, agent_id: str) -> None:
      persisted = self._read_persisted_lease()
      if persisted and persisted != agent_id:
          raise WritingLeaseRequiredError("writing_agent lease is held by another agent")
      if self._writing_agent and self._writing_agent != agent_id:
          raise WritingLeaseRequiredError("writing_agent lease is held by another agent")
      self._writing_agent = agent_id
      self._write_persisted_lease(agent_id)

  def release_writing_lease(self, agent_id: str) -> None:
      persisted = self._read_persisted_lease()
      if persisted != agent_id and self._writing_agent != agent_id:
          raise WritingLeaseRequiredError("writing_agent lease is not held by this agent")
      self._writing_agent = None
      self._clear_persisted_lease()

  def _read_persisted_lease(self) -> str | None:
      if not self._lease_path.is_file():
          return None
      payload = json.loads(self._lease_path.read_text())
      agent = payload.get("writing_agent")
      return str(agent) if isinstance(agent, str) and agent else None

  def _write_persisted_lease(self, agent_id: str) -> None:
      self._lease_path.parent.mkdir(parents=True, exist_ok=True)
      tmp = self._lease_path.with_suffix(".tmp")
      tmp.write_text(json.dumps({"writing_agent": agent_id}, indent=2, sort_keys=True) + "\n")
      tmp.replace(self._lease_path)

  def _clear_persisted_lease(self) -> None:
      if self._lease_path.is_file():
          self._lease_path.unlink()

  def create_attempt_worktree(self, *, attempt_id: str, base_sha: str) -> WorktreeAttempt:
      attempt_dir = self._worktrees_root / attempt_id
      if attempt_dir.exists():
          raise ValueError("attempt worktree already exists")
      self.refresh_authoritative_base(base_sha)
      self._git(
          [
              "git",
              "worktree",
              "add",
              "--detach",
              str(attempt_dir),
              base_sha,
          ],
          cwd=self._mirror_path,
      )
      tree_sha = self._git(["git", "rev-parse", f"{base_sha}^{{tree}}"], cwd=attempt_dir)
      return WorktreeAttempt(
          attempt_id=attempt_id,
          base_sha=base_sha,
          worktree_path=str(attempt_dir),
          tree_sha=tree_sha,
      )

  def transport_patch(
      self,
      *,
      attempt: WorktreeAttempt,
      patch_bytes: bytes,
      branch: str,
      writing_agent: str,
  ) -> TransportReceipt:
      self.acquire_writing_lease(writing_agent)
      try:
          attempt_dir = Path(attempt.worktree_path)
          patch_sha = hashlib.sha256(patch_bytes).hexdigest()
          patch_path = attempt_dir / ".transport.patch"
          patch_path.write_bytes(patch_bytes)
          self._git(["git", "checkout", "-B", branch], cwd=attempt_dir)
          self._git(["git", "apply", str(patch_path)], cwd=attempt_dir)
          self._git(["git", "add", "-A"], cwd=attempt_dir)
          self._git(["git", "commit", "-m", f"transport {attempt.attempt_id}"], cwd=attempt_dir)
          candidate_sha = self._git(["git", "rev-parse", "HEAD"], cwd=attempt_dir)
          tree_sha = self._git(["git", "rev-parse", "HEAD^{tree}"], cwd=attempt_dir)
          return TransportReceipt(
              base_sha=attempt.base_sha,
              candidate_sha=candidate_sha,
              tree_sha=tree_sha,
              patch_sha=patch_sha,
              merge_sha=None,
              branch=branch,
              regenerated=False,
          )
      finally:
          self.release_writing_lease(writing_agent)

  def regenerate_candidate_on_conflict(
      self,
      *,
      attempt_id: str,
      new_base_sha: str,
      patch_bytes: bytes,
      branch: str,
      writing_agent: str,
  ) -> TransportReceipt:
      stale = self._worktrees_root / attempt_id
      if stale.exists():
          self._git(["git", "worktree", "remove", "--force", str(stale)], cwd=self._mirror_path)
      attempt = self.create_attempt_worktree(attempt_id=attempt_id, base_sha=new_base_sha)
      receipt = self.transport_patch(
          attempt=attempt,
          patch_bytes=patch_bytes,
          branch=branch,
          writing_agent=writing_agent,
      )
      return TransportReceipt(
          base_sha=receipt.base_sha,
          candidate_sha=receipt.candidate_sha,
          tree_sha=receipt.tree_sha,
          patch_sha=receipt.patch_sha,
          merge_sha=receipt.merge_sha,
          branch=receipt.branch,
          regenerated=True,
      )

  def write_transport_receipt(self, artifact_dir: Path, receipt: TransportReceipt) -> Path:
      artifact_dir.mkdir(parents=True, exist_ok=True)
      path = artifact_dir / "transport-receipt.json"
      path.write_text(json.dumps(receipt.to_dict(), indent=2, sort_keys=True) + "\n")
      return path
