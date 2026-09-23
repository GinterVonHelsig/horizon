"""Durable goal-state persistence under the controller artifact root."""

from __future__ import annotations

import json
import os
import fcntl
from contextlib import contextmanager
from pathlib import Path

from goal_states import ACTIVE, WAITING_OPERATOR, validate_goal_state

GOAL_STATE_FILENAME = "goal-state.json"
# Whole-run pause only. HARD_BLOCKED_PATH isolates one path; independent
# workstreams must remain claimable (plan §5).
PAUSED_GOAL_STATES = frozenset({WAITING_OPERATOR})


class GoalStateStore:
    """Read and write per-run goal state from artifact files."""

    def __init__(self, artifact_root: Path) -> None:
        self._artifact_root = Path(artifact_root).resolve()

    def _path(self, run_id: str) -> Path:
        return self._artifact_root / "runs" / run_id / GOAL_STATE_FILENAME

    def read(self, run_id: str) -> str:
        path = self._path(run_id)
        if not path.is_file():
            return ACTIVE
        payload = json.loads(path.read_text())
        state = str(payload.get("state", ACTIVE))
        return validate_goal_state(state)

    def write(self, run_id: str, state: str) -> None:
        with self.lock(run_id):
            self._write_locked(run_id,state)

    @contextmanager
    def lock(self,run_id):
        directory=self._path(run_id).parent
        directory.mkdir(parents=True,exist_ok=True)
        if any(p.is_symlink() for p in (directory,*directory.parents)):
            raise ValueError("goal state directory symlink")
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _write_locked(self,run_id,state):
        validate_goal_state(state)
        path = self._path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"w") as stream:
            stream.write(json.dumps({"run_id": run_id, "state": state}, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        tmp.replace(path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)

    def is_paused(self, run_id: str) -> bool:
        return self.read(run_id) in PAUSED_GOAL_STATES
