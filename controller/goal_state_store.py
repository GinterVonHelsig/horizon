"""Durable goal-state persistence under the controller artifact root."""

from __future__ import annotations

import json
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
        validate_goal_state(state)
        path = self._path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"run_id": run_id, "state": state}, indent=2, sort_keys=True) + "\n")
        tmp.replace(path)

    def is_paused(self, run_id: str) -> bool:
        return self.read(run_id) in PAUSED_GOAL_STATES
