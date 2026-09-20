"""Tests for parent_controller reclaimed cleanup failure surfacing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from parent_controller import ParentController


def test_claim_next_emits_cleanup_failed_when_reclaimed_cleanup_raises(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    repo = MagicMock()
    repo.claim_next.return_value = {
        "needs_cleanup": True,
        "attempt_id": "attempt-1",
        "task_id": "task-1",
    }
    repo.current_epoch.return_value = (1, "owner", True)
    repo.idempotent_cleanup.side_effect = RuntimeError("cleanup boom")
    emitted: list[tuple[str, str, dict[str, object]]] = []

    def capture_emit(run_id: str, event_type: str, detail: dict[str, object]) -> object:
        emitted.append((run_id, event_type, detail))
        return MagicMock()

    with patch("parent_controller.PostgresRepository", return_value=repo):
        controller = ParentController(
            "postgresql://top_delivery_workflow@127.0.0.1:5432/top_delivery_control_p1",
            artifact_root=artifact_root,
            lease_holder=False,
        )
    controller.emit = capture_emit  # type: ignore[method-assign]
    controller._epochs["run-1"] = 1

    claimed = controller.claim_next("run-1", "worker")
    assert claimed is None
    assert emitted == [
        (
            "run-1",
            "cleanup_failed",
            {
                "attempt_id": "attempt-1",
                "task_id": "task-1",
                "phase": "claim_next",
                "error": "RuntimeError",
            },
        )
    ]
