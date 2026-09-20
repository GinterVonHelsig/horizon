"""Worker ParentController binds epoch from active controller lease, not acquire."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from parent_controller import ParentController


def test_dt_to_float_accepts_iso_timestamp_strings(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    with patch("parent_controller.PostgresRepository"):
        controller = ParentController(
            "postgresql://top_delivery_workflow@127.0.0.1:5432/top_delivery_control_p1",
            artifact_root=artifact_root,
            lease_holder=False,
        )
    parsed = controller._dt_to_float("2026-08-24T06:59:00+00:00")
    assert parsed > 0


def test_worker_mode_follows_controller_epoch_bump(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    repo = MagicMock()
    repo.current_epoch.side_effect = [(7, "supervisor-owner", True), (8, "supervisor-owner", True)]
    with patch("parent_controller.PostgresRepository", return_value=repo):
        controller = ParentController(
            "postgresql://top_delivery_workflow@127.0.0.1:5432/top_delivery_control_p1",
            artifact_root=artifact_root,
            lease_holder=False,
        )
    assert controller.controller_epoch("run-1") == 7
    assert controller.controller_epoch("run-1") == 8
    repo.acquire_controller.assert_not_called()


def test_lease_holder_mode_raises_when_controller_epoch_superseded(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    repo = MagicMock()
    repo.acquire_controller.return_value = 3
    repo.current_epoch.return_value = (4, "parent-controller-owner", True)
    with patch("parent_controller.PostgresRepository", return_value=repo):
        controller = ParentController(
            "postgresql://top_delivery_workflow@127.0.0.1:5432/top_delivery_control_p1",
            artifact_root=artifact_root,
            lease_holder=True,
            controller_owner="parent-controller-owner",
        )
    controller._epochs["run-1"] = 3
    with pytest.raises(PermissionError, match="controller epoch was superseded"):
        controller.controller_epoch("run-1")
