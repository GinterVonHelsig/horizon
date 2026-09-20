"""Regression tests for worker/controller artifact-root rebinding."""

from __future__ import annotations

from pathlib import Path

import os
import pytest

from artifact_isolation import resolve_run_artifact_root
from parent_controller import ParentController
from worker import TaskWorker


def _controller(db_url: str, artifact_root: Path, **kwargs) -> ParentController:
    return ParentController(db_url, artifact_root=artifact_root, lease_holder=True, **kwargs)


def test_rebind_artifact_root_allows_dedicated_run_evidence(
    db_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs_root = tmp_path / "runs"
    monkeypatch.setattr(
        "artifact_isolation.DEFAULT_RUNS_ROOT",
        runs_root,
    )
    parent_run = "goal-parent-configured"
    child_run = "goal-child-dedicated"
    configured = runs_root / parent_run / "artifacts"
    configured.mkdir(parents=True)
    dedicated = resolve_run_artifact_root(child_run, configured, runs_root=runs_root)
    dedicated.mkdir(parents=True)

    relative = f"runs/{child_run}/attempts/attempt-1/executor/stdout.txt"
    stdout = dedicated / relative
    stdout.parent.mkdir(parents=True)
    stdout.write_text("executor lane\n", encoding="utf-8")

    controller = _controller(db_url, configured)
    controller.register_run(child_run)
    with pytest.raises(FileNotFoundError):
        controller.record_evidence(
            child_run,
            relative,
            producer="executor",
            result="pass",
        )

    controller.rebind_artifact_root(dedicated)
    evidence_id = controller.record_evidence(
        child_run,
        relative,
        producer="executor",
        result="pass",
    )
    assert evidence_id
    rows = controller.evidence(child_run)
    assert len(rows) == 1
    assert rows[0]["artifact_path"] == relative
    assert not (configured / relative).exists()
    assert stdout.exists()
    controller.close()


def test_rebind_noop_when_same_root(db_url: str, tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.rebind_artifact_root(artifact_root)
    assert controller.artifact_root == artifact_root.resolve()
    controller.close()


def test_rebind_sets_top_delivery_artifact_root_env(
    db_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs_root = tmp_path / "runs"
    monkeypatch.setattr(
        "artifact_isolation.DEFAULT_RUNS_ROOT",
        runs_root,
    )
    configured = runs_root / "goal-parent" / "artifacts"
    configured.mkdir(parents=True)
    dedicated = runs_root / "goal-child" / "artifacts"
    dedicated.mkdir(parents=True)
    monkeypatch.setenv("TOP_DELIVERY_ARTIFACT_ROOT", str(configured))

    controller = _controller(db_url, configured)
    controller.rebind_artifact_root(dedicated)
    assert os.environ["TOP_DELIVERY_ARTIFACT_ROOT"] == str(dedicated.resolve())
    controller.close()


def test_prepare_run_root_rebinds_controller_for_cross_run_child(
    db_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs_root = tmp_path / "runs"
    monkeypatch.setattr(
        "artifact_isolation.DEFAULT_RUNS_ROOT",
        runs_root,
    )
    parent_run = "goal-parent-configured"
    child_run = "goal-child-dedicated"
    configured = runs_root / parent_run / "artifacts"
    configured.mkdir(parents=True)

    controller = _controller(db_url, configured)
    worker = TaskWorker(controller, configured, {})  # type: ignore[arg-type]

    def _resolve(run_id: str, configured_root: Path, *, runs_root: Path = runs_root) -> Path:
        return resolve_run_artifact_root(run_id, configured_root, runs_root=runs_root)

    monkeypatch.setattr("worker.resolve_run_artifact_root", _resolve)
    worker._prepare_run_root(child_run)

    assert worker._artifact_root == resolve_run_artifact_root(
        child_run, configured, runs_root=runs_root,
    )
    assert controller.artifact_root == worker._artifact_root
    controller.close()
