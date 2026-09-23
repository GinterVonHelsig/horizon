"""Focused tests for p40 same-parent root-cause repair."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pwd
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from artifact_isolation import resolve_run_artifact_root
from artifact_owner import apply_artifact_owner
from goal_dependencies import goal_spec_for_task, ready_successor_workstreams
from goal_submitter import GoalSubmitter
from prompt_ingest import parse_prompt_bytes
from submission_bundle import (
    SubmissionBundleError,
    publish_parent_bound_submission_bundle,
    resolve_bound_goal_spec_path,
)
from worker import TaskWorker, WorkerLoop


PARENT_RUN_ID = "goal-3eb7b972ec15809e"
HISTORICAL_CONFIGURED_PARENT = "goal-874aaaaaaaaaaaaa"


@pytest.fixture(autouse=True)
def no_host_trusted_store_in_tests(tmp_path: Path, monkeypatch):
    # A forgotten privileged fixture must fail at /tmp's trust boundary, never
    # publish unit-test authority to the real host runtime store. Explicit real
    # permission fixtures override this with their exclusive /var/lib directory.
    monkeypatch.setattr("submission_bundle.TRUSTED_BUNDLES_ROOT",
                        tmp_path / "REQUIRES_EXPLICIT_TRUSTED_FIXTURE")
    # P43 covers dependency closure independently; these P40 unit tests must not
    # inspect the host's systemd graph or external P43 acceptance anchors.
    monkeypatch.setattr("recovery_dependencies.verify_dependencies", lambda: None)


def _two_step_text(title: str) -> str:
    return (
        f"# {title}\n\n"
        f"**Objective:** {title} objective.\n\n"
        "## Mission\n\n"
        f"Mission for {title}.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n\n"
        "## Ordered workstreams\n\n"
        "### 1. First slice\n\n"
        "### 2. Second slice\n\n"
        "## Cross-workstream acceptance matrix\n\n"
        "| Item | Required terminal disposition |\n"
        "|---|---|\n"
        "| 1. First | `PASS/ONE` |\n"
        "| 2. Second | `PASS/TWO` |\n"
    )


def _two_step_prompt(tmp_path: Path, title: str) -> Path:
    path = tmp_path / f"{title}.md"
    path.write_text(_two_step_text(title))
    return path


def _submission_run_id(title: str) -> str:
    return "goal-" + hashlib.sha256(_two_step_text(title).encode()).hexdigest()[:16]


def _write_submission_spec(
    artifact_root: Path,
    submission_run_id: str,
    *,
    title: str,
) -> tuple[Path, list[str], str]:
    run_dir = artifact_root / "runs" / submission_run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    snapshot_text = _two_step_text(title)
    parsed = parse_prompt_bytes(snapshot_text.encode(), source=str(run_dir / "prompt.snapshot.md"))
    assert submission_run_id == parsed.run_id
    task_ids = [workstream.task_id for workstream in parsed.workstreams]
    prompt_digest = parsed.sha256
    spec = {
        "run_id": submission_run_id,
        "prompt_digest": prompt_digest,
        "title": title,
        "objective": parsed.objective,
        "mission": parsed.mission,
        "allowed": list(parsed.allowed),
        "forbidden": list(parsed.forbidden),
        "byte_count": parsed.byte_count,
        "source": parsed.source,
        "workstreams": [
            {
                "number": workstream.number,
                "title": workstream.title,
                "task_id": workstream.task_id,
                "dependencies": list(workstream.dependencies),
                "required_disposition": workstream.required_disposition,
                "prompt": snapshot_text,
                "timeout_seconds": 1800,
                "acceptance_criteria": [workstream.required_disposition],
                "executor_adapter": "executor",
                "auditor_adapter": "auditor",
            }
            for workstream in parsed.workstreams
        ],
    }
    snapshot = run_dir / "prompt.snapshot.md"
    snapshot.write_text(snapshot_text)
    spec_path = run_dir / "goal-spec.json"
    spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    return run_dir, task_ids, prompt_digest


@dataclass
class TrackingController:
    registered_runs: list[str] = field(default_factory=list)
    scheduled: list[tuple[str, str, str, int]] = field(default_factory=list)
    existing_tasks: set[str] = field(default_factory=set)
    artifact_root: Path | None = None

    def register_run(self, run_id: str, state: str = "active") -> None:
        if run_id not in self.registered_runs:
            self.registered_runs.append(run_id)

    def schedule_task(
        self,
        run_id: str,
        task_id: str,
        objective: str,
        *,
        priority: int = 0,
        available_at: float | None = None,
    ) -> dict[str, object]:
        created = task_id not in self.existing_tasks
        if created:
            self.existing_tasks.add(task_id)
        self.scheduled.append((run_id, task_id, objective, priority))
        return {"run_id": run_id, "task_id": task_id, "created": created}


def test_existing_parent_publishes_bound_bundle_before_schedule(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    prompt = _two_step_prompt(tmp_path, "p35-bound")
    controller = TrackingController()
    controller.register_run(PARENT_RUN_ID)
    submitter = GoalSubmitter(controller, artifact_root, mode="dry_run")

    receipt = submitter.submit(prompt, existing_parent=PARENT_RUN_ID)

    bundle_dir = artifact_root / "runs" / PARENT_RUN_ID / "submissions" / receipt.submission_run_id
    binding = json.loads((bundle_dir / "binding.json").read_text())
    assert binding["parent_run_id"] == PARENT_RUN_ID
    assert binding["submission_run_id"] == receipt.submission_run_id
    assert binding["schema_version"] == 1
    assert controller.scheduled[0][0] == PARENT_RUN_ID
    assert (bundle_dir / "goal-spec.json").is_file()
    assert (bundle_dir / "prompt.snapshot.md").is_file()


def test_submit_publishes_to_controller_runtime_root_not_invocation_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trusted_submission,
) -> None:
    runs_root = tmp_path / "var/lib/top-delivery/runs"
    monkeypatch.setattr("artifact_isolation.DEFAULT_RUNS_ROOT", runs_root)
    invocation_root = tmp_path / "harness-artifacts" / "p40"
    invocation_root.mkdir(parents=True)
    configured_root = runs_root / HISTORICAL_CONFIGURED_PARENT / "artifacts"
    configured_root.mkdir(parents=True)
    parent_runtime_root = resolve_run_artifact_root(PARENT_RUN_ID, configured_root, runs_root=runs_root)

    controller = TrackingController(artifact_root=configured_root)
    controller.register_run(PARENT_RUN_ID)
    controller._repo = MagicMock()
    controller._repo.controller_state.return_value = {"state": "active"}
    prompt = _two_step_prompt(tmp_path, "runtime-bound")
    submitter = GoalSubmitter(controller, invocation_root, mode="durable")

    receipt = submitter.submit(prompt, existing_parent=PARENT_RUN_ID)

    bundle_dir = trusted_submission["store"] / "runs" / PARENT_RUN_ID / "submissions" / receipt.submission_run_id
    assert bundle_dir.is_dir()
    assert not (
        invocation_root / "runs" / PARENT_RUN_ID / "submissions" / receipt.submission_run_id
    ).exists()

    worker = TaskWorker(MagicMock(), configured_root, {})  # type: ignore[arg-type]
    monkeypatch.setenv("TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS", "1")
    monkeypatch.setattr(
        "worker.resolve_run_artifact_root",
        lambda run_id, configured, *, runs_root=runs_root: resolve_run_artifact_root(
            run_id, configured, runs_root=runs_root
        ),
    )
    worker._prepare_run_root(PARENT_RUN_ID)
    context = worker._workstream_context(PARENT_RUN_ID, receipt.task_ids[0])
    assert context["task_id"] == receipt.task_ids[0]


def test_publish_bundle_is_idempotent_for_coordinator_replay(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p35")
    run_dir, task_ids, prompt_digest = _write_submission_spec(
        artifact_root, submission_run_id, title="p35"
    )
    first = publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=submission_run_id,
        submission_dir=run_dir,
        task_ids=task_ids,
        prompt_digest=prompt_digest,
    )
    second = publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=submission_run_id,
        submission_dir=run_dir,
        task_ids=task_ids,
        prompt_digest=prompt_digest,
    )
    assert first == second


def test_worker_resolves_bound_workstream_from_parent_artifact_root(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p35")
    run_dir, task_ids, prompt_digest = _write_submission_spec(
        artifact_root, submission_run_id, title="p35"
    )
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=submission_run_id,
        submission_dir=run_dir,
        task_ids=task_ids,
        prompt_digest=prompt_digest,
    )
    worker = TaskWorker(MagicMock(), artifact_root, {})  # type: ignore[arg-type]
    context = worker._workstream_context(PARENT_RUN_ID, task_ids[0])
    assert context["task_id"] == task_ids[0]
    assert context["executor_adapter"] == "executor"


def test_p35_ws01_verified_unlocks_only_its_ws02(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    p35_run = _submission_run_id("p35")
    p35_dir, p35_tasks, prompt_digest = _write_submission_spec(artifact_root, p35_run, title="p35")
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=p35_run,
        submission_dir=p35_dir,
        task_ids=p35_tasks,
        prompt_digest=prompt_digest,
    )
    states = {p35_tasks[0]: "verified"}
    ready = ready_successor_workstreams(artifact_root, PARENT_RUN_ID, p35_tasks[0], states)
    assert [item.task_id for item in ready] == [p35_tasks[1]]


def test_p40_numbering_cannot_cross_unlock_p35(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    p35_run = _submission_run_id("p35")
    p40_run = _submission_run_id("p40")
    p35_dir, p35_tasks, p35_digest = _write_submission_spec(artifact_root, p35_run, title="p35")
    p40_dir, p40_tasks, p40_digest = _write_submission_spec(artifact_root, p40_run, title="p40")
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=p35_run,
        submission_dir=p35_dir,
        task_ids=p35_tasks,
        prompt_digest=p35_digest,
    )
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=p40_run,
        submission_dir=p40_dir,
        task_ids=p40_tasks,
        prompt_digest=p40_digest,
    )
    states = {p35_tasks[0]: "verified", p40_tasks[0]: "queued"}
    ready = ready_successor_workstreams(artifact_root, PARENT_RUN_ID, p35_tasks[0], states)
    assert p40_tasks[1] not in {item.task_id for item in ready}


def test_conflicting_bundle_replay_fails_closed(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p35")
    run_dir, task_ids, prompt_digest = _write_submission_spec(
        artifact_root, submission_run_id, title="p35"
    )
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=submission_run_id,
        submission_dir=run_dir,
        task_ids=task_ids,
        prompt_digest=prompt_digest,
    )
    with pytest.raises(SubmissionBundleError, match="prompt_digest mismatch|conflicting"):
        publish_parent_bound_submission_bundle(
            artifact_root,
            parent_run_id=PARENT_RUN_ID,
            submission_run_id=submission_run_id,
            submission_dir=run_dir,
            task_ids=task_ids,
            prompt_digest="0" * 64,
        )


def test_symlink_binding_for_task_fails_closed(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submissions = artifact_root / "runs" / PARENT_RUN_ID / "submissions" / "goal-3fa391ad04eedbc8"
    submissions.mkdir(parents=True)
    outside = tmp_path / "outside-binding.json"
    outside.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "parent_run_id": PARENT_RUN_ID,
                "submission_run_id": "goal-3fa391ad04eedbc8",
                "prompt_digest": "abc",
                "task_ids": ["goal-3fa391ad04eedbc8-ws-01"],
                "goal_spec_digest": "abc",
                "prompt_snapshot_digest": "abc",
            }
        )
        + "\n"
    )
    (submissions / "binding.json").symlink_to(outside)
    with pytest.raises(SubmissionBundleError, match="symlink"):
        resolve_bound_goal_spec_path(
            artifact_root, PARENT_RUN_ID, "goal-3fa391ad04eedbc8-ws-01"
        )


def test_corrupt_binding_for_task_does_not_fall_back_to_parent_graph(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    parent_dir = artifact_root / "runs" / PARENT_RUN_ID
    parent_dir.mkdir(parents=True)
    (parent_dir / "goal-spec.json").write_text(
        json.dumps(
            {
                "run_id": PARENT_RUN_ID,
                "workstreams": [
                    {
                        "number": 1,
                        "title": "wrong",
                        "task_id": "goal-3fa391ad04eedbc8-ws-01",
                        "dependencies": [],
                        "required_disposition": "PASS",
                    }
                ],
            }
        )
        + "\n"
    )
    bundle_dir = parent_dir / "submissions" / "goal-3fa391ad04eedbc8"
    bundle_dir.mkdir(parents=True)
    (bundle_dir / "binding.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "parent_run_id": PARENT_RUN_ID,
                "submission_run_id": "goal-3fa391ad04eedbc8",
                "prompt_digest": "deadbeef",
                "task_ids": ["goal-3fa391ad04eedbc8-ws-01"],
                "goal_spec_digest": "deadbeef",
                "prompt_snapshot_digest": "deadbeef",
            }
        )
        + "\n"
    )
    with pytest.raises(SubmissionBundleError):
        goal_spec_for_task(artifact_root, PARENT_RUN_ID, "goal-3fa391ad04eedbc8-ws-01")


def test_unbound_parent_goal_spec_still_works(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    run_id = "goal-0000000000000001"
    run_dir = artifact_root / "runs" / run_id
    run_dir.mkdir(parents=True)
    spec = {
        "run_id": run_id,
        "workstreams": [
            {
                "number": 1,
                "title": "only",
                "task_id": f"{run_id}-ws-01",
                "dependencies": [],
                "required_disposition": "PASS",
            }
        ],
    }
    (run_dir / "goal-spec.json").write_text(json.dumps(spec) + "\n")
    loaded = goal_spec_for_task(artifact_root, run_id, f"{run_id}-ws-01")
    assert loaded["run_id"] == run_id


@pytest.mark.parametrize("damage", ["missing_bundle", "missing_binding", "removed_task"])
def test_missing_target_binding_never_schedules_parent_successors(
    tmp_path: Path, damage: str,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p35")
    run_dir, task_ids, prompt_digest = _write_submission_spec(
        artifact_root, submission_run_id, title="p35"
    )
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=submission_run_id,
        submission_dir=run_dir,
        task_ids=task_ids,
        prompt_digest=prompt_digest,
    )
    parent_dir = artifact_root / "runs" / PARENT_RUN_ID
    parent_tasks = [f"{PARENT_RUN_ID}-ws-01", f"{PARENT_RUN_ID}-ws-02"]
    (parent_dir / "goal-spec.json").write_text(json.dumps({
        "run_id": PARENT_RUN_ID,
        "workstreams": [
            {"number": 1, "title": "parent first", "task_id": parent_tasks[0],
             "dependencies": [], "required_disposition": "PASS/PARENT_ONE"},
            {"number": 2, "title": "unrelated parent successor", "task_id": parent_tasks[1],
             "dependencies": [1], "required_disposition": "PASS/PARENT_TWO"},
        ],
    }))
    bundle_dir = parent_dir / "submissions" / submission_run_id
    binding_path = bundle_dir / "binding.json"
    if damage == "missing_bundle":
        bundle_dir.rename(tmp_path / "preserved-bundle")
    elif damage == "missing_binding":
        binding_path.rename(tmp_path / "preserved-binding.json")
    else:
        binding = json.loads(binding_path.read_text())
        binding["task_ids"].remove(task_ids[0])
        binding_path.write_text(json.dumps(binding))

    states = {task_ids[0]: "verified", parent_tasks[0]: "verified"}
    with pytest.raises(SubmissionBundleError):
        goal_spec_for_task(artifact_root, PARENT_RUN_ID, task_ids[0])
    with pytest.raises(SubmissionBundleError):
        ready_successor_workstreams(artifact_root, PARENT_RUN_ID, task_ids[0], states)


def test_completed_task_must_belong_to_the_selected_goal_graph(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p35")
    _, task_ids, _ = _write_submission_spec(artifact_root, submission_run_id, title="p35")
    unrelated_task = f"{submission_run_id}-ws-99"
    states = {task_ids[0]: "verified", unrelated_task: "verified"}
    with pytest.raises(ValueError, match="completed task"):
        ready_successor_workstreams(artifact_root, submission_run_id, unrelated_task, states)


@pytest.mark.parametrize("damage", ["invalid_json", "unreadable"])
def test_unrelated_broken_binding_does_not_block_valid_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p40")
    run_dir, task_ids, prompt_digest = _write_submission_spec(
        artifact_root, submission_run_id, title="p40"
    )
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=submission_run_id,
        submission_dir=run_dir,
        task_ids=task_ids,
        prompt_digest=prompt_digest,
    )
    sibling = artifact_root / "runs" / PARENT_RUN_ID / "submissions" / "goal-0000000000000000"
    sibling.mkdir()
    sibling_binding = sibling / "binding.json"
    sibling_binding.write_text("broken-json" if damage == "invalid_json" else "{}")
    original_read_text = Path.read_text
    unrelated_reads: list[Path] = []

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == sibling_binding:
            unrelated_reads.append(path)
            if damage == "unreadable":
                raise PermissionError("unreadable historical sibling")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    loaded = goal_spec_for_task(artifact_root, PARENT_RUN_ID, task_ids[0])
    assert loaded["run_id"] == submission_run_id
    assert unrelated_reads == []
    ready = ready_successor_workstreams(
        artifact_root, PARENT_RUN_ID, task_ids[0], {task_ids[0]: "verified"}
    )
    assert [workstream.task_id for workstream in ready] == [task_ids[1]]


@pytest.mark.parametrize("location", ["source", "published_bundle"])
@pytest.mark.parametrize("field,value", [
    ("title", "unauthorized replacement workstream"),
    ("number", 99),
    ("task_id", "replacement"),
    ("dependencies", [2]),
    ("required_disposition", "PASS/UNREVIEWED"),
    ("prompt", "A different authority prompt"),
    ("acceptance_criteria", ["PASS/UNREVIEWED"]),
])
def test_rehashed_graph_mutation_cannot_replace_prompt_derived_authority(
    tmp_path: Path, location: str, field: str, value: object,
) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p35")
    run_dir, task_ids, prompt_digest = _write_submission_spec(
        artifact_root, submission_run_id, title="p35"
    )
    if location == "published_bundle":
        publish_parent_bound_submission_bundle(
            artifact_root,
            parent_run_id=PARENT_RUN_ID,
            submission_run_id=submission_run_id,
            submission_dir=run_dir,
            task_ids=task_ids,
            prompt_digest=prompt_digest,
        )
        target_dir = artifact_root / "runs" / PARENT_RUN_ID / "submissions" / submission_run_id
    else:
        target_dir = run_dir
    spec_path = target_dir / "goal-spec.json"
    spec = json.loads(spec_path.read_text())
    if field == "task_id":
        value = f"{submission_run_id}-ws-99"
        task_ids[0] = value
    spec["workstreams"][0][field] = value
    spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    if location == "published_bundle":
        binding_path = target_dir / "binding.json"
        binding = json.loads(binding_path.read_text())
        binding["goal_spec_digest"] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
        binding["task_ids"] = task_ids
        binding_path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n")
        with pytest.raises(SubmissionBundleError):
            goal_spec_for_task(artifact_root, PARENT_RUN_ID, task_ids[0])
    else:
        with pytest.raises(SubmissionBundleError):
            publish_parent_bound_submission_bundle(
                artifact_root,
                parent_run_id=PARENT_RUN_ID,
                submission_run_id=submission_run_id,
                submission_dir=run_dir,
                task_ids=task_ids,
                prompt_digest=prompt_digest,
            )
        assert not (artifact_root / "runs" / PARENT_RUN_ID / "submissions" / submission_run_id).exists()


def test_snapshot_digest_must_derive_submission_run_identity(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    original_run_id = _submission_run_id("p35")
    run_dir, _, prompt_digest = _write_submission_spec(artifact_root, original_run_id, title="p35")
    arbitrary_run_id = "goal-0000000000000000"
    spec_path = run_dir / "goal-spec.json"
    spec = json.loads(spec_path.read_text())
    spec["run_id"] = arbitrary_run_id
    for workstream in spec["workstreams"]:
        workstream["task_id"] = workstream["task_id"].replace(original_run_id, arbitrary_run_id)
    spec_path.write_text(json.dumps(spec))
    with pytest.raises(SubmissionBundleError):
        publish_parent_bound_submission_bundle(
            artifact_root,
            parent_run_id=PARENT_RUN_ID,
            submission_run_id=arbitrary_run_id,
            submission_dir=run_dir,
            task_ids=[workstream["task_id"] for workstream in spec["workstreams"]],
            prompt_digest=prompt_digest,
        )
    assert not (artifact_root / "runs" / PARENT_RUN_ID / "submissions" / arbitrary_run_id).exists()


@pytest.mark.parametrize("tamper", ["none", "spec_digest", "prompt_digest", "route_after_review"])
def test_recovery_requires_the_original_reviewed_source_hashes(tmp_path: Path, tamper: str,
                                                              trusted_submission, monkeypatch) -> None:
    from submission_bundle import recover_parent_bound_submission_bundle

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("recovery-digest")
    run_dir, task_ids, prompt_digest = _write_submission_spec(
        artifact_root, submission_run_id, title="recovery-digest"
    )
    spec_path = run_dir / "goal-spec.json"
    expected_spec_digest = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    if tamper == "spec_digest":
        expected_spec_digest = "0" * 64
    elif tamper == "prompt_digest":
        prompt_digest = "0" * 64
    elif tamper == "route_after_review":
        spec = json.loads(spec_path.read_text())
        spec["workstreams"][0]["executor_adapter"] = "unreviewed-executor"
        spec_path.write_text(json.dumps(spec))

    def recover() -> object:
        return recover_parent_bound_submission_bundle(
            artifact_root,
            parent_run_id=PARENT_RUN_ID,
            submission_run_id=submission_run_id,
            submission_dir=run_dir,
            task_ids=task_ids,
            prompt_digest=prompt_digest,
            expected_goal_spec_digest=expected_spec_digest,
        )

    monkeypatch.setenv("TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS", "1")
    bundle_dir = trusted_submission["store"] / "runs" / PARENT_RUN_ID / "submissions" / submission_run_id
    if tamper == "none":
        recover()
        loaded = goal_spec_for_task(artifact_root, PARENT_RUN_ID, task_ids[0])
        assert loaded["run_id"] == submission_run_id
        recover()  # Recovery replay remains idempotent against the same reviewed bytes.
    else:
        with pytest.raises(SubmissionBundleError):
            recover()
        assert not bundle_dir.exists()


def test_post_transition_rollback_preserves_graph_and_keeps_incompatible_services_stopped(
    tmp_path: Path,
) -> None:
    from recovery_service_plan import assert_worker_resume_compatible, rollback_service_actions

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p35")
    run_dir, task_ids, prompt_digest = _write_submission_spec(artifact_root, submission_run_id, title="p35")
    bundle = publish_parent_bound_submission_bundle(
        artifact_root, parent_run_id=PARENT_RUN_ID, submission_run_id=submission_run_id,
        submission_dir=run_dir, task_ids=task_ids, prompt_digest=prompt_digest,
    )
    preserved = {path.name: path.read_bytes() for path in bundle.iterdir()}
    states = {task_ids[0]: "verified"}
    ready = ready_successor_workstreams(artifact_root, PARENT_RUN_ID, task_ids[0], states)
    assert [item.task_id for item in ready] == [task_ids[1]]
    states[task_ids[1]] = "queued"
    actions = rollback_service_actions(bound_tasks_transitioned=True)
    assert actions == (("recovery_lifecycle.stop_declared",),
                       ("systemctl", "daemon-reload"))
    assert {path.name: path.read_bytes() for path in bundle.iterdir()} == preserved
    assert states == {task_ids[0]: "verified", task_ids[1]: "queued"}
    with pytest.raises(ValueError):
        assert_worker_resume_compatible(installed_sha="1" * 40, accepted_sha="2" * 40, bundles_valid=True)
    for sha, valid in [("2" * 40, False), ("not-a-sha", True)]:
        with pytest.raises(ValueError):
            assert_worker_resume_compatible(installed_sha=sha, accepted_sha=sha, bundles_valid=valid)
    with pytest.raises(ValueError, match="not a start gate"):
        assert_worker_resume_compatible(installed_sha="2" * 40, accepted_sha="2" * 40, bundles_valid=True)


def test_preclaim_rollback_also_requires_explicit_worker_resume() -> None:
    from recovery_service_plan import rollback_service_actions

    assert rollback_service_actions(bound_tasks_transitioned=False) == (
        ("recovery_lifecycle.stop_declared",),
        ("systemctl", "daemon-reload"),
    )


def test_worker_handoff_lookup_still_works_without_bundle(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    run_id = "goal-1111111111111111"
    handoff_root = artifact_root / "runs" / run_id / "handoffs" / "handoff-1"
    handoff_root.mkdir(parents=True)
    from subworkflow_handoff import build_handoff_request
    request = build_handoff_request(run_id=run_id, parent_task_id=f"{run_id}-ws-01",
        parent_attempt_id="test-attempt", failure_code="BLOCKED_VM9201_DISPOSABLE_SEAM",
        request_artifact_root=f"runs/{run_id}/handoffs")
    (handoff_root / "request.json").write_text(json.dumps(request) + "\n")
    (artifact_root / "runs" / run_id / "goal-spec.json").write_text(
        json.dumps({"run_id": run_id, "workstreams": []}) + "\n"
    )
    worker = TaskWorker(MagicMock(), artifact_root, {})  # type: ignore[arg-type]
    context = worker._workstream_context(run_id, request["provider_task_id"])
    assert context["handoff_id"] == request["handoff_id"]


def test_prepare_run_root_tolerates_root_owned_historical_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    run_id = "goal-2222222222222222"
    attempts = artifact_root / "runs" / run_id / "attempts" / "attempt-old"
    auditor = attempts / "auditor"
    auditor.mkdir(parents=True)
    historical = auditor / "stdout.txt"
    historical.write_text("root-owned evidence\n")
    chown_paths: list[Path] = []

    def _record_chown(path: os.PathLike[str] | str, uid: int, gid: int) -> None:
        resolved = Path(path).resolve()
        chown_paths.append(resolved)
        if resolved == historical.resolve():
            raise PermissionError("EPERM on historical evidence")

    monkeypatch.setattr(os, "chown", _record_chown)
    worker = TaskWorker(MagicMock(), artifact_root, {})  # type: ignore[arg-type]
    worker._prepare_run_root(run_id)
    assert worker._artifact_root == artifact_root.resolve()
    assert historical.resolve() not in chown_paths


def test_apply_artifact_owner_skips_descendants_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "runs" / "goal-test"
    run_dir.mkdir(parents=True)
    child = run_dir / "goal-spec.json"
    child.write_text("{}\n")
    calls: list[str] = []

    def _record_chown(path: Path, uid: int, gid: int) -> None:
        calls.append(Path(path).name)

    monkeypatch.setattr("artifact_owner._chown_if_needed", _record_chown)
    monkeypatch.setenv("TOP_DELIVERY_ARTIFACT_OWNER", os.environ.get("USER", "root"))
    apply_artifact_owner(run_dir)
    assert calls == ["goal-test"]


def test_apply_artifact_owner_chowns_only_target_with_mixed_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("actual mixed-identity ownership setup requires root; covered on Comms-01")
    try:
        service = pwd.getpwnam("topdelivery")
    except KeyError:
        pytest.skip("topdelivery user is not available on this host")
    run_dir = tmp_path / "runs" / "goal-mixed"
    run_dir.mkdir(parents=True)
    child = run_dir / "historical.txt"
    child.write_text("historical\n")
    new_file = run_dir / "fresh.txt"
    new_file.write_text("fresh\n")
    monkeypatch.setenv("TOP_DELIVERY_ARTIFACT_OWNER", "topdelivery")
    apply_artifact_owner(new_file)
    assert child.stat().st_uid != service.pw_uid
    assert new_file.stat().st_uid == service.pw_uid


def test_apply_artifact_owner_propagates_real_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "blocked.txt"
    target.write_text("blocked\n")
    monkeypatch.setenv("TOP_DELIVERY_ARTIFACT_OWNER", os.environ.get("USER", "root"))

    def _raise_io(path: Path, uid: int, gid: int) -> None:
        raise OSError(30, "read-only filesystem")

    monkeypatch.setattr("artifact_owner._chown_if_needed", _raise_io)
    with pytest.raises(OSError, match="read-only filesystem"):
        apply_artifact_owner(target)


def test_worker_loop_logs_permission_error_without_secret_payload(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    worker = MagicMock()
    worker.run_once.side_effect = PermissionError(13, "secret-token must not appear")
    loop = WorkerLoop(worker, run_id="goal-3333333333333333", owner="worker", once=True)
    with caplog.at_level(logging.WARNING):
        succeeded = loop.run()
    assert succeeded is False
    assert loop.permission_error_seen is True
    assert any(
        record.levelname == "WARNING"
        and "category=worker_poll" in record.getMessage()
        and "secret-token" not in record.getMessage()
        and "errno=13" in record.getMessage()
        for record in caplog.records
    )


def test_worker_loop_stops_after_permanent_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = MagicMock()
    calls = 0

    def _run_once(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PermissionError(13, "blocked")
        return None

    worker.run_once.side_effect = _run_once
    loop = WorkerLoop(worker, run_id="goal-4444444444444444", owner="worker", once=False)
    monkeypatch.setattr(loop, "_poll_interval", 0.0)

    def _stop_after_recovery(_seconds: float) -> None:
        if calls >= 2:
            loop._stop = True

    monkeypatch.setattr("worker.time.sleep", _stop_after_recovery)
    assert loop.run() is False
    assert calls == 1
    assert loop.last_status == "blocked:permission_or_ownership"


def test_worker_loop_once_reports_failure_after_permission_error() -> None:
    worker = MagicMock()
    worker.run_once.side_effect = PermissionError(13, "blocked")
    loop = WorkerLoop(worker, run_id="goal-5555555555555555", owner="worker", once=True)
    assert loop.run() is False
    assert loop.permission_error_seen is True


def test_worker_cli_once_exits_nonzero_after_permission_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    worker = MagicMock()
    worker.run_once.side_effect = PermissionError(13, "blocked")
    loop = WorkerLoop(worker, run_id="goal-6666666666666666", owner="worker", once=True)
    monkeypatch.setattr("worker_cli.WorkerLoop", lambda *args, **kwargs: loop)
    monkeypatch.setattr(
        "worker_cli.build_controller",
        lambda *_args, **_kwargs: MagicMock(close=lambda: None),
    )
    monkeypatch.setattr(
        "worker_cli.AdapterRegistry.from_config",
        lambda *args, **kwargs: MagicMock(adapters={}),
    )
    monkeypatch.setattr("worker_cli.load_registry_config", lambda *_a, **_k: {})
    monkeypatch.setattr("worker_cli.load_relay_token", lambda: None)
    from worker_cli import main

    exit_code = main(
        [
            "--artifact-root",
            "/tmp/artifacts",
            "--db-url",
            "postgresql://local/test",
            "--config",
            "/tmp/adapters.json",
            "--once",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    payload = json.loads(captured.out.strip())
    assert payload["status"] == "blocked:permission_or_ownership"
    assert "blocked" in captured.out


def test_goal_cli_durable_existing_parent_uses_runtime_root_for_controller_and_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    trusted_submission,
) -> None:
    invocation_root = tmp_path / "harness-artifacts" / "p40"
    runtime_root = tmp_path / "var" / "lib" / "top-delivery" / "runs" / PARENT_RUN_ID / "artifacts"
    invocation_root.mkdir(parents=True)
    runtime_root.mkdir(parents=True)
    prompt = _two_step_prompt(tmp_path, "cli-runtime-bound")
    controller_roots: list[Path] = []

    class FakeDurableController:
        def __init__(self, _db_url: str, artifact_root: Path, *, dry_run: bool = False) -> None:
            self.artifact_root = Path(artifact_root).resolve()
            controller_roots.append(self.artifact_root)
            self._repo = MagicMock()
            self._repo.controller_state.return_value = {"state": "active"}

        def register_run(self, run_id: str, state: str = "active") -> None:
            return None

        def schedule_task(
            self,
            run_id: str,
            task_id: str,
            objective: str,
            *,
            priority: int = 0,
            available_at: float | None = None,
        ) -> dict[str, object]:
            return {"run_id": run_id, "task_id": task_id, "created": True}

        def close(self) -> None:
            return None

    monkeypatch.setattr("goal_cli.build_controller", FakeDurableController)
    from test_only.recovery_fakes import route_config
    adapter_path = tmp_path / "adapters.json"
    adapter_path.write_text(json.dumps(route_config()))
    monkeypatch.setenv("TOP_DELIVERY_ADAPTER_CONFIG", str(adapter_path))
    from goal_cli import main

    exit_code = main(
        [
            "submit",
            "--prompt",
            str(prompt),
            "--artifact-root",
            str(invocation_root),
            "--runtime-artifact-root",
            str(runtime_root),
            "--existing-parent",
            PARENT_RUN_ID,
            "--database-url",
            "postgresql://top_delivery_workflow@127.0.0.1:5432/top_delivery_control_p1",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0, captured.err
    payload = json.loads(captured.out)
    assert controller_roots == [runtime_root.resolve()]
    bundle_dir = trusted_submission["store"] / "runs" / PARENT_RUN_ID / "submissions" / payload["submission_run_id"]
    assert bundle_dir.is_dir()
    assert not (
        invocation_root / "runs" / PARENT_RUN_ID / "submissions" / payload["submission_run_id"]
    ).exists()

    worker = TaskWorker(MagicMock(), runtime_root, {})  # type: ignore[arg-type]
    monkeypatch.setenv("TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS", "1")
    worker._prepare_run_root(PARENT_RUN_ID)
    context = worker._workstream_context(PARENT_RUN_ID, payload["task_ids"][0])
    assert context["task_id"] == payload["task_ids"][0]
    states = {payload["task_ids"][0]: "verified"}
    ready = ready_successor_workstreams(runtime_root, PARENT_RUN_ID, payload["task_ids"][0], states)
    assert [item.task_id for item in ready] == [payload["task_ids"][1]]


def test_staging_publish_directory_is_not_scanned_as_submission(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    submission_run_id = _submission_run_id("p35")
    run_dir, task_ids, prompt_digest = _write_submission_spec(artifact_root, submission_run_id, title="p35")
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=submission_run_id,
        submission_dir=run_dir,
        task_ids=task_ids,
        prompt_digest=prompt_digest,
    )
    submissions = artifact_root / "runs" / PARENT_RUN_ID / "submissions"
    staging = submissions / f".{submission_run_id}.publish-deadbeef"
    staging.mkdir()
    (staging / "binding.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "parent_run_id": PARENT_RUN_ID,
                "submission_run_id": submission_run_id,
                "prompt_digest": "evil",
                "task_ids": task_ids,
                "goal_spec_digest": "evil",
                "prompt_snapshot_digest": "evil",
            }
        )
        + "\n"
    )
    spec_path = resolve_bound_goal_spec_path(artifact_root, PARENT_RUN_ID, task_ids[0])
    assert spec_path is not None
    assert spec_path.parent.name == submission_run_id


def test_tampered_sibling_binding_cannot_claim_committed_task(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    p35_run = _submission_run_id("p35")
    p40_run = _submission_run_id("p40")
    p35_dir, p35_tasks, p35_digest = _write_submission_spec(artifact_root, p35_run, title="p35")
    p40_dir, p40_tasks, p40_digest = _write_submission_spec(artifact_root, p40_run, title="p40")
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=p35_run,
        submission_dir=p35_dir,
        task_ids=p35_tasks,
        prompt_digest=p35_digest,
    )
    publish_parent_bound_submission_bundle(
        artifact_root,
        parent_run_id=PARENT_RUN_ID,
        submission_run_id=p40_run,
        submission_dir=p40_dir,
        task_ids=p40_tasks,
        prompt_digest=p40_digest,
    )
    binding_path = artifact_root / "runs" / PARENT_RUN_ID / "submissions" / p40_run / "binding.json"
    binding = json.loads(binding_path.read_text())
    binding["task_ids"] = list(p40_tasks) + [p35_tasks[0]]
    binding_path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n")
    resolved = resolve_bound_goal_spec_path(artifact_root, PARENT_RUN_ID, p35_tasks[0])
    assert resolved == binding_path.parent.parent / p35_run / "goal-spec.json"
    with pytest.raises(SubmissionBundleError):
        resolve_bound_goal_spec_path(artifact_root, PARENT_RUN_ID, p40_tasks[0])


def test_executor_request_prepends_assignment_and_preserves_authority_prompt(
    tmp_path: Path,
) -> None:
    authority_prompt = "# Authority\n\nExecute both slices in one run.\n"
    task = MagicMock()
    task.run_id = PARENT_RUN_ID
    task.task_id = "goal-3fa391ad04eedbc8-ws-01"
    task.objective = "First slice"
    context = {
        "prompt": authority_prompt,
        "title": "First slice",
        "acceptance_criteria": ["PASS/ONE"],
        "cwd": str(tmp_path / "transported-checkout"),
        "timeout_seconds": 1800,
    }
    (tmp_path / "work").mkdir()
    (tmp_path / "transported-checkout").mkdir()
    worker = TaskWorker(MagicMock(), tmp_path, {})  # type: ignore[arg-type]
    request = worker._build_executor_request(
        task, "attempt-abc123", "executor", tmp_path / "executor", context
    )
    assert request.prompt.startswith("BOUNDED WORKSTREAM ASSIGNMENT\n")
    assert authority_prompt in request.prompt
    assert request.prompt.index("ORIGINAL AUTHORITY PROMPT\n") > 0
    assert "Execute ONLY this assigned workstream" in request.prompt
    assert "sibling or later workstreams" in request.prompt
    assert "work/executor-result.json" in request.prompt
    assignment = json.loads(request.prompt.split("\n", 1)[1].split("\n\n", 1)[0])
    assert Path(assignment["result_file"]) == tmp_path / "work" / "executor-result.json"
    assert Path(assignment["result_file"]) != Path(request.cwd) / "executor-result.json"
    assert "not a nested work/ directory" in request.prompt
    assert "disposition" in request.prompt
    assert "evidence_summary" in request.prompt
    assert "auditor verdict" in request.prompt
    assert "goal-3fa391ad04eedbc8-ws-02" not in request.prompt.split("ORIGINAL AUTHORITY PROMPT", 1)[0]


@pytest.fixture
def trusted_submission(monkeypatch: pytest.MonkeyPatch):
    """Real root-owned disposable store; /tmp's writable ancestor is unsuitable."""
    if os.geteuid() != 0:
        pytest.skip("root-controlled store permission tests require root")
    from submission_bundle import recover_parent_bound_submission_bundle

    with tempfile.TemporaryDirectory(prefix="p40-trusted-test-", dir="/var/lib") as directory:
        base = Path(directory)
        base.chmod(0o755)
        runtime_base, store = base / "runtime", base / "trusted-bundles"
        runtime = runtime_base / PARENT_RUN_ID / "artifacts"
        runtime.mkdir(parents=True)
        source_root = base / "source"
        source_root.mkdir()
        submission = _submission_run_id("p35")
        source, tasks, prompt_digest = _write_submission_spec(source_root, submission, title="p35")
        monkeypatch.setattr("submission_bundle.RUNTIME_RUNS_ROOT", runtime_base)
        monkeypatch.setattr("submission_bundle.TRUSTED_BUNDLES_ROOT", store)
        monkeypatch.delenv("TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS", raising=False)
        monkeypatch.setenv("TOP_DELIVERY_ARTIFACT_OWNER", "topdelivery")
        spec_digest = hashlib.sha256((source / "goal-spec.json").read_bytes()).hexdigest()
        bundle = recover_parent_bound_submission_bundle(
            runtime, parent_run_id=PARENT_RUN_ID, submission_run_id=submission,
            submission_dir=source, task_ids=tasks, prompt_digest=prompt_digest,
            expected_goal_spec_digest=spec_digest,
        )
        yield {"base": base, "runtime_base": runtime_base, "runtime": runtime,
               "store": store, "bundle": bundle, "source": source,
               "submission": submission, "tasks": tasks, "prompt_digest": prompt_digest,
               "spec_digest": spec_digest}


def test_runtime_store_is_root_held_outside_executor_artifacts(trusted_submission) -> None:
    item = trusted_submission
    assert item["bundle"].is_relative_to(item["store"])
    assert not item["bundle"].is_relative_to(item["runtime_base"])
    for path in [item["store"], *item["store"].rglob("*")]:
        assert path.stat().st_uid == 0
        assert stat.S_IMODE(path.stat().st_mode) == (0o555 if path.is_dir() else 0o444)
    loaded = goal_spec_for_task(item["runtime"], PARENT_RUN_ID, item["tasks"][0])
    assert loaded["workstreams"][0]["executor_adapter"] == "executor"


def test_real_service_user_reads_but_cannot_mutate_replace_or_publish(trusted_submission) -> None:
    try:
        service = pwd.getpwnam("topdelivery")
    except KeyError:
        pytest.skip("topdelivery service account is unavailable")
    item = trusted_submission
    controller_path = Path(__file__).resolve().parents[1] / "controller"
    child = r'''
import json,os,sys
from pathlib import Path
from unittest.mock import MagicMock
import submission_bundle
from worker import TaskWorker
item=json.loads(sys.argv[1])
submission_bundle.TRUSTED_BUNDLES_ROOT=Path(item["store"])
submission_bundle.RUNTIME_RUNS_ROOT=Path(item["runtime_base"])
bundle=Path(item["bundle"])
worker=TaskWorker(MagicMock(),Path(item["runtime"]),{})
context=worker._workstream_context(item["parent"],item["tasks"][0])
assert context["executor_adapter"]=="executor"
denied=[]
for name in ("binding.json","goal-spec.json","prompt.snapshot.md"):
 try: (bundle/name).write_text("unreviewed")
 except PermissionError: denied.append(name)
for name,path in (("bundle",bundle),("store",Path(item["store"])),("ancestor",Path(item["store"])/"runs")):
 try: path.rename(path.with_name(path.name+"-replaced"))
 except PermissionError: denied.append(name)
try:
 submission_bundle.publish_parent_bound_submission_bundle(Path(item["runtime"]),parent_run_id=item["parent"],submission_run_id=item["submission"],submission_dir=Path(item["source"]),task_ids=item["tasks"],prompt_digest=item["prompt_digest"])
except submission_bundle.SubmissionBundleError as exc:
 assert "requires the root" in str(exc)
 denied.append("publish")
assert len(denied)==7,denied
print(json.dumps({"uid":os.getuid(),"denied":denied,"context":context["task_id"]}))
'''
    payload = {key: str(value) if isinstance(value, Path) else value for key, value in item.items()}
    payload["parent"] = PARENT_RUN_ID
    result = subprocess.run(
        ["runuser", "-u", "topdelivery", "--", "python3", "-c", child, json.dumps(payload)],
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PYTHONPATH": str(controller_path),
             "PYTHONDONTWRITEBYTECODE": "1", "TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS": "1"},
        capture_output=True, text=True, check=True,
    )
    receipt = json.loads(result.stdout)
    assert receipt["uid"] == service.pw_uid
    assert len(receipt["denied"]) == 7


def _make_untrusted_rehashed_copy(item: dict, destination_root: Path) -> Path:
    bundle = destination_root / "runs" / PARENT_RUN_ID / "submissions" / item["submission"]
    shutil.copytree(item["bundle"], bundle)
    spec_path, binding_path = bundle / "goal-spec.json", bundle / "binding.json"
    spec = json.loads(spec_path.read_text())
    spec["workstreams"][0].update({"cwd": "/tmp/unreviewed", "executor_adapter": "unreviewed"})
    spec_path.write_text(json.dumps(spec))
    binding = json.loads(binding_path.read_text())
    binding["goal_spec_digest"] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    binding_path.write_text(json.dumps(binding))
    return bundle


def test_rehashed_runtime_copy_never_replaces_trusted_route_or_cwd(trusted_submission) -> None:
    item = trusted_submission
    _make_untrusted_rehashed_copy(item, item["runtime"])
    loaded = goal_spec_for_task(item["runtime"], PARENT_RUN_ID, item["tasks"][0])
    assert loaded["workstreams"][0]["executor_adapter"] == "executor"
    assert "cwd" not in loaded["workstreams"][0]
    spec_path = item["bundle"] / "goal-spec.json"
    tampered = json.loads(spec_path.read_text())
    tampered["workstreams"][0]["cwd"] = "/tmp/unreviewed"
    spec_path.write_text(json.dumps(tampered))  # root fault injection; binding stays pinned.
    with pytest.raises(SubmissionBundleError, match="digest mismatch"):
        goal_spec_for_task(item["runtime"], PARENT_RUN_ID, item["tasks"][0])


@pytest.mark.parametrize("trusted_binding_present", [True, False])
def test_root_service_flag_cannot_be_downgraded_by_resolved_runtime_symlink(
    trusted_submission, monkeypatch: pytest.MonkeyPatch, trusted_binding_present: bool,
) -> None:
    item = trusted_submission
    external = item["base"] / "executor-writable"
    external.mkdir()
    _make_untrusted_rehashed_copy(item, external)
    item["runtime"].rmdir()
    item["runtime"].symlink_to(external, target_is_directory=True)
    resolved = item["runtime"].resolve()
    assert not resolved.is_relative_to(item["runtime_base"])
    monkeypatch.setenv("TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS", "1")
    if not trusted_binding_present:
        binding = item["bundle"] / "binding.json"
        binding.rename(binding.with_name("preserved-binding.json"))
        with pytest.raises(SubmissionBundleError):
            goal_spec_for_task(resolved, PARENT_RUN_ID, item["tasks"][0])
    else:
        loaded = goal_spec_for_task(resolved, PARENT_RUN_ID, item["tasks"][0])
        assert loaded["workstreams"][0]["executor_adapter"] == "executor"


@pytest.mark.parametrize("damage", ["ancestor_writable", "ancestor_owner", "store_symlink", "file_owner", "file_mode"])
def test_trusted_store_rejects_unsafe_owners_modes_and_symlinks(trusted_submission, damage: str) -> None:
    item = trusted_submission
    if damage == "ancestor_writable":
        item["base"].chmod(0o777)
    elif damage == "ancestor_owner":
        os.chown(item["store"] / "runs", 65534, 65534)
    elif damage == "store_symlink":
        saved = item["store"].with_name("preserved-store")
        item["store"].rename(saved)
        item["store"].symlink_to(saved, target_is_directory=True)
    elif damage == "file_owner":
        os.chown(item["bundle"] / "binding.json", 65534, 65534)
    else:
        (item["bundle"] / "binding.json").chmod(0o644)
    with pytest.raises(SubmissionBundleError):
        goal_spec_for_task(item["runtime"], PARENT_RUN_ID, item["tasks"][0])


@pytest.mark.parametrize("changed_file", ["goal-spec.json", "prompt.snapshot.md"])
def test_bound_execution_uses_one_verified_buffer_despite_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_file: str,
) -> None:
    import submission_bundle

    root = tmp_path / "artifacts"
    root.mkdir()
    submission = _submission_run_id("p35")
    source, tasks, prompt_digest = _write_submission_spec(root, submission, title="p35")
    bundle = publish_parent_bound_submission_bundle(
        root, parent_run_id=PARENT_RUN_ID, submission_run_id=submission,
        submission_dir=source, task_ids=tasks, prompt_digest=prompt_digest,
    )
    reader = submission_bundle._read_bytes
    reads: dict[str, int] = {}

    def racing_reader(path: Path, *, trusted: bool = False) -> bytes:
        captured = reader(path, trusted=trusted)
        reads[path.name] = reads.get(path.name, 0) + 1
        if path == bundle / changed_file:
            path.write_text("UNVALIDATED REPLACEMENT AFTER THE READ")
        return captured

    monkeypatch.setattr(submission_bundle, "_read_bytes", racing_reader)
    monkeypatch.setattr(submission_bundle, "resolve_bound_goal_spec_path",
                        lambda *_a, **_k: pytest.fail("execution must not consume a validated path"))
    loaded = goal_spec_for_task(root, PARENT_RUN_ID, tasks[0])
    assert loaded["workstreams"][0]["prompt"] == _two_step_text("p35")
    assert reads == {"binding.json": 1, "goal-spec.json": 1, "prompt.snapshot.md": 1}


def test_publisher_copies_captured_reviewed_bytes_despite_source_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trusted_submission,
) -> None:
    import submission_bundle

    root = tmp_path / "artifacts"
    root.mkdir()
    submission = _submission_run_id("captured-source")
    source, tasks, prompt_digest = _write_submission_spec(root, submission, title="captured-source")
    original = (source / "goal-spec.json").read_bytes()
    reader = submission_bundle._read_bytes

    def racing_source(path: Path, *, trusted: bool = False) -> bytes:
        captured = reader(path, trusted=trusted)
        if path == source / "goal-spec.json":
            path.write_text("changed after source capture")
        return captured

    monkeypatch.setattr(submission_bundle, "_read_bytes", racing_source)
    bundle = submission_bundle.recover_parent_bound_submission_bundle(
        root, parent_run_id=PARENT_RUN_ID, submission_run_id=submission,
        submission_dir=source, task_ids=tasks, prompt_digest=prompt_digest,
        expected_goal_spec_digest=hashlib.sha256(original).hexdigest(),
    )
    assert (bundle / "goal-spec.json").read_bytes() == original


@pytest.mark.parametrize("filename", ["goal-spec.json", "prompt.snapshot.md"])
def test_bound_files_are_opened_without_following_symlinks(tmp_path: Path, filename: str) -> None:
    root = tmp_path / "artifacts"
    root.mkdir()
    submission = _submission_run_id("p35")
    source, tasks, prompt_digest = _write_submission_spec(root, submission, title="p35")
    bundle = publish_parent_bound_submission_bundle(
        root, parent_run_id=PARENT_RUN_ID, submission_run_id=submission,
        submission_dir=source, task_ids=tasks, prompt_digest=prompt_digest,
    )
    target = bundle / filename
    saved = target.with_name("preserved-" + filename)
    target.rename(saved)
    target.symlink_to(saved)
    with pytest.raises(SubmissionBundleError, match="symlink"):
        goal_spec_for_task(root, PARENT_RUN_ID, tasks[0])


@pytest.mark.parametrize("existing_source", [False, True])
@pytest.mark.parametrize("field,value", [
    ("cwd", "/tmp/unreviewed"), ("executor_adapter", "unreviewed-executor"),
    ("auditor_adapter", "unreviewed-auditor"), ("timeout_seconds", 999999),
])
def test_canonical_submit_pins_original_coordinator_spec_before_service_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    existing_source: bool, field: str, value: object,
) -> None:
    root = tmp_path / "artifacts"
    root.mkdir()
    prompt = _two_step_prompt(tmp_path, "canonical-pinned")
    controller = TrackingController()
    controller.register_run(PARENT_RUN_ID)
    submitter = GoalSubmitter(controller, root, mode="dry_run")

    def tamper(run_dir: Path, **_kwargs: object) -> None:
        path = run_dir / "goal-spec.json"
        spec = json.loads(path.read_text())
        spec["workstreams"][0][field] = value
        path.write_text(json.dumps(spec))

    if existing_source:
        receipt = submitter.submit(prompt)
        controller.scheduled.clear()
        tamper(root / "runs" / receipt.submission_run_id)
    else:
        # Simulate a service edit immediately after the source ownership handoff.
        original_write = submitter._write_artifacts
        def write_then_tamper(run_dir, *args):
            original_write(run_dir, *args)
            tamper(run_dir)
        monkeypatch.setattr(submitter, "_write_artifacts", write_then_tamper)
    with pytest.raises(SubmissionBundleError, match="reviewed digest"):
        submitter.submit(prompt, existing_parent=PARENT_RUN_ID)
    assert controller.scheduled == []
    assert not (root / "runs" / PARENT_RUN_ID / "submissions").exists()


@pytest.mark.parametrize("kind", ["run_symlink", "runs_symlink", "precreated_with_tmp_symlinks"])
def test_privileged_submit_never_writes_or_chowns_precreated_targets(tmp_path, kind):
    root = tmp_path / "artifacts"
    root.mkdir()
    prompt = _two_step_prompt(tmp_path, "unsafe-create")
    parsed = parse_prompt_bytes(prompt.read_bytes(), source=str(prompt))
    target = tmp_path / "root-sentinel"
    target.mkdir()
    secret = target / "sentinel"
    secret.write_text("preserve this inode and ownership")
    before = {p.name: (p.stat().st_uid, p.stat().st_gid, p.stat().st_mode,
                       p.stat().st_ino, p.read_bytes() if p.is_file() else None)
              for p in (target, secret)}
    if kind == "runs_symlink":
        (root / "runs").symlink_to(target, target_is_directory=True)
    else:
        (root / "runs").mkdir()
        run = root / "runs" / parsed.run_id
        if kind == "run_symlink":
            run.symlink_to(target, target_is_directory=True)
        else:
            run.mkdir()
            (run / "goal-spec.tmp").symlink_to(secret)
            (run / "prompt.snapshot.tmp").symlink_to(secret)
    controller = TrackingController()
    with pytest.raises((ValueError, OSError)):
        GoalSubmitter(controller, root, mode="dry_run").submit(prompt)
    after = {p.name: (p.stat().st_uid, p.stat().st_gid, p.stat().st_mode,
                      p.stat().st_ino, p.read_bytes() if p.is_file() else None)
             for p in (target, secret)}
    assert after == before
    assert sorted(p.name for p in target.iterdir()) == ["sentinel"]
    assert controller.scheduled == []


@pytest.mark.skipif(os.geteuid() != 0, reason="privileged writer boundary")
@pytest.mark.parametrize("kind", ["service_owned", "world_writable"])
def test_root_submit_rejects_replaceable_ancestor_before_any_write(tmp_path, kind):
    root = tmp_path / "artifacts"
    root.mkdir()
    prompt = _two_step_prompt(tmp_path, "unsafe-ancestor")
    if kind == "service_owned":
        os.chown(root, pwd.getpwnam("topdelivery").pw_uid, -1)
    else:
        root.chmod(0o777)
    controller = TrackingController()
    with pytest.raises(SubmissionBundleError, match="ancestor"):
        GoalSubmitter(controller, root).submit(prompt)
    assert not (root / "runs").exists()
    assert controller.scheduled == []


def test_explicit_store_root_is_always_trusted_even_without_service_env(trusted_submission):
    import submission_bundle
    item = trusted_submission
    assert submission_bundle._storage(item["store"]) == (item["store"], True)
    published = submission_bundle.recover_parent_bound_submission_bundle(
        item["store"], parent_run_id=PARENT_RUN_ID, submission_run_id=item["submission"],
        submission_dir=item["source"], task_ids=item["tasks"],
        prompt_digest=item["prompt_digest"], expected_goal_spec_digest=item["spec_digest"],
    )
    assert published == item["bundle"]
    assert stat.S_IMODE((published / "binding.json").stat().st_mode) == 0o444


@pytest.mark.parametrize("artifact_location", ["arbitrary", "runtime"])
def test_recovery_umask_077_still_allows_actual_service_read(trusted_submission, monkeypatch,
                                                           artifact_location):
    import submission_bundle
    item = trusted_submission
    store = item["base"] / "umask-store"
    monkeypatch.setattr(submission_bundle, "TRUSTED_BUNDLES_ROOT", store)
    old_umask = os.umask(0o077)
    try:
        bundle = submission_bundle.recover_parent_bound_submission_bundle(
            item["runtime"] if artifact_location == "runtime" else item["base"] / "arbitrary-runtime-root",
            parent_run_id=PARENT_RUN_ID,
            submission_run_id=item["submission"], submission_dir=item["source"],
            task_ids=item["tasks"], prompt_digest=item["prompt_digest"],
            expected_goal_spec_digest=item["spec_digest"],
        )
    finally:
        os.umask(old_umask)
    assert bundle.is_relative_to(store)
    assert all(stat.S_IMODE(p.stat().st_mode) == (0o555 if p.is_dir() else 0o444)
               for p in [store, *store.rglob("*")])
    code = """import json,sys
from pathlib import Path
import submission_bundle
d=json.loads(sys.argv[1]);submission_bundle.TRUSTED_BUNDLES_ROOT=Path(d['store'])
s=submission_bundle.load_bound_goal_spec(Path(d['store']),d['parent'],d['task'])
assert s['run_id']==d['submission'];print('service-read-pass')
"""
    account = pwd.getpwnam("topdelivery")
    result = subprocess.run(
        ["python3", "-B", "-c", code, json.dumps({"store": str(store), "parent": PARENT_RUN_ID,
         "task": item["tasks"][0], "submission": item["submission"]})],
        user=account.pw_uid, group=account.pw_gid, extra_groups=[],
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "controller")},
        cwd="/", capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "service-read-pass"


def test_cli_retains_artifact_symlink_for_writer_validation(tmp_path):
    from goal_cli import _artifact_root_from_env
    target = tmp_path / "real"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    assert _artifact_root_from_env(str(alias)) == alias


@pytest.mark.parametrize("mode", [0o700, 0o500])
def test_existing_trusted_private_directory_rejected_before_publication(trusted_submission, monkeypatch, mode):
    import submission_bundle as s
    item = trusted_submission
    store = item["base"] / "private-store"
    store.mkdir(mode=mode)
    monkeypatch.setattr(s, "TRUSTED_BUNDLES_ROOT", store)
    with pytest.raises(SubmissionBundleError, match="readable/traversable"):
        s.recover_parent_bound_submission_bundle(
            item["runtime"], parent_run_id=PARENT_RUN_ID, submission_run_id=item["submission"],
            submission_dir=item["source"], task_ids=item["tasks"],
            prompt_digest=item["prompt_digest"], expected_goal_spec_digest=item["spec_digest"])
    assert list(store.iterdir()) == []
    assert stat.S_IMODE(store.stat().st_mode) == mode


def test_durable_metadata_is_final_before_fsync(trusted_submission, monkeypatch):
    import submission_bundle as s
    item = trusted_submission
    store = item["base"] / "durable-store"
    monkeypatch.setattr(s, "TRUSTED_BUNDLES_ROOT", store)
    original_fsync, original_fchmod, original_fchown = os.fsync, os.fchmod, os.fchown
    events = []

    def record(operation, function, fd, *args):
        result = function(fd, *args)
        info = os.fstat(fd)
        events.append((operation, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid))
        return result

    monkeypatch.setattr(os, "fsync", lambda fd: record("sync", original_fsync, fd))
    monkeypatch.setattr(os, "fchmod", lambda fd, mode: record("mode", original_fchmod, fd, mode))
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: record("owner", original_fchown, fd, uid, gid))
    bundle = s.recover_parent_bound_submission_bundle(
        item["runtime"], parent_run_id=PARENT_RUN_ID, submission_run_id=item["submission"],
        submission_dir=item["source"], task_ids=item["tasks"], prompt_digest=item["prompt_digest"],
        expected_goal_spec_digest=item["spec_digest"])
    for file in bundle.iterdir():
        own = [e for e in events if e[1] == file.stat().st_ino]
        assert own[-1][0] == "sync" and own[-1][2:] == (0o444, 0)
        assert next(i for i, e in enumerate(own) if e[0] == "mode") < next(i for i, e in enumerate(own) if e[0] == "sync")
    for directory in [store, store / "runs", store / "runs" / PARENT_RUN_ID,
                      store / "runs" / PARENT_RUN_ID / "submissions", bundle]:
        assert any(e[:3] == ("sync", directory.stat().st_ino, 0o555) for e in events)
        assert any(e[:2] == ("sync", directory.parent.stat().st_ino) for e in events)
    # Reopen using fresh descriptors, not buffered pre-publication data.
    assert s.load_bound_goal_spec(store, PARENT_RUN_ID, item["tasks"][0])["run_id"] == item["submission"]
    events.clear()
    run = item["base"] / "new-source-run"
    GoalSubmitter(MagicMock(), item["base"])._write_artifacts(
        run, run / "prompt.snapshot.md", run / "goal-spec.json", b"original", b"{}")
    for file in run.iterdir():
        own = [e for e in events if e[1] == file.stat().st_ino]
        assert own[-1][0] == "sync" and own[-1][2] == 0o644
        assert own[-1][3] == pwd.getpwnam("topdelivery").pw_uid
        assert [e[0] for e in own] == ["mode", "owner", "sync"]


@pytest.fixture
def recovery_source(tmp_path, monkeypatch):
    """Real disposable Git objects; no origin fetch, host files or service use."""
    if os.geteuid() != 0:
        pytest.skip("real root-controlled source proof is covered on Comms-01")
    base = Path(tempfile.mkdtemp(prefix="p43-source-test-", dir="/var/lib"))
    base.chmod(0o755)
    repo, release = base / "repo", base / "release"
    repo.mkdir()
    release.mkdir()
    (repo / "controller").mkdir()
    (repo / "controller" / "worker.py").write_text("# accepted source\n")
    (repo / "entry").symlink_to("controller/worker.py")
    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    git("init", "-q")
    git("add", "controller", "entry")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
    sha, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    git("update-ref", "refs/remotes/origin/main", sha)
    shutil.copytree(repo / "controller", release / "controller")
    (release / "entry").symlink_to("controller/worker.py")
    monkeypatch.setattr("recovery_acceptance.accepted_source", lambda: {"candidate_sha": sha, "tree": tree})
    try:
        yield repo, release, sha, tree
    finally:
        shutil.rmtree(base)


@pytest.mark.parametrize("damage", ["none", "bytes", "missing", "extra", "mode", "tree", "symlink"])
def test_recovery_source_uses_actual_git_bytes_and_complete_installed_tree(recovery_source, damage):
    from recovery_start import verify_source
    repo, release, sha, tree = recovery_source
    path = release / "controller" / "worker.py"
    if damage == "bytes":
        path.write_text("# wrong bytes\n")
    elif damage == "missing":
        path.unlink()
    elif damage == "extra":
        (release / "extra.py").write_text("# unreviewed\n")
    elif damage == "mode":
        path.chmod(0o755)
    elif damage == "tree":
        tree = "0" * 40
    elif damage == "symlink":
        path.unlink()
        path.symlink_to(repo / "controller" / "worker.py")
    if damage == "none":
        assert verify_source(repo, release, sha, tree) == 2
    else:
        with pytest.raises((ValueError, OSError)):
            verify_source(repo, release, sha, tree)


@pytest.fixture
def recovery_start_fixture(tmp_path, monkeypatch):
    import recovery_start as r
    sha, tree = "a" * 40, "b" * 40
    release = Path("/opt/top-delivery-p1") / f"{sha}-goal-runner"
    current = MagicMock()
    current.resolve.return_value = release
    current.lstat.return_value.st_uid = 0
    current.is_symlink.return_value = True
    monkeypatch.setattr("submission_bundle._open_directory", lambda *args, **kwargs: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY))
    monkeypatch.setattr(r, "CURRENT", current)
    monkeypatch.setattr(r.os, "geteuid", lambda: 0)
    events = []
    monkeypatch.setattr(r, "_run", lambda argv: events.append(tuple(argv)) or "")
    def verified(label, result):
        def call(*args, **kwargs):
            events.append(label)
            return result
        return call
    monkeypatch.setattr(r, "verify_source", verified("actual-source", 42))
    monkeypatch.setattr("recovery_service_anchor.verify_installed_config", verified("installed-config", None))
    monkeypatch.setattr(r, "verify_bundles", verified("service-bundles", {"uid": 999}))
    monkeypatch.setattr(r, "verify_units", verified("effective-units", None))
    monkeypatch.setattr(r, "current_supervisor", lambda release: {'fixture':True})
    monkeypatch.setattr(r, "verify_handover", lambda queue, identity: {'fixture':True})
    monkeypatch.setattr(r, "verify_standalone", lambda: {'fixture':True})
    monkeypatch.setattr(r, "verify_stage", lambda stage: {'fixture':True})
    def final_stage(stage, before):
        standalone = r.verify_standalone()
        if r.verify_stage(stage) != before:
            raise ValueError('fixture final stage changed')
        return standalone
    monkeypatch.setattr(r, "verify_final_stage", final_stage)
    monkeypatch.setattr(r, "guard_action", lambda action, units: {'fixture':True})
    queue = {"database": "top_delivery_control_p1", "head": r.TASKS[0], "active": 0, "lease_live": True}
    monkeypatch.setattr(r, "read_queue", verified("queue", queue))
    return r, (tmp_path, release, sha, tree, r.TASKS[0]), events, queue


@pytest.mark.parametrize("failure", ["source", "bundle", "units", "wrong-head", "active", "lease", "database"])
def test_actual_start_gate_never_starts_on_failed_derived_proof(recovery_start_fixture, monkeypatch, failure):
    r, args, events, queue = recovery_start_fixture
    if failure in {"source", "bundle", "units"}:
        function = {"source": "verify_source", "bundle": "verify_bundles", "units": "verify_units"}[failure]
        def fail(*unused):
            raise ValueError(f"actual {failure} missing/corrupt")
        monkeypatch.setattr(r, function, fail)
    elif failure == "wrong-head":
        queue["head"] = "goal-3fa391ad04eedbc8-ws-02"
    elif failure == "active":
        queue["active"] = 1
    elif failure == "lease":
        queue["lease_live"] = False
    else:
        queue["database"] = "wrong"
    with pytest.raises(ValueError):
        r.start_verified(*args, start=True)
    assert ("systemctl", "start", r.WORKER) not in events


def test_actual_start_gate_orders_reload_unit_and_queue_checks_before_each_start(recovery_start_fixture):
    r, args, events, queue = recovery_start_fixture
    for task in r.TASKS:
        events.clear()
        queue["head"] = task
        result = r.start_verified(*args[:-1], task, start=True)
        assert result["disposition"] == "STARTED_NOT_ACCEPTED"
        assert events == ["actual-source", "installed-config", "service-bundles", ("systemctl", "daemon-reload"),
                          "effective-units", "queue", ("systemctl", "start", r.WORKER)]
    events.clear()
    queue["head"] = args[-1]
    assert r.start_verified(*args)["started"] is False
    assert not any(isinstance(e, tuple) and e[0] == "systemctl" for e in events)


@pytest.mark.parametrize("damage", ["none", "continuous", "multiple-starts", "restart", "pin", "trust", "source", "controller-child", "root-worker", "cwd"])
def test_effective_systemd_state_not_just_dropin_text(monkeypatch, damage):
    import recovery_start as r
    release = Path("/opt/top-delivery-p1") / ("a" * 40 + "-goal-runner")
    env = f"TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS=1 PYTHONPATH={release}/controller TOP_DELIVERY_RUN_ID={r.PARENT}"
    worker = {"ExecStart": f"{{ argv[]=/usr/bin/python3 {release}/controller/worker_cli.py --once --run-id {r.PARENT} --expected-task-id {r.TASKS[0]} ; }}",
              "Restart": "no", "ActiveState": "inactive", "MainPID": "0", "Environment": env,
              "User": "topdelivery", "WorkingDirectory": str(release / "controller")}
    controller = {"ActiveState": "active", "MainPID": "123", "Environment": env,
                  "User": "root", "WorkingDirectory": str(release / "controller")}
    children = f"/usr/bin/python3 {release}/controller/supervisor_cli.py\n/usr/bin/python3 {release}/controller/parent_socket.py\n"
    if damage == "continuous":
        worker["ExecStart"] = worker["ExecStart"].replace(" --once", "")
    elif damage == "multiple-starts":
        worker["ExecStart"] += worker["ExecStart"]
    elif damage == "restart":
        worker["Restart"] = "always"
    elif damage == "pin":
        controller["Environment"] = env.replace(r.PARENT, "goal-wrong")
    elif damage == "trust":
        worker["Environment"] = env.replace("SUBMISSIONS=1", "SUBMISSIONS=0")
    elif damage == "source":
        controller["Environment"] = env.replace(str(release), "/old")
    elif damage == "controller-child":
        children = children.replace("parent_socket.py", "wrong.py")
    elif damage == "root-worker":
        worker["User"] = "root"
    elif damage == "cwd":
        worker["WorkingDirectory"] = "/old/source"
    monkeypatch.setattr(r, "_unit", lambda unit: worker if unit == r.WORKER else controller)
    monkeypatch.setattr(r, "_run", lambda argv: children)
    monkeypatch.setattr("recovery_service_anchor.verify_service_anchor", lambda *args: None)
    if damage == "none":
        r.verify_units(release, r.TASKS[0])
    else:
        with pytest.raises(ValueError):
            r.verify_units(release, r.TASKS[0])


@pytest.mark.parametrize("scenario", ["wrong-head", "race", "empty", "owned", "pass"])
def test_expected_claim_rolls_back_any_wrong_task_before_commit(monkeypatch, scenario):
    import repository as module
    from recovery_start import PARENT, TASKS
    repo = module.PostgresRepository.__new__(module.PostgresRepository)
    connection, cursor = MagicMock(), MagicMock()
    repo._conn, repo.db_url = connection, "fixture-no-database"
    connection.cursor.return_value = cursor
    monkeypatch.setattr(module, "authorize_disposable_test_mutation", lambda *args, **kwargs: None)
    head = {"task_id": TASKS[0] if scenario != "wrong-head" else "obsolete-task"}
    owned = {"active_attempt_id": "existing"} if scenario == "owned" else None
    payload = None if scenario == "empty" else {"task_id": "racing-task" if scenario == "race" else TASKS[0]}
    cursor.fetchone.side_effect = [head, owned, {"result": payload}]
    if scenario == "pass":
        assert repo.claim_next(PARENT, "fixture-worker", controller_epoch=1, lease_seconds=120,
                               expected_task_id=TASKS[0]) == payload
        connection.commit.assert_called_once()
        connection.rollback.assert_not_called()
    else:
        with pytest.raises(PermissionError):
            repo.claim_next(PARENT, "fixture-worker", controller_epoch=1, lease_seconds=120,
                            expected_task_id=TASKS[0])
        connection.commit.assert_not_called()
        connection.rollback.assert_called_once()
        if scenario in {"wrong-head", "owned"}:
            assert not any("longspan_claim_next_parent_task" in str(call) for call in cursor.execute.call_args_list)


def test_expected_task_propagates_worker_and_loop_and_requires_bounded_mode(tmp_path, monkeypatch):
    from recovery_start import PARENT, TASKS
    controller = MagicMock()
    controller.claim_next.return_value = None
    worker = TaskWorker(controller, tmp_path, {})
    monkeypatch.setattr(worker, "_preflight_adapters", lambda: None)
    monkeypatch.setattr(worker, "_prepare_run_root", lambda run_id: None)
    with pytest.raises(PermissionError, match="not claimed"):
        worker.run_once(PARENT, "worker", expected_task_id=TASKS[0])
    controller.claim_next.assert_called_once_with(PARENT, "worker", expected_task_id=TASKS[0])
    fake = MagicMock()
    from worker import WorkerRunResult
    fake.run_once.return_value = WorkerRunResult(TASKS[0], "verified")
    assert WorkerLoop(fake, run_id=PARENT, owner="worker", once=True, expected_task_id=TASKS[0]).run()
    fake.run_once.assert_called_once_with(PARENT, "worker", expected_task_id=TASKS[0])
    fake.run_once_available.assert_not_called()
    for run_id, once in [(None, True), (PARENT, False)]:
        with pytest.raises(ValueError):
            WorkerLoop(fake, run_id=run_id, owner="worker", once=once, expected_task_id=TASKS[0])


@pytest.mark.parametrize("kind", ["actual-shape", "override", "multiline", "unknown-file", "symlink", "writable"])
def test_guard_reads_real_environment_file_precedence_without_leaking_secrets(tmp_path, monkeypatch, kind):
    import recovery_start as r
    path = tmp_path / "worker.env"
    path.write_text(f"TOP_DELIVERY_RUN_ID={r.PARENT}\nEXAMPLE_SECRET=do-not-return\n")
    path.chmod(0o600)
    monkeypatch.setattr(r, "WORKER_ENV", path)
    settings = {"Environment": "TOP_DELIVERY_RUN_ID=inline-ignored TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS=1 PYTHONPATH=/accepted/controller",
                "EnvironmentFiles": f"{path} (ignore_errors=yes)"}
    if kind == "override":
        path.write_text("TOP_DELIVERY_RUN_ID=wrong\n")
    elif kind == "multiline":
        path.write_text("TOP_DELIVERY_RUN_ID=\\\nwrong\n")
    elif kind == "unknown-file":
        settings["EnvironmentFiles"] = "/unreviewed/file (ignore_errors=yes)"
    elif kind == "symlink":
        original = tmp_path / "original"
        path.rename(original)
        path.symlink_to(original)
    elif kind == "writable":
        path.chmod(0o666)
    if kind in {"actual-shape", "override"}:
        result = r._guarded_environment(settings, r.WORKER)
        assert result["TOP_DELIVERY_RUN_ID"] == (r.PARENT if kind == "actual-shape" else "wrong")
        assert set(result) == r.GUARDED_ENV
        assert "do-not-return" not in json.dumps(result)
    else:
        with pytest.raises((ValueError, OSError)):
            r._guarded_environment(settings, r.WORKER)


@pytest.mark.parametrize("field,value", [
    ("User", "root"), ("Group", "root"), ("Type", "oneshot"),
    ("ExecStartPre", "{ path=/bad ; argv[]=/bad ; ignore_errors=no ; start_time=[n/a] ; }"),
    ("ExecStartPost", "{ path=/bad ; argv[]=/bad ; ignore_errors=no ; start_time=[n/a] ; }"),
    ("RootDirectory", "/other-root"), ("PrivateUsers", "yes"), ("PrivateNetwork", "yes"),
    ("BindPaths", "/other:/var/lib"), ("EnvironmentFiles", "/unexpected"),
    ("Environment", "TOP_DELIVERY_DATABASE_URL=postgresql://fixture/wrong"),
    ("Environment", "TOP_DELIVERY_ARTIFACT_ROOT=/wrong"),
    ("Environment", "TOP_DELIVERY_ADAPTER_CONFIG=/wrong"),
    ("Environment", "TOP_DELIVERY_AUTH_URL=http://wrong.invalid"),
])
def test_service_fingerprint_detects_execution_and_target_drift(field, value):
    import recovery_service_anchor as a
    release = Path("/opt/top-delivery-p1/fixture-goal-runner")
    baseline = {"User": "topdelivery", "Group": "topdelivery", "Type": "simple"}
    changed = {**baseline, field: value}
    assert a.normalized_unit(baseline, a.WORKER, release) != a.normalized_unit(changed, a.WORKER, release)


@pytest.mark.parametrize("component", ["units", "files", "controller_environments", "auth_path"])
def test_complete_service_anchor_mismatch_fails_closed(monkeypatch, component):
    import recovery_service_anchor as a
    baseline = {"units": {"worker": "config-hash"}, "files": {"adapter": "hash"},
                "controller_environments": {"socket": "environment-hash"}, "auth_path": "/opt/top-delivery-auth"}
    raw = json.dumps(baseline).encode()
    monkeypatch.setattr(a, "_root_file", lambda path: raw)
    monkeypatch.setattr(a, "ANCHOR_SHA256", hashlib.sha256(raw).hexdigest())
    changed = {**baseline, component: "changed"}
    monkeypatch.setattr(a, "capture_service_anchor", lambda *args, **kwargs: changed)
    runner = MagicMock()
    with pytest.raises(ValueError, match="drift"):
        a.verify_service_anchor(Path("/accepted"), "expected-task", MagicMock(), runner)
    runner.assert_not_called()


@pytest.mark.parametrize("damage", ["symlink", "writable"])
def test_installed_source_ancestor_cannot_be_replaced(recovery_source, tmp_path, damage):
    from recovery_start import verify_source
    repo, release, sha, tree = recovery_source
    if damage == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(release, target_is_directory=True)
        release = alias
    else:
        release.parent.chmod(0o777)
    try:
        with pytest.raises(ValueError):
            verify_source(repo, release, sha, tree)
    finally:
        if damage == "writable":
            release.parent.chmod(0o755)


def test_rollback_has_no_unverified_restart_and_shipped_runbook_uses_actual_gate():
    from recovery_service_plan import rollback_service_actions
    for transitioned in (False, True):
        actions = rollback_service_actions(transitioned)
        assert actions[0] == ("recovery_lifecycle.stop_declared",)
        assert all("start" not in command and "restart" not in command for command in actions)
        # Even a failed restore/config comparison cannot yield an executable
        # predecessor restart from this plan. Reload follows restoration only.
        events = [actions[0], "restore-saved-files", "compare-saved-files", actions[1]]
        assert events.index("restore-saved-files") < events.index(("systemctl", "daemon-reload"))
    guide = (Path(__file__).resolve().parents[1] / "runbooks/p40-recovery-rollback.md").read_text()
    assert "recovery_start.py" in guide and "--expected-task" in guide
    assert "assert_worker_resume_compatible" not in guide
