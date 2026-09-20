"""Goal-spec dependency helpers for progressive workstream scheduling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from prompt_ingest import Workstream, derive_task_id

TERMINAL_PARENT_STATES: frozenset[str] = frozenset(
    {"verified", "parked", "blocked", "failed"}
)

DEPENDENCY_SUCCESS_STATES: frozenset[str] = frozenset({"verified"})


def load_goal_spec(artifact_root: Path, run_id: str) -> dict[str, Any]:
    spec_path = Path(artifact_root).resolve() / "runs" / run_id / "goal-spec.json"
    if not spec_path.is_file():
        raise ValueError("goal spec is required for dependency scheduling")
    return json.loads(spec_path.read_text())


def goal_spec_for_task(artifact_root: Path, run_id: str, task_id: str) -> dict[str, Any]:
    """Load the goal spec graph for a parent-scheduled task.

    Bound existing-parent submissions resolve through immutable submission bundles.
    Unbound parent goals continue to use the parent run's goal-spec.json.
    """
    from submission_bundle import load_bound_goal_spec

    bound_spec = load_bound_goal_spec(artifact_root, run_id, task_id)
    if bound_spec is not None:
        return bound_spec
    return load_goal_spec(artifact_root, run_id)


def workstream_priority(workstream_number: int, total_workstreams: int) -> int:
    if total_workstreams <= 0:
        raise ValueError("workstream count must be positive")
    if workstream_number < 1 or workstream_number > total_workstreams:
        raise ValueError("workstream number is outside the goal spec")
    return total_workstreams - workstream_number + 1


def workstream_from_spec(entry: dict[str, Any], run_id: str) -> Workstream:
    number = int(entry["number"])
    dependencies = tuple(int(value) for value in entry.get("dependencies", ()))
    return Workstream(
        number=number,
        title=str(entry["title"]),
        required_disposition=str(entry.get("required_disposition", "")),
        dependencies=dependencies,
        task_id=str(entry.get("task_id", derive_task_id(run_id, number))),
    )


def ready_successor_workstreams(
    artifact_root: Path,
    run_id: str,
    completed_task_id: str,
    task_states: dict[str, str],
) -> list[Workstream]:
    spec = goal_spec_for_task(artifact_root, run_id, completed_task_id)
    workstreams = spec.get("workstreams")
    if not isinstance(workstreams, list):
        raise ValueError("goal spec workstreams are required")
    submission_run_id = str(spec.get("run_id", run_id))
    by_number = {
        int(entry["number"]): workstream_from_spec(entry, submission_run_id)
        for entry in workstreams
    }
    if completed_task_id not in task_states:
        raise ValueError("completed task is not present in the parent graph")
    if completed_task_id not in {item.task_id for item in by_number.values()}:
        raise ValueError("completed task is not present in the selected goal graph")
    ready: list[Workstream] = []
    total = len(by_number)
    for entry in workstreams:
        workstream = workstream_from_spec(entry, submission_run_id)
        if workstream.task_id in task_states:
            continue
        dependency_ids = [
            by_number[dependency_number].task_id for dependency_number in workstream.dependencies
        ]
        if not dependency_ids:
            continue
        if not all(
            task_states.get(dependency_id) in DEPENDENCY_SUCCESS_STATES
            for dependency_id in dependency_ids
        ):
            continue
        ready.append(workstream)
    ready.sort(key=lambda item: item.number)
    return ready


def root_workstreams(workstreams: tuple[Workstream, ...]) -> tuple[Workstream, ...]:
    return tuple(workstream for workstream in workstreams if not workstream.dependencies)
