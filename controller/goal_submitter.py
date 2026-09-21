"""Canonical goal submission into the parent controller."""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

_EXISTING_PARENT_RUN_ID = re.compile(r"^goal-[0-9a-f]{16}$")

from prompt_ingest import ParsedPrompt, parse_prompt_file
from artifact_owner import _configured_owner_ids
from goal_dependencies import root_workstreams, workstream_priority
from submission_bundle import (
    _absolute, _open_directory, _read_bytes, publish_parent_bound_submission_bundle,
)

DEFAULT_BOUND_TIMEOUT_SECONDS = 1800


@dataclass(frozen=True)
class TaskRoutingSnapshot:
    """Adapter-id routing snapshot. ID-only; not evidence of lane independence."""

    executor_adapter: str
    auditor_adapter: str
    qualification_profile: str | None = None

    def __post_init__(self) -> None:
        if not self.executor_adapter or not self.auditor_adapter:
            raise ValueError("executor and auditor adapter ids are required")
        if self.executor_adapter == self.auditor_adapter:
            raise ValueError("executor and auditor must use distinct adapter ids")


class ParentControllerLike(Protocol):
    def register_run(self, run_id: str, state: str = "active") -> None: ...

    def schedule_task(
        self,
        run_id: str,
        task_id: str,
        objective: str,
        *,
        priority: int = 0,
        available_at: float | None = None,
    ) -> object: ...


@dataclass(frozen=True)
class SubmissionReceipt:
    run_id: str
    prompt_digest: str
    status: str
    mode: str
    artifact_paths: dict[str, str]
    task_ids: list[str]
    dependencies: dict[str, list[int]]
    submission_run_id: str | None = None
    parent_run_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "run_id": self.run_id,
            "prompt_digest": self.prompt_digest,
            "status": self.status,
            "mode": self.mode,
            "artifact_paths": self.artifact_paths,
            "task_ids": self.task_ids,
            "dependencies": self.dependencies,
        }
        if self.submission_run_id is not None:
            payload["submission_run_id"] = self.submission_run_id
        if self.parent_run_id is not None:
            payload["parent_run_id"] = self.parent_run_id
        return payload


class GoalSubmitter:
    def __init__(
        self,
        controller: ParentControllerLike,
        artifact_root: Path,
        *,
        mode: str = "durable",
        task_routing: TaskRoutingSnapshot | None = None,
        prerequisites: dict[int, list[dict]] | None = None,
    ) -> None:
        if mode not in {"durable", "dry_run"}:
            raise ValueError("mode must be durable or dry_run")
        self._controller = controller
        self._artifact_root = _absolute(Path(artifact_root))
        self._mode = mode
        self._task_routing = task_routing
        self._prerequisites = json.loads(json.dumps(prerequisites or {}))
        if not self._artifact_root.is_dir():
            raise ValueError("artifact_root must be an existing directory")

    def submit(
        self,
        prompt_path: Path,
        *,
        existing_parent: str | None = None,
    ) -> SubmissionReceipt:
        # Serialize artifact publication and reconciliation across processes.
        # Lock the trusted directory inode, not a caller-replaceable lock file.
        fd = _open_directory(self._artifact_root, trusted=os.geteuid() == 0,
                             allow_root_sticky=True, require_service_read=False)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            return self._submit_locked(prompt_path, existing_parent=existing_parent)
        finally:
            os.close(fd)

    def _submit_locked(self, prompt_path: Path, *, existing_parent: str | None) -> SubmissionReceipt:
        validate = getattr(self._controller, "validate_submission_routing", None)
        if self._mode == "durable" and callable(validate):
            validate(self._task_routing)
        parsed = parse_prompt_file(prompt_path)
        if existing_parent is not None:
            self._validate_existing_parent_id(existing_parent)
            if existing_parent == parsed.run_id:
                raise ValueError(
                    "existing parent must differ from the prompt-derived submission run id"
                )
            self._assert_existing_parent_registered(existing_parent)
        schedule_run_id = existing_parent or parsed.run_id
        run_dir = self._artifact_root / "runs" / parsed.run_id
        spec_path = run_dir / "goal-spec.json"
        snapshot_path = run_dir / "prompt.snapshot.md"
        prompt_bytes = prompt_path.read_bytes()
        if hashlib.sha256(prompt_bytes).hexdigest() != parsed.sha256:
            raise ValueError("prompt changed after parsing")
        # Capture the complete coordinator-generated graph/routing digest before
        # fresh artifacts are made accessible to the service/executor identity.
        # A replay must match this canonical spec or use explicitly pinned recovery.
        spec_bytes = self._goal_spec_bytes(parsed, prompt_bytes.decode("utf-8"))
        admission=getattr(self._controller,"validate_goal_graph",None)
        if self._mode=="durable" and callable(admission):
            admission(json.loads(spec_bytes))
        expected_spec_digest = hashlib.sha256(spec_bytes).hexdigest()

        existing = spec_path.exists()
        if existing:
            self._validate_existing_snapshot(spec_path, snapshot_path, parsed)
            if _read_bytes(spec_path) != spec_bytes:
                from submission_bundle import SubmissionBundleError
                raise SubmissionBundleError("existing goal spec differs from reviewed digest of immutable submission content/routing")
            status = "existing"
        else:
            self._write_artifacts(run_dir, snapshot_path, spec_path, prompt_bytes, spec_bytes)
            status = "created"

        # Artifacts are not a registration receipt. Reconcile on EVERY retry.
        ready = True
        if existing_parent is None:
            reconcile = getattr(self._controller, "reconcile_submission", None)
            if callable(reconcile):
                disposition = reconcile(parsed.run_id)
                ready = disposition == "ready"
                if not ready:
                    status = disposition
            else:
                self._controller.register_run(parsed.run_id)

        if existing_parent is not None:
            publish_parent_bound_submission_bundle(
                self._parent_publish_artifact_root(existing_parent),
                parent_run_id=existing_parent,
                submission_run_id=parsed.run_id,
                submission_dir=run_dir,
                task_ids=[workstream.task_id for workstream in parsed.workstreams],
                prompt_digest=parsed.sha256,
                expected_goal_spec_digest=expected_spec_digest,
                require_trusted=self._mode == "durable",
            )

        if ready:
            bind = getattr(self._controller, "bind_goal_graph", None)
            if self._mode == "durable" and callable(bind):
                bind(schedule_run_id, json.loads(spec_bytes))
            for workstream in root_workstreams(parsed.workstreams):
                self._schedule_workstream(schedule_run_id, workstream, len(parsed.workstreams))

        return SubmissionReceipt(
            run_id=schedule_run_id,
            prompt_digest=parsed.sha256,
            status=status,
            mode=self._mode,
            artifact_paths={
                "prompt_snapshot": str(snapshot_path),
                "goal_spec": str(spec_path),
            },
            task_ids=[workstream.task_id for workstream in parsed.workstreams],
            dependencies={
                workstream.task_id: list(workstream.dependencies)
                for workstream in parsed.workstreams
            },
            submission_run_id=parsed.run_id,
            parent_run_id=existing_parent,
        )

    def _write_artifacts(
        self,
        run_dir: Path,
        snapshot_path: Path,
        spec_path: Path,
        prompt_bytes: bytes,
        spec_bytes: bytes,
    ) -> None:
        # Create a private NEW directory through no-follow descriptors. Never
        # write through predictable symlinks or chown any preexisting tree.
        # A privileged writer must never create/chown through an executor-owned
        # ancestor. Root-owned sticky temp ancestors are safe only because every
        # subsequent directory is checked root-owned as well. Store readers do
        # not enable this exception. Non-root writers cannot acquire root powers.
        parent_fd = _open_directory(run_dir.parent, trusted=os.geteuid() == 0,
                                    create=True, allow_root_sticky=True,
                                    require_service_read=False)
        run_fd = None
        staging_name = ".submission-" + uuid.uuid4().hex
        try:
            if run_dir.exists():
                raise ValueError("submission directory exists without a valid snapshot")
            try:
                os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError as exc:
                raise ValueError("submission directory exists without a valid snapshot") from exc
            run_fd = os.open(staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent_fd)
            owner = _configured_owner_ids()
            for name, data in ((snapshot_path.name, prompt_bytes), (spec_path.name, spec_bytes)):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=run_fd)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fchmod(handle.fileno(), 0o644)
                    if owner is not None:
                        os.fchown(handle.fileno(), *owner)
                    os.fsync(handle.fileno())
            os.fchmod(run_fd, 0o755)
            if owner is not None:
                os.fchown(run_fd, *owner)
            os.fsync(run_fd)
            os.rename(staging_name, run_dir.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if run_fd is not None:
                os.close(run_fd)
            os.close(parent_fd)

    def _goal_spec_bytes(self, parsed: ParsedPrompt, bound_prompt: str) -> bytes:
        spec = {
            "run_id": parsed.run_id,
            "prompt_digest": parsed.sha256,
            "byte_count": parsed.byte_count,
            "title": parsed.title,
            "objective": parsed.objective,
            "mission": parsed.mission,
            "allowed": list(parsed.allowed),
            "forbidden": list(parsed.forbidden),
            "workstreams": [
                self._bound_workstream(workstream, bound_prompt)
                for workstream in parsed.workstreams
            ],
            "source": parsed.source,
        }
        if self._prerequisites:
            from goal_completion import validate_graph
            if set(self._prerequisites) - {str(w.number) for w in parsed.workstreams}:
                raise ValueError("prerequisite workstream does not exist")
            validate_graph(spec)
        return (json.dumps(spec, indent=2, sort_keys=True) + "\n").encode("utf-8")

    def _bound_workstream(self, workstream: object, bound_prompt: str) -> dict[str, object]:
        from prompt_ingest import Workstream

        if not isinstance(workstream, Workstream):
            raise TypeError("workstream must be a Workstream")
        payload: dict[str, object] = {
            "number": workstream.number,
            "title": workstream.title,
            "task_id": workstream.task_id,
            "required_disposition": workstream.required_disposition,
            "dependencies": list(workstream.dependencies),
            "prompt": bound_prompt,
            "timeout_seconds": DEFAULT_BOUND_TIMEOUT_SECONDS,
            "acceptance_criteria": [workstream.required_disposition],
        }
        if self._task_routing is not None:
            payload["executor_adapter"] = self._task_routing.executor_adapter
            payload["auditor_adapter"] = self._task_routing.auditor_adapter
            if self._task_routing.qualification_profile is not None:
                payload['qualification_profile'] = self._task_routing.qualification_profile
        if str(workstream.number) in self._prerequisites:
            payload["prerequisites"] = self._prerequisites[str(workstream.number)]
        return payload

    def _schedule_workstream(
        self, run_id: str, workstream: object, total_workstreams: int
    ) -> None:
        from prompt_ingest import Workstream

        if not isinstance(workstream, Workstream):
            raise TypeError("workstream must be a Workstream")
        self._controller.schedule_task(
            run_id,
            workstream.task_id,
            workstream.title,
            priority=workstream_priority(workstream.number, total_workstreams),
        )

    def _parent_publish_artifact_root(self, parent_run_id: str) -> Path:
        controller_root = getattr(self._controller, "artifact_root", None)
        if controller_root is None or self._mode == "dry_run":
            return self._artifact_root
        from artifact_isolation import DEFAULT_RUNS_ROOT, resolve_run_artifact_root

        return resolve_run_artifact_root(
            parent_run_id,
            Path(controller_root),
            runs_root=DEFAULT_RUNS_ROOT,
        )

    def _validate_existing_parent_id(self, parent_run_id: str) -> None:
        if not _EXISTING_PARENT_RUN_ID.fullmatch(parent_run_id):
            raise ValueError("existing parent run id must match goal-<16 hex chars>")

    def _assert_existing_parent_registered(self, parent_run_id: str) -> None:
        if self._mode == "dry_run":
            return
        repo = getattr(self._controller, "_repo", None)
        if repo is None:
            raise ValueError("existing parent binding requires a durable controller")
        try:
            repo.controller_state(parent_run_id)
        except KeyError:
            raise ValueError(f"existing parent is not registered: {parent_run_id}") from None

    def _validate_existing_snapshot(
        self,
        spec_path: Path,
        snapshot_path: Path,
        parsed: ParsedPrompt,
    ) -> None:
        stored = json.loads(_read_bytes(spec_path))
        if stored.get("prompt_digest") != parsed.sha256:
            raise ValueError("existing goal spec does not match prompt digest")
        if not snapshot_path.exists():
            raise ValueError("existing goal spec is missing prompt snapshot")
        if hashlib.sha256(_read_bytes(snapshot_path)).hexdigest() != parsed.sha256:
            raise ValueError("existing prompt snapshot does not match source prompt")


class DryRunParentController:
    """In-memory controller used for explicit dry-run submission."""

    def __init__(self) -> None:
        self.registered_runs: list[str] = []
        self.existing_tasks: set[str] = set()

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
        return {
            "run_id": run_id,
            "task_id": task_id,
            "objective": objective,
            "created": created,
        }


def build_controller(
    db_url: str,
    artifact_root: Path,
    *,
    dry_run: bool = False,
) -> ParentControllerLike:
    if dry_run:
        return DryRunParentController()
    from parent_controller import ParentController

    return ParentController(db_url, artifact_root=artifact_root, lease_holder=False)
