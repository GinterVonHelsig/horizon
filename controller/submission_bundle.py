"""Root-held parent-bound authority outside executor-writable runtime trees.

Canonical runtime paths, and services requiring trusted submissions, always use
TRUSTED_BUNDLES_ROOT. Only the root host gateway/recovery coordinator publishes
there. Other local roots support disposable/dry-run use without privileged trust.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path
from typing import Any

from artifact_owner import apply_artifact_owner, _configured_owner_ids
from prompt_ingest import parse_prompt_bytes

RUNTIME_RUNS_ROOT = Path("/var/lib/top-delivery/runs")
# /var/lib/top-delivery is service-owned: use its root-controlled sibling.
TRUSTED_BUNDLES_ROOT = Path("/var/lib/top-delivery-submission-bundles")
_GOAL_RUN_ID = re.compile(r"^goal-[0-9a-f]{16}$")
_GOAL_TASK_ID = re.compile(r"^(goal-[0-9a-f]{16})-ws-[0-9]{2,}$")
_BINDING_SCHEMA_VERSION = 1


class SubmissionBundleError(ValueError):
    """A preserved submission cannot be published or read safely."""


def _validate_run_id(run_id: str, label: str) -> None:
    if not _GOAL_RUN_ID.fullmatch(run_id):
        raise SubmissionBundleError(f"{label} must match goal-<16 hex chars>")


def _absolute(path: Path) -> Path:
    # Normalize '..' without erasing symlinks before the no-follow FD walk.
    return Path(os.path.abspath(path))


def _storage(artifact_root: Path, *, require_trusted: bool = False) -> tuple[Path, bool]:
    root, runtime = _absolute(artifact_root), _absolute(RUNTIME_RUNS_ROOT)
    required = os.environ.get("TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS", "").lower()
    if required not in ("", "0", "false", "1", "true"):
        raise SubmissionBundleError("invalid trusted-submissions service setting")
    # The root-set service flag remains authoritative after callers resolve a
    # runtime artifact symlink to a different path. Aliases cannot downgrade it.
    protected = _absolute(TRUSTED_BUNDLES_ROOT)
    trusted = (require_trusted or required in ("1", "true")
               or root.is_relative_to(protected)
               or root.is_relative_to(runtime)
               or root.resolve().is_relative_to(runtime.resolve()))
    return (_absolute(TRUSTED_BUNDLES_ROOT), True) if trusted else (root, False)


def _check_directory(info: os.stat_result, *, trusted: bool,
                     allow_root_sticky: bool = False,
                     require_service_read: bool = True) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise SubmissionBundleError("submission ancestor is not a directory")
    unsafe_write = bool(info.st_mode & 0o022) and not (
        allow_root_sticky and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
    )
    if trusted and (info.st_uid != 0 or unsafe_write):
        raise SubmissionBundleError("trusted store ancestor must be root-owned and not writable by other identities")
    if trusted and require_service_read and info.st_mode & 0o005 != 0o005:
        raise SubmissionBundleError("trusted store ancestor must be readable/traversable by the service identity")


def _open_directory(path: Path, *, trusted: bool, create: bool = False,
                    allow_root_sticky: bool = False,
                    require_service_read: bool = True) -> int:
    """Walk every component from an open root FD with O_NOFOLLOW."""
    absolute = _absolute(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(absolute.anchor, flags)
    try:
        _check_directory(os.fstat(fd), trusted=trusted, allow_root_sticky=allow_root_sticky,
                         require_service_read=require_service_read)
        for part in absolute.parts[1:]:
            created = False
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o555 if trusted else 0o755, dir_fd=fd)
                    created = True
                except FileExistsError:
                    pass
                next_fd = os.open(part, flags, dir_fd=fd)
            try:
                _check_directory(os.fstat(next_fd), trusted=trusted,
                                 allow_root_sticky=allow_root_sticky,
                                 require_service_read=False if created else require_service_read)
                if created and trusted:
                    os.fchmod(next_fd, 0o555)
                if created:
                    _check_directory(os.fstat(next_fd), trusted=trusted,
                                     allow_root_sticky=allow_root_sticky,
                                     require_service_read=require_service_read)
                    os.fsync(next_fd)
                    os.fsync(fd)
            except Exception:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
        return fd
    except Exception as exc:
        os.close(fd)
        if isinstance(exc, SubmissionBundleError):
            raise
        raise SubmissionBundleError("submission path is missing, unreadable, or contains a symlink") from exc


def _read_bytes(path: Path, *, trusted: bool = False) -> bytes:
    """Hash and parse the bytes from this one no-follow FD; never reopen later."""
    path = _absolute(path)
    directory_fd = _open_directory(path.parent, trusted=trusted)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise SubmissionBundleError("submission artifact must be a regular file")
            if trusted and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o444):
                raise SubmissionBundleError("trusted submission artifact must be root-owned mode 0444")
            return handle.read()
    except OSError as exc:
        raise SubmissionBundleError("submission artifact is missing, unreadable, or a symlink") from exc
    finally:
        os.close(directory_fd)


def _json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SubmissionBundleError(f"{label} is unreadable") from exc
    if not isinstance(payload, dict):
        raise SubmissionBundleError(f"{label} must be an object")
    return payload


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bundle_dir(root: Path, parent_run_id: str, submission_run_id: str) -> Path:
    _validate_run_id(parent_run_id, "parent run id")
    _validate_run_id(submission_run_id, "submission run id")
    if parent_run_id == submission_run_id:
        raise SubmissionBundleError("parent run id must differ from submission run id")
    return root / "runs" / parent_run_id / "submissions" / submission_run_id


def _validate_task_ids(submission_run_id: str, task_ids: tuple[str, ...], spec: dict[str, Any]) -> None:
    if not task_ids or len(set(task_ids)) != len(task_ids):
        raise SubmissionBundleError("unique task ids are required")
    entries = spec.get("workstreams")
    if not isinstance(entries, list) or not entries or not all(isinstance(item, dict) for item in entries):
        raise SubmissionBundleError("goal spec workstreams are required")
    if sorted(str(item.get("task_id", "")) for item in entries) != sorted(task_ids):
        raise SubmissionBundleError("task ids do not match goal spec workstreams")
    for task_id in task_ids:
        match = _GOAL_TASK_ID.fullmatch(task_id)
        if match is None or match.group(1) != submission_run_id:
            raise SubmissionBundleError("task id is outside submission namespace")


def _validate_prompt_graph(snapshot: bytes, spec: dict[str, Any]) -> None:
    try:
        parsed = parse_prompt_bytes(snapshot, source="immutable submission snapshot")
    except (ValueError, UnicodeError) as exc:
        raise SubmissionBundleError("submission prompt cannot be parsed") from exc
    if spec.get("run_id") != parsed.run_id:
        raise SubmissionBundleError("submission run id does not derive from prompt digest")
    for key in ("title", "objective", "mission"):
        if spec.get(key) != getattr(parsed, key):
            raise SubmissionBundleError(f"goal spec {key} differs from original prompt")
    for key in ("allowed", "forbidden"):
        if spec.get(key) != list(getattr(parsed, key)):
            raise SubmissionBundleError(f"goal spec {key} differs from original prompt")
    entries = spec.get("workstreams")
    if not isinstance(entries, list) or len(entries) != len(parsed.workstreams):
        raise SubmissionBundleError("goal spec graph differs from original prompt")
    prompt_text = snapshot.decode("utf-8")
    for entry, workstream in zip(entries, parsed.workstreams):
        expected = {
            "number": workstream.number, "title": workstream.title, "task_id": workstream.task_id,
            "required_disposition": workstream.required_disposition, "dependencies": list(workstream.dependencies),
            "prompt": prompt_text, "acceptance_criteria": [workstream.required_disposition],
        }
        if not isinstance(entry, dict) or any(entry.get(key) != value for key, value in expected.items()):
            raise SubmissionBundleError("goal spec graph/authority differs from original prompt")


def _validate_spec(spec_bytes: bytes, snapshot: bytes, *, submission_run_id: str,
                   prompt_digest: str, task_ids: tuple[str, ...]) -> dict[str, Any]:
    spec = _json_object(spec_bytes, "submission goal spec")
    if spec.get("run_id") != submission_run_id:
        raise SubmissionBundleError("goal spec run_id mismatch")
    if spec.get("prompt_digest") != prompt_digest:
        raise SubmissionBundleError("goal spec prompt_digest mismatch")
    if _digest(snapshot) != prompt_digest:
        raise SubmissionBundleError("prompt snapshot digest mismatch")
    _validate_task_ids(submission_run_id, task_ids, spec)
    _validate_prompt_graph(snapshot, spec)
    return spec


def _read_bundle(bundle: Path, *, parent_run_id: str, trusted: bool,
                 task_id: str | None = None, committed: bool = True,
                 expected_binding: dict[str, Any] | None = None) -> dict[str, Any]:
    # Runtime binding is an external root-held digest anchor. Executor-writable
    # copies are never consulted as authority, including cwd and adapter fields.
    binding = _json_object(_read_bytes(bundle / "binding.json", trusted=trusted), "submission binding")
    if expected_binding is not None and binding != expected_binding:
        raise SubmissionBundleError("conflicting submission bundle")
    if binding.get("schema_version") != _BINDING_SCHEMA_VERSION or binding.get("parent_run_id") != parent_run_id:
        raise SubmissionBundleError("submission binding schema or parent mismatch")
    submission = binding.get("submission_run_id")
    if not isinstance(submission, str):
        raise SubmissionBundleError("submission run id is required")
    _validate_run_id(submission, "submission run id")
    if submission == parent_run_id or (committed and bundle.name != submission):
        raise SubmissionBundleError("submission bundle directory identity mismatch")
    tasks = binding.get("task_ids")
    if not isinstance(tasks, list) or not all(isinstance(item, str) for item in tasks):
        raise SubmissionBundleError("submission binding task ids are required")
    if task_id is not None and task_id not in tasks:
        raise SubmissionBundleError("submission binding task mismatch")
    for key in ("goal_spec_digest", "prompt_snapshot_digest", "prompt_digest"):
        if not isinstance(binding.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", binding[key]):
            raise SubmissionBundleError("submission binding digests are required")
    spec_bytes = _read_bytes(bundle / "goal-spec.json", trusted=trusted)
    snapshot = _read_bytes(bundle / "prompt.snapshot.md", trusted=trusted)
    if _digest(spec_bytes) != binding["goal_spec_digest"]:
        raise SubmissionBundleError("bound goal spec digest mismatch")
    if _digest(snapshot) != binding["prompt_snapshot_digest"]:
        raise SubmissionBundleError("bound prompt snapshot digest mismatch")
    if binding["prompt_snapshot_digest"] != binding["prompt_digest"]:
        raise SubmissionBundleError("prompt digest binding mismatch")
    return _validate_spec(spec_bytes, snapshot, submission_run_id=submission,
                          prompt_digest=binding["prompt_digest"], task_ids=tuple(tasks))


def _write_new_file(path: Path, data: bytes, *, trusted: bool) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fchmod(handle.fileno(), 0o444 if trusted else 0o644)
        if not trusted:
            owner = _configured_owner_ids()
            if owner is not None:
                os.fchown(handle.fileno(), *owner)
        os.fsync(handle.fileno())


def publish_parent_bound_submission_bundle(
    artifact_root: Path, *, parent_run_id: str, submission_run_id: str,
    submission_dir: Path, task_ids: tuple[str, ...] | list[str], prompt_digest: str,
    expected_goal_spec_digest: str | None = None,
    require_trusted: bool = False,
) -> Path:
    """Publish captured source bytes before scheduling; runtime writes require root."""
    root, trusted = _storage(artifact_root, require_trusted=require_trusted)
    if trusted and os.geteuid() != 0:
        raise SubmissionBundleError("runtime submission publication requires the root host gateway")
    bundle = _bundle_dir(root, parent_run_id, submission_run_id)
    tasks = tuple(str(task_id) for task_id in task_ids)
    spec_bytes = _read_bytes(Path(submission_dir) / "goal-spec.json")
    snapshot = _read_bytes(Path(submission_dir) / "prompt.snapshot.md")
    spec_digest = _digest(spec_bytes)
    if expected_goal_spec_digest is not None and spec_digest != expected_goal_spec_digest:
        raise SubmissionBundleError("recovery goal spec differs from reviewed digest")
    _validate_spec(spec_bytes, snapshot, submission_run_id=submission_run_id,
                   prompt_digest=prompt_digest, task_ids=tasks)
    binding = {
        "schema_version": _BINDING_SCHEMA_VERSION, "parent_run_id": parent_run_id,
        "submission_run_id": submission_run_id, "prompt_digest": prompt_digest,
        "task_ids": list(tasks), "goal_spec_digest": spec_digest,
        "prompt_snapshot_digest": _digest(snapshot),
    }
    parent_fd = _open_directory(bundle.parent, trusted=trusted or os.geteuid() == 0,
                                create=True, allow_root_sticky=not trusted,
                                require_service_read=trusted)
    try:
        if bundle.exists() or bundle.is_symlink():
            _read_bundle(bundle, parent_run_id=parent_run_id, trusted=trusted, expected_binding=binding)
            return bundle
        staging = bundle.parent / f".{submission_run_id}.publish-{uuid.uuid4().hex}"
        os.mkdir(staging.name, mode=0o700, dir_fd=parent_fd)
        try:
            _write_new_file(staging / "goal-spec.json", spec_bytes, trusted=trusted)
            _write_new_file(staging / "prompt.snapshot.md", snapshot, trusted=trusted)
            _write_new_file(staging / "binding.json", (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode(), trusted=trusted)
            staging.chmod(0o555 if trusted else 0o755)
            _read_bundle(staging, parent_run_id=parent_run_id, trusted=trusted, committed=False, expected_binding=binding)
            staging_fd = _open_directory(staging, trusted=trusted)
            try:
                os.fsync(staging_fd)
            finally:
                os.close(staging_fd)
            try:
                os.rename(staging.name, bundle.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            except OSError:
                if not bundle.exists():
                    raise
                _read_bundle(bundle, parent_run_id=parent_run_id, trusted=trusted, expected_binding=binding)
            if not trusted:
                apply_artifact_owner(bundle)
            os.fsync(parent_fd)
            return bundle
        finally:
            if staging.exists():
                if not trusted:
                    staging.chmod(0o700)
                shutil.rmtree(staging)
    finally:
        os.close(parent_fd)


def _bound_submission_id(parent_run_id: str, task_id: str) -> str | None:
    if not _GOAL_RUN_ID.fullmatch(parent_run_id):
        return None
    match = _GOAL_TASK_ID.fullmatch(task_id)
    if match is None:
        if task_id.startswith("goal-") and "-ws-" in task_id:
            raise SubmissionBundleError("invalid goal task id")
        return None
    submission = match.group(1)
    return None if submission == parent_run_id else submission


def load_bound_goal_spec(artifact_root: Path, parent_run_id: str, task_id: str) -> dict[str, Any] | None:
    """Return already-validated data; consumers must never reopen a checked path."""
    submission = _bound_submission_id(parent_run_id, task_id)
    if submission is None:
        return None
    root, trusted = _storage(artifact_root)
    return _read_bundle(_bundle_dir(root, parent_run_id, submission), parent_run_id=parent_run_id,
                        trusted=trusted, task_id=task_id)


def resolve_submission_run_id(artifact_root: Path, parent_run_id: str, task_id: str) -> str | None:
    spec = load_bound_goal_spec(artifact_root, parent_run_id, task_id)
    return None if spec is None else str(spec["run_id"])


def resolve_bound_goal_spec_path(artifact_root: Path, parent_run_id: str, task_id: str) -> Path | None:
    """Diagnostic path only; execution consumes load_bound_goal_spec's data."""
    submission = resolve_submission_run_id(artifact_root, parent_run_id, task_id)
    if submission is None:
        return None
    root, _ = _storage(artifact_root)
    return _bundle_dir(root, parent_run_id, submission) / "goal-spec.json"


def recover_parent_bound_submission_bundle(
    artifact_root: Path, *, parent_run_id: str, submission_run_id: str,
    submission_dir: Path, task_ids: tuple[str, ...] | list[str],
    prompt_digest: str, expected_goal_spec_digest: str,
) -> Path:
    """The root-held binding retains the reviewed source digest for every read."""
    if not isinstance(expected_goal_spec_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_goal_spec_digest):
        raise SubmissionBundleError("reviewed goal spec digest is required for recovery")
    return publish_parent_bound_submission_bundle(
        artifact_root, parent_run_id=parent_run_id, submission_run_id=submission_run_id,
        submission_dir=submission_dir, task_ids=task_ids, prompt_digest=prompt_digest,
        expected_goal_spec_digest=expected_goal_spec_digest,
        require_trusted=True,
    )
