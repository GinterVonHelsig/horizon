"""Deterministic structured Executor result from official CLI streams."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from harness_adapters.contract import HarnessRequest
from harness_adapters.schema import validate_json_schema

WORK_EXECUTOR_RESULT_NAME = "executor-result.json"
WORK_EXECUTOR_RESULT_MAX_BYTES = 1024 * 1024
_BINDING_KEYS = ("run_id", "task_id", "attempt_id", "prompt_digest", "response_digest", "stdout_sha256")
_IDENTITY_KEYS = ("run_id", "task_id", "attempt_id")

EXECUTOR_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "adapter": {"type": "string", "minLength": 1},
        "kind": {"type": "string", "minLength": 1},
        "provider": {"type": "string", "minLength": 1},
        "model": {"type": "string", "minLength": 1},
        "model_revision": {"type": "string"},
        "prompt_digest": {"type": "string", "minLength": 64, "maxLength": 64},
        "response_digest": {"type": "string", "minLength": 64, "maxLength": 64},
        "changed_files": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "op": {"type": "string", "minLength": 1},
                },
                "required": ["path", "op"],
                "additionalProperties": False,
            },
        },
        "tool_calls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "status": {"type": "string", "minLength": 1},
                },
                "required": ["name", "status"],
                "additionalProperties": False,
            },
        },
        "focused_test_result": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "minLength": 1},
                "summary": {"type": "string"},
            },
            "required": ["status", "summary"],
            "additionalProperties": False,
        },
        "extracted_json": {"type": "object"},
        "stream_complete": {"type": "boolean"},
    },
    "required": [
        "adapter",
        "kind",
        "provider",
        "model",
        "prompt_digest",
        "response_digest",
        "changed_files",
        "tool_calls",
        "focused_test_result",
        "stream_complete",
    ],
    "additionalProperties": False,
}

_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL | re.IGNORECASE)


class StreamNormalizationError(ValueError):
    """Raised when a CLI stream cannot be normalized into the worker contract."""


def _decode_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StreamNormalizationError(f"malformed JSONL line: {exc}") from exc
    if not isinstance(value, dict):
        raise StreamNormalizationError("malformed JSONL line: expected object")
    return value


def _message_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        return _message_text(value.get("content"))
    if isinstance(value, list):
        texts = [_message_text(item) for item in value]
        joined = "".join(text for text in texts if text)
        return joined or None
    return None


def _try_json_object(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    if stripped.startswith("{"):
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None
    match = _JSON_FENCE.search(stripped)
    if match:
        try:
            value = json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None
    return None


def _tool_entries(event: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    status = str(event.get("subtype") or event.get("status") or "unknown")
    blob = event.get("tool_call")
    if isinstance(blob, dict):
        for key, payload in blob.items():
            if key.endswith("ToolCall") and isinstance(payload, dict):
                return key[: -len("ToolCall")], status, payload
    name = event.get("name") or event.get("tool")
    if isinstance(name, str) and name:
        payload = event.get("input") if isinstance(event.get("input"), dict) else {}
        return name, status, payload
    return "unknown", status, {}


def _changed_file(name: str, payload: dict[str, Any]) -> dict[str, str] | None:
    args = payload.get("args") if isinstance(payload.get("args"), dict) else payload
    path = args.get("path") or args.get("file_path") or args.get("filePath")
    if not isinstance(path, str) or not path:
        return None
    lowered = name.lower()
    if lowered in {"write", "edit", "strreplace", "applypatch", "apply_patch"}:
        op = "write" if lowered == "write" else "edit"
        return {"path": path, "op": op}
    return None


def _focused_test(tool_calls: list[dict[str, str]]) -> dict[str, str]:
    for item in tool_calls:
        if "test" in item["name"].lower():
            status = "pass" if item["status"] in {"completed", "success"} else "fail"
            return {"status": status, "summary": f"tool:{item['name']}"}
    return {"status": "not_run", "summary": "no focused test tool calls"}


def _ndjson_failure_event(event: dict[str, Any]) -> bool:
    event_type = event.get("type")
    if event_type == "result":
        return event.get("is_error") is True or event.get("subtype") not in (None, "success")
    if event_type in {"turn.failed", "error"}:
        return True
    if event_type == "item.completed":
        item = event.get("item")
        if isinstance(item, dict):
            if item.get("type") in {"error", "failed"}:
                return True
            if item.get("status") in {"failed", "error"}:
                return True
    return False


def _ndjson_success_terminal(kind: str, event: dict[str, Any], saw_result: bool) -> bool:
    event_type = event.get("type")
    if kind == "cursor_cli":
        return (
            saw_result
            and event_type == "result"
            and event.get("subtype") == "success"
            and event.get("is_error") is not True
        )
    if kind == "codex_cli":
        return event_type == "turn.completed"
    if kind == "claude_cli":
        return event_type == "result" and event.get("is_error") is not True
    if kind == "pi_cli":
        if event_type == "message_end":
            message = event.get("message")
            return isinstance(message, dict) and message.get("role") == "assistant"
    return False


def _ndjson_terminal(kind: str, events: list[dict[str, Any]], saw_result: bool) -> bool:
    if not events:
        return False
    success_index = -1
    for index, event in enumerate(events):
        if _ndjson_failure_event(event):
            return False
        if _ndjson_success_terminal(kind, event, saw_result):
            success_index = index
    return success_index == len(events) - 1


def collect_executor_stream_events(text: str) -> tuple[list[dict[str, Any]], bool, bool]:
    """Return JSON object events, whether every non-empty line was an object, and result-event presence."""
    events: list[dict[str, Any]] = []
    all_objects = True
    saw_result = False
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            all_objects = False
            continue
        if not isinstance(value, dict):
            all_objects = False
            continue
        events.append(value)
        if value.get("type") == "result":
            saw_result = True
    return events, all_objects, saw_result


def attempt_artifact_root(request: HarnessRequest) -> Path:
    artifact_dir = Path(request.artifact_dir).resolve()
    if artifact_dir.is_symlink():
        raise StreamNormalizationError("attempt artifact dir cannot be a symlink")
    if artifact_dir.name == "executor":
        root = artifact_dir.parent
    else:
        root = artifact_dir
    if root.is_symlink():
        raise StreamNormalizationError("attempt artifact root cannot be a symlink")
    return root


def _assert_contained(path: Path, root: Path) -> None:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise StreamNormalizationError(
            "work executor result escapes attempt artifact root"
        ) from exc


def load_work_executor_result(request: HarnessRequest) -> tuple[Path | None, dict[str, Any] | None]:
    """Load attempt-root work/executor-result.json. Missing is None; bad files fail closed.

    The authoritative sidecar is exactly ``<attempt>/work/executor-result.json``.
    Path containment is the identity binding for live Cursor packets that omit
    run/task/attempt keys. Optional identity and digest keys, when present, must
    still match. A cwd-relative sidecar outside that path is ignored, not trusted.
    """
    root = attempt_artifact_root(request)
    work_dir = root / "work"
    if work_dir.is_symlink():
        raise StreamNormalizationError("work executor result cannot be a symlink")
    if not work_dir.exists():
        return None, None
    if not work_dir.is_dir():
        raise StreamNormalizationError("work executor result must live in a directory")
    _assert_contained(work_dir, root)
    dir_fd = None
    fd = None
    try:
        dir_flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            dir_flags |= os.O_NOFOLLOW
        dir_fd = os.open(work_dir, dir_flags)
        open_flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            open_flags |= os.O_NONBLOCK
        try:
            if hasattr(os, "openat"):
                fd = os.openat(dir_fd, WORK_EXECUTOR_RESULT_NAME, open_flags)
            else:
                fd = os.open(WORK_EXECUTOR_RESULT_NAME, open_flags, dir_fd=dir_fd)
        except FileNotFoundError:
            return None, None
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise StreamNormalizationError("work executor result must be a regular file")
        if info.st_size > WORK_EXECUTOR_RESULT_MAX_BYTES:
            raise StreamNormalizationError("work executor result exceeds size bound")
        raw = b""
        while len(raw) <= WORK_EXECUTOR_RESULT_MAX_BYTES:
            chunk = os.read(fd, min(64 * 1024, WORK_EXECUTOR_RESULT_MAX_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
            if len(raw) > WORK_EXECUTOR_RESULT_MAX_BYTES:
                raise StreamNormalizationError("work executor result exceeds size bound")
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            return None, None
        raise StreamNormalizationError(f"work executor result cannot be opened: {exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if dir_fd is not None:
            os.close(dir_fd)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StreamNormalizationError(f"malformed work executor result: {exc}") from exc
    if not isinstance(payload, dict):
        raise StreamNormalizationError("work executor result must be an object")
    candidate = work_dir / WORK_EXECUTOR_RESULT_NAME
    return candidate, payload


def validate_work_executor_binding(
    payload: dict[str, Any],
    request: HarnessRequest,
    *,
    prompt_digest: str,
    response_digest: str,
) -> None:
    mapping = {
        "run_id": request.run_id,
        "task_id": request.task_id,
        "attempt_id": request.attempt_id,
        "prompt_digest": prompt_digest,
        "response_digest": response_digest,
        "stdout_sha256": response_digest,
    }
    present_identity = [key for key in _IDENTITY_KEYS if key in payload]
    if present_identity and set(present_identity) != set(_IDENTITY_KEYS):
        raise StreamNormalizationError("incomplete work executor result identity binding")
    for key, expected in mapping.items():
        if key not in payload:
            continue
        if payload[key] != expected:
            label = "stale" if key in {"prompt_digest", "response_digest", "stdout_sha256"} else "mismatched"
            raise StreamNormalizationError(f"{label} work executor result {key}")


def _extracted_from_work_file(payload: dict[str, Any]) -> dict[str, Any]:
    nested = payload.get("extracted_json")
    if isinstance(nested, dict):
        return nested
    return {key: value for key, value in payload.items() if key not in _BINDING_KEYS}


def _payload_from_events(
    *,
    kind: str,
    adapter: str,
    provider: str,
    model: str,
    prompt: str,
    text: str,
    truncated: bool,
    events: list[dict[str, Any]],
    extracted: dict[str, Any] | None,
    stream_complete: bool,
) -> dict[str, Any]:
    if not adapter or not kind or not provider or not model:
        raise StreamNormalizationError("required identity fields are missing")
    model_revision = ""
    changed: list[dict[str, str]] = []
    tool_calls: list[dict[str, str]] = []
    seen_files: set[tuple[str, str]] = set()
    stream_extracted = extracted
    for event in events:
        event_type = event.get("type")
        if event_type == "system" and event.get("subtype") == "init":
            revision = event.get("model")
            if isinstance(revision, str):
                model_revision = revision
        if stream_extracted is None and event_type in {"assistant", "item.completed"}:
            candidate = None
            if event_type == "assistant":
                candidate = _message_text(event.get("message"))
            else:
                item = event.get("item", {})
                if isinstance(item, dict) and item.get("type") == "agent_message":
                    candidate = _message_text(item)
            if isinstance(candidate, str):
                parsed = _try_json_object(candidate)
                if parsed is not None:
                    stream_extracted = parsed
        if event_type == "tool_call":
            name, status, payload = _tool_entries(event)
            tool_calls.append({"name": name, "status": status})
            file_change = _changed_file(name, payload)
            if file_change is not None:
                key = (file_change["path"], file_change["op"])
                if key not in seen_files:
                    seen_files.add(key)
                    changed.append(file_change)
    payload = {
        "adapter": adapter,
        "kind": kind,
        "provider": provider,
        "model": model,
        "model_revision": model_revision,
        "prompt_digest": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "response_digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "changed_files": changed,
        "tool_calls": tool_calls,
        "focused_test_result": _focused_test(tool_calls),
        "stream_complete": stream_complete and not truncated,
    }
    if stream_extracted is not None:
        payload["extracted_json"] = stream_extracted
    if "verdict" in payload:
        raise StreamNormalizationError("executor result cannot contain an auditor verdict")
    try:
        validate_json_schema(payload, EXECUTOR_RESULT_SCHEMA)
    except ValueError as exc:
        raise StreamNormalizationError(str(exc)) from exc
    return payload


def compose_canonical_executor_result(
    kind: str,
    text: str,
    *,
    adapter: str,
    provider: str,
    model: str,
    prompt: str,
    truncated: bool,
    request: HarnessRequest,
) -> dict[str, Any]:
    """Canonical Executor result from the typed work file and/or a valid NDJSON stream.

    Raw stdout remains an immutable artifact owned by the runner. When
    ``<attempt>/work/executor-result.json`` is present and valid, it is the sole
    source of ``extracted_json`` and a sidecar-alone completeness signal
    (``stream_complete = True`` even if the NDJSON stdout buffer truncated).
    and model revision. A valid NDJSON stream is used only when no work file
    exists and must include a terminal ``result`` event. This function never
    treats arbitrary top-level prose as success, never copies an Auditor verdict
    onto the Executor object, and fails closed on missing/malformed/stale/cross-run
    files.
    """
    prompt_digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    response_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    _path, work_payload = load_work_executor_result(request)
    if work_payload is not None:
        validate_work_executor_binding(
            work_payload,
            request,
            prompt_digest=prompt_digest,
            response_digest=response_digest,
        )
    events, all_objects, saw_result = collect_executor_stream_events(text)
    if work_payload is None:
        if not all_objects:
            raise StreamNormalizationError("malformed JSONL line: expected object")
        if not _ndjson_terminal(kind, events, saw_result):
            raise StreamNormalizationError("missing terminal stream result")
        return _payload_from_events(
            kind=kind,
            adapter=adapter,
            provider=provider,
            model=model,
            prompt=prompt,
            text=text,
            truncated=truncated,
            events=events,
            extracted=None,
            stream_complete=not truncated,
        )
    extracted = _extracted_from_work_file(work_payload)
    return _payload_from_events(
        kind=kind,
        adapter=adapter,
        provider=provider,
        model=model,
        prompt=prompt,
        text=text,
        truncated=truncated,
        events=events,
        extracted=extracted,
        stream_complete=True,
    )


def normalize_executor_stream(
    kind: str,
    text: str,
    *,
    adapter: str,
    provider: str,
    model: str,
    prompt: str,
    truncated: bool,
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        events.append(_decode_object(line))
    return _payload_from_events(
        kind=kind,
        adapter=adapter,
        provider=provider,
        model=model,
        prompt=prompt,
        text=text,
        truncated=truncated,
        events=events,
        extracted=None,
        stream_complete=not truncated,
    )
