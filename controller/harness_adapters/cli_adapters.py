"""Official CLI harness adapters, argv builders, and JSONL event parsers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness_adapters.contract import HarnessRequest, HarnessResult
from harness_adapters.schema import validate_json_schema
from harness_adapters.structured_result import (
    EXECUTOR_RESULT_SCHEMA,
    StreamNormalizationError,
    compose_canonical_executor_result,
)
from harness_adapters.subprocess_runner import SubprocessRunner


def build_codex_argv(*, executable: str, prompt: str, codex_home: str, model: str | None) -> list[str]:
    # CODEX_HOME is supplied through the child environment, never a CLI flag.
    argv = [executable, "exec", "--json"]
    if model:
        argv.extend(["--model", model])
    argv.append(prompt)
    return argv


def build_cursor_argv(
    *, executable: str, prompt: str, model: str, approval_mode: str,
    worktree: str | None, cursor_mode: str | None = None,
) -> list[str]:
    argv = [executable, "-p", prompt, "--output-format", "stream-json", "--model", model]
    if cursor_mode == "ask":
        argv.extend(["--mode", "ask", "--sandbox", "enabled", "--trust"])
    else:
        argv.append("--force" if approval_mode == "never" else "--approve-mcps")
        if cursor_mode == "agent":
            argv.extend(["--sandbox", "enabled", "--trust"])
    if worktree:
        argv.extend(["--worktree", worktree])
    return argv


def build_claude_argv(
    *, executable: str, prompt: str, model: str, permission_mode: str,
) -> list[str]:
    return [
        executable, "-p", prompt, "--output-format", "stream-json", "--model", model,
        "--permission-mode", permission_mode,
    ]


def build_pi_argv(
    *, executable: str, prompt: str, model: str, endpoint: str = "",
    provider: str = "openrouter",
) -> list[str]:
    # Pi's official interface is --mode json; endpoint selection belongs in its
    # configured provider, not an unsupported --base-url argument.
    return [
        executable, "-p", prompt, "--mode", "json", "--provider", provider,
        "--model", model, "--no-session",
    ]


def _decode_object(text: str) -> dict[str, Any]:
    value = json.loads(text.strip())
    if not isinstance(value, dict):
        raise ValueError("structured response must be an object")
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


def parse_cli_output(kind: str, text: str) -> dict[str, Any]:
    """Extract the final assistant JSON object from an official JSONL stream."""
    candidates: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        event = _decode_object(line)
        event_type = event.get("type")
        candidate: str | None = None
        if kind == "codex_cli" and event_type == "item.completed":
            item = event.get("item", {})
            if isinstance(item, dict) and item.get("type") == "agent_message":
                candidate = _message_text(item)
        elif kind in {"cursor_cli", "claude_cli"} and event_type == "assistant":
            candidate = _message_text(event.get("message"))
        elif kind == "pi_cli" and event_type in {"message_end", "agent_message_end"}:
            message = event.get("message", event)
            if isinstance(message, dict) and message.get("role", "assistant") == "assistant":
                candidate = _message_text(message)
        if candidate is not None:
            candidates.append(candidate)
    if not candidates:
        # Pi may produce one final JSON object rather than events in some versions.
        if kind == "pi_cli":
            value = _decode_object(text)
            if "type" not in value:
                return value
        raise ValueError("no final assistant message in JSONL stream")
    return _decode_object(candidates[-1])


@dataclass
class CliHarnessAdapter:
    adapter_id: str
    kind: str
    executable: str
    model: str
    credential_env: tuple[str, ...]
    timeout_seconds: float
    allowed_cwd_roots: tuple[str, ...]
    runner: SubprocessRunner
    provider: str = "official_cli"
    codex_home: str | None = None
    permission_mode: str | None = None
    approval_mode: str | None = None
    worktree: str | None = None
    endpoint: str | None = None
    cursor_mode: str | None = None
    broker_socket: str | None = None
    broker_route_id: str | None = None
    _cancel_requested: bool = False

    def start(self, request: HarnessRequest) -> HarnessResult:
        return self.execute(request)

    def resume(self, request: HarnessRequest, session_id: str) -> HarnessResult:
        role_dir = Path(request.artifact_dir)
        role_dir.mkdir(parents=True, exist_ok=True)
        (role_dir / "harness-session.json").write_text(
            json.dumps({"session_id": session_id}, indent=2, sort_keys=True) + "\n"
        )
        return self.execute(request)

    def cancel(self) -> None:
        self._cancel_requested = True
        self.runner.cancel()

    def execute(self, request: HarnessRequest) -> HarnessResult:
        self._cancel_requested = False
        cwd = self._resolve_cwd(request.cwd)
        self.runner.artifact_dir = Path(request.artifact_dir)
        argv = self._build_argv(request.prompt)
        extra_env = {"CODEX_HOME": self.codex_home} if self.kind == "codex_cli" and self.codex_home else None
        if self.broker_socket is not None:
            role = request.metadata.get("role") if isinstance(request.metadata, dict) else None
            if role not in {"executor", "auditor"} or not self.broker_route_id:
                return HarnessResult(self.adapter_id, self.kind, self.model, self.provider, "failure", 78,
                    0.0, None, None, None, None, None, "broker_identity_missing", False)
            extra_env = {
                "HORIZON_CURSOR_BROKER_SOCKET": self.broker_socket,
                "HORIZON_CURSOR_BROKER_ROUTE": self.broker_route_id,
                "HORIZON_CURSOR_BROKER_RUN_ID": request.run_id,
                "HORIZON_CURSOR_BROKER_TASK_ID": request.task_id,
                "HORIZON_CURSOR_BROKER_ATTEMPT_ID": request.attempt_id,
                "HORIZON_CURSOR_BROKER_ROLE": role,
            }
        role = request.metadata.get("role") if isinstance(request.metadata, dict) else None
        auditor = role == "auditor"
        parser = (lambda text: parse_cli_output(self.kind, text)) if auditor else None
        run = self.runner.run(
            executable=self.executable, argv=argv, cwd=cwd,
            timeout=min(request.timeout, self.timeout_seconds),
            credential_env_names=self.credential_env,
            output_parser=parser,
            cancel_check=lambda: self._cancel_requested, extra_env=extra_env,
        )
        classification = run.error_classification
        structured = run.structured_payload
        if not auditor and classification is None:
            text = self._stdout_text(request, run)
            try:
                structured = compose_canonical_executor_result(
                    self.kind, text, adapter=self.adapter_id, provider=self.provider,
                    model=self.model, prompt=request.prompt,
                    truncated=bool(run.stdout_truncated or run.stderr_truncated),
                    request=request,
                )
                schema = request.output_schema or EXECUTOR_RESULT_SCHEMA
                validate_json_schema(structured, schema)
                if not structured.get("stream_complete"):
                    classification = "malformed_structured_output"
            except (StreamNormalizationError, ValueError, json.JSONDecodeError):
                classification = "malformed_structured_output"
                structured = None
        elif classification is None:
            try:
                validate_json_schema(structured, request.output_schema)
            except ValueError:
                classification = "malformed_structured_output"
        if run.exit_code not in (0, None) and classification is None:
            classification = "process_failure"
        retryable = run.retryable or classification == "malformed_structured_output"
        status = "success" if classification is None and run.exit_code == 0 else "failure"
        return HarnessResult(
            self.adapter_id, self.kind, self.model, self.provider, status, run.exit_code,
            run.duration_seconds, run.stdout_artifact_path, run.stdout_sha256,
            run.stderr_artifact_path, run.stderr_sha256, structured, classification,
            retryable, run.stdout_truncated, run.stderr_truncated,
        )

    @staticmethod
    def _stdout_text(request: HarnessRequest, run: Any) -> str:
        path_name = run.stdout_artifact_path
        if path_name:
            candidate = Path(request.artifact_dir) / path_name
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8", errors="replace")
        return run.inline_stdout or ""

    def _resolve_cwd(self, cwd: str) -> str:
        resolved = Path(cwd).resolve()
        if any(resolved == Path(root).resolve() or resolved.is_relative_to(Path(root).resolve())
               for root in self.allowed_cwd_roots):
            return str(resolved)
        raise ValueError("cwd is outside allowed roots")

    def _build_argv(self, prompt: str) -> list[str]:
        if self.kind == "codex_cli":
            return build_codex_argv(executable=self.executable, prompt=prompt,
                                    codex_home=self.codex_home or "", model=self.model)
        if self.kind in {"cursor_cli", "gateway_delivery"}:
            return build_cursor_argv(executable=self.executable, prompt=prompt, model=self.model,
                                     approval_mode=self.approval_mode or "never", worktree=self.worktree,
                                     cursor_mode=self.cursor_mode or ("agent" if self.kind == "gateway_delivery" else None))
        if self.kind == "claude_cli":
            return build_claude_argv(executable=self.executable, prompt=prompt, model=self.model,
                                     permission_mode=self.permission_mode or "default")
        if self.kind == "pi_cli":
            return build_pi_argv(executable=self.executable, prompt=prompt, model=self.model,
                                 endpoint=self.endpoint or "", provider=self.provider)
        raise ValueError(f"unsupported cli kind: {self.kind}")


def cli_adapter_from_config(adapter_id: str, config: dict[str, Any], artifact_dir: Path) -> CliHarnessAdapter:
    runner = SubprocessRunner(
        artifact_dir=artifact_dir,
        allowlisted_env=tuple(config.get("allowlisted_env", ("PATH", "HOME", "LANG"))),
        inline_output_limit=int(config.get("inline_output_limit", 4096)),
        artifact_output_limit=int(config.get("artifact_output_limit", 1024 * 1024)),
    )
    return CliHarnessAdapter(
        adapter_id=adapter_id, kind=str(config["kind"]), executable=str(config["executable"]),
        model=str(config["model"]), provider=str(config["provider"]),
        credential_env=tuple(config.get("credential_env", [])),
        timeout_seconds=float(config["timeout_seconds"]),
        allowed_cwd_roots=tuple(config["allowed_cwd_roots"]), runner=runner,
        codex_home=config.get("codex_home"), permission_mode=config.get("permission_mode"),
        approval_mode=config.get("approval_mode"), worktree=config.get("worktree"),
        endpoint=config.get("endpoint"),
        cursor_mode=config.get("cursor_mode"),
        broker_socket=config.get("broker_socket"), broker_route_id=config.get("broker_route_id"),
    )
