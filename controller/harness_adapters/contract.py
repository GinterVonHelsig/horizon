"""Typed harness adapter contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from harness_adapters.redaction import contains_credential, sanitize_value, validate_env_name


@dataclass(frozen=True)
class HarnessRequest:
    run_id: str
    task_id: str
    attempt_id: str
    objective: str
    prompt: str
    cwd: str
    timeout: float
    output_schema: dict[str, Any] | None
    env_var_names: tuple[str, ...]
    artifact_dir: str
    metadata: dict[str, Any]

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        for name in self.env_var_names:
            validate_env_name(name)
        if contains_credential(self.metadata):
            raise ValueError("credential values are not allowed in serializable metadata")


@dataclass(frozen=True)
class HarnessResult:
    adapter_id: str
    kind: str
    model: str | None
    provider: str | None
    status: str
    exit_code: int | None
    duration_seconds: float
    stdout_artifact_path: str | None
    stdout_sha256: str | None
    stderr_artifact_path: str | None
    stderr_sha256: str | None
    structured_payload: dict[str, Any] | None
    error_classification: str | None
    retryable: bool
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return sanitize_value({
            "adapter_id": self.adapter_id,
            "kind": self.kind,
            "model": self.model,
            "provider": self.provider,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "stdout_artifact_path": self.stdout_artifact_path,
            "stdout_sha256": self.stdout_sha256,
            "stderr_artifact_path": self.stderr_artifact_path,
            "stderr_sha256": self.stderr_sha256,
            "structured_payload": self.structured_payload,
            "error_classification": self.error_classification,
            "retryable": self.retryable,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        })


class HarnessAdapter(Protocol):
    adapter_id: str

    def start(self, request: HarnessRequest) -> HarnessResult: ...

    def resume(self, request: HarnessRequest, session_id: str) -> HarnessResult: ...

    def cancel(self) -> None: ...

    def execute(self, request: HarnessRequest) -> HarnessResult: ...
