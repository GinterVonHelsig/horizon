"""Harness adapter contract and registry validation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness_adapters.contract import HarnessRequest, HarnessResult
from harness_adapters.registry import AdapterRegistry, load_registry_config


def _sample_request(**overrides: object) -> HarnessRequest:
    base = {
        "run_id": "run-1",
        "task_id": "task-1",
        "attempt_id": "attempt-1",
        "objective": "do work",
        "prompt": "execute task",
        "cwd": "/tmp/work",
        "timeout": 30.0,
        "output_schema": {"type": "object", "properties": {"status": {"type": "string"}}},
        "env_var_names": ("OPENAI_API_KEY",),
        "artifact_dir": "/tmp/artifacts/attempt-1",
        "metadata": {"executor_adapter": "codex-cli", "auditor_adapter": "claude-cli"},
    }
    base.update(overrides)
    return HarnessRequest(**base)  # type: ignore[arg-type]


def test_harness_request_rejects_credential_values_in_metadata() -> None:
    with pytest.raises(ValueError, match="credential"):
        _sample_request(metadata={"api_key": "sk-secret-value"})


def test_harness_request_rejects_nested_credentials_and_invalid_env_names() -> None:
    with pytest.raises(ValueError, match="credential"):
        _sample_request(metadata={"safe": [{"nested": "Bearer hidden-token-value"}]})
    with pytest.raises(ValueError, match="credential"):
        _sample_request(metadata={"safe": {"password": "nested-hidden"}})
    with pytest.raises(ValueError, match="environment"):
        _sample_request(env_var_names=("BAD-NAME",))


def test_harness_result_recursively_sanitizes_structured_payload() -> None:
    result = HarnessResult(
        adapter_id="safe", kind="fake", model="m", provider="p", status="success",
        exit_code=0, duration_seconds=0.1, stdout_artifact_path=None,
        stdout_sha256=None, stderr_artifact_path=None, stderr_sha256=None,
        structured_payload={"outer": {"password": "hidden", "text": "token=hidden-two"}},
        error_classification=None, retryable=False,
    )
    dumped = json.dumps(result.to_dict())
    assert "hidden" not in dumped
    assert "[REDACTED]" in dumped


def test_harness_result_serializes_without_credential_fields() -> None:
    result = HarnessResult(
        adapter_id="codex-cli",
        kind="cli",
        model="gpt-5",
        provider="openai",
        status="success",
        exit_code=0,
        duration_seconds=1.5,
        stdout_artifact_path="stdout.txt",
        stdout_sha256="a" * 64,
        stderr_artifact_path="stderr.txt",
        stderr_sha256="b" * 64,
        structured_payload={"verdict": "approve"},
        error_classification=None,
        retryable=False,
    )
    payload = result.to_dict()
    dumped = json.dumps(payload)
    assert "sk-" not in dumped
    assert payload["adapter_id"] == "codex-cli"


def test_registry_rejects_relative_executable(tmp_path: Path) -> None:
    config = {
        "adapters": [
            {
                "id": "codex-cli",
                "kind": "codex_cli",
                "provider": "openai",
                "executable": "codex",
                "codex_home": "/tmp/codex",
                "model": "gpt-5",
                "credential_env": ["OPENAI_API_KEY"],
                "timeout_seconds": 60,
                "allowed_cwd_roots": ["/tmp"],
            }
        ],
        "routes": {"default_executor": "codex-cli", "default_auditor": "claude-cli"},
    }
    path = tmp_path / "adapters.json"
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="absolute"):
        load_registry_config(path)


def test_registry_rejects_same_executor_and_auditor() -> None:
    config = {
        "adapters": [
            {
                "id": "shared",
                "kind": "codex_cli",
                "provider": "openai",
                "executable": "/usr/bin/codex",
                "codex_home": "/tmp/codex",
                "model": "gpt-5",
                "credential_env": [],
                "timeout_seconds": 60,
                "allowed_cwd_roots": ["/tmp"],
            }
        ],
        "routes": {"default_executor": "shared", "default_auditor": "shared"},
    }
    with pytest.raises(ValueError, match="distinct"):
        AdapterRegistry.from_config(config, artifact_dir=Path("/tmp/adapters"))


def test_registry_rejects_unknown_kind() -> None:
    config = {
        "adapters": [
            {
                "id": "bad",
                "kind": "unknown_kind",
                "provider": "fake",
                "executable": "/usr/bin/fake",
                "model": "m",
                "credential_env": [],
                "timeout_seconds": 60,
                "allowed_cwd_roots": ["/tmp"],
            }
        ],
        "routes": {"default_executor": "bad", "default_auditor": "other"},
    }
    config["adapters"].append({**config["adapters"][0], "id": "other", "kind": "claude_cli", "permission_mode": "default"})
    with pytest.raises(ValueError, match="unknown"):
        AdapterRegistry.from_config(config, artifact_dir=Path("/tmp/adapters"))


def test_registry_rejects_shallow_invalid_fields() -> None:
    base = {
        "id": "cli", "kind": "codex_cli", "provider": "openai",
        "executable": "/usr/bin/codex", "model": "m", "codex_home": "/tmp/codex",
        "credential_env": [], "timeout_seconds": 60, "allowed_cwd_roots": ["/tmp"],
    }
    configs = [
        {"adapters": [{**base, "allowed_cwd_roots": ["relative"]}], "routes": {"default_executor": "cli", "default_auditor": "other"}},
        {"adapters": [{**base, "credential_env": ["BAD-NAME"]}], "routes": {"default_executor": "cli", "default_auditor": "other"}},
        {"adapters": [{**base, "provider": ""}], "routes": {"default_executor": "cli", "default_auditor": "other"}},
        {"adapters": [base], "routes": {"default_executor": "cli", "default_auditor": "other", "surprise": True}},
    ]
    for config in configs:
        with pytest.raises(ValueError):
            AdapterRegistry.from_config(config, artifact_dir=Path("/tmp/adapters"))


def test_registry_http_requires_one_valid_credential_name_and_no_secret_values() -> None:
    http = {
        "id": "http", "kind": "http_openai", "provider": "comms01",
        "endpoint": "http://127.0.0.1:9000/v1/chat/completions", "model": "m",
        "credential_env": [], "timeout_seconds": 60, "allowed_cwd_roots": ["/tmp"],
    }
    other = {
        "id": "other", "kind": "claude_cli", "provider": "anthropic",
        "executable": "/usr/bin/claude", "model": "m", "permission_mode": "default",
        "credential_env": [], "timeout_seconds": 60, "allowed_cwd_roots": ["/tmp"],
    }
    config = {"adapters": [http, other], "routes": {"default_executor": "http", "default_auditor": "other"}}
    with pytest.raises(ValueError, match="credential"):
        AdapterRegistry.from_config(config, artifact_dir=Path("/tmp/adapters"))
    config["adapters"][0] = {**http, "credential_env": ["COMMS_KEY"], "label": "sk-live-secret-value"}
    with pytest.raises(ValueError):
        AdapterRegistry.from_config(config, artifact_dir=Path("/tmp/adapters"))


def test_registry_rejects_prohibited_codex_yolo_executable(tmp_path: Path) -> None:
    auditor = tmp_path / "claude"
    auditor.write_text("#!/bin/sh\n")
    auditor.chmod(0o755)
    config = {
        "adapters": [
            {
                "id": "codex-cli",
                "kind": "codex_cli",
                "provider": "openai",
                "executable": "/usr/local/bin/codex-yolo",
                "codex_home": str(tmp_path / "codex"),
                "model": "gpt-5",
                "credential_env": [],
                "timeout_seconds": 60,
                "allowed_cwd_roots": [str(tmp_path)],
            },
            {
                "id": "auditor",
                "kind": "claude_cli",
                "provider": "anthropic",
                "permission_mode": "default",
                "executable": str(auditor),
                "model": "claude-opus",
                "credential_env": [],
                "timeout_seconds": 60,
                "allowed_cwd_roots": [str(tmp_path)],
            },
        ],
        "routes": {"default_executor": "codex-cli", "default_auditor": "auditor"},
    }
    (tmp_path / "codex").mkdir()
    with pytest.raises(ValueError, match="prohibited"):
        AdapterRegistry.from_config(config, artifact_dir=tmp_path / "adapters")


def test_registry_defers_missing_executable_at_boot_but_fails_on_execute(tmp_path: Path) -> None:
    auditor = tmp_path / "claude"
    auditor.write_text("#!/bin/sh\n")
    auditor.chmod(0o755)
    config = {
        "adapters": [
            {
                "id": "codex-cli",
                "kind": "codex_cli",
                "provider": "openai",
                "executable": "/usr/local/bin/missing-codex-on-comms01",
                "codex_home": str(tmp_path / "codex"),
                "model": "gpt-5",
                "credential_env": [],
                "timeout_seconds": 60,
                "allowed_cwd_roots": [str(tmp_path)],
            },
            {
                "id": "auditor",
                "kind": "claude_cli",
                "provider": "anthropic",
                "permission_mode": "default",
                "executable": str(auditor),
                "model": "claude-opus",
                "credential_env": [],
                "timeout_seconds": 60,
                "allowed_cwd_roots": [str(tmp_path)],
            },
        ],
        "routes": {"default_executor": "codex-cli", "default_auditor": "auditor"},
    }
    (tmp_path / "codex").mkdir()
    path = tmp_path / "adapters.json"
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="executable must exist"):
        load_registry_config(path)
    loaded = load_registry_config(path, validate_executables=False)
    registry = AdapterRegistry.from_config(
        loaded,
        artifact_dir=tmp_path / "runtime",
        validate_executables=False,
    )
    adapter = registry.get("codex-cli")
    request = _sample_request(
        cwd=str(tmp_path),
        artifact_dir=str(tmp_path / "runtime" / "attempt-1"),
        metadata={"executor_adapter": "codex-cli"},
    )
    result = adapter.execute(request)
    assert result.status == "failure"
    assert result.error_classification == "missing_executable"


def test_registry_rejects_symlink_to_prohibited_codex_yolo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from harness_adapters import executable_policy

    prohibited = tmp_path / "codex-yolo"
    prohibited.write_text("#!/bin/sh\n")
    prohibited.chmod(0o755)
    wrapper = tmp_path / "codex-wrapper"
    wrapper.symlink_to(prohibited)
    monkeypatch.setattr(executable_policy, "PROHIBITED_EXECUTABLES", frozenset({str(prohibited.resolve())}))
    with pytest.raises(ValueError, match="prohibited"):
        executable_policy.resolve_trusted_executable(str(wrapper))

    config = {
        "adapters": [
            {
                "id": "remote",
                "kind": "http_openai",
                "provider": "openai",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "model": "gpt-5",
                "credential_env": ["OPENAI_API_KEY"],
                "timeout_seconds": 60,
                "allowed_cwd_roots": ["/tmp"],
            },
            {
                "id": "auditor",
                "kind": "claude_cli",
                "provider": "anthropic",
                "permission_mode": "default",
                "executable": "/usr/bin/claude",
                "model": "claude-opus",
                "credential_env": [],
                "timeout_seconds": 60,
                "allowed_cwd_roots": ["/tmp"],
            },
        ],
        "routes": {"default_executor": "remote", "default_auditor": "auditor"},
    }
    with pytest.raises(ValueError, match="endpoint"):
        AdapterRegistry.from_config(config, artifact_dir=Path("/tmp/adapters"))
