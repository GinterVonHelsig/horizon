"""OpenRouter Sol auditor bridge: loopback relay, effort max, Anthropic denylisted."""

from __future__ import annotations

import io
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from harness_adapters.contract import HarnessRequest
from harness_adapters.http_adapters import HttpOpenAIAdapter, is_allowed_endpoint, is_loopback_endpoint
from harness_adapters.preflight import AdapterPreflightError, preflight_adapters
from harness_adapters.registry import validate_registry_config
from harness_adapters.schema import validate_json_schema
from openrouter_auditor_relay import (
    ALLOWED_MODEL,
    OpenRouterAuditorRelay,
    RelayPolicyError,
    build_upstream_payload,
)
from worker import AUDITOR_SCHEMA

AUDITOR_APPROVE = {
    "verdict": "approve",
    "criteria": [
        {
            "criterion": "audit me",
            "met": True,
            "rationale": "mock",
            "evidence_refs": [{"name": "stdout", "sha256": "a" * 64}],
        }
    ],
}
AUDITOR_REJECT = {
    "verdict": "reject",
    "criteria": [
        {
            "criterion": "audit me",
            "met": False,
            "rationale": "mock",
            "evidence_refs": [{"name": "stdout", "sha256": "a" * 64}],
        }
    ],
}
AUDITOR_APPROVE_JSON = json.dumps(AUDITOR_APPROVE, separators=(",", ":"))
AUDITOR_REJECT_JSON = json.dumps(AUDITOR_REJECT, separators=(",", ":"))


def _auditor_config(endpoint: str) -> dict[str, Any]:
    return {
        "adapters": [
            {
                "id": "cursor-cli",
                "kind": "cursor_cli",
                "provider": "cursor",
                "executable": "/usr/bin/cursor-agent",
                "model": "composer-2.5",
                "approval_mode": "never",
                "credential_env": [],
                "timeout_seconds": 5,
                "allowed_cwd_roots": ["/tmp"],
            },
            {
                "id": "openrouter-claude-auditor",
                "kind": "http_openai",
                "provider": "openrouter",
                "model": "openai/gpt-5.6-sol",
                "endpoint": endpoint,
                "credential_env": ["TOP_DELIVERY_OPENROUTER_RELAY_TOKEN"],
                "timeout_seconds": 30,
                "allowed_cwd_roots": ["/tmp"],
                "reasoning_effort": "max",
                "loopback_only": True,
            },
        ],
        "routes": {
            "default_executor": "cursor-cli",
            "default_auditor": "openrouter-claude-auditor",
        },
    }


def test_loopback_endpoint_accepts_loopback_and_rejects_lan_and_public() -> None:
    assert is_loopback_endpoint("http://127.0.0.1:18765/v1/chat/completions")
    assert is_loopback_endpoint("http://localhost:18765/v1/chat/completions")
    assert not is_loopback_endpoint("http://192.168.0.91:18765/v1/chat/completions")
    assert not is_loopback_endpoint("http://10.0.0.1/v1/chat/completions")
    assert not is_loopback_endpoint("https://openrouter.ai/api/v1/chat/completions")
    assert not is_loopback_endpoint("http://user:pass@127.0.0.1/v1")
    assert not is_allowed_endpoint("https://openrouter.ai/api/v1/chat/completions")


def test_registry_rejects_public_openrouter_endpoint_for_auditor() -> None:
    config = _auditor_config("https://openrouter.ai/api/v1/chat/completions")
    with pytest.raises(ValueError, match="endpoint"):
        validate_registry_config(config, validate_executables=False)


def test_registry_accepts_loopback_auditor_and_preserves_composer() -> None:
    config = _auditor_config("http://127.0.0.1:18765/v1/chat/completions")
    validate_registry_config(config, validate_executables=False)
    assert config["routes"]["default_executor"] == "cursor-cli"
    cursor = next(item for item in config["adapters"] if item["id"] == "cursor-cli")
    assert cursor["model"] == "composer-2.5"


def test_upstream_payload_forces_model_and_max_effort() -> None:
    payload = build_upstream_payload(
        {
            "model": "openai/gpt-5.6-sol",
            "messages": [{"role": "user", "content": "ROUTE_OK"}],
            "reasoning": {"effort": "high"},
        }
    )
    assert payload["model"] == ALLOWED_MODEL
    assert payload["reasoning"] == {"effort": "max"}


def test_upstream_payload_rejects_other_models() -> None:
    with pytest.raises(RelayPolicyError, match="model"):
        build_upstream_payload({"model": "anthropic/claude-opus-5", "messages": []})
    with pytest.raises(RelayPolicyError, match="model"):
        build_upstream_payload({"model": "anthropic/claude-fable-5", "messages": []})


def test_upstream_payload_allows_grok_fallback_at_high() -> None:
    payload = build_upstream_payload(
        {"model": "x-ai/grok-4.6", "messages": [{"role": "user", "content": "x"}]}
    )
    assert payload["model"] == "x-ai/grok-4.6"
    assert payload["reasoning"] == {"effort": "high"}


class _UpstreamHandler(BaseHTTPRequestHandler):
    captured: dict[str, Any] = {}
    status = 200
    body = b'{"choices":[{"message":{"content":"{\\"verdict\\":\\"approve\\"}"}}],"id":"gen-test"}'

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            "host": self.headers.get("Host"),
            "authorization": self.headers.get("Authorization"),
            "body": json.loads(raw.decode() or "{}"),
        }
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def mock_upstream() -> str:
    _UpstreamHandler.captured = {}
    _UpstreamHandler.status = 200
    server = HTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}/api/v1/chat/completions"
    server.shutdown()


def test_relay_forwards_only_pinned_path_with_redacted_errors(
    monkeypatch: pytest.MonkeyPatch, mock_upstream: str
) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-super-secret-provider-key")
    monkeypatch.setenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", "relay-token-value")
    relay = OpenRouterAuditorRelay(
        bind_host="127.0.0.1",
        bind_port=0,
        provider_url=mock_upstream,
        provider_key_env="OPENROUTER_API_KEY",
        relay_token_env="TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
        allow_test_loopback_provider=True,
    )
    result = relay.handle_json(
        {"model": "openai/gpt-5.6-sol", "messages": [{"role": "user", "content": "x"}]},
        authorization="Bearer relay-token-value",
        peer="127.0.0.1",
    )
    assert result["status"] == 200
    dumped_result = json.dumps(result)
    assert "sk-or-v1-super-secret-provider-key" not in dumped_result
    assert _UpstreamHandler.captured["body"]["reasoning"] == {"effort": "max"}
    assert _UpstreamHandler.captured["body"]["model"] == "openai/gpt-5.6-sol"
    assert str(_UpstreamHandler.captured["authorization"]).startswith("Bearer ")


def test_relay_rejects_invalid_token_and_lan_peer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-provider")
    monkeypatch.setenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", "good-token")
    relay = OpenRouterAuditorRelay(
        bind_host="127.0.0.1",
        bind_port=0,
        provider_url="https://openrouter.ai/api/v1/chat/completions",
        provider_key_env="OPENROUTER_API_KEY",
        relay_token_env="TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
    )
    denied = relay.handle_json({"model": ALLOWED_MODEL, "messages": []}, authorization="Bearer no", peer="127.0.0.1")
    assert denied["status"] == 401
    lan = relay.handle_json(
        {"model": ALLOWED_MODEL, "messages": []},
        authorization="Bearer good-token",
        peer="192.168.0.91",
    )
    assert lan["status"] == 403
    assert "sk-or-v1-provider" not in json.dumps(denied) + json.dumps(lan)


def test_relay_rejects_oversize_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-provider")
    monkeypatch.setenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", "good-token")
    relay = OpenRouterAuditorRelay(
        bind_host="127.0.0.1",
        bind_port=0,
        provider_url="https://openrouter.ai/api/v1/chat/completions",
        provider_key_env="OPENROUTER_API_KEY",
        relay_token_env="TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
        max_request_bytes=64,
    )
    huge = {"model": ALLOWED_MODEL, "messages": [{"role": "user", "content": "x" * 200}]}
    result = relay.handle_json(huge, authorization="Bearer good-token", peer="127.0.0.1")
    assert result["status"] == 413


def test_http_adapter_sends_max_effort_and_parses_auditor_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            captured["body"] = json.loads(self.rfile.read(length))
            captured["auth"] = self.headers.get("Authorization")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({
                    "model": captured["body"].get("model"),
                    "choices": [{"message": {"content": AUDITOR_APPROVE_JSON}}],
                }).encode()
            )

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    monkeypatch.setenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", "relay-secret")
    adapter = HttpOpenAIAdapter(
        adapter_id="openrouter-claude-auditor",
        endpoint=f"http://{host}:{port}/v1/chat/completions",
        model="openai/gpt-5.6-sol",
        credential_env="TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
        provider="openrouter",
        reasoning_effort="max",
        loopback_only=True,
    )
    result = adapter.execute(
        HarnessRequest(
            "run", "task", "attempt", "obj", "audit me", str(tmp_path), 5.0,
            AUDITOR_SCHEMA, (), str(tmp_path), {"role": "auditor"},
        )
    )
    server.shutdown()
    assert result.status == "success"
    assert result.structured_payload == AUDITOR_APPROVE
    validate_json_schema(result.structured_payload, AUDITOR_SCHEMA)
    assert captured["body"]["model"] == "openai/gpt-5.6-sol"
    assert captured["body"]["reasoning"] == {"effort": "max"}
    assert "verdict" in captured["body"]["response_format"]["json_schema"]["schema"]["required"]
    assert "criteria" in captured["body"]["response_format"]["json_schema"]["schema"]["required"]
    artifacts = "\n".join(path.read_text() for path in tmp_path.glob("*") if path.is_file())
    assert "relay-secret" not in artifacts


def test_http_adapter_loopback_only_rejects_lan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", "relay-secret")
    adapter = HttpOpenAIAdapter(
        adapter_id="openrouter-claude-auditor",
        endpoint="http://192.168.0.91:18765/v1/chat/completions",
        model="openai/gpt-5.6-sol",
        credential_env="TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
        artifact_dir=tmp_path,
        timeout_seconds=1.0,
        provider="openrouter",
        loopback_only=True,
    )
    result = adapter.execute(
        HarnessRequest("r", "t", "a", "o", "p", str(tmp_path), 1.0, AUDITOR_SCHEMA, (), str(tmp_path), {})
    )
    assert result.error_classification == "endpoint_not_allowed"


def test_http_adapter_missing_token_is_auth_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", raising=False)
    adapter = HttpOpenAIAdapter(
        adapter_id="openrouter-claude-auditor",
        endpoint="http://127.0.0.1:18765/v1/chat/completions",
        model="openai/gpt-5.6-sol",
        credential_env="TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
        artifact_dir=tmp_path,
        timeout_seconds=1.0,
        provider="openrouter",
        loopback_only=True,
    )
    result = adapter.execute(
        HarnessRequest("r", "t", "a", "o", "p", str(tmp_path), 1.0, None, (), str(tmp_path), {})
    )
    assert result.error_classification == "auth_failure"


def test_preflight_skips_claude_cli_when_openrouter_auditor_is_selected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[tuple[str, str]] = []

    def lister(kind: str, executable: str) -> list[str]:
        called.append((kind, executable))
        if kind == "cursor_cli":
            return ["composer-2.5"]
        raise AssertionError("claude_cli must not be invoked")

    exe = tmp_path / "cursor"
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o700)
    claude = tmp_path / "claude"
    claude.write_text("#!/bin/sh\nexit 1\n")
    claude.chmod(0o700)
    config = {
        "adapters": [
            {
                "id": "cursor-cli",
                "kind": "cursor_cli",
                "provider": "cursor",
                "executable": str(exe),
                "model": "composer-2.5",
                "approval_mode": "never",
                "credential_env": [],
                "timeout_seconds": 5,
                "allowed_cwd_roots": ["/tmp"],
            },
            {
                "id": "claude-cli",
                "kind": "claude_cli",
                "provider": "anthropic",
                "executable": str(claude),
                "model": "claude-opus-5-high",
                "permission_mode": "default",
                "credential_env": [],
                "timeout_seconds": 5,
                "allowed_cwd_roots": ["/tmp"],
            },
            {
                "id": "openrouter-claude-auditor",
                "kind": "http_openai",
                "provider": "openrouter",
                "model": "openai/gpt-5.6-sol",
                "endpoint": "http://127.0.0.1:18765/v1/chat/completions",
                "credential_env": ["TOP_DELIVERY_OPENROUTER_RELAY_TOKEN"],
                "timeout_seconds": 30,
                "allowed_cwd_roots": ["/tmp"],
                "loopback_only": True,
                "reasoning_effort": "max",
            },
        ],
        "routes": {
            "default_executor": "cursor-cli",
            "default_auditor": "openrouter-claude-auditor",
        },
    }
    monkeypatch.setenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", "relay-token")
    report = preflight_adapters(config, list_models=lister)
    assert report["ok"] is True
    assert report["models"]["openrouter-claude-auditor"] == "openai/gpt-5.6-sol"
    assert all(kind != "claude_cli" for kind, _executable in called)


def test_preflight_http_openai_requires_relay_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", raising=False)
    config = _auditor_config("http://127.0.0.1:18765/v1/chat/completions")
    with pytest.raises(AdapterPreflightError) as exc:
        preflight_adapters(config, list_models=lambda *_a, **_k: ["composer-2.5"])
    assert exc.value.code in {"BLOCKED_ADAPTER_MODEL", "BLOCKED_ADAPTER_PREFLIGHT", "BLOCKED_OPENROUTER_RELAY"}


def test_auditor_schema_is_independent_of_executor_object() -> None:
    executor = {
        "adapter": "cursor-cli",
        "kind": "cursor_cli",
        "provider": "cursor",
        "model": "composer-2.5",
        "prompt_digest": "a" * 64,
        "response_digest": "b" * 64,
        "changed_files": [],
        "tool_calls": [],
        "focused_test_result": {"status": "not_run", "summary": "none"},
        "stream_complete": True,
    }
    assert "verdict" not in executor
    validate_json_schema(AUDITOR_APPROVE, AUDITOR_SCHEMA)


def test_relay_provider_url_must_be_pinned_openrouter_https() -> None:
    with pytest.raises(RelayPolicyError):
        OpenRouterAuditorRelay(
            bind_host="127.0.0.1",
            bind_port=0,
            provider_url="https://evil.example/api/v1/chat/completions",
            provider_key_env="OPENROUTER_API_KEY",
            relay_token_env="TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
        )


def test_no_database_url_in_adapter_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOP_DELIVERY_DATABASE_URL", "postgresql://secret-user:secret-pass@127.0.0.1/db")
    monkeypatch.setenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN", "relay-secret")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requested = json.loads(raw).get("model")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({
                    "model": requested,
                    "choices": [{"message": {"content": AUDITOR_REJECT_JSON}}],
                }).encode()
            )

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    adapter = HttpOpenAIAdapter(
        adapter_id="openrouter-claude-auditor",
        endpoint=f"http://{host}:{port}/v1/chat/completions",
        model="openai/gpt-5.6-sol",
        credential_env="TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
        provider="openrouter",
        loopback_only=True,
        reasoning_effort="max",
    )
    adapter.execute(
        HarnessRequest("r", "t", "a", "o", "p", str(tmp_path), 5.0, AUDITOR_SCHEMA, (), str(tmp_path), {})
    )
    server.shutdown()
    dumped = "\n".join(path.read_text() for path in tmp_path.rglob("*") if path.is_file())
    assert "secret-pass" not in dumped
    assert "DATABASE_URL" not in dumped
    assert "postgresql://secret-user" not in dumped
