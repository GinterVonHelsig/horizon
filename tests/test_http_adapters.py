"""HTTP harness adapter tests with local mock server."""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from harness_adapters.contract import HarnessRequest
from harness_adapters.http_adapters import HttpOpenAIAdapter, is_allowed_endpoint


class _MockHandler(BaseHTTPRequestHandler):
    status_code = 200
    response_body: dict = {"choices": [{"message": {"content": '{"verdict":"approve"}'}}]}
    last_body: bytes | None = None
    omit_model: bool = False

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        _MockHandler.last_body = raw
        if not self.headers.get("Authorization", "").startswith("Bearer "):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return
        payload = dict(self.response_body)
        if not self.omit_model and "model" not in payload:
            try:
                requested = json.loads(raw).get("model")
            except (TypeError, json.JSONDecodeError):
                requested = None
            if isinstance(requested, str) and requested:
                payload["model"] = requested
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def mock_server() -> tuple[str, HTTPServer]:
    _MockHandler.status_code = 200
    _MockHandler.response_body = {"choices": [{"message": {"content": '{"verdict":"approve"}'}}]}
    _MockHandler.omit_model = False
    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://{host}:{port}/v1/chat/completions", server
    server.shutdown()


def test_local_endpoint_allowlist_accepts_loopback() -> None:
    assert is_allowed_endpoint("http://127.0.0.1:8080/v1/chat/completions")
    assert is_allowed_endpoint("http://localhost:11434/v1/chat/completions")


def test_local_endpoint_allowlist_rejects_public_host() -> None:
    assert not is_allowed_endpoint("https://api.openai.com/v1/chat/completions")


def test_endpoint_validation_rejects_prefix_bypass_userinfo_and_bad_scheme() -> None:
    assert not is_allowed_endpoint("http://10.evil.example/v1")
    assert not is_allowed_endpoint("http://172.16.evil.example/v1")
    assert not is_allowed_endpoint("http://user:pass@127.0.0.1/v1")
    assert not is_allowed_endpoint("file://127.0.0.1/etc/passwd")
    assert is_allowed_endpoint("http://172.31.255.254/v1")
    assert is_allowed_endpoint("https://192.168.4.2/v1")
    assert not is_allowed_endpoint("http://169.254.169.254/latest/meta-data")
    assert not is_allowed_endpoint("http://local.example/v1")


def test_endpoint_validation_rejects_secret_bearing_query_parameters() -> None:
    assert not is_allowed_endpoint("http://127.0.0.1/v1?api_key=secret")
    assert not is_allowed_endpoint("http://127.0.0.1/v1?token=abc")
    assert not is_allowed_endpoint("http://127.0.0.1/v1?password=hidden")
    assert is_allowed_endpoint("http://127.0.0.1/v1/chat/completions")


def test_explicit_hostname_allowlist_requires_private_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, 1, 6, "", ("10.2.3.4", 80))])
    assert is_allowed_endpoint("http://local.example/v1", allowed_hosts=("local.example",))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, 1, 6, "", ("8.8.8.8", 80))])
    assert not is_allowed_endpoint("http://local.example/v1", allowed_hosts=("local.example",))


def test_http_adapter_parses_json_and_persists_digest(
    tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, _server = mock_server
    monkeypatch.setenv("TEST_API_KEY", "secret-key-value")
    adapter = HttpOpenAIAdapter(
        adapter_id="comms01-qwen",
        endpoint=endpoint,
        model="qwen-3.8",
        credential_env="TEST_API_KEY",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
    )
    result = adapter.execute(
        HarnessRequest(
            run_id="run-1",
            task_id="task-1",
            attempt_id="attempt-1",
            objective="obj",
            prompt="hello",
            cwd=str(tmp_path),
            timeout=5.0,
            output_schema={"type": "object"},
            env_var_names=(),
            artifact_dir=str(tmp_path),
            metadata={"role": "auditor"},
        )
    )
    assert result.status == "success"
    assert result.structured_payload == {"verdict": "approve"}
    assert result.stdout_sha256
    meta_files = list(tmp_path.glob("*.json"))
    assert meta_files
    dumped = json.dumps({path.name: path.read_text() for path in meta_files})
    assert "secret-key-value" not in dumped


def test_http_adapter_request_model_is_construction_model_not_metadata(
    tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, _server = mock_server
    monkeypatch.setenv("TEST_API_KEY", "secret-key-value")
    _MockHandler.last_body = None
    adapter = HttpOpenAIAdapter(
        adapter_id="comms01-qwen",
        endpoint=endpoint,
        model="pinned-model",
        credential_env="TEST_API_KEY",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
        provider="http-relay",
    )
    result = adapter.execute(
        HarnessRequest(
            run_id="run-1",
            task_id="task-1",
            attempt_id="attempt-1",
            objective="obj",
            prompt="hello",
            cwd=str(tmp_path),
            timeout=5.0,
            output_schema=None,
            env_var_names=(),
            artifact_dir=str(tmp_path),
            metadata={"model": "override-model", "provider": "other"},
        )
    )
    assert result.status == "success"
    assert _MockHandler.last_body is not None
    body = json.loads(_MockHandler.last_body)
    assert body["model"] == "pinned-model"
    assert body["model"] != "override-model"
    assert "models" not in body
    assert "route" not in body
    assert "provider" not in body


def test_http_adapter_sends_raw_model_including_variant_suffix(
    tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, _server = mock_server
    monkeypatch.setenv("TEST_API_KEY", "secret-key-value")
    _MockHandler.last_body = None
    adapter = HttpOpenAIAdapter(
        adapter_id="comms01-qwen",
        endpoint=endpoint,
        model="openai/gpt-6-astra:nitro",
        credential_env="TEST_API_KEY",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
        provider="openrouter",
    )
    result = adapter.execute(
        HarnessRequest(
            run_id="run-1",
            task_id="task-1",
            attempt_id="attempt-1",
            objective="obj",
            prompt="hello",
            cwd=str(tmp_path),
            timeout=5.0,
            output_schema=None,
            env_var_names=(),
            artifact_dir=str(tmp_path),
            metadata={"models": ["other"], "route": "fallback", "provider": {"ignore": True}},
        )
    )
    assert result.status == "success"
    body = json.loads(_MockHandler.last_body or b"{}")
    assert body["model"] == "openai/gpt-6-astra:nitro"
    assert "models" not in body
    assert "route" not in body


def test_http_adapter_rejects_served_model_mismatch(
    tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, _server = mock_server
    monkeypatch.setenv("TEST_API_KEY", "secret-key-value")
    _MockHandler.response_body = {
        "model": "other-model",
        "choices": [{"message": {"content": '{"verdict":"approve"}'}}],
    }
    adapter = HttpOpenAIAdapter(
        adapter_id="comms01-qwen",
        endpoint=endpoint,
        model="pinned-model",
        credential_env="TEST_API_KEY",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
        provider="http-relay",
    )
    result = adapter.execute(
        HarnessRequest(
            run_id="run-1",
            task_id="task-1",
            attempt_id="attempt-1",
            objective="obj",
            prompt="hello",
            cwd=str(tmp_path),
            timeout=5.0,
            output_schema=None,
            env_var_names=(),
            artifact_dir=str(tmp_path),
            metadata={},
        )
    )
    _MockHandler.response_body = {"choices": [{"message": {"content": '{"verdict":"approve"}'}}]}
    assert result.status == "failure"
    assert result.error_classification == "integrity_failure"


def test_http_adapter_rejects_absent_response_model(
    tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, _server = mock_server
    monkeypatch.setenv("TEST_API_KEY", "secret-key-value")
    _MockHandler.omit_model = True
    _MockHandler.response_body = {"choices": [{"message": {"content": '{"verdict":"approve"}'}}]}
    adapter = HttpOpenAIAdapter(
        adapter_id="comms01-qwen",
        endpoint=endpoint,
        model="pinned-model",
        credential_env="TEST_API_KEY",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
        provider="http-relay",
    )
    result = adapter.execute(
        HarnessRequest(
            run_id="run-1",
            task_id="task-1",
            attempt_id="attempt-1",
            objective="obj",
            prompt="hello",
            cwd=str(tmp_path),
            timeout=5.0,
            output_schema=None,
            env_var_names=(),
            artifact_dir=str(tmp_path),
            metadata={},
        )
    )
    _MockHandler.omit_model = False
    assert result.status == "failure"
    assert result.error_classification == "integrity_failure"


def test_http_adapter_rejects_empty_and_non_string_response_model(
    tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, _server = mock_server
    monkeypatch.setenv("TEST_API_KEY", "secret-key-value")
    adapter = HttpOpenAIAdapter(
        adapter_id="comms01-qwen",
        endpoint=endpoint,
        model="pinned-model",
        credential_env="TEST_API_KEY",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
        provider="http-relay",
    )
    request = HarnessRequest(
        run_id="run-1",
        task_id="task-1",
        attempt_id="attempt-1",
        objective="obj",
        prompt="hello",
        cwd=str(tmp_path),
        timeout=5.0,
        output_schema=None,
        env_var_names=(),
        artifact_dir=str(tmp_path),
        metadata={},
    )
    for served in ("", "   ", 123, None):
        _MockHandler.response_body = {
            "model": served,
            "choices": [{"message": {"content": '{"verdict":"approve"}'}}],
        }
        result = adapter.execute(request)
        assert result.status == "failure"
        assert result.error_classification == "integrity_failure"
    _MockHandler.response_body = {"choices": [{"message": {"content": '{"verdict":"approve"}'}}]}


def test_http_adapter_accepts_variant_suffix_when_served_base_matches(
    tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint, _server = mock_server
    monkeypatch.setenv("TEST_API_KEY", "secret-key-value")
    _MockHandler.response_body = {
        "model": "openai/gpt-6-astra",
        "choices": [{"message": {"content": '{"verdict":"approve"}'}}],
    }
    adapter = HttpOpenAIAdapter(
        adapter_id="comms01-qwen",
        endpoint=endpoint,
        model="openai/gpt-6-astra:nitro",
        credential_env="TEST_API_KEY",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
        provider="http-relay",
    )
    result = adapter.execute(
        HarnessRequest(
            run_id="run-1",
            task_id="task-1",
            attempt_id="attempt-1",
            objective="obj",
            prompt="hello",
            cwd=str(tmp_path),
            timeout=5.0,
            output_schema=None,
            env_var_names=(),
            artifact_dir=str(tmp_path),
            metadata={},
        )
    )
    _MockHandler.response_body = {"choices": [{"message": {"content": '{"verdict":"approve"}'}}]}
    assert result.status == "success"
    body = json.loads(_MockHandler.last_body or b"{}")
    assert body["model"] == "openai/gpt-6-astra:nitro"


def test_http_adapter_auth_failure_classification(
    tmp_path: Path, mock_server: tuple[str, HTTPServer]
) -> None:
    endpoint, _server = mock_server
    adapter = HttpOpenAIAdapter(
        adapter_id="comms02-kat",
        endpoint=endpoint,
        model="kat",
        credential_env="MISSING_KEY",
        artifact_dir=tmp_path,
        timeout_seconds=5.0,
    )
    result = adapter.execute(
        HarnessRequest(
            run_id="run-1",
            task_id="task-1",
            attempt_id="attempt-1",
            objective="obj",
            prompt="hello",
            cwd=str(tmp_path),
            timeout=5.0,
            output_schema=None,
            env_var_names=(),
            artifact_dir=str(tmp_path),
            metadata={},
        )
    )
    assert result.error_classification == "auth_failure"
    assert "secret" not in json.dumps(result.to_dict())


def _request(tmp_path: Path, *, schema: dict | None = None, metadata: dict | None = None) -> HarnessRequest:
    return HarnessRequest("run", "task", "attempt", "obj", "private prompt", str(tmp_path), 1.0,
                          schema, (), str(tmp_path), metadata or {})


def test_http_status_retry_policy_and_malformed_output(tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint, _ = mock_server
    monkeypatch.setenv("TEST_KEY", "key-value")
    adapter = HttpOpenAIAdapter("http", endpoint, "m", "TEST_KEY", tmp_path, 1.0, provider="comms")
    for code, classification, retryable in [(401, "auth_failure", False), (429, "rate_limit", True), (503, "transport_failure", True)]:
        _MockHandler.status_code = code
        result = adapter.execute(_request(tmp_path))
        assert (result.error_classification, result.retryable) == (classification, retryable)
    _MockHandler.status_code = 200
    _MockHandler.response_body = {"choices": [{"message": {"content": "not-json"}}]}
    malformed = adapter.execute(_request(tmp_path))
    assert malformed.error_classification == "malformed_structured_output"
    assert malformed.retryable


def test_http_schema_validation_and_nested_secret_sanitization(tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint, _ = mock_server
    monkeypatch.setenv("TEST_KEY", "key-value")
    _MockHandler.response_body = {"choices": [{"message": {"content": '{"verdict":"maybe","nested":{"password":"hidden"}}'}}]}
    adapter = HttpOpenAIAdapter("http", endpoint, "m", "TEST_KEY", tmp_path, 1.0, provider="comms")
    schema = {"type":"object", "properties":{"verdict":{"type":"string", "enum":["approve","reject"]}}, "required":["verdict"], "additionalProperties": False}
    result = adapter.execute(_request(tmp_path, schema=schema, metadata={"safe": {"text": "ordinary note"}}))
    assert result.error_classification == "malformed_structured_output"
    dumped = "\n".join(path.read_text() for path in tmp_path.glob("*.json"))
    assert "private prompt" not in dumped
    assert '"password": "hidden"' not in dumped


def test_http_response_artifact_is_bounded_and_marks_truncation(tmp_path: Path, mock_server: tuple[str, HTTPServer], monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint, _ = mock_server
    monkeypatch.setenv("TEST_KEY", "key-value")
    _MockHandler.response_body = {"choices": [{"message": {"content": '{"data":"' + ('x' * 100000) + '"}'}}]}
    adapter = HttpOpenAIAdapter("http", endpoint, "m", "TEST_KEY", tmp_path, 1.0,
                                provider="comms", response_byte_limit=4096)
    result = adapter.execute(_request(tmp_path))
    assert (tmp_path / "stdout.txt").stat().st_size <= 4096
    digest = json.loads((tmp_path / "response.digest.json").read_text())
    assert digest["truncated"] is True
    assert result.error_classification == "malformed_structured_output"


def test_http_timeout_classification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_KEY", "key-value")
    def timeout(*args: object, **kwargs: object) -> None:
        raise socket.timeout("timed out")
    monkeypatch.setattr("urllib.request.urlopen", timeout)
    adapter = HttpOpenAIAdapter("http", "http://127.0.0.1:1/v1", "m", "TEST_KEY", tmp_path, 0.01, provider="comms")
    result = adapter.execute(_request(tmp_path))
    assert (result.error_classification, result.retryable) == ("timeout", True)
