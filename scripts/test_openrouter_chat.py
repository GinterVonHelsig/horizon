from __future__ import annotations

import importlib.util
import base64
import json
import socket
import sys
import time
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pytest


MODULE = Path(__file__).with_name("openrouter_chat.py")
SPEC = importlib.util.spec_from_file_location("openrouter_chat", MODULE)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

_TEST_RUNNER_PRIVATE_KEY = base64.urlsafe_b64encode(
    Ed25519PrivateKey.generate().private_bytes_raw()
).decode("ascii")
_TEST_RUNNER_PUBLIC_KEY = base64.urlsafe_b64encode(
    Ed25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(_TEST_RUNNER_PRIVATE_KEY + "==")
    ).public_key().public_bytes_raw()
).decode("ascii")


def test_parse_plain_json() -> None:
    value, info = runner.parse_json_content('{"ok": true}')
    assert json.loads(value or "") == {"ok": True}
    assert info == {"valid_json": True, "normalized_from_fence": False}


def test_parse_fenced_json_without_retry() -> None:
    value, info = runner.parse_json_content('prefix\n```json\n{"ok": true}\n```\n')
    assert json.loads(value or "") == {"ok": True}
    assert info == {"valid_json": True, "normalized_from_fence": True}


def test_parse_indented_json() -> None:
    value, info = runner.parse_json_content('{\n  "ok": true\n}')
    assert json.loads(value or "") == {"ok": True}
    assert info["valid_json"] is True


def test_reject_truncated_json() -> None:
    value, info = runner.parse_json_content('{"ok":')
    assert value is None
    assert info["valid_json"] is False


def test_reject_trailing_content_after_json() -> None:
    value, info = runner.parse_json_content('{"ok": true} trailing')
    assert value is None
    assert info["valid_json"] is False


def test_reject_partial_fenced_json() -> None:
    value, info = runner.parse_json_content('```json\n{"ok":\n```')
    assert value is None
    assert info["valid_json"] is False


RUNNER_IDENTITY_ARGS = [
    "--run-id",
    "run-1",
    "--task-id",
    "task-1",
    "--child-id",
    "child-1",
    "--attempt-number",
    "0",
    "--fence-token",
    "1",
    "--controller-epoch",
    "1",
    "--reviewed-sha",
    "sha",
    "--tree-sha",
    "tree",
    "--source-digest",
    "source",
    "--request-digest",
    "request",
]


def _write_job_envelope(tmp_path: Path) -> Path:
    system_sha = runner.sha256_text("system")
    user_sha = runner.sha256_text("user")
    envelope = {
        "schema_version": 1,
        "model": "test/model",
        "request_id": "group-1",
        "identity": {
            "run_id": "run-1",
            "task_id": "task-1",
            "child_id": "child-1",
            "attempt_number": 0,
            "fence_token": 1,
            "controller_epoch": 1,
            "reviewed_sha": "sha",
            "tree_sha": "tree",
            "source_digest": "source",
            "request_digest": "request",
        },
        "expected_output_schema": {
            "type": "object",
            "required": ["ok"],
            "properties": {"ok": {"type": "boolean"}},
            "additionalProperties": False,
        },
        "prompt_digests": {
            "system_sha256": system_sha,
            "user_sha256": user_sha,
            "combined_sha256": runner.sha256_text("system" + "user"),
        },
        "provenance": {
            "reviewed_sha": "sha",
            "tree_sha": "tree",
            "source_digest": "source",
        },
    }
    key_path = Path(runner.RUNNER_ENVELOPE_PUBLIC_KEY_PATH)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(_TEST_RUNNER_PUBLIC_KEY + "\n", encoding="utf-8")
    key_path.chmod(0o600)
    envelope["controller_signature"] = runner.sign_job_envelope(
        envelope, signing_key=_TEST_RUNNER_PRIVATE_KEY
    )
    path = tmp_path / "job-envelope.json"
    path.write_text(json.dumps(envelope, indent=2) + "\n")
    return path


class _FakeHttpResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self._offset = 0
        self.status = 200
        self.headers = {}

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _SlowDripHttpResponse(_FakeHttpResponse):
    def __init__(self, *, delay_seconds: float) -> None:
        super().__init__(b"ignored")
        self.delay_seconds = delay_seconds
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        time.sleep(self.delay_seconds)
        return b"still waiting"

    def close(self) -> None:
        self.closed = True


class _SocketBackedResponse:
    def __init__(self) -> None:
        self._reader, self._writer = socket.socketpair()
        self._reader.setblocking(True)
        self._writer.sendall(b"first-byte")
        self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=self._reader))
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._reader.recv(size)

    def close(self) -> None:
        self.closed = True
        self._reader.close()
        self._writer.close()


def test_real_socket_drip_cannot_extend_absolute_deadline() -> None:
    response = _SocketBackedResponse()
    try:
        with pytest.raises(runner.AggregateDeadlineExceeded):
            runner.read_bounded_response(
                response,
                max_bytes=1024,
                deadline=time.monotonic() + 0.05,
            )
        assert response.closed is True
    finally:
        if not response.closed:
            response.close()


class _Read1OnlyResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self._offset = 0
        self.read1_calls = 0

    def read1(self, size: int = -1) -> bytes:
        self.read1_calls += 1
        if size is None or size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def read(self, _size: int = -1) -> bytes:
        raise AssertionError("read1-capable response must not use read()")


class _PlainReadResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self._offset = 0
        self.read_calls = 0

    def read(self, size: int = -1) -> bytes:
        self.read_calls += 1
        if size is None or size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class _NestedRead1Response(_FakeHttpResponse):
    def __init__(self, body: bytes) -> None:
        super().__init__(body)
        self.read_calls = 0
        self.fp = SimpleNamespace(read1=lambda _size: b"wrong-reader")

    def read(self, size: int = -1) -> bytes:
        self.read_calls += 1
        return super().read(size)


def test_bounded_reader_uses_response_read1_without_full_buffer_wait() -> None:
    response = _Read1OnlyResponse(b'{"ok":true}')
    assert runner.read_bounded_response(response, max_bytes=1024) == b'{"ok":true}'
    assert response.read1_calls >= 2


def test_bounded_reader_does_not_use_nested_fp_read1() -> None:
    response = _NestedRead1Response(b'{"ok":true}')
    assert runner.read_bounded_response(response, max_bytes=1024) == b'{"ok":true}'
    assert response.read_calls >= 2


def test_bounded_reader_uses_plain_read_fallback() -> None:
    response = _PlainReadResponse(b'{"ok":true}')
    assert runner.read_bounded_response(response, max_bytes=1024) == b'{"ok":true}'
    assert response.read_calls >= 2


def test_plain_read_fallback_enforces_max_bytes() -> None:
    response = _PlainReadResponse(b"x" * 1025)
    with pytest.raises(ValueError, match="exceeds 1024 bytes"):
        runner.read_bounded_response(response, max_bytes=1024)


def test_plain_read_fallback_accepts_exact_max_bytes() -> None:
    body = b"x" * 1024
    response = _PlainReadResponse(body)
    assert runner.read_bounded_response(response, max_bytes=1024) == body
    assert response.read_calls >= 2


def _run_runner_with_mocked_openrouter(
    tmp_path: Path,
    monkeypatch,
    extra_args: list[str],
    response_document: dict | None = None,
    provider=None,
) -> tuple[list[dict], dict]:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")
    raw_out = tmp_path / "raw.json"
    content_out = tmp_path / "content.json"
    metadata_out = tmp_path / "metadata.json"
    job_envelope = _write_job_envelope(tmp_path)
    captured_payloads: list[dict] = []

    def fake_urlopen(request, timeout=None):
        captured_payloads.append(json.loads(request.data.decode()))
        body = json.dumps(
            response_document
            or {
                "id": "req-1",
                "object": "chat.completion",
                "model": "test/model",
                "choices": [
                    {
                        "message": {"content": '{"ok": true}'},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()
        return _FakeHttpResponse(body)

    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(raw_out),
        "--content-out",
        str(content_out),
        "--metadata-out",
        str(metadata_out),
        "--job-envelope-file",
        str(_write_job_envelope(tmp_path)),
        *RUNNER_IDENTITY_ARGS,
        *extra_args,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with patch.object(runner, "open_provider", provider or fake_urlopen):
        exit_code = runner.main()
    metadata = json.loads(metadata_out.read_text())
    return captured_payloads, {"exit_code": exit_code, "metadata": metadata}


def test_require_json_sends_response_format(tmp_path, monkeypatch) -> None:
    payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path, monkeypatch, []
    )
    assert result["exit_code"] == 0
    assert payloads[0]["response_format"] == {"type": "json_object"}
    assert payloads[0]["provider"] == {"allow_fallbacks": False}
    assert payloads[0]["reasoning"] == {"effort": "high"}
    assert result["metadata"]["attempts"][0]["request_body_bytes"] > 0
    assert len(result["metadata"]["attempts"][0]["request_body_sha256"]) == 64
    assert result["metadata"]["request"]["response_format"] == "json_object"
    assert result["metadata"]["request"]["provider_policy"] == {"allow_fallbacks": False}
    assert result["metadata"]["request"]["reasoning_mode"] == "effort"
    assert result["metadata"]["request"]["reasoning_effort"] == "high"
    assert result["metadata"]["request"]["legacy_reasoning_max_tokens_ignored"] is True


def test_effort_must_be_provider_accepted(tmp_path, monkeypatch) -> None:
    with pytest.raises(SystemExit, match="unsupported reasoning effort"):
        _run_runner_with_mocked_openrouter(
            tmp_path, monkeypatch, ["--effort", "unsupported"]
        )


def test_anthropic_models_are_denylisted(tmp_path, monkeypatch) -> None:
    with pytest.raises(SystemExit, match="denylisted"):
        _run_runner_with_mocked_openrouter(
            tmp_path, monkeypatch, ["--model", "anthropic/claude-opus-5"]
        )


def test_max_effort_is_allowed(tmp_path, monkeypatch) -> None:
    payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path, monkeypatch, ["--effort", "max"]
    )
    assert result["exit_code"] == 0
    assert payloads[0]["reasoning"] == {"effort": "max"}
    assert result["metadata"]["request"]["reasoning_effort"] == "max"
    assert "max" in runner.ALLOWED_REASONING_EFFORTS
    attempt = result["metadata"]["attempts"][0]
    assert attempt["effort"] == "max"
    assert "upstream_provider" in attempt
    assert "usage_cost_usd" in attempt
    assert attempt["price_ceiling_exceeded"] is False


@pytest.mark.parametrize("effort", sorted(runner.ALLOWED_REASONING_EFFORTS))
def test_each_supported_effort_is_sent_and_recorded(tmp_path, monkeypatch, effort) -> None:
    payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path, monkeypatch, ["--effort", effort]
    )
    assert result["exit_code"] == 0
    assert payloads[0]["reasoning"] == {"effort": effort}
    assert payloads[0]["max_tokens"] == runner.DEFAULT_MAX_TOKENS
    assert payloads[0]["response_format"] == {"type": "json_object"}
    assert payloads[0]["provider"] == {"allow_fallbacks": False}
    assert "reasoning_max_tokens" not in payloads[0]
    assert result["metadata"]["request"]["reasoning_effort"] == effort


@pytest.mark.parametrize("legacy_budget", ["1", str(runner.MAX_REASONING_TOKENS)])
def test_legacy_reasoning_budget_remains_bounded_but_is_not_sent(
    tmp_path, monkeypatch, legacy_budget
) -> None:
    payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path, monkeypatch, ["--reasoning-max-tokens", legacy_budget]
    )
    assert result["exit_code"] == 0
    assert payloads[0]["reasoning"] == {"effort": "high"}
    assert payloads[0]["max_tokens"] == runner.DEFAULT_MAX_TOKENS
    assert "reasoning_max_tokens" not in payloads[0]
    assert result["metadata"]["request"]["legacy_reasoning_max_tokens"] == int(legacy_budget)


def test_retry_payloads_preserve_provider_contract_and_nondefault_budget(
    tmp_path, monkeypatch
) -> None:
    captured_payloads: list[dict] = []
    responses = [
        {
            "id": "req-retry-1",
            "object": "chat.completion",
            "model": "test/model",
            "choices": [{"message": {"content": "not-json"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        },
        {
            "id": "req-retry-2",
            "object": "chat.completion",
            "model": "test/model",
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        },
    ]

    def retry_provider(request, timeout=None):
        captured_payloads.append(json.loads(request.data.decode()))
        response = responses[len(captured_payloads) - 1]
        return _FakeHttpResponse(json.dumps(response).encode())

    _payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path,
        monkeypatch,
        [
            "--effort",
            "xhigh",
            "--max-tokens",
            "4000",
            "--max-retry-tokens",
            "6000",
            "--attempts",
            "2",
        ],
        provider=retry_provider,
    )
    assert result["exit_code"] == 0
    assert [payload["max_tokens"] for payload in captured_payloads] == [4000, 6000]
    for payload in captured_payloads:
        assert payload["reasoning"] == {"effort": "xhigh"}
        assert payload["response_format"] == {"type": "json_object"}
        assert payload["provider"] == {"allow_fallbacks": False}
        assert "reasoning_max_tokens" not in payload


def test_legacy_reasoning_budget_out_of_range_is_rejected(tmp_path, monkeypatch) -> None:
    with pytest.raises(SystemExit, match="invalid attempt or token budget"):
        _run_runner_with_mocked_openrouter(
            tmp_path, monkeypatch, ["--reasoning-max-tokens", "0"]
        )
    with pytest.raises(SystemExit, match="invalid attempt or token budget"):
        _run_runner_with_mocked_openrouter(
            tmp_path, monkeypatch,
            ["--reasoning-max-tokens", str(runner.MAX_REASONING_TOKENS + 1)],
        )


def test_legacy_reasoning_budget_constant_is_explicit() -> None:
    assert runner.MAX_REASONING_TOKENS == 32768


def test_provider_length_without_content_is_classified_as_truncation(tmp_path, monkeypatch) -> None:
    _payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path,
        monkeypatch,
        ["--attempts", "1"],
        response_document={
            "id": "req-length",
            "object": "chat.completion",
            "model": "test/model",
            "choices": [
                {"message": {"content": None}, "finish_reason": "length"}
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 12, "total_tokens": 24},
        },
    )
    assert result["exit_code"] == 2
    assert result["metadata"]["attempts"][0]["status"] == "rejected-finish-length"
    assert result["metadata"]["attempts"][0]["content_bytes"] == 0


def test_usage_must_have_numeric_accounting_fields() -> None:
    assert runner.validate_usage(
        {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    )


def test_price_ceiling_flags_promo_expiry() -> None:
    usage = {
        "prompt_tokens": 1_000_000,
        "completion_tokens": 1_000_000,
        "total_tokens": 2_000_000,
        "cost_details": {
            "upstream_inference_prompt_cost": 4.0,
            "upstream_inference_completions_cost": 20.0,
        },
    }
    result = runner.evaluate_price_ceiling("openai/gpt-5.6-sol", usage)
    assert result["price_ceiling_exceeded"] is True
    under = {
        "prompt_tokens": 1_000_000,
        "completion_tokens": 1_000_000,
        "total_tokens": 2_000_000,
        "cost_details": {
            "upstream_inference_prompt_cost": 2.0,
            "upstream_inference_completions_cost": 10.0,
        },
    }
    assert runner.evaluate_price_ceiling("openai/gpt-5.6-sol", under)["price_ceiling_exceeded"] is False


def test_usage_must_have_numeric_accounting_fields() -> None:
    assert runner.validate_usage(
        {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
    ) is True
    assert runner.validate_usage(
        {"prompt_tokens": "1", "completion_tokens": 2, "total_tokens": 3}
    ) is False
    assert runner.validate_usage(
        {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 3}
    ) is False


def test_reject_unsigned_job_envelope(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    envelope_path = _write_job_envelope(tmp_path)
    envelope = json.loads(envelope_path.read_text())
    envelope.pop("controller_signature", None)
    envelope_path.write_text(json.dumps(envelope))
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")
    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--metadata-out",
        str(tmp_path / "metadata.json"),
        "--job-envelope-file",
        str(envelope_path),
        *RUNNER_IDENTITY_ARGS,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit):
        runner.main()


def test_strict_output_schema_rejects_additional_properties() -> None:
    schema = {
        "type": "object",
        "required": ["ok"],
        "properties": {"ok": {"type": "boolean"}},
        "additionalProperties": False,
    }
    assert runner.validate_output_schema({"ok": True}, schema) is True
    assert runner.validate_output_schema({"ok": True, "extra": 1}, schema) is False
    assert runner.validate_output_schema({"ok": "nope"}, schema) is False


def test_forged_envelope_identity_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    envelope_path = _write_job_envelope(tmp_path)
    envelope = json.loads(envelope_path.read_text())
    envelope["identity"]["run_id"] = "forged"
    # Re-sign so signature verification passes and identity binding is what fails.
    envelope["controller_signature"] = runner.sign_job_envelope(
        envelope, signing_key=_TEST_RUNNER_PRIVATE_KEY
    )
    envelope_path.write_text(json.dumps(envelope))
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")
    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--metadata-out",
        str(tmp_path / "metadata.json"),
        "--job-envelope-file",
        str(envelope_path),
        *RUNNER_IDENTITY_ARGS,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as excinfo:
        runner.main()
    assert excinfo.value.code != 0


def test_distinct_idempotency_keys_per_attempt(tmp_path, monkeypatch) -> None:
    captured_headers: list[dict[str, str]] = []
    original_request = runner.urllib.request.Request

    def capture_request(*args, **kwargs):
        request = original_request(*args, **kwargs)
        captured_headers.append(dict(request.header_items()))
        return request

    def fake_urlopen(request, timeout=None):
        body = json.dumps(
            {
                "id": "req-1",
                "object": "chat.completion",
                "model": "test/model",
                "choices": [
                    {"message": {"content": "not-json"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()
        return _FakeHttpResponse(body)

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")
    metadata_out = tmp_path / "metadata.json"
    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--metadata-out",
        str(metadata_out),
        "--job-envelope-file",
        str(_write_job_envelope(tmp_path)),
        *RUNNER_IDENTITY_ARGS,
        "--attempts",
        "2",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(runner.urllib.request, "Request", capture_request)
    with patch.object(runner, "open_provider", fake_urlopen):
        exit_code = runner.main()
    attempt_metadata = sorted((tmp_path / "raw.attempts").glob("attempt-*.metadata.json"))[-1]
    metadata = json.loads(attempt_metadata.read_text())
    assert exit_code == 2
    idem_keys = [
        headers.get("Idempotency-key") or headers.get("Idempotency-Key")
        for headers in captured_headers
    ]
    assert len(idem_keys) == 2
    assert idem_keys[0] != idem_keys[1]
    assert metadata["request_group_id"] == metadata["request_id"]


def test_aggregate_token_budget_terminates_retry_group(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)
    payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path,
        monkeypatch,
        [
            "--max-tokens",
            "4000",
            "--max-retry-tokens",
            "4000",
            "--max-total-tokens",
            "5000",
            "--attempts",
            "2",
        ],
        response_document={
            "id": "req-budget",
            "object": "chat.completion",
            "model": "test/model",
            "choices": [
                {"message": {"content": "not-json"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        },
    )
    assert result["exit_code"] == 2
    assert len(payloads) == 2
    assert [payload["max_tokens"] for payload in payloads] == [4000, 1000]
    assert result["metadata"]["response"]["total_budget"] == 5000
    assert result["metadata"]["termination"]["reason"] == "aggregate-token-budget-exhausted"


def test_aggregate_deadline_terminates_retry_group(tmp_path, monkeypatch) -> None:
    clock = iter((0.0, 0.0, 0.1, 1.0, 2.0))
    def monotonic() -> float:
        try:
            return next(clock)
        except StopIteration:
            return 2.0

    monkeypatch.setattr(runner.time, "monotonic", monotonic)
    _payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path,
        monkeypatch,
        ["--max-job-seconds", "0.5", "--attempts", "2"],
        response_document={
            "id": "req-deadline",
            "object": "chat.completion",
            "model": "test/model",
            "choices": [
                {"message": {"content": "not-json"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        },
    )
    assert result["exit_code"] == 2
    assert len(result["metadata"]["attempts"]) == 1
    assert result["metadata"]["termination"]["reason"] == "aggregate-deadline-exceeded"
    raw_attempt = Path(result["metadata"]["attempts"][0]["raw_attempt_path"])
    assert raw_attempt.read_bytes() == b""


def test_slow_drip_response_cannot_outlive_aggregate_deadline(tmp_path, monkeypatch) -> None:
    response = _SlowDripHttpResponse(delay_seconds=0.20)
    _payloads, result = _run_runner_with_mocked_openrouter(
        tmp_path,
        monkeypatch,
        ["--max-job-seconds", "0.05", "--attempts", "2"],
        provider=lambda _request, timeout=None: response,
    )
    assert result["exit_code"] == 2
    assert response.closed is True
    assert len(result["metadata"]["attempts"]) == 1
    assert result["metadata"]["attempts"][0]["status"] == "aggregate-deadline-exceeded"
    assert result["metadata"]["termination"]["reason"] == "aggregate-deadline-exceeded"


def test_provider_requires_pinned_https_endpoint() -> None:
    request = runner.urllib.request.Request("http://openrouter.ai/api/v1/chat/completions")
    with pytest.raises(ValueError, match="pinned OpenRouter HTTPS"):
        runner.open_provider(request, timeout=1.0)


def test_reject_model_substitution(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")
    metadata_out = tmp_path / "metadata.json"

    def fake_urlopen(request, timeout=None):
        body = json.dumps(
            {
                "id": "req-1",
                "object": "chat.completion",
                "model": "other/model",
                "choices": [
                    {"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()
        return _FakeHttpResponse(body)

    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--metadata-out",
        str(metadata_out),
        "--job-envelope-file",
        str(_write_job_envelope(tmp_path)),
        *RUNNER_IDENTITY_ARGS,
        "--attempts",
        "1",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with patch.object(runner, "open_provider", fake_urlopen):
        exit_code = runner.main()
    attempt_metadata = sorted((tmp_path / "raw.attempts").glob("attempt-*.metadata.json"))[-1]
    metadata = json.loads(attempt_metadata.read_text())
    assert exit_code == 2
    assert metadata["attempts"][0]["status"] == "rejected-model-substitution"


def test_reject_non_object_json_with_require_json(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")
    metadata_out = tmp_path / "metadata.json"

    def fake_urlopen(request, timeout=None):
        body = json.dumps(
            {
                "id": "req-1",
                "object": "chat.completion",
                "model": "test/model",
                "choices": [{"message": {"content": "[1,2,3]"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()
        return _FakeHttpResponse(body)

    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--metadata-out",
        str(metadata_out),
        "--job-envelope-file",
        str(_write_job_envelope(tmp_path)),
        *RUNNER_IDENTITY_ARGS,
        "--attempts",
        "1",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with patch.object(runner, "open_provider", fake_urlopen):
        exit_code = runner.main()
    attempt_metadata = sorted((tmp_path / "raw.attempts").glob("attempt-*.metadata.json"))[-1]
    metadata = json.loads(attempt_metadata.read_text())
    assert exit_code == 2
    assert metadata["attempts"][0]["status"] == "invalid-json-non-object"


def test_reject_multiple_choices(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")
    metadata_out = tmp_path / "metadata.json"

    def fake_urlopen(request, timeout=None):
        body = json.dumps(
            {
                "id": "req-1",
                "object": "chat.completion",
                "model": "test/model",
                "choices": [
                    {"message": {"content": '{"ok": true}'}, "finish_reason": "stop"},
                    {"message": {"content": '{"ok": false}'}, "finish_reason": "stop"},
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()
        return _FakeHttpResponse(body)

    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--metadata-out",
        str(metadata_out),
        "--job-envelope-file",
        str(_write_job_envelope(tmp_path)),
        *RUNNER_IDENTITY_ARGS,
        "--attempts",
        "1",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with patch.object(runner, "open_provider", fake_urlopen):
        exit_code = runner.main()
    attempt_metadata = sorted((tmp_path / "raw.attempts").glob("attempt-*.metadata.json"))[-1]
    metadata = json.loads(attempt_metadata.read_text())
    assert exit_code == 2
    assert metadata["attempts"][0]["status"] == "rejected-choice-count"


def test_attempt_files_are_immutable(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")
    attempt_dir = tmp_path / "attempts"
    metadata_out = tmp_path / "metadata.json"
    bodies = [
        json.dumps(
            {
                "id": "req-1",
                "object": "chat.completion",
                "model": "test/model",
                "choices": [{"message": {"content": "not-json"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ),
        json.dumps(
            {
                "id": "req-2",
                "object": "chat.completion",
                "model": "test/model",
                "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ),
    ]
    call = {"index": 0}

    def fake_urlopen(request, timeout=None):
        body = bodies[call["index"]].encode()
        call["index"] += 1
        return _FakeHttpResponse(body)

    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--metadata-out",
        str(metadata_out),
        "--attempt-dir",
        str(attempt_dir),
        "--job-envelope-file",
        str(_write_job_envelope(tmp_path)),
        *RUNNER_IDENTITY_ARGS,
        "--attempts",
        "2",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with patch.object(runner, "open_provider", fake_urlopen):
        exit_code = runner.main()
    attempt_files = sorted(attempt_dir.glob("attempt-*.raw.json"))
    first = json.loads(attempt_files[0].read_text())
    second = json.loads(attempt_files[1].read_text())
    metadata = json.loads(metadata_out.read_text())
    assert exit_code == 0
    assert first["id"] == "req-1"
    assert second["id"] == "req-2"
    assert all("finished_at" in attempt for attempt in metadata["attempts"])


def test_missing_metadata_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("system")
    user_file.write_text("user")

    def fake_urlopen(request, timeout=None):
        body = json.dumps(
            {
                "object": "chat.completion",
                "model": "test/model",
                "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()
        return _FakeHttpResponse(body)

    metadata_out = tmp_path / "metadata.json"
    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--metadata-out",
        str(metadata_out),
        "--job-envelope-file",
        str(_write_job_envelope(tmp_path)),
        *RUNNER_IDENTITY_ARGS,
        "--attempts",
        "1",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with patch.object(runner, "open_provider", fake_urlopen):
        exit_code = runner.main()
    attempt_metadata = sorted((tmp_path / "raw.attempts").glob("attempt-*.metadata.json"))[-1]
    metadata = json.loads(attempt_metadata.read_text())
    assert exit_code == 2
    assert metadata["attempts"][0]["status"] == "missing-provider-request-id"


def test_rejects_oversized_prompt_before_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system_file = tmp_path / "system.txt"
    user_file = tmp_path / "user.txt"
    system_file.write_text("x" * (runner.MAX_INPUT_BYTES + 1))
    user_file.write_text("ok")
    argv = [
        "openrouter_chat.py",
        "--model",
        "test/model",
        "--system-file",
        str(system_file),
        "--user-file",
        str(user_file),
        "--raw-out",
        str(tmp_path / "raw.json"),
        "--content-out",
        str(tmp_path / "content.json"),
        "--job-envelope-file",
        str(_write_job_envelope(tmp_path)),
        *RUNNER_IDENTITY_ARGS,
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit, match="max input bytes"):
        runner.main()


def test_default_and_retry_tokens_are_32768() -> None:
    assert runner.DEFAULT_MAX_TOKENS == 32768
    assert runner.DEFAULT_MAX_RETRY_TOKENS == 32768
    assert runner.MAX_COMPLETION_TOKENS == 32768
    assert runner.MAX_TOTAL_COMPLETION_TOKENS == 96000
