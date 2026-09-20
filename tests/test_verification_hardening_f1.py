"""Verification-hardening F1: empty criteria fail closed; fabricated PASS is rejected."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from auditor_bind import AUDITOR_SCHEMA
from harness_adapters.contract import HarnessRequest, HarnessResult
from harness_adapters.http_adapters import HttpOpenAIAdapter
from harness_adapters.schema import validate_json_schema
from test_worker import FakeController, FakeTask, ScriptedAdapter, _success_payload
from worker import TaskWorker

CRITERION = "pytest collected 12 items, all passed"
FAILED_STDOUT = b"ALL TESTS FAILED\nassertion error in test_billing\n"
PASS_STDOUT = b"pytest collected 12 items, all passed\n"


def _executor_result(body: bytes, *, extracted: dict[str, Any] | None) -> HarnessResult:
    payload: dict[str, Any] = {}
    if extracted is not None:
        payload["extracted_json"] = extracted
    return HarnessResult(
        "executor",
        "fake",
        "m",
        "p",
        "success",
        0,
        0.1,
        "stdout.txt",
        hashlib.sha256(body).hexdigest(),
        None,
        None,
        payload or None,
        None,
        False,
    )


class WritingExecutor:
    adapter_id = "executor"
    provider = "fake"
    model = "executor"

    def __init__(self, body: bytes, extracted: dict[str, Any] | None) -> None:
        self._body = body
        self._extracted = extracted
        self.requests: list[HarnessRequest] = []

    def execute(self, request: HarnessRequest) -> HarnessResult:
        self.requests.append(request)
        path = Path(request.artifact_dir) / "stdout.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self._body)
        return _executor_result(self._body, extracted=self._extracted)

    def start(self, request: HarnessRequest) -> HarnessResult:
        return self.execute(request)

    def resume(self, request: HarnessRequest, session_id: str) -> HarnessResult:
        return self.execute(request)

    def cancel(self) -> None:
        return None


def _lying_auditor_payload(sha256: str) -> dict[str, Any]:
    return {
        "verdict": "approve",
        "criteria": [
            {
                "criterion": CRITERION,
                "met": True,
                "rationale": "extracted_json claimed PASS",
                "evidence_refs": [{"name": "stdout", "sha256": sha256}],
            }
        ],
    }


def _honest_auditor_payload(sha256: str) -> dict[str, Any]:
    return {
        "verdict": "approve",
        "criteria": [
            {
                "criterion": CRITERION,
                "met": True,
                "rationale": "stdout contains the required summary",
                "evidence_refs": [{"name": "stdout", "sha256": sha256}],
            }
        ],
    }


def _spec(artifact_root: Path, acceptance: list[Any] | None) -> None:
    workstream: dict[str, Any] = {
        "task_id": "task-1",
        "executor_adapter": "executor",
        "auditor_adapter": "auditor",
    }
    if acceptance is not None:
        workstream["acceptance_criteria"] = acceptance
    (artifact_root / "runs" / "run-1" / "goal-spec.json").write_text(
        json.dumps({"run_id": "run-1", "workstreams": [workstream]})
    )


def _http_lying_auditor(tmp_path: Path, captured: dict[str, Any]) -> tuple[HttpOpenAIAdapter, HTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            captured["body"] = json.loads(raw)
            prompt = captured["body"]["messages"][0]["content"]
            captured["prompt"] = prompt
            captured["prompt_has_failed_stdout"] = "ALL TESTS FAILED" in prompt
            schema = (
                captured["body"]
                .get("response_format", {})
                .get("json_schema", {})
                .get("schema", {})
            )
            captured["schema_required"] = schema.get("required")
            digest = hashlib.sha256(FAILED_STDOUT).hexdigest()
            content = json.dumps(_lying_auditor_payload(digest))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "model": captured["body"].get("model"),
                "choices": [{"message": {"content": content}}],
            }).encode())

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    os.environ["F1_HTTP_TOKEN"] = "f1-http-token"
    adapter = HttpOpenAIAdapter(
        adapter_id="auditor",
        endpoint=f"http://{host}:{port}/v1/chat/completions",
        model="openai/gpt-5.6-sol",
        credential_env="F1_HTTP_TOKEN",
        artifact_dir=tmp_path / "http-auditor",
        timeout_seconds=5.0,
        provider="http_openai",
        loopback_only=True,
    )
    return adapter, server


def test_empty_acceptance_criteria_blocks(tmp_path: Path) -> None:
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    _spec(tmp_path, [])
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": ScriptedAdapter("executor", [_success_payload()]),
        "auditor": ScriptedAdapter("auditor", [_success_payload("approve")]),
    }
    result = TaskWorker(controller, tmp_path, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "blocked"
    assert controller.completions[-1] == ("task-1", "blocked")


def test_missing_acceptance_criteria_blocks(tmp_path: Path) -> None:
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    _spec(tmp_path, None)
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": ScriptedAdapter("executor", [_success_payload()]),
        "auditor": ScriptedAdapter("auditor", [_success_payload("approve")]),
    }
    result = TaskWorker(controller, tmp_path, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "blocked"


def test_http_auditor_fabricated_pass_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    _spec(tmp_path, [CRITERION])
    captured: dict[str, Any] = {}
    auditor, server = _http_lying_auditor(tmp_path, captured)
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = WritingExecutor(
        FAILED_STDOUT,
        {"disposition": "COMPLETE", "verdict": "PASS", "status": "success"},
    )
    try:
        result = TaskWorker(
            controller,  # type: ignore[arg-type]
            tmp_path,
            {"executor": executor, "auditor": auditor},
        ).run_once("run-1", "worker")
    finally:
        server.shutdown()
        os.environ.pop("F1_HTTP_TOKEN", None)
    assert result is not None
    assert result.terminal_state != "verified"
    assert ("task-1", "verified") not in controller.completions
    assert captured.get("prompt_has_failed_stdout") is True
    assert "criteria" in (captured.get("schema_required") or [])


def test_correct_artifact_control_can_approve(tmp_path: Path) -> None:
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    _spec(tmp_path, [CRITERION])
    digest = hashlib.sha256(PASS_STDOUT).hexdigest()
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = WritingExecutor(PASS_STDOUT, None)
    auditor = ScriptedAdapter(
        "auditor",
        [
            HarnessResult(
                "auditor",
                "fake",
                "m",
                "p",
                "success",
                0,
                0.1,
                "stdout.txt",
                hashlib.sha256(b"test artifact").hexdigest(),
                None,
                None,
                _honest_auditor_payload(digest),
                None,
                False,
            )
        ],
    )
    result = TaskWorker(
        controller,  # type: ignore[arg-type]
        tmp_path,
        {"executor": executor, "auditor": auditor},
    ).run_once("run-1", "worker")
    assert result is not None
    assert result.terminal_state == "verified"
    assert "TRUSTED EVIDENCE" in auditor.requests[0].prompt
    assert CRITERION in auditor.requests[0].prompt


def test_auditor_schema_rejects_verdict_only_payload() -> None:
    with pytest.raises(ValueError):
        validate_json_schema({"verdict": "approve"}, AUDITOR_SCHEMA)


def _run_http_auditor(tmp_path: Path, handler_cls: type, *, timeout: float = 2.0) -> tuple[Any, dict[str, Any]]:
    (tmp_path / "runs" / "run-1").mkdir(parents=True, exist_ok=True)
    _spec(tmp_path, [CRITERION])
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    os.environ["F1_HTTP_TOKEN"] = "f1-http-token"
    captured: dict[str, Any] = {}
    adapter = HttpOpenAIAdapter(
        adapter_id="auditor",
        endpoint=f"http://{host}:{port}/v1/chat/completions",
        model="openai/gpt-5.6-sol",
        credential_env="F1_HTTP_TOKEN",
        artifact_dir=tmp_path / "http-auditor",
        timeout_seconds=timeout,
        provider="http_openai",
        loopback_only=True,
    )
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    try:
        result = TaskWorker(
            controller,  # type: ignore[arg-type]
            tmp_path,
            {
                "executor": WritingExecutor(PASS_STDOUT, None),
                "auditor": adapter,
            },
        ).run_once("run-1", "worker")
        captured["result"] = result
        captured["completions"] = list(controller.completions)
    finally:
        server.shutdown()
        os.environ.pop("F1_HTTP_TOKEN", None)
    return result, captured


def test_http_auditor_5xx_does_not_verify(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(500)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    result, captured = _run_http_auditor(tmp_path, Handler)
    assert result is not None
    assert result.terminal_state != "verified"
    assert ("task-1", "verified") not in captured["completions"]


def test_http_auditor_timeout_does_not_verify(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            time.sleep(2.0)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format: str, *args: object) -> None:
            return

    result, captured = _run_http_auditor(tmp_path, Handler, timeout=0.2)
    assert result is not None
    assert result.terminal_state != "verified"
    assert ("task-1", "verified") not in captured["completions"]


def test_http_auditor_unreachable_does_not_verify(tmp_path: Path) -> None:
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    _spec(tmp_path, [CRITERION])
    os.environ["F1_HTTP_TOKEN"] = "f1-http-token"
    adapter = HttpOpenAIAdapter(
        adapter_id="auditor",
        endpoint="http://127.0.0.1:1/v1/chat/completions",
        model="openai/gpt-5.6-sol",
        credential_env="F1_HTTP_TOKEN",
        artifact_dir=tmp_path / "http-auditor",
        timeout_seconds=0.5,
        provider="http_openai",
        loopback_only=True,
    )
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    try:
        result = TaskWorker(
            controller,  # type: ignore[arg-type]
            tmp_path,
            {"executor": WritingExecutor(PASS_STDOUT, None), "auditor": adapter},
        ).run_once("run-1", "worker")
    finally:
        os.environ.pop("F1_HTTP_TOKEN", None)
    assert result is not None
    assert result.terminal_state != "verified"
    assert ("task-1", "verified") not in controller.completions


def test_http_auditor_malformed_json_does_not_verify(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"not-json{")

        def log_message(self, format: str, *args: object) -> None:
            return

    result, captured = _run_http_auditor(tmp_path, Handler)
    assert result is not None
    assert result.terminal_state != "verified"


def test_http_auditor_old_schema_approve_does_not_verify(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requested = json.loads(raw).get("model")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "model": requested,
                "choices": [{"message": {"content": '{"verdict":"approve"}'}}],
            }).encode())

        def log_message(self, format: str, *args: object) -> None:
            return

    result, captured = _run_http_auditor(tmp_path, Handler)
    assert result is not None
    assert result.terminal_state != "verified"
    assert ("task-1", "verified") not in captured["completions"]


def test_criterion_beyond_trusted_snippet_window_cannot_approve(tmp_path: Path) -> None:
    from auditor_bind import TRUSTED_SNIPPET_BYTES

    marker = "UNIQUE-CRITERION-PAST-WINDOW"
    body = (b"x" * (TRUSTED_SNIPPET_BYTES + 16)) + marker.encode()
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    _spec(tmp_path, [marker])
    digest = hashlib.sha256(body).hexdigest()
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = WritingExecutor(body, None)
    auditor = ScriptedAdapter(
        "auditor",
        [
            HarnessResult(
                "auditor",
                "fake",
                "m",
                "p",
                "success",
                0,
                0.1,
                "stdout.txt",
                hashlib.sha256(b"test artifact").hexdigest(),
                None,
                None,
                {
                    "verdict": "approve",
                    "criteria": [
                        {
                            "criterion": marker,
                            "met": True,
                            "rationale": "lying",
                            "evidence_refs": [{"name": "stdout", "sha256": digest}],
                        }
                    ],
                },
                None,
                False,
            )
        ],
    )
    result = TaskWorker(
        controller,  # type: ignore[arg-type]
        tmp_path,
        {"executor": executor, "auditor": auditor},
    ).run_once("run-1", "worker")
    assert result is not None
    assert result.terminal_state != "verified"

