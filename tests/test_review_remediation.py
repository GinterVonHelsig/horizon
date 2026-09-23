"""Regressions for the independent review; no live model execution."""
from pathlib import Path
from dataclasses import replace

import pytest

from comms01_release_deploy import build_worker_unit
from model_routing import load_model_routing, resolve_phase_route, IndependentReviewBlocked, build_routing_records
from test_worker import FakeController, FakeTask, ScriptedAdapter, _failure, _success_payload, artifact_root
from worker import TaskWorker

ROOT = Path(__file__).resolve().parents[1]


def test_generated_worker_preserves_health_and_terminal_exit_contract():
    generated = build_worker_unit("/disposable/controller/worker_cli.py", "/disposable")
    tracked = (ROOT / "systemd/top-delivery-worker.service").read_text()
    for directive in (
        "StateDirectory=top-delivery/worker-health",
        "StateDirectoryMode=0700",
        "Environment=TOP_DELIVERY_WORKER_HEALTH_DIR=/var/lib/top-delivery/worker-health",
        "RestartPreventExitStatus=78",
    ):
        assert directive in generated
        assert directive in tracked


@pytest.mark.parametrize("role", ["executor", "auditor"])
def test_uncertain_failure_never_queues_replay(artifact_root, role):
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = ScriptedAdapter("executor", [_failure(True, "process_failure") if role == "executor" else _success_payload()])
    auditor = ScriptedAdapter("auditor", [_failure(True, "process_failure")])
    adapters = {"executor": executor, "auditor": auditor}
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "one")
    assert result.terminal_state == "blocked:execution_outcome_requires_review"
    assert not controller.retries
    assert executor.calls == 1
    # Simulate a legacy queue entry/restart; durable intent must still veto replay.
    controller.tasks["task-1"].state = "scheduled"
    result = TaskWorker(controller, artifact_root, adapters).run_once("run-1", "two")
    assert result.terminal_state == "blocked:execution_outcome_requires_review"
    assert executor.calls == 1


def test_selector_identity_is_not_a_passing_prior_review():
    policy = load_model_routing(ROOT / "architecture/model-routing.yaml")
    author = resolve_phase_route(policy, "3A")
    first = resolve_phase_route(policy, "1.5", author_routes=(author,),
                                available_routes=frozenset({("openai", "gpt-5.6-sol")}))
    with pytest.raises(IndependentReviewBlocked, match="passing prior review"):
        resolve_phase_route(policy, "1.6", author_routes=(author,), prior_review_routes=(first,),
                            available_routes=frozenset({("openrouter", "x-ai/grok-4.6")}))


@pytest.mark.parametrize("verdict", [None, "reject", "reject_with_critical", "transport_failure", "timeout", "malformed_structured_output", "pass", "pass_with_minors"])
def test_selector_enforces_completed_verdict_at_entry(verdict):
    policy = load_model_routing(ROOT / "architecture/model-routing.yaml")
    author = resolve_phase_route(policy, "3A")
    first = replace(resolve_phase_route(policy, "0"), phase="1.5", verdict=verdict)
    kwargs = dict(author_routes=(author,), prior_review_routes=(first,),
                  available_routes=frozenset({("openrouter", "x-ai/grok-4.6")}))
    if verdict in {"pass", "pass_with_minors"}:
        assert resolve_phase_route(policy, "1.6", **kwargs).model == "x-ai/grok-4.6"
        with pytest.raises(IndependentReviewBlocked, match="passing prior review"):
            resolve_phase_route(policy, "1.6", **{**kwargs, "prior_review_routes": (first, first)})
    else:
        with pytest.raises(IndependentReviewBlocked, match="passing prior review"):
            resolve_phase_route(policy, "1.6", **kwargs)


def test_batch_plan_does_not_fabricate_completed_reviews():
    policy = load_model_routing(ROOT / "architecture/model-routing.yaml")
    with pytest.raises(IndependentReviewBlocked, match="passing prior review"):
        build_routing_records(policy, ("1.5", "1.6"), author_routes=(resolve_phase_route(policy, "3A"),),
                              available_routes=frozenset({("openai", "gpt-5.6-sol"), ("openrouter", "x-ai/grok-4.6")}))


@pytest.mark.parametrize("reviewer,allowed", [("x-ai/grok-4.6", True), ("openai/gpt-6-astra", False), ("unconfigured-review-model", False)])
def test_real_worker_path_applies_policy_before_effects(artifact_root, reviewer, allowed, monkeypatch):
    policy = load_model_routing(ROOT / "architecture/model-routing.yaml")
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = ScriptedAdapter("executor", [replace(_success_payload(), adapter_id="executor", provider="openai", model="gpt-6-astra")])
    executor.provider, executor.model = "openai", "gpt-6-astra"
    auditor = ScriptedAdapter("auditor", [replace(_success_payload(), adapter_id="auditor", provider="openrouter", model=reviewer)])
    auditor.provider, auditor.model = "openrouter", reviewer
    worker = TaskWorker(controller, artifact_root, {"executor": executor, "auditor": auditor}, routing_policy=policy)
    # Deterministic fake adapters; no HTTP transport or spending occurs.
    monkeypatch.setattr(worker, "_authorize_adapter_execution", lambda *args: None)
    result = worker.run_once("run-1", "simulated")
    assert result.terminal_state == ("verified" if allowed else "blocked")
    assert executor.calls == auditor.calls == int(allowed)


def test_pre_execution_failure_can_still_retry(artifact_root):
    controller = FakeController()
    task = FakeTask("task-1", "run-1", "obj")
    controller.tasks[task.task_id] = task
    result = TaskWorker(controller, artifact_root, {})._handle_failure(task, "1", "child_crash:pre_execution")
    assert result.terminal_state == "retry_queued"
    assert controller.retries == ["task-1"]


def test_reported_executor_identity_mismatch_cannot_reach_review(artifact_root):
    policy = load_model_routing(ROOT / "architecture/model-routing.yaml")
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = ScriptedAdapter("executor", [_success_payload()])  # Reports a different identity.
    executor.provider, executor.model = "cursor", "composer-latest"
    auditor = ScriptedAdapter("auditor", [])
    auditor.provider, auditor.model = "openai", "gpt-6-astra"
    result = TaskWorker(controller, artifact_root, {"executor": executor, "auditor": auditor},
                        routing_policy=policy).run_once("run-1", "simulated")
    assert result.terminal_state == "blocked"
    assert executor.calls == 1 and auditor.calls == 0
    assert not controller.retries


def test_production_cli_always_supplies_policy_and_preflight_config(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import worker_cli
    captured = {}
    config = {"adapters": [], "routes": {}}
    monkeypatch.setattr(worker_cli, "load_relay_token", lambda: None)
    monkeypatch.setattr(worker_cli, "load_registry_config", lambda *a, **k: config)
    monkeypatch.setattr(worker_cli.AdapterRegistry, "from_config", lambda *a, **k: SimpleNamespace(adapters={}, default_executor="e", default_auditor="a"))
    monkeypatch.setattr(worker_cli, "build_controller", lambda *a: SimpleNamespace(close=lambda: None))
    def capture_worker(*args, **kwargs):
        captured.update(kwargs)
        return object()
    monkeypatch.setattr(worker_cli, "TaskWorker", capture_worker)
    monkeypatch.setattr(worker_cli, "WorkerLoop", lambda *a, **k: SimpleNamespace(run=lambda: True, last_status="verified"))
    assert worker_cli.main(["--once", "--run-id", "disposable", "--artifact-root", str(tmp_path),
                            "--health-dir", str(tmp_path / "health"), "--config", "unused", "--db-url", "unused"]) == 0
    assert captured["routing_policy"]["version"] == 3
    assert captured["routing_policy"]["month"] == "2026-09"
    assert captured["adapter_config"] is config


@pytest.mark.parametrize("boundary", ["before_claim", "after_claim", "before_auditor"])
def test_preflight_block_survives_restart_and_finalizes_claim(artifact_root, tmp_path, monkeypatch, boundary):
    from worker import WorkerLoop
    from worker_health import WorkerHealth
    from harness_adapters.preflight import AdapterPreflightError
    import worker as worker_module
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    executor = ScriptedAdapter("executor", [replace(_success_payload(), adapter_id="executor", provider="cursor", model="composer-latest")])
    executor.provider, executor.model = "cursor", "composer-latest"
    auditor = ScriptedAdapter("auditor", [])
    auditor.provider, auditor.model = "openai", "gpt-6-astra"
    calls = []
    failure_call = {"before_claim": 1, "after_claim": 2, "before_auditor": 3}[boundary]
    def rejected(*args, **kwargs):
        calls.append(1)
        if len(calls) == failure_call:
            raise AdapterPreflightError("sensitive catalog detail must not be persisted")
    monkeypatch.setattr(worker_module, "preflight_adapters", rejected)
    policy = load_model_routing(ROOT / "architecture/model-routing.yaml")
    for _ in range(2):
        worker = TaskWorker(controller, artifact_root, {"executor": executor, "auditor": auditor},
                            routing_policy=policy, adapter_config={})
        health = WorkerHealth(tmp_path / "health")
        loop = WorkerLoop(worker, run_id="run-1", owner="simulated", health=health)
        assert not loop.run()
        assert loop.last_status == "blocked:adapter_preflight"
    assert health.state("run-1")["blocked"] == 1
    assert "sensitive" not in str(health.state("run-1"))
    assert len(calls) == failure_call
    assert auditor.calls == 0
    assert executor.calls == int(boundary == "before_auditor")
    assert controller.tasks["task-1"].state == ("scheduled" if boundary == "before_claim" else "blocked")
    assert len(controller.cleanups) == int(boundary != "before_claim")
    assert not controller.retries


def test_cli_preflight_error_is_terminal_78(monkeypatch):
    from harness_adapters.preflight import AdapterPreflightError
    import worker_cli
    def unavailable(*args):
        raise AdapterPreflightError("sanitized configuration rejection")
    monkeypatch.setattr(worker_cli, "_main", unavailable)
    assert worker_cli.main([]) == 78


def test_real_cli_persists_preflight_block_before_restart(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from harness_adapters.preflight import AdapterPreflightError
    from worker_health import WorkerHealth
    import worker_cli
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(1)
        raise AdapterPreflightError("do not persist remote response")
    monkeypatch.setattr(worker_cli, "load_relay_token", lambda: None)
    monkeypatch.setattr(worker_cli, "load_registry_config", lambda *a, **k: {})
    monkeypatch.setattr(worker_cli.AdapterRegistry, "from_config", lambda *a, **k: SimpleNamespace(adapters={}, default_executor="e", default_auditor="a"))
    monkeypatch.setattr(worker_cli, "build_controller", lambda *a: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(worker_cli, "TaskWorker", lambda *a, **k: SimpleNamespace(run_once=unavailable, cancel_active=lambda: None))
    args = ["--run-id", "disposable", "--artifact-root", str(tmp_path), "--health-dir", str(tmp_path / "health"), "--config", "unused", "--db-url", "unused"]
    assert worker_cli.main(args) == 78
    assert worker_cli.main(args) == 78
    assert len(calls) == 1
    health = WorkerHealth(tmp_path / "health")
    assert health.state("disposable")["reason"] == "adapter_preflight"
    health.recover("disposable", "adapter_configuration_repaired")
    assert health.state("disposable")["blocked"] == 0
