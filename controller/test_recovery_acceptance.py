"""Disposable PostgreSQL + real orchestration; all model adapters are SIMULATED."""
import json
import multiprocessing
import os
import signal
import time
from pathlib import Path

import pytest

from goal_submitter import GoalSubmitter, TaskRoutingSnapshot, DryRunParentController
from parent_controller import ParentController
from worker import TaskWorker, WorkerLoop
from worker_health import WorkerHealth
from subworkflow_handoff import build_handoff_request, validate_product, HandoffValidationError, PROVIDER_REGISTRY
from test_only.recovery_fakes import SimulatedAdapter, route_config, product_for

ROUTES = TaskRoutingSnapshot("simulated-writer", "simulated-reviewer")


@pytest.fixture
def prompt(tmp_path):
    path = tmp_path / "tiny.md"
    path.write_text("# Disposable recovery\n\n**Objective:** Write one trivial file.\n\n## Mission\n\nSimulated execution only.\n\n## P0 authority envelope\n\nAllowed:\n\n- Disposable workspace.\n\nForbidden without a new explicit authority envelope:\n\n- Production changes.\n")
    return path


@pytest.fixture
def parent(db_url, artifact_root):
    controller = ParentController(db_url, artifact_root=artifact_root, controller_lease_seconds=120, adapter_config=route_config())
    yield controller
    controller.close()


def submit(parent, root, prompt):
    return GoalSubmitter(parent, root, task_routing=ROUTES).submit(prompt)


def worker(parent, root, *, reject=False, kill=False):
    return TaskWorker(parent, root, {
        "simulated-writer": SimulatedAdapter("simulated-writer", kill=kill),
        "simulated-reviewer": SimulatedAdapter("simulated-reviewer", review=True, reject=reject),
    })


def test_normal_duplicate_and_truthful_completion(parent, artifact_root, prompt):
    receipt = submit(parent, artifact_root, prompt)
    again = submit(parent, artifact_root, prompt)
    assert receipt.run_id == again.run_id
    loop = WorkerLoop(worker(parent, artifact_root), run_id=receipt.run_id, owner="simulated", once=True)
    assert loop.run() and loop.last_status == "verified"
    assert parent.task(receipt.task_ids[0]).state == "verified"
    assert worker(parent, artifact_root).run_once(receipt.run_id, "second") is None
    with parent._repo.transaction() as cur:
        cur.execute("SELECT count(*) AS n FROM parent_tasks WHERE run_id=%s", (receipt.run_id,))
        assert cur.fetchone()["n"] == 1


@pytest.mark.parametrize("boundary", ["register", "schedule"])
def test_partial_submission_recovers(parent, artifact_root, prompt, monkeypatch, boundary):
    target = parent._repo if boundary == "register" else parent
    name = "register_run" if boundary == "register" else "schedule_task"
    original = getattr(target, name)
    def fail(*args, **kwargs):
        raise RuntimeError("injected boundary failure")
    monkeypatch.setattr(target, name, fail)
    with pytest.raises(RuntimeError, match="injected"):
        submit(parent, artifact_root, prompt)
    monkeypatch.setattr(target, name, original)
    receipt = submit(parent, artifact_root, prompt)
    assert worker(parent, artifact_root).run_once(receipt.run_id, "recovered").terminal_state == "verified"


def test_dry_run_then_durable(parent, artifact_root, prompt):
    dry = GoalSubmitter(DryRunParentController(), artifact_root, mode="dry_run", task_routing=ROUTES).submit(prompt)
    receipt = submit(parent, artifact_root, prompt)
    assert dry.run_id == receipt.run_id
    assert worker(parent, artifact_root).run_once(receipt.run_id, "recovered").terminal_state == "verified"


def test_missing_route_before_provider_scheduling(parent, artifact_root, prompt):
    receipt = submit(parent, artifact_root, prompt)
    task = parent.claim_next(receipt.run_id, "simulated")
    attempt, fence = parent.resolve_parent_attempt(task.task_id, task.generation)
    with pytest.raises(ValueError, match="missing adapter configuration: gateway-delivery, openrouter-independent-review"):
        parent.create_subworkflow_handoff(run_id=receipt.run_id, parent_task_id=task.task_id, parent_attempt_id=attempt, parent_fence_token=fence, failure_code="BLOCKED_HORIZON_PREREQ_MISSING")
    with parent._repo.transaction() as cur:
        cur.execute("SELECT count(*) AS n FROM subworkflow_handoffs")
        assert cur.fetchone()["n"] == 0


@pytest.mark.parametrize("failure", list(PROVIDER_REGISTRY))
def test_provider_contract_and_invalid_bindings(tmp_path, failure):
    request = build_handoff_request(run_id="sim-run", parent_task_id="sim-parent", parent_attempt_id="sim-attempt", failure_code=failure, request_artifact_root="handoffs", handoff_context={"prerequisite_node_id": "tiny-prerequisite"})
    path = product_for(request, tmp_path / "product")
    original = json.loads(path.read_text())
    assert validate_product(path, request, tmp_path)["disposition"] == request["required_disposition"]
    for key, value in (("product_contract", "wrong-provider.v1"), ("parent_task_id", "forged"), ("disposition", "PASS_ANYTHING"), ("status", "failed")):
        path.write_text(json.dumps({**original, key: value}))
        with pytest.raises(HandoffValidationError):
            validate_product(path, request, tmp_path)
    path.write_text(json.dumps(original))
    with pytest.raises(HandoffValidationError):
        validate_product(path, {**request, "provider_route": "forged"}, tmp_path)
    (path.parent / "acceptance.txt").write_text("tampered")
    with pytest.raises(HandoffValidationError):
        validate_product(path, request, tmp_path)


def test_auditor_rejection_is_terminal_and_false_exit(parent, artifact_root, prompt):
    receipt = submit(parent, artifact_root, prompt)
    loop = WorkerLoop(worker(parent, artifact_root, reject=True), run_id=receipt.run_id, owner="sim", once=True)
    assert not loop.run()
    assert loop.last_status == "blocked:auditor_reject"
    assert parent.task(receipt.task_ids[0]).state == "blocked"
    assert worker(parent, artifact_root).run_once(receipt.run_id, "restart") is None


def test_persistent_permission_failure_and_explicit_recovery(tmp_path):
    class Denied:
        calls = 0
        def run_once(self, *args):
            self.calls += 1
            raise PermissionError(13, "sensitive path must not be stored")
        def cancel_active(self): pass
    denied = Denied()
    health_dir = tmp_path / "health"
    for _ in range(2):
        health = WorkerHealth(health_dir)
        loop = WorkerLoop(denied, run_id="disposable", owner="sim", health=health)
        assert not loop.run()
    assert denied.calls == 1
    assert health.state("disposable")["blocked"] == 1
    assert "sensitive" not in str(health.state("disposable"))
    health.recover("disposable", "filesystem_cause_repaired")
    assert health.state("disposable")["blocked"] == 0


def test_disabled_submission_does_not_reopen(parent, artifact_root, prompt):
    receipt = submit(parent, artifact_root, prompt)
    parent.persist_goal_state(receipt.run_id, "WAITING_OPERATOR")
    before = parent._repo.controller_state(receipt.run_id)
    assert submit(parent, artifact_root, prompt).status == "preserved_disabled"
    assert parent._repo.controller_state(receipt.run_id) == before


def test_stopped_run_stays_disabled_on_submit_and_worker_restart(parent, db_url, artifact_root, prompt, tmp_path):
    receipt = submit(parent, artifact_root, prompt)
    epoch = parent._repo.controller_state(receipt.run_id)["current_epoch"]
    parent._repo.rollback_disable(receipt.run_id, expected_epoch=epoch)
    before = parent._repo.controller_state(receipt.run_id)
    assert before["scheduling_enabled"] is False
    assert submit(parent, artifact_root, prompt).status == "preserved_disabled"
    restarted = ParentController(db_url, artifact_root=artifact_root, lease_holder=False)
    try:
        loop = WorkerLoop(worker(restarted, artifact_root), run_id=receipt.run_id, owner="restart", once=True, health=WorkerHealth(tmp_path / "stopped-health"))
        assert not loop.run()
        assert restarted._repo.controller_state(receipt.run_id) == before
    finally:
        restarted.close()


def test_lease_not_stolen(parent, db_url, artifact_root, prompt):
    receipt = submit(parent, artifact_root, prompt)
    before = parent._repo.controller_state(receipt.run_id)
    other = ParentController(db_url, artifact_root=artifact_root)
    try:
        with pytest.raises(Exception, match="lease held"):
            other.register_run(receipt.run_id)
        assert parent._repo.controller_state(receipt.run_id) == before
    finally:
        other.close()


def _duplicate_submit(db_url, root, prompt, queue):
    from test_only.disposable_harness import enable_disposable_harness
    enable_disposable_harness()
    controller = ParentController(db_url, artifact_root=root, lease_holder=False, adapter_config=route_config())
    try:
        queue.put(submit(controller, root, prompt).run_id)
    finally:
        controller.close()


def test_concurrent_submission(parent, db_url, artifact_root, prompt):
    from prompt_ingest import parse_prompt_file
    run_id = parse_prompt_file(prompt).run_id
    parent.register_run(run_id)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [context.Process(target=_duplicate_submit, args=(db_url, artifact_root, prompt, queue)) for _ in range(2)]
    for process in processes: process.start()
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    assert [queue.get(timeout=1) for _ in processes] == [run_id] * 2
    with parent._repo.transaction() as cur:
        cur.execute("SELECT count(*) AS n FROM parent_tasks WHERE run_id=%s", (run_id,))
        assert cur.fetchone()["n"] == 1


def _killed_worker(db_url, root, run_id, after_execution):
    from test_only.disposable_harness import enable_disposable_harness
    enable_disposable_harness()
    controller = ParentController(db_url, artifact_root=root, lease_holder=False, stale_after=2)
    if after_execution:
        worker(controller, root, kill=True).run_once(run_id, "killed")
    else:
        assert controller.claim_next(run_id, "killed") is not None
        os.kill(os.getpid(), signal.SIGKILL)


@pytest.mark.parametrize("after_execution", [False, True])
def test_killed_worker_fencing_and_no_replay(parent, db_url, artifact_root, prompt, after_execution):
    receipt = submit(parent, artifact_root, prompt)
    process = multiprocessing.get_context("spawn").Process(target=_killed_worker, args=(db_url, artifact_root, receipt.run_id, after_execution))
    process.start()
    process.join(10)
    assert process.exitcode == -signal.SIGKILL
    # Lease has not expired: no competing owner may claim.
    assert parent.claim_next(receipt.run_id, "competitor") is None
    time.sleep(2.05)
    recovered = worker(parent, artifact_root).run_once(receipt.run_id, "recovery")
    assert recovered.terminal_state == ("blocked:execution_outcome_requires_review" if after_execution else "verified")
    assert len(list(artifact_root.rglob("tiny-result.txt"))) == 1


@pytest.mark.parametrize("failure", list(PROVIDER_REGISTRY))
def test_provider_worker_review_handoff_end_to_end(parent, artifact_root, prompt, failure):
    receipt = submit(parent, artifact_root, prompt)
    task = parent.claim_next(receipt.run_id, "parent")
    attempt, fence = parent.resolve_parent_attempt(task.task_id, task.generation)
    contract = PROVIDER_REGISTRY[failure]
    parent.adapter_config = route_config(contract.executor_adapter, contract.auditor_adapter)
    handoff = parent.create_subworkflow_handoff(run_id=receipt.run_id, parent_task_id=task.task_id, parent_attempt_id=attempt, parent_fence_token=fence, failure_code=failure, handoff_context={"prerequisite_node_id": "tiny-prerequisite"})
    request_path = artifact_root / handoff["request_path"]
    request = json.loads(request_path.read_text())
    provider = TaskWorker(parent, artifact_root, {
        contract.executor_adapter: SimulatedAdapter(contract.executor_adapter, product=lambda root: product_for(request, root)),
        contract.auditor_adapter: SimulatedAdapter(contract.auditor_adapter, review=True),
    })
    result = provider.run_once(receipt.run_id, "provider")
    assert result.terminal_state == "handoff_completed"
    assert parent.task(handoff["provider_task_id"]).state == "verified"
    assert parent.task(task.task_id).state == "queued"
    # The previously claimed parent never executed; resuming is safe.
    assert worker(parent, artifact_root).run_once(receipt.run_id, "parent-resumed").terminal_state == "verified"


@pytest.mark.parametrize("state", ["paused", "failed", "completed", "blocked"])
def test_existing_nonactive_run_is_preserved(parent, artifact_root, prompt, state):
    from prompt_ingest import parse_prompt_file
    run_id = parse_prompt_file(prompt).run_id
    parent._repo.register_run(run_id, state)
    before = parent._repo.controller_state(run_id)
    assert submit(parent, artifact_root, prompt).status == "preserved_disabled"
    assert parent._repo.controller_state(run_id) == before


def test_unknown_provider_is_rejected():
    with pytest.raises(HandoffValidationError, match="no_registered"):
        build_handoff_request(run_id="r", parent_task_id="t", parent_attempt_id="a", failure_code="BLOCKED_UNKNOWN", request_artifact_root="handoffs")


def test_same_owner_label_does_not_reclaim_live_attempt(parent, db_url, artifact_root, prompt):
    receipt = submit(parent, artifact_root, prompt)
    task = parent.claim_next(receipt.run_id, "shared-label")
    other = ParentController(db_url, artifact_root=artifact_root, lease_holder=False)
    try:
        assert other.claim_next(receipt.run_id, "shared-label") is None
        assert parent.task(task.task_id).generation == task.generation
    finally:
        other.close()


def test_interrupted_artifact_publication_recovers(parent, artifact_root, prompt, monkeypatch):
    def fail(*args, **kwargs): raise OSError("injected publication interruption")
    with monkeypatch.context() as scoped:
        scoped.setattr("goal_submitter.os.rename", fail)
        with pytest.raises(OSError, match="injected"):
            submit(parent, artifact_root, prompt)
    receipt = submit(parent, artifact_root, prompt)
    assert worker(parent, artifact_root).run_once(receipt.run_id, "recovered").terminal_state == "verified"


def test_submission_waits_for_controller_without_acquiring_lease(parent, db_url, artifact_root, prompt):
    passive = ParentController(db_url, artifact_root=artifact_root, lease_holder=False, adapter_config=route_config())
    try:
        first = submit(passive, artifact_root, prompt)
        assert first.status == "awaiting_controller"
        state = passive._repo.controller_state(first.run_id)
        assert state["owner"] is None and state["current_epoch"] == 0
        parent.register_run(first.run_id)
        second = submit(passive, artifact_root, prompt)
        assert second.status == "existing"
        assert worker(parent, artifact_root).run_once(first.run_id, "simulated").terminal_state == "verified"
    finally:
        passive.close()


def test_database_failure_budget_survives_restarts(tmp_path, monkeypatch):
    import psycopg2
    clock = [1000.0]
    monkeypatch.setattr("worker_health.time.time", lambda: clock[0])
    class Offline:
        calls = 0
        def run_once(self, *args):
            self.calls += 1
            raise psycopg2.OperationalError("sensitive DSN must not be retained")
        def cancel_active(self): pass
    offline = Offline()
    for attempt in range(4):
        health = WorkerHealth(tmp_path / "health")
        loop = WorkerLoop(offline, run_id="disposable", owner="sim", once=True, health=health)
        assert not loop.run()
        clock[0] += 60
    assert offline.calls == 3
    assert health.state("disposable")["blocked"] == 1
    assert health.state("disposable")["failures"] == 3


def test_cli_persistent_block_exit_and_explicit_recovery(tmp_path):
    import subprocess, sys
    health = WorkerHealth(tmp_path / "health")
    health.fail("disposable", reason="permission_or_ownership", permanent=True)
    command = [sys.executable, str(Path(__file__).with_name("worker_cli.py")), "--run-id", "disposable", "--health-dir", str(tmp_path / "health")]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 78
    assert json.loads(result.stdout)["status"] == "blocked"
    recovered = subprocess.run(command + ["--recover-block", "--recovery-reason", "filesystem_repaired"], capture_output=True, text=True)
    assert recovered.returncode == 0
    assert json.loads(recovered.stdout)["execution_started"] is False
    assert health.state("disposable")["blocked"] == 0


@pytest.mark.parametrize("failure", list(PROVIDER_REGISTRY))
def test_invalid_provider_product_cannot_resume_parent(parent, artifact_root, prompt, failure):
    receipt = submit(parent, artifact_root, prompt)
    task = parent.claim_next(receipt.run_id, "parent")
    attempt, fence = parent.resolve_parent_attempt(task.task_id, task.generation)
    contract = PROVIDER_REGISTRY[failure]
    parent.adapter_config = route_config(contract.executor_adapter, contract.auditor_adapter)
    handoff = parent.create_subworkflow_handoff(run_id=receipt.run_id, parent_task_id=task.task_id, parent_attempt_id=attempt, parent_fence_token=fence, failure_code=failure, handoff_context={"prerequisite_node_id": "tiny-prerequisite"})
    request = json.loads((artifact_root / handoff["request_path"]).read_text())
    def forged(root):
        path = product_for(request, root)
        payload = json.loads(path.read_text())
        payload["parent_task_id"] = "forged-parent"
        path.write_text(json.dumps(payload))
    provider = TaskWorker(parent, artifact_root, {
        contract.executor_adapter: SimulatedAdapter(contract.executor_adapter, product=forged),
        contract.auditor_adapter: SimulatedAdapter(contract.auditor_adapter, review=True),
    })
    result = provider.run_once(receipt.run_id, "provider")
    assert result.terminal_state == "blocked"
    assert parent.task(task.task_id).state == "parked"
    assert parent.task(handoff["provider_task_id"]).state == "blocked"
