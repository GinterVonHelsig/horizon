"""Real provider + PostgreSQL + Horizon worker, SIMULATED Cursor model calls."""
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import time

import pytest

from bounded_delivery import BoundedDeliveryAdapter, validate_spec
from harness_adapters.contract import HarnessResult
from harness_adapters.registry import AdapterRegistry, validate_task_routes
from parent_controller import ParentController
from subworkflow_handoff import build_handoff_request, digest_value, validate_product, validate_request
from worker import TaskWorker, WorkerLoop

TEMPLATE = Path(__file__).resolve().parents[1] / "systemd/adapters.gateway-delivery-disposable.json.example"


def configuration():
    return json.loads(TEMPLATE.read_text())


class SimulatedCursor:
    provider = "cursor"
    kind = "cursor_cli"
    def __init__(self, adapter_id, model, spec, *, review=False, reject=False, fault=None):
        self.adapter_id, self.model, self.spec = adapter_id, model, spec
        self.review, self.reject, self.fault = review, reject, fault
        self.calls = 0
    def cancel(self): pass
    def execute(self, request):
        self.calls += 1
        root, role = Path(request.cwd), Path(request.artifact_dir)
        role.mkdir(parents=True, exist_ok=True)
        if self.review:
            assert request.metadata["executor_evidence"]["model"] != self.model
            payload = {"verdict": "reject" if self.reject else "approve", "criteria": [
                {"criterion": c, "met": not self.reject, "rationale": "simulated independent review",
                 "evidence_refs": [{"name": a["stream"], "sha256": a["sha256"]} for a in request.metadata["executor_evidence"]["artifacts"]]}
                for c in request.metadata["acceptance_criteria"]]}
            if self.fault == "mutate":
                (root / self.spec["filename"]).write_text("tampered")
            if self.fault == "malformed":
                payload = {"verdict": "approve"}
        else:
            with (root / self.spec["filename"]).open("x") as stream:
                stream.write(self.spec["content"] if self.fault != "wrong" else "wrong")
            payload = {"disposition": "IMPLEMENTED"}
            if self.fault == "lost":
                raise OSError("simulated unknown outcome after file effect")
            if self.fault == "kill":
                os.kill(os.getpid(), signal.SIGKILL)
        output = role / "stdout.txt"
        output.write_text(json.dumps(payload))
        return HarnessResult(self.adapter_id, self.kind, self.model, self.provider, "success", 0, 0.01,
                             output.name, hashlib.sha256(output.read_bytes()).hexdigest(), None, None, payload, None, False)


@pytest.fixture
def scenario(db_url, artifact_root):
    config = configuration()
    parent = ParentController(db_url, artifact_root=artifact_root, adapter_config=config)
    parent.register_run("disposable-provider")
    parent.schedule_task("disposable-provider", "parent", "disposable prerequisite")
    claim = parent.claim_next("disposable-provider", "submitter")
    attempt, fence = parent.resolve_parent_attempt(claim.task_id, claim.generation)
    spec = config["adapters"][0]["delivery_spec"]
    handoff = parent.create_subworkflow_handoff(
        run_id=claim.run_id, parent_task_id=claim.task_id, parent_attempt_id=attempt,
        parent_fence_token=fence, failure_code="BLOCKED_HORIZON_PREREQ_MISSING",
        handoff_context={"delivery_profile": spec["profile"], "delivery_spec_digest": digest_value(spec),
                         "prerequisite_node_id": spec["prerequisite_id"]},
    )
    yield parent, config, spec, handoff
    parent.close()


def make_worker(scenario, root, *, reject=False, writer_fault=None, reviewer_fault=None):
    parent, config, spec, handoff = scenario
    author = SimulatedCursor("gateway-delivery", "composer-2.5", spec, fault=writer_fault)
    review = SimulatedCursor("cursor-independent-review", "cursor-grok-4.6-high", spec, review=True, reject=reject, fault=reviewer_fault)
    provider = BoundedDeliveryAdapter(author, spec)
    worker = TaskWorker(parent, root, {provider.adapter_id: provider, review.adapter_id: review}, adapter_config=config)
    # Simulated catalog, real admission and author-aware selection.
    worker._preflight_adapters = lambda: None
    return worker, author, review


def test_disposable_delivery_and_bound_history(scenario, artifact_root):
    parent, config, spec, handoff = scenario
    worker, author, reviewer = make_worker(scenario, artifact_root)
    loop = WorkerLoop(worker, run_id="disposable-provider", owner="simulated", once=True,
                      expected_task_id=handoff["provider_task_id"])
    assert loop.run() and loop.last_status == "handoff_completed"
    assert parent.task(handoff["provider_task_id"]).state == "verified"
    assert author.calls == reviewer.calls == 1
    product = next(artifact_root.rglob("handoff-product.json"))
    request = json.loads((artifact_root / handoff["request_path"]).read_text())
    assert validate_product(product, request, artifact_root)["disposition"] == request["required_disposition"]
    history = json.loads((product.parent / "delivery-receipt.json").read_text())
    assert history["review"]["verdict"] == "approve"
    assert history["review"]["provider"] == "cursor"
    assert history["review"]["model"] == "cursor-grok-4.6-high"
    assert history["author"]["model"] == "composer-2.5"
    assert history["request_digest"] == request["request_digest"]
    assert history["automatic_retries"] == 0


@pytest.mark.parametrize("reject,writer_fault,reviewer_fault", [
    (True, None, None), (False, "wrong", None), (False, "lost", None),
    (False, None, "mutate"), (False, None, "malformed"),
])
def test_terminal_failure_never_publishes_or_replays(scenario, artifact_root, reject, writer_fault, reviewer_fault):
    parent, _, _, handoff = scenario
    worker, author, reviewer = make_worker(scenario, artifact_root, reject=reject, writer_fault=writer_fault, reviewer_fault=reviewer_fault)
    result = worker.run_once("disposable-provider", "simulated", expected_task_id=handoff["provider_task_id"])
    assert result.terminal_state.startswith("blocked")
    assert parent.task(handoff["provider_task_id"]).state == "blocked"
    assert not list(artifact_root.rglob("handoff-product.json"))
    restarted, new_author, new_review = make_worker(scenario, artifact_root)
    assert restarted.run_once("disposable-provider", "restart") is None
    assert new_author.calls == new_review.calls == 0
    assert author.calls == 1 and reviewer.calls <= 1


def test_author_collision_stops_before_execution(scenario, artifact_root):
    worker, author, reviewer = make_worker(scenario, artifact_root)
    reviewer.model = author.model
    result = worker.run_once("disposable-provider", "simulated")
    assert result.terminal_state.startswith("blocked")
    assert author.calls == reviewer.calls == 0


def test_spec_digest_mismatch_stops_before_model(scenario, artifact_root):
    worker, author, reviewer = make_worker(scenario, artifact_root)
    worker._adapters["gateway-delivery"].spec["content"] = "changed"
    result = worker.run_once("disposable-provider", "simulated")
    assert result.terminal_state.startswith("blocked")
    assert author.calls == reviewer.calls == 0


def test_profile_routes_are_explicit_and_legacy_unchanged():
    config = configuration()
    validate_task_routes(config, "gateway-delivery", "cursor-independent-review")
    registry = AdapterRegistry.from_config(config, artifact_dir=Path("/tmp/not-executed"), validate_executables=False)
    assert isinstance(registry.get("gateway-delivery"), BoundedDeliveryAdapter)
    assert registry.get("cursor-independent-review").cursor_mode == "ask"
    args = registry.get("cursor-independent-review")._build_argv("review")
    assert "ask" in args and "--force" not in args
    legacy = build_handoff_request(run_id="r", parent_task_id="t", parent_attempt_id="a",
                                  failure_code="BLOCKED_HORIZON_PREREQ_MISSING", request_artifact_root="handoffs")
    assert legacy["auditor_adapter"] == "openrouter-independent-review"
    validate_request(legacy)
    config["adapters"][1]["id"] = "openrouter-independent-review"
    with pytest.raises(ValueError, match="read-only cursor"):
        validate_task_routes(config, "gateway-delivery", "openrouter-independent-review")


@pytest.mark.parametrize("field,value", [("filename", "../escape.txt"), ("profile", "full-release"), ("content", "")])
def test_unsupported_spec_is_rejected(field, value):
    spec = configuration()["adapters"][0]["delivery_spec"]
    spec[field] = value
    with pytest.raises(ValueError): validate_spec(spec)


def _killed_provider(db_url, root, handoff, after_effect):
    from test_only.disposable_harness import enable_disposable_harness
    enable_disposable_harness()
    config = configuration()
    parent = ParentController(db_url, artifact_root=root, adapter_config=config, lease_holder=False, stale_after=2)
    if after_effect:
        worker, _, _ = make_worker((parent, config, config["adapters"][0]["delivery_spec"], handoff), root, writer_fault="kill")
        worker.run_once("disposable-provider", "killed")
    else:
        assert parent.claim_next("disposable-provider", "killed") is not None
        os.kill(os.getpid(), signal.SIGKILL)


@pytest.mark.parametrize("after_effect", [False, True])
def test_killed_provider_fencing_and_bounded_recovery(scenario, artifact_root, db_url, after_effect):
    parent, _, _, handoff = scenario
    proc = multiprocessing.get_context("spawn").Process(target=_killed_provider, args=(db_url, artifact_root, handoff, after_effect))
    proc.start()
    proc.join(10)
    assert proc.exitcode == -signal.SIGKILL
    assert parent.claim_next("disposable-provider", "competitor") is None
    time.sleep(2.05)
    worker, author, reviewer = make_worker(scenario, artifact_root)
    result = worker.run_once("disposable-provider", "recovery")
    assert result.terminal_state == ("blocked:execution_outcome_requires_review" if after_effect else "handoff_completed")
    assert author.calls == reviewer.calls == (0 if after_effect else 1)
    assert len(list(artifact_root.rglob("hello.txt"))) == 1


def test_paused_provider_does_not_execute(scenario, artifact_root):
    parent, _, _, _ = scenario
    parent.persist_goal_state("disposable-provider", "WAITING_OPERATOR")
    worker, author, review = make_worker(scenario, artifact_root)
    assert worker.run_once("disposable-provider", "paused") is None
    assert parent._repo.controller_state("disposable-provider")["scheduling_enabled"] is False
    assert author.calls == review.calls == 0


def test_bounded_profile_has_two_claims_one_execution_and_unknown_profiles_fail():
    spec = configuration()["adapters"][0]["delivery_spec"]
    args = dict(run_id="r", parent_task_id="t", parent_attempt_id="a", failure_code="BLOCKED_HORIZON_PREREQ_MISSING", request_artifact_root="handoffs")
    context = {"delivery_profile": spec["profile"], "delivery_spec_digest": digest_value(spec), "prerequisite_node_id": spec["prerequisite_id"]}
    request = build_handoff_request(**args, handoff_context=context)
    assert request["max_attempts"] == 2 and request["timeout_seconds"] == 600
    validate_request(request)
    with pytest.raises(ValueError, match="unsupported_delivery_profile"):
        build_handoff_request(**args, handoff_context={**context, "delivery_profile": "unknown"})
