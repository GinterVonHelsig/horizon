"""Deterministic SIMULATED model execution; never a live Gateway implementation."""
import hashlib
import json
from pathlib import Path

from harness_adapters.contract import HarnessResult


def route_config(executor="simulated-writer", auditor="simulated-reviewer"):
    return {
        "routes": {"default_executor": executor, "default_auditor": auditor},
        "adapters": [
            {"id": executor, "kind": "cursor_cli", "provider": "simulation", "model": "writer",
             "executable": "/usr/bin/false", "approval_mode": "never", "credential_env": [],
             "timeout_seconds": 30, "allowed_cwd_roots": ["/tmp"]},
            {"id": auditor, "kind": "http_openai", "provider": "simulation", "model": "reviewer",
             "endpoint": "http://127.0.0.1:1/v1/chat/completions", "credential_env": ["SIMULATED_KEY"],
             "timeout_seconds": 30, "allowed_cwd_roots": ["/tmp"]},
        ],
    }


class SimulatedAdapter:
    provider = "simulation"

    def __init__(self, adapter_id, *, review=False, reject=False, product=None, kill=False):
        self.adapter_id = adapter_id
        self.model = "reviewer" if review else "writer"
        self.review, self.reject, self.product, self.kill = review, reject, product, kill
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        role = Path(request.artifact_dir)
        role.mkdir(parents=True, exist_ok=True)
        if self.review:
            evidence = request.metadata["executor_evidence"]
            assert evidence["artifacts"]
            assert evidence["model"] != self.model
            payload = {"verdict": "reject" if self.reject else "approve", "criteria": [
                {"criterion": criterion, "met": not self.reject, "rationale": "simulated independent evidence review",
                 "evidence_refs": [{"name": item["stream"], "sha256": item["sha256"]} for item in evidence["artifacts"]]}
                for criterion in request.metadata["acceptance_criteria"]]}
        else:
            effect = Path(request.cwd) / "tiny-result.txt"
            with effect.open("x") as stream:
                stream.write("simulated disposable result\n")
            if self.product:
                self.product(Path(request.cwd))
            if self.kill:
                import os, signal
                os.kill(os.getpid(), signal.SIGKILL)
            payload = {"disposition": "PASS_RECOVERY"}
        output = role / "stdout.json"
        output.write_text(json.dumps(payload) + "\n" + "\n".join(request.metadata.get("acceptance_criteria", [])))
        return HarnessResult(
            self.adapter_id, "simulated", self.model, self.provider, "success", 0, 0.01,
            "stdout.json", hashlib.sha256(output.read_bytes()).hexdigest(), None, None,
            payload, None, False,
        )

    start = execute
    def cancel(self):
        pass


def product_for(request, root):
    from subworkflow_handoff import HORIZON_PREREQ_CONTRACT, validate_request
    contract = validate_request(request)
    root.mkdir(parents=True, exist_ok=True)
    artifacts = []
    for name, text in (("source.txt", "simulated implementation"), ("acceptance.txt", "simulated tests pass"), ("rollback.txt", "discard disposable directory")):
        path = root / name
        path.write_text(text)
        artifacts.append({"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size})
    horizon = contract == HORIZON_PREREQ_CONTRACT
    product = {
        "schema_version": "gateway-subworkflow-product.v1", "product_contract": contract.product_contract,
        "handoff_id": request["handoff_id"], "parent_run_id": request["run_id"],
        "parent_task_id": request["parent_task_id"], "provider_run_id": request["run_id"],
        "disposition": contract.success_disposition,
        "target_identity": {"repository": "GinterVonHelsig/horizon", "scope": "isolated-worktree"} if horizon else {"vmid": "9201", "endpoint": "192.168.0.96:5432", "source": "192.168.0.91"},
        "capability": {"prerequisite_id": "tiny-prerequisite", "implementation_verified": True, "disposable_tests_passed": True, "capability_sha256": artifacts[1]["sha256"]} if horizon else {"role_authenticated": True, "disposable_harness_readable": True, "database_namespace": "td_test_simulated", "credential_ref": "simulated-reference", "capability_sha256": artifacts[1]["sha256"]},
        "provenance": {"source_sha256": artifacts[0]["sha256"], "request_digest": request["request_digest"], "allowed_mutations_digest": contract.allowed_mutations_digest, "forbidden_mutations_digest": contract.forbidden_mutations_digest},
        "artifacts": artifacts, "rollback": {"status": "available", "artifact_path": "rollback.txt"},
        "bounded_error": None, "status": "completed",
    }
    path = root / "handoff-product.json"
    path.write_text(json.dumps(product))
    return path
