"""Bounded Gateway Delivery profile; orchestration stays in Horizon's worker.

One fresh disposable file, one implementation call, one independent review.
This is not a release engine or Comms Relay submission adapter.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import time

from harness_adapters.contract import HarnessRequest, HarnessResult
from harness_adapters.identity import adapter_effective_identity, config_effective_identity, identities_conflict
from harness_adapters.redaction import contains_credential
from subworkflow_handoff import (
    DISPOSABLE_DELIVERY_PROFILE, DISPOSABLE_FILE_CONTRACT, canonical_json,
    digest_value, validate_request, validate_product,
    DELIVERY_CONTRACTS, SOURCE_TEST_PROFILE, SOURCE_TEST_CONTRACT,
)


def validate_spec(spec):
    if isinstance(spec,dict) and spec.get("profile")==SOURCE_TEST_PROFILE:
        from source_test_recipe import validate_spec as validate_source_spec
        return validate_source_spec(spec)
    if not isinstance(spec, dict) or set(spec) != {"profile", "prerequisite_id", "filename", "content"}:
        raise ValueError("delivery specification keys invalid")
    if spec["profile"] != DISPOSABLE_DELIVERY_PROFILE:
        raise ValueError("unsupported delivery profile")
    if not isinstance(spec["prerequisite_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", spec["prerequisite_id"]):
        raise ValueError("invalid prerequisite identity")
    if not isinstance(spec["filename"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,60}\.txt", spec["filename"]):
        raise ValueError("profile permits one plain text filename only")
    if spec["filename"] == "rollback.txt":
        raise ValueError("delivery filename is reserved for provider evidence")
    if not isinstance(spec["content"], str) or not 1 <= len(spec["content"].encode()) <= 1024 or contains_credential(spec):
        raise ValueError("delivery content must be small and non-sensitive")
    return spec


def acceptance_for_spec(spec, digest):
    return [
        ("Bounded source recipe tests verified for specification " if spec==SOURCE_TEST_PROFILE else "Exact disposable file content verified for specification ")+digest,
        "Disposable workspace contains only the authorized deliverable",
    ]


def validate_binding(config, request):
    """Reject unsupported capabilities/spec/identities before child scheduling."""
    from harness_adapters.registry import validate_task_routes
    from model_routing import authorize_delivery_review, load_model_routing
    validate_request(request)
    validate_task_routes(config, request["executor_adapter"], request["auditor_adapter"])
    by_id = {a["id"]: a for a in config["adapters"]}
    author, reviewer = by_id[request["executor_adapter"]], by_id[request["auditor_adapter"]]
    if author["kind"] != "gateway_delivery":
        raise ValueError("delivery profile requires bounded provider capability")
    spec = validate_spec(author["delivery_spec"])
    context = request["handoff_context"]
    if context["delivery_spec_digest"] != digest_value(spec) or context["prerequisite_node_id"] != spec["prerequisite_id"]:
        raise ValueError("configured delivery specification mismatch")
    authorize_delivery_review(load_model_routing(Path(__file__).resolve().parents[1] / "architecture/model-routing.yaml"),
                              config_effective_identity(author), config_effective_identity(reviewer), profile=spec["profile"])


def write_once(path: Path, data: bytes):
    """Durable exclusive publication; never overwrite earlier execution evidence."""
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("delivery evidence symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def bound_delivery_verdict(payload, acceptance, evidence):
    """Independent observations must cite deliverable bytes, not questions."""
    from auditor_bind import AUDITOR_SCHEMA
    from harness_adapters.schema import validate_json_schema
    try:
        validate_json_schema(payload, AUDITOR_SCHEMA)
        if payload["verdict"] == "reject":
            return "reject"
        criteria = payload["criteria"]
        if len(criteria) != len(acceptance) or sorted(c["criterion"] for c in criteria) != sorted(acceptance):
            return None
        for criterion in criteria:
            if criterion["met"] is not True or not all(
                ref["name"] == "deliverable" and ref["sha256"] == evidence["sha256"]
                for ref in criterion["evidence_refs"]
            ):
                return None
        return "approve"
    except (ValueError, KeyError, TypeError):
        return None


class BoundedDeliveryAdapter:
    """Implementation adapter plus worker-called post-review publication gate.

    The wrapper reports its real inner author identity. No fictional coordinator
    identity can hide the model that authored the deliverable from selection.
    """
    kind = "gateway_delivery"

    def __init__(self, executor, spec):
        self.executor = executor
        self.spec = json.loads(json.dumps(validate_spec(spec)))
        self.adapter_id = executor.adapter_id
        self.provider, self.model = executor.provider, executor.model
        self._started = None
        self._budget = 0.0
        self._cancelled = False

    def cancel(self):
        self._cancelled = True
        self.executor.cancel()

    def resume(self, request, session_id):
        raise ValueError("delivery resume requires durable outcome reconciliation; no replay")

    def _request(self, request):
        handoff = request.metadata.get("handoff_request")
        if not isinstance(handoff, dict) or validate_request(handoff) != DELIVERY_CONTRACTS[self.spec["profile"]]:
            raise ValueError("bounded delivery requires Horizon handoff")
        context = handoff.get("handoff_context", {})
        if (context.get("delivery_profile") != self.spec["profile"]
                or context.get("delivery_spec_digest") != digest_value(self.spec)
                or context.get("prerequisite_node_id") != self.spec["prerequisite_id"]
                or request.run_id != handoff["run_id"] or request.task_id != handoff["provider_task_id"]):
            raise ValueError("delivery specification or parent binding mismatch")
        return handoff

    def _check_file(self, cwd):
        root = Path(cwd)
        path = root / self.spec["filename"]
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("delivery file missing or aliased")
        if self.spec["profile"]==SOURCE_TEST_PROFILE:
            if path.stat().st_size>4096:
                raise ValueError("source recipe size exceeded")
            from source_test_recipe import test_source
            test_source(path.read_text(),self.spec)
        elif path.stat().st_size > 1024 or path.read_bytes() != self.spec["content"].encode():
            raise ValueError("delivery file failed exact-content acceptance")
        return path

    def remaining_seconds(self):
        if self._cancelled:
            raise ValueError("delivery cancelled; reconciliation required")
        if self._started is None:
            raise ValueError("delivery did not start")
        remaining = self._budget - (time.monotonic() - self._started)
        if remaining <= 0:
            raise ValueError("delivery time budget exhausted")
        return remaining

    def execute(self, request: HarnessRequest) -> HarnessResult:
        handoff = self._request(request)
        root = Path(request.cwd)
        if any(p.is_symlink() for p in (root, *root.parents)) or list(root.iterdir()):
            raise ValueError("delivery requires fresh empty workspace")
        self._started = time.monotonic()
        self._budget = min(600.0, request.timeout)
        role = Path(request.artifact_dir)
        write_once(role / "delivery-intent.json", canonical_json({
            "profile": self.spec["profile"], "request_digest": handoff["request_digest"],
            "spec_digest": digest_value(self.spec), "attempt_id": request.attempt_id,
            "max_model_calls": 2, "automatic_retries": 0,
        }))
        prompt = ("Create exactly one UTF-8 file in this disposable workspace. Do not run shell commands, "
                  "read other paths, use network tools, create other files, or invoke controllers. "
                  "Use the file edit tool only. No retries or remediation. Do not self-review.\n"
                  + json.dumps(self.spec)
                  + '\nThen return a JSON object {"disposition":"IMPLEMENTED"}.')
        result = self.executor.execute(replace(request, prompt=prompt, timeout=min(request.timeout, self.remaining_seconds())))
        if (result.adapter_id != self.adapter_id or config_effective_identity({"provider": result.provider, "model": result.model})
                != adapter_effective_identity(self.executor)):
            raise ValueError("delivery executor identity mismatch")
        if result.status != "success" or result.exit_code != 0 or result.error_classification:
            return replace(result, retryable=False)
        source = self._check_file(root)
        if set(p.name for p in root.iterdir()) != {self.spec["filename"]}:
            raise ValueError("delivery mutated unexpected workspace paths")
        self.remaining_seconds()
        # Deterministic acceptance evidence is the reviewer input, not a model's
        # assertion that tests passed. Retain inner stdout/stderr separately.
        report = {
            "profile": self.spec["profile"], "request_digest": handoff["request_digest"],
            "spec_digest": digest_value(self.spec), "filename": source.name,
            "content": source.read_text(), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "acceptance_criteria": request.metadata["acceptance_criteria"],
            "exact_content_verified": self.spec["profile"]==DISPOSABLE_DELIVERY_PROFILE,
            "author": {"provider": result.provider, "model": result.model},
            "implementation_stdout_sha256": result.stdout_sha256,
        }
        if self.spec["profile"]==SOURCE_TEST_PROFILE:
            from source_test_recipe import test_source
            report["recipe_result"]=test_source(source.read_text(),self.spec)
        raw = canonical_json(report)
        write_once(role / "delivery-acceptance.json", raw)
        return replace(result, kind=self.kind, stdout_artifact_path="delivery-acceptance.json",
                       stdout_sha256=hashlib.sha256(raw).hexdigest(), structured_payload=report,
                       retryable=False)

    start = execute

    def review_evidence(self, cwd):
        source = self._check_file(cwd)
        return {"name": "deliverable", "filename": source.name,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "observed_content": source.read_text(), "expected_content": self.spec.get("content"),
                "specification":self.spec,
                "spec_digest": digest_value(self.spec), "profile": self.spec["profile"]}

    def finalize_delivery(self, request, execution, review, routing_record):
        """Called only after worker's evidence-bound verdict gate approves."""
        handoff = self._request(request)
        self.remaining_seconds()
        if review.status != "success" or review.exit_code != 0 or review.error_classification:
            raise ValueError("passing review required")
        if bound_delivery_verdict(review.structured_payload, request.metadata["acceptance_criteria"], self.review_evidence(request.cwd)) != "approve":
            raise ValueError("passing prior-review verdict required")
        if not routing_record or identities_conflict(
            (self.provider, self.model), (review.provider, review.model)
        ):
            raise ValueError("eligible independent reviewer required")
        root = Path(request.cwd)
        source = self._check_file(root)
        if set(p.name for p in root.iterdir()) != {self.spec["filename"]}:
            raise ValueError("read-only review changed workspace")
        report_path = Path(request.artifact_dir) / "delivery-acceptance.json"
        report_bytes = report_path.read_bytes()
        if hashlib.sha256(report_bytes).hexdigest() != execution.stdout_sha256:
            raise ValueError("reviewed acceptance evidence changed")
        report = json.loads(report_bytes)
        if report["source_sha256"] != hashlib.sha256(source.read_bytes()).hexdigest():
            raise ValueError("reviewed source changed")
        write_once(root / "acceptance.json", report_bytes)
        history = {"profile": self.spec["profile"], "request_digest": handoff["request_digest"],
                   "spec_digest": digest_value(self.spec), "author": report["author"],
                   "review": {**routing_record, "verdict": "approve", "adapter_id": review.adapter_id,
                              "stdout_sha256": review.stdout_sha256, "result": review.structured_payload},
                   "sequence": ["scope-validated", "implementation", "exact-file-acceptance", "independent-review"],
                   "production_release": "not-authorized", "automatic_retries": 0,
                   "billing_attestation": {"source": "operator-confirmed-account-setting", "on_demand_disabled": True,
                                           "programmatically_verified": False, "transport": "cursor-subscription"}}
        write_once(root / "delivery-receipt.json", canonical_json(history))
        write_once(root / "rollback.txt", b"Discard this disposable attempt workspace; no deployed changes.\n")
        artifacts = [{"path": p.name, "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in (source, root / "acceptance.json", root / "delivery-receipt.json", root / "rollback.txt")]
        product = {
            "schema_version": "gateway-subworkflow-product.v1", "product_contract": handoff["product_contract"],
            "handoff_id": handoff["handoff_id"], "parent_run_id": handoff["run_id"],
            "parent_task_id": handoff["parent_task_id"], "provider_run_id": handoff["run_id"],
            "disposition": DELIVERY_CONTRACTS[self.spec["profile"]].success_disposition,
            "target_identity": {"repository": "GinterVonHelsig/horizon", "scope": "isolated-worktree"},
            "capability": {"prerequisite_id": self.spec["prerequisite_id"], "exact_file_verified": True,
                           "general_test_suite_run": False, "validation_kind": "exact-content-comparison",
                           "capability_sha256": artifacts[0]["sha256"]},
            "provenance": {"source_sha256": artifacts[0]["sha256"], "request_digest": handoff["request_digest"],
                           "allowed_mutations_digest": handoff["allowed_mutations_digest"],
                           "forbidden_mutations_digest": handoff["forbidden_mutations_digest"]},
            "artifacts": artifacts, "rollback": {"status": "available", "artifact_path": "rollback.txt"},
            "bounded_error": None, "status": "completed",
        }
        if self.spec["profile"]==SOURCE_TEST_PROFILE:
            product["capability"]={"prerequisite_id":self.spec["prerequisite_id"],"recipe_tests_passed":True,
                "general_test_suite_run":False,"validation_kind":self.spec["recipe"],"capability_sha256":artifacts[0]["sha256"]}
        path = root / "handoff-product.json"
        write_once(path, canonical_json(product))
        validate_product(path, handoff, root)
        return path
