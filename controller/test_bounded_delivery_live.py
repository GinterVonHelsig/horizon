"""Opt-in included-subscription proof. Never part of unattended CI/model retries."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from bounded_delivery import write_once
from harness_adapters.registry import AdapterRegistry
from parent_controller import ParentController
from subworkflow_handoff import digest_value, validate_product
from worker import TaskWorker, WorkerLoop

pytestmark = pytest.mark.skipif(
    os.environ.get("HORIZON_CURSOR_INCLUDED_ONLY_CONFIRMED") != "operator-confirmed-on-demand-disabled",
    reason="requires explicit included-only Cursor authorization and disposable namespace launcher",
)


def test_live_disposable_provider(db_url):
    evidence = Path(os.environ["HORIZON_PROVIDER_LIVE_EVIDENCE"])
    assert evidence.is_absolute() and "artifacts" in evidence.parts
    assert Path("/run/horizon-cursor-host-network").exists()
    # The persistent marker prevents any automatic rerun after ambiguous output.
    write_once(evidence / "live-invocation-started.json", b'{"calls_authorized":2,"automatic_retries":0}\n')
    root = evidence / "runtime"
    root.mkdir(mode=0o700)
    repo = Path(__file__).resolve().parents[1]
    config = json.loads((repo / "systemd/adapters.gateway-delivery-disposable.json.example").read_text())
    for raw in config["adapters"]:
        raw["executable"] = os.environ["HORIZON_PROVIDER_CURSOR_EXECUTABLE"]
        raw["allowed_cwd_roots"] = [str(root)]
    spec = config["adapters"][0]["delivery_spec"]
    # No background production controller: this isolated lease covers the
    # profile's hard 600-second total call budget plus deterministic finalization.
    parent = ParentController(db_url, artifact_root=root, adapter_config=config,
                              controller_lease_seconds=660, stale_after=660)
    result = None
    try:
        parent.register_run("included-cursor-disposable")
        parent.schedule_task("included-cursor-disposable", "parent", "Create one disposable file and independently review it")
        claim = parent.claim_next("included-cursor-disposable", "direct-codex-test")
        attempt, fence = parent.resolve_parent_attempt(claim.task_id, claim.generation)
        handoff = parent.create_subworkflow_handoff(
            run_id=claim.run_id, parent_task_id=claim.task_id, parent_attempt_id=attempt, parent_fence_token=fence,
            failure_code="BLOCKED_HORIZON_PREREQ_MISSING", handoff_context={
                "delivery_profile": spec["profile"], "delivery_spec_digest": digest_value(spec),
                "prerequisite_node_id": spec["prerequisite_id"]},
        )
        registry = AdapterRegistry.from_config(config, artifact_dir=root / "registry")
        worker = TaskWorker(parent, root, registry.adapters, adapter_config=config)
        loop = WorkerLoop(worker, run_id=claim.run_id, owner="direct-codex-live-proof", once=True,
                          expected_task_id=handoff["provider_task_id"])
        success = loop.run()
        result = {"profile": spec["profile"], "simulated": False, "included_subscription": True,
                  "operator_confirmed_on_demand_disabled": True, "automatic_retries": 0,
                  "status": loop.last_status, "durable_state": parent.task(handoff["provider_task_id"]).state,
                  "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
                  "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repo))}
        write_once(evidence / "live-result.json", json.dumps(result, indent=2).encode())
        assert success and loop.last_status == "handoff_completed"
        product = next(root.rglob("handoff-product.json"))
        request = json.loads((root / handoff["request_path"]).read_text())
        assert validate_product(product, request, root)
        assert parent.task(handoff["provider_task_id"]).state == "verified"
    finally:
        parent.close()
