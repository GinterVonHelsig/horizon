"""Disposable integration tests for Horizon prerequisite orchestration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from parent_controller import ParentController
from program_ingest import parse_program_file, project_node_reference
from project_ledger import ProjectLedgerService

FIXTURE = Path(__file__).resolve().parent / "tests" / "fixtures" / "master-program-v1.json"
BASELINE = Path(
    "/opt/operator-harness/artifacts/20260909T-gateway-horizon-v1-program-baseline/master-program-v1.json"
)
RUN_ID = "goal-3eb7b972ec15809e"
PARENT_TASK_ID = "goal-3eb7b972ec15809e-ws-prereq-demo"
TARGET_NODE = "ATS-PMO-002-DEMO"
PREREQ_NODE = "ATS-PMO-002-PREFLIGHT"


@pytest.fixture()
def controller(db_url: str, artifact_root: Path) -> ParentController:
    parent = ParentController(
        db_url,
        controller_owner="horizon-prereq-test",
        artifact_root=artifact_root,
    )
    try:
        yield parent
    finally:
        parent.close()


def test_demo_fixture_nodes_absent_from_production_baseline() -> None:
    baseline = json.loads(BASELINE.read_bytes())
    fixture = json.loads(FIXTURE.read_bytes())
    baseline_ids = {node["node_id"] for node in baseline["nodes"]}
    fixture_ids = {node["node_id"] for node in fixture["nodes"]}
    assert "ATS-PMO-002-PREFLIGHT" in fixture_ids
    assert "ATS-PMO-002-DEMO" in fixture_ids
    assert "ATS-PMO-002-PREFLIGHT" not in baseline_ids
    assert "ATS-PMO-002-DEMO" not in baseline_ids


def test_prerequisite_orchestration_detects_delivers_and_is_idempotent(
    controller: ParentController,
) -> None:
    parsed = parse_program_file(FIXTURE)
    target = project_node_reference(parsed, TARGET_NODE)
    ProjectLedgerService(controller._repo).ingest_program_file(str(FIXTURE))

    missing = controller.detect_missing_prerequisites(
        project_id=parsed.project_id,
        project_version=parsed.project_version,
        node_id=TARGET_NODE,
        satisfied_nodes=[],
    )
    assert missing == [PREREQ_NODE]

    controller.register_run(RUN_ID)
    controller.schedule_task(RUN_ID, PARENT_TASK_ID, "demo prerequisite orchestration")
    claimed = controller.claim_next(RUN_ID, "worker")
    assert claimed is not None
    parent_attempt_id, parent_fence = controller.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )

    artifact_digest = hashlib.sha256(b"demo-preflight-artifact").hexdigest()
    first = controller.deliver_prerequisite_subworkflow(
        run_id=RUN_ID,
        parent_task_id=PARENT_TASK_ID,
        parent_attempt_id=parent_attempt_id,
        parent_fence_token=parent_fence,
        project_id=parsed.project_id,
        project_version=parsed.project_version,
        target_node_id=TARGET_NODE,
        prerequisite_node_id=PREREQ_NODE,
        reason="prerequisite listed in demo fixture dependency graph",
        artifact_digest=artifact_digest,
    )
    assert first["created"] is True
    decision = first["decision"]
    assert decision["reused"] is False
    assert decision["delivered_by"]
    assert decision["reason"] == "prerequisite listed in demo fixture dependency graph"
    assert decision["artifact_digest"] == artifact_digest
    handoff = first["handoff"]
    assert handoff is not None
    provider_task_id = str(handoff["provider_task_id"])

    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT COUNT(*) AS count FROM subworkflow_handoffs WHERE run_id = %s",
            (RUN_ID,),
        )
        handoff_count = int(cur.fetchone()["count"])
        cur.execute(
            "SELECT COUNT(*) AS count FROM parent_tasks WHERE run_id = %s AND task_id = %s",
            (RUN_ID, provider_task_id),
        )
        provider_count = int(cur.fetchone()["count"])

    assert handoff_count == 1
    assert provider_count == 1

    second = controller.deliver_prerequisite_subworkflow(
        run_id=RUN_ID,
        parent_task_id=PARENT_TASK_ID,
        parent_attempt_id=parent_attempt_id,
        parent_fence_token=parent_fence,
        project_id=parsed.project_id,
        project_version=parsed.project_version,
        target_node_id=TARGET_NODE,
        prerequisite_node_id=PREREQ_NODE,
        reason="prerequisite listed in demo fixture dependency graph",
        artifact_digest=artifact_digest,
    )
    assert second["created"] is False
    assert second["decision"]["decision_id"] == decision["decision_id"]

    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT COUNT(*) AS count FROM subworkflow_handoffs WHERE run_id = %s",
            (RUN_ID,),
        )
        assert int(cur.fetchone()["count"]) == 1

    satisfied = controller.detect_missing_prerequisites(
        project_id=parsed.project_id,
        project_version=parsed.project_version,
        node_id=TARGET_NODE,
        satisfied_nodes=[PREREQ_NODE],
    )
    assert satisfied == []
    assert target.acceptance_criteria_version.startswith("horizon-v1-contract")
