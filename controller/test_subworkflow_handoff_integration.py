"""Disposable integration tests for subworkflow handoff materialization."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from parent_controller import ParentController
from repository import PostgresRepository
from subworkflow_handoff import build_handoff_request, validate_product
from test_only.recovery_fakes import route_config

RUN_ID = "goal-3eb7b972ec15809e"
PARENT_TASK_ID = "goal-3eb7b972ec15809e-ws-04"
FAILURE_CODE = "BLOCKED_VM9201_DISPOSABLE_SEAM"


@pytest.fixture()
def controller(db_url: str, artifact_root: Path) -> ParentController:
    parent = ParentController(
        db_url,
        controller_owner="ats-del-002-test",
        artifact_root=artifact_root,
        adapter_config=route_config("cursor-cli", "openrouter-claude-auditor"),
    )
    try:
        yield parent
    finally:
        parent.close()


def _valid_product(handoff: dict[str, object], artifact_root: Path) -> Path:
    provider_dir = artifact_root / "provider"
    provider_dir.mkdir(parents=True, exist_ok=True)
    acceptance_path = provider_dir / "acceptance.json"
    rollback_path = provider_dir / "rollback.json"
    acceptance_path.write_text("accepted\n", encoding="utf-8")
    rollback_path.write_text("rollback\n", encoding="utf-8")
    product = {
        "schema_version": "gateway-subworkflow-product.v1",
        "product_contract": "vm9201-disposable-seam.v1",
        "handoff_id": handoff["handoff_id"],
        "parent_run_id": RUN_ID,
        "parent_task_id": PARENT_TASK_ID,
        "provider_run_id": "provider-run-01",
        "disposition": "PASS_VM9201_DISPOSABLE_SEAM",
        "target_identity": {
            "vmid": "9201",
            "endpoint": "192.168.0.96:5432",
            "source": "192.168.0.91",
        },
        "capability": {
            "role_authenticated": True,
            "disposable_harness_readable": True,
            "database_namespace": "td_test_example",
            "credential_ref": "credential-ref-01",
            "capability_sha256": "a" * 64,
        },
        "artifacts": [
            {
                "path": "provider/acceptance.json",
                "sha256": hashlib.sha256(acceptance_path.read_bytes()).hexdigest(),
                "bytes": acceptance_path.stat().st_size,
            }
        ],
        "rollback": {"status": "available", "artifact_path": "provider/rollback.json"},
        "provenance": {"source_sha256": "c" * 64},
        "bounded_error": None,
        "status": "completed",
    }
    product_path = artifact_root / "handoff-product.json"
    product_path.write_text(json.dumps(product), encoding="utf-8")
    validate_product(product_path, handoff, artifact_root)
    return product_path


def test_subworkflow_handoff_materializes_provider_and_resumes_parent_once(
    controller: ParentController,
    artifact_root: Path,
) -> None:
    controller.register_run(RUN_ID)
    controller.schedule_task(RUN_ID, PARENT_TASK_ID, "blocked parent work")
    claimed = controller.claim_next(RUN_ID, "worker")
    assert claimed is not None
    parent_attempt_id, parent_fence = controller.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )

    handoff = controller.create_subworkflow_handoff(
        run_id=RUN_ID,
        parent_task_id=PARENT_TASK_ID,
        parent_attempt_id=parent_attempt_id,
        parent_fence_token=parent_fence,
        failure_code=FAILURE_CODE,
    )
    provider_task_id = str(handoff["provider_task_id"])
    assert handoff.get("created") is True

    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT state, run_id FROM parent_tasks WHERE task_id = %s",
            (provider_task_id,),
        )
        provider_row = cur.fetchone()
        cur.execute(
            "SELECT state FROM parent_tasks WHERE task_id = %s",
            (PARENT_TASK_ID,),
        )
        parent_row = cur.fetchone()
        cur.execute(
            "SELECT state FROM subworkflow_handoffs WHERE handoff_id = %s",
            (str(handoff["handoff_id"]),),
        )
        handoff_row = cur.fetchone()

    assert provider_row["run_id"] == RUN_ID
    assert provider_row["state"] == "queued"
    assert parent_row["state"] == "parked"
    assert handoff_row["state"] == "dispatched"

    provider_claimed = controller.claim_next(RUN_ID, "provider-worker")
    assert provider_claimed is not None
    assert provider_claimed.task_id == provider_task_id
    provider_attempt_id, provider_fence = controller.resolve_parent_attempt(
        provider_claimed.task_id, provider_claimed.generation or ""
    )

    request = build_handoff_request(
        run_id=RUN_ID,
        parent_task_id=PARENT_TASK_ID,
        parent_attempt_id=parent_attempt_id,
        failure_code=FAILURE_CODE,
        request_artifact_root=f"runs/{RUN_ID}/handoffs",
    )
    product_path = _valid_product(request, artifact_root)

    first = controller.complete_subworkflow_handoff(
        run_id=RUN_ID,
        handoff_id=str(handoff["handoff_id"]),
        provider_task_id=provider_task_id,
        provider_attempt_id=provider_attempt_id,
        provider_fence_token=provider_fence,
        product_path=product_path,
    )
    assert first.get("resumed") is True

    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT state FROM parent_tasks WHERE task_id = %s",
            (PARENT_TASK_ID,),
        )
        parent_row = cur.fetchone()
        cur.execute(
            "SELECT state FROM subworkflow_handoffs WHERE handoff_id = %s",
            (str(handoff["handoff_id"]),),
        )
        handoff_row = cur.fetchone()

    assert parent_row["state"] == "queued"
    assert handoff_row["state"] == "completed"

    second = controller.complete_subworkflow_handoff(
        run_id=RUN_ID,
        handoff_id=str(handoff["handoff_id"]),
        provider_task_id=provider_task_id,
        provider_attempt_id=provider_attempt_id,
        provider_fence_token=provider_fence,
        product_path=product_path,
    )
    assert second.get("resumed") is False
