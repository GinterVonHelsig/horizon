from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from subworkflow_handoff import (
    HandoffValidationError,
    build_handoff_request,
    detect_capability_failure,
    validate_product,
)


RUN_ID = "goal-test-subworkflow-handoff"
TASK_ID = "goal-test-subworkflow-handoff-ws-04"


def request(attempt_id: str = "attempt-one") -> dict[str, object]:
    return build_handoff_request(
        run_id=RUN_ID,
        parent_task_id=TASK_ID,
        parent_attempt_id=attempt_id,
        failure_code="BLOCKED_VM9201_DISPOSABLE_SEAM",
        request_artifact_root=f"runs/{RUN_ID}/handoffs",
    )


def valid_product(handoff: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "gateway-subworkflow-product.v1",
        "product_contract": "vm9201-disposable-seam.v1",
        "handoff_id": handoff["handoff_id"],
        "parent_run_id": RUN_ID,
        "parent_task_id": TASK_ID,
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
            {"path": "provider/acceptance.json", "sha256": "b" * 64, "bytes": 10}
        ],
        "rollback": {"status": "available", "artifact_path": "provider/rollback.json"},
        "provenance": {"source_sha256": "c" * 64},
        "bounded_error": None,
        "status": "completed",
    }


def test_handoff_digest_excludes_attempt_id() -> None:
    first = request("attempt-one")
    second = request("attempt-two")
    assert first["handoff_id"] == second["handoff_id"]
    assert first["request_digest"] == second["request_digest"]
    assert first["parent_attempt_id"] != second["parent_attempt_id"]


def test_detects_vm9201_disposition(tmp_path: Path) -> None:
    disposition = tmp_path / "vm9201-disposition.json"
    disposition.write_text(json.dumps({"disposition": "BLOCKED_VM9201_DISPOSABLE_SEAM"}))
    assert detect_capability_failure(tmp_path) == "BLOCKED_VM9201_DISPOSABLE_SEAM"


def test_validates_vm9201_product(tmp_path: Path) -> None:
    handoff = request()
    (tmp_path / "provider").mkdir()
    acceptance_path = tmp_path / "provider/acceptance.json"
    rollback_path = tmp_path / "provider/rollback.json"
    acceptance_path.write_text("accepted\n")
    rollback_path.write_text("rollback\n")
    product = valid_product(handoff)
    product["artifacts"][0] = {
        "path": "provider/acceptance.json",
        "sha256": hashlib.sha256(acceptance_path.read_bytes()).hexdigest(),
        "bytes": acceptance_path.stat().st_size,
    }
    product_path = tmp_path / "handoff-product.json"
    product_path.write_text(json.dumps(product))
    validated = validate_product(product_path, handoff, tmp_path)
    assert validated["disposition"] == "PASS_VM9201_DISPOSABLE_SEAM"
    assert validated["capability"]["role_authenticated"] is True


@pytest.mark.parametrize(
    "mutator",
    [
        lambda product: product["target_identity"].update({"vmid": "9005"}),
        lambda product: product["capability"].update({"role_authenticated": False}),
        lambda product: product["rollback"].update({"status": "missing"}),
        lambda product: product["artifacts"][0].update({"path": "../escape"}),
        lambda product: product.update({"password": "secret"}),
    ],
)
def test_rejects_invalid_product(tmp_path: Path, mutator) -> None:
    handoff = request()
    product = valid_product(handoff)
    mutator(product)
    product_path = tmp_path / "handoff-product.json"
    product_path.write_text(json.dumps(product))
    with pytest.raises(HandoffValidationError):
        validate_product(product_path, handoff, tmp_path)
