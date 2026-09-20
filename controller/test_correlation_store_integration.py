"""Disposable integration tests for ATS-COM-001 correlation store."""

from __future__ import annotations

from pathlib import Path

import pytest

from parent_controller import ParentController

RUN_ID = "goal-3eb7b972ec15809e"
REQUEST_ID = "status-req-001"


@pytest.fixture()
def controller(db_url: str, artifact_root: Path) -> ParentController:
    parent = ParentController(
        db_url,
        controller_owner="horizon-correlation-test",
        artifact_root=artifact_root,
    )
    try:
        yield parent
    finally:
        parent.close()


def test_correlation_store_records_and_replays_status_answer(
    controller: ParentController,
) -> None:
    controller.register_run(RUN_ID)
    question = {
        "request_kind": "status",
        "objective": "report run disposition",
        "target_digest": "abc123",
    }
    answer = {
        "disposition": "active",
        "run_id": RUN_ID,
        "scheduling_enabled": True,
    }

    first = controller.record_correlation_status(
        run_id=RUN_ID,
        request_id=REQUEST_ID,
        question=question,
        answer=answer,
    )
    assert first["replayed"] is False
    assert first["answer"] == answer

    replay = controller.record_correlation_status(
        run_id=RUN_ID,
        request_id=REQUEST_ID,
        question=question,
        answer={"disposition": "different"},
    )
    assert replay["replayed"] is True
    assert replay["answer"] == answer
    assert replay["replay_count"] == 1

    fetched = controller.get_correlation_status(run_id=RUN_ID, request_id=REQUEST_ID)
    assert fetched is not None
    assert fetched["answer"] == answer
    assert fetched["answer_digest"] == first["answer_digest"]
