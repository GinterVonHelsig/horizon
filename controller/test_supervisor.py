from __future__ import annotations

import threading
from pathlib import Path

import pytest

from evidence import ManifestEntry, build_required_seed, make_submission, sha256_file
from exceptions import (
    ProvenanceMismatchError,
    RedisConfigurationError,
    ReleaseAuthorityDeniedError,
    SignalEgressDeniedError,
)
from manifest_ids import REQUIRED_ENTRY_IDS
from parent_controller import ParentController
from provenance import derive_provenance, verify_activation
from redis_advisory import RedisAdvisory, RedisAdvisoryConfig
from release_boundary import deny_release_action
from repository import PostgresRepository, retry_queue_key
from signal_status import SignalStatusReader


def make_controller(db_url: str, artifact_root: Path, **kwargs) -> ParentController:
    controller = ParentController(
        db_url,
        stale_after=10,
        controller_lease_seconds=60,
        artifact_root=artifact_root,
        **kwargs,
    )
    return controller


def test_stale_lease_is_recorded_and_queued(db_url: str, artifact_root: Path) -> None:
    notices: list[dict] = []
    controller = make_controller(db_url, artifact_root, notifier=notices.append)
    controller.register_run("run-1")
    lease = controller.acquire_lease("run-1", "task-1", "worker-1")
    with controller._repo.transaction() as cur:
        cur.execute(
            "UPDATE task_attempts SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE attempt_id = %s",
            (lease.attempt_id,),
        )
    assert controller.tick("run-1") == ["task-1"]
    assert controller.lease("task-1").status == "stale"
    event_types = [event.event_type for event in controller.events("run-1")]
    assert "child_stale" in event_types
    assert "retry_queued" in event_types
    controller.close()


def test_stale_retry_ceiling_terminalizes_attempt_without_retry_evidence(
    db_url: str, artifact_root: Path
) -> None:
    controller = make_controller(db_url, artifact_root, max_retries=0)
    controller.register_run("run-stale-limit")
    lease = controller.acquire_lease("run-stale-limit", "task-stale-limit", "worker-1")
    with controller._repo.transaction() as cur:
        cur.execute(
            "UPDATE task_attempts SET lease_expires_at = clock_timestamp() - interval '1 second' "
            "WHERE attempt_id = %s",
            (lease.attempt_id,),
        )
    assert controller.tick("run-stale-limit") == ["task-stale-limit"]
    assert controller.task("task-stale-limit").state == "failed"
    assert controller.lease("task-stale-limit").status == "stale"
    event_types = [event.event_type for event in controller.events("run-stale-limit")]
    assert "child_stale" in event_types
    assert "task_failed_retry_limit" in event_types
    assert "retry_queued" not in event_types
    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT COUNT(*) AS count FROM retry_queue WHERE task_id = %s",
            ("task-stale-limit",),
        )
        assert int(cur.fetchone()["count"]) == 0
    controller.close()


def test_concurrent_retry_enqueue_has_one_next_attempt(
    db_url: str, artifact_root: Path
) -> None:
    controller = make_controller(db_url, artifact_root)
    controller.register_run("run-concurrent-retry")
    controller.schedule_task("run-concurrent-retry", "task-concurrent-retry", "retry")
    claimed = controller.claim_next("run-concurrent-retry", "worker")
    assert claimed is not None and claimed.generation
    attempt_id, fence = controller._resolve_attempt(
        "task-concurrent-retry", claimed.generation
    )
    epoch = controller.controller_epoch("run-concurrent-retry")
    barrier = threading.Barrier(2)

    def enqueue_from_separate_connection() -> str:
        repository = PostgresRepository(db_url)
        try:
            barrier.wait(timeout=10)
            repository.retry_task(
                run_id="run-concurrent-retry",
                task_id="task-concurrent-retry",
                attempt_id=attempt_id,
                fence_token=fence,
                controller_epoch=epoch,
                reason="concurrent-failure",
                delay_seconds=0,
                retry_key=retry_queue_key("run-concurrent-retry", "task-concurrent-retry", 1),
            )
            return "ok"
        except Exception as exc:  # the loser must be fenced, not silently succeed
            return type(exc).__name__
        finally:
            repository.close()

    outcomes: list[str] = []
    first = threading.Thread(
        target=lambda: outcomes.append(enqueue_from_separate_connection())
    )
    second = threading.Thread(
        target=lambda: outcomes.append(enqueue_from_separate_connection())
    )
    first.start()
    second.start()
    first.join(timeout=30)
    second.join(timeout=30)
    assert not first.is_alive() and not second.is_alive()
    assert outcomes.count("ok") == 1
    assert len(outcomes) == 2
    assert any(outcome in {"StaleFenceError", "PermissionError"} for outcome in outcomes)

    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT COUNT(*) AS count, MIN(attempt) AS min_attempt, MAX(attempt) AS max_attempt "
            "FROM retry_queue WHERE run_id = %s AND task_id = %s",
            ("run-concurrent-retry", "task-concurrent-retry"),
        )
        retry_row = cur.fetchone()
    assert retry_row is not None
    assert int(retry_row["count"]) == 1
    assert int(retry_row["min_attempt"]) == 1
    assert int(retry_row["max_attempt"]) == 1
    controller.close()


def test_old_generation_cannot_heartbeat(db_url: str, artifact_root: Path) -> None:
    controller = make_controller(db_url, artifact_root)
    controller.register_run("run-1")
    lease = controller.acquire_lease("run-1", "task-1", "worker-1")
    with controller._repo.transaction() as cur:
        cur.execute(
            "UPDATE task_attempts SET lease_expires_at = clock_timestamp() - interval '1 second' "
            "WHERE attempt_id = %s",
            (lease.attempt_id,),
        )
    controller.acquire_lease("run-1", "task-1", "worker-2", force=True)
    with pytest.raises(PermissionError):
        controller.heartbeat("task-1", lease.generation)
    assert controller.task("task-1").attempt == 1
    controller.close()


def test_parent_scheduler_claims_and_fences_tasks(db_url: str, artifact_root: Path) -> None:
    controller = make_controller(db_url, artifact_root)
    controller.register_run("run-1")
    task = controller.schedule_task("run-1", "task-1", "review evidence", priority=10)
    assert task.state == "queued"
    claimed = controller.claim_next("run-1", "terra")
    assert claimed is not None
    assert claimed.state == "leased"
    assert claimed.generation
    with pytest.raises(PermissionError):
        controller.complete_task("run-1", "task-1", "wrong-generation", "verified")
    completed = controller.complete_task("run-1", "task-1", claimed.generation, "verified")
    assert completed.state == "verified"
    assert controller.claim_next("run-1", "terra") is None
    controller.close()


def test_retry_requeues_with_a_new_fenced_generation(db_url: str, artifact_root: Path) -> None:
    controller = make_controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "task-1", "retry evidence")
    first = controller.claim_next("run-1", "terra")
    assert first is not None
    retried = controller.retry_task(
        "run-1", "task-1", first.generation, "transient dependency", delay=0
    )
    assert retried.state == "queued"
    second = controller.claim_next("run-1", "terra")
    assert second is not None
    assert second.generation != first.generation
    assert second.attempt == 1
    controller.close()
