"""Gate tests for acceptance assertions and failure injections."""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path

import pytest

from db import validate_database_url
from evidence import ManifestEntry, build_required_seed, make_submission, sha256_file
from evidence import sha256_file_at
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
from repository import PostgresRepository
from signal_status import SignalStatusReader


def _controller(db_url: str, artifact_root: Path, **kwargs) -> ParentController:
    return ParentController(
        db_url,
        stale_after=10,
        controller_lease_seconds=5,
        artifact_root=artifact_root,
        **kwargs,
    )


def _submit_all_manifest(controller: ParentController, run_id: str, root: Path) -> None:
    for entry_id in REQUIRED_ENTRY_IDS:
        path = root / "evidence" / f"{entry_id.lower()}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(json.dumps({"entry_id": entry_id, "ok": True}) + "\n")
    controller.seed_manifest(root)
    for entry_id in REQUIRED_ENTRY_IDS:
        path = root / "evidence" / f"{entry_id.lower()}.json"
        controller.submit_manifest_entry(
            run_id, make_submission(entry_id, path, relative_to=root)
        )


def test_a01_isolation_rejects_forbidden_database_url() -> None:
    with pytest.raises(ValueError):
        validate_database_url("postgresql://user@localhost/trading_production")


def test_i01_concurrent_controllers_reject_stale_epoch(db_url: str, artifact_root: Path) -> None:
    first = _controller(db_url, artifact_root, controller_owner="controller-a")
    second = _controller(db_url, artifact_root, controller_owner="controller-b")
    first.register_run("run-1")
    first.schedule_task("run-1", "task-1", "work")
    epoch_a = first._epochs["run-1"]
    with first._repo.transaction() as cur:
        cur.execute("SELECT longspan_test_expire_controller_lease(%s)", ("run-1",))
    epoch_b = second.takeover_controller("run-1", "controller-b")
    assert epoch_b > epoch_a
    with pytest.raises(PermissionError):
        first.claim_next("run-1", "controller-a")
    first.close()
    second.close()


def test_i02_pre_successor_expiry_rejects_writes(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "task-1", "work")
    claimed = controller.claim_next("run-1", "worker")
    assert claimed is not None
    with controller._repo.transaction() as cur:
        cur.execute(
            "UPDATE task_attempts SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE task_id = %s",
            ("task-1",),
        )
    with pytest.raises(PermissionError):
        controller.heartbeat("task-1", claimed.generation)
    with pytest.raises(PermissionError):
        controller.complete_task("run-1", "task-1", claimed.generation, "verified")
    stale = controller.tick("run-1")
    assert stale == ["task-1"]
    controller.close()


def test_i03_concurrent_claimers_single_winner(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "task-1", "work")
    barrier = threading.Barrier(3)
    results: list = []
    errors: list = []

    def claim(owner: str) -> None:
        # The parent lease is single-writer.  These are concurrent child
        # claimers under that one parent controller, not competing parent
        # controllers; keep the parent owner fixed while varying the task
        # claimant identity.
        local = _controller(
            db_url,
            artifact_root,
            controller_owner=controller.controller_owner,
        )
        local._epochs["run-1"] = controller._epochs["run-1"]
        barrier.wait()
        try:
            results.append(local.claim_next("run-1", owner))
        except Exception as exc:
            errors.append(exc)
        finally:
            local.close()

    threads = [threading.Thread(target=claim, args=(f"worker-{index}",)) for index in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    winners = [item for item in results if item is not None]
    assert len(winners) == 1
    with controller._repo.transaction() as cur:
        cur.execute("SELECT COUNT(*) AS count FROM task_attempts WHERE task_id = %s", ("task-1",))
        assert int(cur.fetchone()["count"]) == 1
    controller.close()


def test_i04_sigkill_restart_recovery_rejects_old_controller(db_url: str, artifact_root: Path) -> None:
    killed = _controller(db_url, artifact_root, controller_owner="killed")
    killed.register_run("run-1")
    killed.schedule_task("run-1", "task-1", "work")
    claimed = killed.claim_next("run-1", "worker")
    assert claimed is not None
    old_epoch = killed._epochs["run-1"]
    with killed._repo.transaction() as cur:
        cur.execute("SELECT longspan_test_expire_controller_lease(%s)", ("run-1",))
    replacement = _controller(db_url, artifact_root, controller_owner="replacement")
    new_epoch = replacement.takeover_controller("run-1", "replacement")
    assert new_epoch > old_epoch
    killed._epochs["run-1"] = old_epoch
    with pytest.raises(PermissionError):
        killed.complete_task("run-1", "task-1", claimed.generation, "verified")
    killed.close()
    replacement.close()


def test_live_controller_and_child_lease_cannot_be_forced(db_url: str, artifact_root: Path) -> None:
    first = _controller(db_url, artifact_root, controller_owner="controller-a")
    second = _controller(db_url, artifact_root, controller_owner="controller-b")
    first.register_run("run-1")
    first.schedule_task("run-1", "task-1", "work")
    lease = first.acquire_lease("run-1", "task-1", "worker-a")
    with pytest.raises(PermissionError):
        second.takeover_controller("run-1", "controller-b", force=True)
    with pytest.raises(PermissionError):
        first.acquire_lease("run-1", "task-1", "worker-b", force=True)
    assert first.lease("task-1").attempt_id == lease.attempt_id
    first.close()
    second.close()


def test_i05_postgresql_restart_persistence(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "task-1", "persist")
    claimed = controller.claim_next("run-1", "worker")
    assert claimed is not None
    before = controller._repo.get_task("task-1")
    controller._repo.reconnect()
    after_repo = PostgresRepository(db_url)
    after = after_repo.get_task("task-1")
    assert before["task_id"] == after["task_id"]
    assert before["state"] == after["state"]
    controller.close()
    after_repo.close()


def test_i06_redis_acl_prefix_and_loss(db_url: str, artifact_root: Path) -> None:
    with pytest.raises(RedisConfigurationError):
        RedisAdvisory.from_env(enabled=True, url="redis://localhost/0", acl_user=None)
    advisory = RedisAdvisory(
        RedisAdvisoryConfig(url="redis://disabled", acl_user="td-p1", prefix="td:p1:")
    )
    with pytest.raises(RedisConfigurationError):
        advisory.validate_key("other:status")
    with pytest.raises(RedisConfigurationError):
        RedisAdvisory.from_env(
            enabled=True,
            url="redis://127.0.0.1:1/0?socket_connect_timeout=1",
            acl_user="td-p1",
        )
    controller = _controller(db_url, artifact_root, redis=RedisAdvisory(None))
    controller.register_run("run-1")
    report = controller.readiness("run-1")
    assert not report.ready
    controller.close()


def test_i07_evidence_tampering_and_recovery(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.seed_manifest(artifact_root)
    report = controller.readiness("run-1")
    assert not report.ready
    _submit_all_manifest(controller, "run-1", artifact_root)
    evidence_id = controller.record_evidence(
        "run-1", "evidence/a01.json", producer="test", result="pass"
    )
    assert evidence_id
    assert len(controller.evidence("run-1")) == 1
    controller._repo.set_provenance(
        "run-1",
        reviewed_sha="abc",
        commit_sha="abc",
        tree_sha="def",
        verified=True,
    )
    ready = controller.readiness("run-1")
    assert ready.ready
    tampered = artifact_root / "evidence" / "a01.json"
    original = tampered.read_bytes()
    tampered.write_text('{"tampered":true}\n', encoding="utf-8")
    bad = make_submission("A01", tampered, relative_to=artifact_root)
    with pytest.raises(ValueError):
        controller.submit_manifest_entry("run-1", bad)
    tampered.write_bytes(original)
    restored = controller.readiness("run-1")
    assert restored.ready
    controller.close()


def test_evidence_hash_walk_rejects_symlinked_ancestor(
    db_url: str, artifact_root: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a01.json").write_text("outside\n", encoding="utf-8")
    evidence = artifact_root / "evidence"
    evidence.mkdir()
    (evidence / "a01.json").write_text("inside\n", encoding="utf-8")
    expected = sha256_file_at(artifact_root, "evidence/a01.json")
    evidence.rename(artifact_root / "evidence-real")
    evidence.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        sha256_file_at(artifact_root, "evidence/a01.json")
    assert expected[1] == len(b"inside\n")


def test_i08_provenance_mismatch_rejected(db_url: str, artifact_root: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ProvenanceMismatchError):
        derive_provenance(repo, reviewed_sha="deadbeef")
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller._repo.set_provenance(
        "run-1",
        reviewed_sha="aaa",
        commit_sha="bbb",
        tree_sha="ccc",
        verified=False,
    )
    report = controller.readiness("run-1")
    assert "provenance-unverified" in report.blockers
    controller.close()


def test_a02_clean_provenance_and_activation_hash_chain(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "artifact.txt").write_text("verified\n")
    subprocess.run(["git", "-C", str(repo), "add", "artifact.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "test"],
        check=True,
    )
    reviewed = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    record = derive_provenance(repo, reviewed)
    activated = verify_activation(record, build_sha="build-1", activation_sha="activation-1")
    assert activated.commit_sha == reviewed
    assert activated.tree_sha
    with pytest.raises(ProvenanceMismatchError):
        verify_activation(activated, build_sha="build-2", activation_sha="activation-1")


def test_a04_future_task_is_not_claimed_until_due(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "future-task", "deferred", available_at=4102444800)
    assert controller.claim_next("run-1", "worker") is None
    with controller._repo.transaction() as cur:
        cur.execute(
            "UPDATE parent_tasks SET available_at = clock_timestamp() - interval '1 second' WHERE task_id = %s",
            ("future-task",),
        )
    assert controller.claim_next("run-1", "worker") is not None
    controller.close()


def test_duplicate_task_id_cannot_cross_run_boundary(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.register_run("run-2")
    controller.schedule_task("run-1", "same-task", "first")
    with controller._repo.transaction() as cur:
        cur.execute(
            """
            SELECT constraint_type
            FROM information_schema.table_constraints
            WHERE table_name = 'parent_tasks' AND constraint_name = 'parent_tasks_pkey'
            """
        )
        assert cur.fetchone()["constraint_type"] == "PRIMARY KEY"
    with pytest.raises(ValueError):
        controller.schedule_task("run-2", "same-task", "second")
    controller.close()


def test_recover_executor_contract_failure_requeues_attempt_zero(
    db_url: str, artifact_root: Path
) -> None:
    controller = _controller(db_url, artifact_root, max_retries=5)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "recover-task", "bounded")
    first = controller.claim_next("run-1", "worker")
    assert first is not None
    assert first.attempt == 0
    payload = controller.recover_executor_contract_failure(
        "run-1",
        "recover-task",
        first.generation or "",
        "malformed_structured_output",
        expected_attempt=0,
    )
    assert payload["reason"] == "recovered_contract_failure"
    assert payload["recovered"] is True
    queued = controller.task("recover-task")
    assert queued.state == "queued"
    controller.close()


def test_recover_executor_contract_failure_exhausts_retry_budget(
    db_url: str, artifact_root: Path
) -> None:
    controller = _controller(db_url, artifact_root, max_retries=0)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "exhaust-task", "bounded")
    first = controller.claim_next("run-1", "worker")
    assert first is not None
    payload = controller.recover_executor_contract_failure(
        "run-1",
        "exhaust-task",
        first.generation or "",
        "malformed_structured_output",
        expected_attempt=first.attempt,
    )
    assert payload["reason"] == "exhausted_retry_budget"
    assert payload["recovered"] is False
    failed = controller.task("exhaust-task")
    assert failed.state == "failed"
    controller.close()


def test_recover_executor_contract_failure_mismatch_does_not_retry(
    db_url: str, artifact_root: Path
) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "mismatch-task", "bounded")
    first = controller.claim_next("run-1", "worker")
    assert first is not None
    before = controller.task("mismatch-task")
    with pytest.raises(PermissionError):
        controller.recover_executor_contract_failure(
            "run-1",
            "mismatch-task",
            first.generation or "",
            "malformed_structured_output",
            expected_attempt=99,
        )
    after = controller.task("mismatch-task")
    assert after.state == before.state
    assert after.attempt == before.attempt
    controller.close()


def test_a06_retry_limit_terminalizes_task(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root, max_retries=1)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "retry-task", "bounded")
    first = controller.claim_next("run-1", "worker")
    assert first is not None
    controller.retry_task("run-1", "retry-task", first.generation or "", "temporary")
    second = controller.claim_next("run-1", "worker")
    assert second is not None
    final = controller.retry_task("run-1", "retry-task", second.generation or "", "temporary")
    assert final.state == "failed"
    controller.close()


def test_child_execution_uses_injected_handler_only(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "child-task", "deterministic child")
    result = controller.execute_next("run-1", "worker", lambda task: "verified")
    assert result is not None and result.state == "verified"
    controller.close()


def test_i09_signal_egress_and_control_denied(db_url: str, artifact_root: Path) -> None:
    reader = SignalStatusReader()
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    status = controller.signal_status("run-1")
    assert status["mode"] == "read-only"
    with pytest.raises(SignalEgressDeniedError):
        reader.deny_outbound_send()
    with pytest.raises(SignalEgressDeniedError):
        reader.deny_control_action("send")
    controller.close()


def test_event_sequence_is_monotonic_and_signal_does_not_regress(
    db_url: str, artifact_root: Path
) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.emit("run-1", "one", {})
    controller.emit("run-1", "two", {})
    events = list(controller.events("run-1"))
    assert [int(item.detail.get("missing", 0)) for item in events] == [0, 0]
    rows = controller._repo.events("run-1")
    assert [int(row["event_seq"]) for row in rows] == sorted(int(row["event_seq"]) for row in rows)
    assert controller._repo.latest_event_seq("run-1") == int(rows[-1]["event_seq"])
    assert controller.signal_status("run-1")["run_id"] == "run-1"
    controller.close()


def test_i10_idempotent_cleanup(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    lease = controller.acquire_lease("run-1", "task-1", "worker")
    with controller._repo.transaction() as cur:
        cur.execute(
            "UPDATE task_attempts SET lease_expires_at = clock_timestamp() - interval '1 second' "
            "WHERE attempt_id = %s",
            (lease.attempt_id,),
        )
    assert controller.idempotent_cleanup(lease.attempt_id, run_id="run-1") is True
    assert controller.idempotent_cleanup(lease.attempt_id, run_id="run-1") is False
    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT status FROM task_attempts WHERE attempt_id = %s", (lease.attempt_id,)
        )
        assert cur.fetchone()["status"] == "stale"
        cur.execute(
            "SELECT state, active_attempt_id FROM parent_tasks WHERE task_id = %s",
            ("task-1",),
        )
        task = cur.fetchone()
        assert task["state"] == "queued"
        assert task["active_attempt_id"] is None
    controller.close()


def test_reclaim_rebinds_superseded_attempt_epoch(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "task-1", "rebind")
    worker = ParentController(db_url, artifact_root=artifact_root, lease_holder=False)
    first = worker.claim_next("run-1", "worker")
    assert first is not None
    old_epoch = controller.controller_epoch("run-1")
    new_epoch = controller._repo.acquire_controller(
        "run-1",
        controller.controller_owner,
        lease_seconds=controller.controller_lease_seconds,
        expected_epoch=old_epoch,
    )
    assert new_epoch > old_epoch
    reclaimed = worker.claim_next("run-1", "worker")
    assert reclaimed is not None
    assert reclaimed.task_id == "task-1"
    with controller._repo.transaction() as cur:
        cur.execute(
            """
            SELECT controller_epoch, status
            FROM task_attempts
            WHERE task_id = %s AND status = 'running'
            """,
            ("task-1",),
        )
        attempt = cur.fetchone()
        assert attempt is not None
        assert int(attempt["controller_epoch"]) == new_epoch
        assert attempt["status"] == "running"
    controller.close()
    worker.close()


def test_cleanup_cannot_requeue_after_successor_owns_task(
    db_url: str, artifact_root: Path
) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    old = controller.acquire_lease("run-1", "task-1", "old")
    with controller._repo.transaction() as cur:
        cur.execute(
            "UPDATE task_attempts SET lease_expires_at = clock_timestamp() - interval '1 second' "
            "WHERE attempt_id = %s",
            (old.attempt_id,),
        )
    successor = controller.acquire_lease("run-1", "task-1", "new", force=True)
    assert successor.attempt_id != old.attempt_id
    assert controller.idempotent_cleanup(old.attempt_id, run_id="run-1") is False
    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT COUNT(*) AS count FROM retry_queue WHERE run_id=%s AND task_id=%s",
            ("run-1", "task-1"),
        )
        assert int(cur.fetchone()["count"]) == 0
    controller.close()


def test_a11_terra_release_boundary(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    with pytest.raises(ReleaseAuthorityDeniedError):
        controller.attempt_release("deploy")
    with pytest.raises(ReleaseAuthorityDeniedError):
        deny_release_action("merge")
    controller.close()


def test_a12_rollback_invalidates_epochs(db_url: str, artifact_root: Path) -> None:
    controller = _controller(db_url, artifact_root)
    controller.register_run("run-1")
    controller.schedule_task("run-1", "task-1", "blocked")
    claimed = controller.claim_next("run-1", "worker")
    assert claimed is not None
    old_epoch = controller._epochs["run-1"]
    new_epoch = controller.rollback("run-1")
    assert new_epoch > old_epoch
    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT state, active_attempt_id FROM parent_tasks WHERE task_id = %s",
            ("task-1",),
        )
        task = cur.fetchone()
        assert task["state"] == "parked"
        assert task["active_attempt_id"] is None
        cur.execute(
            "SELECT status FROM task_attempts WHERE task_id = %s ORDER BY created_at DESC LIMIT 1",
            ("task-1",),
        )
        assert cur.fetchone()["status"] == "stale"
        cur.execute(
            "SELECT COUNT(*) AS count FROM supervisor_events WHERE run_id = %s",
            ("run-1",),
        )
        event_count_after_rollback = int(cur.fetchone()["count"])
    with pytest.raises(PermissionError):
        controller._repo.complete_attempt(
            run_id="run-1",
            task_id="task-1",
            attempt_id="missing",
            fence_token=1,
            controller_epoch=old_epoch,
            terminal_state="verified",
        )
    # Every old-epoch mutator must fail at the controller row lock before it
    # can change child, retry, event, or cleanup state after rollback.
    old_attempt, old_fence = controller._resolve_attempt("task-1", claimed.generation or "")
    with pytest.raises(PermissionError):
        controller._repo.heartbeat_attempt(
            run_id="run-1",
            task_id="task-1",
            attempt_id=old_attempt,
            fence_token=old_fence,
            controller_epoch=old_epoch,
            lease_seconds=10,
        )
    with pytest.raises(PermissionError):
        controller._repo.retry_task(
            run_id="run-1",
            task_id="task-1",
            attempt_id=old_attempt,
            fence_token=old_fence,
            controller_epoch=old_epoch,
            reason="old-epoch",
            delay_seconds=0,
        )
    with pytest.raises(PermissionError):
        controller._repo.emit_event(
            "run-1", "old_epoch_event", {}, controller_epoch=old_epoch
        )
    with pytest.raises(PermissionError):
        controller._repo.tick_stale("run-1", old_epoch)
    with pytest.raises(PermissionError):
        controller._repo.idempotent_cleanup(
            old_attempt, run_id="run-1", controller_epoch=old_epoch
        )
    with controller._repo.transaction() as cur:
        cur.execute(
            "SELECT COUNT(*) AS count FROM retry_queue WHERE run_id = %s",
            ("run-1",),
        )
        assert int(cur.fetchone()["count"]) == 0
        cur.execute(
            "SELECT COUNT(*) AS count FROM supervisor_events WHERE run_id = %s",
            ("run-1",),
        )
        assert int(cur.fetchone()["count"]) == event_count_after_rollback
        cur.execute(
            "SELECT COUNT(*) AS count FROM supervisor_events WHERE run_id = %s AND event_type = %s",
            ("run-1", "old_epoch_event"),
        )
        assert int(cur.fetchone()["count"]) == 0
    with pytest.raises(PermissionError):
        controller.schedule_task("run-1", "task-1", "blocked")
    controller.close()
