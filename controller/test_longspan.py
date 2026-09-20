"""Longspan workflow, lifecycle, migration, and failure-injection tests."""

from __future__ import annotations

import os
import subprocess
import hashlib
import hmac
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

import psycopg2
import pytest

from comms01_authority import Comms01AuthorityBoundary
from db import (
    CANONICAL_ALEMBIC_HEAD,
    alembic_command,
    create_disposable_database,
    current_database_revision,
    drop_database,
    run_migrations,
)
from exceptions import AuthorizationFailureError, IntegrityFailureError, LeaseExpiredError
from longspan import (
    ExecutionOutcome,
    LongspanWorkflow,
    child_idempotency_key,
    default_inspector,
    default_plan_producer,
    default_task_handler,
)
from longspan_crypto import compute_ledger_entry_hash, digest_payload, hash_capability_token
from longspan_repository import LongspanRepository
from manifest_ids import REQUIRED_ENTRY_IDS
from parent_controller import ParentController
from provenance import capture_run_provenance, git_commit_sha, git_tree_sha
from terra_review import TerraReviewAuthority
from terra_receipt_attestation import (
    sign_terra_receipt,
    terra_receipt_database_digest,
    terra_receipt_signature_components,
    verify_terra_receipt_signature,
)
from test_authority_helpers import (
    _authority_url_for_database,
    operator_private_key_for_tests,
    terra_private_key_for_tests,
    sign_external_operator_receipt,
)
from test_disposable_helpers import install_create_capability, install_downgrade_capability, install_drop_capability
from evidence import make_submission

ADMIN_URL = os.environ.get(
    "TOP_DELIVERY_PG_ADMIN_URL",
    "postgresql://root@/postgres?host=%2Fvar%2Frun%2Fpostgresql&port=5432",
)


def _create_test_database(name: str | None = None) -> tuple[str, str]:
    from test_role_provision import ensure_test_delivery_roles

    database_name = name or f"td_test_{uuid.uuid4().hex}"
    ensure_test_delivery_roles(ADMIN_URL)
    install_create_capability(database_name=database_name)
    return database_name, create_disposable_database(ADMIN_URL, database_name)


def _drop_test_database(database_name: str) -> None:
    install_drop_capability(database_name=database_name)
    drop_database(ADMIN_URL, database_name)

REPO_ROOT = Path(__file__).resolve().parents[1]
TERRA_TOKEN = "verified-terra-token"
OPERATOR_TOKEN = "verified-operator-token"
TEST_LEDGER_MAC = "test-ledger-mac-secret"
TEST_TERRA_GATEWAY_MAC = "test-terra-gateway-mac-secret"
REVIEWED_SHA = git_commit_sha(REPO_ROOT)


def _controller(db_url: str, artifact_root: Path, **kwargs) -> ParentController:
    return ParentController(
        db_url,
        stale_after=10,
        controller_lease_seconds=5,
        artifact_root=artifact_root,
        **kwargs,
    )


def _workflow(db_url: str, artifact_root: Path) -> LongspanWorkflow:
    parent = _controller(db_url, artifact_root)
    return LongspanWorkflow(parent)


def _seed_ready_parent(controller: ParentController, run_id: str, root: Path) -> None:
    for entry_id in REQUIRED_ENTRY_IDS:
        path = root / "evidence" / f"{entry_id.lower()}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text('{"ok": true}\n', encoding="utf-8")
    controller.seed_manifest(root)
    for entry_id in REQUIRED_ENTRY_IDS:
        path = root / "evidence" / f"{entry_id.lower()}.json"
        controller.submit_manifest_entry(
            run_id, make_submission(entry_id, path, relative_to=root)
        )
    controller._repo.set_provenance(
        run_id,
        reviewed_sha=REVIEWED_SHA,
        commit_sha=REVIEWED_SHA,
        tree_sha=git_tree_sha(REPO_ROOT),
        verified=True,
    )


def _provision_authority(workflow: LongspanWorkflow, run_id: str) -> None:
    boundary = Comms01AuthorityBoundary(workflow.repo, repo_root=REPO_ROOT)
    terra_hash = hash_capability_token(TERRA_TOKEN)
    operator_hash = hash_capability_token(OPERATOR_TOKEN)
    captured = capture_run_provenance(
        REPO_ROOT,
        reviewed_sha=REVIEWED_SHA,
        db_url=workflow.parent._repo.db_url,
    )
    controller_epoch = workflow.parent.controller_epoch(run_id)
    action_digest = digest_payload(
        {
            "action": "initial_provision",
            "run_id": run_id,
            "operator_identity": "operator@test",
            "reviewed_sha": REVIEWED_SHA,
            "tree_sha": captured.tree_sha,
            "source_digest": captured.source_digest,
            "controller_epoch": controller_epoch,
            "config_version": 1,
            "terra_auth_hash": terra_hash,
            "operator_auth_hash": operator_hash,
        }
    )
    challenge = boundary.issue_operator_2fa_challenge(
        run_id=run_id,
        action_type="initial_provision",
        action_digest=action_digest,
        operator_identity="operator@test",
        controller_epoch=controller_epoch,
        config_version=1,
    )
    receipt = sign_external_operator_receipt(challenge)
    boundary.initial_provision(
        run_id=run_id,
        terra_auth_token=TERRA_TOKEN,
        operator_auth_token=OPERATOR_TOKEN,
        reviewed_sha=REVIEWED_SHA,
        tree_sha=captured.tree_sha,
        source_digest=captured.source_digest,
        controller_epoch=controller_epoch,
        operator_identity="operator@test",
        operator_approval_receipt=receipt,
    )


def _terra_auth(token: str = TERRA_TOKEN) -> TerraReviewAuthority:
    class TestTerraSigner:
        def sign(self, receipt: dict[str, object]) -> str:
            return sign_terra_receipt(receipt, terra_private_key_for_tests())

    return TerraReviewAuthority(
        token,
        repo_root=REPO_ROOT,
        signer=TestTerraSigner(),
    )


def test_operator_key_cannot_sign_a_terra_receipt() -> None:
    payload = {
        "child_id": "child",
        "attempt_number": 0,
        "reviewer": "terra",
        "decision": "approved",
        "evidence_chain_head": "a" * 64,
        "run_id": "run",
        "task_id": "task",
        "reviewed_sha": "b" * 40,
        "fence_token": 1,
        "controller_epoch": 1,
        "tree_sha": "c" * 40,
        "source_digest": "d" * 64,
        "request_digest": "e" * 64,
        "migration_head": CANONICAL_ALEMBIC_HEAD,
        "authority_version": 1,
        "evidence_digest": "f" * 64,
        "result_digest": "0" * 64,
    }
    forged = sign_terra_receipt(payload, operator_private_key_for_tests())
    assert not verify_terra_receipt_signature(payload, forged)


def test_terra_receipt_signature_components_require_database_binding() -> None:
    payload = {
        "child_id": "child",
        "attempt_number": 0,
        "reviewer": "terra",
        "decision": "approved",
        "evidence_chain_head": "a" * 64,
        "run_id": "run",
        "task_id": "task",
        "reviewed_sha": "b" * 40,
        "fence_token": 1,
        "controller_epoch": 1,
        "tree_sha": "c" * 40,
        "source_digest": "d" * 64,
        "request_digest": "e" * 64,
        "migration_head": CANONICAL_ALEMBIC_HEAD,
        "authority_version": 1,
        "evidence_digest": "f" * 64,
        "result_digest": "0" * 64,
    }
    external = sign_terra_receipt(payload, terra_private_key_for_tests())
    assert terra_receipt_signature_components(external) is None
    assert terra_receipt_signature_components(
        f"{external}:{'0' * 64}:not-an-attestation"
    ) is None
    assert terra_receipt_signature_components(
        f"{external}:{'0' * 64}:{'1' * 32}"
    ) == (external, "0" * 64, "1" * 32)


def test_terra_receipt_database_digest_matches_postgresql_jsonb(
    db_url: str,
) -> None:
    """The Python admission digest must match PostgreSQL for Unicode/bounds."""
    payload = {
        "child_id": "child-✓",
        "attempt_number": 2_147_483_647,
        "reviewer": "térra-reviewer-✓",
        "decision": "approved",
        "evidence_chain_head": "a" * 64,
        "run_id": "run-✓",
        "task_id": "task-✓",
        "reviewed_sha": "b" * 40,
        "fence_token": 9_223_372_036_854_770_000,
        "controller_epoch": 2_147_483_647,
        "tree_sha": "c" * 40,
        "source_digest": "d" * 64,
        "request_digest": "e" * 64,
        "migration_head": CANONICAL_ALEMBIC_HEAD,
        "authority_version": 2_147_483_647,
        "evidence_digest": "f" * 64,
        "result_digest": "0" * 64,
    }
    expected = terra_receipt_database_digest(payload)
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT encode(digest(convert_to(%s::jsonb::text, 'UTF8'), 'sha256'), 'hex')",
                (json.dumps(payload, ensure_ascii=False),),
            )
            assert cur.fetchone()[0] == expected


def _run_cycle(workflow: LongspanWorkflow, run_id: str, **kwargs) -> object:
    terra_auth = _terra_auth(kwargs.get("terra_auth_token", TERRA_TOKEN))
    parent_task, pending = workflow.run_until_terra_pending(
        run_id,
        "worker",
        request_digest=kwargs.get("request_digest", digest_payload({"run": run_id})),
        plan_producer=kwargs.get("plan_producer", default_plan_producer),
        task_handler=kwargs.get("task_handler", default_task_handler),
        inspector=kwargs.get("inspector", default_inspector),
    )
    if pending is None:
        return workflow.parent.task(parent_task.task_id)
    decision = kwargs.get("terra_decision", "approved")
    if decision != "approved":
        terra_auth.register_receipt(
            workflow.repo,
            workflow.parent,
            child_id=pending.child_id,
            reviewer=kwargs.get("terra_reviewer", "terra-review"),
            decision=decision,
            evidence_chain_head=pending.ledger_head,
        )
        workflow.remediate_rejected_child(
            child_id=pending.child_id,
            parent_task=parent_task,
            parent_attempt_id=pending.parent_attempt_id,
            fence_token=pending.fence_token,
            reason="terra-rejected",
        )
        workflow.parent.retry_task(
            run_id,
            parent_task.task_id,
            parent_task.generation or "",
            "terra-rejected",
        )
        return workflow.parent.task(parent_task.task_id)
    terra_auth.register_receipt(
        workflow.repo,
        workflow.parent,
        child_id=pending.child_id,
        reviewer=kwargs.get("terra_reviewer", "terra-review"),
        decision="approved",
        evidence_chain_head=pending.ledger_head,
    )
    return workflow.finish_cycle_after_terra(pending)


def test_longspan_deterministic_cycle_complete(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "longspan child work")
    result = _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "task-1"}),
    )
    assert result is not None and result.state == "verified"
    with workflow.parent._repo.transaction() as cur:
        cur.execute("SELECT child_id FROM longspan_children WHERE task_id = %s", ("task-1",))
        child_id = cur.fetchone()["child_id"]
    child = workflow.repo.get_child(child_id)
    assert child["state"] == "parent_returned"
    auditor_snapshot = workflow.repo.get_auditor_snapshot(
        child_id, int(child["attempt_number"])
    )
    assert auditor_snapshot["transaction_isolation"] == "repeatable read"
    assert auditor_snapshot["child"]["request_digest"] == child["request_digest"]
    assert workflow.repo.get_auditor_receipt(child_id, int(child["attempt_number"]))["verdict"] == "pass"
    assert (
        workflow.repo.get_terra_receipt(child_id, int(child["attempt_number"]))["decision"]
        == "approved"
    )
    receipt = workflow.repo.get_terra_receipt(child_id, int(child["attempt_number"]))
    assert receipt["authority_signature"].startswith("v1:")
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            """
            SELECT encode(digest((jsonb_build_object(
                'child_id', receipt.child_id,
                'attempt_number', receipt.attempt_number,
                'reviewer', receipt.reviewer,
                'decision', receipt.decision,
                'evidence_chain_head', receipt.evidence_chain_head,
                'run_id', receipt.run_id,
                'task_id', receipt.task_id,
                'reviewed_sha', receipt.reviewed_sha,
                'fence_token', receipt.fence_token,
                'controller_epoch', receipt.controller_epoch,
                'tree_sha', receipt.tree_sha,
                'source_digest', receipt.source_digest,
                'request_digest', receipt.request_digest,
                'migration_head', receipt.migration_head,
                'authority_version', receipt.authority_version,
                'evidence_digest', receipt.evidence_digest,
                'result_digest', receipt.result_digest
            ))::text, 'sha256'), 'hex') AS expected_digest
            FROM longspan_terra_receipts AS receipt
            WHERE receipt.child_id = %s
              AND receipt.attempt_number = %s
            """,
            (child_id, int(child["attempt_number"])),
        )
        expected_digest = cur.fetchone()["expected_digest"]
    expected_signature = hmac.new(
        TEST_TERRA_GATEWAY_MAC.encode("utf-8"),
        f"top_delivery:terra_receipt:v1:{expected_digest}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert receipt["receipt_digest"] == expected_digest
    assert receipt["signature"] == expected_signature
    ok, issues = workflow.repo.verify_ledger_chain(child_id)
    assert ok and not issues
    workflow.close()


def test_approved_terra_receipt_rechecks_gateway_mac_and_attestation(
    db_url: str, artifact_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid Ed25519 prefix cannot bypass the stored DB witness on read."""
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-receipt-read-binding")
    _seed_ready_parent(workflow.parent, "run-receipt-read-binding", artifact_root)
    _provision_authority(workflow, "run-receipt-read-binding")
    workflow.parent.schedule_task(
        "run-receipt-read-binding", "task-receipt-read-binding", "receipt read binding"
    )
    parent_task, pending = workflow.run_until_terra_pending(
        "run-receipt-read-binding",
        "worker",
        request_digest=digest_payload({"task": "receipt-read-binding"}),
        plan_producer=default_plan_producer,
        task_handler=default_task_handler,
        inspector=default_inspector,
    )
    assert pending is not None
    _terra_auth().register_receipt(
        workflow.repo,
        workflow.parent,
        child_id=pending.child_id,
        reviewer="terra-review",
        decision="approved",
        evidence_chain_head=pending.ledger_head,
    )
    receipt = workflow.repo.get_terra_receipt(
        pending.child_id, pending.attempt_number
    )
    components = terra_receipt_signature_components(receipt["authority_signature"])
    assert components is not None
    _external, _gateway_mac, attestation_id = components
    forged_signature = f"{_external}:{'0' * 64}:{attestation_id}"
    original_get_receipt = workflow.repo.get_terra_receipt

    def forged_get_receipt(child_id: str, attempt_number: int) -> dict[str, object]:
        stored = dict(original_get_receipt(child_id, attempt_number))
        stored["authority_signature"] = forged_signature
        return stored

    # The production receipt table is append-only, so a read-path forgery is
    # injected at the repository boundary rather than weakening the database
    # trigger merely to construct a test fixture.
    monkeypatch.setattr(workflow.repo, "get_terra_receipt", forged_get_receipt)
    with pytest.raises(IntegrityFailureError, match="gateway proof|authority"):
        workflow.finish_cycle_after_terra(pending)
    workflow.close()


def test_approved_terra_receipt_rejects_forged_attestation_id(
    db_url: str, artifact_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid external signature cannot claim a different persisted witness."""
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-receipt-attestation-id")
    _seed_ready_parent(workflow.parent, "run-receipt-attestation-id", artifact_root)
    _provision_authority(workflow, "run-receipt-attestation-id")
    workflow.parent.schedule_task(
        "run-receipt-attestation-id", "task-receipt-attestation-id", "receipt id binding"
    )
    parent_task, pending = workflow.run_until_terra_pending(
        "run-receipt-attestation-id",
        "worker",
        request_digest=digest_payload({"task": "receipt-attestation-id"}),
        plan_producer=default_plan_producer,
        task_handler=default_task_handler,
        inspector=default_inspector,
    )
    assert pending is not None
    _terra_auth().register_receipt(
        workflow.repo,
        workflow.parent,
        child_id=pending.child_id,
        reviewer="terra-review",
        decision="approved",
        evidence_chain_head=pending.ledger_head,
    )
    original_get_receipt = workflow.repo.get_terra_receipt

    def forged_get_receipt(child_id: str, attempt_number: int) -> dict[str, object]:
        stored = dict(original_get_receipt(child_id, attempt_number))
        external, gateway_mac, _attestation_id = terra_receipt_signature_components(
            stored["authority_signature"]
        ) or (None, None, None)
        assert external is not None and gateway_mac is not None
        # verify_terra_receipt_signature intentionally authenticates only the
        # external Ed25519 prefix; the authority boundary must bind this extra
        # segment back to the persisted witness.
        stored["authority_signature"] = f"{external}:{gateway_mac}:{'f' * 32}"
        return stored

    monkeypatch.setattr(workflow.repo, "get_terra_receipt", forged_get_receipt)
    with pytest.raises(IntegrityFailureError, match="gateway proof|authority|attestation"):
        workflow.finish_cycle_after_terra(pending)
    workflow.close()


def test_parent_return_replay_is_idempotent_and_epoch_fenced(
    db_url: str, artifact_root: Path
) -> None:
    """A completed return is single-shot and old fences fail after rollback."""
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-replay")
    _seed_ready_parent(workflow.parent, "run-replay", artifact_root)
    _provision_authority(workflow, "run-replay")
    workflow.parent.schedule_task("run-replay", "task-replay", "replay proof")
    parent_task, pending = workflow.run_until_terra_pending(
        "run-replay",
        "worker",
        request_digest=digest_payload({"task": "task-replay"}),
        plan_producer=default_plan_producer,
        task_handler=default_task_handler,
        inspector=default_inspector,
    )
    assert pending is not None
    _terra_auth().register_receipt(
        workflow.repo,
        workflow.parent,
        child_id=pending.child_id,
        reviewer="terra-replay-test",
        decision="approved",
        evidence_chain_head=pending.ledger_head,
    )
    first = workflow.finish_cycle_after_terra(pending)
    assert first.state == "verified"

    replay = workflow.return_to_parent(
        child_id=pending.child_id,
        parent_generation=pending.parent_generation,
        parent_attempt_id=pending.parent_attempt_id,
        fence_token=pending.fence_token,
    )
    assert replay.state == "verified"
    entries = workflow.repo.ledger_entries(pending.child_id)
    assert sum(entry["event_type"] == "parent_return" for entry in entries) == 1

    # A later attempt for the same task must not make an old completed child
    # look replayable merely because the parent has the same terminal state.
    later_attempt_id = "later-parent-attempt"
    with workflow.parent._repo.transaction() as cur:
        cur.execute(
            """
            INSERT INTO task_attempts
                (attempt_id, task_id, run_id, fence_token, controller_epoch,
                 owner, status, heartbeat_at, lease_expires_at, ended_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'verified', clock_timestamp(),
                    clock_timestamp(), clock_timestamp())
            """,
            (later_attempt_id, "task-replay", "run-replay", 999, 7, "later-worker"),
        )
        cur.execute(
            "UPDATE parent_tasks SET active_attempt_id = %s WHERE task_id = %s",
            (later_attempt_id, "task-replay"),
        )
    try:
        with pytest.raises(PermissionError, match="parent task missing"):
            workflow.return_to_parent(
                child_id=pending.child_id,
                parent_generation=pending.parent_generation,
                parent_attempt_id=pending.parent_attempt_id,
                fence_token=pending.fence_token,
            )
    finally:
        with workflow.parent._repo.transaction() as cur:
            cur.execute(
                "UPDATE parent_tasks SET active_attempt_id = %s WHERE task_id = %s",
                (pending.parent_attempt_id, "task-replay"),
            )
            cur.execute(
                "DELETE FROM task_attempts WHERE attempt_id = %s AND task_id = %s",
                (later_attempt_id, "task-replay"),
            )

    old_epoch = workflow.parent.controller_epoch("run-replay")
    assert workflow.parent.rollback("run-replay") > old_epoch
    with pytest.raises(PermissionError):
        workflow.return_to_parent(
            child_id=pending.child_id,
            parent_generation=pending.parent_generation,
            parent_attempt_id=pending.parent_attempt_id,
            fence_token=pending.fence_token,
        )
    entries_after_rollback = workflow.repo.ledger_entries(pending.child_id)
    assert sum(
        entry["event_type"] == "parent_return" for entry in entries_after_rollback
    ) == 1
    workflow.close()


def test_authority_write_challenge_is_content_bound_and_single_use(
    db_url: str, artifact_root: Path
) -> None:
    from urllib.parse import quote, urlsplit

    from authority_pins import AUTHORITY_DATABASE_ROLE

    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-authority-replay")
    _provision_authority(workflow, "run-authority-replay")
    database_name = urlsplit(db_url).path.lstrip("/")
    auth_url = (
        f"postgresql://{AUTHORITY_DATABASE_ROLE}:{quote('td-authority-test')}"
        f"@127.0.0.1/{database_name}"
    )
    with psycopg2.connect(auth_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT approval_id, action_digest, write_binding_digest, config_version
                FROM longspan_operator_challenges
                WHERE run_id = %s
                """,
                ("run-authority-replay",),
            )
            challenge = cur.fetchone()
            cur.execute(
                """
                SELECT terra_auth_hash, operator_auth_hash, reviewed_sha, tree_sha,
                       source_digest, config_version, approval_receipt_digest
                FROM longspan_authority_config
                WHERE run_id = %s
                """,
                ("run-authority-replay",),
            )
            config = cur.fetchone()
            assert challenge is not None and config is not None
            with pytest.raises(psycopg2.Error, match="content digest"):
                cur.execute(
                    """
                    SELECT * FROM longspan_insert_authority_config(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        "run-authority-replay",
                        config[0],
                        "tampered-operator-hash",
                        config[2],
                        config[3],
                        config[4],
                        int(config[5]),
                        config[6],
                        challenge[0],
                        challenge[1],
                        challenge[2],
                    ),
                )
            conn.rollback()
            with pytest.raises(psycopg2.Error, match="already been applied"):
                cur.execute(
                    """
                    SELECT * FROM longspan_insert_authority_config(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        "run-authority-replay",
                        config[0],
                        config[1],
                        config[2],
                        config[3],
                        config[4],
                        int(config[5]),
                        config[6],
                        challenge[0],
                        challenge[1],
                        challenge[2],
                    ),
                )
    workflow.close()


def test_parent_return_refused_without_provenance(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    workflow.parent.schedule_task("run-1", "task-1", "needs provenance")
    with pytest.raises(AuthorizationFailureError, match="provenance"):
        workflow.run_until_terra_pending(
            "run-1",
            "worker",
            request_digest=digest_payload({"task": "no-prov"}),
            plan_producer=default_plan_producer,
            task_handler=default_task_handler,
            inspector=default_inspector,
        )
    workflow.close()


def test_executor_cannot_mark_parent_complete_without_receipts(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    workflow.parent.schedule_task("run-1", "task-1", "blocked completion")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _created = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "blocked"}),
    )
    with pytest.raises(PermissionError):
        workflow.return_to_parent(
            child_id=child["child_id"],
            parent_generation=claimed.generation or "",
            parent_attempt_id=attempt_id,
            fence_token=fence,
        )
    workflow.close()


def test_executor_capability_cannot_write_auditor_receipt(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "role separation")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _created = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "roles"}),
    )
    plan = workflow.manager.create_plan(
        child=child,
        capabilities=capabilities,
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        producer=default_plan_producer,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
    )
    workflow.executor.execute(
        child=workflow.repo.get_child(child["child_id"]),
        capabilities=capabilities,
        plan=plan,
        verified_evidence=(),
        handler=default_task_handler,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
        run_id="run-1",
    )
    child = workflow.repo.get_child(child["child_id"])
    with pytest.raises(AuthorizationFailureError):
        workflow.repo.store_auditor_receipt(
            child_id=child["child_id"],
            expected_version=int(child["version"]),
            attempt_number=int(child["attempt_number"]),
            verdict="pass",
            reasons=[],
            inspector_digest="abc",
            evidence_digest="evidence-digest",
            receipt_digest="def",
            auditor_capability_token=capabilities.executor_token,
            parent_attempt_id=attempt_id,
            fence_token=fence,
            controller_epoch=workflow.parent.controller_epoch("run-1"),
            run_id="run-1",
        )
    workflow.close()


def test_duplicate_idempotency_key_returns_existing_child(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    workflow.parent.schedule_task("run-1", "task-1", "dup")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    digest = digest_payload({"task": "dup"})
    idem = child_idempotency_key("task-1", attempt_id, 0)
    first, cap1, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=idem,
        request_digest=digest,
    )
    with pytest.raises(PermissionError):
        workflow.register_child_for_task(
            parent_task=claimed,
            parent_attempt_id=attempt_id,
            fence_token=fence,
            idempotency_key=idem,
            request_digest=digest,
        )
    workflow.close()


def test_stale_longspan_lease_rejects_writes(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "stale")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "stale"}),
    )
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            "UPDATE longspan_children SET lease_expires_at = clock_timestamp() - interval '1 second' "
            "WHERE child_id = %s",
            (child["child_id"],),
        )
    original_idempotency_key = child["idempotency_key"]
    with pytest.raises(LeaseExpiredError):
        workflow.manager.create_plan(
            child=child,
            capabilities=capabilities,
            parent_task=claimed,
            parent_attempt_id=attempt_id,
            fence_token=fence,
            producer=default_plan_producer,
            controller_epoch=workflow.parent.controller_epoch("run-1"),
        )
    expired = workflow.expire_stale("run-1")
    assert child["child_id"] in expired
    expired_child = workflow.repo.get_child(child["child_id"])
    assert expired_child["idempotency_key"] != original_idempotency_key
    workflow.close()


def test_retry_wait_resume_completes_cycle(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "resume")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, _capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "resume"}),
    )
    with workflow.repo.repo.transaction() as cur:
        cur.execute(
            "UPDATE longspan_children SET lease_expires_at = clock_timestamp() - interval '1 second' "
            "WHERE child_id = %s",
            (child["child_id"],),
        )
    workflow.expire_stale("run-1")
    child = workflow.repo.get_child(child["child_id"])
    assert child["state"] == "retry_wait"
    assert int(child["attempt_number"]) == 1
    child, capabilities = workflow.resume_retry_child(
        child_id=child["child_id"],
        parent_attempt_id=attempt_id,
        fence_token=fence,
    )
    plan = workflow.manager.create_plan(
        child=child,
        capabilities=capabilities,
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        producer=default_plan_producer,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
    )
    workflow.executor.execute(
        child=workflow.repo.get_child(child["child_id"]),
        capabilities=capabilities,
        plan=plan,
        verified_evidence=tuple(workflow.parent.evidence("run-1")),
        handler=default_task_handler,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
        run_id="run-1",
    )
    child = workflow.repo.get_child(child["child_id"])
    child, audit_caps = workflow._issue_audit_capabilities(
        child=child,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
        run_id="run-1",
    )
    verdict = workflow.auditor.audit(
        child=child,
        capabilities=audit_caps,
        plan=plan,
        verified_evidence=tuple(workflow.parent.evidence("run-1")),
        inspector=default_inspector,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
        run_id="run-1",
    )
    assert verdict.verdict == "pass"
    entries = workflow.repo.ledger_entries(child["child_id"])
    terra_auth = _terra_auth()
    terra_auth.register_receipt(
        workflow.repo,
        workflow.parent,
        child_id=child["child_id"],
        reviewer="terra-review",
        decision="approved",
        evidence_chain_head=entries[-1]["entry_hash"],
    )
    workflow.return_to_parent(
        child_id=child["child_id"],
        parent_generation=claimed.generation or "",
        parent_attempt_id=attempt_id,
        fence_token=fence,
    )
    workflow.close()


def test_auditor_failure_retries_parent_task(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "audit fail")

    def failing_inspector(**kwargs):
        from longspan import AuditorVerdict

        return AuditorVerdict(
            verdict="fail",
            reasons=("injected-failure",),
            inspector_digest="deadbeef",
        )

    result = _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "audit-fail"}),
        inspector=failing_inspector,
    )
    assert result is not None
    assert result.state == "queued"
    workflow.close()


def test_terra_rejection_retries_parent_task(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "terra reject")
    result = _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "terra-reject"}),
        terra_decision="rejected",
    )
    assert result is not None
    assert result.state == "queued"
    workflow.close()


def test_unauthenticated_terra_token_rejected(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "bad terra")
    _parent_task, pending = workflow.run_until_terra_pending(
        "run-1",
        "worker",
        request_digest=digest_payload({"task": "bad-terra"}),
        plan_producer=default_plan_producer,
        task_handler=default_task_handler,
        inspector=default_inspector,
    )
    assert pending is not None
    child = workflow.repo.get_child(pending.child_id)
    with pytest.raises(PermissionError, match="terra review auth token"):
        workflow.repo.store_terra_receipt(
            child_id=pending.child_id,
            expected_version=int(child["version"]),
            attempt_number=pending.attempt_number,
            reviewer="terra-review",
            decision="approved",
            evidence_chain_head=pending.ledger_head,
            terra_auth_token="forged-token",
            parent_attempt_id=child["parent_attempt_id"],
            fence_token=int(child["fence_token"]),
            controller_epoch=workflow.parent.controller_epoch("run-1"),
            run_id="run-1",
        )
    forged_token = "self-consistent-forged"
    with pytest.raises(PermissionError, match="terra review auth token"):
        workflow.repo.store_terra_receipt(
            child_id=pending.child_id,
            expected_version=int(child["version"]),
            attempt_number=pending.attempt_number,
            reviewer="terra-review",
            decision="approved",
            evidence_chain_head=pending.ledger_head,
            terra_auth_token=forged_token,
            parent_attempt_id=child["parent_attempt_id"],
            fence_token=int(child["fence_token"]),
            controller_epoch=workflow.parent.controller_epoch("run-1"),
            run_id="run-1",
        )
    workflow.close()


def test_forged_external_terra_signature_rejected(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-forged-terra-signature")
    _seed_ready_parent(workflow.parent, "run-forged-terra-signature", artifact_root)
    _provision_authority(workflow, "run-forged-terra-signature")
    workflow.parent.schedule_task(
        "run-forged-terra-signature", "task-forged-terra-signature", "forged receipt"
    )
    _parent_task, pending = workflow.run_until_terra_pending(
        "run-forged-terra-signature",
        "worker",
        request_digest=digest_payload({"task": "forged-terra-signature"}),
        plan_producer=default_plan_producer,
        task_handler=default_task_handler,
        inspector=default_inspector,
    )
    assert pending is not None
    child = workflow.repo.get_child(pending.child_id)
    with pytest.raises(PermissionError, match="external authority signature"):
        workflow.repo.store_terra_receipt(
            child_id=pending.child_id,
            expected_version=int(child["version"]),
            attempt_number=pending.attempt_number,
            reviewer="terra-review",
            decision="approved",
            evidence_chain_head=pending.ledger_head,
            terra_auth_token=TERRA_TOKEN,
            parent_attempt_id=child["parent_attempt_id"],
            fence_token=int(child["fence_token"]),
            controller_epoch=workflow.parent.controller_epoch(
                "run-forged-terra-signature"
            ),
            run_id="run-forged-terra-signature",
            authority_signature="v1:forged-signature",
        )
    workflow.close()


def test_direct_sql_terra_append_requires_authority_attestation(
    db_url: str, artifact_root: Path
) -> None:
    """A valid workflow capability and gateway MAC cannot mint the Ed witness."""
    workflow = _workflow(db_url, artifact_root)
    run_id = "run-direct-sql-terra-attestation"
    workflow.parent.register_run(run_id)
    _seed_ready_parent(workflow.parent, run_id, artifact_root)
    _provision_authority(workflow, run_id)
    workflow.parent.schedule_task(run_id, "task-direct-sql", "direct SQL receipt")
    _parent_task, pending = workflow.run_until_terra_pending(
        run_id,
        "worker",
        request_digest=digest_payload({"task": "direct-sql"}),
        plan_producer=default_plan_producer,
        task_handler=default_task_handler,
        inspector=default_inspector,
    )
    assert pending is not None
    child = workflow.repo.get_child(pending.child_id)
    authority = workflow.repo.get_authority_config(run_id)
    auditor = workflow.repo.get_auditor_receipt(pending.child_id, pending.attempt_number)
    execution = workflow.repo.get_execution_result(pending.child_id, pending.attempt_number)
    epoch = workflow.parent.controller_epoch(run_id)
    payload = {
        "child_id": pending.child_id,
        "attempt_number": pending.attempt_number,
        "reviewer": "terra-review",
        "decision": "approved",
        "evidence_chain_head": pending.ledger_head,
        "run_id": run_id,
        "task_id": child["task_id"],
        "reviewed_sha": authority["reviewed_sha"],
        "fence_token": int(child["fence_token"]),
        "controller_epoch": epoch,
        "tree_sha": authority["tree_sha"],
        "source_digest": authority["source_digest"],
        "request_digest": child["request_digest"],
        "migration_head": CANONICAL_ALEMBIC_HEAD,
        "authority_version": int(authority["config_version"]),
        "evidence_digest": auditor["evidence_digest"],
        "result_digest": execution["result_digest"],
    }
    external = sign_terra_receipt(payload, terra_private_key_for_tests())
    wrong_head_payload = {**payload, "evidence_chain_head": "0" * 64}
    wrong_head_signature = sign_terra_receipt(
        wrong_head_payload, terra_private_key_for_tests()
    )
    with pytest.raises(PermissionError, match="evidence|head|binding"):
        workflow.repo.store_terra_receipt(
            child_id=pending.child_id,
            expected_version=int(child["version"]),
            attempt_number=pending.attempt_number,
            reviewer="terra-review",
            decision="approved",
            evidence_chain_head=wrong_head_payload["evidence_chain_head"],
            terra_auth_token=TERRA_TOKEN,
            parent_attempt_id=child["parent_attempt_id"],
            fence_token=int(child["fence_token"]),
            controller_epoch=epoch,
            run_id=run_id,
            authority_signature=wrong_head_signature,
        )
    # The direct-SQL forgery proof must reach the attestation guard rather
    # than fail earlier because this deliberately slow test let the short
    # disposable parent lease expire.
    workflow.parent.heartbeat(
        pending.parent_task.task_id,
        pending.parent_generation,
    )
    from authority_repository import AuthorityRepository
    authority_repo = AuthorityRepository.from_url(_authority_url_for_database(db_url))
    try:
        first_attestation = authority_repo.issue_terra_receipt_attestation(
            receipt_payload=payload,
            external_signature=external,
        )
        replayed_attempt_payload = {
            **payload,
            "attempt_number": int(payload["attempt_number"]) + 1,
        }
        with pytest.raises(Exception, match="attestation|signature|binding|attempt"):
            authority_repo.issue_terra_receipt_attestation(
                receipt_payload=replayed_attempt_payload,
                external_signature=external,
            )
        retry_attestation = authority_repo.issue_terra_receipt_attestation(
            receipt_payload=payload,
            external_signature=external,
        )
        assert retry_attestation == first_attestation
    finally:
        authority_repo.close()
    # The authority principal can issue through the SECURITY DEFINER routine,
    # but cannot use the session GUC to write the witness table directly.
    with psycopg2.connect(_authority_url_for_database(db_url)) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error, match="permission denied"):
                cur.execute(
                    "UPDATE longspan_terra_receipt_attestations "
                    "SET invalidation_reason = 'forged' WHERE false"
                )
            conn.rollback()
    # The workflow role is also denied even if a caller sets the transaction
    # GUC that the consume routine uses. A permitted consumption transition
    # must come only from the SECURITY DEFINER routine, never direct SQL.
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('top_delivery.attestation_routine', '1', true)"
            )
            with pytest.raises(psycopg2.Error, match="permission denied"):
                cur.execute(
                    "UPDATE longspan_terra_receipt_attestations "
                    "SET invalidation_reason = 'forged' WHERE false"
                )
            conn.rollback()
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('top_delivery.controller_epoch', %s, true)", (str(epoch),))
            with pytest.raises(psycopg2.Error, match="permission denied"):
                cur.execute(
                    "SELECT longspan_terra_gateway_mac(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        payload["child_id"], payload["attempt_number"], payload["reviewer"],
                        payload["decision"], payload["evidence_chain_head"], payload["run_id"],
                        payload["task_id"], payload["reviewed_sha"], payload["fence_token"],
                        payload["controller_epoch"], payload["tree_sha"], payload["source_digest"],
                        payload["request_digest"], payload["migration_head"],
                        payload["authority_version"], payload["evidence_digest"],
                        payload["result_digest"], TERRA_TOKEN,
                    ),
                )
    with psycopg2.connect(_authority_url_for_database(db_url)) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT longspan_terra_gateway_mac_for_attestation(%s)",
                (first_attestation,),
            )
            gateway = cur.fetchone()[0]
    # A stale/mutated append must not accidentally consume the attestation
    # before the caller has a chance to clean it up.  The authority boundary
    # then explicitly retires the orphaned witness, so it cannot later
    # authorize an append.
    workflow.parent.heartbeat(
        pending.parent_task.task_id,
        pending.parent_generation,
    )
    bad_payload = {**payload, "result_digest": "0" * 64}
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('top_delivery.controller_epoch', %s, true)",
                (str(epoch),),
            )
            with pytest.raises(psycopg2.Error, match="attestation|result|binding"):
                cur.execute(
                    """
                    SELECT longspan_append_terra_receipt(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        uuid.uuid4().hex, bad_payload["child_id"], bad_payload["attempt_number"],
                        bad_payload["reviewer"], bad_payload["decision"], bad_payload["evidence_chain_head"],
                        None, bad_payload["run_id"], bad_payload["task_id"], bad_payload["reviewed_sha"],
                        bad_payload["fence_token"], bad_payload["controller_epoch"], bad_payload["tree_sha"],
                        bad_payload["source_digest"], bad_payload["request_digest"], bad_payload["migration_head"],
                        bad_payload["authority_version"], bad_payload["evidence_digest"], bad_payload["result_digest"],
                        f"{external}:{gateway}:{first_attestation}", TERRA_TOKEN,
                    ),
                )
                conn.rollback()
    authority_repo = AuthorityRepository.from_url(_authority_url_for_database(db_url))
    try:
        signature_digest = hashlib.sha256(
            external.split(":", 1)[1].encode("utf-8")
        ).hexdigest()
        authority_repo.invalidate_terra_receipt_attestation(
            attestation_id=first_attestation,
            run_id=payload["run_id"],
            child_id=payload["child_id"],
            attempt_number=payload["attempt_number"],
            signature_digest=signature_digest,
        )
        authority_repo.invalidate_terra_receipt_attestation(
            attestation_id=first_attestation,
            run_id=payload["run_id"],
            child_id=payload["child_id"],
            attempt_number=payload["attempt_number"],
            signature_digest=signature_digest,
        )
    finally:
        authority_repo.close()
    # The exact populated invalidated-witness state is not an in-place
    # downgrade target. The outer Alembic guard must reject it before 008 can
    # drop the repair columns.
    database_name = urlsplit(db_url).path.lstrip("/")
    root_url = (
        f"postgresql://root@/{database_name}?host=%2Fvar%2Frun%2Fpostgresql&port=5432"
    )
    install_downgrade_capability(
        database_name=database_name,
        migration_revision="007_longspan_authority_hardening",
        database_role="top_delivery_migration",
    )
    with pytest.raises(subprocess.CalledProcessError) as downgrade_error:
        alembic_command(root_url, "downgrade", "007_longspan_authority_hardening")
    assert "populated Longspan evidence" in (downgrade_error.value.stderr or "")
    assert current_database_revision(root_url) == CANONICAL_ALEMBIC_HEAD
    with psycopg2.connect(_authority_url_for_database(db_url)) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.Error, match="consumed|unknown|expired|invalidated"):
                cur.execute(
                    "SELECT longspan_terra_gateway_mac_for_attestation(%s)",
                    (first_attestation,),
                )
    workflow.parent.heartbeat(
        pending.parent_task.task_id,
        pending.parent_generation,
    )
    with psycopg2.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('top_delivery.controller_epoch', %s, true)",
                (str(epoch),),
            )
            envelope = f"{external}:{gateway}:authority-service-must-issue"
            with pytest.raises(psycopg2.Error, match="attestation"):
                cur.execute(
                    """
                    SELECT longspan_append_terra_receipt(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        uuid.uuid4().hex, payload["child_id"], payload["attempt_number"],
                        payload["reviewer"], payload["decision"], payload["evidence_chain_head"],
                        None, payload["run_id"], payload["task_id"], payload["reviewed_sha"],
                        payload["fence_token"], payload["controller_epoch"], payload["tree_sha"],
                        payload["source_digest"], payload["request_digest"],
                        payload["migration_head"], payload["authority_version"],
                        payload["evidence_digest"], payload["result_digest"], envelope,
                        TERRA_TOKEN,
                    ),
                )
                conn.rollback()
    workflow.close()


def test_forged_ledger_insert_detected(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "forge")
    _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "forge"}),
    )
    with workflow.parent._repo.transaction() as cur:
        cur.execute("SELECT child_id FROM longspan_children WHERE task_id = %s", ("task-1",))
        child_id = cur.fetchone()["child_id"]
    with pytest.raises(psycopg2.Error):
        with workflow.parent._repo.transaction() as cur:
            cur.execute(
                """
                INSERT INTO longspan_evidence_ledger
                    (entry_id, child_id, attempt_number, sequence_number, event_type,
                     producer_role, payload_digest, previous_entry_hash, entry_hash)
                VALUES ('forged', %s, 0, 999, 'forged', 'parent', 'bad', NULL, 'deadbeef')
                """,
                (child_id,),
            )
    ok, issues = workflow.repo.verify_ledger_chain(child_id)
    assert ok or any("hash-mismatch" in issue or "sequence-gap" in issue for issue in issues)
    workflow.close()


def test_ledger_update_and_truncate_rejected(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "truncate")
    _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "truncate"}),
    )
    with workflow.parent._repo.transaction() as cur:
        cur.execute("SELECT child_id FROM longspan_children WHERE task_id = %s", ("task-1",))
        child_id = cur.fetchone()["child_id"]
    with pytest.raises(psycopg2.Error):
        with workflow.parent._repo.transaction() as cur:
            cur.execute(
                "UPDATE longspan_evidence_ledger SET payload_digest = 'tampered' WHERE child_id = %s",
                (child_id,),
            )
    with pytest.raises(psycopg2.Error):
        with workflow.parent._repo.transaction() as cur:
            cur.execute("TRUNCATE longspan_evidence_ledger")
    workflow.close()


def test_rollback_parks_longspan_children(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    workflow.parent.schedule_task("run-1", "task-1", "rollback")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, _capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "rollback"}),
    )
    workflow.parent.rollback("run-1")
    parked = workflow.repo.get_child(child["child_id"])
    assert parked["state"] == "parked"
    workflow.close()


def test_rollback_fails_closed_when_parking_incomplete(
    db_url: str, artifact_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    workflow.parent.schedule_task("run-1", "task-1", "rollback-fail")

    from repository import PostgresRepository

    def fail_rollback(self, run_id: str, *, expected_epoch: int) -> int:
        raise PermissionError("longspan child parking incomplete")

    monkeypatch.setattr(PostgresRepository, "rollback_disable", fail_rollback)
    with pytest.raises(PermissionError):
        workflow.parent.rollback("run-1")
    workflow.close()


def test_experiment_adoption_requires_operator_and_auditor_receipt(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _provision_authority(workflow, "run-1")
    experiment = workflow.record_experiment(
        run_id="run-1",
        child_id=None,
        hypothesis="Improve retry diagnostics",
        baseline="current retry logging",
        scope="comms-01",
        predicted_benefit="faster stale-worker triage",
        rollback_plan="revert playbook entry",
        classification="playbook",
    )
    with pytest.raises(PermissionError):
        workflow.repo.adopt_experiment(
            experiment_id=experiment["experiment_id"],
            evidence_digest=digest_payload({"ok": True}),
            auditor_receipt_id="missing",
            operator_auth_token="",
            adoption_decision="accepted",
            state="accepted",
            run_id="run-1",
            controller_epoch=workflow.parent.controller_epoch("run-1"),
        )
    with pytest.raises(PermissionError):
        workflow.record_experiment(
            run_id="run-1",
            child_id=None,
            hypothesis="change authority gates",
            baseline="noop",
            scope="comms-01",
            predicted_benefit="noop",
            rollback_plan="noop",
            classification="workflow",
        )
    workflow.close()


def test_migration_upgrade_downgrade_reupgrade() -> None:
    name, url = _create_test_database(f"td_downgrade_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="004_longspan_workflow"
    )
    try:
        run_migrations(url)
        alembic_command(url, "downgrade", "004_longspan_workflow")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT p.pronargs, pg_get_function_identity_arguments(p.oid)
                    FROM pg_proc AS p
                    JOIN pg_namespace AS n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'public'
                      AND p.proname = 'longspan_append_auditor_receipt'
                    ORDER BY pg_get_function_identity_arguments(p.oid)
                    """
                )
                signatures = cur.fetchall()
        # The 006 -> 005 boundary removes the compatibility routine restored
        # transiently by 007 -> 006; neither legacy overload belongs to 004.
        assert signatures == []
        alembic_command(url, "upgrade", "head")
    finally:
        _drop_test_database(name)


def test_downgrade_requires_signed_capability() -> None:
    name, url = _create_test_database(f"td_downgrade_{uuid.uuid4().hex}")
    try:
        run_migrations(url)
        with pytest.raises(AuthorizationFailureError):
            alembic_command(url, "downgrade", "004_longspan_workflow")
    finally:
        _drop_test_database(name)


def test_fresh_executor_context_excludes_manager_state(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "fresh context")
    seen: list[str] = []

    class TrackingHandler:
        def __call__(self, context):
            seen.append(context.plan.objective)
            assert not hasattr(context, "manager_notes")
            return default_task_handler(context)

    _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "fresh"}),
        task_handler=TrackingHandler(),
    )
    assert seen == ["fresh context"]
    workflow.close()


def test_parent_cleanup_after_longspan_cycle(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "cleanup")
    _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "cleanup"}),
    )
    with workflow.parent._repo.transaction() as cur:
        cur.execute(
            "SELECT state FROM parent_tasks WHERE task_id = %s",
            ("task-1",),
        )
        assert cur.fetchone()["state"] == "verified"
    workflow.close()


def test_handler_failure_records_retry_wait(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "handler fail")

    def boom(_context):
        raise RuntimeError("injected handler failure")

    with pytest.raises(RuntimeError):
        _run_cycle(
            workflow,
            "run-1",
            request_digest=digest_payload({"task": "handler-fail"}),
            task_handler=boom,
        )
    with workflow.parent._repo.transaction() as cur:
        cur.execute("SELECT state, attempt_number FROM longspan_children WHERE task_id = %s", ("task-1",))
        row = cur.fetchone()
        assert row["state"] == "retry_wait"
        assert int(row["attempt_number"]) == 1
    workflow.close()


def test_db_readable_hash_cannot_replay_capability(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "hash replay")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "hash-replay"}),
    )
    stored = workflow.repo.get_child(child["child_id"])
    with pytest.raises(AuthorizationFailureError):
        workflow.repo.verify_capability_token(
            stored, "manager", stored["manager_capability_hash"]
        )
    workflow.close()


def test_cross_role_capability_forgery_rejected(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "cross role")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "cross-role"}),
    )
    plan = workflow.manager.create_plan(
        child=child,
        capabilities=capabilities,
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        producer=default_plan_producer,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
    )
    workflow.executor.execute(
        child=workflow.repo.get_child(child["child_id"]),
        capabilities=capabilities,
        plan=plan,
        verified_evidence=(),
        handler=default_task_handler,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
        run_id="run-1",
    )
    child = workflow.repo.get_child(child["child_id"])
    with pytest.raises(AuthorizationFailureError):
        workflow.repo.store_auditor_receipt(
            child_id=child["child_id"],
            expected_version=int(child["version"]),
            attempt_number=int(child["attempt_number"]),
            verdict="pass",
            reasons=[],
            inspector_digest="abc",
            evidence_digest="evidence-digest",
            receipt_digest="def",
            auditor_capability_token=capabilities.manager_token,
            parent_attempt_id=attempt_id,
            fence_token=fence,
            controller_epoch=workflow.parent.controller_epoch("run-1"),
            run_id="run-1",
        )
    workflow.close()


def test_terra_absent_receipt_blocks_finish(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "no terra")
    _parent_task, pending = workflow.run_until_terra_pending(
        "run-1",
        "worker",
        request_digest=digest_payload({"task": "no-terra"}),
        plan_producer=default_plan_producer,
        task_handler=default_task_handler,
        inspector=default_inspector,
    )
    assert pending is not None
    with pytest.raises(PermissionError, match="approved terra receipt"):
        workflow.finish_cycle_after_terra(pending)
    workflow.close()


def test_lease_renewal_stale_version_rejected(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "lease cas")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "lease-cas"}),
    )
    plan = workflow.manager.create_plan(
        child=child,
        capabilities=capabilities,
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        producer=default_plan_producer,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
    )
    child = workflow.repo.get_child(child["child_id"])
    executing = workflow.repo.begin_execution(
        child_id=child["child_id"],
        expected_version=int(child["version"]),
        executor_capability_token=capabilities.executor_token,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        controller_epoch=workflow.parent.controller_epoch("run-1"),
        run_id="run-1",
    )
    with pytest.raises(PermissionError):
        workflow.repo.renew_lease(
            child_id=executing["child_id"],
            expected_version=int(child["version"]) - 1,
            role="executor",
            capability_token=capabilities.executor_token,
            lease_seconds=10,
            controller_epoch=workflow.parent.controller_epoch("run-1"),
            run_id="run-1",
            parent_attempt_id=attempt_id,
            fence_token=fence,
        )
    workflow.close()


def test_no_writes_after_rollback(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    workflow.parent.schedule_task("run-1", "task-1", "post rollback")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    child, capabilities, _ = workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "post-rollback"}),
    )
    workflow.parent.rollback("run-1")
    with pytest.raises(PermissionError):
        workflow.manager.create_plan(
            child=child,
            capabilities=capabilities,
            parent_task=claimed,
            parent_attempt_id=attempt_id,
            fence_token=fence,
            producer=default_plan_producer,
            controller_epoch=workflow.parent.controller_epoch("run-1"),
        )
    workflow.close()


def test_migration_005_upgrade_on_populated_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    name, url = _create_test_database(f"td_downgrade_populated_{uuid.uuid4().hex}")
    try:
        alembic_command(url, "upgrade", "004_longspan_workflow")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO supervisor_runs (run_id, state)
                    VALUES ('run-pop', 'active')
                    ON CONFLICT (run_id) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO parent_tasks
                        (task_id, run_id, objective, state)
                    VALUES ('task-pop', 'run-pop', 'migration seed', 'queued')
                    ON CONFLICT (task_id) DO NOTHING
                    """
                )
                cur.execute(
                    """
                    INSERT INTO longspan_children
                        (child_id, task_id, run_id, parent_attempt_id, fence_token, state,
                         idempotency_key, request_digest, attempt_number, version,
                         lease_token_hash)
                    VALUES ('child-pop', 'task-pop', 'run-pop', 'attempt-pop', 1, 'ready',
                            'idem-pop', 'digest-pop', 0, 0, 'lease-hash')
                    """
                )
                entry_hash = compute_ledger_entry_hash(
                    child_id="child-pop",
                    attempt_number=0,
                    event_type="seed",
                    producer_role="parent",
                    payload_digest=digest_payload({"seed": True}),
                    previous_entry_hash=None,
                )
                cur.execute(
                    """
                    INSERT INTO longspan_evidence_ledger
                        (entry_id, child_id, attempt_number, event_type, producer_role,
                         payload_digest, previous_entry_hash, entry_hash)
                    VALUES ('entry-pop', 'child-pop', 0, 'seed', 'parent', %s, NULL, %s)
                    """,
                    (digest_payload({"seed": True}), entry_hash),
                )
                conn.commit()
        run_migrations(url)
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT sequence_number FROM longspan_evidence_ledger
                    WHERE entry_id = 'entry-pop'
                    """
                )
                assert int(cur.fetchone()[0]) == 1
        # The authority service performs the out-of-band attestation/backfill
        # after 007.  A pre-007 base hash must remain verifiable as a legacy
        # row, rather than being silently reinterpreted as a keyed hash.
        from conftest import _provision_role_users

        _workflow_url, authority_url = _provision_role_users(ADMIN_URL, name)
        with psycopg2.connect(authority_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT longspan_install_ledger_mac_key(%s)", (TEST_LEDGER_MAC,))
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT longspan_verify_ledger_entry(
                        'child-pop', 0, 'seed', 'parent', %s, NULL, %s, %s, 'run-pop'
                    )
                    """,
                    (digest_payload({"seed": True}), entry_hash, entry_hash),
                )
                assert cur.fetchone()[0] is True
    finally:
        _drop_test_database(name)


def test_migration_005_downgrade_reupgrade_roundtrip(artifact_root: Path) -> None:
    name, url = _create_test_database(f"td_downgrade_005rt_{uuid.uuid4().hex}")
    install_downgrade_capability(
        database_name=name, migration_revision="004_longspan_workflow"
    )
    try:
        run_migrations(url)
        alembic_command(url, "downgrade", "004_longspan_workflow")
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass('public.longspan_execution_audits')"
                )
                assert cur.fetchone()[0] is None
                cur.execute(
                    """
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_name = 'longspan_auditor_receipts'
                      AND column_name = 'evidence_digest'
                    """
                )
                assert cur.fetchone() is None
        run_migrations(url)
        from test_authority_helpers import start_authority_service_for_url

        server = start_authority_service_for_url(url)
        try:
            workflow_url = (
                f"postgresql://top_delivery_workflow:td-workflow-test@127.0.0.1:5432/{name}"
            )
            workflow = _workflow(workflow_url, artifact_root)
            workflow.parent.register_run("run-1")
            _seed_ready_parent(workflow.parent, "run-1", artifact_root)
            _provision_authority(workflow, "run-1")
            workflow.parent.schedule_task("run-1", "task-1", "roundtrip")
            result = _run_cycle(workflow, "run-1", request_digest=digest_payload({"task": "roundtrip"}))
            assert result is not None and result.state == "verified"
            workflow.close()
        finally:
            server.close()
    finally:
        _drop_test_database(name)


def test_auditor_fail_retry_reaudit_succeeds(db_url: str, artifact_root: Path) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "audit retry")

    def failing_inspector(**_kwargs):
        from longspan import AuditorVerdict

        return AuditorVerdict(
            verdict="fail", reasons=("injected-failure",), inspector_digest="deadbeef"
        )

    _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "audit-retry"}),
        inspector=failing_inspector,
    )
    child = workflow.repo.find_resumable_child("run-1", "task-1")
    assert child is not None
    workflow.parent.schedule_task("run-1", "task-1", "audit retry")
    result = _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "audit-retry-2"}),
    )
    assert result is not None and result.state == "verified"
    workflow.close()


def test_malicious_handler_cannot_access_auditor_token(
    db_url: str, artifact_root: Path
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    _seed_ready_parent(workflow.parent, "run-1", artifact_root)
    _provision_authority(workflow, "run-1")
    workflow.parent.schedule_task("run-1", "task-1", "malicious handler")
    seen: list[str] = []

    class MaliciousHandler:
        def __call__(self, context):
            seen.append(type(context).__name__)
            for name in dir(context):
                if "auditor" in name.lower():
                    raise AssertionError("auditor credential visible to handler")
            return default_task_handler(context)

    _run_cycle(
        workflow,
        "run-1",
        request_digest=digest_payload({"task": "malicious"}),
        task_handler=MaliciousHandler(),
    )
    assert seen == ["ExecutorContext"]
    workflow.close()


def test_rollback_parking_incomplete_fails_closed(
    db_url: str, artifact_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workflow = _workflow(db_url, artifact_root)
    workflow.parent.register_run("run-1")
    workflow.parent.schedule_task("run-1", "task-1", "park-fail")
    claimed = workflow.parent.claim_next("run-1", "worker")
    assert claimed is not None
    attempt_id, fence = workflow.parent.resolve_parent_attempt(
        claimed.task_id, claimed.generation or ""
    )
    workflow.register_child_for_task(
        parent_task=claimed,
        parent_attempt_id=attempt_id,
        fence_token=fence,
        idempotency_key=child_idempotency_key("task-1", attempt_id, 0),
        request_digest=digest_payload({"task": "park-fail"}),
    )

    def incomplete_park(self, cur, run_id: str) -> None:
        raise PermissionError("longspan child parking incomplete")

    monkeypatch.setattr(
        workflow.parent._repo.__class__,
        "_park_longspan_children",
        incomplete_park,
    )
    with pytest.raises(PermissionError, match="parking incomplete"):
        workflow.parent.rollback("run-1")
    workflow.close()


def test_terra_attestation_concurrent_distinct_payloads_are_serialized(
    db_url: str, artifact_root: Path
) -> None:
    """The authority routine permits one live witness under concurrent issuance."""
    workflow = _workflow(db_url, artifact_root)
    run_id = "run-attestation-race"
    workflow.parent.register_run(run_id)
    _seed_ready_parent(workflow.parent, run_id, artifact_root)
    _provision_authority(workflow, run_id)
    workflow.parent.schedule_task(run_id, "task-attestation-race", "attestation race")
    _parent_task, pending = workflow.run_until_terra_pending(
        run_id,
        "worker",
        request_digest=digest_payload({"task": "attestation-race"}),
        plan_producer=default_plan_producer,
        task_handler=default_task_handler,
        inspector=default_inspector,
    )
    assert pending is not None
    workflow.parent.heartbeat(pending.parent_task.task_id, pending.parent_generation)
    child = workflow.repo.get_child(pending.child_id)
    authority = workflow.repo.get_authority_config(run_id)
    auditor = workflow.repo.get_auditor_receipt(pending.child_id, pending.attempt_number)
    execution = workflow.repo.get_execution_result(pending.child_id, pending.attempt_number)
    base_payload = {
        "child_id": pending.child_id,
        "attempt_number": pending.attempt_number,
        "decision": "approved",
        "evidence_chain_head": pending.ledger_head,
        "run_id": run_id,
        "task_id": child["task_id"],
        "reviewed_sha": authority["reviewed_sha"],
        "fence_token": int(child["fence_token"]),
        "controller_epoch": workflow.parent.controller_epoch(run_id),
        "tree_sha": authority["tree_sha"],
        "source_digest": authority["source_digest"],
        "request_digest": child["request_digest"],
        "migration_head": CANONICAL_ALEMBIC_HEAD,
        "authority_version": int(authority["config_version"]),
        "evidence_digest": auditor["evidence_digest"],
        "result_digest": execution["result_digest"],
    }
    from authority_repository import AuthorityRepository

    def issue(reviewer: str) -> tuple[str, str, str]:
        payload = {**base_payload, "reviewer": reviewer}
        external = sign_terra_receipt(payload, terra_private_key_for_tests())
        signature_digest = hashlib.sha256(
            external.split(":", 1)[1].encode("utf-8")
        ).hexdigest()
        repository = AuthorityRepository.from_url(_authority_url_for_database(db_url))
        try:
            return (
                "ok",
                repository.issue_terra_receipt_attestation(
                    receipt_payload=payload,
                    external_signature=external,
                ),
                signature_digest,
            )
        except Exception as exc:
            return ("error", str(exc), signature_digest)
        finally:
            repository.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(issue, ("terra-race-a", "terra-race-b")))
    successes = [value for kind, value, _digest in outcomes if kind == "ok"]
    failures = [value for kind, value, _digest in outcomes if kind == "error"]
    success_digests = [digest for kind, _value, digest in outcomes if kind == "ok"]
    assert len(successes) == 1
    assert len(failures) == 1
    assert "attestation" in failures[0] or "unconsumed" in failures[0]
    cleanup = AuthorityRepository.from_url(_authority_url_for_database(db_url))
    try:
        cleanup.invalidate_terra_receipt_attestation(
            attestation_id=successes[0],
            run_id=base_payload["run_id"],
            child_id=base_payload["child_id"],
            attempt_number=base_payload["attempt_number"],
            signature_digest=success_digests[0],
        )
    finally:
        cleanup.close()
        workflow.close()
