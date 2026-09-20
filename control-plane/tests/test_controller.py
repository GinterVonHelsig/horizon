from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "controller"))

from controller import (  # noqa: E402
    AuditLog,
    COMMANDS,
    ChildRegistry,
    CommandParser,
    GroupMessageRejectedError,
    InertQueue,
    READ_ONLY_MODE,
    TargetRejectedError,
    TopDeliveryController,
    UnauthorizedSenderError,
    validate_target_id,
)


RUN_ID = "20260810T004319Z-b626467e"


@pytest.fixture()
def delivery_root(tmp_path: Path) -> Path:
    (tmp_path / "architecture").mkdir()
    (tmp_path / "architecture" / "model-routing.yaml").write_text(
        "version: 1\nroutes:\n  - name: fallback\n    target: comms-01-control-plane\n",
        encoding="utf-8",
    )
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "result.json").write_text(
        '{"ok":true}\n', encoding="utf-8"
    )
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "report.json").write_text(
        '{"report":"ready"}\n', encoding="utf-8"
    )
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / f"{RUN_ID}.json").write_text(
        json.dumps(
            {
                "run_id": RUN_ID,
                "phase": "3A",
                "status": "active",
                "evidence_paths": ["evidence/result.json"],
                "artifacts": ["artifacts/report.json"],
                "blockers": [],
                "next_action": "review evidence",
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def make_controller(root: Path) -> TopDeliveryController:
    return TopDeliveryController(root, authorized_senders={"test-sender"})


def test_read_only_accuracy_and_evidence_hash(delivery_root: Path) -> None:
    before = {
        path.relative_to(delivery_root): path.read_bytes()
        for path in delivery_root.rglob("*")
        if path.is_file()
    }
    controller = make_controller(delivery_root)
    response = json.loads(controller.handle_text(f"status {RUN_ID}", "test-sender"))
    expected_hash = hashlib.sha256(b'{"ok":true}\n').hexdigest()

    assert response["run_id"] == RUN_ID
    assert response["phase"] == "3A"
    assert response["status"] == "active"
    assert response["mode"] == READ_ONLY_MODE
    assert response["evidence"][0]["sha256"] == expected_hash
    assert set(
        ("run_id", "phase", "status", "evidence_paths", "blockers", "next_action")
    ).issubset(response)
    after = {
        path.relative_to(delivery_root): path.read_bytes()
        for path in delivery_root.rglob("*")
        if path.is_file()
    }
    assert before == after
    controller.close()


def test_unknown_run_is_explicit(delivery_root: Path) -> None:
    response = json.loads(
        make_controller(delivery_root).handle_text(
            "status 20260810T004319Z-unknown", "test-sender"
        )
    )
    assert response["status"] == "unknown"
    assert response["run_id"] is None
    assert response["next_action"]


def test_run_scoped_evidence_is_hashed(delivery_root: Path) -> None:
    scoped_run_id = "20260810T004320Z-b626467e"
    run_dir = delivery_root / "runs" / scoped_run_id
    (run_dir / "artifacts").mkdir(parents=True)
    (run_dir / "artifacts" / "scoped.json").write_text(
        '{"scoped":true}\n', encoding="utf-8"
    )
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": scoped_run_id,
                "phase": "4.5",
                "status": "active",
                "evidence_paths": ["artifacts/scoped.json"],
                "next_action": "continue",
            }
        ),
        encoding="utf-8",
    )
    response = json.loads(
        make_controller(delivery_root).handle_text(f"status {scoped_run_id}", "test-sender")
    )
    assert response["evidence"][0]["path"] == "artifacts/scoped.json"
    assert not any(item.startswith("evidence-unavailable:") for item in response["blockers"])


def test_symlink_escape_and_undeclared_artifact_are_rejected(delivery_root: Path, tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("not evidence\n", encoding="utf-8")
    run_id = "20260810T004321Z-b626467e"
    run_dir = delivery_root / "runs" / run_id
    (run_dir / "artifacts").mkdir(parents=True)
    (run_dir / "artifacts" / "escape.txt").symlink_to(outside)
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "phase": "4.5",
                "status": "active",
                "evidence_paths": ["artifacts/escape.txt"],
                "next_action": "continue",
            }
        ),
        encoding="utf-8",
    )
    controller = make_controller(delivery_root)
    response = json.loads(controller.handle_text(f"status {run_id}", "test-sender"))
    assert response["evidence"] == []
    assert "evidence-unavailable:artifacts/escape.txt" in response["blockers"]
    secret = delivery_root / "artifacts" / "undeclared.txt"
    secret.write_text("not declared\n", encoding="utf-8")
    lookup = json.loads(controller.handle_text("artifact lookup artifacts/undeclared.txt", "test-sender"))
    assert lookup["status"] == "unknown"
    assert lookup.get("artifact") is None


def test_release_and_execution_commands_are_rejected(delivery_root: Path) -> None:
    controller = make_controller(delivery_root)
    for command in ("execute", "order", "deploy", "release", "promote"):
        response = json.loads(controller.handle_text(command, "test-sender"))
        assert response["error"]["code"] == "unknown-command"
        assert response["mode"] == READ_ONLY_MODE
        assert response["supported_read_only_commands"] == list(COMMANDS)
        assert "next" in response["error"]["message"]
        assert "authorize" in response["error"]["message"]
        assert response["authorization_commands"][0] == "next"
        assert "authorize" in response["authorization_commands"][1]


def test_unknown_command_error_is_human_actionable(delivery_root: Path) -> None:
    response = json.loads(
        make_controller(delivery_root).handle_text("not-a-command", "test-sender")
    )
    assert response["mode"] == READ_ONLY_MODE
    assert response["error"]["code"] == "unknown-command"
    for command in COMMANDS:
        assert command in response["error"]["message"]
    assert "next" in response["error"]["message"]
    assert "authorize" in response["error"]["message"]
    assert "separate" in response["error"]["message"].lower()
    assert response["next_action"]
    assert "read-only" in response["next_action"].lower()


def test_unauthorized_and_group_messages_are_rejected(delivery_root: Path) -> None:
    controller = make_controller(delivery_root)
    unauthorized = json.loads(controller.handle_text("active-runs", "other-sender"))
    grouped = json.loads(
        controller.handle_text("active-runs", "test-sender", is_group=True)
    )
    assert unauthorized["error"]["code"] == "unauthorized-sender"
    assert grouped["error"]["code"] == "group-message-rejected"
    with pytest.raises(UnauthorizedSenderError):
        CommandParser({"test-sender"}).parse("status", "other-sender")
    with pytest.raises(GroupMessageRejectedError):
        CommandParser({"test-sender"}).parse("status", "test-sender", is_group=True)


def test_signal_forwarding_is_byte_equal(delivery_root: Path) -> None:
    controller = make_controller(delivery_root)
    first = controller.handle_text("architecture-summary", "test-sender")
    second = controller.handle_text("architecture-summary", "test-sender")
    assert first == second
    assert "\n" not in first


def test_architecture_summary_and_recommended_order_use_project_status(
    delivery_root: Path,
) -> None:
    status_path = delivery_root / "architecture" / "project-status.json"
    status_path.write_text(
        json.dumps(
            {
                "title": "Trading Platform Advancement",
                "as_of": "2026-08-10",
                "tree": [
                    {
                        "id": "0",
                        "name": "Workflow",
                        "status": "ACTIVE",
                        "items": [{"name": "Controller", "status": "DONE"}],
                    }
                ],
                "recommended_order": ["Build staging", "Split engine"],
            }
        ),
        encoding="utf-8",
    )
    controller = make_controller(delivery_root)
    architecture = json.loads(
        controller.handle_text("architecture-summary", "test-sender")
    )
    assert architecture["status"] == "ready"
    assert architecture["architecture_summary"]["tree"][0]["name"] == "Workflow"
    recommended = json.loads(controller.handle_text("recommended", "test-sender"))
    assert recommended["recommended_order"] == ["Build staging", "Split engine"]


def test_trading_summary_is_date_isolated(delivery_root: Path) -> None:
    reports = delivery_root / "reports"
    reports.mkdir()
    (reports / "trading-summary-2026-08-10.json").write_text(
        json.dumps(
            {
                "date": "2026-08-10",
                "financial": {"trusted_closed_pnl": 0},
                "operational": {"service_ok": True},
                "verdict": "flat",
            }
        ),
        encoding="utf-8",
    )
    controller = make_controller(delivery_root)
    ready = json.loads(
        controller.handle_text("trading-summary 2026-08-10", "test-sender")
    )
    assert ready["status"] == "ready"
    assert ready["trading_summary"]["date"] == "2026-08-10"
    missing = json.loads(
        controller.handle_text("trading-summary 2026-08-09", "test-sender")
    )
    assert missing["status"] == "pending"
    assert missing["blockers"] == ["trading-summary-unavailable"]


def test_targets_are_positive_allow_list_only() -> None:
    assert validate_target_id("comms-01-control-plane") == "comms-01-control-plane"
    assert validate_target_id("disposable-test-01") == "disposable-test-01"
    for target in (
        "/tmp/comms-01-control-plane",
        "../disposable-test",
        "comms-01",
        "DISPOSABLE-test",
        "disposable-\u212a",
        "disposable-ｅxample",
    ):
        with pytest.raises(TargetRejectedError):
            validate_target_id(target)


def test_idempotent_queue_has_no_second_item(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.sqlite3")
    queue = InertQueue(audit)
    first = queue.enqueue(
        "disposable-test-01",
        {"command": "status"},
        idempotency_key="same-item",
    )
    second = queue.enqueue(
        "disposable-test-01",
        {"command": "status"},
        idempotency_key="same-item",
    )
    assert first.created is True
    assert second.created is False
    assert len(queue.pending()) == 1
    assert len(audit.events()) == 1
    audit.close()


def test_terminal_child_cleanup_is_deterministic() -> None:
    registry = ChildRegistry()
    registry.register_child("child-active", RUN_ID)
    registry.register_child("child-done", RUN_ID, status="completed")
    registry.register_child("child-failed", RUN_ID, status="failed")
    assert registry.cleanup_terminal_children() == ("child-done", "child-failed")
    assert [item.child_id for item in registry.list_children()] == ["child-active"]
