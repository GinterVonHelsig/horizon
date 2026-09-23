from __future__ import annotations

import json
import os
import pwd
import socket
import sys
import tempfile
import threading
import shutil
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.cursor_broker import client, server


def config(tmp_path: Path) -> dict:
    ledger = tmp_path / "ledger"
    ledger.mkdir(mode=0o700)
    ledger.chmod(0o700)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    workspace.chmod(0o700)
    info = workspace.stat()
    return {
        "run_id": "goal-5b434f0a3d720c89",
        "peer_uid": os.geteuid(),
        "workspace_root": str(workspace),
        "workspace_uid": os.geteuid(),
        "workspace_dev": info.st_dev,
        "workspace_ino": info.st_ino,
        "ledger_root": str(ledger),
        "max_sessions": 5,
        "max_request_bytes": server.MAX_REQUEST,
        "max_output_bytes": server.MAX_OUTPUT,
        "routes": server.EXPECTED_ROUTES,
    }


def request(cfg: dict, *, task="task-1", attempt="attempt-1", route="gateway-delivery-disposable-file",
            role="executor", prompt="do tiny work") -> dict:
    return {"schema": server.REQUEST_SCHEMA, "run_id": cfg["run_id"], "task_id": task,
        "attempt_id": attempt, "role": role, "route_id": route,
        "cwd": cfg["workspace_root"], "prompt": prompt}


def fake_launcher(calls: list, config: dict, route: dict, prompt: str) -> dict:
    calls.append((route["model"], prompt))
    return {"exit_code": 0, "outcome": "completed", "duration_seconds": 0.01,
        "stdout": b'{"type":"assistant","message":{"content":"PASS"}}\n',
        "stderr": b"", "stdout_bytes": 60, "stderr_bytes": 0,
        "stdout_truncated": False, "stderr_truncated": False}


def test_no_replay_ledger_redacts_prompt_and_caps_five_slots(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    monkeypatch.setattr(server, "verify_workspace", lambda _config: None)
    monkeypatch.setattr(server, "_secure_path", lambda path, **_kwargs: Path(path))
    calls = []
    secret_marker = "SYNTHETIC_PRIVATE_PROMPT_DO_NOT_PERSIST"
    first = server.dispatch(cfg, request(cfg, prompt=secret_marker), os.geteuid(),
                            launcher=lambda c, r, p: fake_launcher(calls, c, r, p))
    assert first["status"] == "complete"
    assert len(calls) == 1
    ledger_files = list((Path(cfg["ledger_root"]) / cfg["run_id"]).glob("*.json"))
    assert len(ledger_files) == 1
    record = json.loads(ledger_files[0].read_text())
    assert record["state"] == "terminal"
    assert secret_marker not in ledger_files[0].read_text()
    assert "PASS" not in ledger_files[0].read_text()

    duplicate = server.dispatch(cfg, request(cfg, attempt="attempt-2", prompt=secret_marker), os.geteuid(),
                                launcher=lambda c, r, p: fake_launcher(calls, c, r, p))
    assert duplicate == {"status": "blocked", "reason": "duplicate_no_replay"}
    assert len(calls) == 1

    for index in range(2, 6):
        item = request(cfg, task=f"task-{index}", route="cursor-independent-review", role="auditor")
        result = server.dispatch(cfg, item, os.geteuid(), launcher=lambda c, r, p: fake_launcher(calls, c, r, p))
        assert result["status"] == "complete"
    sixth = server.dispatch(cfg, request(cfg, task="task-6"), os.geteuid(),
                            launcher=lambda c, r, p: fake_launcher(calls, c, r, p))
    assert sixth == {"status": "blocked", "reason": "session_budget_exhausted"}
    assert len(calls) == 5


def test_peer_role_route_and_workspace_fail_closed(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    calls = []
    launch = lambda c, r, p: fake_launcher(calls, c, r, p)
    assert server.dispatch(cfg, request(cfg), os.geteuid() + 1, launcher=launch)["reason"] == "peer_uid_not_allowed"
    bad = request(cfg, route="openrouter-grok", role="auditor")
    assert server.dispatch(cfg, bad, os.geteuid(), launcher=launch)["reason"] == "route_or_workspace_not_allowlisted"
    assert not calls
    monkeypatch.setattr(server, "verify_workspace", lambda _config: (_ for _ in ()).throw(ValueError("workspace_inode_or_owner_mismatch")))
    with pytest.raises(ValueError, match="workspace_inode_or_owner_mismatch"):
        server.dispatch(cfg, request(cfg), os.geteuid(), launcher=launch)
    assert not calls


def test_real_socket_client_server_roundtrip_without_model_call(tmp_path, monkeypatch, capfd):
    cfg = config(tmp_path)
    monkeypatch.setattr(server, "verify_workspace", lambda _config: None)
    monkeypatch.setattr(server, "_secure_path", lambda path, **_kwargs: Path(path))
    path = tmp_path / "broker.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    calls = []
    failure = []

    def serve_one():
        try:
            conn, _ = listener.accept()
            with conn:
                server.handle_connection(conn, cfg, launcher=lambda c, r, p: fake_launcher(calls, c, r, p))
        except Exception as exc:  # Make thread failures visible to the assertion.
            failure.append(exc)

    thread = threading.Thread(target=serve_one)
    thread.start()
    monkeypatch.setenv("HORIZON_CURSOR_BROKER_SOCKET", str(path))
    monkeypatch.setenv("HORIZON_CURSOR_BROKER_ROUTE", "gateway-delivery-disposable-file")
    monkeypatch.setenv("HORIZON_CURSOR_BROKER_RUN_ID", cfg["run_id"])
    monkeypatch.setenv("HORIZON_CURSOR_BROKER_TASK_ID", "task-socket")
    monkeypatch.setenv("HORIZON_CURSOR_BROKER_ATTEMPT_ID", "attempt-socket")
    monkeypatch.setenv("HORIZON_CURSOR_BROKER_ROLE", "executor")
    monkeypatch.chdir(cfg["workspace_root"])
    code = client.main(client.expected_argv("synthetic prompt", "composer-2.5", "agent"))
    thread.join(timeout=2)
    listener.close()
    captured = capfd.readouterr()
    assert not thread.is_alive() and not failure
    assert code == 0, captured.err
    assert "PASS" in captured.out
    assert len(calls) == 1


def test_client_rejects_model_or_flag_substitution(monkeypatch):
    monkeypatch.setenv("HORIZON_CURSOR_BROKER_ROUTE", "cursor-independent-review")
    assert client.main(["-p", "review", "--output-format", "stream-json", "--model",
        "cursor-grok-4.6", "--mode", "ask", "--sandbox", "enabled", "--trust"]) == 78


def test_real_child_boundary_drops_to_uid999_with_zero_caps_and_nnp(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("requires root-owned setup capabilities for the UID transition")
    try:
        pwd.getpwuid(999)
    except KeyError:
        pytest.skip("topdelivery UID 999 is unavailable")
    root = Path(tempfile.mkdtemp(prefix="horizon-cursor-broker-", dir="/tmp"))
    root.chmod(0o755)
    try:
        workspace = root / "workspace"
        workspace.mkdir(mode=0o700)
        os.chown(workspace, 999, 989)
        fake = root / "fake-cursor"
        fake.write_text("#!/usr/bin/python3.13\nimport json,os\ns={x.split(':',1)[0]:x.split(':',1)[1].strip() for x in open('/proc/self/status') if x.startswith(('Uid:','Gid:','CapInh:','CapPrm:','CapEff:','CapBnd:','CapAmb:','NoNewPrivs:'))}\nprint(json.dumps({'uid':os.geteuid(),'cwd':os.getcwd(),'status':s}))\n")
        fake.chmod(0o755)
        cfg = {"executable": str(fake), "workspace_root": str(workspace),
            "child_home": str(workspace), "cursor_home": str(workspace),
            "child_uid": 999, "child_gid": 989, "max_output_bytes": server.MAX_OUTPUT}
        result = server._launch(cfg, {"model": "composer-2.5", "mode": "agent", "timeout_seconds": 5},
                                "deterministic probe only")
    finally:
        shutil.rmtree(root)
    assert result["outcome"] == "completed"
    assert result["exit_code"] == 0
    payload = json.loads(result["stdout"])
    assert payload["uid"] == 999
    assert payload["cwd"] == str(workspace)
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(payload["status"][field], 16) == 0
    assert payload["status"]["NoNewPrivs"] == "1"
