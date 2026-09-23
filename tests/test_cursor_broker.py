from __future__ import annotations

import json
import os
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import shutil
from types import SimpleNamespace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.cursor_broker import client, server
from harness_adapters.cli_adapters import CliHarnessAdapter
from harness_adapters.contract import HarnessRequest


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
        "cwd": cfg["workspace_root"], "operation": "prompt", "prompt": prompt}


def fake_launcher(calls: list, config: dict, route: dict, prompt: str) -> dict:
    calls.append((route["model"], prompt))
    return {"exit_code": 0, "outcome": "completed", "duration_seconds": 0.01,
        "stdout": b'{"type":"assistant","message":{"content":"PASS"}}\n',
        "stderr": b"", "stdout_bytes": 60, "stderr_bytes": 0,
        "stdout_truncated": False, "stderr_truncated": False}


def fake_verify_workspace(cfg: dict) -> int:
    return os.open(cfg["workspace_root"], os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)


def test_no_replay_ledger_redacts_prompt_and_caps_five_slots(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    monkeypatch.setattr(server, "verify_workspace", fake_verify_workspace)
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
    monkeypatch.setattr(server, "verify_workspace", fake_verify_workspace)
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


def test_catalog_preflight_is_exact_non_generating_and_no_replay(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    monkeypatch.setattr(server, "verify_workspace", fake_verify_workspace)
    monkeypatch.setattr(server, "_secure_path", lambda path, **_kwargs: Path(path))
    calls = []
    item = {"schema": server.REQUEST_SCHEMA, "run_id": cfg["run_id"], "task_id": "catalog-1",
        "attempt_id": "catalog-attempt-1", "role": "preflight",
        "route_id": "cursor-auth-catalog-preflight", "cwd": cfg["workspace_root"],
        "operation": "models"}
    result = server.dispatch(cfg, item, os.geteuid(),
        launcher=lambda c, r, p: calls.append((r, p)) or fake_launcher([], c, r, p))
    assert result["status"] == "complete"
    assert calls == [(server.EXPECTED_ROUTES["cursor-auth-catalog-preflight"], None)]
    ledger = next((Path(cfg["ledger_root"]) / cfg["run_id"]).glob("*.json"))
    record = json.loads(ledger.read_text())
    assert record["operation"] == "models"
    assert "prompt_sha256" not in record
    assert "prompt" not in ledger.read_text()
    again = server.dispatch(cfg, {**item, "attempt_id": "catalog-attempt-2"}, os.geteuid(),
        launcher=lambda *_args: pytest.fail("catalog route must never replay"))
    assert again == {"status": "blocked", "reason": "duplicate_no_replay"}


def test_catalog_client_accepts_only_models_subcommand(monkeypatch, tmp_path):
    monkeypatch.setenv("HORIZON_CURSOR_BROKER_ROUTE", "cursor-auth-catalog-preflight")
    assert client.main(["-p", "do something"]) == 78
    assert client.main(["models", "--format", "json"]) == 78
    assert client.main(["models"]) == 78  # Missing route identity/socket is rejected before dispatch.


@pytest.mark.parametrize(("failure", "expected_class"), [
    (PermissionError(13, "secret/path/must/not/persist"), "permission_denied"),
    (subprocess.SubprocessError("Exception occurred in preexec_fn; private detail"), "child_setup_failed"),
])
def test_uncertain_launch_persists_bounded_diagnostic_and_never_replays(tmp_path, monkeypatch, failure, expected_class):
    cfg = config(tmp_path)
    monkeypatch.setattr(server, "verify_workspace", fake_verify_workspace)
    monkeypatch.setattr(server, "_secure_path", lambda path, **_kwargs: Path(path))
    calls = []

    def failed_launcher(*_args):
        calls.append("called")
        raise failure

    first = server.dispatch(cfg, request(cfg, task="uncertain-child"), os.geteuid(), launcher=failed_launcher)
    assert first == {"status": "blocked", "reason": "launch_outcome_unknown_no_replay"}
    record_path = next((Path(cfg["ledger_root"]) / cfg["run_id"]).glob("*.json"))
    record = json.loads(record_path.read_text())
    assert record["state"] == "intent"
    assert record["launch_failure_class"] == expected_class
    assert "launch_errno" not in record or record["launch_errno"] == 13
    assert "secret/path" not in record_path.read_text()
    assert "private detail" not in record_path.read_text()

    duplicate = server.dispatch(cfg, request(cfg, task="uncertain-child", attempt="attempt-2"), os.geteuid(),
        launcher=lambda *_args: pytest.fail("uncertain launch must not replay"))
    assert duplicate == {"status": "blocked", "reason": "duplicate_no_replay"}
    assert calls == ["called"]


def test_horizon_adapter_forwards_only_bound_broker_identity(tmp_path):
    class CaptureRunner:
        artifact_dir = None

        def run(self, **kwargs):
            self.call = kwargs
            return SimpleNamespace(exit_code=None, duration_seconds=0.0, inline_stdout=None,
                stdout_artifact_path=None, stdout_sha256=None, stderr_artifact_path=None,
                stderr_sha256=None, structured_payload=None,
                error_classification="transport_failure", retryable=False,
                stdout_truncated=False, stderr_truncated=False)

        def cancel(self):
            pass

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = CaptureRunner()
    adapter = CliHarnessAdapter(adapter_id="cursor-independent-review", kind="cursor_cli",
        executable="/release/bin/top-delivery-cursor-broker-client", model="cursor-grok-4.6-high",
        provider="cursor", credential_env=(), timeout_seconds=900,
        allowed_cwd_roots=(str(workspace),), runner=runner, approval_mode="never", cursor_mode="ask",
        broker_socket="/run/top-delivery-cursor-broker/cursor.sock",
        broker_route_id="cursor-independent-review")
    request_value = HarnessRequest("goal-5b434f0a3d720c89", "task-1", "attempt-1", "review",
        "prompt", str(workspace), 900, None, (), str(tmp_path / "artifacts"), {"role": "auditor"})
    assert adapter.execute(request_value).status == "failure"
    call = runner.call
    assert call["executable"] == adapter.executable
    assert call["argv"] == [adapter.executable, "-p", "prompt", "--output-format", "stream-json",
        "--model", "cursor-grok-4.6-high", "--mode", "ask", "--sandbox", "enabled", "--trust"]
    assert call["extra_env"] == {
        "HORIZON_CURSOR_BROKER_SOCKET": "/run/top-delivery-cursor-broker/cursor.sock",
        "HORIZON_CURSOR_BROKER_ROUTE": "cursor-independent-review",
        "HORIZON_CURSOR_BROKER_RUN_ID": request_value.run_id,
        "HORIZON_CURSOR_BROKER_TASK_ID": request_value.task_id,
        "HORIZON_CURSOR_BROKER_ATTEMPT_ID": request_value.attempt_id,
        "HORIZON_CURSOR_BROKER_ROLE": "auditor",
    }


def test_real_child_boundary_drops_to_uid999_with_zero_caps_and_nnp(tmp_path, monkeypatch):
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
        fake.write_text("#!/usr/bin/python3.13\nimport json,os\nwith open('child-write-check.txt','x') as f: f.write('uid999')\ns={x.split(':',1)[0]:x.split(':',1)[1].strip() for x in open('/proc/self/status') if x.startswith(('Uid:','Gid:','CapInh:','CapPrm:','CapEff:','CapBnd:','CapAmb:','NoNewPrivs:'))}\nprint(json.dumps({'uid':os.geteuid(),'cwd':os.getcwd(),'write_uid':os.stat('child-write-check.txt').st_uid,'status':s}))\n")
        fake.chmod(0o755)
        cfg = {"executable": str(fake), "workspace_root": str(workspace),
            "child_home": str(workspace), "cursor_home": str(workspace),
            "child_uid": 999, "child_gid": 989, "workspace_uid": 999,
            "workspace_dev": workspace.stat().st_dev, "workspace_ino": workspace.stat().st_ino,
            "max_output_bytes": server.MAX_OUTPUT}
        real_open = os.open
        directory_open_flags = []

        def capture_directory_open(path, flags, *args, **kwargs):
            if flags & os.O_DIRECTORY:
                directory_open_flags.append(flags)
            return real_open(path, flags, *args, **kwargs)

        with monkeypatch.context() as patcher:
            patcher.setattr(server.os, "open", capture_directory_open)
            workspace_fd = server.verify_workspace(cfg)
        assert directory_open_flags
        assert all(flags & os.O_PATH and not flags & os.O_RDONLY for flags in directory_open_flags)
        try:
            assert os.fstat(workspace_fd).st_ino == cfg["workspace_ino"]
            assert os.fstat(workspace_fd).st_uid == 999
            cfg["_workspace_fd"] = workspace_fd
            result = server._launch(cfg, {"model": "composer-2.5", "mode": "agent", "timeout_seconds": 5},
                                    "deterministic probe only")
        finally:
            os.close(workspace_fd)
    finally:
        shutil.rmtree(root)
    assert result["outcome"] == "completed"
    assert result["exit_code"] == 0
    payload = json.loads(result["stdout"])
    assert payload["uid"] == 999
    assert payload["write_uid"] == 999
    assert payload["cwd"] == str(workspace)
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(payload["status"][field], 16) == 0
    assert payload["status"]["NoNewPrivs"] == "1"
