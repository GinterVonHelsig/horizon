"""Tests for Terra-owned Comms-01 exact-SHA release deploy and rollback."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from comms01_bounded_transport import (
    PINNED_COMMS01_SSH_CONFIG,
    Comms01TransportUnavailableError,
    assert_bounded_transport_available,
)
from comms01_release_deploy import (
    Comms01ReleaseDeployer,
    DeployBlockedError,
    RecoveryEvidence,
    RestartRecoveryTracker,
    _RemoteEntrypointServiceRunner,
    _sha_from_working_directory,
    build_controller_dropin,
    build_dual_exec_script,
    build_worker_unit,
    recovery_evidence_passes,
    redact_deploy_log,
    release_checkout_path,
)
from operator_asymmetric import generate_keypair
from terra_release_policy import issue_authoritative_receipt, ReleasePolicyInput


def _policy_input(**overrides: object) -> ReleasePolicyInput:
    payload = {
        "run_id": "run-deploy-1",
        "task_id": "task-5",
        "base_sha": "a" * 40,
        "candidate_sha": "b" * 40,
        "tree_sha": "c" * 40,
        "reviewed_sha": "b" * 40,
        "backup_manifest_sha256": "d" * 64,
        "rollback_plan_sha256": "e" * 64,
        "broker_safety": "flat",
        "database_safety": "verified",
        "scope_envelope_sha256": "f" * 64,
    }
    payload.update(overrides)
    return ReleasePolicyInput(**payload)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(cwd), text=True).strip()


def _init_repo(path: Path) -> tuple[str, str]:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")
    (path / "README.md").write_text("base\n")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "base")
    base_sha = _git(path, "rev-parse", "HEAD")
    (path / "README.md").write_text("base\ncandidate\n")
    _git(path, "add", "README.md")
    _git(path, "commit", "-m", "candidate")
    candidate_sha = _git(path, "rev-parse", "HEAD")
    return base_sha, candidate_sha


@dataclass
class FakeTransport:
    config_path: Path
    prior_sha: str = "a" * 40
    deployed_sha: str = "a" * 40
    remote_commands: list[tuple[str, ...]] = field(default_factory=list)
    queue_generation: int = 3
    signal_readiness: str = "incomplete"
    signal_seq: int = 3
    socket_ok: bool = True
    dual_exec_supervisor: bool = True
    checkouts: dict[str, Path] = field(default_factory=dict)
    bound_checkouts: list[str] = field(default_factory=list)
    bind_calls: list[dict[str, str]] = field(default_factory=list)

    def assert_available(self) -> None:
        if not self.config_path.is_file():
            raise Comms01TransportUnavailableError(
                f"bounded Comms-01 transport is unavailable: {self.config_path}"
            )

    def read_prior_sha(self) -> str:
        self.assert_available()
        return self.prior_sha

    def run_remote(self, command: tuple[str, ...]) -> str:
        self.remote_commands.append(command)
        return "active"

    def checkout_exists(self, checkout_dir: str) -> bool:
        return checkout_dir in self.checkouts

    def stage_release_tree(
        self,
        *,
        candidate_sha: str,
        source_repo: Path,
        checkout_dir: str,
    ) -> None:
        self.assert_available()
        checkout_path = Path(checkout_dir)
        checkout_path.mkdir(parents=True, exist_ok=True)
        tar_path = checkout_path / "archive.tar"
        subprocess.run(
            ["git", "archive", "--format=tar", candidate_sha, "-o", str(tar_path)],
            cwd=str(source_repo),
            check=True,
        )
        with tarfile.open(tar_path) as archive:
            archive.extractall(path=checkout_path)
        tar_path.unlink()
        (checkout_path / "controller").mkdir(exist_ok=True)
        (checkout_path / "controller" / "worker_cli.py").write_text("worker\n")
        (checkout_path / "systemd").mkdir(exist_ok=True)
        (checkout_path / "systemd" / "adapters.comms01.json").write_text("{}")
        self.checkouts[checkout_dir] = checkout_path
        self.deployed_sha = candidate_sha

    def bind_services_to_checkout(
        self,
        *,
        candidate_sha: str,
        checkout_dir: str,
        run_id: str,
        artifact_root: str,
    ) -> None:
        self.bind_calls.append(
            {
                "candidate_sha": candidate_sha,
                "checkout_dir": checkout_dir,
                "run_id": run_id,
                "artifact_root": artifact_root,
            }
        )
        self.bound_checkouts.append(checkout_dir)
        root = self.checkouts[checkout_dir]
        bind_root = root / "bound"
        bind_root.mkdir(exist_ok=True)
        controller_dir = f"{checkout_dir}/controller"
        (bind_root / "dual-exec").write_text(build_dual_exec_script(controller_dir))
        (bind_root / "controller-dropin").write_text(
            build_controller_dropin(controller_dir, run_id=run_id, artifact_root=artifact_root)
        )
        (bind_root / "worker.unit").write_text(
            build_worker_unit(f"{controller_dir}/worker_cli.py", checkout_dir)
        )

    def write_deployed_sha(self, candidate_sha: str) -> None:
        self.deployed_sha = candidate_sha

    def probe_controller_socket(self, *, operator_id: str, command: str = "active-runs") -> str:
        if not self.socket_ok:
            return '{"ok": false}'
        return json.dumps({"ok": True, "result": json.dumps({"status": "active", "runs": []})})

    def probe_queue_generation(self, run_id: str) -> int:
        return self.queue_generation

    def probe_signal_status(self, run_id: str) -> tuple[str, int]:
        return self.signal_readiness, self.signal_seq

    def supervisor_runs_in_dual_exec(self) -> bool:
        return self.dual_exec_supervisor

    def stop_standalone_supervisor_unit(self) -> None:
        self.remote_commands.append(
            ("/usr/bin/systemctl", "stop", "top-delivery-supervisor")
        )
        self.remote_commands.append(
            ("/usr/bin/systemctl", "disable", "top-delivery-supervisor")
        )


class FakeBackupStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.writes: list[tuple[str, bytes]] = []

    def write_backup(self, backup_path: str, payload: bytes) -> str:
        path = Path(backup_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        self.writes.append((backup_path, payload))
        return hashlib.sha256(payload).hexdigest()


class FakeServiceRunner:
    def __init__(self) -> None:
        self.statuses: dict[str, str] = {
            "top-delivery-controller": "active",
            "top-delivery-supervisor": "inactive",
            "top-delivery-worker": "inactive",
        }
        self.restarts: list[str] = []

    def status(self, service_name: str) -> str:
        return self.statuses.get(service_name, "inactive")

    def restart(self, service_name: str) -> None:
        self.restarts.append(service_name)
        self.statuses[service_name] = "active"


def test_comms01_transport_loss_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing-comms01_config"
    transport = FakeTransport(config_path=missing)
    deployer = Comms01ReleaseDeployer(transport=transport, source_repo=tmp_path)
    with pytest.raises(Comms01TransportUnavailableError, match="unavailable"):
        deployer.attest_prior_sha()
    with pytest.raises(Comms01TransportUnavailableError):
        assert_bounded_transport_available(config_path=missing)


def test_stage_release_tree_extracts_candidate_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    base_sha, candidate_sha = _init_repo(source)
    config = tmp_path / "comms01_config"
    config.write_text("Host comms-01\nBatchMode yes\n")
    transport = FakeTransport(config_path=config, prior_sha=base_sha)
    releases = tmp_path / "releases"
    checkout_dir = str(release_checkout_path(releases, candidate_sha))
    transport.stage_release_tree(
        candidate_sha=candidate_sha,
        source_repo=source,
        checkout_dir=checkout_dir,
    )
    extracted = Path(checkout_dir)
    assert (extracted / "README.md").read_text(encoding="utf-8").startswith("base\ncandidate")
    assert (extracted / "controller" / "worker_cli.py").is_file()


def test_exact_sha_transport_records_candidate_sha(tmp_path: Path) -> None:
    source = tmp_path / "source"
    base_sha, candidate_sha = _init_repo(source)
    config = tmp_path / "comms01_config"
    config.write_text("Host comms-01\nBatchMode yes\n")
    releases = tmp_path / "releases"
    prior_checkout = release_checkout_path(releases, base_sha)
    prior_checkout.mkdir(parents=True)
    transport = FakeTransport(
        config_path=config,
        prior_sha=base_sha,
        checkouts={str(prior_checkout): prior_checkout},
    )
    backup_root = tmp_path / "backups"
    backup_store = FakeBackupStore(backup_root)
    services = FakeServiceRunner()
    deploy_root = tmp_path / "deploy"
    private_key, _ = generate_keypair()
    receipt = issue_authoritative_receipt(
        _policy_input(
            base_sha=base_sha,
            candidate_sha=candidate_sha,
            tree_sha=candidate_sha,
            reviewed_sha=candidate_sha,
        ),
        private_key_b64=private_key,
    )
    deployer = Comms01ReleaseDeployer(
        transport=transport,
        backup_store=backup_store,
        service_runner=services,
        deploy_parent=deploy_root,
        release_checkout_parent=releases,
        source_repo=source,
    )
    prior = deployer.attest_prior_sha()
    assert prior.deployed_sha == base_sha
    backup = deployer.create_backup(
        database_url="postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_deploy",
        backup_path=str(backup_root / "pre-deploy.dump"),
        payload=b"backup-bytes",
    )
    assert backup.digest == hashlib.sha256(b"backup-bytes").hexdigest()
    receipt_record = deployer.deploy_exact_sha(
        candidate_sha=candidate_sha,
        tree_sha=candidate_sha,
        release_receipt=receipt,
        backup_manifest_sha256=receipt.payload["backup_manifest_sha256"],
    )
    assert receipt_record.candidate_sha == candidate_sha
    assert receipt_record.prior_sha == base_sha
    assert receipt_record.recorded_sha == candidate_sha
    assert transport.deployed_sha == candidate_sha
    assert transport.bind_calls
    candidate_checkout = str(release_checkout_path(releases, candidate_sha))
    assert candidate_checkout in transport.bound_checkouts
    assert (releases / f"{candidate_sha}-goal-runner" / "README.md").is_file()
    restarted = deployer.restart_attested_services()
    assert "top-delivery-controller" in restarted
    assert "top-delivery-worker" in restarted
    assert "top-delivery-supervisor" not in restarted
    tracker = RestartRecoveryTracker(queue_generation=2, side_effect_count=0)
    recovery = deployer.verify_restart_recovery(tracker=tracker)
    assert recovery_evidence_passes(recovery)
    assert recovery.controller_active
    assert recovery.worker_active
    assert recovery.supervisor_active
    assert recovery.queue_generation == 3
    assert recovery.signal_readable
    assert recovery.signal_writable
    assert recovery.duplicate_side_effects is False


def test_recovery_fails_when_socket_unavailable(tmp_path: Path) -> None:
    transport = FakeTransport(config_path=tmp_path / "cfg", socket_ok=False)
    (tmp_path / "cfg").write_text("Host comms-01\n")
    services = FakeServiceRunner()
    deployer = Comms01ReleaseDeployer(
        transport=transport,
        service_runner=services,
        source_repo=tmp_path,
    )
    recovery = deployer.verify_restart_recovery(
        tracker=RestartRecoveryTracker(queue_generation=1, side_effect_count=0)
    )
    assert not recovery_evidence_passes(recovery)


def test_rollback_repoints_services_and_restarts(tmp_path: Path) -> None:
    config = tmp_path / "comms01_config"
    config.write_text("Host comms-01\n")
    prior_sha = "a" * 40
    candidate_sha = "b" * 40
    releases = tmp_path / "releases"
    prior_checkout = release_checkout_path(releases, prior_sha)
    prior_checkout.mkdir(parents=True)
    (prior_checkout / "controller").mkdir()
    (prior_checkout / "controller" / "worker_cli.py").write_text("prior\n")
    (prior_checkout / "systemd").mkdir()
    (prior_checkout / "systemd" / "adapters.comms01.json").write_text("{}")
    transport = FakeTransport(
        config_path=config,
        prior_sha=candidate_sha,
        deployed_sha=candidate_sha,
        checkouts={str(prior_checkout): prior_checkout},
    )
    services = FakeServiceRunner()
    deployer = Comms01ReleaseDeployer(
        transport=transport,
        service_runner=services,
        deploy_parent=tmp_path / "deploy",
        release_checkout_parent=releases,
        source_repo=tmp_path,
    )
    dry = deployer.rollback_dry_run(prior_sha=prior_sha)
    assert dry.restored_sha == prior_sha
    assert dry.live_outage_required is False
    rollback = deployer.rollback_to_prior_sha(prior_sha=prior_sha)
    assert rollback.restored_sha == prior_sha
    assert transport.deployed_sha == prior_sha
    assert str(prior_checkout) in transport.bound_checkouts
    assert "top-delivery-controller" in services.restarts


def test_restart_recovery_reclaims_lease_without_duplicate_work() -> None:
    tracker = RestartRecoveryTracker(queue_generation=2, side_effect_count=1)
    tracker.record_restart()
    assert tracker.duplicate_side_effects() is False
    tracker.record_side_effect()
    assert tracker.duplicate_side_effects() is True


def test_auth_redaction_in_deploy_logs() -> None:
    raw = (
        "token=sk-live-secret api_key=abc123 password=hidden "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
    )
    redacted = redact_deploy_log(raw)
    assert "sk-live-secret" not in redacted
    assert "abc123" not in redacted
    assert "hidden" not in redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted
    assert "token=[REDACTED]" in redacted
    assert "api_key=[REDACTED]" in redacted


def test_deploy_blocked_without_prior_attestation(tmp_path: Path) -> None:
    config = tmp_path / "comms01_config"
    config.write_text("Host comms-01\n")
    transport = FakeTransport(config_path=config)
    transport.prior_sha = ""
    deployer = Comms01ReleaseDeployer(transport=transport, source_repo=tmp_path)
    with pytest.raises(DeployBlockedError, match="prior"):
        deployer.attest_prior_sha()


def test_deploy_blocked_without_source_repo(tmp_path: Path) -> None:
    config = tmp_path / "comms01_config"
    config.write_text("Host comms-01\n")
    releases = tmp_path / "releases"
    prior_sha = "a" * 40
    prior_checkout = release_checkout_path(releases, prior_sha)
    prior_checkout.mkdir(parents=True)
    transport = FakeTransport(
        config_path=config,
        prior_sha=prior_sha,
        checkouts={str(prior_checkout): prior_checkout},
    )
    private_key, _ = generate_keypair()
    receipt = issue_authoritative_receipt(_policy_input(base_sha=prior_sha), private_key_b64=private_key)
    deployer = Comms01ReleaseDeployer(
        transport=transport,
        release_checkout_parent=releases,
        source_repo=None,
    )
    with pytest.raises(DeployBlockedError, match="source repository"):
        deployer.deploy_exact_sha(
            candidate_sha="b" * 40,
            tree_sha="b" * 40,
            release_receipt=receipt,
            backup_manifest_sha256=receipt.payload["backup_manifest_sha256"],
        )


def test_pinned_transport_path_constant() -> None:
    assert PINNED_COMMS01_SSH_CONFIG == Path("/etc/top-delivery/ssh/comms01_config")


def test_sha_from_working_directory_parses_clean_suffix() -> None:
    sha = "a" * 40
    assert _sha_from_working_directory(f"/opt/top-delivery-p1/{sha}-clean/controller") == sha


def test_build_worker_unit_contains_checkout_paths() -> None:
    unit = build_worker_unit("/opt/checkout/controller/worker_cli.py", "/opt/checkout")
    assert "/opt/checkout/controller/worker_cli.py" in unit
    assert "ReadOnlyPaths=/opt/top-delivery /opt/checkout" in unit


@dataclass
class RecordingRemoteTransport:
    commands: list[tuple[str, ...]] = field(default_factory=list)
    status_output: str = "active\nRunning as unit: top-delivery-entrypoint@top-delivery-controller.service"

    def run_remote(self, command: tuple[str, ...]) -> str:
        self.commands.append(command)
        if "service-status" in command:
            return self.status_output
        return ""


def test_remote_service_runner_uses_entrypoint_adapter_not_raw_systemctl() -> None:
    transport = RecordingRemoteTransport()
    runner = _RemoteEntrypointServiceRunner(transport, "/opt/checkout/controller")
    assert runner.status("top-delivery-controller") == "active"
    runner.restart("top-delivery-controller")
    assert transport.commands
    raw_systemctl = [
        cmd
        for cmd in transport.commands
        if cmd[0] == "systemctl" or cmd[:2] == ("systemctl", "restart")
    ]
    assert raw_systemctl == []
    entrypoint_commands = [
        cmd for cmd in transport.commands if any("comms01_entrypoint_cli.py" in part for part in cmd)
    ]
    assert len(entrypoint_commands) == 2
    assert all(cmd[0] == "/usr/bin/systemd-run" for cmd in transport.commands)
    assert any("service-status" in cmd for cmd in transport.commands)
    assert any("service-restart" in cmd for cmd in transport.commands)


def test_supervisor_not_recovered_when_controller_only_without_dual_exec(tmp_path: Path) -> None:
    transport = FakeTransport(
        config_path=tmp_path / "cfg",
        dual_exec_supervisor=False,
    )
    (tmp_path / "cfg").write_text("Host comms-01\n")
    services = FakeServiceRunner()
    services.statuses["top-delivery-controller"] = "active"
    services.statuses["top-delivery-supervisor"] = "inactive"
    deployer = Comms01ReleaseDeployer(transport=transport, service_runner=services, source_repo=tmp_path)
    assert deployer._supervisor_recovered() is False


def test_terra_deploy_cli_does_not_install_worker_unit_locally() -> None:
    cli_source = Path(__file__).resolve().parents[1] / "scripts" / "terra_comms01_release_deploy.py"
    assert "install_worker_unit" not in cli_source.read_text(encoding="utf-8")


class _DualExecLossServiceRunner:
    """Simulates dual-exec children dying when the controller unit restarts."""

    def __init__(self, transport: FakeTransport) -> None:
        self._transport = transport
        self.restarts: list[str] = []

    def status(self, service_name: str) -> str:
        return "inactive"

    def restart(self, service_name: str) -> None:
        if service_name == "top-delivery-controller":
            self._transport.dual_exec_supervisor = False
        self.restarts.append(service_name)


def test_restart_skips_supervisor_when_dual_exec_snapshotted_before_controller(
    tmp_path: Path,
) -> None:
    transport = FakeTransport(
        config_path=tmp_path / "cfg",
        dual_exec_supervisor=True,
    )
    (tmp_path / "cfg").write_text("Host comms-01\n")
    runner = _DualExecLossServiceRunner(transport)
    deployer = Comms01ReleaseDeployer(
        transport=transport,
        service_runner=runner,
        source_repo=tmp_path,
    )
    restarted = deployer.restart_attested_services()
    assert "top-delivery-controller" in restarted
    assert "top-delivery-worker" in restarted
    assert "top-delivery-supervisor" not in restarted
    assert transport.dual_exec_supervisor is False
    assert any(
        cmd[:3] == ("/usr/bin/systemctl", "stop", "top-delivery-supervisor")
        for cmd in transport.remote_commands
    )


def test_restart_restarts_standalone_supervisor_when_not_dual_exec(tmp_path: Path) -> None:
    transport = FakeTransport(
        config_path=tmp_path / "cfg",
        dual_exec_supervisor=False,
    )
    (tmp_path / "cfg").write_text("Host comms-01\n")
    services = FakeServiceRunner()
    deployer = Comms01ReleaseDeployer(
        transport=transport,
        service_runner=services,
        source_repo=tmp_path,
    )
    restarted = deployer.restart_attested_services()
    assert "top-delivery-supervisor" in restarted


def test_remote_runner_status_returns_activating() -> None:
    transport = RecordingRemoteTransport(
        status_output="activating\nRunning as unit: top-delivery-entrypoint@top-delivery-supervisor.service"
    )
    runner = _RemoteEntrypointServiceRunner(transport, "/opt/checkout/controller")
    assert runner.status("top-delivery-supervisor") == "activating"
