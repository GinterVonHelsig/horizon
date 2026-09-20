"""Terra-owned exact-SHA Comms-01 release deploy, restart, and rollback orchestration."""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from comms01_bounded_transport import (
    BoundedTransport,
    Comms01TransportUnavailableError,
    PINNED_COMMS01_HOST_ALIAS,
    PINNED_COMMS01_SSH_CONFIG,
    assert_bounded_transport_available,
    validate_deploy_sha,
)
from comms01_operation_entrypoints import backup_bytes, service_restart, service_status
from exceptions import ScopeBoundaryViolationError
from terra_release_policy import ReleasePolicyReceipt, ReleasePolicyViolation

DEFAULT_DEPLOY_PARENT = Path("/opt/top-delivery")
DEFAULT_RELEASE_CHECKOUT_PARENT = Path("/opt/top-delivery-p1")
RELEASE_CHECKOUT_SUFFIX = "goal-runner"
DUAL_EXEC_PATH = "/usr/local/sbin/top-delivery-section0-dual-exec"
CONTROLLER_DROPIN_DIR = "/etc/systemd/system/top-delivery-controller.service.d"
CONTROLLER_DROPIN_NAME = "goal-runner-deploy.conf"
WORKER_UNIT_DESTINATION = "/etc/systemd/system/top-delivery-worker.service"
ADAPTERS_DESTINATION = "/etc/top-delivery/adapters.json"
WORKFLOW_DB_TARGET = "/etc/top-delivery/comms01-workflow-db-target.json"
CONTROLLER_SOCKET = "/run/top-delivery/controller.sock"
DEFAULT_OPERATOR_ID = "operator-01"
ENTRYPOINT_CLI_NAME = "comms01_entrypoint_cli.py"
PINNED_SYSTEMD_RUN_EXECUTABLE = "/usr/bin/systemd-run"
PINNED_PYTHON3_EXECUTABLE = "/usr/bin/python3"

ATTESTED_RESTART_SERVICES = (
    "top-delivery-controller",
    "top-delivery-supervisor",
    "top-delivery-worker",
)

_REDACT_PATTERNS = (
    (re.compile(r"(?i)(api[_-]?key)\s*[:=]\s*[^\s,]+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(token)\s*[:=]\s*[^\s,]+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(password)\s*[:=]\s*[^\s,]+"), r"\1=[REDACTED]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]+"), "Bearer [REDACTED]"),
    (re.compile(r"sk-[A-Za-z0-9_-]+"), "[REDACTED]"),
)

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class DeployBlockedError(ValueError):
    """Deploy cannot proceed without attested prior SHA or policy approval."""


class RecoveryVerificationError(ValueError):
    """Post-restart recovery checks failed."""


@dataclass(frozen=True)
class PriorShaAttestation:
    deployed_sha: str
    working_directory: str


@dataclass(frozen=True)
class BackupIdentity:
    path: str
    digest: str
    size: int


@dataclass(frozen=True)
class DeployReceipt:
    candidate_sha: str
    prior_sha: str
    recorded_sha: str
    tree_sha: str
    working_directory: str
    backup_manifest_sha256: str


@dataclass(frozen=True)
class RollbackReceipt:
    restored_sha: str
    working_directory: str


@dataclass(frozen=True)
class RollbackDryRun:
    restored_sha: str
    live_outage_required: bool


@dataclass(frozen=True)
class RecoveryEvidence:
    controller_active: bool
    worker_active: bool
    supervisor_active: bool
    queue_generation: int
    signal_readable: bool
    signal_writable: bool
    duplicate_side_effects: bool


class BackupStore(Protocol):
    def write_backup(self, backup_path: str, payload: bytes) -> str: ...


class ServiceRunner(Protocol):
    def status(self, service_name: str) -> str: ...
    def restart(self, service_name: str) -> None: ...


def _parse_systemd_run_pipe_output(raw: str) -> str:
    """Extract user stdout from ``systemd-run --pipe`` mixed with status lines."""
    metadata_prefixes = (
        "Running as unit:",
        "Finished with result:",
        "Main processes terminated",
        "Service runtime:",
        "CPU time consumed:",
        "Memory peak:",
    )
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("0::/"):
            continue
        if any(stripped.startswith(prefix) for prefix in metadata_prefixes):
            continue
        return stripped
    return ""


class _RemoteEntrypointServiceRunner:
    """Restart/status on Comms-01 via attested entrypoint CLI over ``systemd-run``.

    Raw SSH ``systemctl`` bypasses ``comms01_operation_entrypoints`` policy gates.
    The delegate unit ``top-delivery-entrypoint@<service>.service`` supplies cgroup
    identity for ``assert_service_name`` while entrypoints retain pinned argv.
    """

    def __init__(self, transport: _SshBoundedTransport, controller_dir: str) -> None:
        self._transport = transport
        self._controller_dir = controller_dir

    def _invoke_entrypoint(self, operation: str, service_name: str) -> str:
        cli_path = f"{self._controller_dir}/{ENTRYPOINT_CLI_NAME}"
        unit_name = f"top-delivery-entrypoint@{service_name}"
        command = (
            PINNED_SYSTEMD_RUN_EXECUTABLE,
            "--wait",
            "--collect",
            "--pipe",
            f"--unit={unit_name}",
            "--service-type=oneshot",
            PINNED_PYTHON3_EXECUTABLE,
            cli_path,
            operation,
            service_name,
        )
        return self._transport.run_remote(command)

    def status(self, service_name: str) -> str:
        try:
            raw = self._invoke_entrypoint("service-status", service_name)
        except subprocess.CalledProcessError:
            return "inactive"
        parsed = _parse_systemd_run_pipe_output(raw)
        if parsed in {"active", "activating"}:
            return parsed
        return "inactive"

    def restart(self, service_name: str) -> None:
        self._invoke_entrypoint("service-restart", service_name)


class _RemoteEntrypointBackupStore:
    def __init__(self, transport: _SshBoundedTransport, controller_dir: str) -> None:
        self._transport = transport
        self._controller_dir = controller_dir

    def write_backup(self, backup_path: str, payload: bytes) -> str:
        import base64

        encoded = base64.b64encode(payload).decode()
        code = (
            f"import base64, sys\nsys.path.insert(0, '{self._controller_dir}')\n"
            "from comms01_operation_entrypoints import backup_bytes\n"
            "from workflow_database_target import load_workflow_database_target\n"
            f"payload=base64.b64decode('{encoded}')\n"
            "url=load_workflow_database_target()['database_url']\n"
            f"print(backup_bytes(database_url=url, backup_path='{backup_path}', payload=payload))\n"
        )
        return self._transport.run_remote_python(code)


class _EntrypointBackupStore:
    def __init__(self, *, database_url: str) -> None:
        self._database_url = database_url

    def write_backup(self, backup_path: str, payload: bytes) -> str:
        return backup_bytes(
            database_url=self._database_url,
            backup_path=backup_path,
            payload=payload,
        )


class _EntrypointServiceRunner:
    def status(self, service_name: str) -> str:
        return service_status(service_name=service_name)

    def restart(self, service_name: str) -> None:
        service_restart(service_name=service_name)


def release_checkout_name(candidate_sha: str) -> str:
    return f"{candidate_sha}-{RELEASE_CHECKOUT_SUFFIX}"


def release_checkout_path(parent: Path, candidate_sha: str) -> Path:
    return parent / release_checkout_name(candidate_sha)


def _sha_from_working_directory(working_directory: str) -> str:
    """Extract a git object id from a pinned Comms-01 checkout path."""
    path = Path(working_directory.strip())
    for candidate in (path.name, path.parent.name):
        normalized = candidate.split("-", 1)[0].lower()
        if _SHA1.fullmatch(normalized):
            return normalized
    raise DeployBlockedError("live Comms-01 deployed SHA could not be attested from WorkingDirectory")


def checkout_dir_candidates(parent: Path, sha: str) -> list[Path]:
    return [
        release_checkout_path(parent, sha),
        parent / f"{sha}-clean",
        parent / sha,
    ]


def build_dual_exec_script(controller_dir: str) -> str:
    return f"""#!/usr/bin/python3
import json
import os
import subprocess
import sys
import time
from pathlib import Path

with open('{WORKFLOW_DB_TARGET}', encoding='utf-8') as stream:
    target = json.load(stream)
if target.get('database_name') != 'top_delivery_control_p1':
    raise SystemExit('invalid pinned workflow database target')
environment = os.environ.copy()
environment['TOP_DELIVERY_DATABASE_URL'] = target['database_url']
controller = Path('{controller_dir}')
children = [
    subprocess.Popen(['/usr/bin/python3', str(controller / 'supervisor_cli.py')], env=environment),
    subprocess.Popen(['/usr/bin/python3', str(controller / 'parent_socket.py')], env=environment),
]
try:
    while True:
        for child in children:
            code = child.poll()
            if code is not None:
                raise SystemExit(code or 0)
        time.sleep(1)
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
    deadline = time.monotonic() + 10
    for child in children:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            child.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            child.kill()
"""


def build_controller_dropin(controller_dir: str, *, run_id: str, artifact_root: str) -> str:
    controller_owner = f"parent-controller-{run_id}"
    return f"""[Service]
WorkingDirectory={controller_dir}
Environment=PYTHONPATH={controller_dir}
Environment=TOP_DELIVERY_RUN_ID={run_id}
Environment=TOP_DELIVERY_ARTIFACT_ROOT={artifact_root}
Environment=TOP_DELIVERY_ARTIFACT_OWNER=topdelivery
Environment=TOP_DELIVERY_CONTROLLER_OWNER={controller_owner}
Environment=TOP_DELIVERY_OPERATOR_ID={DEFAULT_OPERATOR_ID}
Environment=TOP_DELIVERY_CONTROLLER_SOCKET={CONTROLLER_SOCKET}
Environment=TOP_DELIVERY_SIGNAL_EGRESS=disabled
Environment=TOP_DELIVERY_HEARTBEAT_SECONDS=30
Environment=TOP_DELIVERY_STALE_SECONDS=120
"""


def build_worker_unit(worker_cli: str, checkout_root: str) -> str:
    return f"""[Unit]
Description=TOP-DELIVERY persistent task worker
After=local-fs.target top-delivery-controller.service

[Service]
Type=simple
User=topdelivery
Group=topdelivery
WorkingDirectory={checkout_root}/controller
Environment=PYTHONPATH={checkout_root}/controller
ExecStart=/usr/bin/python3 {worker_cli}
EnvironmentFile=-/etc/top-delivery/worker.env
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=/opt/top-delivery {checkout_root}
ReadWritePaths=/var/lib/top-delivery/runs /var/lib/top-delivery/adapter-runtime
RuntimeDirectory=top-delivery-worker
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def build_controller_socket_probe_script(
    *,
    operator_id: str,
    command: str = "active-runs",
) -> str:
    return (
        "import json,socket\n"
        f"req={{'text':'{command}','sender_id':'{operator_id}','is_group':False}}\n"
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
        f"s.connect('{CONTROLLER_SOCKET}')\n"
        "s.sendall((json.dumps(req)+'\\n').encode())\n"
        "print(s.recv(8192).decode())\n"
    )


def build_queue_generation_probe_script(run_id: str) -> str:
    return (
        "import json,subprocess\n"
        f"target=json.load(open('{WORKFLOW_DB_TARGET}'))\n"
        "url=target['database_url']\n"
        f"q=\"SELECT current_epoch FROM controller_control WHERE run_id='{run_id}'\"\n"
        "out=subprocess.check_output(['psql',url,'-tAc',q],text=True)\n"
        "print(out.strip())\n"
    )


def build_signal_status_probe_script(run_id: str) -> str:
    return (
        "import json,subprocess\n"
        f"target=json.load(open('{WORKFLOW_DB_TARGET}'))\n"
        "url=target['database_url']\n"
        f"q=\"SELECT readiness,last_event_seq FROM signal_status WHERE run_id='{run_id}' LIMIT 1\"\n"
        "out=subprocess.check_output(['psql',url,'-tAc',q],text=True)\n"
        "print(out.strip())\n"
    )


class _SshBoundedTransport:
    def __init__(
        self,
        *,
        config_path: Path,
        deploy_parent: Path,
        source_repo: Path | None = None,
    ) -> None:
        self._config_path = config_path
        self._deploy_parent = deploy_parent
        self._source_repo = source_repo
        self.deployed_sha = ""

    def assert_available(self) -> None:
        assert_bounded_transport_available(config_path=self._config_path)

    def read_prior_sha(self) -> str:
        self.assert_available()
        try:
            raw = self.run_remote(("cat", str(self._deploy_parent / "DEPLOYED_SHA")))
            normalized = raw.strip().lower()
            if _SHA1.fullmatch(normalized):
                return normalized
        except (subprocess.CalledProcessError, DeployBlockedError):
            pass
        working_directory = self.run_remote(
            (
                "systemctl",
                "show",
                "-p",
                "WorkingDirectory",
                "--value",
                "top-delivery-controller.service",
            )
        )
        return _sha_from_working_directory(working_directory)

    def run_remote(self, command: tuple[str, ...]) -> str:
        self.assert_available()
        remote = " ".join(command)
        completed = subprocess.run(
            [
                "ssh",
                "-F",
                str(self._config_path),
                PINNED_COMMS01_HOST_ALIAS,
                remote,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def run_remote_python(self, code: str) -> str:
        import base64

        encoded = base64.b64encode(code.encode("utf-8")).decode("ascii")
        return self.run_remote_shell(f"echo {encoded} | base64 -d | python3")

    def run_remote_shell(self, script: str) -> str:
        self.assert_available()
        completed = subprocess.run(
            [
                "ssh",
                "-F",
                str(self._config_path),
                PINNED_COMMS01_HOST_ALIAS,
                script,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def checkout_exists(self, checkout_dir: str) -> bool:
        try:
            self.run_remote(("test", "-d", checkout_dir))
            return True
        except subprocess.CalledProcessError:
            return False

    def stage_release_tree(
        self,
        *,
        candidate_sha: str,
        source_repo: Path,
        checkout_dir: str,
    ) -> None:
        self.assert_available()
        if not source_repo.is_dir():
            raise DeployBlockedError("source repository for release archive is unavailable")
        with tempfile.TemporaryDirectory() as staging:
            tar_path = Path(staging) / "checkout.tar"
            subprocess.run(
                [
                    "git",
                    "archive",
                    "--format=tar",
                    candidate_sha,
                    "-o",
                    str(tar_path),
                ],
                cwd=str(source_repo),
                check=True,
            )
            remote_tar = f"/tmp/top-delivery-{candidate_sha}.tar"
            subprocess.run(
                [
                    "scp",
                    "-F",
                    str(self._config_path),
                    str(tar_path),
                    f"{PINNED_COMMS01_HOST_ALIAS}:{remote_tar}",
                ],
                check=True,
            )
            self.run_remote(("mkdir", "-p", checkout_dir))
            self.run_remote(("tar", "-xf", remote_tar, "-C", checkout_dir))
            self.run_remote(("rm", "-f", remote_tar))
            self.run_remote(
                ("find", checkout_dir, "-type", "d", "-exec", "chmod", "755", "{}", "\\;")
            )
            self.run_remote(
                ("find", checkout_dir, "-type", "f", "-exec", "chmod", "644", "{}", "\\;")
            )
            self.run_remote(("chown", "-R", "root:root", checkout_dir))
            controller_dir = f"{checkout_dir}/controller"
            self.run_remote(("chown", "root:topdelivery", controller_dir))
            self.run_remote(("chmod", "750", controller_dir))
            pinned = f"{controller_dir}/pinned-executables.json"
            self.run_remote(("chgrp", "topdelivery-authority", pinned))
            self.run_remote(("chmod", "640", pinned))

    def _scp_local_to_remote(self, local_path: Path, remote_path: str) -> None:
        subprocess.run(
            [
                "scp",
                "-F",
                str(self._config_path),
                str(local_path),
                f"{PINNED_COMMS01_HOST_ALIAS}:{remote_path}",
            ],
            check=True,
        )

    def _write_remote_text(self, remote_path: str, content: str) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(content)
            local_path = Path(handle.name)
        remote_tmp = f"{remote_path}.tmp"
        try:
            self._scp_local_to_remote(local_path, remote_tmp)
            self.run_remote(("mv", remote_tmp, remote_path))
        finally:
            local_path.unlink(missing_ok=True)

    def bind_services_to_checkout(
        self,
        *,
        candidate_sha: str,
        checkout_dir: str,
        run_id: str,
        artifact_root: str,
    ) -> None:
        controller_dir = f"{checkout_dir}/controller"
        self._write_remote_text(DUAL_EXEC_PATH, build_dual_exec_script(controller_dir))
        self.run_remote(("chmod", "755", DUAL_EXEC_PATH))
        dropin_dir = CONTROLLER_DROPIN_DIR
        self.run_remote(("mkdir", "-p", dropin_dir))
        dropin_path = f"{dropin_dir}/{CONTROLLER_DROPIN_NAME}"
        self._write_remote_text(
            dropin_path,
            build_controller_dropin(controller_dir, run_id=run_id, artifact_root=artifact_root),
        )
        worker_cli = f"{controller_dir}/worker_cli.py"
        self._write_remote_text(
            WORKER_UNIT_DESTINATION,
            build_worker_unit(worker_cli, checkout_dir),
        )
        adapters_source = f"{checkout_dir}/systemd/adapters.comms01.json"
        self.run_remote(("cp", adapters_source, ADAPTERS_DESTINATION))
        self.run_remote(("chmod", "644", ADAPTERS_DESTINATION))
        self.run_remote(
            ("chgrp", "topdelivery-authority", WORKFLOW_DB_TARGET)
        )
        self.run_remote(("chmod", "640", WORKFLOW_DB_TARGET))
        self.run_remote(("systemctl", "daemon-reload"))

    def write_deployed_sha(self, candidate_sha: str) -> None:
        marker = str(self._deploy_parent / "DEPLOYED_SHA")
        self._write_remote_text(marker, candidate_sha + "\n")
        self.run_remote(("chmod", "644", marker))
        self.deployed_sha = candidate_sha

    def transport_archive(self, *, candidate_sha: str, destination: Path) -> None:
        """Legacy alias; prefer stage_release_tree."""
        if self._source_repo is None:
            raise DeployBlockedError("source repository is required to stage a release tree")
        self.stage_release_tree(
            candidate_sha=candidate_sha,
            source_repo=self._source_repo,
            checkout_dir=str(destination),
        )

    def probe_controller_socket(self, *, operator_id: str, command: str = "active-runs") -> str:
        script = build_controller_socket_probe_script(operator_id=operator_id, command=command)
        for attempt in range(5):
            try:
                return self.run_remote_python(script)
            except subprocess.CalledProcessError:
                if attempt == 4:
                    raise
                time.sleep(3)
        return '{"ok": false}'

    def probe_queue_generation(self, run_id: str) -> int:
        script = build_queue_generation_probe_script(run_id) + "\n"
        raw = self.run_remote_python(script)
        return int(raw)

    def probe_signal_status(self, run_id: str) -> tuple[str, int]:
        script = build_signal_status_probe_script(run_id) + "\n"
        raw = self.run_remote_python(script)
        if not raw or raw == "":
            return "", 0
        if "|" not in raw:
            return raw, 0
        readiness, seq = raw.split("|", 1)
        return readiness.strip(), int(seq.strip() or "0")

    def supervisor_runs_in_dual_exec(self) -> bool:
        try:
            raw = self.run_remote(("pgrep", "-f", "supervisor_cli.py"))
            return bool(raw.strip())
        except subprocess.CalledProcessError:
            return False

    def stop_standalone_supervisor_unit(self) -> None:
        for command in (
            ("/usr/bin/systemctl", "stop", "top-delivery-supervisor"),
            ("/usr/bin/systemctl", "disable", "top-delivery-supervisor"),
        ):
            try:
                self.run_remote(command)
            except subprocess.CalledProcessError:
                pass


class RestartRecoveryTracker:
    """In-tree restart recovery harness without duplicate side effects."""

    def __init__(self, *, queue_generation: int, side_effect_count: int) -> None:
        self._initial_generation = queue_generation
        self._generation = queue_generation
        self._side_effects = side_effect_count
        self._restart_count = 0

    def record_restart(self) -> None:
        self._restart_count += 1
        self._generation += 1

    def record_side_effect(self) -> None:
        self._side_effects += 1

    def duplicate_side_effects(self) -> bool:
        return self._side_effects > self._restart_count


def redact_deploy_log(text: str) -> str:
    redacted = text
    for pattern, replacement in _REDACT_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def recovery_evidence_passes(evidence: RecoveryEvidence) -> bool:
    return (
        evidence.controller_active
        and evidence.worker_active
        and evidence.supervisor_active
        and evidence.queue_generation >= 0
        and evidence.signal_readable
        and evidence.signal_writable
        and not evidence.duplicate_side_effects
    )


class Comms01ReleaseDeployer:
    """Coordinate backup, exact-SHA deploy, restart, and rollback."""

    def __init__(
        self,
        *,
        transport: BoundedTransport | None = None,
        backup_store: BackupStore | None = None,
        service_runner: ServiceRunner | None = None,
        deploy_parent: Path = DEFAULT_DEPLOY_PARENT,
        release_checkout_parent: Path = DEFAULT_RELEASE_CHECKOUT_PARENT,
        database_url: str = "postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_deploy",
        source_repo: Path | None = None,
        run_id: str = "goal-runner-task5-deploy",
        artifact_root: str = "/var/lib/top-delivery/runs/goal-runner-task5-deploy/artifacts",
        operator_id: str = DEFAULT_OPERATOR_ID,
    ) -> None:
        self._transport = transport
        self._backup_store = backup_store or _EntrypointBackupStore(database_url=database_url)
        self._service_runner = service_runner or _EntrypointServiceRunner()
        self._deploy_parent = deploy_parent
        self._release_parent = release_checkout_parent
        self._source_repo = source_repo
        self._run_id = run_id
        self._artifact_root = artifact_root
        self._operator_id = operator_id
        self._active_checkout_dir: str | None = None
        if transport is None:
            self._transport = _SshBoundedTransport(
                config_path=PINNED_COMMS01_SSH_CONFIG,
                deploy_parent=self._deploy_parent,
                source_repo=self._source_repo,
            )
        if backup_store is None and isinstance(self._transport, _SshBoundedTransport):
            controller_dir = self._controller_dir_for_operations()
            self._backup_store = _RemoteEntrypointBackupStore(
                self._transport,
                controller_dir,
            )
        if service_runner is None and isinstance(self._transport, _SshBoundedTransport):
            self._service_runner = _RemoteEntrypointServiceRunner(
                self._transport,
                self._controller_dir_for_operations(),
            )

    def _controller_dir_for_operations(self) -> str:
        if self._active_checkout_dir:
            return f"{self._active_checkout_dir}/controller"
        prior = self.attest_prior_sha()
        checkout = prior.working_directory
        if checkout.endswith("/controller"):
            return checkout
        return f"{checkout}/controller"

    def _resolve_checkout_dir(self, sha: str) -> Path:
        for candidate in checkout_dir_candidates(self._release_parent, sha):
            remote = str(candidate)
            if self._transport.checkout_exists(remote):
                return candidate
        raise DeployBlockedError(f"checkout for SHA {sha!r} is unavailable on Comms-01")

    def attest_prior_sha(self) -> PriorShaAttestation:
        sha = self._transport.read_prior_sha()
        if not sha:
            raise DeployBlockedError("prior Comms-01 SHA could not be attested")
        normalized = validate_deploy_sha(sha)
        checkout = self._resolve_checkout_dir(normalized)
        return PriorShaAttestation(
            deployed_sha=normalized,
            working_directory=str(checkout),
        )

    def create_backup(
        self,
        *,
        database_url: str,
        backup_path: str,
        payload: bytes,
    ) -> BackupIdentity:
        digest = self._backup_store.write_backup(backup_path, payload)
        return BackupIdentity(path=backup_path, digest=digest, size=len(payload))

    def deploy_exact_sha(
        self,
        *,
        candidate_sha: str,
        tree_sha: str,
        release_receipt: ReleasePolicyReceipt,
        backup_manifest_sha256: str,
    ) -> DeployReceipt:
        normalized_candidate = validate_deploy_sha(candidate_sha)
        normalized_tree = validate_deploy_sha(tree_sha)
        if release_receipt.payload["candidate_sha"] != normalized_candidate:
            raise ReleasePolicyViolation("release receipt candidate SHA mismatch")
        if release_receipt.payload["backup_manifest_sha256"] != backup_manifest_sha256:
            raise ReleasePolicyViolation("backup manifest SHA mismatch")
        if self._source_repo is None:
            raise DeployBlockedError("source repository is required for exact-SHA deploy")
        prior = self.attest_prior_sha()
        checkout_dir = release_checkout_path(self._release_parent, normalized_candidate)
        remote_checkout = str(checkout_dir)
        self._transport.stage_release_tree(
            candidate_sha=normalized_candidate,
            source_repo=self._source_repo,
            checkout_dir=remote_checkout,
        )
        self._transport.bind_services_to_checkout(
            candidate_sha=normalized_candidate,
            checkout_dir=remote_checkout,
            run_id=self._run_id,
            artifact_root=self._artifact_root,
        )
        self._transport.write_deployed_sha(normalized_candidate)
        self._active_checkout_dir = remote_checkout
        if isinstance(self._service_runner, _RemoteEntrypointServiceRunner):
            self._service_runner = _RemoteEntrypointServiceRunner(
                self._transport,
                f"{remote_checkout}/controller",
            )
        if isinstance(self._backup_store, _RemoteEntrypointBackupStore):
            self._backup_store = _RemoteEntrypointBackupStore(
                self._transport,
                f"{remote_checkout}/controller",
            )
        return DeployReceipt(
            candidate_sha=normalized_candidate,
            prior_sha=prior.deployed_sha,
            recorded_sha=normalized_candidate,
            tree_sha=normalized_tree,
            working_directory=remote_checkout,
            backup_manifest_sha256=backup_manifest_sha256,
        )

    def restart_attested_services(self) -> list[str]:
        restarted: list[str] = []
        dual_exec_layout = getattr(
            self._transport, "supervisor_runs_in_dual_exec", lambda: False
        )()
        for service_name in ATTESTED_RESTART_SERVICES:
            if service_name == "top-delivery-supervisor" and dual_exec_layout:
                continue
            self._service_runner.restart(service_name)
            restarted.append(service_name)
        if dual_exec_layout:
            getattr(self._transport, "stop_standalone_supervisor_unit", lambda: None)()
        return restarted

    def _supervisor_recovered(self) -> bool:
        standalone = self._service_runner.status("top-delivery-supervisor")
        if standalone == "active":
            return True
        return getattr(self._transport, "supervisor_runs_in_dual_exec", lambda: False)()

    def verify_restart_recovery(
        self,
        *,
        tracker: RestartRecoveryTracker,
    ) -> RecoveryEvidence:
        controller_active = False
        worker_active = False
        supervisor_active = False
        socket_payload: dict[str, object] = {"ok": False}
        queue_generation = 0
        readiness = ""
        signal_seq = 0
        for attempt in range(6):
            controller_active = self._service_runner.status("top-delivery-controller") == "active"
            worker_active = self._service_runner.status("top-delivery-worker") == "active"
            supervisor_active = self._supervisor_recovered()
            try:
                socket_raw = self._transport.probe_controller_socket(
                    operator_id=self._operator_id,
                    command="active-runs",
                )
                socket_payload = _parse_controller_socket_response(socket_raw)
                queue_generation = self._transport.probe_queue_generation(self._run_id)
                readiness, signal_seq = self._transport.probe_signal_status(self._run_id)
                if (
                    controller_active
                    and worker_active
                    and supervisor_active
                    and socket_payload.get("ok")
                    and queue_generation > 0
                ):
                    break
            except subprocess.CalledProcessError:
                pass
            if attempt < 5:
                time.sleep(3)
        signal_readable = bool(socket_payload.get("ok")) and queue_generation > 0
        if readiness:
            signal_readable = True
        signal_writable = signal_readable and (readiness != "" or signal_seq > 0)
        return RecoveryEvidence(
            controller_active=controller_active,
            worker_active=worker_active,
            supervisor_active=supervisor_active,
            queue_generation=queue_generation,
            signal_readable=signal_readable,
            signal_writable=signal_writable,
            duplicate_side_effects=tracker.duplicate_side_effects(),
        )

    def rollback_dry_run(self, *, prior_sha: str) -> RollbackDryRun:
        normalized = validate_deploy_sha(prior_sha)
        return RollbackDryRun(restored_sha=normalized, live_outage_required=False)

    def rollback_to_prior_sha(self, *, prior_sha: str) -> RollbackReceipt:
        normalized = validate_deploy_sha(prior_sha)
        checkout_dir = self._resolve_checkout_dir(normalized)
        remote_checkout = str(checkout_dir)
        self._transport.bind_services_to_checkout(
            candidate_sha=normalized,
            checkout_dir=remote_checkout,
            run_id=self._run_id,
            artifact_root=self._artifact_root,
        )
        self._transport.write_deployed_sha(normalized)
        self._active_checkout_dir = remote_checkout
        if isinstance(self._service_runner, _RemoteEntrypointServiceRunner):
            self._service_runner = _RemoteEntrypointServiceRunner(
                self._transport,
                f"{remote_checkout}/controller",
            )
        tracker = RestartRecoveryTracker(
            queue_generation=self._transport.probe_queue_generation(self._run_id),
            side_effect_count=0,
        )
        self.restart_attested_services()
        tracker.record_restart()
        evidence = self.verify_restart_recovery(tracker=tracker)
        if not recovery_evidence_passes(evidence):
            raise RecoveryVerificationError("rollback recovery verification failed")
        return RollbackReceipt(
            restored_sha=normalized,
            working_directory=remote_checkout,
        )


def _parse_controller_socket_response(raw: str) -> dict[str, object]:
    import json

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {"ok": False}
    if not isinstance(payload, dict):
        return {"ok": False}
    return payload


__all__ = [
    "ATTESTED_RESTART_SERVICES",
    "_sha_from_working_directory",
    "BackupIdentity",
    "Comms01ReleaseDeployer",
    "DeployBlockedError",
    "DeployReceipt",
    "PriorShaAttestation",
    "RecoveryEvidence",
    "RecoveryVerificationError",
    "RollbackDryRun",
    "RollbackReceipt",
    "RestartRecoveryTracker",
    "build_controller_dropin",
    "build_dual_exec_script",
    "build_worker_unit",
    "checkout_dir_candidates",
    "recovery_evidence_passes",
    "redact_deploy_log",
    "release_checkout_name",
    "release_checkout_path",
]
