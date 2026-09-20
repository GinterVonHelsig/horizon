"""Compare the complete saved service/config closure, allowing only P40 changes.

The coordinator captures the existing host state once BEFORE installation and
pins its digest in this reviewed module. Secrets are compared by hashes only.
Root is trusted; a service UID cannot edit the anchor, units, inputs or source.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
from pathlib import Path

ANCHOR_PATH = Path("/opt/operator-harness/artifacts/20260912T-p40-root-cause-repair/service-anchor-r5.json")
ANCHOR_SHA256 = "a6b9c8386e349544ef72cb9d3622d29983c4ae0553aa1db58ae6740218a52e6c"
WORKER = "top-delivery-worker.service"
CONTROLLER = "top-delivery-controller.service"
PROOF_DROPIN = Path("/etc/systemd/system/top-delivery-worker.service.d/p40-one-shot-proof.conf")
TRUST = "TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS"
PARENT = "goal-3eb7b972ec15809e"
UNIT_PROPERTIES = (
    "ExecStart", "ExecStartPre", "ExecStartPost", "ExecCondition", "ExecReload", "ExecStop", "ExecStopPost",
    "Restart", "User", "Group", "Type", "WorkingDirectory", "Environment", "EnvironmentFiles",
    "FragmentPath", "DropInPaths", "RootDirectory", "RootImage", "PrivateMounts", "PrivateUsers",
    "PrivateNetwork", "NetworkNamespacePath", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem",
    "ProtectSystem", "ProtectHome", "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths",
    "NoNewPrivileges", "SupplementaryGroups", "DynamicUser", "PassEnvironment", "UnsetEnvironment",
    "CapabilityBoundingSet", "AmbientCapabilities", "MainPID", "ActiveState",
)
CONFIG_FILES = (
    Path("/etc/top-delivery/worker.env"), Path("/etc/top-delivery/adapters.json"),
    Path("/etc/top-delivery/comms01-workflow-db-target.json"),
    Path("/usr/local/sbin/top-delivery-section0-dual-exec"),
)


def _hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _normal(text: str, release: Path) -> str:
    return text.replace(str(release), "<REVIEWED_RELEASE>")


def _root_file(path: Path) -> bytes:
    from submission_bundle import _open_directory, _read_bytes
    fd = _open_directory(path.parent, trusted=True, require_service_read=False, allow_root_sticky=True)
    os.close(fd)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("service closure file must be root-controlled regular data")
    return _read_bytes(path)


def normalized_unit(settings: dict[str, str], unit: str, release: Path) -> dict:
    result = {}
    for key in UNIT_PROPERTIES:
        if key in {"MainPID", "ActiveState", "FragmentPath", "DropInPaths"} or (unit == WORKER and key in {"ExecStart", "Restart"}):
            continue
        value = settings.get(key, "")
        if key == "Environment":
            entries = dict(item.split("=", 1) for item in shlex.split(value) if "=" in item)
            entries.pop(TRUST, None)  # Independently required to equal1 at activation.
            result[key] = _hash({k: _normal(v, release) for k, v in entries.items()})
        elif key.startswith("Exec"):
            commands = re.findall(r"\{ path=(.*?) ; argv\[\]=(.*?) ; ignore_errors=(.*?) ;", value)
            if value and (not commands or len(commands) != value.count("{ path=")):
                raise ValueError("unrecognized systemd command representation")
            result[key] = [[_normal(part, release) for part in command] for command in commands]
        else:
            result[key] = _normal(value, release)
    return result


def _child_environment(pid: str, release: Path, *, activation: bool) -> str:
    values = dict(item.split(b"=", 1) for item in Path(f"/proc/{int(pid)}/environ").read_bytes().split(b"\0") if b"=" in item)
    selected = {key.decode(): value.decode() for key, value in values.items()
                if key.startswith((b"TOP_DELIVERY_", b"PYTHON", b"LD_")) or key in {b"PATH", b"VIRTUAL_ENV"}}
    if activation and (selected.get(TRUST) != "1" or selected.get("TOP_DELIVERY_RUN_ID") != PARENT
                       or selected.get("PYTHONPATH") != str(release / "controller")):
        raise ValueError("running controller environment differs from reviewed activation")
    selected.pop(TRUST, None)
    return _hash({key: _normal(value, release) for key, value in selected.items()})


def _file_closure(release: Path, paths: set[Path], expected_task: str | None) -> dict:
    paths = set(paths)
    if expected_task is not None:
        expected = ("[Service]\nExecStart=\nExecStart=/usr/bin/python3 " + str(release / "controller/worker_cli.py")
                    + f" --once --run-id {PARENT} --expected-task-id {expected_task}\nRestart=no\n").encode()
        if PROOF_DROPIN not in paths or _root_file(PROOF_DROPIN) != expected:
            raise ValueError("temporary proof drop-in differs from its exact reviewed bytes")
        proof_info = PROOF_DROPIN.lstat()
        if (stat.S_IMODE(proof_info.st_mode), proof_info.st_uid, proof_info.st_gid) != (0o644, 0, 0):
            raise ValueError("temporary proof drop-in mode/owner differs")
        paths.remove(PROOF_DROPIN)
    elif PROOF_DROPIN in paths:
        raise ValueError("baseline must precede proof drop-in installation")
    files = {}
    for path in sorted(paths):
        raw = _root_file(path)
        text = _normal(raw.decode(), release)
        if path.name == "goal-runner-deploy.conf":
            text = text.replace(f"Environment={TRUST}=1\n", "")
        info = path.stat()
        files[str(path)] = {"sha256": hashlib.sha256(text.encode()).hexdigest(),
                            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
    return files


def _saved_anchor() -> dict:
    raw = _root_file(ANCHOR_PATH)
    if hashlib.sha256(raw).hexdigest() != ANCHOR_SHA256:
        raise ValueError("saved service/config anchor is missing or changed")
    return json.loads(raw)


def verify_installed_config(release: Path, expected_task: str) -> None:
    """Read installed bytes, not systemd's potentially stale pre-reload cache."""
    saved = _saved_anchor()
    paths = {Path(name) for name in saved["files"]}
    paths.add(PROOF_DROPIN)
    # Detect unreviewed ordinary/prefix/global drop-ins even before daemon-reload.
    # Generated/transient effective settings are additionally compared after
    # reload and before service start by verify_service_anchor(static=True).
    directories = {"service.d", "top-.service.d", "top-delivery-.service.d",
                   WORKER + ".d", CONTROLLER + ".d"}
    for root in ("/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system"):
        for name in directories:
            paths.update(Path(root, name).glob("*.conf"))
    if _file_closure(release, paths, expected_task) != saved["files"]:
        raise ValueError("installed service/config bytes differ before daemon-reload")


def capture_service_anchor(release: Path, unit_reader, runner, *, expected_task: str | None = None,
                           static: bool = False) -> dict:
    units = {name: unit_reader(name) for name in (WORKER, CONTROLLER)}
    paths = set(CONFIG_FILES)
    for name, settings in units.items():
        if not settings.get("FragmentPath"):
            raise ValueError("service has no installed fragment")
        paths.add(Path(settings["FragmentPath"]))
        paths.update(Path(value) for value in shlex.split(settings.get("DropInPaths", "")))
    files = _file_closure(release, paths, expected_task)
    result = {"units": {name: normalized_unit(settings, name, release) for name, settings in units.items()},
              "files": files, "auth_path": str(Path("/opt/top-delivery-auth").resolve(strict=True))}
    if static:
        return result
    children = {}
    rows = runner(["ps", "--ppid", units[CONTROLLER]["MainPID"], "-o", "pid=,args="]).splitlines()
    for row in rows:
        parts = shlex.split(row)
        if len(parts) >= 3 and parts[1] == "/usr/bin/python3":
            script = Path(parts[2])
            if script.parent == release / "controller" and script.name in {"supervisor_cli.py", "parent_socket.py"}:
                if script.name in children:
                    raise ValueError("duplicate controller child")
                children[script.name] = _child_environment(parts[0], release, activation=expected_task is not None)
    if set(children) != {"supervisor_cli.py", "parent_socket.py"}:
        raise ValueError("missing expected controller child environment")
    result["controller_environments"] = children
    return result


def verify_service_anchor(release: Path, expected_task: str, unit_reader, runner, *, static: bool = False) -> None:
    from recovery_dependencies import verify_dependencies
    verify_dependencies()
    saved = _saved_anchor()
    if static:
        saved.pop("controller_environments")
    actual = capture_service_anchor(release, unit_reader, runner, expected_task=expected_task, static=static)
    if actual != saved:
        raise ValueError("service/config/auth/running-environment drift beyond approved P40 changes")
