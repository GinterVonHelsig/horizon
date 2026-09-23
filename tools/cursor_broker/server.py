"""Root-owned AF_UNIX Cursor broker: UID 999, two fixed routes, five no-replay slots."""
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

SCHEMA = "horizon-cursor-broker.config.v1"
REQUEST_SCHEMA = "horizon-cursor-broker.request.v1"
MAX_REQUEST = 1_048_576
MAX_OUTPUT = 1_000_000
RUN = re.compile(r"goal-[0-9a-f]{16}")
TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
EXPECTED_ROUTES = {
    "gateway-delivery-disposable-file": {"role": "executor", "model": "composer-2.5", "mode": "agent", "timeout_seconds": 300},
    "cursor-independent-review": {"role": "auditor", "model": "cursor-grok-4.6-high", "mode": "ask", "timeout_seconds": 900},
    # One non-generating account/catalog preflight. It has its own durable
    # slot and accepts only the CLI's documented `models` subcommand.
    "cursor-auth-catalog-preflight": {"role": "preflight", "model": None, "mode": "catalog", "timeout_seconds": 60},
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def peer_uid(sock: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("peer_credentials_unavailable")
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def _secure_path(path: Path, *, private: bool = False, directory: bool = False) -> Path:
    if not path.is_absolute() or ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("unsafe_path")
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022):
        raise ValueError("untrusted_path_owner_or_mode")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("wrong_path_type")
    return path


def verify_workspace(config: dict) -> int:
    """Return an O_PATH fd pinned to the validated private workspace inode.

    The broker must not read or list the UID-owned 0700 workspace. The caller
    owns the returned descriptor and must close it after dispatch (or after
    startup validation). The executor child receives it only long enough to
    fchdir after dropping to the workspace owner.
    """
    path = Path(config["workspace_root"])
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        raise ValueError("workspace_path_invalid")
    directory_flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open("/", directory_flags)
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            child = os.open(part, directory_flags, dir_fd=fd)
            info = os.fstat(child)
            if final:
                if (info.st_uid != config["workspace_uid"] or info.st_mode & 0o077
                        or (info.st_dev, info.st_ino) != (config["workspace_dev"], config["workspace_ino"])):
                    os.close(child)
                    raise ValueError("workspace_inode_or_owner_mismatch")
            else:
                sticky_tmp = part == "tmp" and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                if info.st_uid != 0 or (info.st_mode & 0o022 and not sticky_tmp):
                    os.close(child)
                    raise ValueError("workspace_parent_not_root_controlled")
            os.close(fd)
            fd = child
        return fd
    except FileNotFoundError as exc:
        os.close(fd)
        raise ValueError("workspace_not_provisioned") from exc
    except BaseException:
        os.close(fd)
        raise


def load_config(path: Path) -> dict:
    _secure_path(path)
    config = json.loads(path.read_text())
    keys = {"schema", "enabled", "socket_path", "socket_gid", "peer_uid", "run_id",
        "workspace_root", "workspace_uid", "workspace_dev", "workspace_ino", "ledger_root",
        "executable", "executable_resolved", "executable_sha256", "cursor_home", "child_home",
        "child_uid", "child_gid", "max_sessions", "max_request_bytes", "max_output_bytes", "routes"}
    if not isinstance(config, dict) or set(config) != keys or config["schema"] != SCHEMA or config["enabled"] is not True:
        raise ValueError("broker_configuration_disabled_or_invalid")
    if config["run_id"] != "goal-5b434f0a3d720c89" or not RUN.fullmatch(config["run_id"]):
        raise ValueError("broker_run_not_allowlisted")
    for key in ("socket_gid", "peer_uid", "workspace_uid", "workspace_dev", "workspace_ino", "child_uid", "child_gid"):
        if type(config[key]) is not int or config[key] < 0:
            raise ValueError("broker_numeric_identity_invalid")
    if config["peer_uid"] != 999 or config["child_uid"] != 999 or config["child_gid"] != 989:
        raise ValueError("broker_worker_identity_not_allowlisted")
    if config["max_sessions"] != 5 or config["max_request_bytes"] != MAX_REQUEST or config["max_output_bytes"] != MAX_OUTPUT:
        raise ValueError("broker_budget_invalid")
    if config["routes"] != EXPECTED_ROUTES:
        raise ValueError("broker_route_allowlist_mismatch")
    socket_path = Path(config["socket_path"])
    if not socket_path.is_absolute() or len(os.fsencode(socket_path)) >= 108:
        raise ValueError("broker_socket_path_invalid")
    for key in ("workspace_root", "ledger_root", "executable", "executable_resolved", "cursor_home", "child_home"):
        if not isinstance(config[key], str) or not Path(config[key]).is_absolute():
            raise ValueError("broker_path_invalid")
    executable = Path(config["executable"])
    resolved = executable.resolve(strict=True)
    if str(resolved) != config["executable_resolved"] or sha256(resolved) != config["executable_sha256"]:
        raise ValueError("broker_cursor_executable_pin_mismatch")
    ledger = _secure_path(Path(config["ledger_root"]), private=True, directory=True)
    if ledger.stat().st_mode & 0o777 != 0o700:
        raise ValueError("broker_ledger_must_be_0700")
    if not Path(config["cursor_home"]).is_dir() or not Path(config["child_home"]).is_dir():
        raise ValueError("broker_runtime_directory_missing")
    return config


def _receive(conn: socket.socket, maximum: int) -> dict:
    conn.settimeout(5)
    buf = bytearray()
    while not buf.endswith(b"\n"):
        block = conn.recv(min(65536, maximum + 1 - len(buf)))
        if not block:
            raise ValueError("request_incomplete")
        buf.extend(block)
        if len(buf) > maximum:
            raise ValueError("request_too_large")
    value = json.loads(buf)
    if not isinstance(value, dict):
        raise ValueError("request_not_object")
    return value


def _atomic(path: Path, value: dict) -> None:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            size = os.write(fd, view)
            view = view[size:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    parent_fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _identity(request: dict) -> dict:
    return {key: request[key] for key in ("run_id", "task_id", "attempt_id", "role", "route_id")}


def _launch_failure_diagnostic(exc: BaseException) -> dict:
    """Return only bounded, non-sensitive process-boundary diagnostics."""
    if isinstance(exc, PermissionError):
        return {"launch_failure_class": "permission_denied", "launch_errno": errno.EACCES}
    if isinstance(exc, FileNotFoundError):
        return {"launch_failure_class": "executable_or_path_missing", "launch_errno": errno.ENOENT}
    if isinstance(exc, subprocess.SubprocessError):
        return {"launch_failure_class": "child_setup_failed"}
    if isinstance(exc, OSError):
        number = exc.errno
        return {"launch_failure_class": "process_io_error",
            "launch_errno": number if type(number) is int and 0 <= number < 256 else None}
    if isinstance(exc, ValueError):
        return {"launch_failure_class": "launch_configuration_invalid"}
    return {"launch_failure_class": "launch_outcome_unknown"}


def _child_preexec(uid: int, gid: int, workspace_fd: int) -> None:
    # Broker systemd unit grants only SETUID/SETGID/SETPCAP for this transition.
    # Clear ambient and bounding capabilities while SETPCAP is still available;
    # setgroups/setresgid/setresuid then consume the remaining setup authority.
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    PR_CAPBSET_DROP, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, PR_SET_NO_NEW_PRIVS = 24, 47, 4, 38
    if libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
        os._exit(126)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        os._exit(126)
    last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    for cap in [value for value in range(last_cap + 1) if value != 8] + [8]:
        if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
            os._exit(126)
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    # Enter the pinned inode only after the child owns its 0700 permissions.
    os.fchdir(workspace_fd)
    os.close(workspace_fd)


def _launch(config: dict, route: dict, prompt: str) -> dict:
    workspace_fd = config.get("_workspace_fd")
    if type(workspace_fd) is not int:
        raise ValueError("workspace_descriptor_missing")
    executable = config["executable"]
    if route["mode"] == "catalog":
        argv = [executable, "models"]
    else:
        argv = [executable, "-p", prompt, "--output-format", "stream-json", "--model", route["model"]]
        if route["mode"] == "agent":
            argv.extend(["--force", "--sandbox", "enabled", "--trust"])
        else:
            argv.extend(["--mode", "ask", "--sandbox", "enabled", "--trust"])
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": config["child_home"],
        "USER": "topdelivery", "LOGNAME": "topdelivery", "CURSOR_HOME": config["cursor_home"],
        "CURSOR_CONFIG_DIR": config["cursor_home"]}
    proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, start_new_session=True,
        pass_fds=(workspace_fd,),
        preexec_fn=lambda: _child_preexec(config["child_uid"], config["child_gid"], workspace_fd))
    started = time.monotonic()
    selector = selectors.DefaultSelector()
    assert proc.stdout is not None and proc.stderr is not None
    os.set_blocking(proc.stdout.fileno(), False)
    os.set_blocking(proc.stderr.fileno(), False)
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    kept = {"stdout": bytearray(), "stderr": bytearray()}
    observed = {"stdout": 0, "stderr": 0}
    deadline = started + route["timeout_seconds"]
    termination = None
    term_at = None
    while selector.get_map():
        now = time.monotonic()
        if termination is None and now >= deadline:
            termination, term_at = "timeout", now
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        if termination is not None and term_at is not None and now >= term_at + 1.0:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if termination is not None and term_at is not None and now >= term_at + 2.0:
            for key in list(selector.get_map().values()):
                selector.unregister(key.fileobj)
                key.fileobj.close()
            break
        for key, _ in selector.select(0.05):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            kind = key.data
            observed[kind] += len(chunk)
            room = max(0, config["max_output_bytes"] - len(kept[kind]))
            if room:
                kept[kind].extend(chunk[:room])
            if observed[kind] > config["max_output_bytes"] and termination is None:
                termination, term_at = "output_limit", time.monotonic()
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
    try:
        exit_code = proc.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            exit_code = proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            exit_code = None
    return {"exit_code": exit_code, "outcome": termination or "completed",
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": bytes(kept["stdout"]), "stderr": bytes(kept["stderr"]),
        "stdout_bytes": observed["stdout"], "stderr_bytes": observed["stderr"],
        "stdout_truncated": observed["stdout"] > len(kept["stdout"]),
        "stderr_truncated": observed["stderr"] > len(kept["stderr"])}


def dispatch(config: dict, request: dict, uid: int, *, launcher=_launch) -> dict:
    if uid != config["peer_uid"]:
        return {"status": "blocked", "reason": "peer_uid_not_allowed"}
    common_keys = {"schema", "run_id", "task_id", "attempt_id", "role", "route_id", "cwd", "operation"}
    if request.get("schema") != REQUEST_SCHEMA:
        return {"status": "blocked", "reason": "request_schema_invalid"}
    if request["run_id"] != config["run_id"] or not TOKEN.fullmatch(request["task_id"]) or not TOKEN.fullmatch(request["attempt_id"]):
        return {"status": "blocked", "reason": "task_identity_not_allowlisted"}
    route = config["routes"].get(request["route_id"])
    if not route or route["role"] != request["role"] or request["cwd"] != config["workspace_root"]:
        return {"status": "blocked", "reason": "route_or_workspace_not_allowlisted"}
    if route["mode"] == "catalog":
        if set(request) != common_keys or request["route_id"] != "cursor-auth-catalog-preflight" or request["operation"] != "models":
            return {"status": "blocked", "reason": "catalog_preflight_request_invalid"}
        prompt = None
    else:
        if set(request) != common_keys | {"prompt"} or request["operation"] != "prompt":
            return {"status": "blocked", "reason": "request_schema_invalid"}
        prompt = request["prompt"]
        if not isinstance(prompt, str) or not prompt or len(prompt.encode()) > config["max_request_bytes"] // 2:
            return {"status": "blocked", "reason": "prompt_size_invalid"}
    workspace_fd = verify_workspace(config)
    try:
        return _dispatch_with_workspace(config, request, route, prompt, workspace_fd, launcher=launcher)
    finally:
        os.close(workspace_fd)


def _dispatch_with_workspace(config: dict, request: dict, route: dict, prompt: str,
                              workspace_fd: int, *, launcher) -> dict:
    ledger_root = Path(config["ledger_root"])
    run_ledger = ledger_root / config["run_id"]
    run_ledger.mkdir(mode=0o700, exist_ok=True)
    _secure_path(run_ledger, private=True, directory=True)
    identity = _identity(request)
    request_key = hashlib.sha256(json.dumps([request["run_id"], request["task_id"], request["role"]], separators=(",", ":")).encode()).hexdigest()
    record_path = run_ledger / f"{request_key}.json"
    lock_fd = os.open(ledger_root / ".broker.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        files = list(run_ledger.glob("*.json"))
        if record_path.exists():
            return {"status": "blocked", "reason": "duplicate_no_replay"}
        if len(files) >= config["max_sessions"]:
            return {"status": "blocked", "reason": "session_budget_exhausted"}
        intent = {"identity": identity,
            "input_sha256": hashlib.sha256((prompt if prompt is not None else "cursor-agent models").encode()).hexdigest(),
            "operation": request["operation"],
            "workspace_dev": config["workspace_dev"], "workspace_ino": config["workspace_ino"],
            "state": "intent", "created_at": int(time.time())}
        _atomic(record_path, intent)
    finally:
        os.close(lock_fd)
    try:
        launch_config = {**config, "_workspace_fd": workspace_fd}
        result = launcher(launch_config, route, prompt)
        terminal = {**intent, "state": "terminal", "outcome": result["outcome"],
            "exit_code": result["exit_code"], "duration_seconds": result["duration_seconds"],
            "stdout_bytes": result["stdout_bytes"], "stderr_bytes": result["stderr_bytes"],
            "stdout_sha256": hashlib.sha256(result["stdout"]).hexdigest(),
            "stderr_sha256": hashlib.sha256(result["stderr"]).hexdigest(),
            "stdout_truncated": result["stdout_truncated"], "stderr_truncated": result["stderr_truncated"]}
        _atomic(record_path, terminal)
        if result["outcome"] != "completed":
            return {"status": "blocked", "reason": result["outcome"] + "_no_replay"}
        return {"status": "complete", "exit_code": result["exit_code"] if result["exit_code"] is not None else 78,
            "stdout_b64": base64.b64encode(result["stdout"]).decode(),
            "stderr_b64": base64.b64encode(result["stderr"]).decode()}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        # Intent remains durable and consumes one slot. Never retry an uncertain launch.
        try:
            _atomic(record_path, {**intent, **_launch_failure_diagnostic(exc)})
        except OSError:
            # Keep the original intent if diagnostics cannot be persisted.
            pass
        return {"status": "blocked", "reason": "launch_outcome_unknown_no_replay"}


def handle_connection(conn: socket.socket, config: dict, *, launcher=_launch) -> None:
    try:
        request = _receive(conn, min(config["max_request_bytes"], MAX_REQUEST))
        response = dispatch(config, request, peer_uid(conn), launcher=launcher)
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
        response = {"status": "blocked", "reason": "invalid_request_or_configuration"}
    data = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) <= 3_000_000:
        try:
            conn.sendall(data)
        except OSError:
            pass


def serve(config_path: Path) -> None:
    config = load_config(config_path)
    if os.geteuid() != 0:
        raise ValueError("broker_requires_root_service_identity")
    workspace_fd = verify_workspace(config)
    os.close(workspace_fd)
    path = Path(config["socket_path"])
    parent = _secure_path(path.parent, directory=True)
    if os.path.lexists(path):
        raise ValueError("broker_socket_collision_no_unlink")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        os.chmod(path, 0o660)
        os.chown(path, 0, config["socket_gid"])
        inode = path.stat().st_ino
        server.listen(8)
        try:
            while True:
                conn, _ = server.accept()
                with conn:
                    try:
                        if load_config(config_path) != config or _secure_path(path.parent, directory=True) != parent:
                            raise ValueError("broker_configuration_changed")
                    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
                        try:
                            conn.sendall(b'{"reason":"invalid_request_or_configuration","status":"blocked"}\n')
                        except OSError:
                            pass
                    else:
                        handle_connection(conn, config)
        finally:
            if path.exists() and path.stat().st_ino == inode:
                path.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        serve(args.config)
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
