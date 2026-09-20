"""Concrete, target-bound Comms-01 P35/P40 one-shot start gate. No install/DDL."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shlex
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from recovery_handover import current_supervisor, verify_handover
from recovery_lifecycle import ADAPTERS, guard_action, verify_stage, verify_standalone, verify_final_stage

PARENT = "goal-3eb7b972ec15809e"
TASKS = ("goal-3fa391ad04eedbc8-ws-01", "goal-ad220af074326a0e-ws-01")
WORKER = "top-delivery-worker.service"
CONTROLLER = "top-delivery-controller.service"
CURRENT = Path("/opt/top-delivery-p1/current")
WORKER_ENV = Path("/etc/top-delivery/worker.env")
GUARDED_ENV = {"TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS", "PYTHONPATH", "TOP_DELIVERY_RUN_ID"}


def _run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError(f"checked command failed: {Path(argv[0]).name}")
    return result.stdout


def verify_source(repo: Path, release: Path, accepted_sha: str, accepted_tree: str) -> int:
    from recovery_acceptance import accepted_source
    acceptance = accepted_source()
    if accepted_tree != acceptance["tree"]:
        raise ValueError("source tree is not independently accepted")
    from submission_bundle import _open_directory
    for directory in (repo, release):
        fd = _open_directory(directory, trusted=True, require_service_read=False,
                             allow_root_sticky=True)
        os.close(fd)
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (accepted_sha, accepted_tree)):
        raise ValueError("exact accepted commit and tree are required")
    git = ["git", "--no-replace-objects", "-C", str(repo)]
    if _run(git + ["rev-parse", f"{accepted_sha}^{{tree}}", "refs/remotes/origin/main"]).splitlines() != [accepted_tree, accepted_sha]:
        raise ValueError("accepted source is not the exact known merged main tree")
    if _run(git + ["rev-parse", acceptance["candidate_sha"] + "^{tree}"]).strip() != accepted_tree:
        raise ValueError("reviewed candidate object differs from accepted tree")
    _run(git + ["merge-base", "--is-ancestor", acceptance["candidate_sha"], accepted_sha])
    if not release.is_dir() or release.is_symlink():
        raise ValueError("installed release must be a real directory")
    listing = _run(git + ["ls-tree", "-rz", "--full-tree", accepted_sha])
    expected = set()
    expected_directories = {"."}
    for item in listing.split("\0"):
        if not item:
            continue
        metadata, name = item.split("\t", 1)
        mode, kind, digest = metadata.split()
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or kind != "blob":
            raise ValueError("unsupported source tree entry")
        path = release / relative
        expected_directories.update(str(p) for p in relative.parents)
        for ancestor in (release, *[release / p for p in relative.parents if str(p) != "."]):
            info = ancestor.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o755):
                raise ValueError("installed source ancestor is replaceable")
        info = path.lstat()
        if info.st_uid != 0 or info.st_gid != 0:
            raise ValueError("installed source entry is not operator controlled")
        if mode == "120000" and stat.S_ISLNK(info.st_mode):
            if not path.resolve(strict=True).is_relative_to(release):
                raise ValueError("installed source link escapes the closed release")
            data = os.fsencode(os.readlink(path))
        elif mode in {"100644", "100755"} and stat.S_ISREG(info.st_mode):
            if stat.S_IMODE(info.st_mode) != int(mode[-3:], 8):
                raise ValueError("installed executable mode differs")
            data = path.read_bytes()
        else:
            raise ValueError("installed source type differs")
        if hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() != digest:
            raise ValueError("installed source bytes differ from reviewed git tree")
        expected.add(name)
    actual, directories = set(), {"."}
    pending = [release]
    while pending:
        directory = pending.pop()
        for entry in os.scandir(directory):
            name = str(Path(entry.path).relative_to(release))
            if entry.is_dir(follow_symlinks=False):
                directories.add(name)
                pending.append(Path(entry.path))
            else:
                # Includes EVERY non-directory: regular, link, FIFO, socket,
                # device. An extra empty directory is also a closure failure.
                actual.add(name)
    if not expected or actual != expected or directories != expected_directories:
        raise ValueError("installed source contains missing or extra entries")
    verify_service_readability(release)
    return len(expected)


def verify_service_readability(release: Path) -> None:
    """Actual UID read/traversal, catching ancestor permissions and ACL denial."""
    account = pwd.getpwnam("topdelivery")
    code = """import os,sys
from pathlib import Path
root=Path(sys.argv[1]);pending=[root]
while pending:
 for e in os.scandir(pending.pop()):
  if e.is_dir(follow_symlinks=False): pending.append(Path(e.path))
  elif e.is_file(follow_symlinks=False):
   with open(e.path,'rb') as f:
    while f.read(1048576): pass
  elif e.is_symlink():
   target=Path(e.path).resolve(strict=True)
   assert target.is_relative_to(root)
   assert os.access(target,os.R_OK)
  else: raise ValueError('special node')
"""
    result = subprocess.run(["/usr/bin/python3", "-I", "-B", "-c", code, str(release)],
        user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd="/",
        env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError("installed release is not readable by the actual service identity")


def verify_bundles(release: Path) -> dict:
    # Fresh service-identity process reads the actual protected store. No caller
    # boolean, no privileged substitute reader, and no write/credential access.
    code = """import hashlib,json
from pathlib import Path
import submission_bundle as s
from goal_dependencies import goal_spec_for_task,ready_successor_workstreams
p='goal-3eb7b972ec15809e'; r=Path('/var/lib/top-delivery-submission-bundles')
expected={'goal-3fa391ad04eedbc8':'51ec05c6637b705ec867ffa12ce2209be87235d2352802b9597bd6c9414fc846','goal-ad220af074326a0e':'a8b6c2b23772db94b0b63f86e935c57026ee7da63c7d9497cfe435ce7bfb26e7'}
tasks=[]
for submission,digest in expected.items():
 b=r/'runs'/p/'submissions'/submission
 assert hashlib.sha256(s._read_bytes(b/'goal-spec.json',trusted=True)).hexdigest()==digest
 spec=goal_spec_for_task(r,p,submission+'-ws-01')
 for w in spec['workstreams']:
  assert goal_spec_for_task(r,p,w['task_id'])['run_id']==submission
  tasks.append(w['task_id'])
first='goal-3fa391ad04eedbc8-ws-01'
ready=ready_successor_workstreams(r,p,first,{first:'verified'})
assert [w.task_id for w in ready]==['goal-3fa391ad04eedbc8-ws-02']
print(json.dumps({'tasks':tasks,'uid':__import__('os').geteuid(),'successor_isolation':True}))
"""
    account = pwd.getpwnam("topdelivery")
    result = subprocess.run(["/usr/bin/python3", "-B", "-c", code],
        user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd="/",
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(release / "controller"),
             "TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS": "1"},
        capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError("actual service identity could not validate original bundles")
    return json.loads(result.stdout)


def _unit(unit: str) -> dict[str, str]:
    from recovery_service_anchor import UNIT_PROPERTIES
    output = _run(["systemctl", "show", unit, *[arg for key in UNIT_PROPERTIES for arg in ("-p", key)]])
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def _guarded_environment(settings: dict[str, str], unit: str) -> dict[str, str]:
    environment = dict(value.split("=", 1) for value in shlex.split(settings.get("Environment", "")) if "=" in value)
    references = settings.get("EnvironmentFiles", "")
    if references:
        if unit != WORKER or references not in {
            f"{WORKER_ENV} (ignore_errors=yes)", f"{WORKER_ENV} (ignore_errors=no)"
        }:
            raise ValueError("unexpected service environment file")
        # This bounded gate accepts the actual simple one-line assignments used
        # on Comms-01, not arbitrary shell or systemd multi-line syntax. Values
        # never execute; only the three nonsecret source/authority keys escape.
        fd = os.open(WORKER_ENV, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd) as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError("service environment file is not operator controlled")
            for line in handle:
                if line.rstrip().endswith("\\"):
                    raise ValueError("multi-line environment file requires explicit inspection")
                match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)\s*", line.rstrip("\n"))
                if match and match.group(1) in GUARDED_ENV:
                    parsed = shlex.split(line)
                    if len(parsed) != 1 or "=" not in parsed[0]:
                        raise ValueError("guarded environment assignment is unsupported")
                    key, value = parsed[0].split("=", 1)
                    environment[key] = value
    return {key: value for key, value in environment.items() if key in GUARDED_ENV}


def verify_units(release: Path, expected_task: str, *, static: bool = False) -> None:
    worker, controller = _unit(WORKER), _unit(CONTROLLER)
    expected = ["/usr/bin/python3", str(release / "controller/worker_cli.py"),
                "--once", "--run-id", PARENT, "--expected-task-id", expected_task]
    matches = re.findall(r"argv\[\]=(.*?);", worker.get("ExecStart", ""))
    if len(matches) != 1 or shlex.split(matches[0]) != expected:
        raise ValueError("effective worker command is not the exact bounded one-shot")
    if worker.get("Restart") != "no" or worker.get("ActiveState") != "inactive" or worker.get("MainPID") != "0":
        raise ValueError("worker must be inactive with Restart=no")
    for unit, settings, expected_user in ((WORKER, worker, "topdelivery"), (CONTROLLER, controller, "root")):
        if settings.get("User") != expected_user or settings.get("WorkingDirectory") != str(release / "controller"):
            raise ValueError("effective service identity or working directory differs")
        environment = _guarded_environment(settings, unit)
        if environment.get("TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS") != "1" or environment.get("PYTHONPATH") != str(release / "controller"):
            raise ValueError("effective trusted-store/source environment differs")
        if environment.get("TOP_DELIVERY_RUN_ID") != PARENT:
            raise ValueError("effective parent pin differs")
    if static:
        if controller.get("ActiveState") != "inactive" or controller.get("MainPID") != "0":
            raise ValueError("controller must be stopped during static validation")
        from recovery_service_anchor import verify_service_anchor
        verify_service_anchor(release, expected_task, _unit, _run, static=True)
        return
    if controller.get("ActiveState") != "active":
        raise ValueError("parent controller is not active")
    pid = int(controller.get("MainPID", "0"))
    if pid <= 1:
        raise ValueError("parent controller PID is invalid")
    children = _run(["ps", "--ppid", str(pid), "-o", "args="]).splitlines()
    for script in ("supervisor_cli.py", "parent_socket.py"):
        if not any(shlex.split(line)[:2] == ["/usr/bin/python3", str(release / "controller" / script)] for line in children):
            raise ValueError("running controller child does not use reviewed source")
    from recovery_service_anchor import verify_service_anchor
    verify_service_anchor(release, expected_task, _unit, _run)


def read_queue() -> dict:
    from recovery_db import read_queue as pinned_read_queue
    return pinned_read_queue()


def final_start_revalidation(stage: str, before_stage: dict, release: Path,
                             identity: dict | None = None, queue: dict | None = None) -> dict:
    """Fast last checks AFTER graph/DB/file work, directly before start.

    This reduces the observation race; independent reads and systemctl start
    are not atomic. The real worker claim still enforces its DB fence and task.
    """
    standalone = verify_final_stage(stage, before_stage)
    if identity is not None:
        if current_supervisor(release) != identity:
            raise ValueError('supervisor changed during final lifecycle check')
        # Pure validation of the captured event's monotonic freshness; no new
        # database, graph or file-inventory work follows the identity check.
        verify_handover(queue, identity)
    return standalone


def start_verified(repo: Path, release: Path, accepted_sha: str, accepted_tree: str,
                   expected_task: str, *, start: bool = False, controller_stage: bool = False,
                   adapters_stage: bool = False) -> dict:
    if os.geteuid() != 0 or expected_task not in TASKS:
        raise ValueError("root coordinator and exact P35/P40 task are required")
    if controller_stage and adapters_stage:
        raise ValueError('controller and adapter stages must be separate')
    from submission_bundle import _open_directory
    fd = _open_directory(CURRENT.parent, trusted=True, require_service_read=False)
    os.close(fd)
    if CURRENT.lstat().st_uid != 0 or not CURRENT.is_symlink():
        raise ValueError("current must be an operator-owned release symlink")
    expected_release = Path("/opt/top-delivery-p1") / f"{accepted_sha}-goal-runner"
    if release != expected_release or CURRENT.resolve(strict=True) != release:
        raise ValueError("current does not resolve to the exact accepted release")
    files = verify_source(repo, release, accepted_sha, accepted_tree)
    from recovery_service_anchor import verify_installed_config
    verify_installed_config(release, expected_task)
    stage = 'controller' if controller_stage else ('adapters' if adapters_stage else 'worker')
    before_stage = verify_stage(stage)  # Four-unit boundary BEFORE daemon-reload.
    if controller_stage:
        for name in (WORKER, CONTROLLER):
            unit = _unit(name)
            if unit.get("ActiveState") != "inactive" or unit.get("MainPID") != "0":
                raise ValueError("both services must be stopped before controller activation")
        # Reload is not execution. Files/source are checked BEFORE it; effective
        # unit settings are then checked while still stopped, BEFORE any start.
        if start:
            _run(["systemctl", "daemon-reload"])
        verify_units(release, expected_task, static=True)
        queue = read_queue()  # Exact target, zero active attempts; lease may have expired.
        if queue.get("active") != 0 or queue.get("head") != expected_task:
            raise ValueError("controller activation would encounter unexpected active/queued work")
        standalone = verify_standalone()
        if verify_stage(stage) != before_stage:
            raise ValueError('lifecycle stage changed before controller start')
        lifecycle = guard_action('start', (CONTROLLER,))
        standalone = final_start_revalidation(stage, before_stage, release)
        if start:
            _run(["systemctl", "start", CONTROLLER])
        return {"captured_at": datetime.now(timezone.utc).isoformat(), "stage": "controller",
                "accepted_sha": accepted_sha, "accepted_tree": accepted_tree,
                "verified_files": files, "queue": queue, "started": start,
                "standalone_supervisor": standalone, "lifecycle": lifecycle,
                "lifecycle_stage": before_stage,
                "disposition": "CONTROLLER_STARTED_NOT_ACCEPTED" if start else "STATIC_PREFLIGHT_PASSED"}
    bundle_evidence = verify_bundles(release)
    if start:
        _run(["systemctl", "daemon-reload"])
    verify_units(release, expected_task)
    standalone = verify_standalone()
    targets = ADAPTERS if adapters_stage else (WORKER,)
    lifecycle = guard_action('start', targets)
    identity = current_supervisor(release)
    queue = read_queue()
    if queue.get("database") != "top_delivery_control_p1" or queue.get("head") != expected_task or queue.get("active") != 0 or queue.get("lease_live") is not True:
        raise ValueError("immediate queue/lease observation does not authorize this one-shot")
    handover = verify_handover(queue, identity)
    if current_supervisor(release) != identity:
        raise ValueError('supervisor restarted during worker activation gate')
    standalone = verify_standalone()
    if verify_stage(stage) != before_stage:
        raise ValueError('lifecycle stage changed during handover verification')
    # Repeat the complete loaded graph/state/job gate AFTER the database and
    # process probes, then recheck fast process/stage invariants before start.
    lifecycle = guard_action('start', targets)
    standalone = final_start_revalidation(stage, before_stage, release, identity, queue)
    # worker_cli --expected-task-id rechecks inside the real claim transaction;
    # a race selecting another task raises and rolls back before model execution.
    if start:
        _run(["systemctl", "start", *targets])
    return {"captured_at": datetime.now(timezone.utc).isoformat(), "expected_task": expected_task,
            "accepted_sha": accepted_sha, "accepted_tree": accepted_tree, "verified_files": files,
            "bundle_evidence": bundle_evidence, "queue": queue, "started": start,
            "handover": handover, "standalone_supervisor": standalone, "lifecycle": lifecycle,
            "lifecycle_stage": before_stage,
            "stage": "adapters" if adapters_stage else "worker",
            "disposition": ("ADAPTERS_STARTED_NOT_ACCEPTED" if adapters_stage else "STARTED_NOT_ACCEPTED") if start else "PREFLIGHT_PASSED_NOT_STARTED"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "release", "accepted-sha", "accepted-tree", "expected-task"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--controller-stage", action="store_true")
    parser.add_argument("--adapters-stage", action="store_true")
    args = parser.parse_args()
    result = start_verified(Path(args.repo), Path(args.release), args.accepted_sha,
                            args.accepted_tree, args.expected_task, start=args.start,
                            controller_stage=args.controller_stage, adapters_stage=args.adapters_stage)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
