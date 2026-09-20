#!/usr/bin/env python3
"""Task-6 clean re-acceptance: submit + poll without operator SQL or manual chown."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

from artifact_owner import apply_artifact_owner  # noqa: E402
from goal_dependencies import TERMINAL_PARENT_STATES  # noqa: E402
from goal_submitter import GoalSubmitter, TaskRoutingSnapshot, build_controller  # noqa: E402
from prompt_ingest import parse_prompt_file  # noqa: E402


@dataclass(frozen=True)
class TerminalPollResult:
    run_id: str
    task_states: dict[str, str]
    all_terminal: bool
    elapsed_seconds: float
    timed_out: bool


def prepare_artifact_root(artifact_root: Path) -> Path:
    resolved = artifact_root.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    apply_artifact_owner(resolved)
    if not resolved.is_dir():
        raise ValueError("artifact_root must be a directory")
    return resolved


def expected_task_ids(run_id: str, workstream_count: int) -> list[str]:
    from prompt_ingest import derive_task_id

    return [derive_task_id(run_id, number) for number in range(1, workstream_count + 1)]


def all_workstreams_terminal(
    task_states: dict[str, str],
    expected_ids: list[str],
) -> bool:
    if len(task_states) < len(expected_ids):
        return False
    for task_id in expected_ids:
        state = task_states.get(task_id)
        if state not in TERMINAL_PARENT_STATES:
            return False
    return True


def artifact_tree_owned_by(artifact_root: Path, owner_name: str) -> dict[str, Any]:
    passwd = pwd.getpwnam(owner_name)
    run_root = artifact_root
    if not run_root.exists():
        return {"checked": False, "reason": "artifact_root missing"}
    uid = passwd.pw_uid
    gid = passwd.pw_gid
    mismatches: list[str] = []
    for path in sorted(run_root.rglob("*")):
        if path.is_symlink():
            continue
        stat = path.stat()
        if stat.st_uid != uid or stat.st_gid != gid:
            mismatches.append(str(path))
    return {
        "owner": owner_name,
        "uid": uid,
        "gid": gid,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:20],
    }


def poll_parent_tasks(
    controller: Any,
    run_id: str,
    expected_ids: list[str],
    *,
    timeout_seconds: float,
    poll_interval: float,
) -> TerminalPollResult:
    start = time.monotonic()
    timed_out = False
    states: dict[str, str] = {}
    while True:
        states = controller._repo.list_parent_task_states(run_id)
        if all_workstreams_terminal(states, expected_ids):
            break
        if time.monotonic() - start >= timeout_seconds:
            timed_out = True
            break
        time.sleep(poll_interval)
    elapsed = time.monotonic() - start
    return TerminalPollResult(
        run_id=run_id,
        task_states=states,
        all_terminal=all_workstreams_terminal(states, expected_ids),
        elapsed_seconds=elapsed,
        timed_out=timed_out,
    )


def build_evidence(
    *,
    receipt: Any,
    poll: TerminalPollResult,
    artifact_root: Path,
    owner_check: dict[str, Any],
    submit_only: bool,
) -> dict[str, Any]:
    return {
        "kind": "task6_clean_reacceptance",
        "submit_only": submit_only,
        "run_id": receipt.run_id,
        "prompt_digest": receipt.prompt_digest,
        "receipt_status": receipt.status,
        "artifact_root": str(artifact_root),
        "artifact_owner_check": owner_check,
        "expected_task_ids": receipt.task_ids,
        "poll": {
            "all_terminal": poll.all_terminal,
            "timed_out": poll.timed_out,
            "elapsed_seconds": poll.elapsed_seconds,
            "task_states": poll.task_states,
        },
        "operator_surgery": {
            "manual_sql": False,
            "manual_chown": False,
            "note": "submit path uses apply_artifact_owner only",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--database-url", default=os.environ.get("TOP_DELIVERY_DATABASE_URL"))
    parser.add_argument(
        "--adapter-config",
        default=os.environ.get("TOP_DELIVERY_ADAPTER_CONFIG"),
    )
    parser.add_argument("--evidence-out", type=Path, default=None)
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument(
        "--submit-only",
        action="store_true",
        help="submit without polling for worker-driven terminals",
    )
    args = parser.parse_args(argv)

    if not args.database_url:
        sys.stderr.write("database URL is required via --database-url or TOP_DELIVERY_DATABASE_URL\n")
        return 1

    os.environ.setdefault("TOP_DELIVERY_ARTIFACT_OWNER", "topdelivery")
    owner_name = os.environ.get("TOP_DELIVERY_ARTIFACT_OWNER", "topdelivery")

    parsed = parse_prompt_file(args.prompt)
    artifact_root = prepare_artifact_root(Path(args.artifact_root))
    task_routing = None
    if args.adapter_config:
        from harness_adapters.registry import load_registry_config

        routes = load_registry_config(Path(args.adapter_config), validate_executables=False)["routes"]
        task_routing = TaskRoutingSnapshot(
            executor_adapter=routes["default_executor"],
            auditor_adapter=routes["default_auditor"],
        )

    controller = build_controller(args.database_url, artifact_root, dry_run=False)
    try:
        receipt = GoalSubmitter(
            controller,
            artifact_root,
            mode="durable",
            task_routing=task_routing,
        ).submit(args.prompt)
        owner_check = artifact_tree_owned_by(artifact_root, owner_name)
        expected_ids = expected_task_ids(parsed.run_id, len(parsed.workstreams))
        if args.submit_only:
            poll = TerminalPollResult(
                run_id=parsed.run_id,
                task_states={},
                all_terminal=False,
                elapsed_seconds=0.0,
                timed_out=False,
            )
        else:
            poll = poll_parent_tasks(
                controller,
                parsed.run_id,
                expected_ids,
                timeout_seconds=args.timeout_seconds,
                poll_interval=args.poll_interval,
            )
        evidence = build_evidence(
            receipt=receipt,
            poll=poll,
            artifact_root=artifact_root,
            owner_check=owner_check,
            submit_only=args.submit_only,
        )
        payload = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
        if args.evidence_out:
            args.evidence_out.parent.mkdir(parents=True, exist_ok=True)
            args.evidence_out.write_text(payload)
        sys.stdout.write(payload)
        if owner_check.get("mismatch_count", 0) > 0:
            return 2
        if args.submit_only:
            return 0
        if poll.timed_out or not poll.all_terminal:
            return 3
        return 0
    finally:
        close = getattr(controller, "close", None)
        if callable(close):
            close()


if __name__ == "__main__":
    raise SystemExit(main())
