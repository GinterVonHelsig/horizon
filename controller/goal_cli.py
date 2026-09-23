"""Canonical TOP-DELIVERY goal submission CLI."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from goal_submitter import GoalSubmitter, build_controller
from prompt_ingest import PromptIngestError, parse_prompt_file

_CANONICAL_RUNS_ROOT = Path("/var/lib/top-delivery/runs")
_EXISTING_PARENT_RUN_ID = re.compile(r"^goal-[0-9a-f]{16}$")


def _artifact_root_from_env(explicit: str | None) -> Path:
    if explicit:
        return Path(os.path.abspath(Path(explicit).expanduser()))
    env_value = os.environ.get("TOP_DELIVERY_ARTIFACT_ROOT")
    if not env_value:
        raise SystemExit("artifact root is required via --artifact-root or TOP_DELIVERY_ARTIFACT_ROOT")
    return Path(os.path.abspath(Path(env_value).expanduser()))


def _database_url_from_env(explicit: str | None) -> str:
    if explicit:
        return explicit
    env_value = os.environ.get("TOP_DELIVERY_DATABASE_URL")
    if not env_value:
        raise SystemExit(
            "database URL is required via --database-url or TOP_DELIVERY_DATABASE_URL"
        )
    return env_value


def _inspect_payload(prompt_path: Path) -> dict[str, object]:
    parsed = parse_prompt_file(prompt_path)
    return {
        "title": parsed.title,
        "objective": parsed.objective,
        "mission": parsed.mission,
        "prompt_digest": parsed.sha256,
        "byte_count": parsed.byte_count,
        "run_id": parsed.run_id,
        "workstream_count": len(parsed.workstreams),
        "workstreams": [
            {
                "number": workstream.number,
                "title": workstream.title,
                "task_id": workstream.task_id,
                "required_disposition": workstream.required_disposition,
                "dependencies": list(workstream.dependencies),
            }
            for workstream in parsed.workstreams
        ],
        "allowed": list(parsed.allowed),
        "forbidden": list(parsed.forbidden),
    }


def _emit(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _validate_existing_parent_id(parent_run_id: str) -> None:
    if not _EXISTING_PARENT_RUN_ID.fullmatch(parent_run_id):
        raise ValueError("existing parent run id must match goal-<16 hex chars>")


def _runtime_artifact_root(
    existing_parent: str | None,
    explicit: str | None,
    *,
    dry_run: bool,
) -> Path | None:
    if dry_run or existing_parent is None:
        return None
    _validate_existing_parent_id(existing_parent)
    if explicit:
        return Path(explicit).expanduser().resolve()
    return (_CANONICAL_RUNS_ROOT / existing_parent / "artifacts").resolve()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TOP-DELIVERY canonical goal CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="parse a prompt without submission")
    inspect_parser.add_argument("--prompt", required=True, type=Path)

    submit_parser = subparsers.add_parser("submit", help="submit a prompt to the parent controller")
    submit_parser.add_argument("--prompt", required=True, type=Path)
    submit_parser.add_argument("--artifact-root", default=None)
    submit_parser.add_argument("--database-url", default=None)
    submit_parser.add_argument("--prerequisites-json", type=Path)
    submit_parser.add_argument('--qualification-profile', choices=['cursor-disposable-v1'])
    status_parser = subparsers.add_parser("status", help="read durable whole-goal status, not worker/task success")
    status_parser.add_argument("--run-id", required=True)
    status_parser.add_argument("--artifact-root", required=True)
    status_parser.add_argument("--database-url", default=None)
    submit_parser.add_argument(
        "--adapter-config",
        default=os.environ.get("TOP_DELIVERY_ADAPTER_CONFIG"),
        help="adapter registry JSON used to snapshot executor/auditor routes into goal-spec",
    )
    submit_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="parse and write artifacts without durable controller writes",
    )
    submit_parser.add_argument(
        "--existing-parent",
        default=None,
        help="schedule tasks under an already-registered parent run instead of creating a new one",
    )
    submit_parser.add_argument(
        "--runtime-artifact-root",
        default=None,
        help=(
            "controller and bundle publish root for durable existing-parent submit; "
            "defaults to /var/lib/top-delivery/runs/<existing-parent>/artifacts"
        ),
    )

    args = parser.parse_args(argv)
    prompt_path = Path(args.prompt).expanduser() if hasattr(args, "prompt") else None

    try:
        if args.command == "status":
            controller = build_controller(_database_url_from_env(args.database_url), Path(args.artifact_root), dry_run=False)
            try:
                result = controller.durable_goal_status(args.run_id)
                _emit(result)
                return result["exit_code"]
            finally:
                controller.close()
        if args.command == "inspect":
            _emit(_inspect_payload(prompt_path))
            return 0

        # Route/profile admission is before controller construction or artifact writes.
        config = None
        if args.adapter_config:
            from harness_adapters.registry import load_registry_config
            from qualification_profile import admit_profile
            config = load_registry_config(Path(args.adapter_config), validate_executables=False)
            admit_profile(config, args.qualification_profile,
                          _database_url_from_env(args.database_url) if not args.dry_run else 'postgresql://unused@127.0.0.1:5432/td_test_dry_run')
        elif args.qualification_profile:
            raise ValueError('qualification profile requires explicit registry')
        artifact_root = _artifact_root_from_env(args.artifact_root)
        runtime_root = _runtime_artifact_root(
            args.existing_parent,
            args.runtime_artifact_root,
            dry_run=args.dry_run,
        )
        if args.dry_run:
            controller = build_controller("", artifact_root, dry_run=True)
            mode = "dry_run"
        elif args.existing_parent:
            if runtime_root is None or not runtime_root.is_dir():
                raise SystemExit(
                    "runtime artifact root is required for existing-parent durable submit"
                )
            db_url = _database_url_from_env(args.database_url)
            controller = build_controller(db_url, runtime_root, dry_run=False)
            mode = "durable"
        else:
            db_url = _database_url_from_env(args.database_url)
            controller = build_controller(db_url, artifact_root, dry_run=False)
            mode = "durable"
        try:
            if config is not None:
                controller.adapter_config = config
            task_routing = None
            if args.adapter_config:
                from goal_submitter import TaskRoutingSnapshot
                routes = config["routes"]
                from harness_adapters.registry import validate_task_routes
                validate_task_routes(config, routes["default_executor"], routes["default_auditor"])
                task_routing = TaskRoutingSnapshot(
                    executor_adapter=routes["default_executor"],
                    auditor_adapter=routes["default_auditor"],
                    qualification_profile=args.qualification_profile,
                )
            elif not args.dry_run:
                raise ValueError("durable submission requires --adapter-config with independent executable routes")
            receipt = GoalSubmitter(
                controller, artifact_root, mode=mode, task_routing=task_routing,
                prerequisites=json.loads(args.prerequisites_json.read_text()) if args.prerequisites_json else None,
            ).submit(prompt_path, existing_parent=args.existing_parent)
        finally:
            close = getattr(controller, "close", None)
            if callable(close):
                close()
        _emit(receipt.to_dict())
        return 0
    except (PromptIngestError, ValueError, SystemExit) as exc:
        if isinstance(exc, SystemExit):
            raise
        sys.stderr.write(f"goal submission failed: {exc}\n")
        return 1
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        sys.stderr.write(f"goal submission failed: {exc}\n")
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit as exc:
        if exc.code not in (0, None):
            if not str(exc):
                sys.stderr.write("goal submission failed\n")
        raise
