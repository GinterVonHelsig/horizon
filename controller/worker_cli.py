"""CLI entrypoint for the TOP-DELIVERY worker."""

from __future__ import annotations

import argparse
import json
import os
from decimal import Decimal
from pathlib import Path

from artifact_isolation import load_relay_token
from harness_adapters.registry import AdapterRegistry, load_registry_config
from openrouter_budget import BudgetLimits, OpenRouterBudgetGuard
from worktree_transport import WorktreeTransport
from worker import TaskWorker, WorkerLoop


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TOP-DELIVERY task worker")
    parser.add_argument("--run-id", default=os.environ.get("TOP_DELIVERY_RUN_ID"))
    parser.add_argument("--owner", default=os.environ.get("TOP_DELIVERY_WORKER_OWNER", "top-delivery-worker"))
    parser.add_argument("--artifact-root", default=os.environ.get("TOP_DELIVERY_ARTIFACT_ROOT"))
    parser.add_argument("--db-url", default=os.environ.get("TOP_DELIVERY_DATABASE_URL"))
    parser.add_argument("--config", default=os.environ.get("TOP_DELIVERY_ADAPTER_CONFIG"))
    parser.add_argument("--poll-interval", type=float, default=float(os.environ.get("TOP_DELIVERY_WORKER_POLL_SECONDS", "5")))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--expected-task-id", default=None)
    return parser


def build_controller(db_url: str, artifact_root: Path):
    from parent_controller import ParentController

    return ParentController(db_url, artifact_root=artifact_root, lease_holder=False)


def main(argv: list[str] | None = None) -> int:
    load_relay_token()
    args = build_parser().parse_args(argv)
    if args.expected_task_id and (not args.once or not args.run_id):
        raise SystemExit("--expected-task-id requires --once and --run-id")
    if not args.artifact_root or not args.db_url or not args.config:
        raise SystemExit("artifact root, db url, and adapter config are required")

    artifact_root = Path(args.artifact_root).resolve()
    config = load_registry_config(Path(args.config), validate_executables=False)
    registry = AdapterRegistry.from_config(
        config,
        artifact_dir=artifact_root / "adapter-runtime",
        validate_executables=False,
    )
    controller = build_controller(args.db_url, artifact_root)
    budget_guard = None
    per_run = os.environ.get("TOP_DELIVERY_OPENROUTER_PER_RUN_USD")
    monthly = os.environ.get("TOP_DELIVERY_OPENROUTER_MONTHLY_USD")
    if per_run and monthly:
        budget_guard = OpenRouterBudgetGuard(
            BudgetLimits(per_run_usd=Decimal(per_run), monthly_usd=Decimal(monthly)),
            ledger_path=artifact_root / "openrouter-budget-ledger.json",
        )
    transport = None
    if os.environ.get("TOP_DELIVERY_ENABLE_MIRROR_TRANSPORT", "").lower() in {"1", "true", "yes"}:
        transport = WorktreeTransport(
            mirror_root=Path(os.environ.get("TOP_DELIVERY_MIRROR_ROOT", "/var/lib/top-delivery")),
            repo_name=os.environ.get("TOP_DELIVERY_MIRROR_REPO", "top-delivery"),
        )
    from goal_runner import GoalRunner

    worker = TaskWorker(
        controller,
        artifact_root,
        registry.adapters,
        default_executor=registry.default_executor,
        default_auditor=registry.default_auditor,
        goal_runner=GoalRunner(budget_guard=budget_guard),
        worktree_transport=transport,
        transport_owner=args.owner,
    )
    loop = WorkerLoop(
        worker,
        run_id=args.run_id or None,
        owner=args.owner,
        poll_interval=args.poll_interval,
        once=args.once,
        expected_task_id=args.expected_task_id,
    )
    try:
        poll_succeeded = loop.run()
    finally:
        controller.close()
    if args.once:
        if poll_succeeded and not loop.permission_error_seen:
            print(json.dumps({"status": "ok", "mode": "once"}))
            return 0
        print(json.dumps({"status": "failed", "mode": "once", "reason": "permission_error"}))
        return 1
    if loop.permission_error_seen:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
