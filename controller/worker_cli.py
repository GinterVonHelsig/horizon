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
    parser.add_argument("--health-dir", default=os.environ.get("TOP_DELIVERY_WORKER_HEALTH_DIR", "/var/lib/top-delivery/worker-health"))
    parser.add_argument("--recover-block", action="store_true")
    parser.add_argument("--recovery-reason")
    return parser


def build_controller(db_url: str, artifact_root: Path):
    from parent_controller import ParentController

    return ParentController(db_url, artifact_root=artifact_root, lease_holder=False)


def _main(argv: list[str] | None = None) -> int:
    load_relay_token()
    args = build_parser().parse_args(argv)
    from worker_health import WorkerHealth
    health = WorkerHealth(Path(args.health_dir))
    scope = args.run_id or "available"
    if args.recover_block:
        if not args.recovery_reason:
            raise SystemExit("--recover-block requires --recovery-reason after correcting the cause")
        health.recover(scope, args.recovery_reason)
        print(json.dumps({"status": "recovery_acknowledged", "execution_started": False}))
        return 0
    if health.state(scope)["blocked"]:
        print(json.dumps({"status": "blocked", **health.state(scope)}))
        return 78
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
    import psycopg2
    try:
        controller = build_controller(args.db_url, artifact_root)
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        state = health.fail(scope, reason="database_unavailable", permanent=False)
        print(json.dumps({"status": "blocked" if state["blocked"] else "retry_pending", **state}))
        return 78 if state["blocked"] else 1
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
    from model_routing import load_model_routing

    worker = TaskWorker(
        controller,
        artifact_root,
        registry.adapters,
        default_executor=registry.default_executor,
        default_auditor=registry.default_auditor,
        goal_runner=GoalRunner(budget_guard=budget_guard),
        worktree_transport=transport,
        transport_owner=args.owner,
        adapter_config=config,
        routing_policy=load_model_routing(Path(__file__).resolve().parents[1] / "architecture/model-routing.yaml"),
    )
    loop = WorkerLoop(
        worker,
        run_id=args.run_id or None,
        owner=args.owner,
        poll_interval=args.poll_interval,
        once=args.once,
        expected_task_id=args.expected_task_id,
        health=health,
    )
    try:
        poll_succeeded = loop.run()
    finally:
        controller.close()
    if args.once:
        if poll_succeeded:
            print(json.dumps({"status": loop.last_status, "mode": "once"}))
            return 0
    print(json.dumps({"status": loop.last_status, "mode": "once" if args.once else "continuous"}))
    return 78 if health.state(scope)["blocked"] else (0 if poll_succeeded else 1)


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except (OSError, ValueError) as exc:
        # Config/health-store failures must also stop systemd restart polling.
        # Exception messages can include credentials, paths, or request bodies.
        print(json.dumps({"status": "blocked", "reason": "worker_configuration_or_filesystem", "exception_type": type(exc).__name__}))
        return 78
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        print(json.dumps({"status": "blocked", "reason": "worker_arguments_invalid"}))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
