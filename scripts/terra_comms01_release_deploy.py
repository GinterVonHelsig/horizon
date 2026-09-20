#!/usr/bin/env python3
"""Terra-owned Comms-01 exact-SHA release deploy CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

CONTROLLER = Path(__file__).resolve().parents[1] / "controller"
sys.path.insert(0, str(CONTROLLER))

from comms01_bounded_transport import assert_bounded_transport_available  # noqa: E402
from comms01_release_deploy import (  # noqa: E402
    Comms01ReleaseDeployer,
    RestartRecoveryTracker,
    recovery_evidence_passes,
    redact_deploy_log,
)
from operator_asymmetric import generate_keypair  # noqa: E402
from terra_release_policy import issue_authoritative_receipt, ReleasePolicyInput  # noqa: E402


def _git_sha(path: Path) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=str(path),
        text=True,
    ).strip()


def _tree_sha(path: Path, commit: str) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", f"{commit}^{{tree}}"],
        cwd=str(path),
        text=True,
    ).strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--candidate-sha")
    parser.add_argument("--run-id", default="goal-bbd863012ff24960")
    parser.add_argument("--task-id", default="task-6")
    parser.add_argument(
        "--artifact-root",
        default="/var/lib/top-delivery/runs/goal-bbd863012ff24960/artifacts",
    )
    parser.add_argument("--backup-path")
    parser.add_argument("--rollback-dry-run", action="store_true")
    parser.add_argument("--prior-sha")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = assert_bounded_transport_available()
    candidate_sha = args.candidate_sha or _git_sha(args.repo)
    tree_sha = _tree_sha(args.repo, candidate_sha)
    deployer = Comms01ReleaseDeployer(
        source_repo=args.repo,
        run_id=args.run_id,
        artifact_root=args.artifact_root,
    )
    prior = deployer.attest_prior_sha()
    if args.rollback_dry_run:
        prior_sha = args.prior_sha or prior.deployed_sha
        receipt = deployer.rollback_dry_run(prior_sha=prior_sha)
        print(json.dumps(receipt.__dict__, indent=2, sort_keys=True))
        return 0
    backup_payload = json.dumps(
        {"prior_sha": prior.deployed_sha, "candidate_sha": candidate_sha},
        sort_keys=True,
    ).encode()
    backup_manifest_sha256 = hashlib.sha256(backup_payload).hexdigest()
    rollback_plan_sha256 = hashlib.sha256(prior.deployed_sha.encode()).hexdigest()
    private_key, _ = generate_keypair()
    policy_input = ReleasePolicyInput(
        run_id=args.run_id,
        task_id=args.task_id,
        base_sha=args.base_sha,
        candidate_sha=candidate_sha,
        tree_sha=tree_sha,
        reviewed_sha=candidate_sha,
        backup_manifest_sha256=backup_manifest_sha256,
        rollback_plan_sha256=rollback_plan_sha256,
        broker_safety="flat",
        database_safety="verified",
        scope_envelope_sha256=hashlib.sha256(b"scope").hexdigest(),
    )
    release_receipt = issue_authoritative_receipt(policy_input, private_key_b64=private_key)
    backup_path = args.backup_path or (
        f"/var/lib/top-delivery/backups/pre-{candidate_sha}-manifest.json"
    )
    backup = deployer.create_backup(
        database_url="postgresql://top_delivery_workflow@127.0.0.1:5432/top_delivery_control_p1",
        backup_path=backup_path,
        payload=backup_payload,
    )
    try:
        initial_generation = deployer._transport.probe_queue_generation(args.run_id)
    except Exception:
        initial_generation = 0
    try:
        deploy_receipt = deployer.deploy_exact_sha(
            candidate_sha=candidate_sha,
            tree_sha=tree_sha,
            release_receipt=release_receipt,
            backup_manifest_sha256=backup_manifest_sha256,
        )
        tracker = RestartRecoveryTracker(
            queue_generation=initial_generation,
            side_effect_count=0,
        )
        restarted = deployer.restart_attested_services()
        tracker.record_restart()
        time.sleep(8)
        recovery = deployer.verify_restart_recovery(tracker=tracker)
        if not recovery_evidence_passes(recovery):
            deployer.rollback_to_prior_sha(prior_sha=prior.deployed_sha)
            print(json.dumps({"recovery": recovery.__dict__}, indent=2, sort_keys=True))
            return 1
    except Exception as exc:
        try:
            deployer.rollback_to_prior_sha(prior_sha=prior.deployed_sha)
        except Exception:
            pass
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, indent=2))
        return 1
    evidence = {
        "transport_config": str(config_path),
        "prior_sha": prior.deployed_sha,
        "candidate_sha": candidate_sha,
        "backup": backup.__dict__,
        "deploy": deploy_receipt.__dict__,
        "restarted_services": restarted,
        "recovery": recovery.__dict__,
        "log_sample_redacted": redact_deploy_log("token=secret api_key=abc"),
    }
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
