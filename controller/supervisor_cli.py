"""Foreground/systemd entrypoint for the TOP-DELIVERY supervisor."""

from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path

from supervisor import Supervisor
from supervisor_identity import tick_with_identity


def signal_notifier(payload: dict[str, object]) -> bool:
    """Send sanitized status through the local signal-cli JSON-RPC daemon."""
    if os.environ.get("TOP_DELIVERY_SIGNAL_EGRESS", "disabled").lower() != "enabled":
        return False
    endpoint = os.environ.get("TOP_DELIVERY_SIGNAL_RPC", "http://127.0.0.1:8080/api/v1/rpc")
    account = os.environ.get("TOP_DELIVERY_SIGNAL_ACCOUNT")
    recipient = os.environ.get("TOP_DELIVERY_SIGNAL_RECIPIENT")
    if not account or not recipient:
        return False
    message = "TOP-DELIVERY: " + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": int(time.time() * 1000),
            "method": "send",
            "params": {"account": account, "recipient": [recipient], "message": message},
        }
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode())
        return result.get("result", {}).get("results", [{}])[0].get("type") == "SUCCESS"
    except Exception:
        return False


def configured_notifier():
    """Return a notifier only when Signal egress is explicitly enabled.

    The hardened database protects notification rows as workflow mutations.
    When egress is disabled, there is no notification work to enqueue, so the
    supervisor must not install a disabled no-op notifier that still attempts
    those writes.
    """
    if os.environ.get("TOP_DELIVERY_SIGNAL_EGRESS", "disabled").lower() != "enabled":
        return None
    return signal_notifier


def _skip_run_ids() -> frozenset[str]:
    raw = os.environ.get("TOP_DELIVERY_SKIP_RUN_IDS", "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def main() -> None:
    pinned_run_id = os.environ.get("TOP_DELIVERY_RUN_ID") or None
    skip_run_ids = _skip_run_ids()
    db_url = os.environ.get(
        "TOP_DELIVERY_DATABASE_URL",
        "postgresql:///top_delivery_control_p1",
    )
    interval = float(os.environ.get("TOP_DELIVERY_HEARTBEAT_SECONDS", "300"))
    artifact_root = Path(os.environ["TOP_DELIVERY_ARTIFACT_ROOT"])
    controller_owner = os.environ.get("TOP_DELIVERY_CONTROLLER_OWNER")
    supervisor = Supervisor(
        db_url,
        stale_after=float(os.environ.get("TOP_DELIVERY_STALE_SECONDS", "600")),
        notifier=configured_notifier(),
        artifact_root=artifact_root,
        controller_owner=controller_owner,
        controller_lease_seconds=float(
            os.environ.get("TOP_DELIVERY_CONTROLLER_LEASE_SECONDS", "3600")
        ),
    )
    if pinned_run_id and pinned_run_id not in skip_run_ids:
        supervisor.start_or_preserve_run(pinned_run_id)
    started: set[str] = set([pinned_run_id] if pinned_run_id and pinned_run_id not in skip_run_ids else [])
    try:
        while True:
            if pinned_run_id:
                targets = [pinned_run_id] if pinned_run_id not in skip_run_ids else []
            else:
                targets = [
                    run_id
                    for run_id in supervisor.list_active_run_ids()
                    if run_id not in skip_run_ids
                ]
            for run_id in targets:
                if run_id not in started:
                    supervisor.start_or_preserve_run(run_id)
                    started.add(run_id)
                tick_with_identity(supervisor, run_id, interval)
            time.sleep(interval)
    finally:
        supervisor.close()


if __name__ == "__main__":
    main()
