"""Read-only Unix-socket adapter for the PostgreSQL parent controller."""

from __future__ import annotations

import json
import os
import shlex
import socketserver
import threading
from pathlib import Path
from typing import Any

from parent_controller import ParentController

SOCKET_PATH = Path(
    os.environ.get("TOP_DELIVERY_CONTROLLER_SOCKET", "/run/top-delivery/controller.sock")
)
SENDER = os.environ.get("TOP_DELIVERY_OPERATOR_ID", "operator-01")
RUN_ID = os.environ.get("TOP_DELIVERY_RUN_ID", "")
DB_URL = os.environ.get("TOP_DELIVERY_DATABASE_URL", "postgresql:///top_delivery_control_p1")
ARTIFACT_ROOT = Path(os.environ["TOP_DELIVERY_ARTIFACT_ROOT"])


class ParentStatusAdapter:
    """Serialize read-only requests over one PostgreSQL repository connection."""

    def __init__(self) -> None:
        self.controller = ParentController(
            DB_URL,
            artifact_root=ARTIFACT_ROOT,
            controller_owner=f"status-socket-{os.getpid()}",
        )
        self._lock = threading.RLock()

    def close(self) -> None:
        self.controller.close()

    def _active_runs(self) -> list[dict[str, Any]]:
        with self.controller._repo.transaction() as cur:
            cur.execute(
                """
                SELECT r.run_id, r.state, c.current_epoch,
                       c.scheduling_enabled,
                       c.lease_expires_at > clock_timestamp() AS lease_active
                FROM supervisor_runs AS r
                JOIN controller_control AS c USING (run_id)
                WHERE r.state = 'active'
                  AND c.scheduling_enabled = TRUE
                  AND c.lease_expires_at > clock_timestamp()
                ORDER BY r.updated_at DESC, r.run_id
                """
            )
            rows = cur.fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            run_id = str(row["run_id"])
            status = self.controller.signal_status(run_id)
            result.append(
                {
                    "run_id": run_id,
                    "status": "active",
                    "phase": "parent-controller",
                    "blockers": status.get("blockers", []),
                    "next_action": "review readiness blockers",
                    "controller_epoch": int(row["current_epoch"]),
                    "scheduling_enabled": bool(row["scheduling_enabled"]),
                    "lease_active": bool(row["lease_active"]),
                }
            )
        return result

    def _selected_run(self, requested: str | None = None) -> str | None:
        if requested:
            return requested
        if RUN_ID:
            return RUN_ID
        runs = self._active_runs()
        return str(runs[0]["run_id"]) if runs else None

    def handle_text(self, text: str, sender_id: str, *, is_group: bool = False) -> str:
        if sender_id != SENDER or is_group:
            raise PermissionError("controller sender rejected")
        words = shlex.split(text, comments=False, posix=True)
        if not words:
            return json.dumps({"status": "error", "error": {"code": "empty-command"}})
        command = words[0]
        if command == "active-runs" and len(words) == 1:
            return json.dumps(
                {
                    "status": "active",
                    "runs": self._active_runs(),
                    "next_action": "send status",
                },
                sort_keys=True,
            )
        if command in {"status", "latest-evidence"} and len(words) <= 2:
            run_id = self._selected_run(words[1] if len(words) == 2 else None)
            if run_id is None:
                return json.dumps(
                    {
                        "status": "error",
                        "error": {"code": "no-active-run", "message": "No active parent run."},
                        "next_action": "status",
                    },
                    sort_keys=True,
                )
            status = self.controller.signal_status(run_id)
            payload: dict[str, Any] = {
                **status,
                "status": "active",
                "phase": "parent-controller",
                "next_action": "review readiness blockers",
            }
            if command == "latest-evidence":
                payload["evidence_paths"] = [
                    str(item["artifact_path"])
                    for item in self.controller.evidence(run_id)[-10:]
                ]
            return json.dumps(payload, sort_keys=True)
        return json.dumps(
            {
                "status": "error",
                "error": {"code": "unknown-command", "message": "command is not supported"},
                "next_action": "send status or active-runs",
            },
            sort_keys=True,
        )

    def request(self, request: dict[str, Any]) -> str:
        if set(request) != {"text", "sender_id", "is_group"}:
            raise ValueError("invalid request")
        with self._lock:
            return self.handle_text(
                request["text"], request["sender_id"], is_group=request["is_group"]
            )


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        for raw in self.rfile:
            try:
                request = json.loads(raw)
                if not isinstance(request, dict):
                    raise ValueError("invalid request")
                result = self.server.adapter.request(request)
                response = {"ok": True, "result": result}
            except Exception as exc:  # noqa: BLE001
                response = {"ok": False, "error": type(exc).__name__}
            self.wfile.write((json.dumps(response, sort_keys=True) + "\n").encode())
            self.wfile.flush()


class Server(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True

    def __init__(self, path: str, adapter: ParentStatusAdapter) -> None:
        self.adapter = adapter
        super().__init__(path, Handler)


def main() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists():
        if not SOCKET_PATH.is_socket():
            raise RuntimeError("controller socket path is not a socket")
        SOCKET_PATH.unlink()
    adapter = ParentStatusAdapter()
    try:
        with Server(str(SOCKET_PATH), adapter) as server:
            os.chmod(SOCKET_PATH, 0o660)
            server.serve_forever()
    finally:
        adapter.close()


if __name__ == "__main__":
    main()
