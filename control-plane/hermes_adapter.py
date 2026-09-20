"""Local Hermes-compatible command socket.

This is the command adapter, not an unrestricted model runner.  It gives a
future Hermes process a local, authenticated JSON interface to the same
read-only controller used by Signal.  No TCP listener, broker credential, or
production authority is present here.
"""

from __future__ import annotations

import json
import logging
import os
import socketserver
from pathlib import Path

from signal_adapter import ControllerSocketClient

LOGGER = logging.getLogger("top_delivery.hermes_adapter")
SOCKET_PATH = Path(os.environ.get("TOP_DELIVERY_HERMES_SOCKET", "/run/top-delivery/hermes.sock"))
CONTROLLER_SOCKET = os.environ.get("TOP_DELIVERY_CONTROLLER_SOCKET", "/run/top-delivery/controller.sock")
OPERATOR_ID = os.environ.get("TOP_DELIVERY_OPERATOR_ID", "operator-01")


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        for raw in self.rfile:
            try:
                request = json.loads(raw.decode("utf-8"))
                if not isinstance(request, dict) or set(request) != {"text", "sender_id", "is_group"}:
                    raise ValueError("invalid request")
                if request["sender_id"] != OPERATOR_ID or request["is_group"] is not False:
                    raise PermissionError("unauthorized local Hermes request")
                result = self.server.controller.handle_text(  # type: ignore[attr-defined]
                    request["text"], request["sender_id"], is_group=False
                )
                response = {"ok": True, "result": result}
            except Exception as exc:
                response = {"ok": False, "error": type(exc).__name__}
            self.wfile.write((json.dumps(response, sort_keys=True) + "\n").encode("utf-8"))
            self.wfile.flush()


class Server(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True

    def __init__(self, path: str, controller: ControllerSocketClient) -> None:
        self.controller = controller
        super().__init__(path, Handler)


def main() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
    with Server(
        str(SOCKET_PATH), ControllerSocketClient(CONTROLLER_SOCKET, OPERATOR_ID)
    ) as server:
        os.chmod(SOCKET_PATH, 0o660)
        LOGGER.info("Hermes-compatible local command socket active at %s", SOCKET_PATH)
        server.serve_forever()


if __name__ == "__main__":
    main()
