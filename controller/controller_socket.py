"""Local Unix-socket adapter for read-only TOP-DELIVERY commands."""

from __future__ import annotations

import json
import os
import socket
import socketserver
from pathlib import Path

from controller import TopDeliveryController


SOCKET_PATH = Path(os.environ.get("TOP_DELIVERY_CONTROLLER_SOCKET", "/run/top-delivery/controller.sock"))
ROOT = Path(os.environ.get("TOP_DELIVERY_ROOT", "/root/TOP-DELIVERY"))
SENDER = os.environ.get("TOP_DELIVERY_OPERATOR_ID", "operator-01")


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        for raw in self.rfile:
            try:
                request = json.loads(raw)
                if not isinstance(request, dict) or set(request) != {"text", "sender_id", "is_group"}:
                    raise ValueError("invalid request")
                if request["sender_id"] != SENDER or request["is_group"] is not False:
                    raise PermissionError("unauthorized sender")
                result = self.server.controller.handle_text(
                    request["text"], request["sender_id"], is_group=False
                )
                response = {"ok": True, "result": result}
            except Exception as exc:
                response = {"ok": False, "error": type(exc).__name__}
            self.wfile.write((json.dumps(response, sort_keys=True) + "\n").encode())
            self.wfile.flush()


class Server(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True

    def __init__(self, path: str, controller: TopDeliveryController) -> None:
        self.controller = controller
        super().__init__(path, Handler)


def main() -> None:
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
    controller = TopDeliveryController(ROOT, authorized_senders=(SENDER,))
    with Server(str(SOCKET_PATH), controller) as server:
        os.chmod(SOCKET_PATH, 0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()
