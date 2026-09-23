"""One-shot adapter shim that forwards only canonical Cursor CLI requests."""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import sys

MAX_FRAME = 1_048_576
MAX_REPLY = 3_000_000
ROUTES = {
    "gateway-delivery-disposable-file": ("executor", "composer-2.5", "agent"),
    "cursor-independent-review": ("auditor", "cursor-grok-4.6-high", "ask"),
}


def peer_uid(sock: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("peer_credentials_unavailable")
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def expected_argv(prompt: str, model: str, mode: str) -> list[str]:
    args = ["-p", prompt, "--output-format", "stream-json", "--model", model]
    if mode == "agent":
        args.extend(["--force", "--sandbox", "enabled", "--trust"])
    elif mode == "ask":
        args.extend(["--mode", "ask", "--sandbox", "enabled", "--trust"])
    else:
        raise ValueError("route_mode_denied")
    return args


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    route_id = os.environ.get("HORIZON_CURSOR_BROKER_ROUTE", "")
    expected = ROUTES.get(route_id)
    if expected is None:
        return 78
    role, model, mode = expected
    # Prompt is the sole free-form CLI value; flags and model are exact.
    if len(args) < 2 or args[0] != "-p":
        return 78
    prompt = args[1]
    if args != expected_argv(prompt, model, mode):
        return 78
    values = {
        "schema": "horizon-cursor-broker.request.v1",
        "run_id": os.environ.get("HORIZON_CURSOR_BROKER_RUN_ID", ""),
        "task_id": os.environ.get("HORIZON_CURSOR_BROKER_TASK_ID", ""),
        "attempt_id": os.environ.get("HORIZON_CURSOR_BROKER_ATTEMPT_ID", ""),
        "role": os.environ.get("HORIZON_CURSOR_BROKER_ROLE", ""),
        "route_id": route_id,
        "cwd": os.getcwd(),
        "prompt": prompt,
    }
    if values["role"] != role:
        return 78
    path = os.environ.get("HORIZON_CURSOR_BROKER_SOCKET", "")
    try:
        if not path or not os.path.isabs(path) or len(os.fsencode(path)) >= 108:
            raise ValueError("broker_socket_invalid")
        payload = (json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(payload) > MAX_FRAME:
            raise ValueError("broker_request_too_large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(930)
            client.connect(path)
            if peer_uid(client) != 0:
                raise ValueError("broker_server_identity_mismatch")
            client.sendall(payload)
            response = bytearray()
            while not response.endswith(b"\n"):
                chunk = client.recv(min(65536, MAX_REPLY + 1 - len(response)))
                if not chunk:
                    raise ValueError("broker_response_incomplete")
                response.extend(chunk)
                if len(response) > MAX_REPLY:
                    raise ValueError("broker_response_too_large")
        result = json.loads(response)
        if not isinstance(result, dict) or result.get("status") != "complete":
            reason = result.get("reason", "request_blocked") if isinstance(result, dict) else "invalid_response"
            sys.stderr.write(f"cursor_broker_blocked:{reason}\n")
            return 78
        stdout = base64.b64decode(result["stdout_b64"], validate=True)
        stderr = base64.b64decode(result["stderr_b64"], validate=True)
        if len(stdout) > MAX_REPLY or len(stderr) > MAX_REPLY:
            raise ValueError("broker_response_output_too_large")
        out_fd, err_fd = sys.stdout.fileno(), sys.stderr.fileno()
        for fd, content in ((out_fd, stdout), (err_fd, stderr)):
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("stream_write_failed")
                view = view[written:]
        exit_code = result.get("exit_code")
        if type(exit_code) is not int or not 0 <= exit_code <= 255:
            raise ValueError("broker_exit_code_invalid")
        return exit_code
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"cursor_broker_transport_failure:{type(exc).__name__}\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
