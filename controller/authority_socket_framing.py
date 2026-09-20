"""Length-prefixed framing for authority Unix socket messages."""

from __future__ import annotations

import socket
import struct
import time

MAX_FRAME_BYTES = 1_048_576


def send_framed(
    sock: socket.socket, payload: bytes, *, deadline: float | None = None
) -> None:
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError("authority socket frame exceeds maximum size")
    if deadline is not None:
        seconds_left = deadline - time.monotonic()
        if seconds_left <= 0:
            raise socket.timeout("authority socket send deadline exceeded")
        sock.settimeout(seconds_left)
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_exact(
    sock: socket.socket, nbytes: int, *, deadline: float | None = None
) -> bytes:
    chunks: list[bytes] = []
    remaining = nbytes
    while remaining > 0:
        if deadline is not None:
            seconds_left = deadline - time.monotonic()
            if seconds_left <= 0:
                raise socket.timeout("authority socket frame deadline exceeded")
            sock.settimeout(seconds_left)
        try:
            chunk = sock.recv(remaining)
        except socket.timeout as exc:
            if deadline is not None and time.monotonic() >= deadline:
                raise socket.timeout(
                    "authority socket frame deadline exceeded"
                ) from exc
            raise
        if not chunk:
            raise ConnectionError("authority socket closed before frame completed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_framed(sock: socket.socket, *, deadline: float | None = None) -> bytes:
    header = recv_exact(sock, 4, deadline=deadline)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise ValueError("authority socket frame length is invalid")
    return recv_exact(sock, length, deadline=deadline)
