"""Persistent poll circuit breaker, independent of run artifacts and PostgreSQL.

Permission/ownership errors block immediately. Connection failures get three total
attempts across process restarts. Recovery requires an explicit operator action.
Only stable error categories are stored; exception messages may contain secrets.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import time
from contextlib import contextmanager


class WorkerHealth:
    def __init__(self, directory: Path):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("worker health directory must be private and worker-owned")
        path = directory / "poll.sqlite3"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise PermissionError("unsafe worker health file")
        finally:
            os.close(fd)
        self.path = path
        with self.connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS poll_health (scope TEXT PRIMARY KEY, failures INTEGER NOT NULL, blocked INTEGER NOT NULL, reason TEXT NOT NULL, retry_at REAL NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS recoveries (scope TEXT, recovered_at REAL, reason TEXT)")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def state(self, scope: str) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT failures, blocked, reason, retry_at FROM poll_health WHERE scope=?", (scope,)).fetchone()
        return dict(zip(("failures", "blocked", "reason", "retry_at"), row or (0, 0, "", 0)))

    def fail(self, scope: str, *, reason: str, permanent: bool) -> dict:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT failures FROM poll_health WHERE scope=?", (scope,)).fetchone()
            count = (row[0] if row else 0) + 1
            conn.execute("INSERT OR REPLACE INTO poll_health VALUES (?, ?, ?, ?, ?)",
                         (scope, count, int(permanent or count >= 3), reason, time.time() + min(2 ** count, 30)))
        return self.state(scope)

    def success(self, scope: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM poll_health WHERE scope=? AND blocked=0", (scope,))

    def recover(self, scope: str, reason: str) -> None:
        # Bounded reason code, not arbitrary potentially sensitive operator text.
        if not reason or len(reason) > 80 or not all(c.isalnum() or c in "_-" for c in reason):
            raise ValueError("recovery reason must be a bounded reason code")
        with self.connect() as conn:
            conn.execute("INSERT INTO recoveries VALUES (?, ?, ?)", (scope, time.time(), reason))
            conn.execute("DELETE FROM poll_health WHERE scope=?", (scope,))
