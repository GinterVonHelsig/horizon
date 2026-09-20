"""Source-order lock for retry-limit parent-then-attempt UPDATEs."""

from __future__ import annotations

from pathlib import Path


def test_retry_limit_updates_parent_before_attempt() -> None:
    src = (Path(__file__).resolve().parents[1] / "controller" / "repository.py").read_text()
    start = src.index('if int(parent["attempt"]) >= max_retries:')
    chunk = src[start : start + 2200]
    parent_pos = chunk.index("UPDATE parent_tasks")
    attempt_pos = chunk.index("UPDATE task_attempts")
    assert parent_pos < attempt_pos
