"""Executable allow/deny policy for official CLI harness adapters."""

from __future__ import annotations

import os
from pathlib import Path

PROHIBITED_EXECUTABLES = frozenset({"/usr/local/bin/codex-yolo"})


def resolve_trusted_executable(path: str) -> Path:
    """Resolve an absolute executable path and reject prohibited wrappers."""
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError("executable must be an absolute path")
    if str(candidate) in PROHIBITED_EXECUTABLES:
        raise ValueError("prohibited executable")
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("executable must exist") from exc
    if not resolved.is_file():
        raise ValueError("executable must be a regular file")
    if not os.access(resolved, os.X_OK):
        raise ValueError("executable must be executable")
    canonical = str(resolved)
    if canonical in PROHIBITED_EXECUTABLES:
        raise ValueError("prohibited executable")
    return resolved
