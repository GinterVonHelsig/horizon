"""Minimal test harness for goal-runner unit tests outside controller/."""

from __future__ import annotations

import sys
import pytest
from pathlib import Path

CONTROLLER_DIR = Path(__file__).resolve().parents[1] / "controller"
if str(CONTROLLER_DIR) not in sys.path:
    sys.path.insert(0, str(CONTROLLER_DIR))


@pytest.fixture(autouse=True)
def isolate_worker_health(tmp_path, monkeypatch):
    monkeypatch.setenv("TOP_DELIVERY_WORKER_HEALTH_DIR", str(tmp_path / "worker-health"))
    monkeypatch.setenv("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN_FILE", str(tmp_path / "absent-relay"))
