from __future__ import annotations

from pathlib import Path


SOURCE = Path("/opt/top-delivery-p1/f2658c33c9f881be59f25608038f4f585641e0a5-goal-runner/controller/repository.py")


def test_rollback_disable_uses_dedicated_child_parking_scope() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    rollback = source.split("    def rollback_disable(", 1)[1].split("    def idempotent_cleanup(", 1)[0]
    assert 'scope_kind="controller", controller_operation="park_children"' in rollback
