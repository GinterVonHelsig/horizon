"""Lineage placeholder so Alembic can resolve 015's down_revision.

Live top_delivery_control_p1 is already at 016_recover_exhausted_executor_contract_once,
which revises 015, which revises 014_requeue_blocked_parent_task. This file does not
re-apply 014. Do not use stale 014_parent_rollback_routine.
"""

from __future__ import annotations

revision = "014_requeue_blocked_parent_task"
down_revision = "013_cleanup_expired_attempt"
branch_labels = None
depends_on = None


def upgrade() -> None:
    raise RuntimeError(
        "014_requeue_blocked_parent_task is already applied on live; "
        "do not re-apply from the 017 candidate worktree"
    )


def downgrade() -> None:
    raise RuntimeError(
        "014_requeue_blocked_parent_task downgrade is not authorized from the 017 candidate worktree"
    )
