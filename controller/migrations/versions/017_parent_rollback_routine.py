"""Add a keyed door to park retry_queue rows on an already-disabled parent.

Revision ID: 017_parent_rollback_routine
Revises: 016_recover_exhausted_executor_contract_once

Authorized live-apply envelope 2026-09-06 may apply this revision to
top_delivery_control_p1. Still refuses any other non-td_test_* database.
Do not overlay /opt/top-delivery-p1/current from this file.
"""

from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "017_parent_rollback_routine"
down_revision = "016_recover_exhausted_executor_contract_once"
branch_labels = None
depends_on = None

SQL_DIR = Path(__file__).resolve().parents[2] / "sql"
UPGRADE_SQL = (SQL_DIR / "017_park_disabled_parent_retries.sql").read_text()
DOWNGRADE_SQL = (SQL_DIR / "017_downgrade_restore_016_scope.sql").read_text()


def _assert_apply_target() -> None:
    bind = op.get_bind()
    database = bind.exec_driver_sql("SELECT current_database()").scalar_one()
    name = str(database)
    if name.startswith("td_test_") or name == "top_delivery_control_p1":
        return
    raise RuntimeError(
        "017 may apply only on disposable td_test_* clones or live top_delivery_control_p1 "
        "under an authorized live-apply envelope"
    )


def upgrade() -> None:
    _assert_apply_target()
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    _assert_apply_target()
    op.execute(DOWNGRADE_SQL)
