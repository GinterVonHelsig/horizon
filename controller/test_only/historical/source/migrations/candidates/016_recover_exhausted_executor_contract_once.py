"""Authorize terminal Executor-contract recovery under a dedicated workflow scope.

Revision ID: 016_recover_exhausted_executor_contract_once
Revises: 015_recover_executor_contract_failure

Candidate migration. Do not apply to top_delivery_control_p1 from the
executor-contract 016 activation envelope. Activation must pin source provenance
before any live upgrade. This file is not on the Alembic versions/ auto-load
path; 014 remains the candidate Alembic head until a later pin envelope.
"""

from __future__ import annotations

import re
from pathlib import Path

from alembic import op

revision = "016_recover_exhausted_executor_contract_once"
down_revision = "015_recover_executor_contract_failure"
branch_labels = None
depends_on = None

SQL_DIR = Path(__file__).resolve().parents[2] / "sql"
UPGRADE_SQL = (SQL_DIR / "016_recover_exhausted_executor_contract_once.sql").read_text()
DOWNGRADE_SQL = (SQL_DIR / "016_downgrade_restore_015_scope.sql").read_text()

MIGRATION_ROLE = "top_delivery_migration"
WORKFLOW_ROLE = "top_delivery_workflow"

_DOLLAR_TAG_RE = re.compile(r"\$[A-Za-z0-9_]*\$")


def _split_pg_sql(sql: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    index = 0
    length = len(sql)
    dollar_tag: str | None = None

    def flush() -> None:
        statement = "".join(current).strip()
        if statement:
            statements.append(statement)
        current.clear()

    while index < length:
        if dollar_tag is not None:
            end = sql.find(dollar_tag, index)
            if end < 0:
                current.append(sql[index:])
                break
            current.append(sql[index : end + len(dollar_tag)])
            index = end + len(dollar_tag)
            dollar_tag = None
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index)
            if newline < 0:
                current.append(sql[index:])
                break
            current.append(sql[index : newline + 1])
            index = newline + 1
            continue
        if sql[index] == "$":
            match = _DOLLAR_TAG_RE.match(sql, index)
            if match:
                dollar_tag = match.group(0)
                current.append(dollar_tag)
                index += len(dollar_tag)
                continue
        if sql[index] == ";":
            current.append(";")
            flush()
            index += 1
            continue
        current.append(sql[index])
        index += 1
    flush()
    return statements


def _execute_sql_script(sql: str) -> None:
    bind = op.get_bind()
    connection = bind.connection.dbapi_connection
    with connection.cursor() as cursor:
        for statement in _split_pg_sql(sql):
            cursor.execute(statement)


def _stamp_revision(expected: str, new: str) -> None:
    bind = op.get_bind()
    result = bind.exec_driver_sql(
        "UPDATE alembic_version SET version_num = %s WHERE version_num = %s",
        (new, expected),
    )
    if result.rowcount != 1:
        raise RuntimeError(
            f"alembic compare-and-set stamp failed: expected one row at {expected!r}, got {result.rowcount}"
        )


def _assert_disposable_candidate_upgrade() -> None:
    bind = op.get_bind()
    database = bind.exec_driver_sql("SELECT current_database()").scalar_one()
    name = str(database)
    if not name.startswith("td_test_"):
        raise RuntimeError(
            "015 is a candidate revision; apply only on disposable clones until provenance is pinned"
        )


def upgrade() -> None:
    _assert_disposable_candidate_upgrade()
    bind = op.get_bind()
    bind.exec_driver_sql("ALTER TABLE alembic_version ALTER COLUMN version_num TYPE varchar(64)")
    _execute_sql_script(UPGRADE_SQL.replace("{WORKFLOW_ROLE}", WORKFLOW_ROLE))
    _stamp_revision(down_revision, revision)


def downgrade() -> None:
    _assert_disposable_candidate_upgrade()
    bind = op.get_bind()
    _execute_sql_script(DOWNGRADE_SQL.replace("{WORKFLOW_ROLE}", WORKFLOW_ROLE))
    _stamp_revision(revision, down_revision)
