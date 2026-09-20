#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
from pathlib import Path

WT = Path(__file__).resolve().parents[1] / "controller"
versions = WT / "migrations/versions"

mapping = [
    ("014_horizon_project_ledger", "018_horizon_project_ledger_live", "017_parent_rollback_routine"),
    ("015_subworkflow_handoff", "019_subworkflow_handoff_live", "018_horizon_project_ledger_live"),
    ("016_horizon_prereq_corr", "020_horizon_prereq_corr_live", "019_subworkflow_handoff_live"),
]

ASSERT_BLOCK = '''
def _assert_apply_target() -> None:
    bind = op.get_bind()
    database = bind.exec_driver_sql("SELECT current_database()").scalar_one()
    name = str(database)
    if name.startswith("td_test_") or name == "top_delivery_control_p1":
        return
    raise RuntimeError(
        "{revision} may apply only on disposable td_test_* clones or live top_delivery_control_p1"
    )

'''

for src_rev, dst_rev, down in mapping:
    src = (versions / f"{src_rev}.py").read_text()
    dst = re.sub(r'(?m)^revision = "[^"]+"', f'revision = "{dst_rev}"', src, count=1)
    dst = re.sub(r'(?m)^down_revision = "[^"]+"', f'down_revision = "{down}"', dst, count=1)
    dst = re.sub(
        r'(?m)^"""[\s\S]*?"""',
        f'"""Live-stack horizon migration above {down}.\n\nRevision ID: {dst_rev}\nRevises: {down}\n"""',
        dst,
        count=1,
    )
    if "_assert_apply_target" not in dst:
        assert_block = ASSERT_BLOCK.format(revision=dst_rev)
        dst = dst.replace(
            "\ndef upgrade() -> None:\n    verify_migration_source_anchor",
            assert_block + "\ndef upgrade() -> None:\n    _assert_apply_target()\n    verify_migration_source_anchor",
            1,
        )
    out = versions / f"{dst_rev}.py"
    out.write_text(dst)
    print(dst_rev, hashlib.sha256(out.read_bytes()).hexdigest())
