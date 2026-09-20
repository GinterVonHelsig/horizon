#!/usr/bin/env python3
"""Patch migration graph reconciliation into the restack worktree."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path("/opt/operator-harness/worktrees/20260910T-ats-del-002-subworkflow-handoff")
CTRL = ROOT / "controller"
VERSIONS = CTRL / "migrations/versions"

NEW_PINS = {
    "014_requeue_blocked_parent_task": "07b5a02e7ffb22e08b38947629396a96ab80235c9fd7bf0a7ce55c8955e6f73e",
    "015_recover_executor_contract_failure": "19b9c2c5dd0ed8a349330baba6e5259b1ceb19dfe794430951bac035cbfa4cc5",
    "016_recover_exhausted_executor_contract_once": "a17ab7da918d6c3a861e3177bca1200beac06597ab8da33894dd9896d5a4cef6",
    "017_parent_rollback_routine": "30ae5700613aabc5f4c40788e78ad5290cacba2335aca9a474d3b61f6394e103",
    "018_horizon_project_ledger_live": "9e30a586002a025529fe646cb7b731452aade698efc6a05805ad429cb2a0d0d6",
    "019_subworkflow_handoff_live": "df4b1c4f6d580ccd78a28d602c4df336e975fdad017689513d982fbe2051e63b",
    "020_horizon_prereq_corr_live": "16bd70bb01a4d3eea4d972e9806ca3fd4536d4c0914a0cdba88e0594ba087f9a",
}

BASE_TABLES = """(
            _CONTROLLER_TABLES
            + _LONGSPAN_TABLES
            + _PROVENANCE_TABLES
            + _ARCHIVE_PUBLIC_TABLES
        )"""
HORIZON_TABLES = BASE_TABLES.replace(")", " + _HORIZON_TABLES)")
SUBWF_TABLES = HORIZON_TABLES.replace(")", " + (\"subworkflow_handoffs\",))")
SEQ = "(\"supervisor_events_event_seq_seq\",) + _ARCHIVE_SEQUENCES"
REC = '"recovery_tables": _RECOVERY_TABLES,\n        "recovery_sequences": _ARCHIVE_SEQUENCES,'


def patch_catalog() -> None:
    path = CTRL / "migration_catalog.py"
    text = path.read_text()
    pin_lines = "".join(
        f'    "{rev}": "{pin}",\n'
        for rev, pin in NEW_PINS.items()
        if f'"{rev}"' not in text
    )
    if pin_lines:
        text = text.replace(
            '    "016_horizon_prereq_corr": "437b0d2d2387c9fd9ce95b0afb38d73c2ed80049d2532278166767f4c377d766",\n}',
            '    "016_horizon_prereq_corr": "437b0d2d2387c9fd9ce95b0afb38d73c2ed80049d2532278166767f4c377d766",\n'
            + pin_lines
            + "}",
            1,
        )
    if "_ROUTINES_017" not in text:
        insert = '''
_ROUTINES_015_RECOVER: Final[tuple[str, ...]] = _ROUTINES_013 + (
    "longspan_requeue_blocked_parent_task(TEXT, TEXT, TEXT, INTEGER, TEXT, INTEGER)",
)
_ROUTINES_016_RECOVER: Final[tuple[str, ...]] = _ROUTINES_015_RECOVER + (
    "longspan_recover_executor_contract_failure(TEXT, TEXT, TEXT, INTEGER, TEXT, INTEGER, TEXT, INTEGER, BIGINT, BOOLEAN)",
)
_ROUTINES_017: Final[tuple[str, ...]] = _ROUTINES_016_RECOVER + (
    "longspan_recover_exhausted_executor_contract_once(TEXT, TEXT, TEXT, INTEGER, TEXT, BIGINT, TEXT)",
    "longspan_park_disabled_parent_retries(TEXT, INTEGER, BIGINT, TEXT)",
)
'''
        text = text.replace("_ROUTINES_007_ACL:", insert + "_ROUTINES_007_ACL:")
    block = f'''
    "014_requeue_blocked_parent_task": {{
        "public_tables": {BASE_TABLES},
        "public_sequences": ({SEQ}),
        "public_routines": _ROUTINES_013,
        {REC}
    }},
    "015_recover_executor_contract_failure": {{
        "public_tables": {BASE_TABLES},
        "public_sequences": ({SEQ}),
        "public_routines": _ROUTINES_015_RECOVER,
        {REC}
    }},
    "016_recover_exhausted_executor_contract_once": {{
        "public_tables": {BASE_TABLES},
        "public_sequences": ({SEQ}),
        "public_routines": _ROUTINES_016_RECOVER,
        {REC}
    }},
    "017_parent_rollback_routine": {{
        "public_tables": {BASE_TABLES},
        "public_sequences": ({SEQ}),
        "public_routines": _ROUTINES_017,
        {REC}
    }},
    "018_horizon_project_ledger_live": {{
        "public_tables": {HORIZON_TABLES},
        "public_sequences": ({SEQ}),
        "public_routines": _ROUTINES_014,
        {REC}
    }},
    "019_subworkflow_handoff_live": {{
        "public_tables": {SUBWF_TABLES},
        "public_sequences": ({SEQ}),
        "public_routines": _ROUTINES_015,
        {REC}
    }},
    "020_horizon_prereq_corr_live": {{
        "public_tables": {SUBWF_TABLES},
        "public_sequences": ({SEQ}),
        "public_routines": _ROUTINES_016,
        {REC}
    }},
'''
    if '"014_requeue_blocked_parent_task"' not in text:
        text = text.replace(
            '    "016_horizon_prereq_corr": {',
            block + '    "016_horizon_prereq_corr": {',
            1,
        )
    extra = ",\n        ".join(f'"{k}"' for k in NEW_PINS)
    text = re.sub(
        r'if revision in \{\n        "010_goal_claim_parent_task",\n        "011_goal_claim_fence_token_fix",\n        "012_claim_parent_scope_fix",\n        "013_cleanup_expired_attempt",\n        "014_horizon_project_ledger",\n        "015_subworkflow_handoff",\n        "016_horizon_prereq_corr",\n    \}:',
        'if revision in {\n        "010_goal_claim_parent_task",\n        "011_goal_claim_fence_token_fix",\n        "012_claim_parent_scope_fix",\n        "013_cleanup_expired_attempt",\n        "014_horizon_project_ledger",\n        "015_subworkflow_handoff",\n        "016_horizon_prereq_corr",\n        '
        + extra
        + ",\n    }:",
        text,
        count=1,
    )
    path.write_text(text)
    import importlib.util
    spec = importlib.util.spec_from_file_location("migration_catalog_patch", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    digest = mod.migration_catalog_digest()
    text = path.read_text()
    text = re.sub(
        r'EXPECTED_MIGRATION_CATALOG_DIGEST: Final\[str\] = \(\n    "[0-9a-f]+"\n\)',
        f'EXPECTED_MIGRATION_CATALOG_DIGEST: Final[str] = (\n    "{digest}"\n)',
        text,
        count=1,
    )
    path.write_text(text)
    print("catalog digest", digest)


def patch_source_anchor() -> None:
    path = CTRL / "migration_source_anchor.py"
    text = path.read_text()
    pin_lines = "".join(
        f'    "{rev}": "{pin}",\n'
        for rev, pin in NEW_PINS.items()
        if f'"{rev}"' not in text
    )
    if pin_lines:
        text = text.replace(
            '    "016_horizon_prereq_corr": "437b0d2d2387c9fd9ce95b0afb38d73c2ed80049d2532278166767f4c377d766",\n}',
            '    "016_horizon_prereq_corr": "437b0d2d2387c9fd9ce95b0afb38d73c2ed80049d2532278166767f4c377d766",\n'
            + pin_lines
            + "}",
            1,
        )
    path.write_text(text)


def patch_migration_target() -> None:
    path = CTRL / "migration_target.py"
    text = path.read_text()
    additions = "\n        ".join(f'"{rev}",' for rev in NEW_PINS)
    text = text.replace(
        '        "016_horizon_prereq_corr",\n    }\n)',
        '        "016_horizon_prereq_corr",\n        ' + additions + "\n    }\n)",
        1,
    )
    text = text.replace(
        'return "016_horizon_prereq_corr"',
        'return "020_horizon_prereq_corr_live"',
        1,
    )
    path.write_text(text)


def patch_db_run_migrations() -> None:
    path = CTRL / "db.py"
    text = path.read_text()
    old = '''def run_migrations(db_url: str) -> None:
    alembic_command(db_url, "upgrade", "head")'''
    new = '''def run_migrations(db_url: str) -> None:
    if is_disposable_test_database(db_url):
        alembic_command(db_url, "upgrade", "016_horizon_prereq_corr")
    else:
        alembic_command(db_url, "upgrade", "020_horizon_prereq_corr_live")'''
    if old in text:
        text = text.replace(old, new, 1)
    path.write_text(text)


def chain(*revs: str) -> str:
    lines = []
    for i, rev in enumerate(revs):
        lines.append(f'        "{rev}",')
    return "\n".join(lines)


def patch_env() -> None:
    path = CTRL / "migrations/env.py"
    text = path.read_text()
    horizon_chain = [
        "004_longspan_workflow", "005_longspan_hardening", "006_longspan_authority",
        "007_longspan_authority_hardening", "008_longspan_authority_repair",
        "009_goal_schedule_task", "010_goal_claim_parent_task", "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix", "013_cleanup_expired_attempt",
        "014_horizon_project_ledger", "015_subworkflow_handoff", "016_horizon_prereq_corr",
    ]
    recover_tail = [
        "014_requeue_blocked_parent_task", "015_recover_executor_contract_failure",
        "016_recover_exhausted_executor_contract_once", "017_parent_rollback_routine",
    ]
    live_tail = [
        "018_horizon_project_ledger_live", "019_subworkflow_handoff_live", "020_horizon_prereq_corr_live",
    ]
    base = horizon_chain[:9] + ["013_cleanup_expired_attempt"]
    live_chain = base[:10] + recover_tail + live_tail
    upgrade_block = f'''    "020_horizon_prereq_corr_live": (
{chain(*live_chain)}
    ),'''
    if '"020_horizon_prereq_corr_live"' not in text:
        text = text.replace(
            '    "016_horizon_prereq_corr": (\n'
            + chain(*horizon_chain)
            + "\n    ),\n}",
            '    "016_horizon_prereq_corr": (\n'
            + chain(*horizon_chain)
            + "\n    ),\n"
            + upgrade_block
            + "\n}",
            1,
        )
    allowed = text.split("if target not in {", 1)[1].split("}:", 1)[0]
    for rev in NEW_PINS:
        if rev not in allowed:
            text = text.replace(
                "        '016_horizon_prereq_corr',\n    }:",
                "        '016_horizon_prereq_corr',\n        "
                + ",\n        ".join(f"'{r}'" for r in NEW_PINS)
                + ",\n    }:",
                1,
            )
    target_line = '    target = "016_horizon_prereq_corr" if raw_target == "head" else raw_target'
    text = text.replace(
        target_line,
        '    target = "020_horizon_prereq_corr_live" if raw_target == "head" else raw_target',
        1,
    )
    path.write_text(text)


def main() -> None:
    patch_catalog()
    patch_source_anchor()
    patch_migration_target()
    patch_db_run_migrations()
    patch_env()
    print("patched")


if __name__ == "__main__":
    main()
