"""One canonical resolver for Alembic command targets."""

from __future__ import annotations

from typing import Any


CANONICAL_MIGRATION_REVISIONS = frozenset(
    {
        "004_longspan_workflow",
        "005_longspan_hardening",
        "006_longspan_authority",
        "007_longspan_authority_hardening",
        "008_longspan_authority_repair",
        "009_goal_schedule_task",
        "010_goal_claim_parent_task",
        "011_goal_claim_fence_token_fix",
        "012_claim_parent_scope_fix",
        "013_cleanup_expired_attempt",
        "014_requeue_blocked_parent_task",
    }
)


def _argv_revision(command: str) -> str | None:
    import sys

    if command not in sys.argv:
        return None
    index = sys.argv.index(command)
    if index + 1 >= len(sys.argv):
        return None
    value = sys.argv[index + 1]
    return value.strip() if isinstance(value, str) and value.strip() else None


def _option_revision(config_obj: Any | None) -> str | None:
    cmd_opts = getattr(config_obj, "cmd_opts", None)
    for option in ("revision", "target"):
        candidate = getattr(cmd_opts, option, None)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def requested_revision(command: str, config_obj: Any | None = None) -> str | None:
    """Resolve one canonical target and reject caller/parser disagreement."""
    if config_obj is None:
        try:
            from alembic import context

            config_obj = context.config
        except Exception:
            config_obj = None
    argv_value = _argv_revision(command)
    option_value = _option_revision(config_obj)
    if argv_value and option_value and argv_value != option_value:
        raise ValueError(
            f"{command} migration target disagrees between argv and Alembic options"
        )
    raw = option_value or argv_value
    if raw is None:
        return None
    if command == "upgrade" and raw == "head":
        return "014_requeue_blocked_parent_task"
    if raw not in CANONICAL_MIGRATION_REVISIONS:
        raise ValueError(f"{command} migration target is not a canonical revision")
    return raw
