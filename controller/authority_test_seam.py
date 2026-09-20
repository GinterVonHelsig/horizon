"""Test-only authority identity allowances.

Production runtime must never call inject_* ; import of inject helpers from
non-test packages is rejected by reject_runtime_test_seam_use().
"""

from __future__ import annotations

import inspect
import sys

_test_owner_uids: frozenset[int] | None = None
_test_peer_uids: frozenset[int] | None = None

_ALLOWED_INJECT_MODULES = frozenset(
    {
        "conftest",
        "test_only.disposable_harness",
        "test_authority_helpers",
        "test_disposable_helpers",
        "test_remediation",
        "test_longspan",
        "test_parent_gates",
        "test_supervisor",
    }
)


def _caller_is_test() -> bool:
    # Inspect only the synchronous caller chain. Scanning every thread and
    # accepting arbitrary module-name prefixes could let an unrelated
    # test-looking module relax the live identity boundary.
    if "pytest" not in sys.modules:
        return False
    frame = inspect.currentframe()
    try:
        frame = frame.f_back if frame is not None else None
        while frame is not None:
            if frame.f_globals.get("__name__", "") in _ALLOWED_INJECT_MODULES:
                return True
            frame = frame.f_back
    finally:
        del frame
    return False


def inject_test_owner_uids(uids: frozenset[int]) -> None:
    if not _caller_is_test():
        raise RuntimeError("authority test seam inject_test_owner_uids is unreachable from production")
    global _test_owner_uids
    _test_owner_uids = uids


def inject_test_peer_uids(uids: frozenset[int]) -> None:
    if not _caller_is_test():
        raise RuntimeError("authority test seam inject_test_peer_uids is unreachable from production")
    global _test_peer_uids
    _test_peer_uids = uids


def allowed_test_owner_uids() -> frozenset[int]:
    return _test_owner_uids or frozenset()


def allowed_test_peer_uids() -> frozenset[int]:
    return _test_peer_uids or frozenset()


def reject_runtime_test_seam_use() -> None:
    if allowed_test_owner_uids() or allowed_test_peer_uids():
        # Presence alone is OK only under pytest; production entrypoints call this.
        if "pytest" not in sys.modules:
            raise RuntimeError("authority test seam must not be active outside tests")
