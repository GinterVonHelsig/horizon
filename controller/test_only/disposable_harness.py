"""Explicit test-only disposable harness injection; never imported by production paths."""

from __future__ import annotations

import os

from authority_test_seam import inject_test_peer_uids, inject_test_owner_uids


def enable_disposable_harness() -> None:
    """Allow local uid/root only during pytest via injected seam, not environment flags."""
    inject_test_owner_uids(frozenset({0, os.getuid()}))
    inject_test_peer_uids(frozenset({0, os.getuid()}))
