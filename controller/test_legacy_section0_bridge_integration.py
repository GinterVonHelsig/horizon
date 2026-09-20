"""Opt-in behavioral rehearsal for the disposable Section-0 bridge.

The normal suite stays credential-free.  A delivery run enables this test only
after it has created and independently verified disposable source and target
databases at the exact 004 and 003 revisions.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import psycopg2
import pytest
from legacy_section0_bridge import bridge


def test_bridge_copy_and_post_bridge_event_write(tmp_path) -> None:
    source_url = os.environ.get("TOP_DELIVERY_BRIDGE_SOURCE_URL")
    target_url = os.environ.get("TOP_DELIVERY_BRIDGE_TARGET_URL")
    if not source_url or not target_url:
        pytest.skip("delivery run did not provide verified disposable bridge URLs")

    evidence = bridge(source_url, target_url, tmp_path / "bridge-evidence.json")
    assert evidence["status"] == "passed"
    assert evidence["source"]["transaction_isolation"] == "repeatable read"
    assert evidence["source"]["read_only_transaction"] is True
    assert evidence["schema_completeness"]["source_tables"]
    assert evidence["sequence_reconciliation"]

    # Prove that explicit-key copying left the per-run event cursor safe for a
    # first post-bridge write for every event-bearing run. The disposable
    # transaction is rolled back.
    with psycopg2.connect(target_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT run_id, COALESCE(MAX(event_seq), 0) "
                "FROM public.supervisor_events GROUP BY run_id ORDER BY run_id"
            )
            rows = cursor.fetchall()
            if not rows:
                pytest.skip("disposable source contains no event run")
            for run_id, high_water in rows:
                cursor.execute(
                    """
                    INSERT INTO public.supervisor_events
                        (event_id, run_id, controller_epoch, event_type,
                         occurred_at, detail_json, event_seq)
                    VALUES (%s, %s, 0, 'bridge_post_copy_probe', %s, '{}', %s)
                    """,
                    (
                        f"bridge-probe-{uuid.uuid4().hex}",
                        run_id,
                        datetime.now(timezone.utc),
                        int(high_water) + 1,
                    ),
                )
        connection.rollback()
