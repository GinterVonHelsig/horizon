from __future__ import annotations

import supervisor_cli


def test_disabled_signal_egress_has_no_notification_writer(monkeypatch) -> None:
    monkeypatch.delenv("TOP_DELIVERY_SIGNAL_EGRESS", raising=False)
    assert supervisor_cli.configured_notifier() is None


def test_enabled_signal_egress_uses_the_notifier(monkeypatch) -> None:
    monkeypatch.setenv("TOP_DELIVERY_SIGNAL_EGRESS", "enabled")
    assert supervisor_cli.configured_notifier() is supervisor_cli.signal_notifier
