"""Systemd worker unit security directive tests."""

from __future__ import annotations

from pathlib import Path

SERVICE_PATH = Path(__file__).resolve().parents[1] / "systemd" / "top-delivery-worker.service"


def test_worker_service_uses_scoped_readwrite_paths() -> None:
    content = SERVICE_PATH.read_text()
    assert "/var/lib/top-delivery/runs" in content
    assert "/var/lib/top-delivery/adapter-runtime" in content
    assert "ReadWritePaths=/var/lib/top-delivery\n" not in content


def test_worker_service_has_security_directives() -> None:
    content = SERVICE_PATH.read_text()
    assert "NoNewPrivileges=true" in content
    assert "ProtectSystem=strict" in content
    assert "ReadWritePaths=" in content
    assert "RestrictAddressFamilies=" in content
    assert "User=topdelivery" in content
    assert "sk-" not in content
    assert "api_key" not in content.lower()
