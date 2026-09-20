"""Attestation host fingerprint accepts legacy uid suffixes for service users."""

from __future__ import annotations

import socket

import pytest

from attestation import (
    Comms01Attestation,
    assert_attestation_matches_runtime,
    _runtime_host_fingerprint,
)
from authority_pins import AUTHORITY_DATABASE_ROLE, WORKFLOW_DATABASE_ROLE
from exceptions import ScopeBoundaryViolationError


def _attestation(host_fingerprint: str) -> Comms01Attestation:
    return Comms01Attestation(
        scope="comms-01",
        environment_marker="isolated-top-delivery",
        host_fingerprint=host_fingerprint,
        database_name="top_delivery_control_p1",
        database_role=WORKFLOW_DATABASE_ROLE,
        workflow_database_role=WORKFLOW_DATABASE_ROLE,
        authority_database_role=AUTHORITY_DATABASE_ROLE,
        controller_service="top-delivery-controller",
        database_endpoint="local",
        database_port=5432,
        authority_service="top-delivery-authority-service",
    )


def test_runtime_host_fingerprint_is_hostname_only() -> None:
    assert _runtime_host_fingerprint() == f"comms01-{socket.gethostname()}"


def test_legacy_uid_suffix_attestation_matches_worker_runtime() -> None:
    prefix = f"comms01-{socket.gethostname()}"
    assert_attestation_matches_runtime(_attestation(f"{prefix}-0"))


def test_wrong_host_prefix_attestation_rejected() -> None:
    with pytest.raises(ScopeBoundaryViolationError, match="host fingerprint mismatch"):
        assert_attestation_matches_runtime(_attestation("comms01-wrong-host-0"))
