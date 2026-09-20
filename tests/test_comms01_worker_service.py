"""Worker service identity resolves from live cgroup, not hardcoded controller."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from attestation import Comms01Attestation
from comms01_scope import resolve_live_comms01_service_name
from authority_pins import AUTHORITY_DATABASE_ROLE, WORKFLOW_DATABASE_ROLE
from exceptions import ScopeBoundaryViolationError


def _attestation() -> Comms01Attestation:
    return Comms01Attestation(
        scope="comms-01",
        environment_marker="isolated-top-delivery",
        host_fingerprint="comms01-isolated-top-delivery-local",
        database_name="top_delivery_control_p1",
        database_role=WORKFLOW_DATABASE_ROLE,
        workflow_database_role=WORKFLOW_DATABASE_ROLE,
        authority_database_role=AUTHORITY_DATABASE_ROLE,
        controller_service="top-delivery-controller",
        database_endpoint="local",
        database_port=5432,
        authority_service="top-delivery-authority-service",
    )


def test_resolve_live_service_name_from_worker_cgroup() -> None:
    with patch(
        "comms01_scope._live_service_units_from_cgroup",
        return_value=["top-delivery-worker.service"],
    ), patch(
        "comms01_scope._attestation_identity",
        return_value=_attestation(),
    ):
        assert resolve_live_comms01_service_name() == "top-delivery-worker"


def test_resolve_live_service_name_from_entrypoint_delegate_cgroup() -> None:
    with patch(
        "comms01_scope._live_service_units_from_cgroup",
        return_value=["top-delivery-entrypoint@top-delivery-controller.service"],
    ), patch(
        "comms01_scope._attestation_identity",
        return_value=_attestation(),
    ):
        assert resolve_live_comms01_service_name() == "top-delivery-controller"


def test_resolve_live_service_name_rejects_unknown_unit() -> None:
    with patch(
        "comms01_scope._live_service_units_from_cgroup",
        return_value=["unknown.service"],
    ), patch(
        "comms01_scope._attestation_identity",
        return_value=_attestation(),
    ):
        with pytest.raises(ScopeBoundaryViolationError, match="outside Comms-01 boundary"):
            resolve_live_comms01_service_name()
