"""Bounded Comms-01 SSH transport gate for Terra-owned release actions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from exceptions import ScopeBoundaryViolationError

PINNED_COMMS01_SSH_CONFIG = Path("/etc/top-delivery/ssh/comms01_config")
PINNED_COMMS01_HOST_ALIAS = "comms-01"
_REQUIRED_CONFIG_MARKERS = (
    f"Host {PINNED_COMMS01_HOST_ALIAS}",
    "BatchMode yes",
    "PasswordAuthentication no",
)


class Comms01TransportUnavailableError(ScopeBoundaryViolationError):
    """Bounded Comms-01 transport is missing or not policy-legal."""


class BoundedTransport(Protocol):
    def assert_available(self) -> None: ...
    def read_prior_sha(self) -> str: ...
    def run_remote(self, command: tuple[str, ...]) -> str: ...
    def checkout_exists(self, checkout_dir: str) -> bool: ...
    def stage_release_tree(
        self, *, candidate_sha: str, source_repo: Path, checkout_dir: str
    ) -> None: ...
    def bind_services_to_checkout(
        self,
        *,
        candidate_sha: str,
        checkout_dir: str,
        run_id: str,
        artifact_root: str,
    ) -> None: ...
    def write_deployed_sha(self, candidate_sha: str) -> None: ...
    def probe_controller_socket(self, *, operator_id: str, command: str = "active-runs") -> str: ...
    def probe_queue_generation(self, run_id: str) -> int: ...
    def probe_signal_status(self, run_id: str) -> tuple[str, int]: ...
    def supervisor_runs_in_dual_exec(self) -> bool: ...
    def stop_standalone_supervisor_unit(self) -> None: ...


def assert_bounded_transport_available(
    *,
    config_path: Path | None = None,
) -> Path:
    """Fail closed when the pinned bounded transport config is absent or weak."""
    path = config_path or PINNED_COMMS01_SSH_CONFIG
    if not path.is_file():
        raise Comms01TransportUnavailableError(
            f"bounded Comms-01 transport is unavailable: {path}"
        )
    content = path.read_text(encoding="utf-8")
    missing = [marker for marker in _REQUIRED_CONFIG_MARKERS if marker not in content]
    if missing:
        raise Comms01TransportUnavailableError(
            f"bounded Comms-01 transport config is incomplete: {path}"
        )
    if "IdentitiesOnly yes" not in content and "IdentityFile" not in content:
        raise Comms01TransportUnavailableError(
            f"bounded Comms-01 transport config lacks pinned identity: {path}"
        )
    return path


_SHA1 = re.compile(r"^[0-9a-f]{40}$")


def validate_deploy_sha(candidate_sha: str) -> str:
    normalized = candidate_sha.strip().lower()
    if not _SHA1.fullmatch(normalized):
        raise ScopeBoundaryViolationError("deploy candidate SHA must be a 40-char git object id")
    return normalized


__all__ = [
    "BoundedTransport",
    "Comms01TransportUnavailableError",
    "PINNED_COMMS01_HOST_ALIAS",
    "PINNED_COMMS01_SSH_CONFIG",
    "assert_bounded_transport_available",
    "validate_deploy_sha",
]
