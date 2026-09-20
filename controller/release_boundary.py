"""Terra release-authority boundary enforcement."""

from __future__ import annotations

from exceptions import ReleaseAuthorityDeniedError

RELEASE_ACTIONS: frozenset[str] = frozenset(
    {
        "release",
        "deploy",
        "promote",
        "merge",
        "approve",
        "authorize-release",
        "cutover",
        "broker-order",
        "production-mutation",
    }
)


def deny_release_action(action: str) -> None:
    if action.lower().replace("_", "-") in RELEASE_ACTIONS:
        raise ReleaseAuthorityDeniedError(
            "Terra remains the sole release authority; Comms-01 cannot self-authorize"
        )


def assert_no_release_capability(capabilities: set[str]) -> None:
    for action in capabilities:
        deny_release_action(action)
