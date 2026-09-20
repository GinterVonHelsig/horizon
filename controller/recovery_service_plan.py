"""Fail-closed service actions for the bounded P35/P40 recovery coordinator."""
def rollback_service_actions(bound_tasks_transitioned: bool) -> tuple[tuple[str, ...], ...]:
    """A paused rollback never restarts predecessor code, even before a claim.

    Stop both services before restoring saved files; reload after restoration.
    Availability restoration is a separately verified compatible roll-forward.
    """
    return (
        ("recovery_lifecycle.stop_declared",),
        ("systemctl", "daemon-reload"),
    )


def assert_worker_resume_compatible(
    installed_sha: str, accepted_sha: str, bundles_valid: bool,
) -> None:
    raise ValueError("caller-supplied labels are not a start gate; use recovery_start.start_verified")
