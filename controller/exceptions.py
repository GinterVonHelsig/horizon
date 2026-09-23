"""Control-plane errors for the PostgreSQL parent controller."""

from __future__ import annotations


class ControlPlaneError(PermissionError):
    """Base error for expected control-plane failures."""


class AuthorityServiceUnavailableError(ControlPlaneError):
    """The authority service or socket is temporarily unavailable."""


class AuthorityServiceCapacityError(ControlPlaneError):
    """The authority service replay/capacity guard requests a retry later."""


class StaleControllerEpochError(ControlPlaneError):
    """Raised when a mutation uses a superseded controller epoch."""


class StaleAttemptError(ControlPlaneError):
    """Raised when an attempt-side write is stale or lease-expired."""


class SchedulingDisabledError(ControlPlaneError):
    """Raised when scheduling has been disabled (rollback)."""


class ReleaseAuthorityDeniedError(ControlPlaneError):
    """Raised when Comms-01 attempts a Terra-only release action."""


class ProvenanceMismatchError(ControlPlaneError):
    """Raised when provenance hashes do not match the reviewed SHA."""


class RedisConfigurationError(ControlPlaneError):
    """Raised when Redis is enabled without required ACL/prefix configuration."""


class SignalEgressDeniedError(ControlPlaneError):
    """Raised when outbound Signal transport is attempted."""


class ScopeBoundaryViolationError(ControlPlaneError):
    """Raised when a request crosses the Comms-01 execution boundary."""


class AuthorizationFailureError(ScopeBoundaryViolationError):
    """Non-retryable authorization failure; child/parent must park, not requeue."""


class IntegrityFailureError(AuthorizationFailureError):
    """Raised when persisted evidence, ledger, or receipt integrity checks fail."""


class StaleFenceError(AuthorizationFailureError):
    """Raised when a parent fence token or attempt no longer matches."""


class LeaseExpiredError(AuthorizationFailureError):
    """Raised when a longspan lease or capability has expired."""


class DependencyScheduleError(ControlPlaneError):
    """Raised when dependency successor scheduling fails after a terminal complete."""
class MissingLiveMigrationBaselineError(RuntimeError):
    """Disposable deployment rehearsal lacks the authoritative historical baseline."""
