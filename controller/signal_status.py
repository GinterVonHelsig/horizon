"""Read-only local Signal status projection from PostgreSQL-derived readiness."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from exceptions import SignalEgressDeniedError


@dataclass(frozen=True)
class SignalStatusProjection:
    run_id: str
    readiness: str
    status: dict[str, Any]
    last_event_seq: int


class SignalStatusReader:
    """Local read-only status; no outbound relay or control path."""

    def project(
        self,
        *,
        run_id: str,
        readiness: str,
        blockers: tuple[str, ...],
        last_event_seq: int,
        task_summary: dict[str, Any] | None = None,
    ) -> SignalStatusProjection:
        status = {
            "run_id": run_id,
            "readiness": readiness,
            "blockers": list(blockers),
            "mode": "read-only",
            "task_summary": task_summary or {},
        }
        return SignalStatusProjection(
            run_id=run_id,
            readiness=readiness,
            status=status,
            last_event_seq=last_event_seq,
        )

    def to_json(self, projection: SignalStatusProjection) -> str:
        return json.dumps(projection.status, sort_keys=True, separators=(",", ":"))

    def deny_outbound_send(self, *_args: object, **_kwargs: object) -> None:
        raise SignalEgressDeniedError(
            "Signal outbound egress is disabled; status is read-only local projection"
        )

    def deny_control_action(self, action: str) -> None:
        raise SignalEgressDeniedError(
            f"Signal control action denied: {action}"
        )
