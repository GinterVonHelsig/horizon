"""Automatic Horizon prerequisite detection, decision recording, and delivery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from correlation_store import digest_json
from subworkflow_handoff import HORIZON_PREREQ_FAILURE, build_handoff_request


class PrerequisiteRepositoryLike(Protocol):
    def detect_missing_prerequisites(
        self,
        project_id: str,
        project_version: str,
        node_id: str,
        satisfied_nodes: list[str],
    ) -> dict[str, Any]: ...

    def record_prerequisite_decision(
        self,
        *,
        run_id: str,
        target_node_id: str,
        prerequisite_node_id: str,
        request_digest: str,
        reused: bool,
        delivered_by: str | None,
        reason: str,
        artifact_digest: str,
        handoff_id: str | None,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class PrerequisiteDecision:
    decision_id: str
    run_id: str
    target_node_id: str
    prerequisite_node_id: str
    reused: bool
    delivered_by: str | None
    reason: str
    artifact_digest: str
    request_digest: str
    handoff_id: str | None
    created: bool

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> PrerequisiteDecision:
        return cls(
            decision_id=str(payload["decision_id"]),
            run_id=str(payload["run_id"]),
            target_node_id=str(payload["target_node_id"]),
            prerequisite_node_id=str(payload["prerequisite_node_id"]),
            reused=bool(payload["reused"]),
            delivered_by=payload.get("delivered_by"),
            reason=str(payload["reason"]),
            artifact_digest=str(payload["artifact_digest"]),
            request_digest=str(payload["request_digest"]),
            handoff_id=payload.get("handoff_id"),
            created=bool(payload.get("created", False)),
        )


class PrerequisiteOrchestrator:
    """Detect missing ledger prerequisites and materialize durable delivery decisions."""

    def __init__(self, repository: PrerequisiteRepositoryLike) -> None:
        self._repository = repository

    def detect_missing(
        self,
        *,
        project_id: str,
        project_version: str,
        node_id: str,
        satisfied_nodes: list[str] | tuple[str, ...] | None = None,
    ) -> list[str]:
        payload = self._repository.detect_missing_prerequisites(
            project_id,
            project_version,
            node_id,
            list(satisfied_nodes or ()),
        )
        missing = payload.get("missing")
        if not isinstance(missing, list):
            return []
        return [str(item) for item in missing]

    def record_decision(
        self,
        *,
        run_id: str,
        target_node_id: str,
        prerequisite_node_id: str,
        request_digest: str,
        reused: bool,
        delivered_by: str | None,
        reason: str,
        artifact_digest: str,
        handoff_id: str | None = None,
    ) -> PrerequisiteDecision:
        payload = self._repository.record_prerequisite_decision(
            run_id=run_id,
            target_node_id=target_node_id,
            prerequisite_node_id=prerequisite_node_id,
            request_digest=request_digest,
            reused=reused,
            delivered_by=delivered_by,
            reason=reason,
            artifact_digest=artifact_digest,
            handoff_id=handoff_id,
        )
        return PrerequisiteDecision.from_payload(payload)

    def build_delivery_request(
        self,
        *,
        run_id: str,
        parent_task_id: str,
        parent_attempt_id: str,
        target_node_id: str,
        prerequisite_node_id: str,
        request_artifact_root: str,
    ) -> dict[str, Any]:
        return build_handoff_request(
            run_id=run_id,
            parent_task_id=parent_task_id,
            parent_attempt_id=parent_attempt_id,
            failure_code=HORIZON_PREREQ_FAILURE,
            request_artifact_root=request_artifact_root,
            handoff_context={
                "target_node_id": target_node_id,
                "prerequisite_node_id": prerequisite_node_id,
            },
        )

    def delivery_decision_digest(
        self,
        *,
        run_id: str,
        target_node_id: str,
        prerequisite_node_id: str,
        reason: str,
        artifact_digest: str,
    ) -> str:
        return digest_json(
            {
                "run_id": run_id,
                "target_node_id": target_node_id,
                "prerequisite_node_id": prerequisite_node_id,
                "reason": reason,
                "artifact_digest": artifact_digest,
            }
        )
