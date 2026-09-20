"""Durable ATS-COM-001 correlation store for status Q&A across harness paths."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol


class CorrelationRepositoryLike(Protocol):
    def record_correlation_qa(
        self,
        *,
        run_id: str,
        request_id: str,
        question_kind: str,
        question_json: dict[str, Any],
        question_digest: str,
        answer_json: dict[str, Any],
        answer_digest: str,
    ) -> dict[str, Any]: ...

    def get_correlation_answer(self, *, run_id: str, request_id: str) -> dict[str, Any] | None: ...


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CorrelationAnswer:
    run_id: str
    request_id: str
    question_kind: str
    question_digest: str
    answer_json: dict[str, Any]
    answer_digest: str
    replay_count: int
    replayed: bool

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> CorrelationAnswer:
        answer = payload.get("answer_json")
        if not isinstance(answer, dict):
            raise ValueError("correlation payload is missing answer_json")
        return cls(
            run_id=str(payload["run_id"]),
            request_id=str(payload["request_id"]),
            question_kind=str(payload["question_kind"]),
            question_digest=str(payload["question_digest"]),
            answer_json=dict(answer),
            answer_digest=str(payload["answer_digest"]),
            replay_count=int(payload.get("replay_count", 0)),
            replayed=bool(payload.get("replayed", False)),
        )


class CorrelationStore:
    """Persist and replay status answers keyed by (run_id, request_id)."""

    STATUS_QUESTION_KIND = "status"

    def __init__(self, repository: CorrelationRepositoryLike) -> None:
        self._repository = repository

    def record_status_answer(
        self,
        *,
        run_id: str,
        request_id: str,
        question: dict[str, Any],
        answer: dict[str, Any],
    ) -> CorrelationAnswer:
        if not run_id or not request_id:
            raise ValueError("run_id and request_id are required")
        question_digest = digest_json(question)
        answer_digest = digest_json(answer)
        payload = self._repository.record_correlation_qa(
            run_id=run_id,
            request_id=request_id,
            question_kind=self.STATUS_QUESTION_KIND,
            question_json=question,
            question_digest=question_digest,
            answer_json=answer,
            answer_digest=answer_digest,
        )
        return CorrelationAnswer.from_payload(payload)

    def get_status_answer(self, *, run_id: str, request_id: str) -> CorrelationAnswer | None:
        payload = self._repository.get_correlation_answer(run_id=run_id, request_id=request_id)
        if payload is None:
            return None
        return CorrelationAnswer.from_payload(payload)
