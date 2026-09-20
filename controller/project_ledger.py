"""Durable Horizon project ledger ingest and query."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from program_ingest import ParsedProgram, ProgramNode, parse_program_bytes, parse_program_file


class ProjectLedgerRepositoryLike(Protocol):
    def ingest_project_program(self, parsed: ParsedProgram) -> dict[str, Any]: ...

    def get_project_node_ledger(
        self,
        project_id: str,
        project_version: str,
        node_id: str,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ProjectLedgerSnapshot:
    project_ledger_id: str
    project_id: str
    project_version: str
    node_ledger_ids: dict[str, str]

    @classmethod
    def from_ingest_payload(cls, payload: dict[str, Any]) -> ProjectLedgerSnapshot:
        node_ids = payload.get("node_ledger_ids")
        if not isinstance(node_ids, dict):
            raise ValueError("ingest payload is missing node_ledger_ids")
        return cls(
            project_ledger_id=str(payload["project_ledger_id"]),
            project_id=str(payload["project_id"]),
            project_version=str(payload["project_version"]),
            node_ledger_ids={str(key): str(value) for key, value in node_ids.items()},
        )


class ProjectLedgerService:
    def __init__(self, repository: ProjectLedgerRepositoryLike) -> None:
        self._repository = repository

    def ingest_program_file(self, path: str) -> ProjectLedgerSnapshot:
        parsed = parse_program_file(path)
        payload = self._repository.ingest_project_program(parsed)
        return ProjectLedgerSnapshot.from_ingest_payload(payload)

    def ingest_program_bytes(self, data: bytes, *, source: str) -> ProjectLedgerSnapshot:
        parsed = parse_program_bytes(data, source=source)
        payload = self._repository.ingest_project_program(parsed)
        return ProjectLedgerSnapshot.from_ingest_payload(payload)

    def query_node(
        self,
        project_id: str,
        project_version: str,
        node_id: str,
    ) -> dict[str, Any]:
        return self._repository.get_project_node_ledger(project_id, project_version, node_id)


def nodes_payload(parsed: ParsedProgram) -> list[dict[str, str | None | list[str]]]:
    return [
        {
            "node_id": node.node_id,
            "parent_node_id": node.parent_node_id,
            "project_version": node.project_version,
            "acceptance_criteria_version": node.acceptance_criteria_version,
            "node_digest": node.node_digest,
            "dependencies": list(node.dependencies),
        }
        for node in parsed.nodes
    ]


def program_node_from_query(row: dict[str, Any]) -> ProgramNode:
    raw_dependencies = row.get("dependencies", [])
    dependencies: tuple[str, ...] = ()
    if isinstance(raw_dependencies, list):
        dependencies = tuple(str(item) for item in raw_dependencies)
    return ProgramNode(
        node_id=str(row["node_id"]),
        parent_node_id=row.get("parent_node_id"),
        project_version=str(row["project_version"]),
        acceptance_criteria_version=str(row["acceptance_criteria_version"]),
        node_digest=str(row["node_digest"]),
        dependencies=dependencies,
    )


def canonical_nodes_json(parsed: ParsedProgram) -> str:
    return json.dumps(nodes_payload(parsed), sort_keys=True, separators=(",", ":"))
