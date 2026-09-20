"""Parse Horizon master program fixtures into project ledger inputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProgramIngestError(ValueError):
    """Raised when a master program fixture fails closed."""


@dataclass(frozen=True)
class ProgramNode:
    node_id: str
    parent_node_id: str | None
    project_version: str
    acceptance_criteria_version: str
    node_digest: str
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedProgram:
    project_id: str
    project_version: str
    schema_version: str
    program_digest: str
    nodes: tuple[ProgramNode, ...]
    source: str


def parse_program_file(path: str | Path) -> ParsedProgram:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise ProgramIngestError(f"program fixture is missing or unreadable: {resolved}")
    return parse_program_bytes(resolved.read_bytes(), source=str(resolved))


def parse_program_bytes(data: bytes, *, source: str) -> ParsedProgram:
    if not data or not data.strip():
        raise ProgramIngestError("program fixture is empty")
    try:
        payload = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProgramIngestError("program fixture is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ProgramIngestError("program fixture must be a JSON object")
    return parse_program_object(payload, program_digest=_digest(data), source=source)


def parse_program_object(
    payload: dict[str, Any],
    *,
    program_digest: str,
    source: str,
) -> ParsedProgram:
    schema_version = _required_text(payload, "schema_version")
    project_id = _required_text(payload, "program_id")
    project_version = _required_text(payload, "project_version")
    raw_nodes = payload.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise ProgramIngestError("program fixture must include a non-empty nodes array")

    nodes: list[ProgramNode] = []
    seen: set[str] = set()
    for index, raw_node in enumerate(raw_nodes):
        if not isinstance(raw_node, dict):
            raise ProgramIngestError(f"node at index {index} must be an object")
        node_id = _required_text(raw_node, "node_id")
        if node_id in seen:
            raise ProgramIngestError(f"duplicate node_id in program fixture: {node_id}")
        seen.add(node_id)
        parent_node_id = raw_node.get("parent_id")
        if parent_node_id is not None and not isinstance(parent_node_id, str):
            raise ProgramIngestError(f"parent_id for {node_id} must be a string or null")
        node_version = raw_node.get("project_version")
        if node_version is None:
            node_version = project_version
        elif not isinstance(node_version, str) or not node_version.strip():
            raise ProgramIngestError(f"project_version for {node_id} must be a non-empty string")
        else:
            node_version = node_version.strip()
        acceptance_version = _required_text(raw_node, "acceptance_criteria_version")
        raw_dependencies = raw_node.get("dependencies", [])
        if not isinstance(raw_dependencies, list):
            raise ProgramIngestError(f"dependencies for {node_id} must be an array")
        dependencies: list[str] = []
        for index, dependency in enumerate(raw_dependencies):
            if not isinstance(dependency, str) or not dependency.strip():
                raise ProgramIngestError(
                    f"dependency at index {index} for {node_id} must be a non-empty string"
                )
            dependencies.append(dependency.strip())
        nodes.append(
            ProgramNode(
                node_id=node_id,
                parent_node_id=parent_node_id,
                project_version=node_version,
                acceptance_criteria_version=acceptance_version,
                node_digest=_node_digest(raw_node),
                dependencies=tuple(dependencies),
            )
        )

    return ParsedProgram(
        project_id=project_id,
        project_version=project_version,
        schema_version=schema_version,
        program_digest=program_digest,
        nodes=tuple(nodes),
        source=source,
    )


def project_node_reference(parsed: ParsedProgram, node_id: str) -> ProgramNode:
    for node in parsed.nodes:
        if node.node_id == node_id:
            return node
    raise ProgramIngestError(f"project node reference not found: {node_id}")


def resume_pointer_for_node(path: str | Path, node_id: str) -> str:
    resolved = Path(path).expanduser().resolve()
    try:
        payload = json.loads(resolved.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProgramIngestError(f"program fixture is unreadable: {resolved}") from exc
    if not isinstance(payload, dict):
        raise ProgramIngestError("program fixture must be a JSON object")
    raw_nodes = payload.get("nodes")
    if not isinstance(raw_nodes, list):
        raise ProgramIngestError("program fixture must include a nodes array")
    for raw_node in raw_nodes:
        if not isinstance(raw_node, dict):
            continue
        if raw_node.get("node_id") != node_id:
            continue
        resume_pointer = raw_node.get("resume_pointer")
        if not isinstance(resume_pointer, str) or not resume_pointer.strip():
            raise ProgramIngestError(f"resume pointer is missing for node: {node_id}")
        return resume_pointer.strip()
    raise ProgramIngestError(f"project node reference not found: {node_id}")


def _required_text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ProgramIngestError(f"program fixture field is missing or empty: {field}")
    return value.strip()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _node_digest(node: dict[str, Any]) -> str:
    canonical = json.dumps(node, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
