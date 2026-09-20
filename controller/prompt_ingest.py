"""Deterministic authority prompt ingestion for TOP-DELIVERY goal submission."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


class PromptIngestError(ValueError):
    """Raised when prompt parsing fails closed."""


@dataclass(frozen=True)
class Workstream:
    number: int
    title: str
    required_disposition: str
    dependencies: tuple[int, ...]
    task_id: str


@dataclass(frozen=True)
class ProjectNodeBinding:
    project_id: str
    project_version: str
    node_id: str
    parent_node_id: str | None
    acceptance_version: str


@dataclass(frozen=True)
class ParsedPrompt:
    sha256: str
    byte_count: int
    title: str
    objective: str
    mission: str
    allowed: tuple[str, ...]
    forbidden: tuple[str, ...]
    workstreams: tuple[Workstream, ...]
    run_id: str
    source: str
    project_node: ProjectNodeBinding | None = None


def derive_run_id(prompt_digest: str) -> str:
    return f"goal-{prompt_digest[:16]}"


def derive_task_id(run_id: str, workstream_number: int) -> str:
    return f"{run_id}-ws-{workstream_number:02d}"


def parse_prompt_file(path: Path) -> ParsedPrompt:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise PromptIngestError(f"prompt file is missing or unreadable: {resolved}")
    return parse_prompt_bytes(resolved.read_bytes(), source=str(resolved))


def parse_prompt_bytes(data: bytes, *, source: str) -> ParsedPrompt:
    if not data or not data.strip():
        raise PromptIngestError("prompt is empty")

    text = data.decode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    run_id = derive_run_id(digest)

    title = _parse_title(text)
    objective = _parse_objective(text)
    mission = _parse_section(text, "Mission")
    allowed, forbidden = _parse_authority_envelope(text)
    project_node = _parse_project_node_binding(text)
    workstream_specs = _parse_workstreams(text)
    dispositions = _parse_acceptance_matrix(text)

    workstreams: list[Workstream] = []
    if workstream_specs:
        seen: set[int] = set()
        for number, ws_title in workstream_specs:
            if number in seen:
                raise PromptIngestError(f"duplicate workstream number: {number}")
            seen.add(number)
            if number not in dispositions:
                raise PromptIngestError(
                    f"missing acceptance disposition for workstream {number}"
                )
            dependencies = () if number == 1 else (number - 1,)
            workstreams.append(
                Workstream(
                    number=number,
                    title=ws_title,
                    required_disposition=dispositions[number],
                    dependencies=dependencies,
                    task_id=derive_task_id(run_id, number),
                )
            )
    else:
        workstreams.append(
            Workstream(
                number=1,
                title=title,
                required_disposition="COMPLETE",
                dependencies=(),
                task_id=derive_task_id(run_id, 1),
            )
        )

    return ParsedPrompt(
        sha256=digest,
        byte_count=len(data),
        title=title,
        objective=objective,
        mission=mission,
        allowed=allowed,
        forbidden=forbidden,
        workstreams=tuple(workstreams),
        run_id=run_id,
        source=source,
        project_node=project_node,
    )


def _parse_title(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    raise PromptIngestError("prompt title is missing")


def _parse_objective(text: str) -> str:
    lines = text.splitlines()
    start_idx = None
    for index, line in enumerate(lines):
        if line.startswith("**Objective:**"):
            start_idx = index
            break
    if start_idx is None:
        raise PromptIngestError("prompt objective is missing")

    first = lines[start_idx][len("**Objective:**") :].strip()
    objective_lines = [first] if first else []
    for line in lines[start_idx + 1 :]:
        if not line.strip():
            break
        if line.startswith("##") or line.startswith("**"):
            break
        objective_lines.append(line.rstrip())

    objective = "\n".join(objective_lines).strip()
    if not objective:
        raise PromptIngestError("prompt objective is missing")
    return objective


def _section_body(text: str, heading: str) -> str:
    pattern = rf"^## {re.escape(heading)}\s*$"
    match = re.search(pattern, text, flags=re.MULTILINE)
    if not match:
        raise PromptIngestError(f"prompt section is missing: {heading}")
    start = match.end()
    next_heading = re.search(r"^## ", text[start:], flags=re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(text)
    return text[start:end].strip()


def _parse_section(text: str, heading: str) -> str:
    return _section_body(text, heading)


def _parse_authority_envelope(text: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        body = _section_body(text, "P0 authority envelope")
    except PromptIngestError as exc:
        raise PromptIngestError("authority envelope is missing") from exc

    allowed_match = re.search(r"^Allowed:\s*$", body, flags=re.MULTILINE)
    forbidden_match = re.search(
        r"^Forbidden without a new explicit authority envelope:\s*$",
        body,
        flags=re.MULTILINE,
    )
    if not allowed_match or not forbidden_match:
        raise PromptIngestError("authority envelope is missing")

    allowed_block = body[allowed_match.end() : forbidden_match.start()]
    forbidden_block = body[forbidden_match.end() :]
    allowed = _bullet_lines(allowed_block)
    forbidden = _bullet_lines(forbidden_block)
    if not allowed or not forbidden:
        raise PromptIngestError("authority envelope is missing")
    return tuple(allowed), tuple(forbidden)


def _bullet_lines(block: str) -> list[str]:
    bullets: list[str] = []
    current: str | None = None
    for line in block.splitlines():
        if line.startswith("- "):
            if current is not None:
                bullets.append(current)
            current = line
        elif not line.strip():
            if current is not None:
                bullets.append(current)
                current = None
        elif current is not None:
            current = f"{current}\n{line}"
    if current is not None:
        bullets.append(current)
    return bullets


def _parse_workstreams(text: str) -> list[tuple[int, str]]:
    try:
        body = _section_body(text, "Ordered workstreams")
    except PromptIngestError:
        return []

    matches = re.findall(r"^### (\d+)\. (.+)$", body, flags=re.MULTILINE)
    return [(int(number), title.strip()) for number, title in matches]


def _parse_project_node_binding(text: str) -> ProjectNodeBinding | None:
    try:
        body = _section_body(text, "Project node binding")
    except PromptIngestError:
        return None

    rows = [line.strip() for line in body.splitlines() if line.strip().startswith("|")]
    if len(rows) < 2:
        raise PromptIngestError("malformed project node binding")

    values: dict[str, str] = {}
    for row in rows[2:]:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        if len(cells) < 2:
            raise PromptIngestError("malformed project node binding")
        key = cells[0].strip().lower()
        values[key] = cells[1].strip()

    program = values.get("program")
    node = values.get("node")
    acceptance = values.get("acceptance version")
    if not program or not node or not acceptance:
        raise PromptIngestError("project node binding is missing required fields")

    program_match = re.search(r"`([^`]+)`\s+v(.+)$", program)
    if not program_match:
        raise PromptIngestError("project node binding program must use `ID` vVERSION form")
    project_id = program_match.group(1).strip()
    project_version = program_match.group(2).strip()

    node_match = re.search(r"`([^`]+)`(?:\s*\(child of `([^`]+)`\))?", node)
    if not node_match:
        raise PromptIngestError("project node binding node must use `NODE` form")
    node_id = node_match.group(1).strip()
    parent_node_id = node_match.group(2).strip() if node_match.group(2) else None

    return ProjectNodeBinding(
        project_id=project_id,
        project_version=project_version,
        node_id=node_id,
        parent_node_id=parent_node_id,
        acceptance_version=_strip_binding_value(acceptance),
    )


def _strip_binding_value(value: str) -> str:
    ticked = re.findall(r"`([^`]+)`", value)
    if ticked:
        return ticked[0].strip()
    return value.strip()


def _parse_acceptance_matrix(text: str) -> dict[int, str]:
    try:
        body = _section_body(text, "Cross-workstream acceptance matrix")
    except PromptIngestError:
        if _parse_workstreams(text):
            raise PromptIngestError("malformed acceptance matrix") from None
        return {}

    rows = [line.strip() for line in body.splitlines() if line.strip().startswith("|")]
    if len(rows) < 2:
        raise PromptIngestError("malformed acceptance matrix")

    dispositions: dict[int, str] = {}
    for row in rows[2:]:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        if len(cells) < 2:
            raise PromptIngestError("malformed acceptance matrix")
        item_match = re.match(r"^(\d+)\.", cells[0])
        if not item_match:
            continue
        number = int(item_match.group(1))
        disposition = _primary_disposition(cells[1])
        if not disposition:
            raise PromptIngestError("malformed acceptance matrix")
        dispositions[number] = disposition
    if not dispositions and _parse_workstreams(text):
        raise PromptIngestError("malformed acceptance matrix")
    return dispositions


def _primary_disposition(cell: str) -> str:
    ticked = re.findall(r"`([^`]+)`", cell)
    if ticked:
        return ticked[0].strip()
    for separator in (" only", " with", ";", ","):
        if separator in cell:
            return cell.split(separator, 1)[0].strip()
    return cell.strip()
