"""Fail-closed HTTP-auditor evidence bind: schema, trusted snippets, verdict checks.

Trusted snippets are the first TRUSTED_SNIPPET_BYTES of each executor stdout/stderr
file after redaction. evidence_refs sha256 values must match the full artifact
bytes persisted by the worker, not the truncated snippet. Substring checks run
on the same redacted snippet bytes placed in the auditor prompt. A criterion
that exists only past the 4KiB window cannot approve.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from harness_adapters.contract import HarnessResult
from harness_adapters.redaction import redact_text
from harness_adapters.schema import validate_json_schema

TRUSTED_SNIPPET_BYTES = 4096
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

AUDITOR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["approve", "reject"]},
        "criteria": {
            "type": "array",
            "minItems": 1,
            "maxItems": 64,
            "items": {
                "type": "object",
                "properties": {
                    "criterion": {"type": "string", "minLength": 1, "maxLength": 512},
                    "met": {"type": "boolean"},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": 2048},
                    "evidence_refs": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 32,
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                                "sha256": {"type": "string", "minLength": 64, "maxLength": 64},
                            },
                            "required": ["name", "sha256"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["criterion", "met", "rationale", "evidence_refs"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["verdict", "criteria"],
    "additionalProperties": False,
}


class AcceptanceCriteriaError(ValueError):
    """Empty or malformed acceptance_criteria."""


def normalize_acceptance_criteria(acceptance: Any) -> list[str]:
    if not isinstance(acceptance, list):
        raise AcceptanceCriteriaError("acceptance_criteria must be an array")
    if not acceptance:
        raise AcceptanceCriteriaError("acceptance_criteria must be a non-empty array")
    out: list[str] = []
    for item in acceptance:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict) and item:
            out.append(json.dumps(item, sort_keys=True))
        else:
            raise AcceptanceCriteriaError(
                "acceptance_criteria items must be non-empty strings or objects"
            )
    return out


def _extracted_json(executor_result: HarnessResult) -> dict[str, Any] | None:
    structured = executor_result.structured_payload
    if not isinstance(structured, dict):
        return None
    extracted = structured.get("extracted_json")
    return extracted if isinstance(extracted, dict) else None


def collect_trusted_evidence(
    *,
    artifact_root: Path,
    role_dir: Path,
    executor_result: HarnessResult,
    executor_evidence: list[dict[str, str]],
    acceptance: list[str],
) -> dict[str, Any]:
    snippets: list[dict[str, Any]] = []
    text_parts: list[str] = []
    digest_by_name: dict[str, str] = {}
    known_digests: set[str] = set()
    root = Path(artifact_root).resolve()
    role = Path(role_dir).resolve()
    for item in executor_evidence:
        name = str(item.get("stream") or item.get("name") or "artifact")
        digest = str(item.get("sha256") or "")
        if not _SHA256_RE.fullmatch(digest):
            continue
        digest_by_name[name] = digest
        known_digests.add(digest)
        relative = item.get("artifact_path")
        path: Path | None = None
        if isinstance(relative, str) and relative:
            candidate = (root / relative).resolve()
            if candidate.is_file() and not candidate.is_symlink() and (
                candidate.is_relative_to(root) or candidate.is_relative_to(role)
            ):
                path = candidate
        if path is None:
            fallback = role / f"{name}.txt"
            if fallback.is_file() and not fallback.is_symlink():
                path = fallback.resolve()
        if path is None or not path.is_file():
            continue
        raw = path.read_bytes()
        snippet = raw[:TRUSTED_SNIPPET_BYTES]
        text = redact_text(snippet.decode("utf-8", "replace"))
        snippets.append(
            {
                "name": name,
                "sha256": digest,
                "byte_count": len(raw),
                "truncated": len(raw) > TRUSTED_SNIPPET_BYTES,
                "text": text,
            }
        )
        text_parts.append(text)
    trusted_text = "\n".join(text_parts)
    checks: list[dict[str, Any]] = []
    for criterion in acceptance:
        checks.append(
            {
                "criterion": criterion,
                "kind": "substring_in_trusted_evidence",
                "passed": criterion in trusted_text,
            }
        )
    extracted = _extracted_json(executor_result)
    if extracted is not None:
        checks.append(
            {
                "criterion": "extracted_json_is_untrusted",
                "kind": "untrusted_extracted_json",
                "passed": True,
                "untrusted": True,
                "extracted_sha256": hashlib.sha256(
                    json.dumps(extracted, sort_keys=True).encode()
                ).hexdigest(),
            }
        )
    substring_ok = all(
        item["passed"] for item in checks if item["kind"] == "substring_in_trusted_evidence"
    )
    return {
        "snippets": snippets,
        "checks": checks,
        "digest_by_name": digest_by_name,
        "known_digests": sorted(known_digests),
        "substring_ok": substring_ok,
        "trusted_text_sha256": hashlib.sha256(trusted_text.encode()).hexdigest(),
    }


def bound_auditor_verdict(
    payload: Any,
    *,
    acceptance: list[str],
    trusted: dict[str, Any],
    executor_evidence: list[dict[str, str]],
) -> str | None:
    if not isinstance(payload, dict):
        return None
    try:
        validate_json_schema(payload, AUDITOR_SCHEMA)
    except ValueError:
        return None
    verdict = payload["verdict"]
    rows = payload["criteria"]
    if len(rows) != len(acceptance):
        return "reject" if verdict == "approve" else verdict if verdict == "reject" else None
    known = {item["sha256"] for item in executor_evidence if _SHA256_RE.fullmatch(item.get("sha256", ""))}
    referenced: set[str] = set()
    for row, expected in zip(rows, acceptance):
        if row["criterion"] != expected:
            return "reject" if verdict == "approve" else "reject"
        for ref in row["evidence_refs"]:
            digest = ref["sha256"]
            if not _SHA256_RE.fullmatch(digest) or digest not in known:
                return "reject" if verdict == "approve" else "reject"
            referenced.add(digest)
    if verdict == "reject":
        return "reject"
    if verdict != "approve":
        return None
    if not trusted.get("substring_ok"):
        return "reject"
    if not all(row["met"] is True for row in rows):
        return "reject"
    EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
    required = {
        item["sha256"]
        for item in executor_evidence
        if _SHA256_RE.fullmatch(item.get("sha256", ""))
        and (
            item.get("stream") == "stdout"
            or (
                item.get("stream") == "stderr"
                and item["sha256"] != EMPTY_SHA256
            )
        )
    }
    if required and not required.issubset(referenced):
        return "reject"
    if not known:
        return "reject"
    return "approve"
