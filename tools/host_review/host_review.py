"""Host-namespace independent-review runtime."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "controller"))

PER_ATTEMPT_TOKENS_DEFAULT = 16384
PER_ATTEMPT_TOKENS_MAX = 32768
PER_ATTEMPT_TOKENS = PER_ATTEMPT_TOKENS_MAX
ATTEMPTS_PER_MODEL = 2
MAX_REVIEW_REDOS = 5
MAX_REVIEW_SUBMISSIONS = MAX_REVIEW_REDOS + 1
AGGREGATE_TOKEN_BUDGET = 160000
LUNA_TTFT_SECONDS = 30.0
LUNA_MODEL = "openai/gpt-5.6-luna"
LUNA_MODEL_SLUG = "gpt-5.6-luna"
CODEX_BIN = "/opt/operator-harness/bin/codex"
CODEX_HOME = os.environ.get("CODEX_HOME", "/opt/operator-harness/homes/.codex")
DENIED_PREFIXES = ()
TERMINAL_VERDICTS = frozenset(
    {"approve", "approve-with-minors", "changes-required", "fail"}
)
FINDING_SEVERITIES = frozenset({"blocker", "major", "minor", "info"})
FEEDBACK_MAX_ITEMS = 8
FEEDBACK_TEXT_MAX_BYTES = 512
FEEDBACK_TARGETS = frozenset({"spec", "plan", "code", "test", "evidence", "routing"})
FEEDBACK_SENSITIVE_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]+|Bearer\s+\S+|postgres(?:ql)?://\S+|-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----)",
    re.IGNORECASE | re.DOTALL,
)
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
ENV_MAX_TOKENS = "HOST_REVIEW_MAX_TOKENS"
WRAPPER_PATH = "/opt/operator-harness/bin/openrouter-review"
LIBRARY_PATH = "/opt/operator-harness/lib/top_delivery_host_review/host_openrouter_review.py"
CURSOR_BIN = "/opt/operator-harness/bin/cursor"
CONNECT_TIMEOUT_SECONDS = 30.0
READ_TIMEOUT_SECONDS = 600.0
TOTAL_ATTEMPT_TIMEOUT_SECONDS = 900.0

REVIEW_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "findings", "suggestions"],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": sorted(TERMINAL_VERDICTS),
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "severity", "summary", "recommendation"],
                "properties": {
                    "id": {"type": "string"},
                    "severity": {"type": "string", "enum": sorted(FINDING_SEVERITIES)},
                    "summary": {"type": "string"},
                    "recommendation": {"type": ["string", "null"]},
                },
            },
        },
        "suggestions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "target", "priority", "action", "acceptance"],
                "properties": {
                    "id": {"type": "string"},
                    "target": {"type": "string", "enum": sorted(FEEDBACK_TARGETS)},
                    "priority": {"type": "string"},
                    "action": {"type": "string"},
                    "acceptance": {"type": ["string", "null"]},
                },
            },
        },
    },
}

SCHEMA_CONTRACT = (
    "Return exactly one JSON object with keys verdict and findings. "
    f"verdict must be one of: {', '.join(sorted(TERMINAL_VERDICTS))}. "
    "Each finding must include id, severity "
    f"({', '.join(sorted(FINDING_SEVERITIES))}), and summary. "
    "No markdown fences or prose outside the JSON object."
)


class ReviewPolicyError(ValueError):
    """Policy refusal before or after a provider call."""


@dataclass
class RouteHop:
    provider: str
    model: str
    effort: str


@dataclass
class ParseReviewResult:
    status: str
    verdict: str | None = None
    payload: dict[str, Any] | None = None


@dataclass
class TransportResult:
    http_status: int
    model_returned: str | None
    content: str
    finish_reason: str | None
    completion_tokens: int | None
    first_byte_seconds: float = 0.0
    ttft_measured: bool = False
    error: str | None = None
    generation_id: str | None = None
    provider: str | None = None
    reasoning_tokens: int | None = None


@dataclass
class SeatResult:
    status: str
    verdict: str | None
    hops: list[dict[str, Any]] = field(default_factory=list)
    fallback_reason: str | None = None
    tokens_used: int = 0
    model: str | None = None
    provider: str | None = None
    suggestions: list[dict[str, str]] = field(default_factory=list)
    finding_summaries: list[dict[str, str]] = field(default_factory=list)
    suggestions_complete: bool = False


def allowed_max_tokens(cli_value: int | None, environ: Mapping[str, str] | None = None) -> int:
    env = os.environ if environ is None else environ
    if ENV_MAX_TOKENS in env and str(env[ENV_MAX_TOKENS]).strip():
        try:
            env_val = int(str(env[ENV_MAX_TOKENS]).strip())
        except ValueError as exc:
            raise ReviewPolicyError("HOST_REVIEW_MAX_TOKENS is not an integer") from exc
        if env_val not in {PER_ATTEMPT_TOKENS_DEFAULT, PER_ATTEMPT_TOKENS_MAX}:
            raise ReviewPolicyError("HOST_REVIEW_MAX_TOKENS must be 16384 or 32768")
        return env_val
    if cli_value is None:
        return PER_ATTEMPT_TOKENS_DEFAULT
    if cli_value not in {PER_ATTEMPT_TOKENS_DEFAULT, PER_ATTEMPT_TOKENS_MAX}:
        raise ReviewPolicyError("max-tokens must be 16384 or 32768")
    return cli_value


def enforce_max_tokens(cli_value: int | None, environ: Mapping[str, str] | None = None) -> int:
    return allowed_max_tokens(cli_value, environ)


def tokens_for_hop(effort: str, configured_max: int) -> int:
    if configured_max == PER_ATTEMPT_TOKENS_MAX:
        return PER_ATTEMPT_TOKENS_MAX
    if effort in {"max", "xhigh"}:
        return PER_ATTEMPT_TOKENS_MAX
    return PER_ATTEMPT_TOKENS_DEFAULT


def deny_model(model: str) -> None:
    if not model:
        raise ReviewPolicyError("model is required")
    if DENIED_PREFIXES and model.startswith(DENIED_PREFIXES):
        raise ReviewPolicyError("model is denylisted")


def normalize_model_id(model: str) -> str:
    if model.startswith("openai/"):
        return model[len("openai/") :]
    return model


def is_luna_model(model: str) -> bool:
    return normalize_model_id(model) == LUNA_MODEL_SLUG


def returned_model_ok(requested: str, returned: str | None) -> bool:
    if not returned:
        return False
    from harness_adapters.identity import canonical_model
    return canonical_model(returned.lower().replace(" ","-")) == canonical_model(requested.lower().replace(" ","-"))


def account_tokens(completion_tokens: int | None, hop_tokens: int) -> int:
    if isinstance(completion_tokens, int) and completion_tokens >= 0:
        return completion_tokens
    return hop_tokens


def would_exceed_aggregate(tokens_used: int, next_cost: int = PER_ATTEMPT_TOKENS_MAX) -> bool:
    return tokens_used + next_cost > AGGREGATE_TOKEN_BUDGET


def _json_object_with_verdict(text: str) -> str | None:
    if not isinstance(text, str) or not text.strip():
        return None
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            obj, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("verdict") in TERMINAL_VERDICTS:
            return text[index:end]
    return None


def review_text_from_message(message: Mapping[str, Any] | None) -> str:
    if not isinstance(message, Mapping):
        return ""
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content
    recovered = _json_object_with_verdict(str(message.get("reasoning") or message.get("reasoning_content") or ""))
    if recovered:
        return recovered
    details = message.get("reasoning_details")
    if isinstance(details, list):
        for item in details:
            if not isinstance(item, Mapping):
                continue
            recovered = _json_object_with_verdict(str(item.get("text") or ""))
            if recovered:
                return recovered
    return content if isinstance(content, str) else ""


def continuation_chat_body(
    base: Mapping[str, Any], message: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    if not isinstance(message, Mapping):
        return None
    if review_text_from_message(message).strip():
        return None
    details = message.get("reasoning_details")
    reasoning = message.get("reasoning") or message.get("reasoning_content")
    if not details and not (isinstance(reasoning, str) and reasoning.strip()):
        return None
    assistant: dict[str, Any] = {
        "role": "assistant",
        "content": message.get("content") if isinstance(message.get("content"), str) else "",
    }
    if isinstance(details, list) and details:
        assistant["reasoning_details"] = details
    elif isinstance(reasoning, str) and reasoning.strip():
        assistant["reasoning"] = reasoning
    body = dict(base)
    body["messages"] = list(base.get("messages") or []) + [
        assistant,
        {
            "role": "user",
            "content": (
                "Your previous message left content empty. Return only the JSON object "
                "with keys verdict and findings. Do not omit the JSON object."
            ),
        },
    ]
    body["reasoning"] = {"effort": "low"}
    return body


def _bounded_feedback_text(value: Any) -> str:
    text = " ".join(str(value or "").split())
    text = FEEDBACK_SENSITIVE_RE.sub("[REDACTED]", text)
    encoded = text.encode("utf-8")[:FEEDBACK_TEXT_MAX_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def parse_review_feedback(content: str) -> dict[str, Any]:
    parsed = parse_review_content(content)
    if parsed.status != "ok" or not isinstance(parsed.payload, dict):
        return {
            "suggestions": [],
            "finding_summaries": [],
            "suggestions_complete": False,
            "suggestions_source": parsed.status,
        }
    payload = parsed.payload
    verdict = payload.get("verdict")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        findings = []
    finding_summaries: list[dict[str, str]] = []
    for finding in findings[:FEEDBACK_MAX_ITEMS]:
        if not isinstance(finding, dict):
            continue
        finding_id = _bounded_feedback_text(finding.get("id") or "unnamed-finding")
        severity = _bounded_feedback_text(finding.get("severity") or "unknown")
        summary = _bounded_feedback_text(finding.get("summary") or "")
        if summary:
            finding_summaries.append({"id": finding_id, "severity": severity, "summary": summary})

    raw_suggestions = payload.get("suggestions")
    explicit_suggestions = raw_suggestions if isinstance(raw_suggestions, list) else []
    suggestions: list[dict[str, str]] = []
    for suggestion in explicit_suggestions[:FEEDBACK_MAX_ITEMS]:
        if isinstance(suggestion, str):
            suggestion = {"action": suggestion}
        if not isinstance(suggestion, dict):
            continue
        target = _bounded_feedback_text(suggestion.get("target") or "code").lower()
        if target not in FEEDBACK_TARGETS:
            target = "code"
        priority = _bounded_feedback_text(
            suggestion.get("priority") or suggestion.get("severity") or "major"
        ).lower()
        action = _bounded_feedback_text(
            suggestion.get("action") or suggestion.get("recommendation") or suggestion.get("summary")
        )
        acceptance = _bounded_feedback_text(
            suggestion.get("acceptance") or suggestion.get("verification") or ""
        )
        if action:
            suggestions.append({
                "id": _bounded_feedback_text(suggestion.get("id") or f"suggestion-{len(suggestions) + 1}"),
                "target": target,
                "priority": priority,
                "action": action,
                "acceptance": acceptance,
            })

    if not suggestions:
        for finding in findings[:FEEDBACK_MAX_ITEMS]:
            if not isinstance(finding, dict):
                continue
            recommendation = _bounded_feedback_text(finding.get("recommendation") or "")
            if recommendation:
                suggestions.append({
                    "id": _bounded_feedback_text(f"finding-{finding.get('id') or len(suggestions) + 1}"),
                    "target": "code",
                    "priority": _bounded_feedback_text(finding.get("severity") or "major").lower(),
                    "action": recommendation,
                    "acceptance": _bounded_feedback_text(finding.get("summary") or ""),
                })
    requires_suggestions = verdict in {"changes-required", "fail"}
    return {
        "suggestions": suggestions,
        "finding_summaries": finding_summaries,
        "suggestions_complete": (not requires_suggestions) or bool(explicit_suggestions),
        "suggestions_source": "explicit" if explicit_suggestions else ("derived-from-findings" if suggestions else "missing"),
    }


def _finding_schema_valid(findings: Any) -> bool:
    if not isinstance(findings, list):
        return False
    for finding in findings:
        if not isinstance(finding, dict):
            return False
        if not str(finding.get("id") or "").strip():
            return False
        severity = str(finding.get("severity") or "")
        if severity not in FINDING_SEVERITIES:
            return False
        if not str(finding.get("summary") or "").strip():
            return False
    return True


def parse_review_content(content: str) -> ParseReviewResult:
    extracted = _json_object_with_verdict(content)
    candidate = extracted if extracted is not None else content
    try:
        payload = json.loads(candidate)
    except (TypeError, json.JSONDecodeError):
        return ParseReviewResult(status="json-syntax-error")
    if not isinstance(payload, dict):
        return ParseReviewResult(status="json-syntax-error")
    verdict = payload.get("verdict")
    if verdict not in TERMINAL_VERDICTS:
        return ParseReviewResult(status="invalid-verdict", payload=payload)
    if not _finding_schema_valid(payload.get("findings")):
        return ParseReviewResult(status="invalid-schema", payload=payload, verdict=str(verdict))
    return ParseReviewResult(status="ok", verdict=str(verdict), payload=payload)


def parse_verdict(content: str) -> str | None:
    parsed = parse_review_content(content)
    return parsed.verdict if parsed.status == "ok" else None


class LunaReservation:
    def __init__(self, artifact_root: Path):
        self.path = Path(artifact_root) / "luna-reservation.json"

    def try_acquire(self, run_id: str, seat: str) -> bool:
        payload = {
            "run_id": run_id,
            "seat": seat,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(str(self.path), flags, 0o600)
        except FileExistsError:
            return False
        try:
            os.write(fd, json.dumps(payload).encode())
        finally:
            os.close(fd)
        return True

    def exists(self) -> bool:
        return self.path.exists()


def seat_chain(routing: Mapping[str, Any], seat: str) -> list[RouteHop]:
    phases = routing.get("phases")
    if not isinstance(phases, dict) or seat not in phases:
        raise ReviewPolicyError(f"unknown seat {seat}")
    entry = phases[seat]
    if not isinstance(entry, dict):
        raise ReviewPolicyError("seat entry must be a mapping")
    if entry.get("enabled") is False:
        raise ReviewPolicyError("seat is disabled")
    primary = str(entry.get("model") or "")
    effort = str(entry.get("effort") or "high")
    primary_provider = str(entry.get("provider") or "openrouter")
    deny_model(primary)
    chain = [RouteHop(provider=primary_provider, model=primary, effort=effort)]
    fallbacks = entry.get("fallbacks") or []
    if not isinstance(fallbacks, list):
        raise ReviewPolicyError("fallbacks must be a list")
    for item in fallbacks:
        if not isinstance(item, dict):
            raise ReviewPolicyError("fallback must be a mapping")
        model = str(item.get("model") or "")
        deny_model(model)
        hop_effort = str(item.get("effort") or effort)
        provider = str(item.get("provider") or primary_provider)
        chain.append(RouteHop(provider=provider, model=model, effort=hop_effort))
    if chain and not is_luna_model(chain[-1].model) and any(is_luna_model(h.model) for h in chain):
        raise ReviewPolicyError("Luna must be last in the chain")
    return chain


def classify_transport(requested: str, result: TransportResult, luna: bool, ttft_limit: float) -> str:
    if result.error in {"ConnectionResetError", "TimeoutError", "URLError", "SSLError", "BrokenPipeError"}:
        return "transport-reset"
    if result.error in {
        "CursorExit",
        "CursorAgentError",
        "CursorEnvelopeJSONError",
        "CodexUsageLimit",
        "ArgumentListTooLong",
    } or (
        result.error
        and (result.error.startswith("CursorExit") or result.error.startswith("CodexExit"))
    ):
        return "transport-error"
    if luna and result.ttft_measured and result.first_byte_seconds > ttft_limit:
        return "luna-ttft-exceeded"
    if result.error or result.http_status >= 400 or (result.http_status != 0 and result.http_status < 200):
        return "http-error"
    if result.http_status == 0 and result.error:
        return "transport-reset"
    if not returned_model_ok(requested, result.model_returned):
        if result.model_returned and str(result.model_returned).startswith(DENIED_PREFIXES):
            return "returned-denylisted-model"
        return "returned-model-mismatch"
    if not (result.content or "").strip():
        return "empty-content"
    if result.finish_reason in {None, "", "length"}:
        return "bad-finish"
    parsed = parse_review_content(result.content)
    if parsed.status == "json-syntax-error":
        return "json-syntax-error"
    if parsed.status == "invalid-verdict":
        return "invalid-verdict"
    if parsed.status == "invalid-schema":
        return "invalid-schema"
    if parsed.status != "ok":
        return "invalid-json"
    return "terminal"


Transport = Callable[[str, str, str, int], TransportResult]


def run_seat(
    *,
    seat: str,
    routing: Mapping[str, Any],
    artifact_root: Path,
    run_id: str,
    transport: Transport,
    ttft_limit: float = LUNA_TTFT_SECONDS,
    configured_max_tokens: int = PER_ATTEMPT_TOKENS_DEFAULT,
    review_context: dict | None = None,
) -> SeatResult:
    from review_execution import select_review
    if review_context is None:
        raise ReviewPolicyError("bound actual author/source/review history required")
    selected=select_review(dict(routing),seat,review_context,artifact_root,run_id)
    from bounded_delivery import write_once
    from subworkflow_handoff import digest_value, canonical_json
    intent={"run_id":run_id,"seat":seat,"subject":review_context["subject"]["sha256"]}
    write_once(artifact_root/"review-intents"/(digest_value(intent)+".json"),canonical_json(intent))
    chain = [RouteHop(provider=selected.provider,model=selected.model,effort=selected.effort)]
    reservation = LunaReservation(artifact_root)
    hops: list[dict[str, Any]] = []
    tokens_used = 0
    for index, hop in enumerate(chain):
        luna = is_luna_model(hop.model)
        if luna:
            if not reservation.try_acquire(run_id, seat):
                return SeatResult(
                    status="luna-already-consumed",
                    verdict=None,
                    hops=hops,
                    fallback_reason="luna-already-consumed",
                    tokens_used=tokens_used,
                )
        hop_tokens = tokens_for_hop(hop.effort, configured_max_tokens)
        for attempt in range(1):
            if would_exceed_aggregate(tokens_used, hop_tokens):
                return SeatResult(
                    status="aggregate-token-budget-exhausted",
                    verdict=None,
                    hops=hops,
                    fallback_reason="aggregate-token-budget-exhausted",
                    tokens_used=tokens_used,
                )
            result = transport(hop.provider, hop.model, hop.effort, hop_tokens)
            cost = account_tokens(result.completion_tokens, hop_tokens)
            tokens_used += cost
            kind = classify_transport(hop.model, result, luna, ttft_limit)
            hop_record = {
                "index": index,
                "provider": hop.provider,
                "model": hop.model,
                "model_returned": result.model_returned,
                "effort": hop.effort,
                "attempt": attempt + 1,
                "kind": kind,
                "http_status": result.http_status,
                "finish_reason": result.finish_reason,
                "tokens": cost,
            }
            if result.generation_id:
                hop_record["generation_id"] = result.generation_id
            if result.provider:
                hop_record["upstream_provider"] = result.provider
            if result.reasoning_tokens is not None:
                hop_record["reasoning_tokens"] = result.reasoning_tokens
            if result.ttft_measured:
                hop_record["first_byte_seconds"] = result.first_byte_seconds
            hops.append(hop_record)
            if kind == "terminal":
                import hashlib
                normalized={"status":"success","exit_code":0,"provider":hop.provider,"model":result.model_returned,
                    "structured_payload":parse_review_content(result.content).payload,"generation_id":result.generation_id}
                result_bytes=canonical_json(normalized)
                result_path=Path("review-results")/(digest_value(intent)+".json")
                write_once(artifact_root/result_path,result_bytes)
                history={"run_id":run_id,"subject_sha256":review_context["subject"]["sha256"],
                    "route":replace(selected,model=result.model_returned.lower().replace(" ","-")).to_dict(),"result":{"path":str(result_path),"sha256":hashlib.sha256(result_bytes).hexdigest()}}
                write_once(artifact_root/"review-history"/(digest_value(intent)+".json"),canonical_json(history))
                feedback = parse_review_feedback(result.content)
                return SeatResult(
                    status="ok",
                    verdict=parse_verdict(result.content),
                    hops=hops,
                    fallback_reason=None if index == 0 and attempt == 0 else "retried-or-hopped",
                    tokens_used=tokens_used,
                    model=result.model_returned,
                    provider=hop.provider,
                    suggestions=feedback["suggestions"],
                    finding_summaries=feedback["finding_summaries"],
                    suggestions_complete=feedback["suggestions_complete"],
                )
            if kind == "returned-denylisted-model":
                return SeatResult(
                    status="returned-denylisted-model",
                    verdict=None,
                    hops=hops,
                    fallback_reason="returned-denylisted-model",
                    tokens_used=tokens_used,
                    model=hop.model,
                    provider=hop.provider,
                )
            if kind == "luna-ttft-exceeded":
                return SeatResult(
                    status="luna-ttft-exceeded",
                    verdict=None,
                    hops=hops,
                    fallback_reason="luna-ttft-exceeded",
                    tokens_used=tokens_used,
                    model=hop.model,
                    provider=hop.provider,
                )
    return SeatResult(
        status="chain-exhausted",
        verdict=None,
        hops=hops,
        fallback_reason="chain-exhausted",
        tokens_used=tokens_used,
    )




def _transport_error_result(exc: BaseException, started: datetime) -> TransportResult:
    first_byte = (datetime.now(timezone.utc) - started).total_seconds()
    return TransportResult(
        http_status=0,
        model_returned=None,
        content="",
        finish_reason=None,
        completion_tokens=None,
        first_byte_seconds=first_byte,
        ttft_measured=False,
        error=type(exc).__name__,
    )




def parse_cursor_envelope(stdout: str) -> tuple[TransportResult, dict[str, Any] | None]:
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError:
        return (
            TransportResult(
                http_status=0,
                model_returned=None,
                content=stdout[:4000],
                finish_reason=None,
                completion_tokens=None,
                error="CursorEnvelopeJSONError",
                provider="cursor",
            ),
            None,
        )
    if not isinstance(envelope, dict):
        return (
            TransportResult(
                http_status=0,
                model_returned=None,
                content=stdout[:4000],
                finish_reason=None,
                completion_tokens=None,
                error="CursorEnvelopeJSONError",
                provider="cursor",
            ),
            None,
        )
    if envelope.get("is_error"):
        return (
            TransportResult(
                http_status=500,
                model_returned=None,
                content=str(envelope.get("result") or ""),
                finish_reason=None,
                completion_tokens=None,
                error="CursorAgentError",
                generation_id=envelope.get("request_id"),
                provider="cursor",
            ),
            envelope,
        )
    usage = envelope.get("usage") if isinstance(envelope.get("usage"), dict) else {}
    result_text = str(envelope.get("result") or "")
    extracted = _json_object_with_verdict(result_text) or result_text
    return (
        TransportResult(
            http_status=200,
            model_returned=None,
            content=extracted,
            finish_reason="stop" if envelope.get("subtype") == "success" else None,
            completion_tokens=usage.get("outputTokens"),
            first_byte_seconds=0.0,
            ttft_measured=False,
            generation_id=envelope.get("request_id"),
            provider="cursor",
        ),
        envelope,
    )


def cursor_transport(
    system: str,
    user: str,
    timeout: float = TOTAL_ATTEMPT_TIMEOUT_SECONDS,
) -> Transport:
    system_text = f"{system.strip()}\n\n{SCHEMA_CONTRACT}"

    def _call(provider: str, model: str, effort: str, max_tokens: int) -> TransportResult:
        if provider != "cursor":
            raise ReviewPolicyError(f"cursor_transport cannot serve provider {provider}")
        deny_model(model)
        prompt = (
            f"{system_text}\n\n---\n\nReview packet:\n{user}\n\n"
            f"Respond with only the JSON review object. effort={effort} max_tokens={max_tokens}"
        )
        cmd = [
            CURSOR_BIN,
            "agent",
            "--mode",
            "ask",
            "--model",
            model,
            "-p",
            "--output-format",
            "stream-json",
            "--sandbox",
            "enabled",
            prompt,
        ]
        started = datetime.now(timezone.utc)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd="/tmp",
            )
        except subprocess.TimeoutExpired as exc:
            return replace(_transport_error_result(exc, started), provider="cursor")
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        if proc.returncode != 0:
            return TransportResult(
                http_status=proc.returncode,
                model_returned=model,
                content=(proc.stderr or proc.stdout or "")[:4000],
                finish_reason=None,
                completion_tokens=None,
                first_byte_seconds=elapsed,
                ttft_measured=False,
                error=f"CursorExit{proc.returncode}",
                provider="cursor",
            )
        try:
            events=[json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
            init=[e for e in events if e.get("type")=="system" and e.get("subtype")=="init"]
            ends=[e for e in events if e.get("type")=="result"]
            if len(init)!=1 or len(ends)!=1:
                raise ValueError("missing unique harness attribution")
            from harness_adapters.identity import canonical_model
            actual=str(init[0].get("model","")).lower().replace(" ","-")
            if canonical_model(actual)!=canonical_model(model):
                raise ValueError("harness model mismatch")
            result, _envelope = parse_cursor_envelope(json.dumps(ends[0]))
            return replace(result, model_returned=init[0]["model"], first_byte_seconds=elapsed)
        except (ValueError,TypeError):
            return TransportResult(http_status=0,model_returned=None,content="",finish_reason=None,
                completion_tokens=None,error="CursorAttributionMismatch",provider="cursor")

    return _call


def composite_transport(system: str, user: str) -> Transport:
    """Only the explicitly authorized subscription transport is executable."""
    return cursor_transport(system, user)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seat")
    parser.add_argument("--review-context",type=Path,help="trusted source/author/history manifest; mandatory")
    parser.add_argument("--routing-yaml", type=Path)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--run-id", default="host-review")
    parser.add_argument("--smoke-model")
    parser.add_argument("--smoke-provider", default="openrouter")
    parser.add_argument("--effort", default="high")
    parser.add_argument("--review-attempt", type=int, default=0)
    parser.add_argument("--max-tokens", type=int, default=PER_ATTEMPT_TOKENS_DEFAULT)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--system-file", type=Path)
    parser.add_argument("--user-file", type=Path)
    parser.add_argument(
        "--prior-seat-json",
        type=Path,
        help="Required for seat 1.6 when routing defines an ordered review gate.",
    )
    args = parser.parse_args(argv)
    configured_max = enforce_max_tokens(args.max_tokens)
    if not 0 <= args.review_attempt <= MAX_REVIEW_REDOS:
        raise ReviewPolicyError("review-attempt must be between 0 and 5")
    if args.smoke_model:
        raise ReviewPolicyError("unbound smoke execution is disabled in the source-owned review entry point")
    else:
        if not args.seat or not args.routing_yaml:
            raise SystemExit("seat reviews require --seat and --routing-yaml")
        import yaml

        routing = yaml.safe_load(args.routing_yaml.read_text())
        if not args.system_file or not args.user_file:
            raise SystemExit("seat reviews require --system-file and --user-file")
        if args.seat == "1.6" and isinstance(routing.get("review_sequence"), dict):
            if not args.prior_seat_json:
                raise SystemExit("seat 1.6 requires --prior-seat-json under the ordered review policy")
            try:
                prior = json.loads(args.prior_seat_json.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                raise SystemExit(f"invalid --prior-seat-json: {exc}") from exc
            prior_verdict = str(prior.get("verdict") or "")
            allowed = {"pass", "pass_with_minors", "approve", "approve-with-minors"}
            if prior_verdict not in allowed:
                raise SystemExit(
                    f"ordered review gate blocked seat 1.6: seat 1.5 verdict={prior_verdict or 'missing'}"
                )
        if not args.review_context:
            raise ReviewPolicyError("bound review context required")
        context=json.loads(args.review_context.read_text())
        import hashlib
        packet=args.user_file.read_bytes()
        if hashlib.sha256(packet).hexdigest()!=context.get("subject",{}).get("sha256"):
            raise ReviewPolicyError("review packet differs from bound subject")
        transport = composite_transport(
            args.system_file.read_text(),
            packet.decode("utf-8"),
        )
        result = run_seat(
            seat=args.seat,
            routing=routing,
            artifact_root=args.artifact_root,
            run_id=args.run_id,
            transport=transport,
            configured_max_tokens=configured_max,
            review_context=context,
        )
    payload = {
        "status": result.status,
        "verdict": result.verdict,
        "hops": result.hops,
        "fallback_reason": result.fallback_reason,
        "tokens_used": result.tokens_used,
        "model": result.model,
        "provider": result.provider,
        "transport": "cursor-agent",
        "review_attempt": args.review_attempt,
        "max_review_redos": MAX_REVIEW_REDOS,
        "suggestions": result.suggestions,
        "finding_summaries": result.finding_summaries,
        "suggestions_complete": result.suggestions_complete,
    }
    text = json.dumps(payload, indent=2) + "\n"
    if args.out:
        args.out.write_text(text)
    else:
        print(text)
    return 0 if result.status == "ok" and result.verdict in {"approve", "approve-with-minors"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
