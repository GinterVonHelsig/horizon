"""Model routing authority with explicit harness and account-class records."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from harness_adapters.identity import canonical_model, model_family

ROUTING_RECORD_FIELDS = (
    "model",
    "harness",
    "account_class",
    "effort",
    "fallback_reason",
)

MANAGER_REVIEW_CODE_PHASES = ("0", "1", "2", "3A", "4", "5", "6", "7")
REVIEW_PHASES = frozenset({"1.5", "1.6", "1.7", "1.8", "1.9", "4", "6"})
PHASE_PROVIDERS = frozenset({"openai", "openrouter", "cursor", "antigravity"})


class IndependentReviewBlocked(ValueError):
    """No demonstrably independent configured review route can be selected."""


def review_sequence_allows_next(routing: dict[str, Any], completed_seat: str, verdict: str, next_seat: str) -> bool:
    """Return whether the configured ordered review may advance."""
    policy = routing.get("review_sequence") or {}
    order = policy.get("required_order") or []
    if not isinstance(order, list) or completed_seat not in order or next_seat not in order:
        return False
    if order.index(next_seat) != order.index(completed_seat) + 1:
        return False
    allowed = (policy.get("invoke_next_only_when") or {}).get(completed_seat, [])
    return verdict in allowed


@dataclass(frozen=True)
class RoutingRecord:
    phase: str
    role: str
    provider: str
    model: str
    harness: str
    account_class: str
    effort: str | None
    fallback_reason: str | None
    verdict: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "role": self.role,
            "provider": self.provider,
            "model": self.model,
            "harness": self.harness,
            "account_class": self.account_class,
            "effort": self.effort,
            "fallback_reason": self.fallback_reason,
            "verdict": self.verdict,
        }


def _account_class_for_provider(provider: str) -> str:
    if provider == "openrouter":
        return "metered-fallback"
    if provider in {"cursor", "claude", "codex", "antigravity"}:
        return "subscription"
    if provider.startswith("comms-"):
        return "local-pool"
    return "subscription"


def _harness_for_provider(provider: str) -> str:
    mapping = {
        "cursor": "cursor-agent",
        "claude": "claude-code",
        "codex": "codex-cli",
        "openrouter": "openrouter-chat",
        "comms-01-local": "ollama-openai-compatible",
        "comms-02-local": "ollama-openai-compatible",
        "antigravity": "qemu-x86_64-Haswell-agy",
    }
    return mapping.get(provider, provider)


def load_model_routing(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("model routing document must be a mapping")
    validate_routing_policy(payload)
    return payload


def validate_routing_policy(routing: dict[str, Any]) -> None:
    """Mirrors must be references, never a second source of model assignments."""
    if routing.get("version") != 3:
        raise ValueError("unsupported routing contract; version 3 is required")
    phases = routing.get("phases")
    if not isinstance(phases, dict):
        raise ValueError("routing phases must be a mapping")
    for entry in phases.values():
        if not isinstance(entry, dict) or not isinstance(entry.get("fallbacks", []), list):
            raise ValueError("phase routes and fallbacks must be structured mappings")
        for route in (entry, *entry.get("fallbacks", [])):
            _validate_phase_identity(route)
    for review in routing.get("reviews", []):
        phase = str(review.get("phase"))
        if review != {"phase": phase, "route_ref": phase} or phase not in phases:
            raise ValueError("review declarations must reference the authoritative phase")
    independence = routing.get("independence", {})
    for phase, slot in independence.get("adversarial_slots", {}).items():
        if slot != {"route_ref": phase} or phase not in phases:
            raise ValueError("independence slots must reference the authoritative phase")
    if "author_failover" in independence:
        raise ValueError("duplicate author_failover policy is forbidden")
    for rule in independence.get("author_failover_by_model", {}).values():
        if rule.get("or_stop") is not True:
            raise ValueError("author remapping must stop when independence is unavailable")
        for phase, route in rule.get("remap", {}).items():
            _validate_phase_identity(route)
            if phase not in REVIEW_PHASES or not all(route.get(k) for k in ("provider", "model", "effort")):
                raise ValueError("author remap requires an explicit review provider/model/effort")


def _validate_phase_identity(route: dict[str, Any]) -> None:
    if not isinstance(route, dict) or route.get("provider") not in PHASE_PROVIDERS:
        raise ValueError("unsupported phase provider; executable route must be explicit")
    if not isinstance(route.get("model"), str) or not route["model"].strip():
        raise ValueError("phase model must be explicit")


def resolve_phase_route(
    routing: dict[str, Any],
    phase: str,
    *,
    fallback_reason: str | None = None,
    use_fallback_index: int | None = None,
    author_routes: tuple[RoutingRecord, ...] | None = None,
    prior_review_routes: tuple[RoutingRecord, ...] = (),
    available_routes: frozenset[tuple[str, str]] | None = None,
    allow_optional_review: bool = False,
) -> RoutingRecord:
    """Select a route, never execute it or retry a rejected review.

    Reviews require actual author records and an explicit qualified availability
    inventory supplied by the caller. Include prior required review records to
    enforce distinct families across those seats. This API does not manufacture
    availability, spending approval, history provenance, or a Gateway binding.
    """
    validate_routing_policy(routing)
    phases = routing.get("phases")
    if not isinstance(phases, dict) or phase not in phases:
        raise ValueError(f"unknown routing phase: {phase}")
    entry = phases[phase]
    if not isinstance(entry, dict):
        raise ValueError(f"phase {phase} must be a mapping")
    if entry.get("enabled") is False:
        raise IndependentReviewBlocked(f"phase {phase}: disabled route")
    if phase in REVIEW_PHASES:
        if entry.get("invoke_by_default") is False and not allow_optional_review:
            raise IndependentReviewBlocked(f"phase {phase}: optional review requires explicit invocation")
        return _resolve_review(
            routing, phase, entry, author_routes, prior_review_routes,
            available_routes, use_fallback_index, fallback_reason,
        )

    provider = entry.get("provider")
    model = entry.get("model")
    effort = entry.get("effort")
    if not isinstance(provider, str) or not isinstance(model, str):
        raise ValueError(f"phase {phase} requires provider and model")

    if use_fallback_index is not None:
        fallbacks = entry.get("fallbacks")
        if not isinstance(fallbacks, list) or use_fallback_index < 0 or use_fallback_index >= len(fallbacks):
            raise ValueError(f"fallback index unavailable for phase {phase}")
        selected = fallbacks[use_fallback_index]
        if not isinstance(selected, dict):
            raise ValueError("fallback entry must be a mapping")
        provider = selected.get("provider", provider)
        model = selected.get("model", model)
        if selected.get("effort") not in (None, ""):
            effort = selected.get("effort")
        if fallback_reason is None:
            fallback_reason = selected.get("reason") or "configured-fallback"

    return RoutingRecord(
        phase=phase,
        role=str(entry.get("role", phase)),
        provider=provider,
        model=model,
        harness=_harness_for_provider(provider),
        account_class=_account_class_for_provider(provider),
        effort=str(effort or "default"),
        fallback_reason=fallback_reason or "none",
    )


def _resolve_review(
    routing: dict[str, Any], phase: str, entry: dict[str, Any],
    authors: tuple[RoutingRecord, ...] | None,
    prior_reviews: tuple[RoutingRecord, ...],
    available: frozenset[tuple[str, str]] | None,
    fallback_index: int | None, fallback_reason: str | None,
) -> RoutingRecord:
    # These must be actual persisted execution identities, not planned authors.
    if not authors:
        raise IndependentReviewBlocked(f"phase {phase}: actual author history required")
    if available is None:
        raise IndependentReviewBlocked(f"phase {phase}: qualified reviewer availability required")
    order = routing.get("review_sequence", {}).get("required_order", [])
    if phase in order and order.index(phase) > 0:
        previous = order[order.index(phase) - 1]
        completed = [route for route in prior_reviews if route.phase == previous]
        if len(completed) != 1 or not review_sequence_allows_next(routing, previous, completed[0].verdict, phase):
            raise IndependentReviewBlocked(f"phase {phase}: passing prior review required (one completed {previous} verdict)")
    forbidden = set()
    for route in (*authors, *prior_reviews):
        if not route.provider or not route.model:
            raise IndependentReviewBlocked(f"phase {phase}: incomplete execution identity")
        try:
            forbidden.add(model_family(route.model))
        except ValueError as exc:
            raise IndependentReviewBlocked(f"phase {phase}: unknown execution model family") from exc
    candidates: list[tuple[dict[str, Any], str]] = []
    if fallback_index is not None:
        fallbacks = entry.get("fallbacks", [])
        if fallback_index < 0 or fallback_index >= len(fallbacks):
            raise ValueError(f"fallback index unavailable for phase {phase}")
        candidates.append((fallbacks[fallback_index], "configured-fallback"))
    else:
        rules = routing.get("independence", {}).get("author_failover_by_model", {})
        # Stable policy order, independent of the caller's author-history order.
        for model, rule in rules.items():
            if any(canonical_model(author.model) == canonical_model(model) for author in authors):
                remap = rule.get("remap", {}).get(phase)
                if remap:
                    candidates.append((remap, "author-independence-remap"))
        candidates.append((entry, "none"))
        candidates.extend((item, "independence-or-availability-fallback") for item in entry.get("fallbacks", []))
    for candidate, reason in candidates:
        provider, model = candidate.get("provider"), candidate.get("model")
        if not isinstance(provider, str) or not provider or not isinstance(model, str) or not model:
            raise IndependentReviewBlocked(f"phase {phase}: incomplete configured review identity")
        try:
            family = model_family(model)
        except ValueError as exc:
            raise IndependentReviewBlocked(f"phase {phase}: unknown configured review model family") from exc
        if family in forbidden or (available is not None and (provider, model) not in available):
            continue
        if provider == "anthropic" or (family == "anthropic" and phase != "1.8"):
            continue
        return RoutingRecord(
            phase=phase, role=str(entry.get("role", phase)), provider=provider,
            model=model, harness=_harness_for_provider(provider),
            account_class=_account_class_for_provider(provider),
            effort=str(candidate.get("effort") or entry.get("effort") or "default"),
            fallback_reason=fallback_reason or candidate.get("reason") or reason,
        )
    raise IndependentReviewBlocked(f"phase {phase}: no eligible independent reviewer available")


def build_routing_records(
    routing: dict[str, Any],
    phases: tuple[str, ...] = MANAGER_REVIEW_CODE_PHASES,
    *,
    author_routes: tuple[RoutingRecord, ...] | None = None,
    prior_review_routes: tuple[RoutingRecord, ...] = (),
    available_routes: frozenset[tuple[str, str]] | None = None,
) -> list[RoutingRecord]:
    # Plans are NOT completed reviews. Never manufacture a passing verdict or
    # accumulate planned records as if their adapters had run successfully.
    return [resolve_phase_route(
        routing, phase, author_routes=author_routes,
        prior_review_routes=prior_review_routes, available_routes=available_routes,
    ) for phase in phases]


def authorize_task_review(
    routing: dict[str, Any], author_identity: tuple[str, str], reviewer_identity: tuple[str, str],
) -> RoutingRecord:
    """Gate an explicitly authorized worker pair; never select another adapter.

    Inventory is the single registered/preflighted reviewer the task authorized,
    not every model mentioned by YAML. Provider/transport must match exactly;
    model aliases are normalized only within that provider. The real executor
    supplies author identity, never a workstream's claimed author metadata.
    """
    provider, model = author_identity
    author = RoutingRecord("3A", "actual-task-executor", provider, model,
                           _harness_for_provider(provider), _account_class_for_provider(provider), None, None)
    entries = [routing["phases"]["4"], *routing["phases"]["4"].get("fallbacks", [])]
    entries += [rule["remap"]["4"] for rule in routing.get("independence", {}).get("author_failover_by_model", {}).values() if "4" in rule.get("remap", {})]
    available = frozenset((item["provider"], item["model"]) for item in entries
                          if item["provider"] == reviewer_identity[0]
                          and canonical_model(item["model"]) == canonical_model(reviewer_identity[1]))
    return resolve_phase_route(routing, "4", author_routes=(author,), available_routes=available)


def authorize_delivery_review(routing, author_identity, reviewer_identity, *, profile="gateway-delivery-disposable-file.v1"):
    """Explicit bounded-profile transport policy; no OpenRouter alias/fallback."""
    from copy import deepcopy
    profile = routing.get("delivery_profiles", {}).get(profile)
    if not isinstance(profile, dict) or profile.get("automatic_retries") != 0:
        raise IndependentReviewBlocked("bounded delivery profile is not authorized")
    policy = deepcopy(routing)
    policy["phases"]["4"] = profile["review"]
    # No legacy phase remap may introduce a different transport for this profile.
    policy["independence"]["author_failover_by_model"] = {}
    if profile["review"].get("fallbacks"):
        raise IndependentReviewBlocked("bounded delivery fallbacks are forbidden")
    return authorize_task_review(policy, author_identity, reviewer_identity)


def validate_routing_records(records: list[RoutingRecord]) -> None:
    for record in records:
        payload = record.to_dict()
        missing = [field for field in ROUTING_RECORD_FIELDS if payload.get(field) in (None, "")]
        if missing:
            raise ValueError(f"routing record missing fields: {', '.join(missing)}")


def write_routing_record_artifact(path: Path, records: list[RoutingRecord]) -> str:
    payload = {"records": [record.to_dict() for record in records]}
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.write_text(encoded)
    return encoded
