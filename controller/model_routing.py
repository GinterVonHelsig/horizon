"""Model routing authority with explicit harness and account-class records."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROUTING_RECORD_FIELDS = (
    "model",
    "harness",
    "account_class",
    "effort",
    "fallback_reason",
)

MANAGER_REVIEW_CODE_PHASES = ("0", "1", "2", "3A", "4", "5", "6", "7")


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
    return payload


def resolve_phase_route(
    routing: dict[str, Any],
    phase: str,
    *,
    fallback_reason: str | None = None,
    use_fallback_index: int | None = None,
) -> RoutingRecord:
    phases = routing.get("phases")
    if not isinstance(phases, dict) or phase not in phases:
        raise ValueError(f"unknown routing phase: {phase}")
    entry = phases[phase]
    if not isinstance(entry, dict):
        raise ValueError(f"phase {phase} must be a mapping")

    provider = entry.get("provider")
    model = entry.get("model")
    effort = entry.get("effort")
    if not isinstance(provider, str) or not isinstance(model, str):
        raise ValueError(f"phase {phase} requires provider and model")

    if use_fallback_index is not None:
        fallbacks = entry.get("fallbacks")
        if not isinstance(fallbacks, list) or use_fallback_index >= len(fallbacks):
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


def build_routing_records(
    routing: dict[str, Any],
    phases: tuple[str, ...] = MANAGER_REVIEW_CODE_PHASES,
) -> list[RoutingRecord]:
    return [resolve_phase_route(routing, phase) for phase in phases]


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
