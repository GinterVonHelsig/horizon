"""Tests for model routing records."""

from __future__ import annotations

from pathlib import Path

from model_routing import (
    ROUTING_RECORD_FIELDS,
    build_routing_records,
    load_model_routing,
    resolve_phase_route,
    validate_routing_records,
)


def test_model_routing_yaml_records_required_fields() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    records = build_routing_records(routing, phases=("3A", "4", "5"))
    validate_routing_records(records)
    for record in records:
        payload = record.to_dict()
        for field in ROUTING_RECORD_FIELDS:
            assert payload[field]
        if record.phase == "4":
            assert record.provider == "openrouter"
            assert record.model == "qwen/qwen3.8-max"
            assert record.effort == "xhigh"
            assert record.harness == "openrouter-chat"
            assert record.account_class == "metered-fallback"
        if record.phase == "3A":
            assert record.harness == "cursor-agent"
            assert record.account_class == "subscription"


def test_phases_0_1_2_use_sol_max_openrouter() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    for phase in ("0", "1", "2"):
        record = resolve_phase_route(routing, phase)
        assert record.provider == "openrouter"
        assert record.model == "openai/gpt-5.6-sol"
        assert record.effort == "max"
        assert record.harness == "openrouter-chat"


def test_phase_6_uses_glm_max_not_sol() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    record = resolve_phase_route(routing, "6")
    assert record.provider == "openrouter"
    assert record.model == "z-ai/glm-5.3"
    assert record.effort == "max"


def test_anthropic_is_absent_from_required_routes() -> None:
    routing = load_model_routing(_routing_path())
    for key, entry in routing["phases"].items():
        if key in {"1.7", "1.8", "1.9"}:
            continue
        models = [str(entry.get("model") or "")]
        models.extend(str(item.get("model") or "") for item in (entry.get("fallbacks") or []))
        assert all(not m.startswith("anthropic/") for m in models)
    policy = routing["provider_policy"]
    assert policy.get("denylist") == []
    assert "1.8" in policy.get("conditional_escalation_openrouter_anthropic_seats", [])


def test_fallback_route_records_fallback_reason() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    record = resolve_phase_route(routing, "3A", use_fallback_index=2, fallback_reason="provider-limit")
    assert record.provider == "openrouter"
    assert record.account_class == "metered-fallback"
    assert record.fallback_reason == "provider-limit"


def test_phases_3b_45_75_use_glm_flash_with_gemini_and_glm_fallbacks() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    for phase in ("3B", "4.5", "7.5"):
        primary = resolve_phase_route(routing, phase)
        assert primary.provider == "openrouter"
        assert primary.model == "z-ai/glm-5.3-flash"
        assert primary.effort == "high"
        gemini = resolve_phase_route(
            routing, phase, use_fallback_index=0, fallback_reason="provider-limit"
        )
        assert gemini.model == "google/gemini-3.8-flash"
        assert gemini.effort == "high"
        glm = resolve_phase_route(
            routing, phase, use_fallback_index=1, fallback_reason="provider-limit"
        )
        assert glm.model == "z-ai/glm-5.3"
        assert glm.effort == "max"


def _routing_path() -> Path:
    return Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"


def test_routing_authority_is_tree_under_test_not_current() -> None:
    routing_path = _routing_path()
    current = Path("/opt/top-delivery-p1/current/architecture/model-routing.yaml")
    assert routing_path.resolve() != current.resolve()
    assert "current" not in str(routing_path)


def test_phase_15_and_16_have_independent_fallbacks() -> None:
    routing = load_model_routing(_routing_path())
    p15 = routing["phases"]["1.5"]
    p16 = routing["phases"]["1.6"]
    assert "no_fallback" not in p15
    assert p15["fallbacks"][0]["model"] == "gemini-3.8-flash-high"
    assert p15["fallbacks"][-1]["model"] == "google/gemini-3.8-flash"
    assert p16["fallbacks"][0]["model"] == "cursor-grok-4.6-high"
    assert p16["fallbacks"][-1]["model"] == "x-ai/grok-4.6"
    reviews = {str(item["phase"]): item for item in routing["reviews"]}
    assert reviews["1.5"]["model"] == "moonshotai/kimi-k3"
    assert reviews["1.6"]["model"] == "claude-opus-5-thinking-high"
    p17 = routing["phases"]["1.7"]
    p18 = routing["phases"]["1.8"]
    assert p17.get("invoke_by_default") is False
    assert p18.get("invoke_by_default") is False
    assert p17.get("required") is False
    assert p18.get("required") is False
    assert p17["model"] == "openai/gpt-6-astra"
    assert p17["effort"] == "max"
    assert p18["model"] == "claude-fable-5-1-thinking-high"
    assert p18["effort"] == "high"
    assert p18["provider"] == "cursor"
    assert routing["phases"]["1.9"].get("enabled") is False


def test_default_invoked_routes_have_no_anthropic() -> None:
    routing = load_model_routing(_routing_path())
    models: list[str] = []
    for key, entry in routing["phases"].items():
        if entry.get("enabled") is False or entry.get("invoke_by_default") is False:
            continue
        models.append(str(entry.get("model", "")))
        for item in entry.get("fallbacks") or []:
            models.append(str(item.get("model", "")))
    assert all(not m.startswith("anthropic/") for m in models)
    assert routing["independence"]["author_failover"]["remap"]["1.6"]["model"] == "z-ai/glm-5.3"
