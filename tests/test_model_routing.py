"""Tests for model routing records."""

from __future__ import annotations

from pathlib import Path
from dataclasses import replace

import pytest

from model_routing import (
    ROUTING_RECORD_FIELDS,
    build_routing_records,
    load_model_routing,
    resolve_phase_route as _resolve_phase_route,
    validate_routing_records,
    IndependentReviewBlocked,
    review_sequence_allows_next,
)


def _available(routing):
    """Simulated qualification inventory; this never probes or calls a model."""
    routes = []
    for entry in routing["phases"].values():
        routes.extend([entry, *entry.get("fallbacks", [])])
    for rule in routing["independence"]["author_failover_by_model"].values():
        routes.extend(rule["remap"].values())
    return frozenset((route["provider"], route["model"]) for route in routes)


def resolve_phase_route(routing, phase, **kwargs):
    kwargs.setdefault("available_routes", _available(routing))
    if phase == "1.6" and kwargs.get("author_routes") and "prior_review_routes" not in kwargs:
        first = _resolve_phase_route(routing, "1.5", author_routes=kwargs["author_routes"],
                                     available_routes=_available(routing))
        kwargs["prior_review_routes"] = (first,)
    return _resolve_phase_route(routing, phase, **kwargs)


def _author(routing, phase="3A"):
    return resolve_phase_route(routing, phase)


def test_model_routing_yaml_records_required_fields() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    records = build_routing_records(routing, phases=("3A", "4", "5"),
                                    author_routes=(_author(routing),), available_routes=_available(routing))
    validate_routing_records(records)
    for record in records:
        payload = record.to_dict()
        for field in ROUTING_RECORD_FIELDS:
            assert payload[field]
        if record.phase == "4":
            assert record.provider == "openai"
            assert record.model == "gpt-6-astra"
            assert record.effort == "high"
            assert record.harness == "openai"
            assert record.account_class == "subscription"
        if record.phase == "3A":
            assert record.harness == "cursor-agent"
            assert record.account_class == "subscription"


def test_phases_0_1_2_use_september_assignments() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    for phase in ("0", "1", "2"):
        record = resolve_phase_route(routing, phase)
        assert record.provider == "openai"
        assert record.model == ("gpt-5.6-sol" if phase == "0" else "gpt-6-astra")
        assert record.effort == ("max" if phase == "0" else "high")
        assert record.harness == "openai"


def test_phase_6_uses_september_primary_for_independent_author() -> None:
    routing_path = Path(__file__).resolve().parents[1] / "architecture" / "model-routing.yaml"
    routing = load_model_routing(routing_path)
    record = resolve_phase_route(routing, "6", author_routes=(_author(routing),))
    assert record.provider == "openai"
    assert record.model == "gpt-6-astra"
    assert record.effort == "high"


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
    assert record.provider == "openai"
    assert record.model == "gpt-5.6-luna"
    assert record.account_class == "subscription"
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
    assert p16["fallbacks"][0]["model"] == "x-ai/grok-4.6"
    assert p16["fallbacks"][-1]["model"] == "z-ai/glm-5.3"
    reviews = {str(item["phase"]): item for item in routing["reviews"]}
    assert reviews["1.5"] == {"phase": "1.5", "route_ref": "1.5"}
    assert reviews["1.6"] == {"phase": "1.6", "route_ref": "1.6"}
    assert p15["model"] == "gpt-5.6-sol"
    assert p16["model"] == "gpt-6-astra"
    assert p16["effort"] == "high"
    p17 = routing["phases"]["1.7"]
    p18 = routing["phases"]["1.8"]
    assert p17.get("invoke_by_default") is False
    assert p18.get("invoke_by_default") is False
    assert p17.get("required") is False
    assert p18.get("required") is False
    assert p17["provider"] == "openai"
    assert p17["model"] == "gpt-6-astra"
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
    assert routing["independence"]["author_failover_by_model"]["x-ai/grok-4.6"]["remap"]["1.6"]["model"] == "z-ai/glm-5.3"


@pytest.mark.parametrize("phase", ["1.5", "1.6", "4", "6"])
def test_reviews_require_actual_author_history(phase):
    routing = load_model_routing(_routing_path())
    with pytest.raises(IndependentReviewBlocked, match="actual author history"):
        resolve_phase_route(routing, phase)


def test_review_without_qualified_availability_stops():
    routing = load_model_routing(_routing_path())
    with pytest.raises(IndependentReviewBlocked, match="qualified reviewer availability"):
        _resolve_phase_route(routing, "4", author_routes=(_author(routing),))


def test_second_required_review_requires_first_seat_identity():
    routing = load_model_routing(_routing_path())
    with pytest.raises(IndependentReviewBlocked, match="prior required review history"):
        _resolve_phase_route(routing, "1.6", author_routes=(_author(routing, "1"),),
                             available_routes=_available(routing))


def test_old_routing_contract_is_explicitly_rejected():
    routing = load_model_routing(_routing_path())
    routing["version"] = 2
    with pytest.raises(ValueError, match="unsupported routing contract"):
        resolve_phase_route(routing, "3A")


def test_unknown_provider_is_rejected_even_when_claimed_available():
    routing = load_model_routing(_routing_path())
    author = _author(routing)
    routing["phases"]["4"]["provider"] = "missing-adapter-provider"
    with pytest.raises(ValueError, match="unsupported phase provider"):
        resolve_phase_route(routing, "4", author_routes=(author,))


@pytest.mark.parametrize("verdict", ["reject", "reject_with_critical", "transport_failure", "timeout", "malformed_structured_output"])
def test_failed_review_cannot_advance_required_sequence(verdict):
    routing = load_model_routing(_routing_path())
    assert not review_sequence_allows_next(routing, "1.5", verdict, "1.6")
    assert review_sequence_allows_next(routing, "1.5", "pass", "1.6")


def test_grok_and_astra_authors_cannot_be_selected_by_competing_remaps():
    routing = load_model_routing(_routing_path())
    authors = (_author(routing, "1"), resolve_phase_route(routing, "1", use_fallback_index=0))
    for history in (authors, tuple(reversed(authors))):
        record = resolve_phase_route(routing, "1.6", author_routes=history)
        assert record.model == "z-ai/glm-5.3"


def test_batch_selection_cannot_bypass_missing_history():
    routing = load_model_routing(_routing_path())
    with pytest.raises(IndependentReviewBlocked, match="author history"):
        build_routing_records(routing, available_routes=_available(routing))


@pytest.mark.parametrize("phase,model", [("1.6", "x-ai/grok-4.6"), ("4", "qwen/qwen3.8-max"), ("6", "z-ai/glm-5.3")])
@pytest.mark.parametrize("alias", ["gpt-6-astra", "openai/gpt-6-astra:nitro", "gpt-6-astra-high"])
def test_astra_author_is_remapped_across_transport_and_effort(phase, model, alias):
    routing = load_model_routing(_routing_path())
    author = replace(_author(routing, "1"), provider="cursor", model=alias)
    selected = resolve_phase_route(routing, phase, author_routes=(author,))
    assert selected.model == model
    assert selected.provider == "openrouter"
    assert selected.fallback_reason == "author-independence-remap"


def test_independent_families_and_previous_required_seat():
    routing = load_model_routing(_routing_path())
    authors = tuple(_author(routing, phase) for phase in ("0", "1", "2", "3A"))
    first = resolve_phase_route(routing, "1.5", author_routes=authors)
    assert first.model == "gemini-3.8-flash-high"  # Sol cannot review an OpenAI author.
    second = resolve_phase_route(routing, "1.6", author_routes=authors, prior_review_routes=(first,))
    assert second.model == "x-ai/grok-4.6"
    # Availability cannot authorize a conflicting author or reuse a review family.
    with pytest.raises(IndependentReviewBlocked, match="no eligible"):
        resolve_phase_route(routing, "1.6", author_routes=authors,
                            prior_review_routes=(first, second),
                            available_routes=frozenset({("openrouter", "x-ai/grok-4.6")}))


def test_unavailable_remap_uses_only_eligible_configured_route_or_stops():
    routing = load_model_routing(_routing_path())
    authors = (_author(routing, "1"),)
    selected = resolve_phase_route(routing, "1.6", author_routes=authors,
                                  available_routes=frozenset({("openrouter", "z-ai/glm-5.3")}),
                                  fallback_reason="qualified-route-unavailable")
    assert selected.model == "z-ai/glm-5.3"
    assert selected.fallback_reason == "qualified-route-unavailable"
    for available in (frozenset(), frozenset({("openai", "gpt-6-astra")})):
        with pytest.raises(IndependentReviewBlocked, match="no eligible"):
            resolve_phase_route(routing, "1.6", author_routes=authors, available_routes=available)


def test_explicit_fallback_cannot_bypass_author_independence():
    routing = load_model_routing(_routing_path())
    grok = resolve_phase_route(routing, "1", use_fallback_index=0)
    with pytest.raises(IndependentReviewBlocked, match="no eligible"):
        resolve_phase_route(routing, "4", author_routes=(grok,), use_fallback_index=0)
    with pytest.raises(ValueError, match="fallback index"):
        resolve_phase_route(routing, "3A", use_fallback_index=-1)


def test_unknown_history_and_optional_or_disabled_seats_stop():
    routing = load_model_routing(_routing_path())
    author = _author(routing)
    with pytest.raises(IndependentReviewBlocked, match="unknown execution model"):
        resolve_phase_route(routing, "4", author_routes=(replace(author, model="unknown"),))
    with pytest.raises(IndependentReviewBlocked, match="optional review"):
        resolve_phase_route(routing, "1.7", author_routes=(author,))
    assert resolve_phase_route(routing, "1.7", author_routes=(author,), allow_optional_review=True).model == "gpt-6-astra"
    with pytest.raises(IndependentReviewBlocked, match="disabled"):
        resolve_phase_route(routing, "1.9", author_routes=(author,), allow_optional_review=True)


@pytest.mark.parametrize("mutation", ["review", "slot", "stop"])
def test_contradictory_policy_is_rejected_before_selection(mutation):
    routing = load_model_routing(_routing_path())
    if mutation == "review":
        routing["reviews"][0]["model"] = "moonshotai/kimi-k3"
    elif mutation == "slot":
        routing["independence"]["adversarial_slots"]["1.6"]["effort"] = "medium"
    else:
        routing["independence"]["author_failover_by_model"]["openai/gpt-6-astra"]["or_stop"] = False
    with pytest.raises(ValueError):
        resolve_phase_route(routing, "3A")
