"""Effective adapter identity is normalized (provider, model), not adapter id.

provider is the configured gateway/vendor label from adapter config. It is not
inferred from transport kind. model is the configured model id. OpenRouter
routing-variant suffixes after ':' are stripped so ``openai/gpt-6-astra`` and
``openai/gpt-6-astra:nitro`` collide. The first ':' is the variant separator;
unknown suffixes collide with the base. HTTP request bodies still send the raw
configured model string. Meta-router ids under the ``openrouter/`` vendor prefix,
including ``openrouter/auto``, are forbidden. Incomplete identity (missing or
empty after normalize) is not independence: callers must fail closed.

Provider records transport provenance, not independence. The September routing
continuation forbids the same model through different transports from reviewing
itself. TaskRoutingSnapshot is ID-only, not evidence of lane independence.
"""

from __future__ import annotations

import unicodedata
from typing import Any

_FORBIDDEN_MODELS = frozenset({"auto", "openrouter/auto", "openrouter/auto-router"})


def normalize_identity_part(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return unicodedata.normalize("NFKC", value).strip().casefold()


def normalize_model_part(value: Any) -> str:
    text = normalize_identity_part(value)
    if ":" in text:
        text = text.split(":", 1)[0]
    return text


def config_effective_identity(raw: dict[str, Any]) -> tuple[str, str] | None:
    provider = normalize_identity_part(raw.get("provider"))
    model = normalize_model_part(raw.get("model"))
    if not provider or not model:
        return None
    return (provider, model)


def adapter_effective_identity(adapter: Any) -> tuple[str, str] | None:
    return config_effective_identity(
        {
            "provider": getattr(adapter, "provider", None),
            "model": getattr(adapter, "model", None),
        }
    )


def identities_conflict(
    left: tuple[str, str] | None,
    right: tuple[str, str] | None,
) -> bool:
    if left is None or right is None:
        raise ValueError("identities must be complete")
    if canonical_model(left[1]) == canonical_model(right[1]):
        return True
    try:
        return model_family(left[1]) == model_family(right[1])
    except ValueError:
        # Non-policy adapters (including deterministic test adapters) can have
        # opaque identities. Phase review selection separately rejects unknown
        # families, rather than treating this result as qualification evidence.
        return False


def canonical_model(model: str) -> str:
    """Collapse known transport aliases and effort suffixes, never infer a lane."""
    value = normalize_model_part(model)
    if "/" in value:
        vendor, name = value.split("/", 1)
        if vendor in {"openai", "x-ai", "z-ai", "google", "qwen", "moonshotai", "deepseek", "anthropic"}:
            value = name
    if value.startswith("cursor-"):
        value = value[len("cursor-"):]
    for suffix in ("-thinking-high", "-xhigh", "-medium", "-high", "-max"):
        # 'max' is part of Qwen's model identity, not an effort alias.
        if value.endswith(suffix) and not value.startswith("qwen"):
            value = value[:-len(suffix)]
            break
    return value


def model_family(model: str) -> str:
    """Known upstream families for policy review seats; unknown means blocked."""
    value = canonical_model(model)
    for prefix, family in (
        ("gpt-", "openai"), ("grok-", "x-ai"), ("glm-", "z-ai"),
        ("gemini-", "google"), ("qwen", "qwen"), ("kimi-", "moonshotai"),
        ("deepseek-", "deepseek"), ("claude-", "anthropic"), ("composer-", "cursor"),
    ):
        if value.startswith(prefix):
            return family
    raise ValueError("unknown model family; independent review cannot be established")


def identity_is_forbidden(identity: tuple[str, str] | None) -> bool:
    if identity is None:
        return False
    _provider, model = identity
    return (
        model in _FORBIDDEN_MODELS
        or model.startswith("openrouter/")
        or model.endswith("/auto")
    )
