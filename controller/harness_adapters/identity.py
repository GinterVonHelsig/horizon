"""Effective adapter identity is normalized (provider, model), not adapter id.

provider is the configured gateway/vendor label from adapter config. It is not
inferred from transport kind. model is the configured model id. OpenRouter
routing-variant suffixes after ':' are stripped so ``openai/gpt-6-astra`` and
``openai/gpt-6-astra:nitro`` collide. The first ':' is the variant separator;
unknown suffixes collide with the base. HTTP request bodies still send the raw
configured model string. Meta-router ids under the ``openrouter/`` vendor prefix,
including ``openrouter/auto``, are forbidden. Incomplete identity (missing or
empty after normalize) is not independence: callers must fail closed.

Provider remains part of identity: the same model through two different
provider labels is still two lanes unless a later operator envelope chooses
otherwise. TaskRoutingSnapshot is ID-only and is not evidence of lane
independence.
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
    return left == right


def identity_is_forbidden(identity: tuple[str, str] | None) -> bool:
    if identity is None:
        return False
    _provider, model = identity
    return (
        model in _FORBIDDEN_MODELS
        or model.startswith("openrouter/")
        or model.endswith("/auto")
    )
