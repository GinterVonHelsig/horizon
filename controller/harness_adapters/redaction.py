"""Recursive credential-shaped redaction and validation helpers."""

from __future__ import annotations

import re
from typing import Any

ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_CREDENTIAL_KEY_RE = re.compile(
    r"(?:^|[_-])(api[_-]?key|token|password|secret|authorization|bearer)(?:$|[_-])",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(
    r'''(?i)(["']?(?:api[_-]?key|token|password|secret|authorization|bearer)["']?\s*[:=]\s*)(["']?)([^\s,;"'}]+)(["']?)'''
)
_BEARER_RE = re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+")
_SK_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")


def validate_env_name(name: str) -> str:
    if not isinstance(name, str) or not ENV_NAME_RE.fullmatch(name):
        raise ValueError("invalid environment-variable name")
    return name


def redact_text(text: str, *, extra_values: tuple[str, ...] = ()) -> str:
    redacted = str(text)
    redacted = _TOKEN_RE.sub(lambda match: f'{match.group(1)}{match.group(2)}[REDACTED]{match.group(4)}', redacted)
    for pattern in (_BEARER_RE, _SK_RE):
        redacted = pattern.sub("[REDACTED]", redacted)
    for value in sorted((v for v in extra_values if v), key=len, reverse=True):
        redacted = redacted.replace(value, "[REDACTED]")
    return redacted


def sanitize_value(value: Any, *, extra_values: tuple[str, ...] = ()) -> Any:
    """Return a JSON-safe recursively redacted copy."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, nested in value.items():
            key_text = str(key)
            sanitized[key_text] = (
                "[REDACTED]"
                if _CREDENTIAL_KEY_RE.search(key_text)
                else sanitize_value(nested, extra_values=extra_values)
            )
        return sanitized
    if isinstance(value, (list, tuple)):
        return [sanitize_value(item, extra_values=extra_values) for item in value]
    if isinstance(value, str):
        return redact_text(value, extra_values=extra_values)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value), extra_values=extra_values)


def contains_credential(value: Any) -> bool:
    """Detect credential keys or values recursively in operator configuration."""
    if isinstance(value, dict):
        for key, nested in value.items():
            if _CREDENTIAL_KEY_RE.search(str(key)):
                return True
            if contains_credential(nested):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(contains_credential(item) for item in value)
    if isinstance(value, str):
        return redact_text(value) != value
    return False
