"""Strict deterministic adapter registry and JSON configuration loader."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness_adapters.cli_adapters import cli_adapter_from_config
from harness_adapters.contract import HarnessAdapter
from harness_adapters.executable_policy import resolve_trusted_executable
from harness_adapters.http_adapters import HttpOpenAIAdapter, is_allowed_endpoint, is_loopback_endpoint
from harness_adapters.identity import (
    config_effective_identity,
    identities_conflict,
    identity_is_forbidden,
    normalize_identity_part,
    normalize_model_part,
)
from harness_adapters.redaction import contains_credential, validate_env_name

_KINDS = frozenset({"codex_cli", "cursor_cli", "claude_cli", "pi_cli", "http_openai", "gateway_delivery"})
_COMMON = frozenset({
    "id", "kind", "provider", "model", "credential_env", "timeout_seconds",
    "allowed_cwd_roots", "artifact_output_limit", "inline_output_limit",
})
_KIND_KEYS = {
    "codex_cli": frozenset({"executable", "codex_home", "allowlisted_env"}),
    "cursor_cli": frozenset({"executable", "approval_mode", "worktree", "allowlisted_env", "cursor_mode"}),
    "gateway_delivery": frozenset({"executable", "approval_mode", "allowlisted_env", "delivery_spec", "subscription_only", "on_demand_disabled"}),
    "claude_cli": frozenset({"executable", "permission_mode", "allowlisted_env"}),
    "pi_cli": frozenset({"executable", "endpoint", "allowlisted_env"}),
    "http_openai": frozenset({
        "endpoint", "allowed_hosts", "response_byte_limit", "request_byte_limit",
        "reasoning_effort", "loopback_only",
    }),
}
_ROUTE_KEYS = frozenset({"default_executor", "default_auditor"})


def validate_task_routes(config: dict[str, Any], executor: str, auditor: str) -> None:
    """Validate the selected pair, including identity and execution capability."""
    ids = {item.get("id") for item in config.get("adapters", [])}
    missing = sorted({executor, auditor} - ids)
    if missing:
        raise ValueError("missing adapter configuration: " + ", ".join(missing))
    selected = {**config, "routes": {"default_executor": executor, "default_auditor": auditor}}
    validate_registry_config(selected, validate_executables=False)
    writer = next(item for item in config["adapters"] if item["id"] == executor)
    if writer["kind"] == "http_openai":
        raise ValueError("executor requires workspace execution capability; HTTP completion is review-only")
    if writer["kind"] == "gateway_delivery":
        reviewer = next(item for item in config["adapters"] if item["id"] == auditor)
        if reviewer["kind"] != "cursor_cli" or reviewer["provider"] != "cursor" or reviewer.get("cursor_mode") != "ask" or auditor != "cursor-independent-review":
            raise ValueError("bounded delivery requires explicit read-only cursor-independent-review")


def load_registry_config(path: Path, *, validate_executables: bool = True) -> dict[str, Any]:
    config = json.loads(path.read_text())
    validate_registry_config(config, validate_executables=validate_executables)
    return config


def _require_type(value: Any, expected: type, label: str) -> None:
    if not isinstance(value, expected):
        raise ValueError(f"{label} has invalid type")


def validate_registry_config(config: dict[str, Any], *, validate_executables: bool = True) -> None:
    _require_type(config, dict, "registry config")
    unknown = set(config) - {"adapters", "routes"}
    if unknown:
        raise ValueError(f"unknown registry keys: {sorted(unknown)}")
    adapters = config.get("adapters")
    routes = config.get("routes")
    _require_type(adapters, list, "adapters")
    _require_type(routes, dict, "routes")
    route_unknown = set(routes) - _ROUTE_KEYS
    if route_unknown:
        raise ValueError(f"unknown route keys: {sorted(route_unknown)}")
    if set(routes) != _ROUTE_KEYS or not all(isinstance(routes[key], str) and routes[key] for key in _ROUTE_KEYS):
        raise ValueError("routes require non-empty default executor and auditor ids")
    if routes["default_executor"] == routes["default_auditor"]:
        raise ValueError("executor and auditor must use distinct adapter ids")
    ids: set[str] = set()
    for raw in adapters:
        _require_type(raw, dict, "adapter")
        kind = raw.get("kind")
        if kind not in _KINDS:
            raise ValueError(f"unknown adapter kind: {kind}")
        unknown_keys = set(raw) - _COMMON - _KIND_KEYS[kind]
        if unknown_keys:
            raise ValueError(f"unknown adapter keys: {sorted(unknown_keys)}")
        required = {"id", "kind", "provider", "model", "credential_env", "timeout_seconds", "allowed_cwd_roots"}
        missing = required - set(raw)
        if missing:
            raise ValueError(f"missing adapter keys: {sorted(missing)}")
        adapter_id = raw["id"]
        if not isinstance(adapter_id, str) or not adapter_id or adapter_id in ids:
            raise ValueError("duplicate or invalid adapter id")
        ids.add(adapter_id)
        if not isinstance(raw["model"], str) or not normalize_model_part(raw["model"]):
            raise ValueError("adapter model is required")
        if not isinstance(raw["provider"], str) or not normalize_identity_part(raw["provider"]):
            raise ValueError("adapter provider identity is required")
        identity = config_effective_identity(raw)
        if identity_is_forbidden(identity):
            raise ValueError("meta-router models are forbidden")
        if not isinstance(raw["timeout_seconds"], (int, float)) or isinstance(raw["timeout_seconds"], bool) or raw["timeout_seconds"] <= 0:
            raise ValueError("timeout_seconds must be positive")
        roots = raw["allowed_cwd_roots"]
        if not isinstance(roots, list) or not roots or not all(isinstance(root, str) and Path(root).is_absolute() for root in roots):
            raise ValueError("allowed cwd roots must be non-empty absolute paths")
        credentials = raw["credential_env"]
        if not isinstance(credentials, list):
            raise ValueError("credential_env must be an array")
        for name in credentials:
            validate_env_name(name)
        if kind == "http_openai" and len(credentials) != 1:
            raise ValueError("http adapter requires exactly one credential environment name")
        if contains_credential({key: value for key, value in raw.items() if key != "credential_env"}):
            raise ValueError("credential values are forbidden in adapter config")
        if kind == "http_openai":
            endpoint = raw.get("endpoint")
            allowed_hosts = raw.get("allowed_hosts", [])
            if not isinstance(allowed_hosts, list) or not all(isinstance(host, str) and host for host in allowed_hosts):
                raise ValueError("allowed_hosts must be a string array")
            if not isinstance(endpoint, str) or not is_allowed_endpoint(endpoint, allowed_hosts=tuple(allowed_hosts)):
                raise ValueError("endpoint is not allowlisted")
            if raw.get("loopback_only") not in {None, True, False}:
                raise ValueError("loopback_only must be a boolean")
            if raw.get("loopback_only") is True and not is_loopback_endpoint(endpoint):
                raise ValueError("endpoint is not a loopback relay")
            if "reasoning_effort" in raw and raw["reasoning_effort"] != "max":
                raise ValueError("reasoning_effort must be max")
            if "request_byte_limit" in raw and (
                not isinstance(raw["request_byte_limit"], int)
                or isinstance(raw["request_byte_limit"], bool)
                or raw["request_byte_limit"] <= 0
            ):
                raise ValueError("request_byte_limit must be a positive integer")
            if "response_byte_limit" in raw and (
                not isinstance(raw["response_byte_limit"], int)
                or isinstance(raw["response_byte_limit"], bool)
                or raw["response_byte_limit"] <= 0
            ):
                raise ValueError("response_byte_limit must be a positive integer")
        for limit_key in ("artifact_output_limit", "inline_output_limit"):
            if limit_key in raw and (
                not isinstance(raw[limit_key], int)
                or isinstance(raw[limit_key], bool)
                or raw[limit_key] <= 0
            ):
                raise ValueError(f"{limit_key} must be a positive integer")
        if kind != "http_openai":
            executable = raw.get("executable")
            if not isinstance(executable, str) or not Path(executable).is_absolute():
                raise ValueError("executable must be an absolute path")
            if validate_executables:
                resolve_trusted_executable(str(executable))
            if kind == "codex_cli" and (not isinstance(raw.get("codex_home"), str) or not Path(raw["codex_home"]).is_absolute()):
                raise ValueError("codex_home must be absolute")
            if kind in {"cursor_cli", "gateway_delivery"} and raw.get("approval_mode") not in {"never", "approve_mcps"}:
                raise ValueError("invalid cursor approval_mode")
            if kind == "cursor_cli" and raw.get("cursor_mode") not in {None, "agent", "ask"}:
                raise ValueError("invalid cursor_mode")
            if kind == "gateway_delivery":
                from bounded_delivery import validate_spec
                validate_spec(raw.get("delivery_spec"))
                if raw["id"] != "gateway-delivery-disposable-file" or raw["provider"] != "cursor" or raw.get("subscription_only") is not True or raw.get("on_demand_disabled") is not True:
                    raise ValueError("bounded delivery requires explicit Cursor included-subscription authorization")
            if kind == "claude_cli" and not isinstance(raw.get("permission_mode"), str):
                raise ValueError("claude permission_mode is required")
    if routes["default_executor"] not in ids or routes["default_auditor"] not in ids:
        raise ValueError("route adapter ids must exist in adapters")
    by_id = {raw["id"]: raw for raw in adapters}
    executor_identity = config_effective_identity(by_id[routes["default_executor"]])
    auditor_identity = config_effective_identity(by_id[routes["default_auditor"]])
    if executor_identity is None or auditor_identity is None:
        raise ValueError("executor and auditor identities are incomplete")
    if identity_is_forbidden(executor_identity) or identity_is_forbidden(auditor_identity):
        raise ValueError("meta-router models are forbidden for executor and auditor")
    if identities_conflict(executor_identity, auditor_identity):
        raise ValueError("executor and auditor must use distinct effective identities")


@dataclass
class AdapterRegistry:
    adapters: dict[str, HarnessAdapter]
    default_executor: str
    default_auditor: str

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any],
        *,
        artifact_dir: Path,
        validate_executables: bool = True,
    ) -> "AdapterRegistry":
        validate_registry_config(config, validate_executables=validate_executables)
        adapters: dict[str, HarnessAdapter] = {}
        for raw in config["adapters"]:
            adapter_id = raw["id"]
            if raw["kind"] == "gateway_delivery":
                from bounded_delivery import BoundedDeliveryAdapter
                inner = cli_adapter_from_config(adapter_id, {**raw, "kind": "cursor_cli", "cursor_mode": "agent"}, artifact_dir / adapter_id)
                adapters[adapter_id] = BoundedDeliveryAdapter(inner, raw["delivery_spec"])
            elif raw["kind"] == "http_openai":
                adapters[adapter_id] = HttpOpenAIAdapter(
                    adapter_id=adapter_id, endpoint=raw["endpoint"], model=raw["model"],
                    credential_env=raw["credential_env"][0], artifact_dir=artifact_dir / adapter_id,
                    timeout_seconds=float(raw["timeout_seconds"]), provider=raw["provider"],
                    allowed_hosts=tuple(raw.get("allowed_hosts", [])),
                    response_byte_limit=int(raw.get("response_byte_limit", 1024 * 1024)),
                    request_byte_limit=int(raw.get("request_byte_limit", 512 * 1024)),
                    reasoning_effort=raw.get("reasoning_effort"),
                    loopback_only=bool(raw.get("loopback_only", False)),
                )
            else:
                adapters[adapter_id] = cli_adapter_from_config(adapter_id, raw, artifact_dir / adapter_id)
        routes = config["routes"]
        return cls(adapters, routes["default_executor"], routes["default_auditor"])

    def get(self, adapter_id: str) -> HarnessAdapter:
        if adapter_id not in self.adapters:
            raise KeyError(adapter_id)
        return self.adapters[adapter_id]
