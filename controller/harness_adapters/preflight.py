"""Adapter executable and model availability checks that run before claim."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from harness_adapters.executable_policy import resolve_trusted_executable
from harness_adapters.http_adapters import is_loopback_endpoint


class AdapterPreflightError(Exception):
    def __init__(self, message: str, *, code: str = "BLOCKED_ADAPTER_PREFLIGHT") -> None:
        super().__init__(message)
        self.code = code


ListModels = Callable[[str, str], list[str]]


def parse_model_list_text(text: str) -> list[str]:
    models: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("available"):
            continue
        lowered = line.lower()
        if "error" in lowered and "401" in lowered:
            raise AdapterPreflightError(line, code="BLOCKED_ADAPTER_MODEL")
        if "oauth" in lowered and "revoked" in lowered:
            raise AdapterPreflightError(line, code="BLOCKED_ADAPTER_MODEL")
        token = line.split()[0]
        if token in {"-", "*"}:
            continue
        models.append(token)
    return models


def list_cli_models(kind: str, executable: str) -> list[str]:
    if kind == "cursor_cli":
        argv = [executable, "--list-models"]
    elif kind == "claude_cli":
        argv = [executable, "models"]
    else:
        return []
    try:
        proc = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterPreflightError(
            f"model catalog unavailable for {kind}: {type(exc).__name__}",
            code="BLOCKED_ADAPTER_MODEL",
        ) from exc
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        if "401" in combined or "revoked" in combined.lower() or "unauthor" in combined.lower():
            raise AdapterPreflightError(
                f"{kind} model catalog authentication failed",
                code="BLOCKED_ADAPTER_MODEL",
            )
        raise AdapterPreflightError(
            f"{kind} model catalog exited {proc.returncode}",
            code="BLOCKED_ADAPTER_MODEL",
        )
    return parse_model_list_text(combined)


def preflight_adapters(
    config: dict[str, Any],
    *,
    list_models: ListModels | None = None,
    probe_http: bool = False,
) -> dict[str, Any]:
    lister = list_models or list_cli_models
    models: dict[str, str] = {}
    routes = config.get("routes") if isinstance(config.get("routes"), dict) else {}
    required = {
        str(routes.get("default_executor") or ""),
        str(routes.get("default_auditor") or ""),
    }
    required.discard("")
    for raw in config.get("adapters", []):
        if not isinstance(raw, dict):
            raise AdapterPreflightError("adapter config is invalid")
        kind = str(raw.get("kind") or "")
        adapter_id = str(raw.get("id") or "")
        model = str(raw.get("model") or "").strip()
        if required and adapter_id not in required:
            continue
        if kind == "http_openai":
            endpoint = str(raw.get("endpoint") or "")
            if raw.get("loopback_only") and not is_loopback_endpoint(endpoint):
                raise AdapterPreflightError(
                    f"adapter {adapter_id} endpoint is not loopback",
                    code="BLOCKED_OPENROUTER_EGRESS_POLICY",
                )
            creds = raw.get("credential_env") or []
            if not isinstance(creds, list) or not creds:
                raise AdapterPreflightError(f"adapter {adapter_id} relay token env is required")
            token_name = str(creds[0])
            if not os.environ.get(token_name):
                raise AdapterPreflightError(
                    f"adapter {adapter_id} relay token is missing",
                    code="BLOCKED_OPENROUTER_RELAY",
                )
            if probe_http:
                _probe_loopback_relay(endpoint, os.environ[token_name])
            models[adapter_id] = model
            continue
        executable = raw.get("executable")
        if not isinstance(executable, str) or not executable:
            raise AdapterPreflightError(f"adapter {adapter_id} executable is required")
        try:
            resolve_trusted_executable(executable)
        except ValueError as exc:
            raise AdapterPreflightError(
                f"adapter {adapter_id} executable is unavailable: {exc}"
            ) from exc
        if not model:
            raise AdapterPreflightError(
                f"adapter {adapter_id} model is required",
                code="BLOCKED_ADAPTER_MODEL",
            )
        catalog = lister("cursor_cli" if kind == "gateway_delivery" else kind, executable)
        if catalog and model not in catalog:
            raise AdapterPreflightError(
                f"adapter {adapter_id} model {model} is unavailable",
                code="BLOCKED_ADAPTER_MODEL",
            )
        models[adapter_id] = model
    return {"ok": True, "models": models, "executables_ok": True}


def _probe_loopback_relay(endpoint: str, token: str) -> None:
    import urllib.error
    import urllib.request

    parsed = urlsplit(endpoint)
    health = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}/health"
    req = urllib.request.Request(
        health,
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if int(getattr(response, "status", 200)) >= 400:
                raise AdapterPreflightError(
                    "openrouter relay health check failed",
                    code="BLOCKED_OPENROUTER_RELAY",
                )
    except AdapterPreflightError:
        raise
    except Exception as exc:
        raise AdapterPreflightError(
            f"openrouter relay is unavailable: {type(exc).__name__}",
            code="BLOCKED_OPENROUTER_RELAY",
        ) from exc
