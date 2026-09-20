"""Bounded OpenAI-compatible HTTP harness adapter."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from harness_adapters.contract import HarnessRequest, HarnessResult
from harness_adapters.identity import normalize_model_part
from harness_adapters.redaction import redact_text, sanitize_value
from harness_adapters.schema import validate_json_schema

_LOOPBACK_NAMES = frozenset({"localhost"})
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
_SECRET_QUERY_KEY_RE = re.compile(
    r"(?:^|[_-])(api[_-]?key|token|password|secret|authorization|bearer)(?:$|[_-])",
    re.IGNORECASE,
)


def _query_has_secret_parameters(query: str) -> bool:
    if not query:
        return False
    for key in parse_qs(query, keep_blank_values=True):
        if _SECRET_QUERY_KEY_RE.search(key):
            return True
    return False


def _is_approved_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.is_loopback or any(address in network for network in _PRIVATE_NETWORKS)


def is_loopback_endpoint(endpoint: str) -> bool:
    """True only for loopback HTTP(S) URLs with no userinfo or secret query."""
    try:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        if _query_has_secret_parameters(parsed.query):
            return False
        host = parsed.hostname.rstrip(".").lower()
        if host in _LOOPBACK_NAMES:
            return True
        return ipaddress.ip_address(host).is_loopback
    except (ValueError, TypeError, OSError):
        return False


def is_allowed_endpoint(endpoint: str, *, allowed_hosts: tuple[str, ...] = ()) -> bool:
    try:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        if _query_has_secret_parameters(parsed.query):
            return False
        host = parsed.hostname.rstrip(".").lower()
        if host in _LOOPBACK_NAMES:
            return True
        try:
            return _is_approved_address(host)
        except ValueError:
            pass
        if host not in {item.rstrip(".").lower() for item in allowed_hosts}:
            return False
        # Explicitly named hosts must currently resolve only to private/loopback
        # addresses; this prevents an allowlisted label from becoming a public hop.
        resolved = {
            item[4][0]
            for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
        }
        return bool(resolved) and all(_is_approved_address(address) for address in resolved)
    except (ValueError, TypeError, OSError):
        return False


@dataclass
class HttpOpenAIAdapter:
    adapter_id: str
    endpoint: str
    model: str
    credential_env: str
    artifact_dir: Path
    timeout_seconds: float
    provider: str = "openai_compatible"
    allowed_hosts: tuple[str, ...] = ()
    response_byte_limit: int = 1024 * 1024
    request_byte_limit: int = 512 * 1024
    reasoning_effort: str | None = None
    loopback_only: bool = False
    _cancel_requested: bool = False
    _active_response: Any = None

    def start(self, request: HarnessRequest) -> HarnessResult:
        return self.execute(request)

    def resume(self, request: HarnessRequest, session_id: str) -> HarnessResult:
        role_dir = Path(request.artifact_dir)
        role_dir.mkdir(parents=True, exist_ok=True)
        (role_dir / "harness-session.json").write_text(
            json.dumps({"session_id": session_id}, indent=2, sort_keys=True) + "\n"
        )
        return self.execute(request)

    def cancel(self) -> None:
        self._cancel_requested = True
        response = self._active_response
        if response is not None:
            try:
                response.close()
            except Exception:
                pass

    def execute(self, request: HarnessRequest) -> HarnessResult:
        import time
        self._cancel_requested = False
        self.artifact_dir = Path(request.artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        if self.loopback_only:
            if not is_loopback_endpoint(self.endpoint):
                return self._failure("endpoint_not_allowed", False)
        elif not is_allowed_endpoint(self.endpoint, allowed_hosts=self.allowed_hosts):
            return self._failure("endpoint_not_allowed", False)
        api_key = os.environ.get(self.credential_env, "")
        if not api_key:
            return self._failure("auth_failure", False)
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if self.reasoning_effort:
            body["reasoning"] = {"effort": self.reasoning_effort}
        if request.output_schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "harness_response", "strict": True, "schema": request.output_schema},
            }
        request_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        if len(request_bytes) > self.request_byte_limit:
            return self._failure("process_failure", False)
        # Persist a digest rather than the prompt-bearing request body.
        self._atomic_write(self.artifact_dir / "request.metadata.json", sanitize_value({
            "endpoint": self.endpoint, "model": self.model, "provider": self.provider,
            "credential_env_name": self.credential_env,
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "prompt_sha256": hashlib.sha256(request.prompt.encode()).hexdigest(),
            "metadata": request.metadata,
        }, extra_values=(api_key,)))
        started = time.monotonic()
        req = urllib.request.Request(
            self.endpoint, data=request_bytes,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=min(request.timeout, self.timeout_seconds)) as response:
                self._active_response = response
                raw, truncated = self._read_bounded(response)
        except urllib.error.HTTPError as exc:
            classification, retryable = self._http_failure(exc.code)
            return self._failure(classification, retryable, time.monotonic() - started)
        except (socket.timeout, TimeoutError):
            return self._failure("timeout", True, time.monotonic() - started)
        except (urllib.error.URLError, ConnectionError, OSError):
            return self._failure("transport_failure", True, time.monotonic() - started)
        finally:
            self._active_response = None
        duration = time.monotonic() - started
        if self._cancel_requested:
            return self._failure("cancelled", False, duration)
        redacted_bytes = redact_text(raw.decode("utf-8", "replace"), extra_values=(api_key,)).encode()
        if len(redacted_bytes) > self.response_byte_limit:
            redacted_bytes = redacted_bytes[: self.response_byte_limit]
            truncated = True
        stdout_path = self.artifact_dir / "stdout.txt"
        self._atomic_bytes(stdout_path, redacted_bytes)
        stdout_sha = hashlib.sha256(redacted_bytes).hexdigest()
        self._atomic_write(self.artifact_dir / "response.digest.json", {
            "retained_sha256": stdout_sha, "retained_byte_count": len(redacted_bytes), "truncated": truncated,
        })
        structured: dict[str, Any] | None = None
        classification: str | None = None
        if truncated:
            classification = "malformed_structured_output"
        else:
            try:
                # Parse the retained, redacted artifact so credential-shaped model
                # fields can never re-enter HarnessResult through structured data.
                payload = json.loads(redacted_bytes)
                served = payload.get("model") if isinstance(payload, dict) else None
                if not isinstance(served, str) or not served.strip():
                    return self._failure("integrity_failure", False, duration)
                if normalize_model_part(served) != normalize_model_part(self.model):
                    return self._failure("integrity_failure", False, duration)
                content = payload["choices"][0]["message"]["content"]
                structured = json.loads(content) if isinstance(content, str) else content
                if not isinstance(structured, dict):
                    raise ValueError("structured payload must be object")
                validate_json_schema(structured, request.output_schema)
                structured = sanitize_value(structured, extra_values=(api_key,))
            except (KeyError, ValueError, json.JSONDecodeError, TypeError):
                classification = "malformed_structured_output"
                structured = None
        return HarnessResult(
            self.adapter_id, "http_openai", self.model, self.provider,
            "success" if classification is None else "failure",
            0 if classification is None else 1, duration, stdout_path.name, stdout_sha,
            None, None, structured, classification, classification == "malformed_structured_output",
            truncated, False,
        )

    def _read_bounded(self, response: Any) -> tuple[bytes, bool]:
        retained = bytearray()
        truncated = False
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            remaining = self.response_byte_limit - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                truncated = True
        return bytes(retained), truncated

    @staticmethod
    def _http_failure(code: int) -> tuple[str, bool]:
        if code in {401, 403}:
            return "auth_failure", False
        if code == 429:
            return "rate_limit", True
        if 500 <= code <= 599:
            return "transport_failure", True
        return "process_failure", False

    def _failure(self, classification: str, retryable: bool, duration: float = 0.0) -> HarnessResult:
        return HarnessResult(
            self.adapter_id, "http_openai", self.model, self.provider, "failure", 1,
            duration, None, None, None, None, None, classification, retryable,
        )

    def _atomic_write(self, path: Path, payload: Any) -> None:
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
        self._atomic_bytes(path, encoded)

    @staticmethod
    def _atomic_bytes(path: Path, payload: bytes) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(payload)
        tmp.replace(path)
