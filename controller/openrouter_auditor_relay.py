"""Loopback-only OpenRouter Auditor relay. Provider key never leaves this process."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

_SK_RE = __import__("re").compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = __import__("re").compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+")


def _redact_text(text: str, extra: tuple[str, ...] = ()) -> str:
    redacted = _BEARER_RE.sub("[REDACTED]", _SK_RE.sub("[REDACTED]", str(text)))
    for value in sorted((item for item in extra if item), key=len, reverse=True):
        redacted = redacted.replace(value, "[REDACTED]")
    return redacted

ALLOWED_MODEL = "openai/gpt-5.6-sol"
ALLOWED_MODELS = {
    "openai/gpt-5.6-sol": "max",
    "x-ai/grok-4.6": "high",
}
DENIED_MODEL_PREFIXES = ("anthropic/",)
PINNED_PROVIDER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MAX_REQUEST_BYTES = 256 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 120.0


class RelayPolicyError(ValueError):
    """Raised when the relay refuses a policy-violating configuration or body."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise HTTPError(request.full_url, code, "provider redirect refused", headers, fp)


def _is_loopback_peer(peer: str) -> bool:
    try:
        return ipaddress.ip_address(peer).is_loopback
    except ValueError:
        return peer in {"localhost", "127.0.0.1", "::1"}


def build_upstream_payload(body: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise RelayPolicyError("request body must be an object")
    model = str(body.get("model") or ALLOWED_MODEL)
    if model.startswith(DENIED_MODEL_PREFIXES) or model not in ALLOWED_MODELS:
        raise RelayPolicyError("model is not allowed")
    payload = dict(body)
    payload["model"] = model
    payload["reasoning"] = {"effort": ALLOWED_MODELS[model]}
    return payload


class OpenRouterAuditorRelay:
    def __init__(
        self,
        *,
        bind_host: str = "127.0.0.1",
        bind_port: int = 18765,
        provider_url: str = PINNED_PROVIDER_URL,
        provider_key_env: str = "OPENROUTER_API_KEY",
        relay_token_env: str = "TOP_DELIVERY_OPENROUTER_RELAY_TOKEN",
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        allow_test_loopback_provider: bool = False,
    ) -> None:
        if bind_host not in {"127.0.0.1", "::1"}:
            raise RelayPolicyError("relay must bind only to loopback")
        if allow_test_loopback_provider:
            parsed = urlsplit(provider_url)
            if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise RelayPolicyError("test provider must be loopback HTTP")
        elif provider_url != PINNED_PROVIDER_URL:
            raise RelayPolicyError("provider URL must be the pinned OpenRouter HTTPS endpoint")
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.provider_url = provider_url
        self.provider_key_env = provider_key_env
        self.relay_token_env = relay_token_env
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        self.timeout_seconds = timeout_seconds
        self._opener = build_opener(
            _NoRedirectHandler(),
            HTTPSHandler(context=ssl.create_default_context()),
        )

    def _secrets(self) -> tuple[str, str]:
        provider_key = os.environ.get(self.provider_key_env, "")
        relay_token = os.environ.get(self.relay_token_env, "")
        return provider_key, relay_token

    def _redact(self, text: str) -> str:
        provider_key, relay_token = self._secrets()
        return _redact_text(text, extra=(provider_key, relay_token))

    def handle_json(
        self,
        body: dict[str, Any] | None,
        *,
        authorization: str | None,
        peer: str,
        raw_len: int | None = None,
    ) -> dict[str, Any]:
        provider_key, relay_token = self._secrets()
        try:
            if not _is_loopback_peer(peer):
                return {"status": 403, "body": {"error": "loopback only"}}
            expected = f"Bearer {relay_token}" if relay_token else ""
            if not relay_token or authorization != expected:
                return {"status": 401, "body": {"error": "unauthorized"}}
            if not provider_key:
                return {"status": 503, "body": {"error": "provider unavailable"}}
            encoded = json.dumps(body or {}, separators=(",", ":")).encode()
            size = raw_len if raw_len is not None else len(encoded)
            if size > self.max_request_bytes:
                return {"status": 413, "body": {"error": "request too large"}}
            payload = build_upstream_payload(body or {})
            upstream = json.dumps(payload, separators=(",", ":")).encode()
            if len(upstream) > self.max_request_bytes:
                return {"status": 413, "body": {"error": "request too large"}}
            request = Request(
                self.provider_url,
                data=upstream,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {provider_key}",
                },
                method="POST",
            )
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
            if len(raw) > self.max_response_bytes:
                return {"status": 502, "body": {"error": "response too large"}}
            parsed = json.loads(raw.decode("utf-8"))
            digest = {
                "provider_request_id": parsed.get("id"),
                "model": parsed.get("model"),
                "upstream_provider": parsed.get("provider"),
                "effort": payload.get("reasoning", {}).get("effort"),
                "usage_cost_usd": (parsed.get("usage") or {}).get("cost") if isinstance(parsed.get("usage"), dict) else None,
                "finish_reason": (parsed.get("choices") or [{}])[0].get("finish_reason"),
                "request_sha256": hashlib.sha256(upstream).hexdigest(),
                "response_sha256": hashlib.sha256(raw).hexdigest(),
            }
            return {"status": 200, "body": parsed, "digest": digest}
        except RelayPolicyError as exc:
            return {"status": 400, "body": {"error": self._redact(str(exc))}}
        except HTTPError as exc:
            code = int(exc.code)
            return {"status": code if code in {401, 403, 429} or 500 <= code <= 599 else 502, "body": {"error": "upstream error"}}
        except (URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
            return {"status": 502, "body": {"error": self._redact(type(exc).__name__)}}

    def health(self, *, authorization: str | None, peer: str) -> dict[str, Any]:
        _provider_key, relay_token = self._secrets()
        if not _is_loopback_peer(peer):
            return {"status": 403, "body": {"error": "loopback only"}}
        if not relay_token or authorization != f"Bearer {relay_token}":
            return {"status": 401, "body": {"error": "unauthorized"}}
        return {"status": 200, "body": {"ok": True, "model": ALLOWED_MODEL, "allowed_models": sorted(ALLOWED_MODELS), "effort": ALLOWED_MODELS[ALLOWED_MODEL]}}


def _make_handler(relay: OpenRouterAuditorRelay):
    class Handler(BaseHTTPRequestHandler):
        def _peer(self) -> str:
            return self.client_address[0]

        def _auth(self) -> str | None:
            return self.headers.get("Authorization")

        def _write(self, payload: dict[str, Any]) -> None:
            body = json.dumps(payload["body"]).encode()
            self.send_response(int(payload["status"]))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/health":
                self._write({"status": 404, "body": {"error": "not found"}})
                return
            self._write(relay.health(authorization=self._auth(), peer=self._peer()))

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path not in {"/v1/chat/completions", "/api/v1/chat/completions"}:
                self._write({"status": 404, "body": {"error": "not found"}})
                return
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(min(length, relay.max_request_bytes + 1))
            if length > relay.max_request_bytes or len(raw) > relay.max_request_bytes:
                self._write({"status": 413, "body": {"error": "request too large"}})
                return
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._write({"status": 400, "body": {"error": "malformed json"}})
                return
            if not isinstance(body, dict):
                self._write({"status": 400, "body": {"error": "malformed json"}})
                return
            self._write(
                relay.handle_json(
                    body,
                    authorization=self._auth(),
                    peer=self._peer(),
                    raw_len=length,
                )
            )

        def log_message(self, format: str, *args: object) -> None:
            sys.stderr.write(relay._redact("%s - %s\n" % (self.address_string(), format % args)))

    return Handler


def serve(relay: OpenRouterAuditorRelay) -> None:
    server = ThreadingHTTPServer((relay.bind_host, relay.bind_port), _make_handler(relay))
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openrouter-auditor-relay")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18765)
    args = parser.parse_args(argv)
    relay = OpenRouterAuditorRelay(bind_host=args.bind, bind_port=args.port)
    serve(relay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
