"""Bounded, auditable OpenRouter JSON runner for TOP-DELIVERY.

The runner separates prompt-size accounting from completion accounting, keeps
every provider attempt, preserves finish/usage/error metadata, and normalizes
only a valid JSON object returned inside a markdown fence. It never prints or
stores the API key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import signal
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)
RUNNER_SCHEMA_VERSION = 2
JOB_ENVELOPE_SCHEMA_VERSION = 1
REQUIRED_IDENTITY_FIELDS = (
    "run_id",
    "task_id",
    "child_id",
    "attempt_number",
    "fence_token",
    "controller_epoch",
    "reviewed_sha",
    "tree_sha",
    "source_digest",
    "request_digest",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_json_content(content: str) -> tuple[str | None, dict[str, bool]]:
    """Return normalized JSON text and parse metadata without guessing content."""
    candidates: list[tuple[str, bool]] = [(content.strip(), False)]
    candidates.extend((match.strip(), True) for match in JSON_FENCE_RE.findall(content))

    decoder = json.JSONDecoder()
    for candidate, from_fence in candidates:
        if not candidate:
            continue
        try:
            value, end = decoder.raw_decode(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, (dict, list)):
            continue
        trailing = candidate[end:].strip()
        if trailing:
            continue
        normalized = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return normalized, {
            "valid_json": True,
            "normalized_from_fence": from_fence,
        }
    return None, {"valid_json": False, "normalized_from_fence": False}


ALLOWED_FINISH_REASONS = frozenset({"stop"})
REJECTED_FINISH_REASONS = frozenset({"content_filter", "length"})
MAX_INPUT_BYTES = 512_000
DEFAULT_MAX_TOKENS = 32_768
DEFAULT_MAX_RETRY_TOKENS = 32_768
MAX_COMPLETION_TOKENS = 32_768
MAX_ATTEMPTS = 2
MAX_TIMEOUT_SECONDS = 600.0
MIN_REQUEST_TIMEOUT_SECONDS = 0.001
MAX_JOB_ELAPSED_SECONDS = 1_800.0
MAX_TOTAL_COMPLETION_TOKENS = 96_000
MAX_RESPONSE_BYTES = 4_000_000
MAX_RESPONSE_CONTENT_BYTES = 1_000_000
DEFAULT_REASONING_MAX_TOKENS = 8_000
MAX_REASONING_TOKENS = 32_768
ALLOWED_REASONING_EFFORTS = frozenset({"medium", "high", "xhigh", "max"})
DENIED_MODEL_PREFIXES = ("anthropic/",)
# 10% above currently discounted OpenRouter list prices. Exceeding these is
# recorded as price_ceiling_exceeded so promo expiry is visible.
PRICE_CEILINGS_USD_PER_1M = {
    "openai/gpt-5.6-sol": {"prompt": 2.20, "completion": 11.0},
    "openai/gpt-5.6-luna": {"prompt": 0.22, "completion": 1.32},
    "z-ai/glm-5.3-flash": {"prompt": 0.0825, "completion": 0.275},
    "z-ai/glm-5.3": {"prompt": 1.54, "completion": 4.84},
    "qwen/qwen3.8-max": {"prompt": 2.20, "completion": 6.60},
    "moonshotai/kimi-k3": {"prompt": 3.30, "completion": 16.50},
    "x-ai/grok-4.6": {"prompt": 2.20, "completion": 6.60},
    "deepseek/deepseek-v4-flash-0731": {"prompt": 0.242, "completion": 0.726},
    "google/gemini-3.8-flash": {"prompt": 0.825, "completion": 4.125},
}
RUNNER_ENVELOPE_PUBLIC_KEY_PATH = "/etc/top-delivery/comms01-runner-envelope.pub"
REQUIRED_USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")


class AggregateDeadlineExceeded(TimeoutError):
    """The provider response did not finish before the controller job deadline."""


class _ReadDeadlineSignal(TimeoutError):
    """Internal signal used to interrupt non-socket provider readers."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            request.full_url,
            code,
            "provider redirect refused",
            headers,
            fp,
        )


_PROVIDER_OPENER = urllib.request.build_opener(
    _NoRedirectHandler(),
    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
)


def open_provider(request: urllib.request.Request, *, timeout: float):
    """Open only the pinned HTTPS provider endpoint with verified TLS/no redirects."""
    parsed = urlsplit(request.full_url)
    if parsed.scheme != "https" or parsed.hostname != "openrouter.ai":
        raise ValueError("provider URL must be the pinned OpenRouter HTTPS endpoint")
    return _PROVIDER_OPENER.open(request, timeout=timeout)


def create_only_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    handle = os.open(path, flags, 0o600)
    with os.fdopen(handle, "wb") as stream:
        stream.write(data)


def create_only_write_text(path: Path, text: str) -> None:
    create_only_write_bytes(path, text.encode("utf-8"))


def read_bounded_file(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> str:
    """Read controller-supplied prompt material with a hard byte ceiling."""
    chunks: list[bytes] = []
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(min(64 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise SystemExit(f"input file exceeds max input bytes ({max_bytes}): {path}")
            chunks.append(chunk)
            if len(chunk) < 64 * 1024:
                break
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"input file is not valid UTF-8: {path}") from exc


def _read_bounded_response_sync(
    response: Any,
    *,
    max_bytes: int,
    deadline: float | None = None,
    raw_socket: socket.socket | None = None,
) -> bytes:
    """Read a provider response without allowing an unbounded body into memory."""
    chunks: list[bytes] = []
    total = 0
    while True:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AggregateDeadlineExceeded("aggregate-deadline-exceeded")
            if raw_socket is not None:
                try:
                    # Recompute the socket timeout for every read. A peer
                    # that drips one byte per idle timeout cannot extend the
                    # absolute attempt deadline indefinitely.
                    raw_socket.settimeout(remaining)
                except OSError as exc:
                    raise AggregateDeadlineExceeded(
                        "provider socket became unavailable"
                    ) from exc
        read_size = min(64 * 1024, max_bytes - total + 1)
        # HTTPResponse.read(amt) may wait for amt bytes on a keep-alive or
        # chunked provider response.  read1() drains bytes already available
        # without waiting for an arbitrary full-size buffer; the socket
        # timeout above still supplies the absolute deadline for the next
        # read.  Only response-level read1() is trusted; response.read() is
        # the sole fallback, and nested fp readers are never consulted.
        read1 = getattr(response, "read1", None)
        try:
            chunk = (read1(read_size) if callable(read1) else response.read(read_size))
        except TypeError as exc:
            raise ValueError("provider response reader does not support bounded reads") from exc
        if not chunk:
            break
        if not isinstance(chunk, (bytes, bytearray)):
            raise ValueError("provider response read returned a non-bytes value")
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"provider response exceeds {max_bytes} bytes")
        chunks.append(bytes(chunk))
        if deadline is not None and time.monotonic() > deadline:
            raise AggregateDeadlineExceeded("aggregate-deadline-exceeded")
    return b"".join(chunks)


def read_bounded_response(
    response: Any,
    *,
    max_bytes: int = MAX_RESPONSE_BYTES,
    deadline: float | None = None,
) -> bytes:
    """Read a bounded body and enforce a hard wall-clock deadline.

    urllib's socket timeout is an idle/read-operation bound. A slow-drip peer
    can otherwise reset that timeout on every byte. For real urllib responses,
    bind the underlying socket to the absolute deadline and read synchronously;
    the fallback thread is only for test doubles or non-socket providers.
    """
    if deadline is None:
        return _read_bounded_response_sync(response, max_bytes=max_bytes)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AggregateDeadlineExceeded("aggregate-deadline-exceeded")
    raw_socket = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    if isinstance(raw_socket, socket.socket):
        original_timeout = raw_socket.gettimeout()
        try:
            return _read_bounded_response_sync(
                response,
                max_bytes=max_bytes,
                deadline=deadline,
                raw_socket=raw_socket,
            )
        except socket.timeout as exc:
            try:
                response.close()
            except Exception:
                pass
            raise AggregateDeadlineExceeded("aggregate-deadline-exceeded") from exc
        except AggregateDeadlineExceeded:
            try:
                response.close()
            except Exception:
                pass
            raise
        finally:
            try:
                if raw_socket.fileno() >= 0:
                    raw_socket.settimeout(original_timeout)
            except OSError:
                pass
    # urllib's production response has a real socket and takes the path above.
    # For a non-socket test/double response, use a process-local signal rather
    # than a daemon reader thread: a timed-out reader must not survive the
    # attempt and quietly consume resources after the attempt is recorded.
    if threading.current_thread() is not threading.main_thread() or not hasattr(
        signal, "setitimer"
    ):
        raise ValueError(
            "bounded provider response requires a socket or the main thread"
        )

    def on_deadline(_signum: int, _frame: Any) -> None:
        raise _ReadDeadlineSignal("aggregate-deadline-exceeded")

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)
    signal.signal(signal.SIGALRM, on_deadline)
    timer_started = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, remaining)
    deadline_hit = False
    try:
        result = _read_bounded_response_sync(response, max_bytes=max_bytes)
        if time.monotonic() > deadline:
            raise _ReadDeadlineSignal("aggregate-deadline-exceeded")
        return result
    except _ReadDeadlineSignal:
        deadline_hit = True
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            elapsed = max(0.0, time.monotonic() - timer_started)
            restored = previous_timer[0] - elapsed
            if restored > 0:
                signal.setitimer(signal.ITIMER_REAL, restored, previous_timer[1])
    if deadline_hit:
        try:
            response.close()
        except Exception:
            pass
        raise AggregateDeadlineExceeded("aggregate-deadline-exceeded")
    return result


def validate_usage(usage: Any) -> bool:
    """Require numeric, non-negative accounting fields from every accepted response."""
    if not isinstance(usage, dict):
        return False
    values: list[int] = []
    for field in REQUIRED_USAGE_FIELDS:
        value = usage.get(field)
        if type(value) is not int or value < 0:
            return False
        values.append(value)
    prompt_tokens, completion_tokens, total_tokens = values
    return total_tokens >= prompt_tokens + completion_tokens


def evaluate_price_ceiling(model: str, usage: Any) -> dict[str, Any]:
    """Record billed rates against pinned ceilings. Never abort the call."""
    result: dict[str, Any] = {
        "price_ceiling": PRICE_CEILINGS_USD_PER_1M.get(model),
        "price_ceiling_exceeded": False,
        "billed_prompt_usd_per_1m": None,
        "billed_completion_usd_per_1m": None,
    }
    if not isinstance(usage, dict):
        return result
    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    details = usage.get("cost_details") if isinstance(usage.get("cost_details"), dict) else {}
    prompt_cost = details.get("upstream_inference_prompt_cost")
    completion_cost = details.get("upstream_inference_completions_cost")
    if type(prompt_tokens) is int and prompt_tokens > 0 and isinstance(prompt_cost, (int, float)):
        result["billed_prompt_usd_per_1m"] = (float(prompt_cost) / prompt_tokens) * 1_000_000
    if type(completion_tokens) is int and completion_tokens > 0 and isinstance(completion_cost, (int, float)):
        result["billed_completion_usd_per_1m"] = (float(completion_cost) / completion_tokens) * 1_000_000
    ceiling = result["price_ceiling"]
    if not ceiling:
        return result
    prompt_rate = result["billed_prompt_usd_per_1m"]
    completion_rate = result["billed_completion_usd_per_1m"]
    if prompt_rate is not None and prompt_rate > ceiling["prompt"]:
        result["price_ceiling_exceeded"] = True
    if completion_rate is not None and completion_rate > ceiling["completion"]:
        result["price_ceiling_exceeded"] = True
    return result


def write_json(path: Path, value: Any) -> None:
    create_only_write_text(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
    )


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _canonical_envelope_body(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": envelope.get("schema_version"),
        "model": envelope.get("model"),
        "request_id": envelope.get("request_id"),
        "identity": envelope.get("identity"),
        "expected_output_schema": envelope.get("expected_output_schema"),
        "prompt_digests": envelope.get("prompt_digests"),
        "provenance": envelope.get("provenance"),
    }


def _envelope_public_key() -> Ed25519PublicKey:
    path = Path(RUNNER_ENVELOPE_PUBLIC_KEY_PATH)
    if not path.is_file() or path.is_symlink():
        raise SystemExit("controller runner envelope public key is missing")
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o077:
        raise SystemExit("runner envelope public key trust is invalid")
    material = path.read_text(encoding="utf-8").strip()
    if not material:
        raise SystemExit("controller runner envelope public key is empty")
    try:
        return Ed25519PublicKey.from_public_bytes(_b64_decode(material))
    except (ValueError, TypeError) as exc:
        raise SystemExit("controller runner envelope public key is malformed") from exc


def sign_job_envelope(envelope: dict[str, Any], *, signing_key: str) -> str:
    """Test/controller helper; the runtime runner only verifies a pinned public key."""
    body = _canonical_envelope_body(envelope)
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(_b64_decode(signing_key))
    except (ValueError, TypeError) as exc:
        raise ValueError("runner envelope signing key is malformed") from exc
    return base64.urlsafe_b64encode(private_key.sign(encoded)).decode("ascii")


def verify_job_envelope_signature(envelope: dict[str, Any], signature: str) -> bool:
    body = _canonical_envelope_body(envelope)
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        _envelope_public_key().verify(_b64_decode(signature), encoded)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def envelope_digest(envelope: dict[str, Any]) -> str:
    body = _canonical_envelope_body(envelope)
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_job_envelope(path: Path, args: argparse.Namespace) -> dict[str, Any]:
    envelope = json.loads(read_bounded_file(path, max_bytes=128 * 1024))
    if envelope.get("schema_version") != JOB_ENVELOPE_SCHEMA_VERSION:
        raise SystemExit("job envelope schema_version mismatch")
    identity = envelope.get("identity")
    if not isinstance(identity, dict):
        raise SystemExit("job envelope identity is required")
    signature = envelope.get("controller_signature")
    if not isinstance(signature, str) or not signature.strip():
        raise SystemExit("job envelope lacks controller_signature")
    if not verify_job_envelope_signature(envelope, signature):
        raise SystemExit("job envelope controller_signature is invalid")
    for field in REQUIRED_IDENTITY_FIELDS:
        expected = identity.get(field)
        actual = getattr(args, field.replace("-", "_"))
        if str(expected) != str(actual):
            raise SystemExit(f"job envelope identity mismatch for {field}")
    expected_schema = envelope.get("expected_output_schema")
    if not isinstance(expected_schema, dict) or expected_schema.get("type") != "object":
        raise SystemExit("job envelope expected_output_schema must be a JSON object schema")
    if envelope.get("model") != args.model:
        raise SystemExit("job envelope model mismatch")
    prompt_digests = envelope.get("prompt_digests")
    if not isinstance(prompt_digests, dict):
        raise SystemExit("job envelope prompt_digests are required")
    return envelope


def _schema_type_matches(value: Any, expected_type: str) -> bool:
    if expected_type == "null":
        return value is None
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "integer":
        return type(value) is int
    if expected_type == "number":
        return type(value) in {int, float}
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    return False


def _validate_schema_value(value: Any, schema: Any) -> bool:
    if schema is True:
        return True
    if schema is False or not isinstance(schema, dict):
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    expected = schema.get("type")
    if expected is not None:
        types = expected if isinstance(expected, list) else [expected]
        if not any(isinstance(item, str) and _schema_type_matches(value, item) for item in types):
            return False
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            return False
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            return False
    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            return False
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            return False
        item_schema = schema.get("items", True)
        if not all(_validate_schema_value(item, item_schema) for item in value):
            return False
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return False
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(key, str) for key in required):
            return False
        if any(key not in value for key in required):
            return False
        additional = schema.get("additionalProperties", True)
        for key, child in value.items():
            if key in properties:
                if not _validate_schema_value(child, properties[key]):
                    return False
            elif additional is False:
                return False
            elif isinstance(additional, (dict, bool)) and not _validate_schema_value(child, additional):
                return False
    return True


def validate_output_schema(value: Any, schema: dict[str, Any]) -> bool:
    """Validate the complete nested JSON schema; never accept a shallow match."""
    return isinstance(schema, dict) and schema.get("type") == "object" and _validate_schema_value(
        value, schema
    )


def preflight_output_paths(*paths: Path) -> None:
    for path in paths:
        if path.exists():
            raise SystemExit(f"output path already exists: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)


def publish_accepted_bundle(
    *,
    content_out: Path,
    raw_out: Path,
    metadata_out: Path,
    attempt_metadata_path: Path,
    content: str,
    raw: bytes,
    metadata: dict[str, Any],
) -> None:
    """Create-only publish of content+raw+metadata as one fail-closed bundle."""
    preflight_output_paths(content_out, raw_out, metadata_out, attempt_metadata_path)
    staging = {
        "content": content_out.with_suffix(content_out.suffix + ".staging"),
        "raw": raw_out.with_suffix(raw_out.suffix + ".staging"),
        "metadata": metadata_out.with_suffix(metadata_out.suffix + ".staging"),
        "attempt": attempt_metadata_path.with_suffix(attempt_metadata_path.suffix + ".staging"),
    }
    try:
        create_only_write_text(staging["content"], content)
        create_only_write_bytes(staging["raw"], raw)
        write_json(staging["metadata"], metadata)
        write_json(staging["attempt"], metadata)
        for staged in staging.values():
            with staged.open("rb") as stream:
                os.fsync(stream.fileno())
        directory_fd = os.open(str(content_out.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.rename(staging["content"], content_out)
        os.rename(staging["raw"], raw_out)
        os.rename(staging["metadata"], metadata_out)
        os.rename(staging["attempt"], attempt_metadata_path)
        directory_fd = os.open(str(content_out.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        for staged in staging.values():
            if staged.exists():
                staged.unlink()
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider", default="openrouter")
    parser.add_argument("--effort", default="high")
    parser.add_argument("--request-id")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--child-id", required=True)
    parser.add_argument("--attempt-number", type=int, required=True)
    parser.add_argument("--fence-token", type=int, required=True)
    parser.add_argument("--controller-epoch", type=int, required=True)
    parser.add_argument("--reviewed-sha", required=True)
    parser.add_argument("--tree-sha", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--request-digest", required=True)
    parser.add_argument("--job-envelope-file", type=Path, required=True)
    parser.add_argument("--system-file", type=Path, required=True)
    parser.add_argument("--user-file", type=Path, required=True)
    parser.add_argument("--raw-out", type=Path, required=True)
    parser.add_argument("--content-out", type=Path, required=True)
    parser.add_argument("--metadata-out", type=Path)
    parser.add_argument("--attempt-dir", type=Path)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument(
        "--reasoning-max-tokens", type=int, default=DEFAULT_REASONING_MAX_TOKENS
    )
    parser.add_argument("--max-retry-tokens", type=int, default=DEFAULT_MAX_RETRY_TOKENS)
    parser.add_argument("--attempts", type=int, default=MAX_ATTEMPTS)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--max-job-seconds", type=float, default=MAX_JOB_ELAPSED_SECONDS)
    parser.add_argument("--max-total-tokens", type=int, default=MAX_TOTAL_COMPLETION_TOKENS)
    return parser.parse_args()


def _validate_identity(args: argparse.Namespace) -> None:
    for field in REQUIRED_IDENTITY_FIELDS:
        attr = field.replace("-", "_")
        value = getattr(args, attr)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise SystemExit(f"missing required runner identity field: {field}")
    if args.attempt_number < 0:
        raise SystemExit("attempt_number must be non-negative")
    if args.fence_token < 0:
        raise SystemExit("fence_token must be non-negative")
    if args.controller_epoch < 0:
        raise SystemExit("controller_epoch must be non-negative")


def main() -> int:
    args = parse_args()
    _validate_identity(args)
    if str(args.model).startswith(DENIED_MODEL_PREFIXES):
        raise SystemExit(f"anthropic models are denylisted: {args.model}")
    envelope = load_job_envelope(args.job_envelope_file, args)
    expected_schema = envelope["expected_output_schema"]
    if (
        args.provider != "openrouter"
        or args.attempts < 1
        or args.attempts > MAX_ATTEMPTS
        or args.max_tokens < 1
        or args.max_tokens > MAX_COMPLETION_TOKENS
        or args.reasoning_max_tokens < 1
        or args.reasoning_max_tokens > MAX_REASONING_TOKENS
        or args.max_retry_tokens < args.max_tokens
        or args.max_retry_tokens > MAX_COMPLETION_TOKENS
    ):
        raise SystemExit("invalid attempt or token budget")
    if args.effort not in ALLOWED_REASONING_EFFORTS:
        allowed = ", ".join(sorted(ALLOWED_REASONING_EFFORTS))
        raise SystemExit(f"unsupported reasoning effort {args.effort!r}; allowed: {allowed}")
    if args.timeout_seconds <= 0 or args.timeout_seconds > MAX_TIMEOUT_SECONDS:
        raise SystemExit("invalid timeout_seconds bound")
    if args.max_job_seconds <= 0 or args.max_job_seconds > MAX_JOB_ELAPSED_SECONDS:
        raise SystemExit("invalid max-job-seconds bound")
    if args.max_total_tokens < 1 or args.max_total_tokens > MAX_TOTAL_COMPLETION_TOKENS:
        raise SystemExit("invalid max-total-tokens bound")

    system_text = read_bounded_file(args.system_file)
    user_text = read_bounded_file(args.user_file)
    system_bytes = len(system_text.encode("utf-8"))
    user_bytes = len(user_text.encode("utf-8"))
    combined_bytes = system_bytes + user_bytes
    if system_bytes > MAX_INPUT_BYTES or user_bytes > MAX_INPUT_BYTES:
        raise SystemExit("prompt component exceeds max input bytes")
    if combined_bytes > MAX_INPUT_BYTES:
        raise SystemExit("combined prompt exceeds max input bytes")
    prompt_digests = envelope["prompt_digests"]
    if prompt_digests.get("system_sha256") != sha256_text(system_text):
        raise SystemExit("system prompt digest does not match controller envelope")
    if prompt_digests.get("user_sha256") != sha256_text(user_text):
        raise SystemExit("user prompt digest does not match controller envelope")
    if prompt_digests.get("combined_sha256") != sha256_text(system_text + user_text):
        raise SystemExit("combined prompt digest does not match controller envelope")
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise SystemExit("OPENROUTER_API_KEY is not configured")
    metadata_path = args.metadata_out or args.raw_out.with_suffix(".metadata.json")
    attempt_dir = args.attempt_dir or args.raw_out.with_suffix(".attempts")
    attempt_dir.mkdir(parents=True, exist_ok=True)
    preflight_output_paths(args.content_out, args.raw_out, metadata_path)
    request_id = envelope.get("request_id") or args.request_id or sha256_text(
        f"{args.model}:{args.run_id}:{args.task_id}:{args.child_id}:{args.attempt_number}"
    )
    request_group_id = request_id
    canonical_envelope = envelope_digest(envelope)
    metadata: dict[str, Any] = {
        "schema_version": RUNNER_SCHEMA_VERSION,
        "request_id": request_group_id,
        "request_group_id": request_group_id,
        "envelope_digest": canonical_envelope,
        "canonical_request_digest": args.request_digest,
        "identity": {
            "run_id": args.run_id,
            "task_id": args.task_id,
            "child_id": args.child_id,
            "attempt_number": args.attempt_number,
            "fence_token": args.fence_token,
            "controller_epoch": args.controller_epoch,
            "request_digest": args.request_digest,
        },
        "provenance": {
            "reviewed_sha": args.reviewed_sha,
            "tree_sha": args.tree_sha,
            "source_digest": args.source_digest,
        },
        "provider": args.provider,
        "route": OPENROUTER_URL,
        "model": args.model,
        "effort": args.effort,
        "input": {
            "system_bytes": system_bytes,
            "user_bytes": user_bytes,
            "combined_bytes": combined_bytes,
            "max_input_bytes": MAX_INPUT_BYTES,
            "system_sha256": sha256_text(system_text),
            "user_sha256": sha256_text(user_text),
            "combined_sha256": sha256_text(system_text + user_text),
        },
        "request": {
            "initial_max_tokens": args.max_tokens,
            "max_retry_tokens": args.max_retry_tokens,
            "attempt_limit": args.attempts,
            "timeout_seconds": args.timeout_seconds,
            "max_job_seconds": args.max_job_seconds,
            "max_total_tokens": args.max_total_tokens,
            "response_format": "json_object",
            "provider_policy": {"allow_fallbacks": False},
            "requested_effort": args.effort,
            "reasoning_mode": "effort",
            "reasoning_effort": args.effort,
            "legacy_reasoning_max_tokens": args.reasoning_max_tokens,
            "legacy_reasoning_max_tokens_ignored": True,
            "job_envelope_file": str(args.job_envelope_file),
            "envelope_digest": canonical_envelope,
            "bounds": {
                "max_input_bytes": MAX_INPUT_BYTES,
                "max_completion_tokens": MAX_COMPLETION_TOKENS,
                "max_attempts": MAX_ATTEMPTS,
                "max_timeout_seconds": MAX_TIMEOUT_SECONDS,
                "max_job_elapsed_seconds": MAX_JOB_ELAPSED_SECONDS,
                "max_total_completion_tokens": MAX_TOTAL_COMPLETION_TOKENS,
                "max_response_bytes": MAX_RESPONSE_BYTES,
                "max_response_content_bytes": MAX_RESPONSE_CONTENT_BYTES,
            },
        },
        "attempts": [],
        "response": {"accepted": False},
    }

    job_started = time.monotonic()
    job_deadline = job_started + args.max_job_seconds
    total_budget = 0
    for attempt in range(1, args.attempts + 1):
        elapsed = time.monotonic() - job_started
        remaining_before_attempt = job_deadline - time.monotonic()
        if remaining_before_attempt <= 0:
            metadata["termination"] = {
                "reason": "aggregate-deadline-exceeded",
                "elapsed_seconds": elapsed,
                "max_job_seconds": args.max_job_seconds,
            }
            break
        started = utc_now()
        budget = min(
            args.max_retry_tokens,
            args.max_tokens * (2 ** (attempt - 1)),
            args.max_total_tokens - total_budget,
        )
        if budget < 1:
            metadata["termination"] = {
                "reason": "aggregate-token-budget-exhausted",
                "total_budget": total_budget,
                "max_total_tokens": args.max_total_tokens,
            }
            break
        total_budget += budget
        attempt_request_id = sha256_text(f"{request_group_id}:attempt:{attempt}")
        payload: dict[str, Any] = {
            "model": args.model,
            "messages": [
                {"role": "system", "content": system_text},
                {"role": "user", "content": user_text},
            ],
            # OpenRouter counts reasoning.max_tokens inside the total
            # completion budget.  A small cap can consume the entire budget
            # before any visible JSON is emitted.  Use the provider's effort
            # control so the visible completion retains its own max_tokens
            # budget.
            "reasoning": {"effort": args.effort},
            "max_tokens": budget,
            "response_format": {"type": "json_object"},
            # The workflow must never silently route a review or execution
            # request through another OpenRouter provider.  Model-substitution
            # checks below are defense in depth; this is the provider-side
            # routing policy that makes the intent explicit on every request.
            "provider": {"allow_fallbacks": False},
        }
        request_body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        request = urllib.request.Request(
            OPENROUTER_URL,
            data=request_body,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://top-delivery.local",
                "X-Title": "TOP-DELIVERY run artifact",
                "Idempotency-Key": attempt_request_id,
            },
        )
        remaining_for_request = job_deadline - time.monotonic()
        request_timeout = max(
            0.0, min(args.timeout_seconds, remaining_for_request)
        )
        request_deadline = min(job_deadline, time.monotonic() + request_timeout)
        record: dict[str, Any] = {
            "attempt": attempt,
            "started_at": started,
            "max_tokens": budget,
            "timeout_seconds": request_timeout,
            "elapsed_before_attempt_seconds": elapsed,
            "cumulative_budget": total_budget,
            "local_request_id": attempt_request_id,
            "request_group_id": request_group_id,
            "request_body_bytes": len(request_body),
            "request_body_sha256": hashlib.sha256(request_body).hexdigest(),
        }
        attempt_path = attempt_dir / f"attempt-{attempt}-{attempt_request_id[:12]}.raw.json"
        attempt_metadata_path = attempt_dir / f"attempt-{attempt}-{attempt_request_id[:12]}.metadata.json"
        record["raw_attempt_path"] = str(attempt_path)
        if remaining_for_request < MIN_REQUEST_TIMEOUT_SECONDS:
            create_only_write_bytes(attempt_path, b"")
            record.update(
                {
                    "status": "aggregate-deadline-exceeded",
                    "error": "aggregate job deadline elapsed before provider request",
                    "raw_bytes": 0,
                    "raw_sha256": hashlib.sha256(b"").hexdigest(),
                    "finished_at": utc_now(),
                    "retry_cause": "aggregate-deadline-exceeded",
                }
            )
            metadata["attempts"].append(record)
            metadata["termination"] = {
                "reason": "aggregate-deadline-exceeded",
                "elapsed_seconds": time.monotonic() - job_started,
                "max_job_seconds": args.max_job_seconds,
            }
            write_json(attempt_metadata_path, metadata)
            break
        try:
            with open_provider(request, timeout=request_timeout) as response:
                # Bound both connection establishment and body reading to this
                # attempt.  Passing the overall job deadline here would allow a
                # slow-drip provider response to monopolize the entire retry
                # group after the socket timeout had already expired.
                raw = read_bounded_response(response, deadline=request_deadline)
                record["http_status"] = response.status
                record["response_bytes"] = len(raw)
                record["upstream_provider"] = (
                    response.headers.get("x-openrouter-provider")
                    or response.headers.get("X-OpenRouter-Provider")
                )
            document = json.loads(raw)
            create_only_write_bytes(attempt_path, raw)
            record["raw_bytes"] = len(raw)
            record["raw_sha256"] = hashlib.sha256(raw).hexdigest()
            record["provider_request_id"] = document.get("id") if isinstance(document, dict) else None
            record["provider_model"] = document.get("model") if isinstance(document, dict) else None
            record["usage"] = document.get("usage") if isinstance(document, dict) else None
            record["effort"] = args.effort
            if isinstance(document, dict) and document.get("provider") and not record.get("upstream_provider"):
                record["upstream_provider"] = document.get("provider")
            record["usage_cost_usd"] = (
                (record["usage"] or {}).get("cost") if isinstance(record.get("usage"), dict) else None
            )
            record.update(evaluate_price_ceiling(args.model, record.get("usage")))
            if not isinstance(document, dict) or document.get("object") != "chat.completion":
                record["status"] = "invalid-response-object"
            elif not record.get("provider_request_id"):
                record["status"] = "missing-provider-request-id"
            elif not validate_usage(record.get("usage")):
                record["status"] = "invalid-usage"
            elif document.get("model") and document.get("model") != args.model:
                record["status"] = "rejected-model-substitution"
            elif document.get("error"):
                record["status"] = "provider-error"
                record["error"] = document["error"]
            else:
                choices = document.get("choices") or []
                if len(choices) != 1:
                    record["status"] = "rejected-choice-count"
                else:
                    choice = choices[0] if isinstance(choices[0], dict) else {}
                    message = choice.get("message") if isinstance(choice, dict) else {}
                    content = message.get("content") if isinstance(message, dict) else None
                    finish_reason = choice.get("finish_reason")
                    record["finish_reason"] = finish_reason
                    record["content_bytes"] = len(content.encode()) if isinstance(content, str) else 0
                    if finish_reason not in ALLOWED_FINISH_REASONS:
                        if finish_reason in REJECTED_FINISH_REASONS:
                            record["status"] = f"rejected-finish-{finish_reason}"
                        else:
                            record["status"] = f"rejected-finish-{finish_reason or 'missing'}"
                        # A length-truncated response may have no message content;
                        # preserve that fact without misclassifying it as a schema
                        # or content-type failure.
                        normalized, parse_info = None, {
                            "valid_json": False,
                            "normalized_from_fence": False,
                        }
                        if isinstance(content, str) and content:
                            if record["content_bytes"] > MAX_RESPONSE_CONTENT_BYTES:
                                record["status"] = "response-content-too-large"
                            else:
                                _, parse_info = parse_json_content(content)
                        record.update(parse_info)
                    elif not isinstance(content, str):
                        record["status"] = "invalid-content-type"
                        normalized, parse_info = None, {
                            "valid_json": False,
                            "normalized_from_fence": False,
                        }
                        record.update(parse_info)
                    elif record["content_bytes"] > MAX_RESPONSE_CONTENT_BYTES:
                        record["status"] = "response-content-too-large"
                        normalized, parse_info = None, {
                            "valid_json": False,
                            "normalized_from_fence": False,
                        }
                        record.update(parse_info)
                    else:
                        normalized, parse_info = parse_json_content(content)
                        record.update(parse_info)
                        if normalized is None:
                            record["status"] = "invalid-json"
                        elif not isinstance(json.loads(normalized or "{}"), dict):
                            record["status"] = "invalid-json-non-object"
                        elif not validate_output_schema(
                            json.loads(normalized or "{}"), expected_schema
                        ):
                            record["status"] = "invalid-output-schema"
                        elif not content.strip():
                            record["status"] = "empty-content"
                        else:
                            record["status"] = "accepted"
                            record["finished_at"] = utc_now()
                            record["output_sha256"] = sha256_text(
                                normalized if normalized is not None else content
                            )
                            metadata["response"] = {
                                "accepted": True,
                                "attempt": attempt,
                                "local_request_id": attempt_request_id,
                                "request_group_id": request_group_id,
                                "provider_request_id": record.get("provider_request_id"),
                                "finish_reason": finish_reason,
                                "content_bytes": record["content_bytes"],
                                "output_sha256": record["output_sha256"],
                                "raw_attempt_path": record["raw_attempt_path"],
                                "envelope_digest": canonical_envelope,
                                "total_budget": total_budget,
                                "elapsed_seconds": time.monotonic() - job_started,
                            }
                            metadata["attempts"].append(record)
                            publish_accepted_bundle(
                                content_out=args.content_out,
                                raw_out=args.raw_out,
                                metadata_out=metadata_path,
                                attempt_metadata_path=attempt_metadata_path,
                                content=normalized,
                                raw=raw,
                                metadata=metadata,
                            )
                            print(json.dumps({"status": "accepted", **metadata["response"]}))
                            return 0
        except AggregateDeadlineExceeded:
            record.update(
                {
                    "status": "aggregate-deadline-exceeded",
                    "error": "provider response exceeded aggregate job deadline",
                }
            )
            record["finished_at"] = utc_now()
            record["retry_cause"] = record["status"]
            metadata["attempts"].append(record)
            metadata["termination"] = {
                "reason": "aggregate-deadline-exceeded",
                "elapsed_seconds": time.monotonic() - job_started,
                "max_job_seconds": args.max_job_seconds,
            }
            write_json(attempt_metadata_path, metadata)
            break
        except urllib.error.HTTPError as exc:
            try:
                error_deadline = min(
                    job_deadline,
                    time.monotonic() + min(2.0, max(0.05, request_timeout)),
                )
                error_raw = read_bounded_response(
                    exc, max_bytes=64_000, deadline=error_deadline
                )
            except Exception as body_exc:
                error_raw = b""
                record["error_body_read_error"] = type(body_exc).__name__
            attempt_path = attempt_dir / f"attempt-{attempt}-{attempt_request_id[:12]}.raw.json"
            create_only_write_bytes(attempt_path, error_raw)
            record["raw_attempt_path"] = str(attempt_path)
            record["raw_bytes"] = len(error_raw)
            record["raw_sha256"] = hashlib.sha256(error_raw).hexdigest()
            body = error_raw.decode("utf-8", errors="replace")
            record.update(
                {
                    "status": "http-error",
                    "http_status": exc.code,
                    "error_body": body[:4000].replace(key, "[REDACTED]"),
                }
            )
        except Exception as exc:  # no credential material in exception output
            record.update(
                {
                    "status": "transport-error",
                    "error_type": type(exc).__name__,
                    "error": str(exc).replace(key, "[REDACTED]")[:1000],
                }
            )
        record["finished_at"] = utc_now()
        record["retry_cause"] = record.get("status", "unknown")
        metadata["attempts"].append(record)
        attempt_metadata_path = attempt_dir / f"attempt-{attempt}-{attempt_request_id[:12]}.metadata.json"
        write_json(attempt_metadata_path, metadata)
        if total_budget >= args.max_total_tokens:
            metadata["termination"] = {
                "reason": "aggregate-token-budget-exhausted",
                "total_budget": total_budget,
                "max_total_tokens": args.max_total_tokens,
            }
            break
        if attempt < args.attempts:
            remaining = max(0.0, args.max_job_seconds - (time.monotonic() - job_started))
            if remaining <= 0:
                metadata["termination"] = {
                    "reason": "aggregate-deadline-exceeded",
                    "elapsed_seconds": time.monotonic() - job_started,
                    "max_job_seconds": args.max_job_seconds,
                }
                break
            time.sleep(min(2**attempt, 8, remaining))

    termination = metadata.get("termination")
    metadata["response"] = {
        "accepted": False,
        "reason": (
            termination.get("reason")
            if isinstance(termination, dict)
            else "attempts-exhausted"
        ),
    }
    metadata.setdefault("termination", {"reason": "attempts-exhausted"})
    metadata["response"]["total_budget"] = total_budget
    metadata["response"]["elapsed_seconds"] = time.monotonic() - job_started
    write_json(metadata_path, metadata)
    print(json.dumps({"status": "failed", "model": args.model, "metadata": str(metadata_path)}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
