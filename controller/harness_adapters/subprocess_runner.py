"""Bounded, argv-only subprocess runner for CLI harness adapters.

Process groups: Popen uses start_new_session=True so the child is its own
session/process-group leader. Cleanup SIGTERM/SIGKILL uses the pgid captured
at start, then SIGKILL even if the leader has already exited. This covers
same-group descendants that keep stdout open. Descendants that setsid or
double-fork into a new process group are out of scope for this runner
(cgroup containment would be a later envelope). Bytes arriving after the
drain deadline are discarded to prevent hangs.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from harness_adapters.redaction import redact_text, validate_env_name
from harness_adapters.executable_policy import PROHIBITED_EXECUTABLES, resolve_trusted_executable
from artifact_isolation import apply_safe_home


@dataclass(frozen=True)
class SubprocessRunResult:
    exit_code: int | None
    duration_seconds: float
    inline_stdout: str | None
    inline_stderr: str | None
    stdout_artifact_path: str | None
    stdout_sha256: str | None
    stderr_artifact_path: str | None
    stderr_sha256: str | None
    structured_payload: dict[str, Any] | None
    error_classification: str | None
    retryable: bool
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class SubprocessRunner:
    def __init__(
        self, *, artifact_dir: Path, allowlisted_env: tuple[str, ...],
        inline_output_limit: int = 4096, artifact_output_limit: int = 1024 * 1024,
        term_grace_seconds: float = 5.0,
    ) -> None:
        if inline_output_limit <= 0 or artifact_output_limit <= 0:
            raise ValueError("output limits must be positive")
        self.artifact_dir = Path(artifact_dir)
        self.allowlisted_env = tuple(validate_env_name(name) for name in allowlisted_env)
        self.inline_output_limit = inline_output_limit
        self.artifact_output_limit = artifact_output_limit
        self.term_grace_seconds = term_grace_seconds
        self._active: subprocess.Popen[bytes] | None = None
        self._active_pgid: int | None = None

    def run(
        self, *, executable: str, argv: list[str], cwd: str, timeout: float,
        credential_env_names: tuple[str, ...], expect_json: bool = False,
        output_parser: Callable[[str], dict[str, Any]] | None = None,
        cancel_check: Callable[[], bool] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> SubprocessRunResult:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        executable_path = Path(executable)
        if str(executable_path) in PROHIBITED_EXECUTABLES:
            return self._classified_result("integrity_failure", False, 0.0)
        try:
            canonical_executable = resolve_trusted_executable(executable)
            canonical_argv0 = resolve_trusted_executable(argv[0]) if argv else None
        except ValueError as exc:
            if "prohibited" in str(exc) or "integrity" in str(exc):
                return self._classified_result("integrity_failure", False, 0.0)
            return self._classified_result("missing_executable", False, 0.0)
        except (FileNotFoundError, OSError):
            return self._classified_result("missing_executable", False, 0.0)
        if canonical_argv0 != canonical_executable:
            return self._classified_result("integrity_failure", False, 0.0)
        credential_env_names = tuple(validate_env_name(name) for name in credential_env_names)
        credential_values = tuple(os.environ.get(name, "") for name in credential_env_names if os.environ.get(name))
        env = {name: os.environ[name] for name in self.allowlisted_env if name in os.environ}
        for name in credential_env_names:
            if name in os.environ:
                env[name] = os.environ[name]
        for name, value in (extra_env or {}).items():
            env[validate_env_name(name)] = str(value)
        env = apply_safe_home(env)
        if cancel_check and cancel_check():
            return self._classified_result("cancelled", False, 0.0)
        try:
            proc = subprocess.Popen(
                argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, start_new_session=True,
            )
        except (FileNotFoundError, PermissionError, OSError):
            return self._classified_result("missing_executable", False, time.monotonic() - started)
        self._active = proc
        try:
            self._active_pgid = os.getpgid(proc.pid)
        except ProcessLookupError:
            self._active_pgid = None
        try:
            stdout, stderr, stdout_truncated, stderr_truncated, termination = self._drain(
                proc, timeout=timeout, cancel_check=cancel_check
            )
            duration = time.monotonic() - started
            redacted_stdout = redact_text(stdout.decode("utf-8", "replace"), extra_values=credential_values)
            redacted_stderr = redact_text(stderr.decode("utf-8", "replace"), extra_values=credential_values)
            stdout_path, stdout_sha = self._write_artifact("stdout.txt", redacted_stdout)
            stderr_path, stderr_sha = self._write_artifact("stderr.txt", redacted_stderr)
            structured: dict[str, Any] | None = None
            classification = termination
            retryable = classification in {"timeout"}
            if classification is None and proc.returncode != 0:
                classification = self._classify_stderr(redacted_stderr) or "process_failure"
                retryable = classification in {"rate_limit", "transport_failure"}
            elif classification is None and (expect_json or output_parser):
                try:
                    structured = output_parser(redacted_stdout) if output_parser else self._parse_json(redacted_stdout)
                except (ValueError, json.JSONDecodeError, KeyError, TypeError):
                    classification = "malformed_structured_output"
                    retryable = True
            result = SubprocessRunResult(
                proc.returncode, duration, redacted_stdout[: self.inline_output_limit],
                redacted_stderr[: self.inline_output_limit], stdout_path, stdout_sha,
                stderr_path, stderr_sha, structured, classification, retryable,
                stdout_truncated, stderr_truncated,
            )
            self._write_result_metadata(result, argv=argv, executable=str(canonical_executable))
            return result
        finally:
            self._active = None
            self._active_pgid = None

    def _drain(
        self, proc: subprocess.Popen[bytes], *, timeout: float,
        cancel_check: Callable[[], bool] | None,
    ) -> tuple[bytes, bytes, bool, bool, str | None]:
        selector = selectors.DefaultSelector()
        assert proc.stdout is not None and proc.stderr is not None
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        retained = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = {"stdout": False, "stderr": False}
        deadline = time.monotonic() + timeout
        termination: str | None = None
        terminate_started: float | None = None
        try:
            while selector.get_map():
                now = time.monotonic()
                if termination is None and cancel_check and cancel_check():
                    termination = "cancelled"
                    self._terminate_process_group(proc)
                    terminate_started = now
                elif termination is None and now >= deadline:
                    termination = "timeout"
                    self._terminate_process_group(proc)
                    terminate_started = now
                elif (
                    termination is not None
                    and terminate_started is not None
                    and now >= terminate_started + max(self.term_grace_seconds, 0.05) + 0.25
                ):
                    for registered in list(selector.get_map().values()):
                        try:
                            selector.unregister(registered.fileobj)
                        except Exception:
                            pass
                        try:
                            registered.fileobj.close()
                        except Exception:
                            pass
                    break
                for key, _ in selector.select(0.05):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = retained[key.data]
                    remaining = self.artifact_output_limit - len(target)
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                    if len(chunk) > max(remaining, 0):
                        truncated[key.data] = True
            try:
                proc.wait(timeout=max(self.term_grace_seconds, 1.0))
            except subprocess.TimeoutExpired:
                self._terminate_process_group(proc)
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            selector.close()
        return bytes(retained["stdout"]), bytes(retained["stderr"]), truncated["stdout"], truncated["stderr"], termination

    def cancel(self) -> None:
        proc = self._active
        if proc is not None and proc.poll() is None:
            self._terminate_process_group(proc)

    def _terminate_process_group(self, proc: subprocess.Popen[bytes]) -> None:
        pgid = self._active_pgid
        if pgid is None:
            try:
                pgid = os.getpgid(proc.pid)
            except ProcessLookupError:
                pgid = None
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + self.term_grace_seconds
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.02)
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _write_artifact(self, name: str, content: str) -> tuple[str, str]:
        encoded = content.encode("utf-8")[: self.artifact_output_limit]
        path = self.artifact_dir / name
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(encoded)
        tmp.replace(path)
        return path.name, hashlib.sha256(encoded).hexdigest()

    def _write_result_metadata(self, result: SubprocessRunResult, *, argv: list[str], executable: str) -> None:
        argv_digest = hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
        payload = {
            "executable": executable, "argv_sha256": argv_digest, "argument_count": len(argv),
            "exit_code": result.exit_code, "duration_seconds": result.duration_seconds,
            "stdout_artifact_path": result.stdout_artifact_path, "stdout_sha256": result.stdout_sha256,
            "stderr_artifact_path": result.stderr_artifact_path, "stderr_sha256": result.stderr_sha256,
            "stdout_truncated": result.stdout_truncated, "stderr_truncated": result.stderr_truncated,
            "error_classification": result.error_classification, "retryable": result.retryable,
        }
        self._atomic_json("process-result.json", payload)

    def _atomic_json(self, name: str, payload: dict[str, Any]) -> None:
        path = self.artifact_dir / name
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        tmp.replace(path)

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any]:
        value = json.loads(text.strip())
        if not isinstance(value, dict):
            raise ValueError("structured payload must be object")
        return value

    @staticmethod
    def _classify_stderr(stderr: str) -> str | None:
        lowered = stderr.lower()
        if "rate limit" in lowered or "429" in lowered:
            return "rate_limit"
        if any(value in lowered for value in ("unauthorized", "401", "forbidden", "403", "authentication")):
            return "auth_failure"
        if any(value in lowered for value in ("connection reset", "temporarily unavailable", "service unavailable", "502", "503", "504")):
            return "transport_failure"
        return None

    def _classified_result(self, classification: str, retryable: bool, duration: float) -> SubprocessRunResult:
        result = SubprocessRunResult(None, duration, None, None, None, None, None, None, None, classification, retryable)
        self._write_result_metadata(result, argv=[], executable="")
        return result
