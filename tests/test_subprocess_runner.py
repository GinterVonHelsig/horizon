"""Subprocess runner safety and classification tests."""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import textwrap
import time
from unittest.mock import patch
from pathlib import Path

import pytest

from harness_adapters.subprocess_runner import SubprocessRunner


def _write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def runner(tmp_path: Path) -> SubprocessRunner:
    return SubprocessRunner(
        artifact_dir=tmp_path / "artifacts",
        allowlisted_env=("PATH", "HOME"),
        inline_output_limit=256,
    )


def test_subprocess_runner_uses_argv_not_shell(tmp_path: Path, runner: SubprocessRunner) -> None:
    exe = tmp_path / "echo.sh"
    _write_executable(
        exe,
        """\
        #!/bin/sh
        echo "$1"
        """,
    )
    result = runner.run(
        executable=str(exe.resolve()),
        argv=[str(exe.resolve()), "hello"],
        cwd=str(tmp_path),
        timeout=5.0,
        credential_env_names=(),
    )
    assert result.exit_code == 0
    assert "hello" in (result.inline_stdout or "")


def test_subprocess_runner_rejects_missing_executable(runner: SubprocessRunner, tmp_path: Path) -> None:
    missing = tmp_path / "missing-binary"
    result = runner.run(
        executable=str(missing),
        argv=[str(missing)],
        cwd=str(tmp_path),
        timeout=2.0,
        credential_env_names=(),
    )
    assert result.error_classification == "missing_executable"
    assert result.retryable is False


def test_subprocess_runner_environment_is_allowlisted(tmp_path: Path, runner: SubprocessRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "env.py"
    _write_executable(exe, """\
        #!/usr/bin/env python3
        import json, os
        print(json.dumps(dict(os.environ)))
    """)
    monkeypatch.setenv("ALLOWED_SECRET", "kept-value")
    monkeypatch.setenv("FORBIDDEN_VALUE", "must-not-pass")
    result = runner.run(
        executable=str(exe.resolve()), argv=[str(exe.resolve())], cwd=str(tmp_path),
        timeout=5.0, credential_env_names=("ALLOWED_SECRET",), expect_json=True,
    )
    assert "must-not-pass" not in (result.inline_stdout or "")
    assert result.structured_payload is not None
    assert "FORBIDDEN_VALUE" not in result.structured_payload


def test_subprocess_runner_redacts_credential_output(tmp_path: Path, runner: SubprocessRunner) -> None:
    exe = tmp_path / "leak.sh"
    _write_executable(
        exe,
        """\
        #!/bin/sh
        echo "token=super-secret-api-key-value"
        """,
    )
    os.environ["TEST_HARNESS_SECRET"] = "super-secret-api-key-value"
    try:
        result = runner.run(
            executable=str(exe.resolve()),
            argv=[str(exe.resolve())],
            cwd=str(tmp_path),
            timeout=5.0,
            credential_env_names=("TEST_HARNESS_SECRET",),
        )
    finally:
        os.environ.pop("TEST_HARNESS_SECRET", None)
    assert "super-secret-api-key-value" not in (result.inline_stdout or "")
    assert "[REDACTED]" in (result.inline_stdout or "")
    meta_path = tmp_path / "artifacts" / "process-result.json"
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text())
    assert "super-secret-api-key-value" not in json.dumps(meta)


def test_subprocess_runner_never_persists_prompt_or_argv(tmp_path: Path, runner: SubprocessRunner) -> None:
    exe = tmp_path / "ok.sh"
    _write_executable(exe, "#!/bin/sh\necho '{}'")
    secret_prompt = "prompt-with-private-value"
    runner.run(executable=str(exe.resolve()), argv=[str(exe.resolve()), secret_prompt],
               cwd=str(tmp_path), timeout=5, credential_env_names=(), expect_json=True)
    metadata = (tmp_path / "artifacts" / "process-result.json").read_text()
    assert secret_prompt not in metadata
    assert "argv_sha256" in metadata


def test_subprocess_runner_caps_artifacts_while_draining(tmp_path: Path) -> None:
    exe = tmp_path / "large.py"
    _write_executable(exe, """\
        #!/usr/bin/env python3
        import sys
        sys.stdout.write("x" * 500000)
        sys.stderr.write("y" * 500000)
    """)
    runner = SubprocessRunner(artifact_dir=tmp_path / "artifacts", allowlisted_env=(),
                              artifact_output_limit=4096, inline_output_limit=128)
    result = runner.run(executable=str(exe.resolve()), argv=[str(exe.resolve())], cwd=str(tmp_path),
                        timeout=5, credential_env_names=())
    assert (tmp_path / "artifacts" / "stdout.txt").stat().st_size <= 4096
    assert (tmp_path / "artifacts" / "stderr.txt").stat().st_size <= 4096
    assert result.stdout_truncated and result.stderr_truncated


def test_subprocess_runner_requires_matching_executable_and_classifies_popen_errors(tmp_path: Path) -> None:
    exe = tmp_path / "ok.sh"
    other = tmp_path / "other.sh"
    _write_executable(exe, "#!/bin/sh\nexit 0")
    _write_executable(other, "#!/bin/sh\nexit 0")
    runner = SubprocessRunner(artifact_dir=tmp_path / "artifacts", allowlisted_env=())
    mismatch = runner.run(executable=str(exe.resolve()), argv=[str(other.resolve())], cwd=str(tmp_path),
                          timeout=1, credential_env_names=())
    assert mismatch.error_classification == "integrity_failure"
    exe.chmod(stat.S_IRUSR)
    denied = runner.run(executable=str(exe.resolve()), argv=[str(exe.resolve())], cwd=str(tmp_path),
                        timeout=1, credential_env_names=())
    assert denied.error_classification == "missing_executable"


def test_subprocess_runner_classifies_auth_and_rate_limit(tmp_path: Path) -> None:
    for message, expected, retryable in [("401 unauthorized", "auth_failure", False), ("429 rate limit", "rate_limit", True)]:
        exe = tmp_path / f"{expected}.sh"
        _write_executable(exe, f"#!/bin/sh\necho '{message}' >&2\nexit 1")
        result = SubprocessRunner(artifact_dir=tmp_path / expected, allowlisted_env=()).run(
            executable=str(exe.resolve()), argv=[str(exe.resolve())], cwd=str(tmp_path),
            timeout=2, credential_env_names=())
        assert (result.error_classification, result.retryable) == (expected, retryable)


def test_subprocess_runner_timeout_classification(tmp_path: Path) -> None:
    exe = tmp_path / "sleep.sh"
    _write_executable(
        exe,
        """\
        #!/bin/sh
        trap '' TERM
        sleep 30
        """,
    )
    runner = SubprocessRunner(
        artifact_dir=tmp_path / "artifacts",
        allowlisted_env=(),
        inline_output_limit=128,
        term_grace_seconds=0.2,
    )
    started = time.monotonic()
    result = runner.run(
        executable=str(exe.resolve()),
        argv=[str(exe.resolve())],
        cwd=str(tmp_path),
        timeout=0.5,
        credential_env_names=(),
    )
    assert time.monotonic() - started < 5.0
    assert result.error_classification == "timeout"
    assert result.retryable is True


def test_subprocess_runner_cancel_classification(tmp_path: Path) -> None:
    exe = tmp_path / "loop.sh"
    _write_executable(
        exe,
        """\
        #!/bin/sh
        while true; do sleep 1; done
        """,
    )
    runner = SubprocessRunner(
        artifact_dir=tmp_path / "artifacts",
        allowlisted_env=(),
        inline_output_limit=128,
        term_grace_seconds=0.1,
    )
    proc_holder: dict[str, subprocess.Popen[bytes]] = {}

    def launch() -> None:
        proc_holder["proc"] = subprocess.Popen(
            [str(exe.resolve())],
            cwd=str(tmp_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

    import threading

    thread = threading.Thread(target=launch)
    thread.start()
    thread.join(timeout=1.0)
    proc = proc_holder["proc"]
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    proc.wait(timeout=2)
    result = runner.run(
        executable=str(exe.resolve()),
        argv=[str(exe.resolve())],
        cwd=str(tmp_path),
        timeout=0.2,
        credential_env_names=(),
        cancel_check=lambda: True,
    )
    assert result.error_classification == "cancelled"
    assert result.retryable is False


def test_subprocess_runner_malformed_json_classification(tmp_path: Path, runner: SubprocessRunner) -> None:
    exe = tmp_path / "badjson.sh"
    _write_executable(
        exe,
        """\
        #!/bin/sh
        echo '{not-json'
        exit 0
        """,
    )
    result = runner.run(
        executable=str(exe.resolve()),
        argv=[str(exe.resolve())],
        cwd=str(tmp_path),
        timeout=5.0,
        credential_env_names=(),
        expect_json=True,
    )
    assert result.error_classification == "malformed_structured_output"
    assert result.retryable is True


def test_descendant_holding_stdout_does_not_hang_after_leader_exits(tmp_path: Path) -> None:
    exe = tmp_path / "orphan.py"
    _write_executable(
        exe,
        """\
        #!/usr/bin/env python3
        import os
        import sys
        import time
        if os.fork() == 0:
            while True:
                sys.stdout.write("still-open\\n")
                sys.stdout.flush()
                time.sleep(0.2)
        os._exit(0)
        """,
    )
    runner = SubprocessRunner(
        artifact_dir=tmp_path / "artifacts",
        allowlisted_env=(),
        inline_output_limit=128,
        term_grace_seconds=0.2,
    )
    started = time.monotonic()
    result = runner.run(
        executable=str(exe.resolve()),
        argv=[str(exe.resolve())],
        cwd=str(tmp_path),
        timeout=0.5,
        credential_env_names=(),
    )
    elapsed = time.monotonic() - started
    assert elapsed < 3.0
    assert result.error_classification == "timeout"
    assert result.retryable is True
    source = Path(__file__).resolve().parents[1] / "controller" / "harness_adapters" / "subprocess_runner.py"
    text = source.read_text()
    assert "start_new_session=True" in text
    assert "setsid or" in text and "double-fork" in text


