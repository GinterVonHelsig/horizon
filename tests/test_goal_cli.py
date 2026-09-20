"""Unit tests for goal_cli JSON entrypoint."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[1] / "controller" / "goal_cli.py"


def _run_cli(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True,
        text=True,
        env=merged,
        check=False,
    )


def test_inspect_emits_json_without_database(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Inspect me\n\n"
        "**Objective:** Parse only.\n\n"
        "## Mission\n\n"
        "Inspect path.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- read\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- write\n"
    )
    result = _run_cli("inspect", "--prompt", str(prompt))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["title"] == "Inspect me"
    assert payload["workstream_count"] == 1
    assert "TOP_DELIVERY_DATABASE_URL" not in result.stdout


def test_submit_requires_artifact_root(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Submit me\n\n"
        "**Objective:** Submit.\n\n"
        "## Mission\n\n"
        "Submit path.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- read\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- write\n"
    )
    result = _run_cli("submit", "--prompt", str(prompt))
    assert result.returncode != 0
    assert "artifact" in result.stderr.lower()


def test_submit_snapshots_adapter_routes_without_executable_validation(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Routed goal\n\n"
        "**Objective:** Route adapters.\n\n"
        "## Mission\n\n"
        "Snapshot routes.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- one\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- two\n"
    )
    adapter_config = tmp_path / "adapters.json"
    adapter_config.write_text(
        json.dumps(
            {
                "adapters": [
                    {
                        "id": "cursor-cli",
                        "kind": "cursor_cli",
                        "provider": "cursor",
                        "executable": "/nonexistent/cursor-agent",
                        "model": "composer-1",
                        "approval_mode": "never",
                        "credential_env": [],
                        "timeout_seconds": 60,
                        "allowed_cwd_roots": [str(tmp_path)],
                    },
                    {
                        "id": "claude-cli",
                        "kind": "claude_cli",
                        "provider": "anthropic",
                        "executable": "/nonexistent/claude",
                        "model": "claude-opus-4",
                        "permission_mode": "default",
                        "credential_env": [],
                        "timeout_seconds": 60,
                        "allowed_cwd_roots": [str(tmp_path)],
                    },
                ],
                "routes": {
                    "default_executor": "cursor-cli",
                    "default_auditor": "claude-cli",
                },
            }
        )
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    env = {"TOP_DELIVERY_ARTIFACT_ROOT": str(artifact_root)}
    result = _run_cli(
        "submit",
        "--prompt",
        str(prompt),
        "--dry-run",
        "--adapter-config",
        str(adapter_config),
        env=env,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    spec = json.loads(
        (artifact_root / "runs" / payload["run_id"] / "goal-spec.json").read_text()
    )
    for workstream in spec["workstreams"]:
        assert workstream["executor_adapter"] == "cursor-cli"
        assert workstream["auditor_adapter"] == "claude-cli"


def test_submit_with_explicit_dry_run_flag(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Submit me\n\n"
        "**Objective:** Submit.\n\n"
        "## Mission\n\n"
        "Submit path.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- read\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- write\n"
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    env = {"TOP_DELIVERY_ARTIFACT_ROOT": str(artifact_root)}
    result = _run_cli(
        "submit",
        "--prompt",
        str(prompt),
        "--dry-run",
        env=env,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["mode"] == "dry_run"
    assert payload["status"] in {"created", "existing"}
    assert "run_id" in payload


def test_submit_without_database_url_fails_for_durable_submit(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Submit me\n\n"
        "**Objective:** Submit.\n\n"
        "## Mission\n\n"
        "Submit path.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- read\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- write\n"
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    env = {"TOP_DELIVERY_ARTIFACT_ROOT": str(artifact_root)}
    result = _run_cli("submit", "--prompt", str(prompt), env=env)
    assert result.returncode != 0
    assert "database" in result.stderr.lower()


def test_ambient_dry_run_env_does_not_bypass_database_requirement(tmp_path: Path) -> None:
    prompt = tmp_path / "goal.md"
    prompt.write_text(
        "# Submit me\n\n"
        "**Objective:** Submit.\n\n"
        "## Mission\n\n"
        "Submit path.\n\n"
        "## P0 authority envelope\n\n"
        "Allowed:\n\n"
        "- read\n\n"
        "Forbidden without a new explicit authority envelope:\n\n"
        "- write\n"
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    env = {
        "TOP_DELIVERY_ARTIFACT_ROOT": str(artifact_root),
        "TOP_DELIVERY_GOAL_DRY_RUN": "1",
    }
    result = _run_cli("submit", "--prompt", str(prompt), env=env)
    assert result.returncode != 0
    assert "database" in result.stderr.lower()
