"""CLI harness adapter command builder tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from harness_adapters.cli_adapters import (
    CliHarnessAdapter,
    build_claude_argv,
    build_codex_argv,
    build_cursor_argv,
    build_pi_argv,
    parse_cli_output,
)
from harness_adapters.contract import HarnessRequest
from harness_adapters.subprocess_runner import SubprocessRunner


def test_codex_argv_uses_exec_json_and_codex_home() -> None:
    argv = build_codex_argv(
        executable="/opt/codex/bin/codex",
        prompt="do task",
        codex_home="/var/lib/codex",
        model=None,
    )
    assert argv[0] == "/opt/codex/bin/codex"
    assert "exec" in argv
    assert "--json" in argv
    assert "--codex-home" not in argv
    assert "/var/lib/codex" not in argv
    assert "/usr/local/bin/codex-yolo" not in argv


def test_cursor_argv_uses_stream_json_and_flags() -> None:
    argv = build_cursor_argv(
        executable="/usr/bin/cursor-agent",
        prompt="review",
        model="composer-1",
        approval_mode="never",
        worktree="/tmp/wt",
    )
    assert argv[0] == "/usr/bin/cursor-agent"
    assert "--output-format" in argv
    assert "stream-json" in argv
    assert "--model" in argv
    assert "composer-1" in argv
    assert "--approve-mcps" in argv or "--force" in argv


def test_claude_argv_uses_stream_json_and_permission_mode() -> None:
    argv = build_claude_argv(
        executable="/usr/bin/claude",
        prompt="audit",
        model="claude-opus-4",
        permission_mode="plan",
    )
    assert "--output-format" in argv
    assert "stream-json" in argv
    assert "--permission-mode" in argv
    assert "plan" in argv


def test_pi_argv_uses_json_mode() -> None:
    argv = build_pi_argv(
        executable="/usr/local/bin/pi",
        prompt="experiment",
        model="qwen-3.8",
        endpoint="http://127.0.0.1:8080/v1",
    )
    assert "--mode" in argv
    assert "json" in argv
    assert "--provider" in argv
    assert "127.0.0.1" not in " ".join(argv)


def test_cli_builders_never_embed_credential_values() -> None:
    builders = [
        build_codex_argv(executable="/bin/codex", prompt="p", codex_home="/home/codex", model=None),
        build_cursor_argv(executable="/bin/cursor-agent", prompt="p", model="m", approval_mode="never", worktree="/tmp"),
        build_claude_argv(executable="/bin/claude", prompt="p", model="m", permission_mode="default"),
        build_pi_argv(executable="/bin/pi", prompt="p", model="m", endpoint="http://127.0.0.1:8080/v1"),
    ]
    for argv in builders:
        joined = " ".join(argv)
        assert "sk-" not in joined
        assert "api_key" not in joined.lower()


def test_cli_jsonl_event_parsers_use_final_structured_message() -> None:
    fixtures = {
        "codex_cli": '\n'.join([
            '{"type":"thread.started","thread_id":"t1"}',
            '{"type":"item.completed","item":{"type":"agent_message","text":"{\\"verdict\\":\\"approve\\"}"}}',
            '{"type":"turn.completed","usage":{"input_tokens":3}}',
        ]),
        "cursor_cli": '\n'.join([
            '{"type":"system","subtype":"init"}',
            '{"type":"assistant","message":{"content":[{"type":"text","text":"{\\"verdict\\":\\"reject\\"}"}]}}',
            '{"type":"result","subtype":"success"}',
        ]),
        "claude_cli": '\n'.join([
            '{"type":"system","subtype":"init"}',
            '{"type":"assistant","message":{"content":[{"type":"text","text":"{\\"verdict\\":\\"approve\\"}"}]}}',
            '{"type":"result","result":"done"}',
        ]),
        "pi_cli": '\n'.join([
            '{"type":"agent_message_start"}',
            '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"{\\"verdict\\":\\"approve\\"}"}]}}',
        ]),
    }
    assert parse_cli_output("codex_cli", fixtures["codex_cli"])["verdict"] == "approve"
    assert parse_cli_output("cursor_cli", fixtures["cursor_cli"])["verdict"] == "reject"
    assert parse_cli_output("claude_cli", fixtures["claude_cli"])["verdict"] == "approve"
    assert parse_cli_output("pi_cli", fixtures["pi_cli"])["verdict"] == "approve"


def test_codex_home_is_passed_only_by_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "codex"
    exe.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"type":"item.completed","item":{"type":"agent_message","text":"{}"}}\' \'{"type":"turn.completed"}\'\n')
    exe.chmod(0o700)
    adapter = CliHarnessAdapter(
        adapter_id="codex", kind="codex_cli", executable=str(exe), model="m", provider="openai",
        credential_env=(), timeout_seconds=5, allowed_cwd_roots=(str(tmp_path),),
        runner=SubprocessRunner(artifact_dir=tmp_path / "out", allowlisted_env=()), codex_home=str(tmp_path / "home"),
    )
    request = HarnessRequest("r", "t", "a", "o", "private-prompt", str(tmp_path), 5, {"type":"object"}, (), str(tmp_path / "out"), {})
    result = adapter.execute(request)
    assert result.status == "success"
    metadata = (tmp_path / "out" / "process-result.json").read_text()
    assert "private-prompt" not in metadata
    assert "--codex-home" not in metadata


def test_cli_resume_writes_checkpoint_and_executes(tmp_path: Path) -> None:
    exe = tmp_path / "claude"
    exe.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"type":"assistant","message":{"content":"{}"}}\' \'{"type":"result","is_error":false}\'\n')
    exe.chmod(0o700)
    adapter = CliHarnessAdapter(
        adapter_id="x", kind="claude_cli", executable=str(exe), model="m", provider="p",
        credential_env=(), timeout_seconds=5, allowed_cwd_roots=(str(tmp_path),),
        runner=SubprocessRunner(artifact_dir=tmp_path, allowlisted_env=()),
    )
    request = HarnessRequest("r", "t", "a", "o", "p", str(tmp_path), 5, None, (), str(tmp_path), {})
    result = adapter.resume(request, "session")
    assert result.status == "success"
    assert (tmp_path / "harness-session.json").is_file()
