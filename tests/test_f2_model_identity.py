"""Independent identities cannot be manufactured by switching transport or effort."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness_adapters.identity import (
    adapter_effective_identity,
    config_effective_identity,
    identities_conflict,
)
from harness_adapters.registry import validate_registry_config
from test_worker import (
    DEFAULT_CRITERION,
    FakeController,
    FakeTask,
    ScriptedAdapter,
    _success_payload,
)
from worker import TaskWorker


class IdentifiedAdapter(ScriptedAdapter):
    def __init__(
        self,
        adapter_id: str,
        responses: list,
        *,
        provider: str,
        model: str,
    ) -> None:
        super().__init__(adapter_id, responses)
        self.provider = provider
        self.model = model


def _same_identity_registry() -> dict:
    http = {
        "kind": "http_openai",
        "endpoint": "http://127.0.0.1:18765/v1/chat/completions",
        "credential_env": ["TOP_DELIVERY_OPENROUTER_RELAY_TOKEN"],
        "timeout_seconds": 30,
        "allowed_cwd_roots": ["/tmp"],
        "loopback_only": True,
    }
    return {
        "adapters": [
            {**http, "id": "exec-a", "provider": "openrouter", "model": "openai/gpt-5.6-sol"},
            {**http, "id": "audit-b", "provider": "OpenRouter", "model": "OpenAI/GPT-5.6-sol"},
        ],
        "routes": {"default_executor": "exec-a", "default_auditor": "audit-b"},
    }


def _spec(artifact_root: Path) -> None:
    (artifact_root / "runs" / "run-1").mkdir(parents=True)
    (artifact_root / "runs" / "run-1" / "goal-spec.json").write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "workstreams": [
                    {
                        "task_id": "task-1",
                        "executor_adapter": "executor",
                        "auditor_adapter": "auditor",
                        "acceptance_criteria": [DEFAULT_CRITERION],
                    }
                ],
            }
        )
    )


def test_identity_normalizes_case_and_whitespace() -> None:
    left = config_effective_identity({"provider": " OpenRouter ", "model": "OpenAI/GPT-5.6-sol"})
    right = config_effective_identity({"provider": "openrouter", "model": " openai/gpt-5.6-sol "})
    assert identities_conflict(left, right)
    adapter = IdentifiedAdapter("x", [], provider=" HTTP-Relay ", model=" shared-model ")
    assert adapter_effective_identity(adapter) == ("http-relay", "shared-model")
    fake = ScriptedAdapter("executor", [])
    assert adapter_effective_identity(fake) == ("fake", "executor")


def test_identity_conflict_requires_complete_identities() -> None:
    with pytest.raises(ValueError, match="complete"):
        identities_conflict(None, ("openrouter", "openai/gpt-5.6-sol"))
    empty = config_effective_identity({"provider": "openrouter", "model": ":nitro"})
    assert empty is None


def test_identity_fullwidth_colon_collides_and_openrouter_auto_casefolds() -> None:
    left = config_effective_identity({"provider": "openrouter", "model": "openai/gpt-6-astra"})
    wide = config_effective_identity({"provider": "openrouter", "model": "openai/gpt-6-astra：nitro"})
    assert identities_conflict(left, wide)
    config = _same_identity_registry()
    config["adapters"][1]["provider"] = "openrouter"
    config["adapters"][1]["model"] = "OpenRouter/Auto"
    with pytest.raises(ValueError, match="meta-router"):
        validate_registry_config(config, validate_executables=False)
    left = config_effective_identity({"provider": "openrouter", "model": "openai/gpt-6-astra"})
    right = config_effective_identity({"provider": "openrouter", "model": "openai/gpt-6-astra:nitro"})
    assert identities_conflict(left, right)
    wide = config_effective_identity({"provider": "ｏｐｅｎｒｏｕｔｅｒ", "model": "openai/gpt-6-astra"})
    assert identities_conflict(left, wide)


def test_registry_rejects_openrouter_auto_on_non_default_adapter() -> None:
    config = _same_identity_registry()
    config["adapters"][1]["model"] = "openai/gpt-5.6-luna"
    config["adapters"].append(
        {
            **{k: v for k, v in config["adapters"][0].items() if k != "id"},
            "id": "spare-c",
            "provider": "openrouter",
            "model": "OpenRouter/Auto",
        }
    )
    with pytest.raises(ValueError, match="meta-router"):
        validate_registry_config(config, validate_executables=False)


def test_registry_rejects_same_provider_model_under_two_ids() -> None:
    with pytest.raises(ValueError, match="distinct effective identities"):
        validate_registry_config(_same_identity_registry(), validate_executables=False)


def test_registry_rejects_whitespace_only_provider_or_model() -> None:
    config = _same_identity_registry()
    config["adapters"][1]["model"] = "openai/gpt-5.6-luna"
    config["adapters"][0]["model"] = "  "
    with pytest.raises(ValueError, match="model is required"):
        validate_registry_config(config, validate_executables=False)
    config = _same_identity_registry()
    config["adapters"][1]["model"] = "openai/gpt-5.6-luna"
    config["adapters"][0]["provider"] = "  "
    with pytest.raises(ValueError, match="provider identity is required"):
        validate_registry_config(config, validate_executables=False)


def test_registry_rejects_variant_suffix_collision_and_meta_router() -> None:
    config = _same_identity_registry()
    config["adapters"][1]["provider"] = "openrouter"
    config["adapters"][1]["model"] = "openai/gpt-5.6-sol:nitro"
    with pytest.raises(ValueError, match="distinct effective identities"):
        validate_registry_config(config, validate_executables=False)
    config = _same_identity_registry()
    config["adapters"][1]["provider"] = "openrouter"
    config["adapters"][1]["model"] = "openrouter/auto"
    with pytest.raises(ValueError, match="meta-router"):
        validate_registry_config(config, validate_executables=False)
    config = _same_identity_registry()
    config["adapters"][1]["provider"] = "openrouter"
    config["adapters"][1]["model"] = "openrouter/something-else"
    with pytest.raises(ValueError, match="meta-router"):
        validate_registry_config(config, validate_executables=False)
    config = _same_identity_registry()
    config["adapters"][1]["provider"] = "openrouter"
    config["adapters"][1]["model"] = "openai/gpt-5.6-sol:floor"
    with pytest.raises(ValueError, match="distinct effective identities"):
        validate_registry_config(config, validate_executables=False)


def test_registry_allows_distinct_models() -> None:
    config = _same_identity_registry()
    config["adapters"][1]["model"] = "moonshotai/kimi-k3"
    config["adapters"][1]["provider"] = "openrouter"
    validate_registry_config(config, validate_executables=False)


def test_registry_blocks_distinct_models_in_same_known_family() -> None:
    config = _same_identity_registry()
    config["adapters"][1]["model"] = "gpt-6-astra-high"
    config["adapters"][1]["provider"] = "cursor"
    with pytest.raises(ValueError, match="distinct effective identities"):
        validate_registry_config(config, validate_executables=False)


def test_registry_blocks_same_model_across_distinct_providers() -> None:
    config = _same_identity_registry()
    config["adapters"][1]["provider"] = "cursor"
    config["adapters"][1]["model"] = "openai/gpt-5.6-sol"
    with pytest.raises(ValueError, match="distinct effective identities"):
        validate_registry_config(config, validate_executables=False)


def test_worker_blocks_same_provider_model_two_adapter_ids(tmp_path: Path) -> None:
    _spec(tmp_path)
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": IdentifiedAdapter(
            "executor", [_success_payload()], provider="http-relay", model="openai/gpt-5.6-sol"
        ),
        "auditor": IdentifiedAdapter(
            "auditor", [_success_payload("approve")], provider="HTTP-Relay", model="OpenAI/GPT-5.6-sol"
        ),
    }
    result = TaskWorker(controller, tmp_path, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "blocked"
    assert controller.completions[-1] == ("task-1", "blocked")
    assert adapters["executor"].calls == 0
    assert adapters["auditor"].calls == 0


def test_worker_allows_distinct_model_same_provider(tmp_path: Path) -> None:
    _spec(tmp_path)
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": IdentifiedAdapter(
            "executor", [_success_payload()], provider="http-relay", model="openai/gpt-5.6-sol"
        ),
        "auditor": IdentifiedAdapter(
            "auditor", [_success_payload("approve")], provider="http-relay", model="moonshotai/kimi-k3"
        ),
    }
    result = TaskWorker(controller, tmp_path, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "verified"


@pytest.mark.parametrize("writer_model,reviewer_model", [
    ("shared-model", "shared-model"),
    ("gpt-6-astra", "openai/gpt-6-astra:nitro"),
    ("gpt-6-astra", "gpt-5.6-sol-max"),
])
def test_worker_blocks_distinct_provider_same_model(tmp_path: Path, writer_model: str, reviewer_model: str) -> None:
    _spec(tmp_path)
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": IdentifiedAdapter(
            "executor", [_success_payload()], provider="http-relay", model=writer_model
        ),
        "auditor": IdentifiedAdapter(
            "auditor", [_success_payload("approve")], provider="cursor-cli", model=reviewer_model
        ),
    }
    result = TaskWorker(controller, tmp_path, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "blocked"
    assert adapters["executor"].calls == 0
    assert adapters["auditor"].calls == 0


def test_worker_blocks_incomplete_identity_before_execute(tmp_path: Path) -> None:
    _spec(tmp_path)
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": IdentifiedAdapter(
            "executor", [_success_payload()], provider="http-relay", model="openai/gpt-5.6-sol"
        ),
        "auditor": IdentifiedAdapter(
            "auditor", [_success_payload("approve")], provider="http-relay", model="   "
        ),
    }
    result = TaskWorker(controller, tmp_path, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "blocked"
    assert adapters["executor"].calls == 0
    assert adapters["auditor"].calls == 0


def test_worker_blocks_openrouter_auto_before_execute(tmp_path: Path) -> None:
    _spec(tmp_path)
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": IdentifiedAdapter(
            "executor", [_success_payload()], provider="openrouter", model="openai/gpt-5.6-sol"
        ),
        "auditor": IdentifiedAdapter(
            "auditor", [_success_payload("approve")], provider="openrouter", model="OpenRouter/Auto"
        ),
    }
    result = TaskWorker(controller, tmp_path, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "blocked"
    assert adapters["executor"].calls == 0
    assert adapters["auditor"].calls == 0


def test_worker_id_only_fakes_with_distinct_models_still_run(tmp_path: Path) -> None:
    _spec(tmp_path)
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    adapters = {
        "executor": ScriptedAdapter("executor", [_success_payload()]),
        "auditor": ScriptedAdapter("auditor", [_success_payload("approve")]),
    }
    result = TaskWorker(controller, tmp_path, adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "verified"


def test_worker_blocks_non_default_registry_pair_sharing_identity(tmp_path: Path) -> None:
    from harness_adapters.registry import AdapterRegistry

    config = {
        "adapters": [
            {
                "id": "exec-a",
                "kind": "http_openai",
                "provider": "openrouter",
                "endpoint": "http://127.0.0.1:18765/v1/chat/completions",
                "model": "openai/gpt-5.6-sol",
                "credential_env": ["TOP_DELIVERY_OPENROUTER_RELAY_TOKEN"],
                "timeout_seconds": 30,
                "allowed_cwd_roots": ["/tmp"],
                "loopback_only": True,
            },
            {
                "id": "audit-b",
                "kind": "http_openai",
                "provider": "openrouter",
                "endpoint": "http://127.0.0.1:18765/v1/chat/completions",
                "model": "moonshotai/kimi-k3",
                "credential_env": ["TOP_DELIVERY_OPENROUTER_RELAY_TOKEN"],
                "timeout_seconds": 30,
                "allowed_cwd_roots": ["/tmp"],
                "loopback_only": True,
            },
            {
                "id": "exec-c",
                "kind": "http_openai",
                "provider": "openrouter",
                "endpoint": "http://127.0.0.1:18765/v1/chat/completions",
                "model": "openai/gpt-5.6-sol",
                "credential_env": ["TOP_DELIVERY_OPENROUTER_RELAY_TOKEN"],
                "timeout_seconds": 30,
                "allowed_cwd_roots": ["/tmp"],
                "loopback_only": True,
            },
        ],
        "routes": {"default_executor": "exec-a", "default_auditor": "audit-b"},
    }
    registry = AdapterRegistry.from_config(
        config, artifact_dir=tmp_path / "adapters", validate_executables=False
    )
    (tmp_path / "runs" / "run-1").mkdir(parents=True)
    (tmp_path / "runs" / "run-1" / "goal-spec.json").write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "workstreams": [
                    {
                        "task_id": "task-1",
                        "executor_adapter": "exec-a",
                        "auditor_adapter": "exec-c",
                        "acceptance_criteria": [DEFAULT_CRITERION],
                    }
                ],
            }
        )
    )
    controller = FakeController()
    controller.tasks["task-1"] = FakeTask("task-1", "run-1", "obj", state="scheduled")
    result = TaskWorker(controller, tmp_path, registry.adapters).run_once("run-1", "worker")  # type: ignore[arg-type]
    assert result is not None
    assert result.terminal_state == "blocked"
