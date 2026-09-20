"""Durable capability-provider handoff contracts and validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9._:@-]{1,160}$")
SAFE_FAILURE = re.compile(r"^[A-Z0-9_:-]{1,120}$")
SAFE_PRODUCT = re.compile(r"^[a-z0-9][a-z0-9._:-]{1,120}$")
SECRET_FIELD = re.compile(r"(?i)(password|secret|token|private[_-]?key|api[_-]?key|database[_-]?url)")
FORBIDDEN_VALUE = re.compile(r"(?i)(-----BEGIN .* PRIVATE KEY-----|postgres(?:ql)?://[^\s]+:[^\s@]+@)")


class HandoffValidationError(ValueError):
    """Raised when a handoff or provider product violates its contract."""


@dataclass(frozen=True)
class ProviderContract:
    failure_code: str
    provider_key: str
    target: str
    product_contract: str
    objective: str
    executor_adapter: str
    auditor_adapter: str
    allowed_mutations: tuple[str, ...]
    forbidden_mutations: tuple[str, ...]
    timeout_seconds: int = 1800
    max_attempts: int = 5

    @property
    def allowed_mutations_digest(self) -> str:
        return digest_value(self.allowed_mutations)

    @property
    def forbidden_mutations_digest(self) -> str:
        return digest_value(self.forbidden_mutations)


HORIZON_PREREQ_FAILURE = "BLOCKED_HORIZON_PREREQ_MISSING"

HORIZON_PREREQ_CONTRACT = ProviderContract(
    failure_code=HORIZON_PREREQ_FAILURE,
    provider_key="gateway-horizon-prerequisite-provider",
    target="horizon-prerequisite-delivery",
    product_contract="horizon-prerequisite-product.v1",
    objective="Deliver missing Horizon prerequisite under the same authorized envelope",
    executor_adapter="gateway-delivery",
    auditor_adapter="openrouter-independent-review",
    allowed_mutations=(
        "isolated-worktree:implementation-and-disposable-tests-only",
        "artifact-root:sanitized-evidence-only",
    ),
    forbidden_mutations=(
        "production-vm9005",
        "broker-trading",
        "live-database-mutation",
        "top-delivery-current-retarget",
        "supervisor-enable",
    ),
)

VM9201_CONTRACT = ProviderContract(
    failure_code="BLOCKED_VM9201_DISPOSABLE_SEAM",
    provider_key="gateway-vm9201-capability-provider",
    target="vm9201-disposable-seam",
    product_contract="vm9201-disposable-seam.v1",
    objective="Provision and validate the missing VM 9201 disposable capability seam",
    executor_adapter="cursor-cli",
    auditor_adapter="openrouter-claude-auditor",
    allowed_mutations=(
        "vm9201:td_test_*:dedicated-role-and-capability-only",
        "vm9201:td_downgrade_*:dedicated-role-and-capability-only",
        "comms01-02:credential-ref-and-sanitized-evidence-only",
    ),
    forbidden_mutations=(
        "vm9201:bridge_observability",
        "vm9201:production",
        "remote-root",
        "authority-keys",
        "broker-trading",
        "unrestricted-commands",
    ),
)

PROVIDER_REGISTRY: dict[str, ProviderContract] = {
    VM9201_CONTRACT.failure_code: VM9201_CONTRACT,
    HORIZON_PREREQ_CONTRACT.failure_code: HORIZON_PREREQ_CONTRACT,
}


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _validate_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise HandoffValidationError(f"{field}_invalid")
    return value


def _validate_hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise HandoffValidationError(f"{field}_invalid")
    return value


def _scan_secret(value: Any, *, field: str = "value") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if SECRET_FIELD.search(str(key)) and str(key) not in {"credential_ref", "capability_sha256"}:
                raise HandoffValidationError(f"{field}_secret_field")
            _scan_secret(child, field=f"{field}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_secret(child, field=f"{field}.{index}")
    elif isinstance(value, str) and FORBIDDEN_VALUE.search(value):
        raise HandoffValidationError(f"{field}_secret_value")


def _validate_relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise HandoffValidationError(f"{field}_invalid")
    path = Path(value)
    if ".." in path.parts or path.is_absolute() or "\\" in value:
        raise HandoffValidationError(f"{field}_invalid")
    return path.as_posix()


def provider_for_failure(failure_code: str) -> ProviderContract | None:
    return PROVIDER_REGISTRY.get(failure_code)


def build_handoff_request(
    *,
    run_id: str,
    parent_task_id: str,
    parent_attempt_id: str,
    failure_code: str,
    request_artifact_root: str,
    handoff_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    contract = provider_for_failure(failure_code)
    if contract is None:
        raise HandoffValidationError("no_registered_subworkflow")
    _validate_id(run_id, "run_id")
    _validate_id(parent_task_id, "parent_task_id")
    _validate_id(parent_attempt_id, "parent_attempt_id")
    if not SAFE_FAILURE.fullmatch(failure_code):
        raise HandoffValidationError("failure_code_invalid")
    evidence_root = _validate_relative_path(request_artifact_root, "evidence_root")
    immutable: dict[str, Any] = {
        "schema_version": "gateway-subworkflow-handoff.v1",
        "run_id": run_id,
        "parent_task_id": parent_task_id,
        "failure_code": failure_code,
        "target": contract.target,
        "product_contract": contract.product_contract,
        "provider_route": contract.provider_key,
        "allowed_mutations_digest": contract.allowed_mutations_digest,
        "forbidden_mutations_digest": contract.forbidden_mutations_digest,
    }
    if handoff_context:
        if not isinstance(handoff_context, Mapping):
            raise HandoffValidationError("handoff_context_invalid")
        for key, value in handoff_context.items():
            if not isinstance(key, str) or not SAFE_ID.fullmatch(key):
                raise HandoffValidationError("handoff_context_key_invalid")
            if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
                raise HandoffValidationError("handoff_context_value_invalid")
        immutable["handoff_context"] = {key: handoff_context[key] for key in sorted(handoff_context)}
    request_digest = digest_value(immutable)
    handoff_id = f"handoff-{request_digest[:32]}"
    provider_task_id = f"{parent_task_id}-handoff-{request_digest[:12]}"
    request = {
        **immutable,
        "handoff_id": handoff_id,
        "parent_attempt_id": parent_attempt_id,
        "objective": contract.objective,
        "executor_adapter": contract.executor_adapter,
        "auditor_adapter": contract.auditor_adapter,
        "evidence_root": evidence_root,
        "timeout_seconds": contract.timeout_seconds,
        "max_attempts": contract.max_attempts,
        "provider_task_id": provider_task_id,
        "request_digest": request_digest,
        "status": "created",
    }
    _scan_secret(request)
    return request


def _validate_target_identity(value: Any, contract: ProviderContract) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise HandoffValidationError("target_identity_missing")
    expected = {"vmid": "9201", "endpoint": "192.168.0.96:5432"}
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise HandoffValidationError("target_identity_mismatch")
    source = value.get("source")
    if source not in {"192.168.0.91", "192.168.0.92"}:
        raise HandoffValidationError("target_source_invalid")
    return {key: str(value[key]) for key in ("vmid", "endpoint", "source")}


def validate_product(product_path: Path, request: Mapping[str, Any], artifact_root: Path) -> dict[str, Any]:
    product_path = product_path.resolve()
    artifact_root = artifact_root.resolve()
    if not product_path.is_file() or product_path.is_symlink() or not product_path.is_relative_to(artifact_root):
        raise HandoffValidationError("product_path_invalid")
    if product_path.stat().st_size > 256 * 1024:
        raise HandoffValidationError("product_too_large")
    try:
        product = json.loads(product_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoffValidationError("product_json_invalid") from exc
    if not isinstance(product, dict):
        raise HandoffValidationError("product_not_object")
    _scan_secret(product)
    allowed_product_keys = {
        "schema_version", "product_contract", "handoff_id", "parent_run_id",
        "parent_task_id", "provider_run_id", "disposition", "target_identity",
        "capability", "artifacts", "rollback", "provenance", "bounded_error", "status",
    }
    if set(product) != allowed_product_keys:
        raise HandoffValidationError("product_keys_invalid")
    contract = provider_for_failure(str(request.get("failure_code", "")))
    if contract is None:
        raise HandoffValidationError("no_registered_subworkflow")
    if product.get("schema_version") != "gateway-subworkflow-product.v1":
        raise HandoffValidationError("product_schema_invalid")
    if product.get("product_contract") != contract.product_contract:
        raise HandoffValidationError("product_contract_mismatch")
    if product.get("handoff_id") != request.get("handoff_id"):
        raise HandoffValidationError("handoff_id_mismatch")
    if product.get("parent_run_id") != request.get("run_id") or product.get("parent_task_id") != request.get("parent_task_id"):
        raise HandoffValidationError("parent_binding_mismatch")
    provider_run_id = _validate_id(product.get("provider_run_id"), "provider_run_id")
    disposition = product.get("disposition")
    if disposition != "PASS_VM9201_DISPOSABLE_SEAM":
        raise HandoffValidationError("product_disposition_invalid")
    target_identity = _validate_target_identity(product.get("target_identity"), contract)
    capability = product.get("capability")
    if not isinstance(capability, Mapping) or capability.get("role_authenticated") is not True or capability.get("disposable_harness_readable") is not True:
        raise HandoffValidationError("capability_proof_missing")
    namespace = capability.get("database_namespace")
    if not isinstance(namespace, str) or not (namespace.startswith("td_test_") or namespace.startswith("td_downgrade_")):
        raise HandoffValidationError("capability_namespace_invalid")
    _validate_hex(capability.get("capability_sha256"), "capability_sha256")
    if not isinstance(capability.get("credential_ref"), str) or not SAFE_ID.fullmatch(capability["credential_ref"]):
        raise HandoffValidationError("credential_ref_invalid")
    rollback = product.get("rollback")
    if not isinstance(rollback, Mapping) or rollback.get("status") != "available":
        raise HandoffValidationError("rollback_proof_missing")
    rollback_path = _validate_relative_path(rollback.get("artifact_path"), "rollback_artifact_path")
    rollback_file = (product_path.parent / rollback_path).resolve()
    if not rollback_file.is_file() or rollback_file.is_symlink() or not rollback_file.is_relative_to(artifact_root):
        raise HandoffValidationError("rollback_artifact_missing")
    artifacts = product.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 32:
        raise HandoffValidationError("product_artifacts_invalid")
    validated_artifacts = []
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            raise HandoffValidationError("product_artifact_invalid")
        artifact_path = _validate_relative_path(artifact.get("path"), "artifact_path")
        artifact_sha256 = _validate_hex(artifact.get("sha256"), "artifact_sha256")
        artifact_bytes = artifact.get("bytes")
        if type(artifact_bytes) is not int or artifact_bytes < 0:
            raise HandoffValidationError("artifact_bytes_invalid")
        artifact_file = (product_path.parent / artifact_path).resolve()
        if not artifact_file.is_file() or artifact_file.is_symlink() or not artifact_file.is_relative_to(artifact_root):
            raise HandoffValidationError("artifact_missing")
        if artifact_file.stat().st_size != artifact_bytes:
            raise HandoffValidationError("artifact_size_mismatch")
        if hashlib.sha256(artifact_file.read_bytes()).hexdigest() != artifact_sha256:
            raise HandoffValidationError("artifact_digest_mismatch")
        validated_artifacts.append({"path": artifact_path, "sha256": artifact_sha256, "bytes": artifact_bytes})
    return {
        "provider_run_id": provider_run_id,
        "disposition": disposition,
        "target_identity": target_identity,
        "capability": {
            "role_authenticated": True,
            "disposable_harness_readable": True,
            "database_namespace": namespace,
            "credential_ref": capability["credential_ref"],
            "capability_sha256": capability["capability_sha256"],
        },
        "rollback_artifact_path": rollback_path,
        "artifacts": validated_artifacts,
        "product_sha256": hashlib.sha256(product_path.read_bytes()).hexdigest(),
    }


def detect_capability_failure(attempt_root: Path, structured_payload: Mapping[str, Any] | None = None) -> str | None:
    candidates: list[str] = []
    if isinstance(structured_payload, Mapping):
        extracted = structured_payload.get("extracted_json")
        if isinstance(extracted, Mapping) and isinstance(extracted.get("disposition"), str):
            candidates.append(extracted["disposition"])
        if isinstance(structured_payload.get("disposition"), str):
            candidates.append(structured_payload["disposition"])
    for path in sorted(attempt_root.rglob("*.json")):
        if len(candidates) >= 4:
            break
        if path.is_symlink() or path.stat().st_size > 256 * 1024:
            continue
        if not (path.name.endswith("-disposition.json") or path.name == "acceptance-results.json"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(payload, Mapping) and isinstance(payload.get("disposition"), str):
            candidates.append(payload["disposition"])
    for candidate in candidates:
        if provider_for_failure(candidate) is not None:
            return candidate
    return None
