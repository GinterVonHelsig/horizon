"""Out-of-band trust anchor for Comms-01 live snapshot signatures."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from operator_asymmetric import verify_message_signature  # noqa: E402
from artifact_signing import domain_separated_message  # noqa: E402


CONTROLLER_PUBLIC_KEY = Path(__file__).resolve().parent / "trust" / "comms01-live-snapshot-signing.pub"
OPERATOR_PUBLIC_KEY = Path("/etc/top-delivery/comms01-live-snapshot-signing.pub")
EXPECTED_PUBLIC_KEY_SHA256 = "ce4f3ad8434b68f3a4da8f102b9ff8d8a11743d68f0fe973293046556e2b3488"
RELEASE_PROVENANCE = Path("/etc/top-delivery/comms01-release-provenance.json")
RELEASE_PROVENANCE_KEY = Path("/etc/top-delivery/comms01-release-provenance.pub")
RELEASE_PROVENANCE_KEY_SHA256 = "ea4509835ced8af7a6491b23ba9f338da59377e993205e9cc677e524c7c94bfb"
CONTENT_DIGEST_SCOPE = (
    "regular-files-v1;relative-posix-path;mode;size;sha256;"
    "excludes-symlinks-pyc-and-pycache"
)


def _read_public_key(path: Path, *, require_root: bool) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"live snapshot trust anchor is unavailable: {path}")
    mode = path.stat()
    if not stat.S_ISREG(mode.st_mode) or mode.st_mode & 0o022:
        raise ValueError(f"live snapshot trust anchor permissions are unsafe: {path}")
    if require_root and mode.st_uid != 0:
        raise ValueError(f"live snapshot trust anchor is not root-owned: {path}")
    value = path.read_text(encoding="ascii").strip()
    if not value or "\n" in value:
        raise ValueError(f"live snapshot trust anchor is malformed: {path}")
    return value


def read_pinned_live_snapshot_key() -> tuple[str, str]:
    candidate = _read_public_key(CONTROLLER_PUBLIC_KEY, require_root=False)
    operator = _read_public_key(OPERATOR_PUBLIC_KEY, require_root=True)
    digest = hashlib.sha256(operator.encode("ascii")).hexdigest()
    if candidate != operator:
        raise ValueError(
            "controller-side live-snapshot public key drifted from the root-owned anchor"
        )
    if digest != EXPECTED_PUBLIC_KEY_SHA256:
        raise ValueError(
            "root-owned live-snapshot public key does not match its pinned digest"
        )
    return operator, digest


def deployed_content_digest(working_directory: str) -> str:
    root = Path(working_directory)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("deployed Comms-01 working directory is not a regular directory")
    files: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"deployed checkout contains an unexpected symlink: {path}")
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        data = path.read_bytes()
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "mode": stat.S_IMODE(path.stat().st_mode),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    canonical = json.dumps(
        files, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def read_signed_release_provenance(
    *, working_directory: str, deployed_sha: str
) -> dict[str, str]:
    if (
        not RELEASE_PROVENANCE.is_file()
        or RELEASE_PROVENANCE.is_symlink()
        or RELEASE_PROVENANCE.stat().st_uid != 0
        or RELEASE_PROVENANCE.stat().st_mode & 0o077
        or not RELEASE_PROVENANCE_KEY.is_file()
        or RELEASE_PROVENANCE_KEY.is_symlink()
        or RELEASE_PROVENANCE_KEY.stat().st_uid != 0
        or RELEASE_PROVENANCE_KEY.stat().st_mode & 0o022
    ):
        raise ValueError("signed Comms-01 release provenance is unavailable")
    verify_key = RELEASE_PROVENANCE_KEY.read_text(encoding="ascii").strip()
    if hashlib.sha256(verify_key.encode("ascii")).hexdigest() != RELEASE_PROVENANCE_KEY_SHA256:
        raise ValueError("signed Comms-01 release provenance key anchor is invalid")
    payload = json.loads(RELEASE_PROVENANCE.read_text(encoding="utf-8"))
    required = {
        "schema",
        "working_directory",
        "deployed_sha",
        "deployed_tree_sha",
        "deployed_content_sha256",
        "deployed_content_digest_scope",
        "source",
        "artifact_sha256",
        "signature_algorithm",
        "signature",
        "verify_key_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("signed Comms-01 release provenance fields are invalid")
    body = dict(payload)
    artifact_sha256 = body.pop("artifact_sha256")
    signature = body.pop("signature")
    body.pop("signature_algorithm")
    body.pop("verify_key_sha256")
    expected = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if (
        payload["schema"] != "top-delivery/comms01-release-provenance/v1"
        or payload["working_directory"] != working_directory
        or payload["deployed_sha"] != deployed_sha
        or not isinstance(payload["deployed_content_sha256"], str)
        or len(payload["deployed_content_sha256"]) != 64
        or payload["deployed_content_digest_scope"] != CONTENT_DIGEST_SCOPE
        or payload["signature_algorithm"]
        != "Ed25519 over domain-separated artifact_sha256"
        or payload["verify_key_sha256"] != RELEASE_PROVENANCE_KEY_SHA256
        or artifact_sha256 != expected
        or not verify_message_signature(
            domain_separated_message(str(payload["schema"]), artifact_sha256),
            signature,
            verify_key,
        )
    ):
        raise ValueError("signed Comms-01 release provenance verification failed")
    actual_content_sha = deployed_content_digest(working_directory)
    if actual_content_sha != payload["deployed_content_sha256"]:
        raise ValueError("signed Comms-01 release content digest does not match checkout")
    return {
        "working_directory": str(payload["working_directory"]),
        "deployed_sha": str(payload["deployed_sha"]),
        "deployed_tree_sha": str(payload["deployed_tree_sha"]),
        "deployed_content_sha256": str(payload["deployed_content_sha256"]),
        "deployed_content_digest_scope": str(payload["deployed_content_digest_scope"]),
        "source": str(payload["source"]),
        "artifact_sha256": str(artifact_sha256),
    }
