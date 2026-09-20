"""Run-specific artifact roots, attempt canaries, and a non-root adapter HOME."""

from __future__ import annotations

import os
import shutil
import stat
import uuid
from pathlib import Path

DEFAULT_RUNS_ROOT = Path("/var/lib/top-delivery/runs")
SAFE_ADAPTER_HOME = "/var/lib/top-delivery/adapter-runtime/home"
_FORBIDDEN_HOMES = {"", "/root", "/", "/nonexistent"}


def load_relay_token() -> None:
    """Load the OpenRouter relay token from its env file into the process env."""
    env_file = os.environ.get(
        "TOP_DELIVERY_OPENROUTER_RELAY_TOKEN_FILE",
        "/etc/top-delivery/openrouter-relay.env",
    )
    path = Path(env_file)
    if path.is_file():
        for line in path.read_text().splitlines():
            if line.startswith("TOP_DELIVERY_OPENROUTER_RELAY_TOKEN="):
                os.environ["TOP_DELIVERY_OPENROUTER_RELAY_TOKEN"] = line.split("=", 1)[1].strip()
                return


def resolve_run_artifact_root(
    run_id: str,
    configured: Path,
    *,
    runs_root: Path = DEFAULT_RUNS_ROOT,
) -> Path:
    configured = Path(configured).resolve()
    dedicated = (Path(runs_root) / run_id / "artifacts").resolve()
    try:
        relative = configured.relative_to(Path(runs_root).resolve())
    except ValueError:
        return configured
    parts = relative.parts
    if parts and parts[0] != run_id:
        return dedicated
    return configured


def ensure_run_spec(
    run_id: str,
    *,
    configured: Path,
    dedicated: Path,
) -> None:
    dest = dedicated / "runs" / run_id
    dest.mkdir(parents=True, exist_ok=True)
    src = Path(configured) / "runs" / run_id
    if not src.is_dir() or src.resolve() == dest.resolve():
        return
    for name in ("goal-spec.json", "prompt.snapshot.md", "goal-state.json"):
        source = src / name
        target = dest / name
        if source.is_file() and not target.exists():
            shutil.copy2(source, target)


def preflight_attempt_canary(artifact_root: Path, run_id: str) -> None:
    root = Path(artifact_root).resolve()
    attempts = root / "runs" / run_id / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    canary = attempts / f"canary-{uuid.uuid4().hex}"
    canary.mkdir(mode=0o750)
    probe = canary / ".writable"
    probe.write_text("ok\n")
    probe.unlink()
    canary.rmdir()
    mode = stat.S_IMODE(attempts.stat().st_mode)
    if mode & 0o077:
        os.chmod(attempts, 0o750)


def apply_safe_home(env: dict[str, str]) -> dict[str, str]:
    current = env.get("HOME", "")
    if current in _FORBIDDEN_HOMES or Path(current).as_posix() == "/root":
        env["HOME"] = os.environ.get("TOP_DELIVERY_ADAPTER_HOME", SAFE_ADAPTER_HOME)
    home = Path(env.get("HOME", ""))
    cursor_auth = home / ".config" / "cursor" / "auth.json"
    if cursor_auth.is_file():
        env.setdefault("CURSOR_CONFIG_DIR", str(home / ".config" / "cursor"))
    return env
