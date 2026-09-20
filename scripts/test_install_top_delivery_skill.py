"""Unit tests for top-delivery skill installer/validator."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE = Path(__file__).with_name("install_top_delivery_skill.py")
SPEC = importlib.util.spec_from_file_location("install_top_delivery_skill", MODULE)
assert SPEC and SPEC.loader
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)

REPO_SKILL = Path(__file__).resolve().parents[1] / "skills" / "top-delivery" / "SKILL.md"


def test_destination_mapping_uses_home_relative_paths(tmp_path: Path) -> None:
    mapping = installer.destination_paths(tmp_path)
    assert mapping["codex"] == tmp_path / ".codex" / "skills" / "top-delivery" / "SKILL.md"
    assert mapping["cursor"] == tmp_path / ".cursor" / "skills" / "top-delivery" / "SKILL.md"
    assert mapping["qwen"] == tmp_path / ".qwen" / "skills" / "top-delivery" / "SKILL.md"


def test_check_reports_missing_destinations(tmp_path: Path) -> None:
    report = installer.check_installation(tmp_path, source=REPO_SKILL)
    assert report.ok is False
    assert report.missing


def test_install_is_idempotent(tmp_path: Path) -> None:
    first = installer.install(tmp_path, source=REPO_SKILL, force=False)
    second = installer.install(tmp_path, source=REPO_SKILL, force=False)
    assert first.installed
    assert second.unchanged
    check = installer.check_installation(tmp_path, source=REPO_SKILL)
    assert check.ok is True


def test_divergent_destination_requires_force(tmp_path: Path) -> None:
    dest = installer.destination_paths(tmp_path)["codex"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("divergent\n")
    with pytest.raises(installer.SkillInstallError, match="divergent"):
        installer.install(tmp_path, source=REPO_SKILL, force=False)
    repaired = installer.install(tmp_path, source=REPO_SKILL, force=True)
    assert repaired.installed
    assert dest.read_text() == REPO_SKILL.read_text()
