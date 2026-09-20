#!/usr/bin/env python3
"""Install or validate the canonical top-delivery skill across harness homes."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


class SkillInstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallReport:
    installed: bool = False
    unchanged: bool = False
    updated: list[str] | None = None


@dataclass(frozen=True)
class CheckReport:
    ok: bool
    missing: list[str]
    divergent: list[str]


DESTINATION_LAYOUT = {
    "codex": (".codex", "skills", "top-delivery", "SKILL.md"),
    "qwen": (".qwen", "skills", "top-delivery", "SKILL.md"),
    "claude": (".claude", "skills", "top-delivery", "SKILL.md"),
    "pi": (".pi", "agent", "skills", "top-delivery", "SKILL.md"),
    "cursor": (".cursor", "skills", "top-delivery", "SKILL.md"),
}


def default_source() -> Path:
    return Path(__file__).resolve().parents[1] / "skills" / "top-delivery" / "SKILL.md"


def destination_paths(home: Path) -> dict[str, Path]:
    resolved_home = home.expanduser().resolve()
    return {
        name: resolved_home.joinpath(*parts)
        for name, parts in DESTINATION_LAYOUT.items()
    }


def _safe_read_text(path: Path) -> str:
    if path.is_symlink():
        raise SkillInstallError(f"unsafe pre-existing symlink at {path}")
    return path.read_text()


def _same_content(left: Path, right: Path) -> bool:
    if not left.exists() or not right.exists():
        return False
    if left.is_symlink() or right.is_symlink():
        return False
    return left.read_text() == right.read_text()


def check_installation(home: Path, *, source: Path | None = None) -> CheckReport:
    source_path = (source or default_source()).resolve()
    if not source_path.is_file():
        raise SkillInstallError(f"canonical skill source is missing: {source_path}")
    missing: list[str] = []
    divergent: list[str] = []
    for name, dest in destination_paths(home).items():
        if dest.is_symlink():
            divergent.append(name)
            continue
        if not dest.exists():
            missing.append(name)
            continue
        if not _same_content(dest, source_path):
            divergent.append(name)
    return CheckReport(ok=not missing and not divergent, missing=missing, divergent=divergent)


def _atomic_copy(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        if dest.is_symlink():
            dest.unlink()
        elif dest.is_file():
            dest.unlink()
        elif dest.is_dir():
            raise SkillInstallError(f"destination is a directory: {dest}")
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    shutil.copyfile(source, tmp)
    os.replace(tmp, dest)


def install(home: Path, *, source: Path | None = None, force: bool = False) -> InstallReport:
    source_path = (source or default_source()).resolve()
    if not source_path.is_file():
        raise SkillInstallError(f"canonical skill source is missing: {source_path}")
    updated: list[str] = []
    unchanged = True
    for name, dest in destination_paths(home).items():
        if dest.is_symlink():
            if force:
                dest.unlink()
            else:
                raise SkillInstallError(f"divergent destination requires --force: {name}")
        if dest.exists() and not _same_content(dest, source_path):
            if force:
                dest.unlink()
            else:
                raise SkillInstallError(f"divergent destination requires --force: {name}")
        if dest.exists() and _same_content(dest, source_path):
            continue
        _atomic_copy(source_path, dest)
        updated.append(name)
        unchanged = False
    return InstallReport(installed=bool(updated), unchanged=unchanged, updated=updated)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install or validate top-delivery skills")
    parser.add_argument("--home", default=str(Path.home()))
    parser.add_argument("--source", default=None)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--install", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    home = Path(args.home)
    source = Path(args.source) if args.source else None
    try:
        if args.check:
            report = check_installation(home, source=source)
            payload = {
                "ok": report.ok,
                "missing": report.missing,
                "divergent": report.divergent,
            }
            sys.stdout.write(f"{payload}\n")
            return 0 if report.ok else 1
        report = install(home, source=source, force=args.force)
        sys.stdout.write(f"{report}\n")
        return 0
    except SkillInstallError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
