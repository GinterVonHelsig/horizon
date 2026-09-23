"""Stage an allowlisted reviewer release; never installs or invokes a model."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = (
    'artifact_isolation.py', 'artifact_owner.py', 'auditor_bind.py',
    'bounded_delivery.py', 'model_routing.py', 'prompt_ingest.py', 'qualification_profile.py',
    'review_execution.py', 'source_test_recipe.py', 'submission_bundle.py',
    'subworkflow_handoff.py',
    *(f'harness_adapters/{name}.py' for name in (
        '__init__', 'cli_adapters', 'contract', 'executable_policy', 'http_adapters',
        'identity', 'redaction', 'registry', 'schema', 'structured_result', 'subprocess_runner')),
)
SOURCES = (
    *(f'controller/{name}' for name in CONTROLLER),
    'tools/host_review/package.py', 'tools/host_review/host_review.py', 'tools/host_review/release_entry.py',
    'tools/host_review/consumer.example.json', 'tools/host_review/requirements.txt',
    'tools/host_review/PROVENANCE.md', 'architecture/model-routing.yaml',
)
WRAPPER = b'''#!/usr/bin/env -S python3 -I
import runpy
import sys
from pathlib import Path
sys.dont_write_bytecode = True
runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/host_review/release_entry.py"), run_name="__main__")
'''


def stage(destination: Path, *, allow_uncommitted: bool = False) -> dict:
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    files = {}
    dirty = []
    for name in SOURCES:
        path = ROOT / name
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('source symlinks are forbidden')
        data = path.read_bytes()
        committed = subprocess.run(['git', 'show', f'{revision}:{name}'], cwd=ROOT, capture_output=True)
        if committed.returncode or committed.stdout != data:
            dirty.append(name)
        files[name] = data
    if dirty and not allow_uncommitted:
        raise ValueError('uncommitted package inputs; commit first or explicitly stage a TEST_ONLY package')
    files['bin/cursor-independent-review'] = WRAPPER
    # Compatibility is argv forwarding only, never provider-name translation.
    files['bin/openrouter-review'] = WRAPPER
    manifest = {'schema': 'horizon-review-release.v1', 'source_commit': revision,
        'source_state': 'TEST_ONLY_UNCOMMITTED' if dirty else 'committed',
        'uncommitted_inputs': dirty, 'runtime': {'python': '>=3.11', 'PyYAML': '6.0.2'},
        'files': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}
    destination = destination.absolute()
    if any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError('destination symlinks are forbidden')
    # Refuse overwrite, including a partial previous build. No install destinations/defaults.
    destination.mkdir(parents=False, exist_ok=False, mode=0o755)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if name.startswith('bin/') else 0o644)
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new staging directory; parent must exist')
    parser.add_argument('--allow-uncommitted', action='store_true', help='label output TEST_ONLY; never deploy')
    args = parser.parse_args()
    print(json.dumps(stage(args.output, allow_uncommitted=args.allow_uncommitted), indent=2))


if __name__ == '__main__':
    main()
