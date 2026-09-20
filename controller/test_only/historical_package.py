"""Reconstruct a pinned historical runner only inside the verified test sandbox."""
import hashlib
import json
from pathlib import Path
import tempfile

from test_only.isolation import require_isolation

PACKAGE = Path(__file__).resolve().parent / 'historical'
REPO = PACKAGE.parents[2]


def verified_sources():
    manifest = json.loads((PACKAGE / 'manifest.json').read_text())
    if manifest.get('test_only') is not True:
        raise ValueError('historical package is not test-only')
    sources = []
    for item in manifest['sources']:
        relative = Path(item['path'])
        source = (REPO / item['packaged']).resolve()
        if relative.is_absolute() or '..' in relative.parts or not source.is_relative_to(REPO):
            raise ValueError('historical package path escape')
        content = source.read_bytes()
        if hashlib.sha256(content).hexdigest() != item['sha256']:
            raise ValueError('historical source hash mismatch: ' + str(relative))
        sources.append((relative, content))
    return sources


def materialize(admin_url):
    require_isolation(admin_url)  # before even mkdir; no host-file fallback
    sources = verified_sources()  # every byte verified before writing any copy
    root = Path(tempfile.mkdtemp(prefix='historical-test-', dir='/etc/top-delivery'))
    for relative, content in sources:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o600)
    return root
