"""Packaged consumer entry point. Configuration failures exit 78 before transport."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys


def trusted_bytes(path: Path) -> bytes:
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('symlink in trusted input')
    info = path.stat()
    if not path.is_file() or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        raise ValueError('trusted input must be an owned non-writable regular file')
    return path.read_bytes()


def pinned(path: Path, expected: str) -> bytes:
    data = trusted_bytes(path)
    if len(expected) != 64 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('trusted input digest mismatch')
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--consumer-config', type=Path, required=True)
    args, forwarded = parser.parse_known_args(argv)
    try:
        if sys.version_info < (3, 11):
            raise ValueError('Python 3.11 or newer required')
        root = Path(__file__).resolve().parents[2]
        manifest = json.loads(trusted_bytes(root / 'manifest.json'))
        if manifest.get('schema') != 'horizon-review-release.v1':
            raise ValueError('unsupported release manifest')
        for name, digest in manifest['files'].items():
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('manifest path escapes release')
            pinned(root / relative, digest)
        config_path = args.consumer_config.absolute()
        config = json.loads(trusted_bytes(config_path))
        if set(config) != {'schema', 'enabled', 'transport', 'cursor_executable', 'cursor_sha256', 'routing_yaml', 'routing_sha256'}:
            raise ValueError('unknown or missing consumer configuration fields')
        if config['schema'] != 'horizon-review-consumer.v1' or config['enabled'] is not True:
            raise ValueError('consumer is not explicitly enabled')
        if config['transport'] != 'cursor':
            raise ValueError('explicit Cursor transport required; legacy names do not translate providers')
        executable = Path(config['cursor_executable'])
        if not executable.is_absolute() or not os.access(executable, os.X_OK):
            raise ValueError('absolute executable Cursor harness required')
        pinned(executable, config['cursor_sha256'])
        routing = Path(config['routing_yaml'])
        if not routing.is_absolute():
            routing = config_path.parent / routing
        pinned(routing, config['routing_sha256'])
        # Do not let argv override the consumer's pinned route configuration.
        if any(arg.startswith('--routing') for arg in forwarded):
            raise ValueError('routing is owned by the consumer configuration')
        sys.path.insert(0, str(root / 'controller'))
        import yaml
        if yaml.__version__ != manifest['runtime']['PyYAML']:
            raise ValueError('reviewer runtime requires pinned PyYAML')
        spec = importlib.util.spec_from_file_location('packaged_host_review', root / 'tools/host_review/host_review.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        module.CURSOR_BIN = str(executable)
        return module.main(['--routing-yaml', str(routing), *forwarded])
    except (ValueError, OSError, KeyError, TypeError, ImportError):
        # Never echo configuration, packet contents, credentials or raw exception text.
        print('review blocked: invalid package, consumer configuration, evidence, or independent route; no automatic retry', file=sys.stderr)
        return 78


if __name__ == '__main__':
    raise SystemExit(main())
