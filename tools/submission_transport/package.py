"""Stage both submission paths and their exact Horizon runtime, never install."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
ENTRIES = ('top-delivery-submit', 'top-delivery-host-gateway', 'top-delivery-host-gateway-server')


def stage(output, allow_uncommitted=False):
    sha = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip()
    tracked = subprocess.check_output(['git','ls-files','controller'], cwd=ROOT, text=True).splitlines()
    sources = [name for name in tracked if (name.endswith('.py') or name in {'controller/alembic.ini','controller/requirements.txt'})
        and not any(p in {'test_only','tests','__pycache__'} or p.startswith('test_') or p == 'conftest.py' for p in Path(name).parts)]
    sources += ['architecture/model-routing.yaml', *(f'tools/submission_transport/{name}' for name in
        ('transport.py','package.py','consumer.example.json','host-gateway.service.in','PROVENANCE.md'))]
    files, dirty = {}, []
    for name in sources:
        path = ROOT / name
        if any(p.is_symlink() for p in (path,*path.parents)):
            raise ValueError('source symlink')
        data = path.read_bytes()
        old = subprocess.run(['git','show',f'{sha}:{name}'], cwd=ROOT, capture_output=True)
        if old.returncode or old.stdout != data:
            dirty.append(name)
        files[name] = data
    if dirty and not allow_uncommitted:
        raise ValueError('uncommitted package inputs')
    for entry in ENTRIES:
        files['bin/' + entry] = ('''#!/usr/bin/env -S python3 -I
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(root / 'tools/submission_transport'), str(root / 'controller')]
from transport import main
raise SystemExit(main(''' + repr(entry) + '))\n').encode()
    manifest = {'schema':'horizon-submission-release.v1', 'source_commit':sha,
        'source_state':'TEST_ONLY_UNCOMMITTED' if dirty else 'committed', 'uncommitted_inputs':dirty,
        'files':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(files.items())}}
    output = Path(output).absolute()
    if any(p.is_symlink() for p in (output,*output.parents)):
        raise ValueError('destination symlink')
    output.mkdir(mode=0o755, exist_ok=False)
    for name,data in files.items():
        path = output / name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if name.startswith('bin/') else 0o644)
    (output / 'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--allow-uncommitted',action='store_true')
    args = parser.parse_args()
    print(json.dumps(stage(args.output,args.allow_uncommitted),indent=2))
