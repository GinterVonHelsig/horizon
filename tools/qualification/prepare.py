"""Prepare (never execute) an exact-commit isolated five-session qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]


def builder(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'tools'/name/'package.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def prepare(output,runtime,auth):
    if os.geteuid()!=0: raise ValueError('private root-controlled staging required')
    sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT):
        raise ValueError('commit and review the source before live preparation')
    output=output.absolute(); runtime=runtime.absolute(); auth=auth.absolute()
    for path in (output,runtime,auth):
        if any(p.is_symlink() for p in (path,*path.parents)) or '..' in path.parts:
            raise ValueError('canonical staging paths required')
    if (not output.is_relative_to('/opt/operator-harness/artifacts')
            or runtime.parent!=Path('/opt/operator-harness/share/cursor-agent/versions')
            or not all((runtime/name).is_file() for name in ('cursor-agent','node','index.js'))):
        raise ValueError('explicit artifact destination and installed Cursor runtime required')
    if not auth.is_file() or auth.stat().st_uid!=0 or auth.stat().st_mode & 0o077:
        raise ValueError('existing private authentication reference required; never copy it')
    output.mkdir(mode=0o700,exist_ok=False)
    for name in ('state','workspaces'):
        (output/name).mkdir(mode=0o700)
    submission=output/'submission'; review=output/'reviewer'
    builder('submission_transport').stage(submission)
    builder('host_review').stage(review)
    # Public runtime only: no homes, session caches, environment or auth files.
    sources=[p for p in runtime.rglob('*') if not p.is_dir()]
    if any(p.is_symlink() or not p.is_file() for p in sources):
        raise ValueError('runtime symlink/special file must be resolved explicitly')
    if any(p.name.lower() in {'auth.json','credentials.json'} or p.suffix in {'.pem','.key'} for p in sources):
        raise ValueError('runtime contains a sensitive-looking file; stop')
    copied=output/'cursor-runtime'
    shutil.copytree(runtime,copied,copy_function=shutil.copyfile)
    for path in copied.rglob('*'):
        path.chmod(0o755 if path.is_dir() or os.access(runtime/path.relative_to(copied),os.X_OK) else 0o644)
    files={str(p.relative_to(copied)):hashlib.sha256(p.read_bytes()).hexdigest() for p in copied.rglob('*') if p.is_file()}
    config={'schema':'horizon-qualification.v1','execution':'cursor-subscription',
        'socket':str(output/'state/session.sock'),'state_root':str(output/'state'),'workspace_root':str(output/'workspaces'),
        'runtime_root':str(copied),'runtime_entry':'cursor-agent','runtime_files':files,
        'auth_file':str(auth),'subscription_only':True,'on_demand_disabled':True}
    gate=output/'gate.json'; gate.write_text(json.dumps(config,indent=2)+'\n')
    value={'status':'NOT_INVOKED','source_commit':sha,'gate_config':str(gate),
        'submission_release':str(submission),'review_release':str(review),'maximum_sessions':5,
        'automatic_retries':0,'fallback_calls':0,'on_demand_disabled_evidence':'operator confirmation',
        'runtime_source':str(runtime),'authentication_reference_only':str(auth)}
    for key in ('submission_release','review_release'):
        value[key+'_manifest_sha256']=hashlib.sha256((Path(value[key])/'manifest.json').read_bytes()).hexdigest()
    path=output/'prepared.json'; path.write_text(json.dumps(value,indent=2)+'\n')
    return {'prepared':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'status':'NOT_INVOKED'}


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--runtime-source',required=True,type=Path)
    parser.add_argument('--auth-file',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(prepare(args.output,args.runtime_source,args.auth_file)))
