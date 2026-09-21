"""Prepare (never execute) an exact-commit isolated five-session qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
from session_gate import inventory_digest, validate_socket_path

ROOT=Path(__file__).resolve().parents[2]
SHORT_SOCKET_BASE=Path('/opt/horizon-q')


def builder(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'tools'/name/'package.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def freeze_public_payload(runtime,copied,manifest):
    """Allowlisted vendor code only; installed .running is neither read nor copied."""
    expected=manifest['files']
    actual=set()
    for directory,dirs,files in os.walk(runtime,followlinks=False):
        relative=Path(directory).relative_to(runtime)
        if relative==Path('.'):
            dirs[:]=[name for name in dirs if name!='.running']
        for name in dirs:
            if (Path(directory)/name).is_symlink(): raise ValueError('runtime directory symlink')
        for name in files:
            path=Path(directory)/name
            if path.is_symlink() or not path.is_file(): raise ValueError('runtime special file')
            actual.add(str(path.relative_to(runtime)))
    if actual!=set(expected):
        raise ValueError('installed public runtime differs from reviewed allowlist')
    copied.mkdir(mode=0o755,exist_ok=False)
    for name,sha in expected.items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts or '.running' in relative.parts:
            raise ValueError('non-payload runtime member')
        source=runtime/relative
        target=copied/relative; target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
        target.chmod(0o755 if os.access(source,os.X_OK) else 0o644)
        if hashlib.sha256(target.read_bytes()).hexdigest()!=sha:
            raise ValueError('runtime payload digest mismatch')
    return expected


def durable_json(path,value):
    with path.open('x') as stream:
        json.dump(value,stream,indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def qualification_sockets(output,sha,base=None):
    """Return deterministic short runtime addresses, never artifact pathnames."""
    base=SHORT_SOCKET_BASE if base is None else Path(base)
    token=hashlib.sha256((sha+'\0'+str(output)).encode()).hexdigest()[:16]
    root=base/token
    return root, {
        'session_broker': validate_socket_path(root/'b.sock'),
        'submission_listener': validate_socket_path(root/'g.sock'),
    }


def qualification_socket(output,sha,base=None):
    """Compatibility helper for callers that need only the broker endpoint."""
    root,sockets=qualification_sockets(output,sha,base)
    return root,sockets['session_broker']


def create_private_socket_root(root):
    """Atomically reserve a private listener root; never reuse a collision."""
    root=Path(root); base=root.parent
    if os.path.lexists(root):
        raise ValueError('qualification socket runtime collision')
    if not base.exists():
        base.mkdir(mode=0o700)
    if (base.is_symlink() or base.stat().st_uid!=0 or base.stat().st_mode & 0o077
            or any(p.is_symlink() for p in (base,*base.parents))):
        raise ValueError('socket runtime base must be private and root controlled')
    root.mkdir(mode=0o700)
    if root.stat().st_uid!=0 or root.stat().st_mode & 0o077:
        raise ValueError('socket runtime root must be private and root controlled')


def prepare(output,runtime,auth):
    if os.geteuid()!=0: raise ValueError('private root-controlled staging required')
    sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT):
        raise ValueError('commit and review the source before live preparation')
    output=output.absolute(); runtime=runtime.absolute(); auth=auth.absolute()
    socket_root,sockets=qualification_sockets(output,sha)
    socket_path=sockets['session_broker']
    if os.path.lexists(socket_root):
        raise ValueError('qualification socket runtime collision')
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
    manifest=json.loads((Path(__file__).parent/('cursor-runtime-'+runtime.name+'.json')).read_text())
    if manifest['version']!=runtime.name or manifest['public_payload_only'] is not True:
        raise ValueError('reviewed vendor payload manifest required')
    copied=output/'cursor-runtime'
    files=freeze_public_payload(runtime,copied,manifest)
    create_private_socket_root(socket_root)
    config={'schema':'horizon-qualification.v1','execution':'cursor-subscription',
        'socket':str(socket_path),'socket_root':str(socket_root),
        'state_root':str(output/'state'),'workspace_root':str(output/'workspaces'),
        'runtime_root':str(copied),'runtime_entry':'cursor-agent','runtime_files':files,
        'auth_file':str(auth),'subscription_only':True,'on_demand_disabled':True}
    gate=output/'gate.json'; durable_json(gate,config)
    endpoint_inventory={
        'session_broker': {'path':str(sockets['session_broker']),
            'encoded_bytes':len(os.fsencode(str(sockets['session_broker']))),
            'producer_namespace':'Comms-01 host',
            'consumer_namespace':'isolated qualification and packaged worker clients'},
        'submission_listener': {'path':str(sockets['submission_listener']),
            'encoded_bytes':len(os.fsencode(str(sockets['submission_listener']))),
            'producer_namespace':'isolated qualification',
            'consumer_namespace':'isolated packaged submission clients'},
        'postgresql': {'path':'/run/postgresql/.s.PGSQL.5432',
            'encoded_bytes':len(os.fsencode('/run/postgresql/.s.PGSQL.5432')),
            'producer_namespace':'isolated qualification',
            'consumer_namespace':'isolated migration and orchestration fixtures'},
        'authority_service': {'path':'/run/top-delivery/comms01-authority.sock',
            'encoded_bytes':len(os.fsencode('/run/top-delivery/comms01-authority.sock')),
            'producer_namespace':'isolated qualification',
            'consumer_namespace':'isolated orchestration fixtures'},
    }
    value={'schema':'horizon-qualification-prepared.v2','status':'NOT_INVOKED','source_commit':sha,'gate_config':str(gate),
        'gate_sha256':hashlib.sha256(gate.read_bytes()).hexdigest(),
        'runtime_inventory_sha256':inventory_digest(files),'excluded_installed_state':['.running/'],
        'broker_socket':str(socket_path),'broker_socket_path_bytes':len(os.fsencode(str(socket_path))),
        'submission_socket':str(sockets['submission_listener']),
        'submission_socket_path_bytes':len(os.fsencode(str(sockets['submission_listener']))),
        'socket_endpoints':endpoint_inventory,
        'submission_release':str(submission),'review_release':str(review),'maximum_sessions':5,
        'automatic_retries':0,'fallback_calls':0,'on_demand_disabled_evidence':'operator confirmation',
        'runtime_source':str(runtime),'authentication_reference_only':str(auth)}
    for key in ('submission_release','review_release'):
        value[key+'_manifest_sha256']=hashlib.sha256((Path(value[key])/'manifest.json').read_bytes()).hexdigest()
    path=output/'prepared.json'; durable_json(path,value)
    return {'prepared':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'status':'NOT_INVOKED'}


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--runtime-source',required=True,type=Path)
    parser.add_argument('--auth-file',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(prepare(args.output,args.runtime_source,args.auth_file)))
