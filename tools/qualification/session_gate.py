"""Five-session, no-retry qualification broker; never a production controller.

Run outside the private PostgreSQL network namespace. Only the Unix socket is
shared with the disposable worker. Model processes receive one workspace mount,
not the submission store, database, broker ledger or development checkout.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import selectors
import socket
import struct
import subprocess
import sys
import time

MODELS = ['composer-2.5','cursor-grok-4.6-high','composer-2.5','cursor-grok-4.6-high','cursor-grok-4.6-high']
LIMITS = [300,300,300,300,900]
MAX_BYTES = 2*1024*1024
SUN_PATH_BYTES = 108  # Linux sockaddr_un.sun_path, including the terminating NUL.


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('unsafe qualification path')
    for parent in (path,*path.parents):
        info=parent.stat()
        if info.st_uid != 0 or (info.st_mode & 0o022 and not (parent == Path('/tmp') and info.st_mode & 0o1000)):
            raise ValueError('qualification paths must be root controlled')
    if directory != path.is_dir():
        raise ValueError('unexpected qualification path type')
    return path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inventory_digest(files):
    return digest(json.dumps(files,sort_keys=True,separators=(',',':')).encode())


def validate_socket_path(path):
    """Reject a pathname AF_UNIX address before a ledger or process is created."""
    path=Path(path)
    encoded=os.fsencode(str(path))
    if not path.is_absolute():
        raise ValueError('qualification Unix socket path must be absolute')
    if b'\0' in encoded or len(encoded)>=SUN_PATH_BYTES:
        raise ValueError('qualification Unix socket path exceeds Linux sockaddr_un limit')
    return path


def sanitized_startup_failure(error):
    """Return an inspectable reason without echoing configured paths or values."""
    if isinstance(error, ValueError):
        return str(error)
    if isinstance(error, OSError):
        return 'os_error_errno_'+str(error.errno)
    if isinstance(error, KeyError):
        return 'missing_configuration_field'
    return 'invalid_configuration_type'


def child_diagnostic(stderr, reason, exit_code):
    """Classify bounded child diagnostics without persisting their contents."""
    text = str(stderr or '').lower()
    if any(value in text for value in ('eai_again', 'enotfound', 'name or service not known',
                                       'temporary failure in name resolution')):
        return 'network_dns_failure'
    if any(value in text for value in ('certificate verify failed', 'tls handshake',
                                       'ssl_error', 'unable to verify the first certificate')):
        return 'network_tls_failure'
    if any(value in text for value in ('connection refused', 'connection reset',
                                       'network is unreachable', 'fetch failed')):
        return 'network_transport_failure'
    if re.search(r'\b(?:401|403|404|408|409|429|500|502|503|504)\b', text) and any(
            value in text for value in ('http', 'api', 'status', 'response')):
        return 'api_http_failure'
    if any(value in text for value in ('pivot_root', 'pivot root', 'detaching old root', 'oldroot', 'chroot')):
        return 'confinement_startup_failure'
    if any(value in text for value in ('sandbox', 'landlock', 'seccomp', 'unshare',
                                       'mount', 'namespace', 'capability')):
        return 'sandbox_setup_failure'
    if any(value in text for value in ('eacces', 'eperm', 'enoent', 'enotdir',
                                       'read-only file system', 'permission denied')):
        return 'filesystem_access_failure'
    if any(value in text for value in ('permission denied', 'unauthorized', 'forbidden', 'authentication')):
        return 'authentication_or_permission_failure'
    if any(value in text for value in ('unknown option', 'invalid option', 'usage:')):
        return 'cursor_cli_argument_failure'
    if text:
        return 'child_process_failure'
    if reason in {'timeout', 'cancelled', 'bounded_process_outcome_uncertain'}:
        return 'child_outcome_uncertain'
    if exit_code not in (0, None):
        return 'child_process_failure_without_diagnostics'
    return 'no_child_diagnostics'


def validate_prepared(path, expected, config_path):
    raw=trusted(path).read_bytes()
    if digest(raw)!=expected:
        raise ValueError('prepared authorization digest mismatch')
    prepared=json.loads(raw)
    config_path=Path(config_path).absolute()
    config_bytes=trusted(config_path).read_bytes()
    config=json.loads(config_bytes)
    submission_socket=validate_socket_path(prepared.get('submission_socket',''))
    endpoints=prepared.get('socket_endpoints',{})
    if not isinstance(endpoints,dict) or any(not isinstance(item,dict) for item in endpoints.values()):
        raise ValueError('prepared socket endpoint inventory is invalid')
    if (prepared.get('schema')!='horizon-qualification-prepared.v2'
            or prepared.get('status')!='NOT_INVOKED'
            or prepared.get('gate_config')!=str(config_path)
            or prepared.get('gate_sha256')!=digest(config_bytes)
            or config.get('execution')!='cursor-subscription'
            or config.get('auth_file')!=prepared.get('authentication_reference_only')
            or config.get('socket')!=prepared.get('broker_socket')
            or len(os.fsencode(config.get('socket','')))!=prepared.get('broker_socket_path_bytes')
            or submission_socket.parent!=Path(config.get('socket_root',''))
            or submission_socket.name!='g.sock'
            or len(os.fsencode(str(submission_socket)))!=prepared.get('submission_socket_path_bytes')
            or set(endpoints)!={'session_broker','submission_listener','postgresql','authority_service'}
            or endpoints.get('session_broker',{}).get('path')!=config.get('socket')
            or endpoints.get('submission_listener',{}).get('path')!=str(submission_socket)
            or endpoints.get('postgresql',{}).get('path')!='/run/postgresql/.s.PGSQL.5432'
            or endpoints.get('authority_service',{}).get('path')!='/run/top-delivery/comms01-authority.sock'
            or any(item.get('encoded_bytes')!=len(os.fsencode(item.get('path','')))
                   for item in endpoints.values())
            or prepared.get('runtime_inventory_sha256')!=inventory_digest(config.get('runtime_files'))
            or prepared.get('maximum_sessions')!=5
            or prepared.get('automatic_retries')!=0 or prepared.get('fallback_calls')!=0):
        raise ValueError('prepared gate/runtime/auth binding mismatch')
    return prepared


def save(path, value):
    temporary = path.with_suffix('.pending')
    # A previous interrupted write is ambiguous; never erase it on restart.
    with temporary.open('x') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def load_config(path, authorize_live=False):
    try:
        config=json.loads(trusted(path).read_text())
    except ValueError as error:
        raise ValueError('config: '+str(error)) from error
    required={'schema','execution','socket','socket_root','state_root','workspace_root','runtime_root',
              'runtime_entry','runtime_files','auth_file','subscription_only','on_demand_disabled'}
    if set(config)!=required or config['schema']!='horizon-qualification.v1':
        raise ValueError('unsupported qualification configuration')
    if config['execution'] not in {'simulated','cursor-subscription'}:
        raise ValueError('unknown execution transport')
    if config['execution']=='cursor-subscription' and not authorize_live:
        raise ValueError('live qualification is not invoked')
    if config['execution']=='simulated':
        # A label cannot authorize a real runtime in a networked host process.
        if {name for _,name in socket.if_nameindex()}!={'lo'} or not Path(config['auth_file']).is_relative_to('/tmp'):
            raise ValueError('simulation requires isolated loopback and disposable authentication')
        mounts={line.split(' - ',1)[0].split()[4]:line.split(' - ',1)[1].split()[0]
                for line in Path('/proc/self/mountinfo').read_text().splitlines()}
        if any(mounts.get(path)!='tmpfs' for path in ('/tmp','/run','/etc/top-delivery','/var/lib/top-delivery-submission-bundles')):
            raise ValueError('simulation requires private disposable stores')
    if config['subscription_only'] is not True or config['on_demand_disabled'] is not True:
        raise ValueError('included subscription authorization required')
    for name in ('socket_root','state_root','workspace_root','runtime_root'):
        try:
            trusted(config[name],directory=True)
        except ValueError as error:
            raise ValueError(name+': '+str(error)) from error
    try:
        trusted(config['auth_file'])
    except ValueError as error:
        raise ValueError('auth_file: '+str(error)) from error
    workspace=Path(config['workspace_root'])
    for name in ('socket_root','state_root','runtime_root','auth_file'):
        protected=Path(config[name])
        if protected.is_relative_to(workspace) or workspace.is_relative_to(protected):
            raise ValueError('workspace must not overlap protected qualification inputs')
    socket_path=validate_socket_path(config['socket'])
    socket_root=Path(config['socket_root'])
    if (socket_path.parent!=socket_root or socket_path.name!='b.sock'
            or socket_root==Path(config['state_root'])):
        raise ValueError('socket must be in its separate private runtime root')
    state_root=Path(config['state_root'])
    if config['execution']=='cursor-subscription' and not socket_root.is_relative_to('/opt/horizon-q'):
        raise ValueError('live socket must use the short qualification runtime root')
    if socket_root.is_relative_to(state_root) or state_root.is_relative_to(socket_root):
        raise ValueError('socket and durable state roots must not overlap')
    if any(Path(config[name]).stat().st_mode & 0o077 for name in ('socket_root','state_root')):
        raise ValueError('session state and socket runtime must be private')
    if socket_path.exists() or socket_path.is_symlink():
        raise ValueError('qualification socket collision or stale listener evidence')
    if not config['runtime_files'] or config['runtime_entry'] not in config['runtime_files']:
        raise ValueError('pinned runtime required')
    runtime=Path(config['runtime_root'])
    entries=list(runtime.rglob('*'))
    allowed_dirs={str(p) for name in config['runtime_files'] for p in Path(name).parents}
    if (any(p.is_symlink() or (not p.is_dir() and not p.is_file()) for p in entries)
            or {str(p.relative_to(runtime)) for p in entries if p.is_file()}!=set(config['runtime_files'])
            or any(str(p.relative_to(runtime)) not in allowed_dirs for p in entries if p.is_dir())):
        raise ValueError('runtime inventory has missing or unlisted payload/state')
    for name, expected in config['runtime_files'].items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid runtime member')
        if digest(trusted(Path(config['runtime_root'])/relative).read_bytes())!=expected:
            raise ValueError('runtime digest mismatch')
    return config


def parent_death(expected_parent):
    # Killing the broker kills unshare; --kill-child then destroys its PID
    # namespace (including daemonized descendants, not merely its process group).
    if ctypes.CDLL(None).prctl(1, signal.SIGKILL,0,0,0)!=0 or os.getppid()!=expected_parent:
        os._exit(78)


def launch(config, cwd, model, prompt, timeout):
    payload={'config':{**config,'outer_mnt':os.readlink('/proc/self/ns/mnt'),
                       'outer_pid':os.readlink('/proc/self/ns/pid')},
             'cwd':cwd,'model':model,'prompt':prompt}
    argv=['/usr/bin/unshare','--user','--map-user=65534','--map-group=65534','--keep-caps',
          '--mount','--pid','--fork','--kill-child=SIGKILL',
          sys.executable,str(Path(__file__).with_name('jail.py'))]
    broker_pid=os.getpid()
    proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          start_new_session=True,preexec_fn=lambda:parent_death(broker_pid))
    outgoing=memoryview(json.dumps(payload).encode())
    out=bytearray(); stderr=bytearray(); stderr_bytes=0; deadline=time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream,event in ((proc.stdin,selectors.EVENT_WRITE),(proc.stdout,selectors.EVENT_READ),(proc.stderr,selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(),False)
                selector.register(stream,event)
            while selector.get_map():
                if time.monotonic()>=deadline:
                    raise TimeoutError('session deadline')
                for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
                    stream=key.fileobj
                    if stream is proc.stdin:
                        try: outgoing=outgoing[os.write(stream.fileno(),outgoing[:65536]):]
                        except BrokenPipeError: outgoing=memoryview(b'')
                        if not outgoing: selector.unregister(stream); stream.close()
                    else:
                        chunk=os.read(stream.fileno(),65536)
                        if not chunk: selector.unregister(stream); stream.close(); continue
                        if stream is proc.stdout: out.extend(chunk)
                        else:
                            stderr_bytes+=len(chunk)
                            if len(stderr)<MAX_BYTES:
                                stderr.extend(chunk[:MAX_BYTES-len(stderr)])
                        if len(out)>MAX_BYTES or stderr_bytes>MAX_BYTES:
                            raise ValueError('bounded output exceeded')
        proc.wait(timeout=max(.01,deadline-time.monotonic()))
        return {'exit':proc.returncode,'stdout':out.decode('utf-8',errors='strict'),
                'stderr':stderr.decode('utf-8',errors='replace'),
                'stderr_bytes':stderr_bytes,'reason':'process_exit'}
    except (TimeoutError,ValueError,subprocess.TimeoutExpired):
        try: os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        proc.wait(timeout=10)
        return {'exit':78,'reason':'bounded_process_outcome_uncertain','stdout':'',
                'stderr':stderr.decode('utf-8',errors='replace'),'stderr_bytes':stderr_bytes}
    finally:
        for stream in (proc.stdin,proc.stdout,proc.stderr):
            if not stream.closed: stream.close()


def validate_output(result, model):
    if result['exit']!=0:
        return False
    try:
        events=[json.loads(line) for line in result['stdout'].splitlines() if line.strip()]
        init=[e for e in events if e.get('type')=='system' and e.get('subtype')=='init']
        aliases={'composer-2.5':{'composer-2.5','Composer 2.5'},
                 'cursor-grok-4.6-high':{'cursor-grok-4.6-high','Cursor Grok 4.6 High'}}
        return (len(init)==1 and init[0].get('model') in aliases[model]
                and events[-1].get('type')=='result' and events[-1].get('subtype')=='success'
                and events[-1].get('is_error') is not True)
    except (ValueError,TypeError,KeyError,IndexError,AttributeError):
        return False


class Gate:
    def __init__(self, config):
        self.config=config
        self.path=Path(config['state_root'])/'sessions.json'
        self.binding=digest(json.dumps(config,sort_keys=True).encode())
        self.lock=os.fdopen(os.open(self.path.parent/'sessions.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600),'a')
        fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if self.path.with_suffix('.pending').exists():
            raise ValueError('interrupted ledger write requires inspection')
        if not self.path.exists():
            save(self.path,{'config_sha256':self.binding,'started_at':time.time(),
                'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'started_monotonic':time.monotonic(),'sessions':[]})
        trusted(self.path)

    def request(self, request):
        state=json.loads(trusted(self.path).read_text())
        elapsed=time.monotonic()-state['started_monotonic']
        if (state['config_sha256']!=self.binding or elapsed<0 or elapsed>2400
                or state['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
            raise ValueError('configuration changed or qualification deadline expired')
        if set(request)!={'model','prompt','cwd'} or not isinstance(request['prompt'],str) or not request['prompt']:
            raise ValueError('invalid session request')
        index=len(state['sessions'])
        if index>=5 or any(s['state']!='complete' for s in state['sessions']):
            raise ValueError('session budget exhausted or outcome uncertain; no replay')
        model=request['model']
        if model!=MODELS[index]:
            raise ValueError('unexpected model or session order')
        cwd=trusted(request['cwd'],directory=True)
        if not cwd.is_relative_to(self.config['workspace_root']) or cwd==Path(self.config['workspace_root']):
            raise ValueError('single disposable task workspace required')
        record={'state':'intent','model':model,'prompt_sha256':digest(request['prompt'].encode()),
                'workspace':str(cwd),'started_at':time.time(),'limit_seconds':LIMITS[index]}
        state['sessions'].append(record)
        save(self.path,state)  # Durable consumption BEFORE any child launch.
        result=launch(self.config,str(cwd),model,request['prompt'],LIMITS[index])
        child_stderr=result.get('stderr','')
        record.update(state='complete' if validate_output(result,model) else 'uncertain',
                      elapsed_seconds=time.time()-record['started_at'],exit=result['exit'],
                      stdout_sha256=digest(result['stdout'].encode()),
                      launch_reason=result.get('reason','unknown'),
                      child_exit=result.get('exit'),
                      child_stderr_sha256=digest(child_stderr.encode()),
                      child_stderr_bytes=result.get('stderr_bytes',len(child_stderr.encode())),
                      child_diagnostic=child_diagnostic(child_stderr,result.get('reason'),result.get('exit')))
        if record['state']=='complete':
            init=next(e for e in (json.loads(line) for line in result['stdout'].splitlines() if line.strip())
                      if e.get('type')=='system' and e.get('subtype')=='init')
            record.update(observed_model=init['model'],execution=self.config['execution'],
                          runtime_inventory_sha256=inventory_digest(self.config['runtime_files']))
        save(self.path,state)
        if record['state']!='complete':
            return {'exit':78,'reason':'outcome_uncertain_no_replay','stdout':''}
        return result


def receive(connection):
    connection.settimeout(10)
    data=b''
    while not data.endswith(b'\n'):
        chunk=connection.recv(min(65536,MAX_BYTES+1-len(data)))
        if not chunk or len(data)+len(chunk)>MAX_BYTES:
            raise ValueError('invalid request frame')
        data+=chunk
    return json.loads(data)


def serve(config):
    path=validate_socket_path(config['socket'])
    # A stale socket is evidence; an operator may remove ONLY the socket after
    # inspecting sessions.json, never reset the ledger to authorize replay.
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path)); os.chmod(path,0o600); server.listen(4)
        # Listener admission succeeds before creating or opening a durable ledger.
        gate=Gate(config)
        try:
            while True:
                connection,_=server.accept()
                with connection:
                    try:
                        uid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
                        if uid!=os.geteuid(): raise ValueError('untrusted peer')
                        result=gate.request(receive(connection))
                    except Exception:
                        result={'exit':78,'reason':'qualification_blocked_no_replay','stdout':''}
                    try: connection.sendall((json.dumps(result)+'\n').encode())
                    except OSError: pass  # Committed consumption survives disconnect.
        finally:
            path.unlink()


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--execute-authorized-live',action='store_true')
    parser.add_argument('--prepared',type=Path)
    parser.add_argument('--prepared-sha256')
    args=parser.parse_args()
    try:
        prepared=None
        if args.execute_authorized_live:
            if args.prepared is None or not args.prepared_sha256:
                raise ValueError('exact prepared authorization required')
            prepared=validate_prepared(args.prepared,args.prepared_sha256,args.config)
        config=load_config(args.config,args.execute_authorized_live)
        if config['execution']=='cursor-subscription':
            if prepared is None:
                raise ValueError('exact prepared authorization required')
            package=Path(prepared['submission_release'])
            manifest_bytes=trusted(package/'manifest.json').read_bytes()
            manifest=json.loads(manifest_bytes)
            if (digest(manifest_bytes)!=prepared['submission_release_manifest_sha256']
                    or manifest['source_commit']!=prepared['source_commit']
                    or manifest['source_state']!='committed'
                    or Path(__file__).resolve()!=package/'tools/qualification/session_gate.py'):
                raise ValueError('broker must be the authorized staged release')
            for name, expected in manifest['files'].items():
                relative=Path(name)
                if relative.is_absolute() or '..' in relative.parts or digest(trusted(package/relative).read_bytes())!=expected:
                    raise ValueError('staged broker package changed')
        serve(config)
    except (ValueError,OSError,KeyError,TypeError) as error:
        print('qualification blocked: '+sanitized_startup_failure(error)+'; no automatic retry',file=sys.stderr)
        raise SystemExit(78)
