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
    config=json.loads(trusted(path).read_text())
    required={'schema','execution','socket','state_root','workspace_root','runtime_root',
              'runtime_entry','runtime_files','auth_file','subscription_only','on_demand_disabled'}
    if set(config)!=required or config['schema']!='horizon-qualification.v1':
        raise ValueError('unsupported qualification configuration')
    if config['execution'] not in {'simulated','cursor-subscription'}:
        raise ValueError('unknown execution transport')
    if config['execution']=='cursor-subscription' and not authorize_live:
        raise ValueError('live qualification is not invoked')
    if config['subscription_only'] is not True or config['on_demand_disabled'] is not True:
        raise ValueError('included subscription authorization required')
    for name in ('state_root','workspace_root','runtime_root'):
        trusted(config[name],directory=True)
    trusted(config['auth_file'])
    workspace=Path(config['workspace_root'])
    for name in ('state_root','runtime_root','auth_file'):
        protected=Path(config[name])
        if protected.is_relative_to(workspace) or workspace.is_relative_to(protected):
            raise ValueError('workspace must not overlap protected qualification inputs')
    socket_path=Path(config['socket'])
    trusted(socket_path.parent,directory=True)
    if socket_path.parent != Path(config['state_root']) or socket_path.name!='session.sock':
        raise ValueError('socket must be in private state root')
    if Path(config['state_root']).stat().st_mode & 0o077:
        raise ValueError('session state must be private')
    if not config['runtime_files'] or config['runtime_entry'] not in config['runtime_files']:
        raise ValueError('pinned runtime required')
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
    argv=['/usr/bin/unshare','--mount','--pid','--fork','--kill-child=SIGKILL',
          sys.executable,str(Path(__file__).with_name('jail.py'))]
    broker_pid=os.getpid()
    proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          start_new_session=True,preexec_fn=lambda:parent_death(broker_pid))
    outgoing=memoryview(json.dumps(payload).encode())
    out=bytearray(); stderr_bytes=0; deadline=time.monotonic()+timeout
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
                        else: stderr_bytes+=len(chunk)  # discard authentication diagnostics
                        if len(out)>MAX_BYTES or stderr_bytes>MAX_BYTES:
                            raise ValueError('bounded output exceeded')
        proc.wait(timeout=max(.01,deadline-time.monotonic()))
        return {'exit':proc.returncode,'stdout':out.decode('utf-8',errors='strict'),'reason':'process_exit'}
    except (TimeoutError,ValueError,subprocess.TimeoutExpired):
        try: os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        proc.wait(timeout=10)
        return {'exit':78,'reason':'bounded_process_outcome_uncertain','stdout':''}
    finally:
        for stream in (proc.stdin,proc.stdout,proc.stderr):
            if not stream.closed: stream.close()


def validate_output(result, model):
    if result['exit']!=0:
        return False
    try:
        events=[json.loads(line) for line in result['stdout'].splitlines() if line]
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
        record.update(state='complete' if validate_output(result,model) else 'uncertain',
                      elapsed_seconds=time.time()-record['started_at'],exit=result['exit'],
                      stdout_sha256=digest(result['stdout'].encode()))
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
    gate=Gate(config)
    path=Path(config['socket'])
    # A stale socket is evidence; an operator may remove ONLY the socket after
    # inspecting sessions.json, never reset the ledger to authorize replay.
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path)); os.chmod(path,0o600); server.listen(4)
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
    args=parser.parse_args()
    serve(load_config(args.config,args.execute_authorized_live))
