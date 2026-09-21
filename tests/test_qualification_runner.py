"""Disposable namespaces and SIMULATED subprocesses only; no Cursor calls."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
from test_only.isolation import require_isolation

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('qualification_gate',ROOT/'tools/qualification/session_gate.py')
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


@pytest.fixture
def config(tmp_path):
    require_isolation(os.environ.get('TOP_DELIVERY_PG_ADMIN_URL',''))
    for name in ('state','workspaces','runtime'):
        (tmp_path/name).mkdir(mode=0o700)
    (tmp_path/'workspaces/task').mkdir()
    (tmp_path/'auth.json').write_text('{}')  # dummy, never existing authentication
    executable=tmp_path/'runtime/cursor-agent'
    executable.write_text('''#!/usr/bin/python3 -I
import json,os,pathlib,socket,sys,time
model=sys.argv[sys.argv.index('--model')+1]
prompt=sys.argv[sys.argv.index('-p')+1]
if prompt in {'timeout','orphan'}:
    if prompt=='orphan' and os.fork()==0:
        os.setsid()
        while True:
            pathlib.Path('heartbeat').write_text(str(time.monotonic()))
            time.sleep(.02)
    pathlib.Path('started').touch()
    time.sleep(60)
if prompt=='probe':
    for port in (80,5432):
        with socket.socket() as connection:
            try:
                connection.connect(('127.0.0.1',port))
                raise AssertionError('network boundary bypassed')
            except PermissionError: pass
    assert not pathlib.Path('/opt/operator-harness').exists()
    assert not pathlib.Path('/etc/ssl/private').exists()
    assert not pathlib.Path('/usr/local').exists()
    assert not pathlib.Path('/var/lib/top-delivery-submission-bundles').exists()
    assert not pathlib.Path('/etc/top-delivery').exists()
    assert not pathlib.Path('/run/postgresql').exists()
    assert pathlib.Path('/cursor-home/.config/cursor/auth.json').read_text()=='{}'
    try:
        pathlib.Path('/cursor-home/.config/cursor/auth.json').write_text('forbidden')
        raise AssertionError('auth was writable')
    except OSError: pass
    if model=='cursor-grok-4.6-high':
        try:
            pathlib.Path('forbidden-write').touch()
            raise AssertionError('review workspace writable')
        except OSError: pass
print(json.dumps({'type':'system','subtype':'init','model':model,'session_id':'SIMULATED'}))
print(json.dumps({'type':'result','subtype':'success','is_error':False}))
''')
    executable.chmod(0o755)
    value={'schema':'horizon-qualification.v1','execution':'simulated',
           'socket':str(tmp_path/'state/session.sock'),'state_root':str(tmp_path/'state'),
           'workspace_root':str(tmp_path/'workspaces'),'runtime_root':str(tmp_path/'runtime'),
           'runtime_entry':'cursor-agent','runtime_files':{'cursor-agent':gate.digest(executable.read_bytes())},
           'auth_file':str(tmp_path/'auth.json'),'subscription_only':True,'on_demand_disabled':True}
    (tmp_path/'config.json').write_text(json.dumps(value))
    assert gate.load_config(tmp_path/'config.json')==value
    return value


def request(config, model='composer-2.5', prompt='probe'):
    return {'model':model,'prompt':prompt,'cwd':str(Path(config['workspace_root'])/'task')}


def test_jail_entry_with_dummy_auth_only(config):
    payload={'config':{**config,'outer_mnt':os.readlink('/proc/self/ns/mnt'),
                      'outer_pid':os.readlink('/proc/self/ns/pid')}, **request(config)}
    result=subprocess.run(['/usr/bin/unshare','--mount','--pid','--fork','--kill-child=SIGKILL',
        sys.executable,str(ROOT/'tools/qualification/jail.py')],input=json.dumps(payload),
        capture_output=True,text=True,timeout=10)
    assert result.returncode==0, result.stderr


def test_real_jail_five_sessions_restart_limit_and_readonly_review(config):
    for model in gate.MODELS:
        broker=gate.Gate(config)
        try:
            result=broker.request(request(config,model))
            assert result['exit']==0, result
        finally: broker.lock.close()
    broker=gate.Gate(config)
    with pytest.raises(ValueError,match='budget exhausted'):
        broker.request(request(config))
    state=json.loads(broker.path.read_text())
    assert len(state['sessions'])==5 and all(s['state']=='complete' for s in state['sessions'])
    assert not (Path(config['workspace_root'])/'task/forbidden-write').exists()
    broker.lock.close()


@pytest.mark.parametrize('behavior',['timeout','orphan'])
def test_timeout_kills_namespace_and_restart_never_replays(config,monkeypatch,behavior):
    monkeypatch.setattr(gate,'LIMITS',[.4,300,300,300,900])
    broker=gate.Gate(config)
    result=broker.request(request(config,prompt=behavior))
    assert result['exit']==78
    broker.lock.close()
    heartbeat=Path(config['workspace_root'])/'task/heartbeat'
    before=heartbeat.read_text() if heartbeat.exists() else None
    time.sleep(.1)
    assert (heartbeat.read_text() if heartbeat.exists() else None)==before
    broker=gate.Gate(config)
    with pytest.raises(ValueError,match='outcome uncertain'):
        broker.request(request(config))
    assert len(json.loads(broker.path.read_text())['sessions'])==1
    broker.lock.close()


def test_broker_killed_after_launch_cannot_leave_orphan_or_reset_budget(config):
    # A separate broker process, not a monkeypatched launch. Its death must
    # propagate through unshare to every member of the new PID namespace.
    script='''import importlib.util,json,sys
s=importlib.util.spec_from_file_location('gate',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
c=m.load_config(sys.argv[2]);m.Gate(c).request({'model':'composer-2.5','prompt':'orphan','cwd':c['workspace_root']+'/task'})
'''
    process=subprocess.Popen([sys.executable,'-c',script,str(ROOT/'tools/qualification/session_gate.py'),
                              str(Path(config['state_root']).parent/'config.json')],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    heartbeat=Path(config['workspace_root'])/'task/heartbeat'
    try:
        deadline=time.monotonic()+10
        while not heartbeat.exists() and process.poll() is None and time.monotonic()<deadline:
            time.sleep(.02)
        assert heartbeat.exists()
        process.kill(); process.wait(timeout=5)
        time.sleep(.1)
        before=heartbeat.read_text(); time.sleep(.1)
        assert heartbeat.read_text()==before
        broker=gate.Gate(config)
        with pytest.raises(ValueError,match='outcome uncertain'):
            broker.request(request(config))
        assert json.loads(broker.path.read_text())['sessions'][0]['state']=='intent'
        broker.lock.close()
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)


def test_live_requires_explicit_invocation_and_on_demand_disabled(config):
    path=Path(config['state_root']).parent/'config.json'
    config['execution']='cursor-subscription'
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError,match='not invoked'): gate.load_config(path)
    config['on_demand_disabled']=False
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError,match='subscription'): gate.load_config(path,authorize_live=True)


def test_reboot_or_interrupted_write_cannot_reset_deadline(config):
    broker=gate.Gate(config)
    path=broker.path; state=json.loads(path.read_text()); broker.lock.close()
    state['boot_id']='not-this-boot'; gate.save(path,state)
    broker=gate.Gate(config)
    with pytest.raises(ValueError,match='deadline expired'): broker.request(request(config))
    broker.lock.close()
    path.with_suffix('.pending').write_text('incomplete durable write')
    with pytest.raises(ValueError,match='interrupted ledger'): gate.Gate(config)
