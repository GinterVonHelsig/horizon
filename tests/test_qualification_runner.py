"""Disposable namespaces and SIMULATED subprocesses only; no Cursor calls."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import pwd
import grp

import pytest
from test_only.isolation import require_isolation

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('qualification_gate',ROOT/'tools/qualification/session_gate.py')
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
jail_spec=importlib.util.spec_from_file_location('qualification_jail',ROOT/'tools/qualification/jail.py')
jail=importlib.util.module_from_spec(jail_spec)
jail_spec.loader.exec_module(jail)


@pytest.fixture
def config(tmp_path):
    require_isolation(os.environ.get('TOP_DELIVERY_PG_ADMIN_URL',''))
    for name in ('state','workspaces','runtime'):
        (tmp_path/name).mkdir(mode=0o700)
    token=hashlib.sha256(os.fsencode(str(tmp_path))).hexdigest()[:16]
    configured_base=os.environ.get('HORIZON_TEST_SOCKET_BASE')
    socket_root=Path(configured_base or '/tmp')/(token if configured_base else 'horizon-qual-'+token)
    socket_root.mkdir(mode=0o700)
    (tmp_path/'workspaces/task').mkdir()
    (tmp_path/'auth.json').write_text('{}')  # dummy, never existing authentication
    executable=tmp_path/'runtime/cursor-agent'
    executable.write_text('''#!/usr/bin/python3 -I
import grp,hashlib,json,os,pathlib,pwd,re,socket,sys,time
model=sys.argv[sys.argv.index('--model')+1]
prompt=sys.argv[sys.argv.index('-p')+1]
if prompt=='blank-lines': print('\\n  \\n')
if prompt in {'timeout','orphan'}:
    if prompt=='orphan' and os.fork()==0:
        os.setsid()
        while True:
            pathlib.Path('heartbeat').write_text(str(time.monotonic()))
            time.sleep(.02)
    pathlib.Path('started').touch()
    time.sleep(60)
if prompt=='probe':
    assert os.getuid()==65534 and os.getgid()==65534
    assert pathlib.Path.cwd()==pathlib.Path('/workspace')
    slug=re.sub(r'-+','-',re.sub(r'[^a-zA-Z0-9]','-',str(pathlib.Path.cwd()))).strip('-')
    trust_marker=pathlib.Path('/cursor-home/.cursor/projects')/slug/'.workspace-trusted'
    trust_marker.parent.mkdir(parents=True,exist_ok=True)
    trust_marker.write_text(json.dumps({'workspacePath':str(pathlib.Path.cwd())}))
    assert trust_marker.is_file()
    assert pwd.getpwuid(65534).pw_name=='nobody'
    assert grp.getgrgid(65534).gr_name=='nogroup'
    assert pathlib.Path('/etc/subuid').read_text()==''
    assert pathlib.Path('/etc/subgid').read_text()==''
    assert not pathlib.Path('/oldroot').exists()
    status={line.split(':',1)[0]:line.split()[1] for line in pathlib.Path('/proc/self/status').read_text().splitlines() if line.startswith(('CapInh:','CapPrm:','CapEff:','CapBnd:','CapAmb:','NoNewPrivs:'))}
    assert all(status[name]=='0000000000000000' for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
    assert status['NoNewPrivs']=='1'
    for port in (80,5432):
        with socket.socket() as connection:
            try:
                connection.connect(('127.0.0.1',port))
                raise AssertionError('network boundary bypassed')
            except PermissionError: pass
    # The durable bind may create empty synthetic ancestors under the jail
    # tmpfs. Assert forbidden host contents are absent rather than rejecting
    # the authorized path's ancestor names.
    assert not pathlib.Path('/opt/operator-harness/controller').exists()
    assert not pathlib.Path('/opt/operator-harness/.git').exists()
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
if prompt=='exit78':
    print('Permission denied: /secret/auth.json', file=sys.stderr)
    sys.exit(78)
print(json.dumps({'type':'system','subtype':'init','model':model,'session_id':'SIMULATED'}))
print(json.dumps({'type':'result','subtype':'success','is_error':False}))
''')
    executable.chmod(0o755)
    value={'schema':'horizon-qualification.v1','execution':'simulated',
           'socket':str(socket_root/'b.sock'),'socket_root':str(socket_root),
           'state_root':str(tmp_path/'state'),
           'workspace_root':str(tmp_path/'workspaces'),'runtime_root':str(tmp_path/'runtime'),
           'runtime_entry':'cursor-agent','runtime_files':{'cursor-agent':gate.digest(executable.read_bytes())},
           'auth_file':str(tmp_path/'auth.json'),'subscription_only':True,'on_demand_disabled':True}
    (tmp_path/'config.json').write_text(json.dumps(value))
    assert gate.load_config(tmp_path/'config.json')==value
    try:
        yield value
    finally:
        shutil.rmtree(socket_root)


def request(config, model='composer-2.5', prompt='probe'):
    return {'model':model,'prompt':prompt,'cwd':str(Path(config['workspace_root'])/'task')}


def start_listener(config):
    path=Path(config['state_root']).parent/'config.json'
    process=subprocess.Popen([sys.executable,str(ROOT/'tools/qualification/session_gate.py'),
                              '--config',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    deadline=time.monotonic()+10
    listener=Path(config['socket'])
    while not listener.exists() and process.poll() is None and time.monotonic()<deadline:
        time.sleep(.02)
    assert listener.is_socket(), process.stderr.read().decode() if process.poll() is not None else ''
    return process


def blocked_exchange(config):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(config['socket'])
        connection.sendall(b'{}\n')
        return json.loads(connection.recv(4096))


def test_short_listener_really_binds_connects_and_restarts_with_durable_ledger(config):
    listener=Path(config['socket'])
    assert len(os.fsencode(str(listener)))<gate.SUN_PATH_BYTES
    for _ in range(2):
        process=start_listener(config)
        try:
            assert listener.stat().st_mode & 0o777==0o600
            assert blocked_exchange(config)['exit']==78
            assert json.loads((Path(config['state_root'])/'sessions.json').read_text())['sessions']==[]
        finally:
            process.send_signal(signal.SIGINT); process.wait(timeout=5)
        assert not listener.exists()


def test_overlong_or_stale_socket_rejected_before_ledger_write(config):
    path=Path(config['state_root']).parent/'config.json'
    original=Path(config['socket_root'])
    name='x'
    while len(os.fsencode(str(original.parent/name/'b.sock')))<gate.SUN_PATH_BYTES:
        name+='x'
    overlong=original.parent/name; overlong.mkdir(mode=0o700)
    try:
        changed={**config,'socket_root':str(overlong),'socket':str(overlong/'b.sock')}
        path.write_text(json.dumps(changed))
        assert len(os.fsencode(changed['socket']))>=gate.SUN_PATH_BYTES
        with pytest.raises(ValueError,match='sockaddr_un'): gate.load_config(path)
        assert not (Path(config['state_root'])/'sessions.json').exists()
    finally:
        overlong.rmdir()
    Path(config['socket']).write_text('collision evidence')
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError,match='collision'): gate.load_config(path)
    assert not (Path(config['state_root'])/'sessions.json').exists()


def test_socket_runtime_permissions_and_separation_fail_closed(config):
    path=Path(config['state_root']).parent/'config.json'
    root=Path(config['socket_root']); root.chmod(0o750)
    with pytest.raises(ValueError,match='private'): gate.load_config(path)
    assert not (Path(config['state_root'])/'sessions.json').exists()
    root.chmod(0o700)
    changed={**config,'state_root':config['socket_root'],
             'socket_root':config['socket_root'],
             'socket':str(Path(config['socket_root'])/'b.sock')}
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError,match='separate private runtime'): gate.load_config(path)
    assert not (Path(config['state_root'])/'sessions.json').exists()
    nested=Path(config['socket_root'])/'nested'; nested.mkdir(mode=0o700)
    changed={**config,'state_root':config['socket_root'],
             'socket_root':str(nested),'socket':str(nested/'b.sock')}
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError,match='must not overlap'): gate.load_config(path)
    assert not (Path(config['state_root'])/'sessions.json').exists()


def test_jail_entry_with_dummy_auth_only(config):
    payload={'config':{**config,'outer_mnt':os.readlink('/proc/self/ns/mnt'),
                      'outer_pid':os.readlink('/proc/self/ns/pid')}, **request(config)}
    result=subprocess.run(['/usr/bin/unshare','--user','--map-user=65534','--map-group=65534','--keep-caps',
        '--mount','--pid','--fork','--kill-child=SIGKILL',
        sys.executable,str(ROOT/'tools/qualification/jail.py')],input=json.dumps(payload),
        capture_output=True,text=True,timeout=10)
    assert result.returncode==0, result.stderr


def test_installed_cursor_helper_no_model_preflight_through_gate(config, tmp_path):
    helper_value=os.environ.get('HORIZON_CURSOR_SANDBOX')
    if not helper_value:
        pytest.skip('real Cursor helper unavailable in CI; helper preflight remains unverified')
    helper=Path(helper_value)
    assert helper.is_file() and helper.stat().st_uid==0 and not (helper.stat().st_mode & 0o4000)
    runtime=tmp_path/'runtime-real'; runtime.mkdir(mode=0o755)
    shutil.copy2(helper,runtime/'cursorsandbox'); (runtime/'cursorsandbox').chmod(0o755)
    staged_bwrap=helper.parent/'bwrap'
    if staged_bwrap.exists():
        shutil.copy2(staged_bwrap,runtime/'bwrap'); (runtime/'bwrap').chmod(0o755)
    agent=runtime/'cursor-agent'
    agent.write_text('''#!/usr/bin/python3 -I
import json, pathlib, subprocess, sys
policy=pathlib.Path.cwd()/'sandbox-policy.json'
policy.write_text(json.dumps({'sandbox':{'type':'workspace_readonly','cwd':str(pathlib.Path.cwd())}}))
r=subprocess.run(['/cursor-runtime/cursorsandbox','--policy',str(policy),'--preflight-only','/bin/true'],capture_output=True,text=True)
if r.returncode:
    pathlib.Path('helper-stderr').write_text(r.stderr); print(r.stderr,file=sys.stderr); raise SystemExit(78)
print(json.dumps({'type':'system','subtype':'init','model':'composer-2.5','session_id':'HELPER-PREFLIGHT'}))
print(json.dumps({'type':'result','subtype':'success','is_error':False}))
'''); agent.chmod(0o755)
    runtime_names=['cursor-agent','cursorsandbox'] + (['bwrap'] if (runtime/'bwrap').exists() else [])
    value={**config,'runtime_root':str(runtime),'runtime_files':{name:gate.digest((runtime/name).read_bytes()) for name in runtime_names}}
    broker=gate.Gate(value)
    result=broker.request({'model':'composer-2.5','prompt':'sandbox-preflight',
                           'cwd':str(Path(value['workspace_root'])/'task')})
    assert result['exit']==0, result
    state=json.loads(broker.path.read_text())
    assert len(state['sessions'])==1
    assert state['sessions'][0]['state']=='complete'
    assert state['sessions'][0]['observed_model']=='composer-2.5'
    assert state['sessions'][0]['child_diagnostic']=='no_child_diagnostics'
    broker.lock.close()


def test_long_durable_workspace_uses_short_child_alias_and_preserves_ledger_path(config):
    long_workspace=Path(config['workspace_root'])/('a'*100)/('b'*100)/'task'
    long_workspace.mkdir(parents=True)
    broker=gate.Gate(config)
    try:
        result=broker.request({'model':'composer-2.5','prompt':'probe','cwd':str(long_workspace)})
        assert result['exit']==0
    finally:
        broker.lock.close()
    state=json.loads((Path(config['state_root'])/'sessions.json').read_text())
    assert state['sessions'][0]['workspace']==str(long_workspace)
    assert len(os.fsencode(str(long_workspace)))>255


def test_long_cursor_trust_slug_reproduces_enametoolong_before_alias(tmp_path):
    durable = '/'+('/'.join(('opt','horizon-q') + ('x'*150, 'y'*150, 'task')))
    slug = __import__('re').sub(r'-+', '-', __import__('re').sub(r'[^a-zA-Z0-9]', '-', durable)).strip('-')
    assert len(os.fsencode(slug)) > 255
    target = tmp_path/'projects'/slug
    with pytest.raises(OSError) as error:
        target.mkdir(parents=True)
    assert error.value.errno == 36  # ENAMETOOLONG, the vendor trust-write failure


def test_long_durable_workspace_grok_keeps_readonly_policy_and_ledger_path(config):
    long_workspace=Path(config['workspace_root'])/('g'*100)/('h'*100)/'task'
    long_workspace.mkdir(parents=True)
    broker=gate.Gate(config)
    try:
        assert broker.request({'model':'composer-2.5','prompt':'probe','cwd':str(long_workspace)})['exit']==0
        result=broker.request({'model':'cursor-grok-4.6-high','prompt':'probe','cwd':str(long_workspace)})
        assert result['exit']==0
    finally:
        broker.lock.close()
    state=json.loads((Path(config['state_root'])/'sessions.json').read_text())
    assert state['sessions'][0]['workspace']==str(long_workspace)
    assert state['sessions'][1]['workspace']==str(long_workspace)
    assert state['sessions'][1]['model']=='cursor-grok-4.6-high'


def test_parent_result_file_mapping_is_structured_and_rejects_neighbor_paths(tmp_path):
    cwd=tmp_path/'work'; cwd.mkdir()
    inside=cwd/'executor-result.json'
    prompt=('BOUNDED WORKSTREAM ASSIGNMENT\n'+json.dumps({'result_file':str(inside),'literal':str(inside)+'-text'})+'\nTAIL')
    mapped=jail.map_bounded_result_file(prompt,str(cwd))
    assert '"result_file": "/workspace/executor-result.json"' in mapped
    assert str(inside)+'-text' in mapped
    with pytest.raises(ValueError,match='outside authorized workspace'):
        jail.map_bounded_result_file('BOUNDED WORKSTREAM ASSIGNMENT\n'+json.dumps({'result_file':str(tmp_path/'neighbor.json')}),str(cwd))


@pytest.mark.parametrize('stderr', ['pivot_root failed', 'detaching old root failed'])
def test_pivot_and_oldroot_failures_are_confinement_diagnostics(stderr):
    assert gate.child_diagnostic(stderr, 'process_exit', 78)=='confinement_startup_failure'


def test_vendor_grok_catalog_display_name_is_accepted_only_for_exact_route():
    result={'exit':0,'stdout':'\n'.join([
        json.dumps({'type':'system','subtype':'init','model':'Grok 4.6'}),
        json.dumps({'type':'result','subtype':'success','is_error':False}),
    ]),'stderr':'','reason':'process_exit'}
    assert gate.validate_output(result,'cursor-grok-4.6-high')
    assert not gate.validate_output(result,'composer-2.5')
    assert not gate.validate_output({**result,'stdout':result['stdout'].replace('Grok 4.6','Grok 4.7')},'cursor-grok-4.6-high')
    assert not gate.validate_output({**result,'stdout':result['stdout'].replace('Grok 4.6','Grok 4.6 Fast')},'cursor-grok-4.6-high')
    assert not gate.validate_output({**result,'stdout':result['stdout'].replace('Grok 4.6','Grok 4.6 Extra High')},'cursor-grok-4.6-high')


@pytest.mark.parametrize(('stdout','model','expected'), [
    ('not-json', 'cursor-grok-4.6-high', 'malformed_stream_json'),
    ('', 'cursor-grok-4.6-high', 'missing_events'),
    ('null', 'cursor-grok-4.6-high', 'malformed_event'),
    ('[]', 'cursor-grok-4.6-high', 'malformed_event'),
    ('1', 'cursor-grok-4.6-high', 'malformed_event'),
    (json.dumps({'type':'system','subtype':'init','model':'Grok 4.7'}), 'cursor-grok-4.6-high', 'identity_mismatch'),
])
def test_output_validation_reason_is_bounded_and_fail_closed(stdout, model, expected):
    result={'exit':0,'stdout':stdout,'stderr':'','reason':'process_exit'}
    assert gate.output_validation_reason(result, model)==expected
    assert gate.validate_output(result, model) is False


def test_output_validation_reason_rejects_non_string_stdout_without_leaking_content():
    assert gate.output_validation_reason({'exit':0,'stdout':None}, 'cursor-grok-4.6-high') == 'malformed_stream_json'


def test_output_identity_mismatch_reason_is_durable_class():
    stdout='\n'.join([
        json.dumps({'type':'system','subtype':'init','model':'Grok 4.7'}),
        json.dumps({'type':'result','subtype':'success','is_error':False}),
    ])
    assert gate.output_validation_reason({'exit':0,'stdout':stdout}, 'cursor-grok-4.6-high') == 'identity_mismatch'


def test_pivot_root_rejects_unknown_architecture_before_syscall(monkeypatch, tmp_path):
    monkeypatch.setattr(jail.platform, 'machine', lambda: 'unsupported-test-arch')
    with pytest.raises(OSError, match='unsupported architecture'):
        jail.pivot_root_into(tmp_path)


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


def test_leading_blank_lines_use_the_same_validation_and_attribution_parser(config):
    broker=gate.Gate(config)
    try:
        result=broker.request(request(config,prompt='blank-lines'))
        assert result['exit']==0
        sessions=json.loads(broker.path.read_text())['sessions']
        assert len(sessions)==1 and sessions[0]['state']=='complete'
        assert sessions[0]['observed_model']=='composer-2.5'
    finally:
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


def test_startup_failures_are_inspectable_without_echoing_paths():
    assert gate.sanitized_startup_failure(ValueError('socket collision'))=='socket collision'
    assert gate.sanitized_startup_failure(PermissionError(13,'denied','/secret/auth.json'))=='os_error_errno_13'
    assert gate.sanitized_startup_failure(KeyError('auth_file'))=='missing_configuration_field'
    assert '/secret' not in gate.sanitized_startup_failure(PermissionError(13,'denied','/secret/auth.json'))


def test_child_failure_persists_sanitized_launch_diagnostic_without_replay(config,monkeypatch):
    secret_stderr='Permission denied: /secret/auth.json bearer-token=do-not-persist'
    monkeypatch.setattr(gate, 'launch', lambda *args, **kwargs: {
        'exit': 78, 'stdout': '', 'stderr': secret_stderr, 'stderr_bytes': len(secret_stderr.encode()),
        'reason': 'process_exit'})
    broker=gate.Gate(config)
    try:
        result=broker.request(request(config))
        assert result['exit']==78
    finally:
        broker.lock.close()
    record=json.loads((Path(config['state_root'])/'sessions.json').read_text())['sessions'][0]
    assert record['state']=='uncertain'
    assert record['child_exit']==78
    assert record['launch_reason']=='process_exit'
    assert record['child_diagnostic']=='authentication_or_permission_failure'
    assert record['child_stderr_bytes']==len(secret_stderr.encode())
    assert record['child_stderr_sha256']==gate.digest(secret_stderr.encode())
    serialized=(Path(config['state_root'])/'sessions.json').read_text()
    assert '/secret/auth.json' not in serialized
    assert 'bearer-token' not in serialized
    broker=gate.Gate(config)
    with pytest.raises(ValueError,match='outcome uncertain'):
        broker.request(request(config))
    broker.lock.close()


@pytest.mark.parametrize(('stderr','expected'), [
    ('error: [unavailable] getaddrinfo EAI_AGAIN api2.cursor.sh', 'network_dns_failure'),
    ('TypeError: unable to verify the first certificate', 'network_tls_failure'),
    ('Fetch failed: connection reset by peer', 'network_transport_failure'),
])
def test_network_startup_diagnostics_are_allowlisted_without_persisting_text(stderr, expected):
    assert gate.child_diagnostic(stderr + ' bearer-token=do-not-persist', 'process_exit', 1) == expected


@pytest.mark.parametrize(('stderr','expected'), [
    ('HTTP 503 response from service', 'api_http_failure'),
    ('open /cursor-home/.config: EACCES', 'filesystem_access_failure'),
    ('sandbox setup: unshare failed with EPERM', 'sandbox_setup_failure'),
    ('unknown option --bad-flag', 'cursor_cli_argument_failure'),
])
def test_startup_diagnostic_classes_are_bounded_and_secret_free(stderr, expected):
    value = stderr + ' api_key=super-secret bearer-token=never-persist'
    assert gate.child_diagnostic(value, 'process_exit', 1) == expected


@pytest.mark.parametrize(('stderr','expected'), [
    ('API key rejected; retry number 503', 'child_process_failure'),
    ('unknown option --sandbox enabled', 'cursor_cli_argument_failure'),
    ('cursorsandbox preflight failed: EPERM', 'sandbox_setup_failure'),
    ('cannot drop jail privileges', 'sandbox_setup_failure'),
])
def test_diagnostic_context_does_not_shadow_cli_or_secrets(stderr, expected):
    assert gate.child_diagnostic(stderr + ' bearer-token=never-persist', 'process_exit', 1) == expected


@pytest.mark.parametrize('stderr', [
    'HTTP 503 response bearer-token=secret',
    'open /cache: EACCES api_key=secret',
    'cursorsandbox preflight failed: EPERM bearer-token=secret',
    'unknown option --sandbox api_key=secret',
])
def test_new_diagnostic_classes_persist_no_secret_and_block_replay(config, monkeypatch, stderr):
    monkeypatch.setattr(gate, 'launch', lambda *args, **kwargs: {
        'exit': 1, 'stdout': '', 'stderr': stderr, 'stderr_bytes': len(stderr.encode()),
        'reason': 'process_exit'})
    broker=gate.Gate(config)
    try:
        assert broker.request(request(config))['exit']==78
    finally:
        broker.lock.close()
    serialized=(Path(config['state_root'])/'sessions.json').read_text()
    assert 'secret' not in serialized and 'api_key' not in serialized and 'bearer-token' not in serialized
    broker=gate.Gate(config)
    with pytest.raises(ValueError,match='outcome uncertain'):
        broker.request(request(config))
    broker.lock.close()


def test_real_launch_propagates_child_exit_and_records_diagnostic(config):
    broker=gate.Gate(config)
    try:
        result=broker.request(request(config,prompt='exit78'))
        assert result['exit']==78
    finally:
        broker.lock.close()
    record=json.loads((Path(config['state_root'])/'sessions.json').read_text())['sessions'][0]
    assert record['state']=='uncertain'
    assert record['child_exit']==78
    assert record['launch_reason']=='process_exit'
    assert record['child_diagnostic']=='authentication_or_permission_failure'
    assert record['child_stderr_bytes']>0
    assert 'secret/auth' not in (Path(config['state_root'])/'sessions.json').read_text()


def test_reboot_or_interrupted_write_cannot_reset_deadline(config):
    broker=gate.Gate(config)
    path=broker.path; state=json.loads(path.read_text()); broker.lock.close()
    state['boot_id']='not-this-boot'; gate.save(path,state)
    broker=gate.Gate(config)
    with pytest.raises(ValueError,match='deadline expired'): broker.request(request(config))
    broker.lock.close()
    path.with_suffix('.pending').write_text('incomplete durable write')
    with pytest.raises(ValueError,match='interrupted ledger'): gate.Gate(config)
