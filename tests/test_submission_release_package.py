"""Packaged direct/socket consumers with fake systemd-run; no services/DB/models."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


builder = module('submission_package', ROOT / 'tools/submission_transport/package.py')
runtime = module('submission_runtime', ROOT / 'tools/submission_transport/transport.py')


@pytest.fixture(scope='session')
def built(tmp_path_factory):
    path = tmp_path_factory.mktemp('submission-build') / 'release'
    builder.stage(path, allow_uncommitted=True)
    return path


@pytest.fixture
def consumer(tmp_path, built):
    release = tmp_path / 'release'
    shutil.copytree(built, release)
    for name in ('prompts', 'runs', 'journal'):
        (tmp_path / name).mkdir(mode=0o700)
    prompt = tmp_path / 'prompts' / 'goal.md'
    prompt.write_text('# Disposable submission\n\n**Objective:** Parse only.\n\n## Mission\n\nTest transport.\n\n## P0 authority envelope\n\nAllowed:\n\n- disposable work\n\nForbidden without a new explicit authority envelope:\n\n- production\n')
    (tmp_path / 'environment').write_text('# simulated only, no credentials\n')
    (tmp_path / 'adapters.json').write_text('{}\n')
    fake = tmp_path / 'fake-systemd-run'
    fake.write_text('''#!/usr/bin/python3 -I
import json,os,pathlib,sys,time
root=pathlib.Path(__file__).parent
args=sys.argv[1:]
with (root/'calls.jsonl').open('a') as stream: stream.write(json.dumps(args)+'\\n')
identity=json.loads((pathlib.Path(args[args.index('--prompt')+1]).parent/'request.json').read_text())
mode=json.loads((root/'mode.json').read_text())
(root/'child-pid').write_text(str(os.getpid()))
if mode=='wait':
    (root/'effect').write_text('one simulated registration; not model execution')
    while not (root/'release-child').exists(): time.sleep(.01)
if mode=='delay': time.sleep(.2)
value={'run_id':identity['existing_parent'] or identity['submission_run_id'],
       'submission_run_id':identity['submission_run_id'],'parent_run_id':identity['existing_parent'],
       'prompt_digest':identity['prompt_sha256'],'task_ids':identity['task_ids'],
       'mode':'durable','status':'preserved_disabled' if mode=='paused' else 'created'}
if mode=='wrong_digest': value['prompt_digest']='0'*64
if mode=='array': print('[]')
elif mode=='malformed': print('DO_NOT_EMIT_CHILD_DIAGNOSTICS')
else: print(json.dumps(value))
if mode=='nonzero': raise SystemExit(5)
''')
    fake.chmod(0o755)
    (tmp_path / 'mode.json').write_text('"ok"')
    manifest = json.loads((release / 'manifest.json').read_text())
    python = Path(sys.executable).resolve()
    cfg = {'schema':'horizon-submission-consumer.v1','enabled':True,'release_root':str(release),
        'release_commit':manifest['source_commit'],'release_manifest_sha256':runtime.digest((release/'manifest.json').read_bytes()),
        'prompt_root':str(tmp_path/'prompts'),'runs_root':str(tmp_path/'runs'),'journal_root':str(tmp_path/'journal'),
        'socket_path':str(tmp_path/'s'),'service_uid':os.geteuid(),'socket_gid':os.getegid(),'allowed_uids':[os.geteuid()],
        'systemd_run':str(fake),'systemd_run_sha256':runtime.digest(fake.read_bytes()),
        'python':str(python),'python_sha256':runtime.digest(python.read_bytes()),
        'environment_file':str(tmp_path/'environment'),'adapter_config':str(tmp_path/'adapters.json'),
        'adapter_sha256':runtime.digest((tmp_path/'adapters.json').read_bytes())}
    path = tmp_path / 'consumer.json'
    path.write_text(json.dumps(cfg))
    return release, path, prompt


def command(consumer, entry, *args):
    release, cfg, _ = consumer
    return [str(release/'bin'/entry), '--config', str(cfg), *map(str,args)]


def env():
    return {'PATH':str(Path(sys.executable).parent)+':/usr/bin:/bin','PYTHONPATH':'/nonexistent-checkout'}


def invoke(consumer, entry, *args):
    return subprocess.run(command(consumer,entry,*args),env=env(),cwd=consumer[1].parent,
        capture_output=True,text=True,timeout=20)


def calls(consumer):
    path = consumer[1].parent/'calls.jsonl'
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


@pytest.fixture
def server(consumer):
    process = subprocess.Popen(command(consumer,'top-delivery-host-gateway-server'), env=env(),
        cwd=consumer[1].parent, stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    path = consumer[1].parent/'s'
    deadline = time.monotonic()+10
    while not path.exists() and process.poll() is None and time.monotonic()<deadline:
        time.sleep(.02)
    assert path.exists(), process.communicate(timeout=2)
    yield process
    process.terminate()
    process.communicate(timeout=10)


def test_both_paths_share_release_config_journal_and_receipt(consumer, server):
    release, cfg, prompt = consumer
    inspected = invoke(consumer,'top-delivery-submit','--inspect',prompt)
    assert inspected.returncode == 0, inspected.stdout+inspected.stderr
    assert not calls(consumer) and not list((cfg.parent/'journal').iterdir())
    socket_inspect = invoke(consumer,'top-delivery-host-gateway','inspect','--prompt',prompt)
    assert socket_inspect.returncode == 0, socket_inspect.stdout+socket_inspect.stderr
    assert json.loads(socket_inspect.stdout) == json.loads(inspected.stdout)
    submitted = invoke(consumer,'top-delivery-host-gateway','submit','--prompt',prompt)
    assert submitted.returncode == 0, submitted.stdout+submitted.stderr
    repeated = invoke(consumer,'top-delivery-submit',prompt)
    assert repeated.returncode == 0 and repeated.stdout == submitted.stdout
    assert len(calls(consumer)) == 1
    argv = calls(consumer)[0]
    assert str(release/'controller/goal_cli.py') in argv
    assert '--unit=top-delivery-entrypoint@top-delivery-controller' in argv
    assert '--adapter-config' in argv and '--database-url' not in argv
    assert 'd7305d4' not in str(argv) and '/current/' not in str(argv)
    assert json.loads(submitted.stdout)['release_commit'] == json.loads(cfg.read_text())['release_commit']


@pytest.mark.parametrize('fault', ['release_hash','release_commit','current_symlink','adapter_hash','disabled','host_only','outside_prompt','prompt_traversal','open_permissions','denied_peer'])
def test_consumer_rejects_before_dispatch(consumer, fault):
    release,cfg,prompt = consumer
    value=json.loads(cfg.read_text())
    if fault=='release_hash': value['release_manifest_sha256']='0'*64
    if fault=='release_commit': value['release_commit']='0'*40
    if fault=='current_symlink':
        link=cfg.parent/'current'
        link.symlink_to(release,target_is_directory=True)
        value['release_root']=str(link)
    if fault=='adapter_hash': value['adapter_sha256']='0'*64
    if fault=='disabled': value['enabled']=False
    if fault=='denied_peer': value['allowed_uids']=[os.geteuid()+10000]
    if fault=='host_only': prompt.write_text(prompt.read_text()+'\nDo not invoke `$top-delivery`.\n')
    if fault in {'outside_prompt','prompt_traversal'}:
        other=cfg.parent/'outside.md'
        other.write_bytes(prompt.read_bytes())
        prompt=other
        if fault=='prompt_traversal': prompt=cfg.parent/'prompts'/'..'/'outside.md'
    cfg.write_text(json.dumps(value))
    if fault=='open_permissions': cfg.chmod(0o666)
    result=invoke(consumer,'top-delivery-submit',prompt)
    assert result.returncode==78, result.stdout+result.stderr
    assert calls(consumer)==[]
    assert not list((cfg.parent/'journal').iterdir())


@pytest.mark.parametrize('mode', ['nonzero','malformed','array','wrong_digest','paused'])
def test_failed_child_or_disabled_run_is_not_success_and_never_replayed(consumer, mode):
    _,cfg,prompt=consumer
    (cfg.parent/'mode.json').write_text(json.dumps(mode))
    result=invoke(consumer,'top-delivery-submit',prompt)
    assert result.returncode==78
    assert 'DO_NOT_EMIT' not in result.stdout+result.stderr
    assert invoke(consumer,'top-delivery-submit',prompt).returncode==78
    assert len(calls(consumer))==1


def test_concurrent_direct_and_socket_consumers_dispatch_once(consumer, server):
    _,cfg,prompt=consumer
    (cfg.parent/'mode.json').write_text('"delay"')
    direct=subprocess.Popen(command(consumer,'top-delivery-submit',prompt),env=env(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    other=invoke(consumer,'top-delivery-host-gateway','submit','--prompt',prompt)
    stdout,stderr=direct.communicate(timeout=20)
    assert direct.returncode==other.returncode==0,stderr+other.stderr
    assert stdout==other.stdout and len(calls(consumer))==1


def test_unknown_effect_after_process_death_blocks_other_path(consumer, server):
    _,cfg,prompt=consumer
    (cfg.parent/'mode.json').write_text('"wait"')
    process=subprocess.Popen(command(consumer,'top-delivery-submit',prompt),env=env(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    deadline=time.monotonic()+10
    while not (cfg.parent/'effect').exists() and time.monotonic()<deadline: time.sleep(.02)
    assert (cfg.parent/'effect').exists()
    process.kill()
    (cfg.parent/'release-child').write_text('finish fake child only')
    process.communicate(timeout=10)
    result=invoke(consumer,'top-delivery-host-gateway','submit','--prompt',prompt)
    assert result.returncode==78 and 'outcome_unknown' in result.stdout
    assert len(calls(consumer))==1


@pytest.mark.parametrize('boundary', ['snapshot','intent','receipt','final_state'])
def test_partial_journal_failure_recovery(consumer, monkeypatch, boundary):
    release,cfg,prompt=consumer
    monkeypatch.setattr(runtime,'ROOT',release)
    config=runtime.load_config(cfg)
    request={'operation':'submit','prompt_path':str(prompt),'prompt_sha256':runtime.digest(prompt.read_bytes())}
    original=runtime.atomic
    def fail(path,value):
        if (boundary=='snapshot' and path.name=='prompt.md'
            or boundary=='intent' and path.name=='state.json' and value['state']=='dispatch_intent'
            or boundary=='receipt' and path.name=='receipt.json'
            or boundary=='final_state' and path.name=='state.json' and value['state']=='receipt_recorded'):
            raise OSError('simulated interrupted persistence')
        return original(path,value)
    monkeypatch.setattr(runtime,'atomic',fail)
    try: runtime.handle(config,request,os.geteuid())
    except OSError: pass
    monkeypatch.setattr(runtime,'atomic',original)
    result=invoke(consumer,'top-delivery-submit',prompt)
    assert result.returncode==(78 if boundary=='receipt' else 0),result.stdout+result.stderr
    assert len(calls(consumer))==1


def test_existing_parent_forwarding_and_changed_destination_conflict(consumer, server):
    _,cfg,prompt=consumer
    parent='goal-'+'a'*16
    (cfg.parent/'runs'/parent/'artifacts').mkdir(parents=True)
    result=invoke(consumer,'top-delivery-host-gateway','submit','--prompt',prompt,'--existing-parent',parent)
    assert result.returncode==0,result.stdout+result.stderr
    argv=calls(consumer)[0]
    assert argv[argv.index('--existing-parent')+1]==parent
    assert argv[argv.index('--runtime-artifact-root')+1]==str(cfg.parent/'runs'/parent/'artifacts')
    conflict=invoke(consumer,'top-delivery-host-gateway','submit','--prompt',prompt,'--existing-parent',parent,
        '--artifact-root',cfg.parent/'runs'/'different')
    assert conflict.returncode==78 and len(calls(consumer))==1


def test_artifact_traversal_rejected_before_journal_or_dispatch(consumer, server):
    _,cfg,prompt=consumer
    result=invoke(consumer,'top-delivery-host-gateway','submit','--prompt',prompt,
        '--artifact-root',cfg.parent/'runs'/'..'/'escape')
    assert result.returncode==78, result.stdout+result.stderr
    assert calls(consumer)==[] and not list((cfg.parent/'journal').iterdir())


def test_recovery_is_explicitly_blocked_and_peer_credentials_fail_closed(consumer, server, monkeypatch):
    _,_,prompt=consumer
    result=invoke(consumer,'top-delivery-host-gateway','execute-recovery','--prompt',prompt)
    assert result.returncode==78 and 'historical_recovery' in result.stdout
    assert not calls(consumer)
    monkeypatch.delattr(socket,'SO_PEERCRED')
    with pytest.raises(ValueError,match='unavailable'): runtime.peer_uid(None)


def test_client_disconnect_after_receipt_recovers_without_dispatch(consumer, server):
    _,cfg,prompt=consumer
    request={'operation':'submit','prompt_path':str(prompt),'prompt_sha256':runtime.digest(prompt.read_bytes())}
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.connect(str(cfg.parent/'s'))
        client.sendall(runtime.encoded(request))
    result=invoke(consumer,'top-delivery-submit',prompt)
    assert result.returncode==0,result.stdout+result.stderr
    assert len(calls(consumer))==1


def test_busy_attested_unit_refuses_before_effect_and_recovers(consumer):
    import fcntl
    _,cfg,prompt=consumer
    with (cfg.parent/'journal'/'dispatch.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        result=invoke(consumer,'top-delivery-submit',prompt)
        assert result.returncode==78 and 'before_effect_safe_to_retry' in result.stdout
        assert calls(consumer)==[]
    assert invoke(consumer,'top-delivery-submit',prompt).returncode==0
    assert len(calls(consumer))==1


def test_invalid_server_config_stops_with_nonrestartable_exit(consumer):
    release,cfg,_=consumer
    value=json.loads(cfg.read_text())
    value['release_commit']='0'*40
    cfg.write_text(json.dumps(value))
    result=invoke(consumer,'top-delivery-host-gateway-server')
    assert result.returncode==78 and 'invalid_service_configuration' in result.stdout
    assert 'RestartPreventExitStatus=78' in (release/'tools/submission_transport/host-gateway.service.in').read_text()
    assert not (cfg.parent/'s').exists() and not calls(consumer)


def test_socket_dry_run_flag_cannot_become_durable_submit(consumer, server):
    _,cfg,prompt=consumer
    result=invoke(consumer,'top-delivery-host-gateway','submit','--prompt',prompt,'--dry-run')
    assert result.returncode==78 and calls(consumer)==[]
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.connect(str(cfg.parent/'s'))
        client.sendall(runtime.encoded({'operation':'submit','prompt_path':str(prompt),
            'prompt_sha256':runtime.digest(prompt.read_bytes()),'dry_run':True}))
        assert runtime.receive(client)['status']=='blocked'
    assert calls(consumer)==[]
