"""Review regression: immutable prepared plan and frozen public runtime only."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest
from test_only.isolation import require_isolation

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/qualification'))
import session_gate as gate
spec=importlib.util.spec_from_file_location('qualification_prepare',ROOT/'tools/qualification/prepare.py')
prepare=importlib.util.module_from_spec(spec); spec.loader.exec_module(prepare)


@pytest.fixture(autouse=True)
def isolated():
    require_isolation(os.environ.get('TOP_DELIVERY_PG_ADMIN_URL',''))


def test_installed_pid_markers_never_enter_frozen_public_payload(tmp_path):
    source=tmp_path/'installed'; source.mkdir()
    (source/'index.js').write_text('public vendor code')
    (source/'.running').mkdir(); marker=source/'.running/123'; marker.write_text('dummy process marker')
    manifest={'files':{'index.js':gate.digest((source/'index.js').read_bytes())}}
    target=tmp_path/'frozen'
    prepare.freeze_public_payload(source,target,manifest)
    assert {p.name for p in target.iterdir()}=={'index.js'}
    assert marker.read_text()=='dummy process marker'  # installed state untouched
    (source/'unexpected-cache').write_text('dummy state')
    with pytest.raises(ValueError,match='allowlist'):
        prepare.freeze_public_payload(source,tmp_path/'second',manifest)
    assert not (tmp_path/'second').exists()


@pytest.mark.parametrize('extra',['.running/123','cache/session.json','unlisted.js'])
def test_frozen_runtime_rejects_unlisted_state_before_prepared_receipt(tmp_path,extra):
    for name in ('state','socket','workspaces','runtime'): (tmp_path/name).mkdir(mode=0o700)
    (tmp_path/'auth.json').write_text('{}')
    binary=tmp_path/'runtime/cursor-agent'; binary.write_text('simulated public payload')
    config={'schema':'horizon-qualification.v1','execution':'simulated','socket':str(tmp_path/'socket/b.sock'),
        'socket_root':str(tmp_path/'socket'),'state_root':str(tmp_path/'state'),
        'workspace_root':str(tmp_path/'workspaces'),
        'runtime_root':str(tmp_path/'runtime'),'runtime_entry':'cursor-agent',
        'runtime_files':{'cursor-agent':gate.digest(binary.read_bytes())},'auth_file':str(tmp_path/'auth.json'),
        'subscription_only':True,'on_demand_disabled':True}
    path=tmp_path/'gate.json'; path.write_text(json.dumps(config))
    assert gate.load_config(path)==config
    added=tmp_path/'runtime'/extra; added.parent.mkdir(parents=True,exist_ok=True); added.write_text('dummy')
    with pytest.raises(ValueError,match='inventory'):
        gate.load_config(path)
    assert not (tmp_path/'prepared.json').exists()


@pytest.mark.parametrize('fault',['gate_bytes','auth_reference','runtime_inventory','simulated_execution','socket_binding','submission_binding','endpoint_length','prepared_bytes'])
def test_authorization_binds_gate_inventory_auth_and_live_semantics(tmp_path,fault):
    socket_path=tmp_path/'b.sock'
    submission_path=tmp_path/'g.sock'
    config={'execution':'cursor-subscription','auth_file':str(tmp_path/'auth.json'),
            'socket':str(socket_path),'socket_root':str(tmp_path),
            'runtime_files':{'cursor-agent':'a'*64}}
    path=tmp_path/'gate.json'; prepare.durable_json(path,config)
    endpoints={
        'session_broker':{'path':str(socket_path),'encoded_bytes':len(os.fsencode(str(socket_path)))},
        'submission_listener':{'path':str(submission_path),'encoded_bytes':len(os.fsencode(str(submission_path)))},
        'postgresql':{'path':'/run/postgresql/.s.PGSQL.5432','encoded_bytes':len(os.fsencode('/run/postgresql/.s.PGSQL.5432'))},
        'authority_service':{'path':'/run/top-delivery/comms01-authority.sock','encoded_bytes':len(os.fsencode('/run/top-delivery/comms01-authority.sock'))},
    }
    value={'schema':'horizon-qualification-prepared.v2','status':'NOT_INVOKED','gate_config':str(path),
        'gate_sha256':gate.digest(path.read_bytes()),'runtime_inventory_sha256':gate.inventory_digest(config['runtime_files']),
        'authentication_reference_only':config['auth_file'],'broker_socket':str(socket_path),
        'broker_socket_path_bytes':len(os.fsencode(str(socket_path))),
        'submission_socket':str(submission_path),'submission_socket_path_bytes':len(os.fsencode(str(submission_path))),
        'socket_endpoints':endpoints,
        'maximum_sessions':5,'automatic_retries':0,'fallback_calls':0}
    prepared=tmp_path/'prepared.json'; prepare.durable_json(prepared,value)
    expected=gate.digest(prepared.read_bytes())
    assert gate.validate_prepared(prepared,expected,path)==value
    if fault=='gate_bytes': path.write_text(path.read_text()+'\n')
    if fault=='auth_reference': config['auth_file']=str(tmp_path/'different-auth.json')
    if fault=='runtime_inventory': config['runtime_files']['cursor-agent']='b'*64
    if fault=='simulated_execution': config['execution']='simulated'
    if fault=='socket_binding': config['socket']=str(tmp_path/'different.sock')
    if fault=='submission_binding': value['submission_socket']=str(tmp_path/'different-g.sock')
    if fault=='endpoint_length': value['socket_endpoints']['submission_listener']['encoded_bytes']+=1
    if fault in {'auth_reference','runtime_inventory','simulated_execution','socket_binding'}:
        path.write_text(json.dumps(config))
        # Even a freshly signed receipt cannot waive these semantic bindings.
        value['gate_sha256']=gate.digest(path.read_bytes())
        prepared.write_text(json.dumps(value)); expected=gate.digest(prepared.read_bytes())
    if fault in {'submission_binding','endpoint_length'}:
        prepared.write_text(json.dumps(value)); expected=gate.digest(prepared.read_bytes())
    if fault=='prepared_bytes': prepared.write_text(prepared.read_text()+'\n')
    with pytest.raises(ValueError,match='binding|digest'):
        gate.validate_prepared(prepared,expected,path)


def test_live_broker_without_prepared_pin_never_opens_socket(tmp_path):
    import subprocess
    result=subprocess.run([sys.executable,str(ROOT/'tools/qualification/session_gate.py'),
        '--config',str(tmp_path/'nonexistent.json'),'--execute-authorized-live'],capture_output=True,text=True)
    assert result.returncode==78 and not list(tmp_path.iterdir())


def test_final_generated_socket_path_is_short_private_and_really_connects(tmp_path):
    output=Path('/opt/operator-harness/artifacts')/('socket-test-'+tmp_path.name)
    root,paths=prepare.qualification_sockets(output,'a'*40)
    assert root.parent==Path('/opt/horizon-q')
    assert set(paths)=={'session_broker','submission_listener'}
    assert all(len(os.fsencode(str(path)))<gate.SUN_PATH_BYTES for path in paths.values())
    prepare.create_private_socket_root(root)
    assert root.stat().st_uid==0 and root.stat().st_mode & 0o777==0o700
    try:
        for path in paths.values():
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(path)); server.listen(1)
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(path))
                    connection,_=server.accept(); connection.close()
            path.unlink()
        with pytest.raises(ValueError,match='collision'):
            prepare.create_private_socket_root(root)
    finally:
        for path in paths.values():
            if path.exists(): path.unlink()
        root.rmdir()


def test_overlong_preparation_path_rejected_before_any_write(tmp_path,monkeypatch):
    def clean_git(argv,cwd,text=False):
        return 'a'*40+'\n' if argv[1:]==['rev-parse','HEAD'] else ''
    monkeypatch.setattr(prepare.subprocess,'check_output',clean_git)
    monkeypatch.setattr(prepare,'SHORT_SOCKET_BASE',Path('/run')/('x'*100))
    output=tmp_path/'must-not-exist'
    with pytest.raises(ValueError,match='sockaddr_un'):
        prepare.prepare(output,tmp_path/'runtime',tmp_path/'auth')
    assert not output.exists()


def test_final_generated_socket_visible_after_private_run_overmount(tmp_path):
    output=Path('/opt/operator-harness/artifacts')/('namespace-test-'+tmp_path.name)
    root,paths=prepare.qualification_sockets(output,'b'*40)
    assert all(not path.is_relative_to('/run') for path in paths.values())
    prepare.create_private_socket_root(root)
    child='''import socket,subprocess,sys
subprocess.run(['/usr/bin/mount','-t','tmpfs','tmpfs','/run'],check=True)
with socket.socket(socket.AF_UNIX) as connection:
    connection.connect(sys.argv[1]); connection.sendall(b'visible-after-private-run')
'''
    process=None
    try:
        for path in paths.values():
            with socket.socket(socket.AF_UNIX) as server:
                server.settimeout(10); server.bind(str(path)); server.listen(1)
                process=subprocess.Popen(['/usr/bin/unshare','--mount','--fork',sys.executable,
                                          '-c',child,str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                connection,_=server.accept()
                with connection: assert connection.recv(64)==b'visible-after-private-run'
                stdout,stderr=process.communicate(timeout=10)
                assert process.returncode==0,(stdout,stderr)
            path.unlink()
    finally:
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=5)
        for path in paths.values():
            if path.exists(): path.unlink()
        root.rmdir()
