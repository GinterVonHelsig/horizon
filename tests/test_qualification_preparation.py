"""Review regression: immutable prepared plan and frozen public runtime only."""
import importlib.util
import json
import os
from pathlib import Path
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
    for name in ('state','workspaces','runtime'): (tmp_path/name).mkdir(mode=0o700)
    (tmp_path/'auth.json').write_text('{}')
    binary=tmp_path/'runtime/cursor-agent'; binary.write_text('simulated public payload')
    config={'schema':'horizon-qualification.v1','execution':'simulated','socket':str(tmp_path/'state/session.sock'),
        'state_root':str(tmp_path/'state'),'workspace_root':str(tmp_path/'workspaces'),
        'runtime_root':str(tmp_path/'runtime'),'runtime_entry':'cursor-agent',
        'runtime_files':{'cursor-agent':gate.digest(binary.read_bytes())},'auth_file':str(tmp_path/'auth.json'),
        'subscription_only':True,'on_demand_disabled':True}
    path=tmp_path/'gate.json'; path.write_text(json.dumps(config))
    assert gate.load_config(path)==config
    added=tmp_path/'runtime'/extra; added.parent.mkdir(parents=True,exist_ok=True); added.write_text('dummy')
    with pytest.raises(ValueError,match='inventory'):
        gate.load_config(path)
    assert not (tmp_path/'prepared.json').exists()


@pytest.mark.parametrize('fault',['gate_bytes','auth_reference','runtime_inventory','simulated_execution','prepared_bytes'])
def test_authorization_binds_gate_inventory_auth_and_live_semantics(tmp_path,fault):
    config={'execution':'cursor-subscription','auth_file':str(tmp_path/'auth.json'),
            'runtime_files':{'cursor-agent':'a'*64}}
    path=tmp_path/'gate.json'; prepare.durable_json(path,config)
    value={'schema':'horizon-qualification-prepared.v1','status':'NOT_INVOKED','gate_config':str(path),
        'gate_sha256':gate.digest(path.read_bytes()),'runtime_inventory_sha256':gate.inventory_digest(config['runtime_files']),
        'authentication_reference_only':config['auth_file'],'maximum_sessions':5,'automatic_retries':0,'fallback_calls':0}
    prepared=tmp_path/'prepared.json'; prepare.durable_json(prepared,value)
    expected=gate.digest(prepared.read_bytes())
    assert gate.validate_prepared(prepared,expected,path)==value
    if fault=='gate_bytes': path.write_text(path.read_text()+'\n')
    if fault=='auth_reference': config['auth_file']=str(tmp_path/'different-auth.json')
    if fault=='runtime_inventory': config['runtime_files']['cursor-agent']='b'*64
    if fault=='simulated_execution': config['execution']='simulated'
    if fault in {'auth_reference','runtime_inventory','simulated_execution'}:
        path.write_text(json.dumps(config))
        # Even a freshly signed receipt cannot waive these semantic bindings.
        value['gate_sha256']=gate.digest(path.read_bytes())
        prepared.write_text(json.dumps(value)); expected=gate.digest(prepared.read_bytes())
    if fault=='prepared_bytes': prepared.write_text(prepared.read_text()+'\n')
    with pytest.raises(ValueError,match='binding|digest'):
        gate.validate_prepared(prepared,expected,path)


def test_live_broker_without_prepared_pin_never_opens_socket(tmp_path):
    import subprocess
    result=subprocess.run([sys.executable,str(ROOT/'tools/qualification/session_gate.py'),
        '--config',str(tmp_path/'nonexistent.json'),'--execute-authorized-live'],capture_output=True,text=True)
    assert result.returncode==78 and not list(tmp_path.iterdir())
