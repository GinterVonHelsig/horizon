"""Actual packaged submission/worker CLIs and PostgreSQL; SIMULATED model processes.

Only systemd peer identity is provided by the existing private pytest seam.
No installed service, Cursor authentication, transport or model is exercised.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import shlex
import socket
import subprocess
import sys
import time

import pytest
from parent_controller import ParentController
from prompt_ingest import parse_prompt_file
from test_historical_upgrade import db_url  # recovered historical schema -> 021

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('submission_tests', ROOT/'tests/test_submission_release_package.py')
transport_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport_tests)
built = transport_tests.built


@pytest.fixture
def qualification_inputs():
    return None  # Live inputs exist only in the separately opt-in test module.


@pytest.fixture
def consumer(tmp_path, built, db_url, qualification_inputs):
    # Reuse real package consumer preparation, replacing receipt simulation with
    # a dispatcher that runs the actual packaged canonical CLI in a subprocess.
    base_consumer = transport_tests.consumer.__wrapped__(tmp_path, built)
    value = next(base_consumer)
    release, cfg_path, prompt = value
    prompt.write_text(prompt.read_text()+'\n## Ordered workstreams\n\n### 1. Parent\n\n## Cross-workstream acceptance matrix\n\n| Item | Required terminal disposition |\n|---|---|\n| 1. Parent | `PASS/PARENT` |\n\nDisposable test identity: '+tmp_path.name+'\n')
    prompt.write_text(prompt.read_text()+'\nParent continuation: acknowledge only the host-validated prerequisite product listed in VALIDATED PREREQUISITE PRODUCTS. Do not read paths outside this task workspace or create any other files. Write the assigned executor-result.json with disposition PASS/PARENT, evidence_summary, and adopted_product_sha256 equal to that validated product_sha256. Do not invoke shell, network, controllers, siblings, retries or remediation.\n')
    runtime_root=tmp_path/'runtime'
    runtime_root.mkdir(mode=0o700)
    fake = runtime_root/'cursor-agent'
    shutil.copyfile(ROOT/'controller/test_only/simulated_cursor_process.py', fake)
    fake.chmod(0o755)
    state=tmp_path/'session-state'; state.mkdir(mode=0o700)
    socket_root=transport_tests.configured_socket(value).parent
    simulated_auth_root=Path('/tmp')/('horizon-auth-'+socket_root.name)
    simulated_auth_root.mkdir(mode=0o700)
    simulated_auth=simulated_auth_root/'auth.json'
    simulated_auth.write_text('{}')
    standalone=tmp_path/'runs/standalone-review'; standalone.mkdir()
    gate_config={'schema':'horizon-qualification.v1','execution':'simulated',
        'socket':str(socket_root/'b.sock'),'socket_root':str(socket_root),
        'state_root':str(state),'workspace_root':str(tmp_path/'runs'),
        'runtime_root':str(runtime_root),'runtime_entry':'cursor-agent',
        'runtime_files':{'cursor-agent':transport_tests.runtime.digest(fake.read_bytes())},
        'auth_file':str(simulated_auth),'subscription_only':True,'on_demand_disabled':True}
    if qualification_inputs:
        gate_config=json.loads(Path(qualification_inputs['gate_config']).read_text())
        state=Path(gate_config['state_root'])
        assert tmp_path.is_relative_to(gate_config['workspace_root'])
    gate_path=tmp_path/'gate.json'; gate_path.write_text(json.dumps(gate_config))
    client=tmp_path/'qualification-client'
    client.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,'+repr(str(release/'tools/qualification'))+')\nfrom client import main\nraise SystemExit(main('+repr(str(gate_config['socket']))+','+repr(str(standalone))+'))\n')
    client.chmod(0o755)
    config = json.loads((tmp_path/'adapters.json').read_text())
    author = {k:v for k,v in config['adapters'][0].items() if k not in {'delivery_spec','subscription_only','on_demand_disabled'}}
    author.update(id='cursor-parent-composer', kind='cursor_cli', cursor_mode='agent')
    config['adapters'].append(author)
    config['routes']['default_executor'] = author['id']
    config['qualification_profile'] = 'cursor-disposable-v1'
    for adapter in config['adapters']:
        adapter.update(executable=str(client), allowed_cwd_roots=[str(tmp_path)], timeout_seconds=300 if qualification_inputs else 30)
    (tmp_path/'adapters.json').write_text(json.dumps(config))
    runtime_env = {k:v for k,v in os.environ.items() if k.startswith(('HORIZON_TEST_OUTER_', 'TOP_DELIVERY_'))}
    runtime_env.update(TOP_DELIVERY_DATABASE_URL=db_url, PYTHONPATH=str(ROOT/'controller'),
                       PATH='/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1')
    (tmp_path/'environment').write_text(json.dumps(runtime_env))
    dispatcher = tmp_path/'fake-systemd-run'
    dispatcher.write_text('''#!/usr/bin/python3 -I
import json,os,pathlib,subprocess,sys
root=pathlib.Path(__file__).parent
argv=sys.argv[1:]
target=argv.index('submit')-1
env=json.loads((root/'environment').read_text())
with (root/'calls.jsonl').open('a') as out: out.write(json.dumps(argv)+'\\n')
result=subprocess.run(argv[target-1:],env=env,capture_output=True)
if json.loads((root/'mode.json').read_text())=='lose-canonical-receipt': os._exit(5)
sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
''')
    dispatcher.chmod(0o755)
    cfg = json.loads(cfg_path.read_text())
    if qualification_inputs:
        cfg['socket_path']=qualification_inputs['submission_socket']
        assert Path(cfg['socket_path']).parent==Path(gate_config['socket_root'])
        assert len(os.fsencode(cfg['socket_path']))==qualification_inputs['submission_socket_path_bytes']
    python_pin=Path(cfg['python'])
    python_pin.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' '+shlex.quote(str(ROOT/'controller/test_only/packaged_cli.py'))+' "$@"\n')
    cfg['python_sha256']=transport_tests.runtime.digest(python_pin.read_bytes())
    cfg['adapter_sha256'] = transport_tests.runtime.digest((tmp_path/'adapters.json').read_bytes())
    cfg['systemd_run_sha256'] = transport_tests.runtime.digest(dispatcher.read_bytes())
    cfg_path.write_text(json.dumps(cfg))
    broker=None
    try:
        if qualification_inputs:
            assert Path(gate_config['socket']).is_socket()
        else:
            broker=subprocess.Popen([sys.executable,str(release/'tools/qualification/session_gate.py'),'--config',str(gate_path)],
                                    stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            deadline=time.monotonic()+10
            while not Path(gate_config['socket']).exists() and broker.poll() is None and time.monotonic()<deadline:
                time.sleep(.02)
            assert Path(gate_config['socket']).exists(),broker.stderr.read().decode() if broker.poll() is not None else ''
        yield value
    finally:
        if broker is not None:
            broker.terminate(); broker.communicate(timeout=5)
        try:
            next(base_consumer)
        except StopIteration:
            pass
        shutil.rmtree(simulated_auth_root)


server = transport_tests.server


def socket_inventory(consumer, qualification_inputs):
    root=consumer[1].parent
    gate=json.loads((root/'gate.json').read_text())
    if qualification_inputs:
        endpoints=qualification_inputs['socket_endpoints']
    else:
        submission=str(transport_tests.configured_socket(consumer))
        values={
            'session_broker':gate['socket'],
            'submission_listener':submission,
            'postgresql':'/run/postgresql/.s.PGSQL.5432',
            'authority_service':'/run/top-delivery/comms01-authority.sock',
        }
        endpoints={name:{'path':path,'encoded_bytes':len(os.fsencode(path))}
                   for name,path in values.items()}
    assert set(endpoints)=={'session_broker','submission_listener','postgresql','authority_service'}
    for endpoint in endpoints.values():
        assert endpoint['encoded_bytes']==len(os.fsencode(endpoint['path']))<transport_tests.runtime.SUN_PATH_BYTES
        assert Path(endpoint['path']).is_socket(), endpoint
    assert Path(endpoints['session_broker']['path']).parent==Path(endpoints['submission_listener']['path']).parent
    assert not Path(endpoints['session_broker']['path']).is_relative_to(root)
    # Real connections in the namespace which will dispatch. Close-only probes
    # prove visibility without consuming a broker session or application row.
    for name in ('session_broker','postgresql','authority_service'):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.connect(endpoints[name]['path'])
    health=transport_tests.invoke(consumer,'top-delivery-host-gateway','health')
    assert health.returncode==0,health.stdout+health.stderr
    assert json.loads(health.stdout)['status']=='ok'
    assert not transport_tests.calls(consumer)
    return {name:{'path':item['path'],'encoded_bytes':item['encoded_bytes'],
                  'mount_namespace':os.readlink('/proc/self/ns/mnt')}
            for name,item in endpoints.items()}


@pytest.mark.parametrize('first_path',['direct','socket'])
def test_packaged_submission_to_durable_whole_goal(consumer, server, db_url, first_path, qualification_inputs):
    release, cfg_path, prompt = consumer
    root = cfg_path.parent
    config = json.loads((root/'adapters.json').read_text())
    endpoints=socket_inventory(consumer,qualification_inputs)
    parsed = parse_prompt_file(prompt)
    artifacts = root/'runs'/parsed.run_id/'artifacts'
    artifacts.mkdir(parents=True)
    parent = ParentController(db_url, artifact_root=artifacts, adapter_config=config,
                              controller_lease_seconds=1800, max_retries=0)
    try:
        parent.register_run(parsed.run_id)
        parent._ensure_epoch(parsed.run_id)
        prereq = prompt.parent/'prerequisites.json'
        prereq.write_text(json.dumps({'1':[config['adapters'][0]['delivery_spec']]}))
        flags = ['--prerequisites-json', prereq, '--prerequisites-sha256', transport_tests.runtime.digest(prereq.read_bytes())]
        direct=['top-delivery-submit', prompt, *flags]
        socket=['top-delivery-host-gateway', 'submit', '--prompt', prompt, *flags]
        first = transport_tests.invoke(consumer, *(direct if first_path=='direct' else socket))
        assert first.returncode == 0, first.stdout+first.stderr
        repeat = transport_tests.invoke(consumer, *(socket if first_path=='direct' else direct))
        assert repeat.returncode == 0 and repeat.stdout == first.stdout
        assert len(transport_tests.calls(consumer)) == 1
        env = json.loads((root/'environment').read_text())
        def cli(name, args):
            return subprocess.run([sys.executable, str(ROOT/'controller/test_only/packaged_cli.py'),
                                   str(release/'controller'/name), *args], env=env,
                                  capture_output=True, text=True, timeout=660 if qualification_inputs else 40)
        status_args = ['status', '--run-id', parsed.run_id, '--artifact-root', str(artifacts)]
        before = cli('goal_cli.py', status_args)
        assert before.returncode == 2, before.stdout+before.stderr
        worker_args = ['--once', '--run-id', parsed.run_id, '--artifact-root', str(artifacts),
                       '--config', str(root/'adapters.json'), '--qualification-profile', 'cursor-disposable-v1',
                       '--health-dir', str(root/'health')]
        steps = []
        for owner in ('prerequisite-gate', 'bounded-provider', 'parent-continuation'):
            result = cli('worker_cli.py', [*worker_args, '--owner', owner])
            steps.append({'exit': result.returncode, 'stdout': result.stdout})
            assert result.returncode == (1 if owner == 'prerequisite-gate' else 0), result.stdout+result.stderr+str({str(p.relative_to(artifacts)):p.read_text()[-3000:] for p in artifacts.rglob('*') if p.is_file() and p.name in {'process-result.json','stderr.txt','result.json'}})
        after = cli('goal_cli.py', status_args)
        assert after.returncode == 0, after.stdout+after.stderr+str(steps)
        assert json.loads(after.stdout)['status'] == 'complete'
        state_root=Path(json.loads((root/'gate.json').read_text())['state_root'])
        sessions=json.loads((state_root/'sessions.json').read_text())['sessions']
        assert len(sessions)==4 and all(s['state']=='complete' for s in sessions)
        assert [s['model'] for s in sessions]==['composer-2.5','cursor-grok-4.6-high']*2
        if qualification_inputs:
            assert all(s['execution']=='cursor-subscription' and s['observed_model'] in {'Composer 2.5','Cursor Grok 4.6 High'}
                       and s['runtime_inventory_sha256']==qualification_inputs['runtime_inventory_sha256'] for s in sessions)
        with parent._repo.transaction() as cur:
            cur.execute('SELECT product_digest FROM horizon_prerequisite_adoptions WHERE run_id=%s', (parsed.run_id,))
            adoptions=list(cur.fetchall())
            assert len(adoptions)==1
        parent_result=next(json.loads(p.read_text()) for p in artifacts.rglob('harness-result.json')
                           if json.loads(p.read_text()).get('adapter_id')=='cursor-parent-composer')
        assert parent_result['structured_payload']['extracted_json']['adopted_product_sha256']==adoptions[0]['product_digest']
        (root/'packaged-chain-evidence.json').write_text(json.dumps({'execution':'CURSOR SUBSCRIPTION' if qualification_inputs else 'SIMULATED MODEL SUBPROCESSES',
            'service_identity':'pytest private seam, not live systemd', 'steps':steps,
            'durable_status':json.loads(after.stdout),'socket_endpoints':endpoints,
            'durable_artifact_root':str(root)}, indent=2))
        standalone_review(root, artifacts, config, db_url, parsed.run_id, qualification_inputs)
        sessions=json.loads((state_root/'sessions.json').read_text())['sessions']
        assert len(sessions)==5 and all(s['state']=='complete' for s in sessions)
        if qualification_inputs:
            assert sessions[-1]['execution']=='cursor-subscription'
            assert sessions[-1]['observed_model']=='Cursor Grok 4.6 High'
            assert sessions[-1]['runtime_inventory_sha256']==qualification_inputs['runtime_inventory_sha256']
    finally:
        parent.close()


def standalone_review(root, artifacts, config, db_url, run_id, qualification_inputs):
    """Separate launcher protocol; never substitutes for the worker's review."""
    import yaml
    from model_routing import RoutingRecord, load_model_routing
    from qualification_profile import worker_policy
    builder=transport_tests.module('review_package',ROOT/'tools/host_review/package.py')
    release=Path(qualification_inputs['review_release']) if qualification_inputs else root/'review-release'
    if not qualification_inputs: builder.stage(release,allow_uncommitted=True)
    evidence=root/'standalone-evidence'; evidence.mkdir(mode=0o700)
    author_result=next(p for p in artifacts.rglob('harness-result.json')
                       if json.loads(p.read_text()).get('adapter_id')=='cursor-parent-composer')
    result=json.loads(author_result.read_text())
    assert result['status']=='success' and result['provider']=='cursor' and result['model']=='composer-2.5'
    def artifact(name,data):
        path=evidence/name
        path.write_bytes(data if isinstance(data,bytes) else json.dumps(data).encode())
        return {'path':name,'sha256':transport_tests.runtime.digest(path.read_bytes())}
    subject=artifact('packet.md',json.dumps({'boundary':'standalone reviewer; not worker auditor',
        'author_result':result,'executor_stdout':(author_result.parent/'stdout.txt').read_text(),
        'durable_chain':json.loads((root/'packaged-chain-evidence.json').read_text())}).encode())
    author=artifact('author.json',{'run_id':run_id,'subject_sha256':subject['sha256'],
        'result':artifact('author-result.json',author_result.read_bytes()),
        'route':RoutingRecord('3A','actual-parent-author','cursor','composer-2.5','cursor-agent','subscription','default','none').to_dict()})
    artifact('context.json',{'run_id':run_id,'subject':subject,'authors':[author],'reviews':[],
        'max_calls':1,'fallback_calls':0,'on_demand_disabled_operator_confirmed':True,
        'available_routes':[{'provider':'cursor','model':'cursor-grok-4.6-high'}]})
    artifact('system.md',b'Read-only independent review of this disposable completion evidence. No execution or file changes.')
    routing=evidence/'routing.yaml'
    routing.write_text(yaml.safe_dump(worker_policy(load_model_routing(ROOT/'architecture/model-routing.yaml'),config,'cursor-disposable-v1',db_url)))
    client=root/'qualification-client'
    consumer=evidence/'consumer.json'
    consumer.write_text(json.dumps({'schema':'horizon-review-consumer.v1','enabled':True,'transport':'cursor',
        'cursor_executable':str(client),'cursor_sha256':transport_tests.runtime.digest(client.read_bytes()),
        'routing_yaml':str(routing),'routing_sha256':transport_tests.runtime.digest(routing.read_bytes())}))
    reviewed=subprocess.run([str(release/'bin/cursor-independent-review'),'--consumer-config',str(consumer),
        '--seat','4','--run-id',run_id,'--artifact-root',str(evidence),'--review-context',str(evidence/'context.json'),
        '--system-file',str(evidence/'system.md'),'--user-file',str(evidence/'packet.md')],
        capture_output=True,text=True,timeout=930 if qualification_inputs else 30)
    assert reviewed.returncode==0, reviewed.stdout+reviewed.stderr
    record=json.loads(reviewed.stdout)
    assert record['provider']=='cursor' and record['transport']=='cursor-agent'
    (root/'standalone-review-evidence.json').write_text(reviewed.stdout)


def test_lost_packaged_receipt_preserves_one_durable_graph_without_redispatch(consumer,server,db_url):
    release,cfg,prompt=consumer
    root=cfg.parent; parsed=parse_prompt_file(prompt)
    artifacts=root/'runs'/parsed.run_id/'artifacts'; artifacts.mkdir(parents=True)
    config=json.loads((root/'adapters.json').read_text())
    parent=ParentController(db_url,artifact_root=artifacts,adapter_config=config,controller_lease_seconds=1800)
    try:
        parent.register_run(parsed.run_id); parent._ensure_epoch(parsed.run_id)
        (root/'mode.json').write_text('"lose-canonical-receipt"')
        failed=transport_tests.invoke(consumer,'top-delivery-submit',prompt)
        assert failed.returncode==78
        repeated=transport_tests.invoke(consumer,'top-delivery-host-gateway','submit','--prompt',prompt)
        assert repeated.returncode==78 and len(transport_tests.calls(consumer))==1
        env=json.loads((root/'environment').read_text())
        dispatched=transport_tests.calls(consumer)[0]
        # Reconcile the immutable journal snapshot, not a new source pathname.
        reconciled=subprocess.run(dispatched[dispatched.index('submit')-2:],
            env=env,capture_output=True,text=True,timeout=20)
        assert reconciled.returncode==0, reconciled.stdout+reconciled.stderr
        with parent._repo.transaction() as cur:
            cur.execute('SELECT count(*) AS n FROM horizon_goal_graphs WHERE run_id=%s',(parsed.run_id,))
            assert cur.fetchone()['n']==1
            cur.execute('SELECT count(*) AS n FROM parent_tasks WHERE run_id=%s',(parsed.run_id,))
            assert cur.fetchone()['n']==1
        state=json.loads((root/'session-state/sessions.json').read_text())
        assert state['sessions']==[]
        assert parent.durable_goal_status(parsed.run_id)['exit_code']==2
        # Durable state reconciles; an unknown transport receipt is not invented.
        assert transport_tests.invoke(consumer,'top-delivery-submit',prompt).returncode==78
    finally:
        parent.close()
