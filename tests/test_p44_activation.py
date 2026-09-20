"""P44 handover and lifecycle regression tests; no live service or DB mutation."""
import copy
import hashlib
import json
import os
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

import recovery_handover as handover
import recovery_lifecycle as lifecycle
import recovery_start as start
import supervisor_identity as tick
from test_p40_root_cause_repair import recovery_source, recovery_start_fixture
from test_p43_activation import external_acceptance


def identity_fixture():
    return {'supervisor':{'pid':42, 'ppid':41, 'start_ticks':1},
            'controller':{'pid':41, 'ppid':1, 'start_ticks':1},
            'boot_id':'fixture-boot', 'invocation_id':'a'*32, 'owner':'fixture-owner',
            'run_id':start.PARENT, 'interval_seconds':30.0}


def queue_fixture():
    identity = identity_fixture()
    return {'lease_live':True, 'lease':{'owner':identity['owner'], 'run_id':start.PARENT,
            'current_epoch':7, 'lease_expires_at':'fixed-one-hour-expiry'},
        'supervisor_tick':{'event_id':'fixture-event', 'event_seq':42, 'controller_epoch':7,
            'age_seconds':0.1, 'detail':{**identity, 'controller_epoch':7,
                                      'completed_monotonic_ns':time.monotonic_ns()}}}


@pytest.mark.parametrize('damage', ['none','no-tick','old-pid','old-start','old-invocation','old-boot',
    'wrong-owner','wrong-epoch','event-epoch','detail-epoch','expired','stale','future','wrong-parent',
    'pre-start','old-monotonic','future-monotonic'])
def test_handover_requires_this_process_and_current_fence(damage):
    identity, queue = identity_fixture(), queue_fixture()
    detail = queue['supervisor_tick']['detail']
    if damage == 'no-tick': queue['supervisor_tick'] = None
    elif damage == 'old-pid': detail['supervisor']['pid'] = 999
    elif damage == 'old-start': detail['supervisor']['start_ticks'] = 999
    elif damage == 'old-invocation': detail['invocation_id'] = 'b'*32
    elif damage == 'old-boot': detail['boot_id'] = 'old-boot'
    elif damage == 'wrong-owner': queue['lease']['owner'] = 'another-owner'
    elif damage == 'wrong-epoch': queue['lease']['current_epoch'] = 8
    elif damage == 'event-epoch': queue['supervisor_tick']['controller_epoch'] = 6
    elif damage == 'detail-epoch': detail['controller_epoch'] = 6
    elif damage == 'expired': queue['lease_live'] = False
    elif damage == 'stale': queue['supervisor_tick']['age_seconds'] = 66
    elif damage == 'future': queue['supervisor_tick']['age_seconds'] = -1
    elif damage == 'wrong-parent': detail['run_id'] = 'another-parent'
    elif damage == 'pre-start': detail['completed_monotonic_ns'] = 0
    elif damage == 'old-monotonic': detail['completed_monotonic_ns'] -= int(70e9)
    elif damage == 'future-monotonic': detail['completed_monotonic_ns'] += int(10e9)
    if damage == 'none':
        proof = handover.verify_handover(queue, identity)
        assert proof['lease_expires_at'] == 'fixed-one-hour-expiry'
        # Another successful tick may keep exactly the same normal lease expiry.
        assert handover.verify_handover(queue_fixture(), identity)['controller_epoch'] == 7
    else:
        with pytest.raises(ValueError): handover.verify_handover(queue, identity)


@pytest.mark.parametrize('damage', ['none','tick-failure','epoch-race','process-race'])
def test_only_actual_successful_tick_emits_handover(monkeypatch, damage):
    supervisor = Mock(controller_owner='fixture-owner')
    supervisor.controller_epoch.side_effect = [7, 8 if damage == 'epoch-race' else 7]
    identities = [identity_fixture(), identity_fixture()]
    if damage == 'process-race': identities[1]['supervisor']['start_ticks'] = 999
    monkeypatch.setattr(tick, 'own_identity', Mock(side_effect=identities))
    if damage == 'tick-failure':
        supervisor.tick.side_effect = PermissionError('fixture lease lost')
        with pytest.raises(PermissionError): tick.tick_with_identity(supervisor, start.PARENT, 30)
    else:
        tick.tick_with_identity(supervisor, start.PARENT, 30)
    names = [call.args[1] for call in supervisor.emit.call_args_list]
    assert ('supervisor_tick_completed' in names) == (damage == 'none')
    if damage == 'none':
        assert supervisor.method_calls[2][0] == 'tick'
        assert supervisor.method_calls[-1].args[2]['controller_epoch'] == 7


GOOD_STANDALONE = {'LoadState':'loaded','ActiveState':'inactive','SubState':'dead',
                  'UnitFileState':'disabled','MainPID':'0','ControlPID':'0','Job':''}


@pytest.mark.parametrize('controller_stage', [False, True])
@pytest.mark.parametrize('key,value', [('ActiveState','active'),('UnitFileState','enabled'),
    ('ActiveState','failed'),('LoadState','not-found'),('MainPID','123'),('ControlPID','124'),
    ('Job','999'),('SubState','running'),('UnitFileState',''),('UnitFileState','disabled')])
def test_both_start_stages_check_standalone_before_start(recovery_start_fixture, monkeypatch, controller_stage, key, value):
    r,args,events,_queue = recovery_start_fixture
    state = {**GOOD_STANDALONE, key:value}
    monkeypatch.setattr(lifecycle, 'show', lambda unit, properties: state)
    monkeypatch.setattr(r, 'verify_standalone', lifecycle.verify_standalone)
    monkeypatch.setattr(r, '_unit', lambda name: {'ActiveState':'inactive','MainPID':'0'})
    if state == GOOD_STANDALONE:
        result = r.start_verified(*args, start=True, controller_stage=controller_stage)
        assert result['standalone_supervisor'] == state
    else:
        with pytest.raises(ValueError): r.start_verified(*args, start=True, controller_stage=controller_stage)
        assert not any(isinstance(e,tuple) and e[:2]==('systemctl','start') for e in events)


@pytest.mark.parametrize('failure', ['old-lease','restart-race','none'])
def test_worker_cannot_start_before_new_tick_or_during_restart(recovery_start_fixture, monkeypatch, failure):
    r,args,events,queue = recovery_start_fixture
    identities = [identity_fixture(), identity_fixture(), identity_fixture()]
    if failure == 'restart-race': identities[1]['invocation_id'] = 'b'*32
    monkeypatch.setattr(r,'current_supervisor',Mock(side_effect=identities))
    monkeypatch.setattr(r,'verify_handover',handover.verify_handover)
    queue.update(queue_fixture())
    if failure == 'old-lease': queue['supervisor_tick'] = None
    if failure == 'none': r.start_verified(*args,start=True)
    else:
        with pytest.raises(ValueError): r.start_verified(*args,start=True)
        assert ('systemctl','start',r.WORKER) not in events


def graph_fixture():
    graph = {unit:{key:[] for key in lifecycle.PROPERTIES} for unit in lifecycle.UNITS}
    graph[lifecycle.CONTROLLER]['RequiredBy'] = list(lifecycle.ADAPTERS)
    for unit in lifecycle.ADAPTERS: graph[unit]['Requires'] = [lifecycle.CONTROLLER]
    return graph


@pytest.mark.parametrize('edge', [*lifecycle.STOP_EDGES, 'UpheldBy', 'TriggeredBy','OnSuccess','OnFailure'])
@pytest.mark.parametrize('indirect', [False,True])
def test_unknown_reverse_edges_are_denied_before_first_stop(monkeypatch, edge, indirect):
    graph = graph_fixture()
    unit = lifecycle.ADAPTERS[0] if indirect else lifecycle.CONTROLLER
    graph[unit][edge].append('unrelated.service')
    graph['unrelated.service'] = {key:[] for key in lifecycle.PROPERTIES}
    captured = lifecycle.capture_reverse(reader=lambda name:graph[name])
    def verify():
        lifecycle.assert_declared_graph(captured)
        return {'reverse':captured,'activation':captured}
    monkeypatch.setattr(lifecycle,'verify_stop_safety',verify)
    monkeypatch.setattr(lifecycle.os,'geteuid',lambda:0)
    runner = Mock()
    monkeypatch.setattr(lifecycle, 'stop_loaded_unit', runner)
    with pytest.raises(ValueError): lifecycle.stop_declared()
    runner.assert_not_called()


@pytest.fixture
def fake_manager(monkeypatch):
    graph = graph_fixture()
    states = {u:{'ActiveState':'active','MainPID':'42','ControlPID':'0','Job':''} for u in lifecycle.UNITS}
    monkeypatch.setattr(lifecycle.os,'geteuid',lambda:0)
    monkeypatch.setattr(lifecycle,'verify_lifecycle',lambda:{'reverse':graph,'activation':graph})
    monkeypatch.setattr(lifecycle,'verify_stop_safety',lambda:{'reverse':graph})
    def show(unit, properties):
        if properties == ('NeedDaemonReload',): return {'NeedDaemonReload':'no'}
        return {key:states[unit].get(key,'') for key in properties}
    monkeypatch.setattr(lifecycle,'show',show)
    monkeypatch.setattr(lifecycle,'loaded_show',show)
    events=[]
    def run(argv):
        events.append(tuple(argv))
        assert argv[:2] == ['systemctl','stop']
        states[argv[2]].update(ActiveState='inactive',MainPID='0')
    monkeypatch.setattr(lifecycle, 'stop_loaded_unit', lambda unit: run(['systemctl','stop',unit]))
    return graph,states,events,run


def test_declared_stop_and_safe_adapter_restoration(fake_manager):
    graph,states,events,run=fake_manager
    lifecycle.stop_declared()
    assert events == [('systemctl','stop',unit) for unit in lifecycle.UNITS]
    # Starting an adapter would pull the predecessor controller in: forbidden.
    with pytest.raises(ValueError,match='out-of-stage'):
        lifecycle.guard_action('start',lifecycle.ADAPTERS)
    states[lifecycle.CONTROLLER]['ActiveState']='active'
    assert lifecycle.guard_action('start',lifecycle.ADAPTERS)['units']==list(lifecycle.ADAPTERS)


def test_stop_failure_cannot_restart_or_authorize_config_restoration(fake_manager, monkeypatch):
    _graph,_states,events,run=fake_manager
    def fail(argv):
        if argv[-1] == lifecycle.ADAPTERS[0]: raise ValueError('fixture stop failure')
        return run(argv)
    monkeypatch.setattr(lifecycle, 'stop_loaded_unit', lambda unit: fail(['systemctl','stop',unit]))
    with pytest.raises(ValueError): lifecycle.stop_declared()
    assert events == [('systemctl','stop',lifecycle.WORKER)]
    assert not any('start' in command or 'restart' in command for command in events)


def test_pending_outside_dependency_and_conflict_are_denied(fake_manager):
    graph,states,_events,_run=fake_manager
    graph[lifecycle.WORKER]['Requires']=['external.service']
    graph['external.service']={}
    states['external.service']={'ActiveState':'inactive','Job':''}
    with pytest.raises(ValueError): lifecycle.guard_action('start',(lifecycle.WORKER,))
    states['external.service']={'ActiveState':'active','Job':'99'}
    with pytest.raises(ValueError): lifecycle.guard_action('start',(lifecycle.WORKER,))
    graph[lifecycle.WORKER]['Requires']=[]
    graph[lifecycle.WORKER]['Conflicts']=['shutdown.target']
    states['shutdown.target']={'ActiveState':'active','Job':''}
    with pytest.raises(ValueError): lifecycle.guard_action('start',(lifecycle.WORKER,))
    states['shutdown.target']['ActiveState']='inactive'
    lifecycle.guard_action('start',(lifecycle.WORKER,))


def test_adapter_start_uses_full_source_and_handover_gate(recovery_start_fixture):
    r,args,events,_queue=recovery_start_fixture
    result=r.start_verified(*args,start=True,adapters_stage=True)
    assert result['stage']=='adapters'
    assert events[-1]==('systemctl','start',*lifecycle.ADAPTERS)
    assert ('systemctl','start',r.WORKER) not in events


def test_lifecycle_anchor_detects_hash_or_protected_configuration_drift(tmp_path, monkeypatch):
    path=tmp_path/'fixture.json';data={'reverse':graph_fixture(),'activation':{},'protected':{}}
    path.write_text(json.dumps(data));raw=path.read_bytes()
    monkeypatch.setattr(lifecycle,'ANCHOR_PATH',path)
    monkeypatch.setattr(lifecycle,'ANCHOR_SHA256',hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr('recovery_service_anchor._root_file',lambda p:p.read_bytes())
    monkeypatch.setattr(lifecycle,'capture_lifecycle',lambda:copy.deepcopy(data))
    monkeypatch.setattr(lifecycle.dependencies,'verify_dependencies',lambda:None)
    assert lifecycle.verify_lifecycle()==data
    data['protected']['changed']='unexpected'
    with pytest.raises(ValueError): lifecycle.verify_lifecycle()
    path.write_text('changed')
    with pytest.raises(ValueError): lifecycle.verify_lifecycle()


@pytest.mark.parametrize('where', ['worker', 'A', 'B'])
def test_all_transitive_pending_jobs_are_checked_even_behind_active_nodes(where):
    graph={'worker':{'Requires':['A']},'A':{'Wants':['B']},'B':{}}
    states={'worker':{'ActiveState':'inactive','Job':''},
            'A':{'ActiveState':'active','Job':''},'B':{'ActiveState':'inactive','Job':''}}
    states[where]['Job']='99'
    with pytest.raises(ValueError,match='pending/unstable'):
        lifecycle.start_transaction(graph,('worker',),lambda u,p:states[u])


def test_normal_systemd_redundant_job_and_orphan_collection_not_blanket_boot_readiness():
    graph={'worker':{'Requires':['A']},'A':{'Wants':['B']},'B':{}}
    states={'worker':{'ActiveState':'inactive','Job':''},
            'A':{'ActiveState':'active','Job':''},'B':{'ActiveState':'inactive','Job':''}}
    result=lifecycle.start_transaction(graph,('worker',),lambda u,p:states[u])
    assert result=={'inspected_nodes':3,'retained_start_jobs':['worker'],'pruned_inactive_nodes':['B']}
    # A direct second path retains B, so it cannot be pruned as an orphan.
    graph['worker']['Wants']=['B']
    with pytest.raises(ValueError,match='out-of-stage'):
        lifecycle.start_transaction(graph,('worker',),lambda u,p:states[u])
    graph['worker'].pop('Wants');states['A']['ActiveState']='inactive'
    with pytest.raises(ValueError,match='out-of-stage'):
        lifecycle.start_transaction(graph,('worker',),lambda u,p:states[u])


def test_uncertain_retained_inactive_dependency_cycle_is_denied():
    graph={'worker':{'Requires':['A']},'A':{'Wants':['B']},'B':{'Wants':['C']},'C':{'Wants':['B']}}
    def state(unit,props):return {'ActiveState':'active' if unit=='A' else 'inactive','Job':''}
    with pytest.raises(ValueError,match='out-of-stage'):
        lifecycle.start_transaction(graph,('worker',),state)


@pytest.mark.parametrize('stage', ['controller','adapters','worker'])
@pytest.mark.parametrize('damage', ['none','adapter-state','adapter-job','adapter-pid','controller-job'])
def test_four_unit_stage_contract(stage, damage, monkeypatch):
    active=set() if stage=='controller' else {lifecycle.CONTROLLER}
    if stage=='worker':active.update(lifecycle.ADAPTERS)
    states={u:{'LoadState':'loaded','ActiveState':'active' if u in active else 'inactive',
               'SubState':'running' if u in active else 'dead','MainPID':'42' if u in active else '0',
               'ControlPID':'0','Job':'','InvocationID':'fixture-invocation'} for u in lifecycle.UNITS}
    adapter=states[lifecycle.ADAPTERS[0]]
    if damage=='adapter-state':adapter['ActiveState']='inactive' if stage=='worker' else 'active'
    elif damage=='adapter-job':adapter['Job']='99'
    elif damage=='adapter-pid':adapter['MainPID']='0' if stage=='worker' else '99'
    elif damage=='controller-job':states[lifecycle.CONTROLLER]['Job']='99'
    monkeypatch.setattr(lifecycle,'show',lambda u,p:states[u])
    if damage=='none':assert lifecycle.verify_stage(stage)==states
    else:
        with pytest.raises(ValueError):lifecycle.verify_stage(stage)


@pytest.mark.parametrize('damage', ['lifecycle-job','adapter-restart'])
def test_lifecycle_drift_during_database_probe_cannot_start(recovery_start_fixture, monkeypatch, damage):
    r,args,events,queue=recovery_start_fixture
    changed=False
    def query():
        nonlocal changed
        changed=True
        return queue
    def guard(action,units):
        if changed and damage=='lifecycle-job':raise ValueError('job appeared during DB probe')
        return {'fixture':True}
    monkeypatch.setattr(r,'read_queue',query)
    monkeypatch.setattr(r,'guard_action',guard)
    monkeypatch.setattr(r,'verify_stage',lambda stage:{'invocation':'new' if changed and damage=='adapter-restart' else 'old'})
    with pytest.raises(ValueError):r.start_verified(*args,start=True)
    assert ('systemctl','start',r.WORKER) not in events


@pytest.mark.parametrize('controller_stage', [True,False])
def test_stage_failure_is_checked_before_daemon_reload(recovery_start_fixture,monkeypatch,controller_stage):
    r,args,events,queue=recovery_start_fixture
    def stage(_):raise ValueError('unpaused adapter')
    monkeypatch.setattr(r,'verify_stage',stage)
    with pytest.raises(ValueError):r.start_verified(*args,start=True,controller_stage=controller_stage)
    assert ('systemctl','daemon-reload') not in events


@pytest.mark.parametrize('damage',['sha','tree','missing','duplicate','api-only','log-only'])
def test_ci_must_bind_actual_tested_checkout_not_just_api_head(external_acceptance,damage):
    import recovery_acceptance as acceptance
    receipt,path,_=external_acceptance
    ci_path=Path(receipt['ci']['path']);log_path=Path(receipt['ci_log']['path'])
    ci=json.loads(ci_path.read_text());log=log_path.read_text()
    if damage=='sha':log=log.replace(receipt['candidate_sha'],'a'*40)
    elif damage=='tree':log=log.replace(receipt['tree'],'b'*40)
    elif damage=='missing':log='no tested identity\n'
    elif damage=='duplicate':log+=log
    elif damage=='api-only':ci.pop('tested_sha')
    else:ci['tested_tree']='b'*40
    ci_path.write_text(json.dumps(ci));log_path.write_text(log)
    for key in ('ci','ci_log'):
        receipt[key]['sha256']=hashlib.sha256(Path(receipt[key]['path']).read_bytes()).hexdigest()
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError,match='CI did not execute'):acceptance.accepted_source()
