"""P46: no alternate stop runner or loading lookup in the final start path.

All manager calls below are fake; no live unit or database is mutated.
"""
import copy
import inspect

import pytest

import recovery_handover as handover
import recovery_lifecycle as lifecycle
from test_p40_root_cause_repair import recovery_start_fixture


def test_stop_has_no_legacy_runner_escape_hatch(monkeypatch):
    assert not inspect.signature(lifecycle.stop_declared).parameters
    monkeypatch.setattr(lifecycle, 'guard_action', lambda *_: pytest.fail('must reject before any operation'))
    with pytest.raises(TypeError):
        lifecycle.stop_declared(lambda *_: None)
    with pytest.raises(TypeError):
        lifecycle.stop_declared(runner=lambda *_: None)


@pytest.fixture
def final_manager(monkeypatch):
    states = {}
    paths = {u:'/org/freedesktop/systemd1/unit/'+format(i+1, '032x')
             for i,u in enumerate(lifecycle.UNITS)}
    m = {'states':states, 'paths':paths, 'calls':[], 'enabled':'disabled',
         'omit':set(), 'reload':set(), 'disk_drift':False, 'name_loads':0}
    def configure(stage):
        active = set() if stage == 'controller' else {lifecycle.CONTROLLER}
        if stage == 'worker': active.update(lifecycle.ADAPTERS)
        for u in lifecycle.UNITS:
            states[u] = {'LoadState':'loaded', 'ActiveState':'active' if u in active else 'inactive',
                         'SubState':'running' if u in active else 'dead', 'MainPID':'42' if u in active else '0',
                         'ControlPID':'0', 'Job':'', 'InvocationID':paths[u].rsplit('/',1)[1]}
        states[lifecycle.SUPERVISOR] = {'LoadState':'loaded', 'ActiveState':'inactive', 'SubState':'dead',
                                       'Job':'', 'MainPID':'0', 'ControlPID':'0'}
        return copy.deepcopy({u:states[u] for u in lifecycle.UNITS})
    m['configure'] = configure
    monkeypatch.setattr(lifecycle, '_invocation_path', lambda u:paths[u])
    monkeypatch.setattr(lifecycle, 'show', lambda *_: pytest.fail('name lookup can reload changed disk bytes'))
    def bus(*args):
        m['calls'].append(args)
        assert not any(a in {'LoadUnit','StartUnit','StopUnit','ListUnitsByNames','Reload'} for a in args)
        if args[0] == 'call' and args[4] == 'ListUnits':
            rows=[]
            for u,s in states.items():
                if u in m['omit']: continue
                path='/org/freedesktop/systemd1/unit/'+''.join(
                    chr(b) if chr(b).isalnum() else '_'+format(b,'02x') for b in u.encode('ascii'))
                job=0 if not s['Job'] else 9
                rows.append([u,'',s['LoadState'],s['ActiveState'],s['SubState'],'',path,job,'',
                             '/' if not job else '/org/freedesktop/systemd1/job/9'])
            return [{'type':'a(ssssssouso)','data':[rows]}]
        if args[0] == 'call':
            assert args[4:] == ('GetUnitFileState','s',lifecycle.SUPERVISOR)
            return [{'type':'s','data':[m['enabled']]}]
        assert args[0] == 'get-property' and args[2] in paths.values()
        u=next(u for u,p in paths.items() if p==args[2])
        types=lifecycle.UNIT_TYPES if args[3].endswith('.Unit') else lifecycle.SERVICE_TYPES
        values={**states[u], 'Id':u, 'NeedDaemonReload':'yes' if u in m['reload'] else 'no'}
        result=[]
        for key in args[4:]:
            value=values[key]; signature=types[key]
            if signature=='b':value=value=='yes'
            elif signature in {'i','u','t'}:value=int(value)
            elif signature=='ay':value=list(bytes.fromhex(value))
            elif signature=='(uo)':value=[0,'/'] if not value else [9,'/org/freedesktop/systemd1/job/9']
            result.append({'type':signature,'data':value})
        return result
    monkeypatch.setattr(lifecycle, '_bus', bus)
    return m


@pytest.mark.parametrize('stage',['controller','adapters','worker'])
@pytest.mark.parametrize('damage',['none','gc-disk-drift','pending','active-state','standalone-enabled','standalone-active'])
def test_real_final_gate_is_wired_and_no_name_load_can_reach_start(
        recovery_start_fixture, final_manager, monkeypatch, stage, damage):
    r,args,events,_=recovery_start_fixture
    m=final_manager; baseline=m['configure'](stage)
    guards={'count':0}
    def guard(*_):
        guards['count']+=1
        if guards['count']==(1 if stage=='controller' else 2):
            if damage=='gc-disk-drift':
                m['disk_drift']=True; m['omit'].add(lifecycle.WORKER)
            elif damage=='pending':m['states'][lifecycle.WORKER]['Job']='9'
            elif damage=='active-state':m['states'][lifecycle.WORKER].update(ActiveState='active',SubState='running')
            elif damage=='standalone-enabled':m['enabled']='enabled'
            elif damage=='standalone-active':m['states'][lifecycle.SUPERVISOR].update(ActiveState='active',SubState='running')
        return {}
    monkeypatch.setattr(r, 'verify_stage', lambda _:copy.deepcopy(baseline))
    monkeypatch.setattr(r, 'verify_final_stage', lifecycle.verify_final_stage)
    monkeypatch.setattr(r, 'guard_action', guard)
    monkeypatch.setattr(r, '_unit', lambda _: {'ActiveState':'inactive','MainPID':'0'})
    kwargs={'start':True,'controller_stage':stage=='controller','adapters_stage':stage=='adapters'}
    if damage=='none':assert r.start_verified(*args,**kwargs)['started']
    else:
        with pytest.raises(ValueError):r.start_verified(*args,**kwargs)
        assert not any(isinstance(e,tuple) and e[:2]==('systemctl','start') for e in events)
    assert m['name_loads']==0
    assert all(c[0]!='get-property' or c[2] in m['paths'].values() for c in m['calls'])


@pytest.mark.parametrize('damage',['invocation','pid','reload','missing'])
def test_active_final_observation_rejects_invocation_or_config_drift(final_manager,damage):
    m=final_manager; baseline=m['configure']('worker'); unit=lifecycle.CONTROLLER
    if damage=='invocation':m['states'][unit]['InvocationID']='f'*32
    elif damage=='pid':m['states'][unit]['MainPID']='43'
    elif damage=='reload':m['reload'].add(unit)
    else:m['omit'].add(unit)
    with pytest.raises(ValueError):lifecycle.verify_final_stage('worker',baseline)


@pytest.mark.parametrize('damage',['none','reload','missing'])
def test_last_controller_identity_read_is_also_nonloading(final_manager,damage):
    m=final_manager;m['configure']('worker');unit=lifecycle.CONTROLLER
    if damage=='reload':m['reload'].add(unit)
    elif damage=='missing':m['omit'].add(unit)
    if damage=='none':assert handover._controller()['InvocationID']==m['states'][unit]['InvocationID']
    else:
        with pytest.raises(ValueError):handover._controller()


def test_disabled_garbage_collected_standalone_is_quiescent_without_loading(final_manager):
    m=final_manager;baseline=m['configure']('worker')
    m['omit'].add(lifecycle.SUPERVISOR)
    result=lifecycle.verify_final_stage('worker',baseline)
    assert result['LoadState']=='not-in-loaded-inventory' and result['quiescent']
    m['enabled']='enabled'
    with pytest.raises(ValueError):lifecycle.verify_final_stage('worker',baseline)


@pytest.mark.parametrize('value',[[],[0]*15,[0]*17,[True]*16,[-1]*16,[256]*16,'a'*32])
def test_invocation_byte_array_is_strictly_typed(value):
    with pytest.raises(ValueError):lifecycle._property_value({'type':'ay','data':value},'ay')
