"""P45's two terminal P44 findings: late identity race and safe-stop separation.

All service operations are fake. No live dependencies, files or database change.
"""
import copy
import hashlib
import json

import pytest

import recovery_lifecycle as lifecycle
from test_p40_root_cause_repair import recovery_start_fixture
from test_p44_activation import graph_fixture


@pytest.mark.parametrize('stage',['controller','adapters','worker'])
@pytest.mark.parametrize('damage',['none','stage','standalone','controller','supervisor'])
def test_late_graph_mutation_cannot_reach_start(recovery_start_fixture,monkeypatch,stage,damage):
    r,args,events,_=recovery_start_fixture
    state={'guards':0,'late':False}
    def guard(*_):
        state['guards']+=1
        if state['guards']==(1 if stage=='controller' else 2):state['late']=True
        return {'fake_graph':True}
    def standalone():
        if state['late'] and damage=='standalone':raise ValueError('standalone activated during graph read')
        return {'standalone':'disabled'}
    def current_stage(_):
        changed=state['late'] and (damage=='stage' or stage=='controller' and damage in {'controller','supervisor'})
        return {'stage':'changed' if changed else 'original'}
    def identity(_):
        return {'controller':'new' if state['late'] and damage=='controller' else 'old',
                'supervisor':'new' if state['late'] and damage=='supervisor' else 'old'}
    monkeypatch.setattr(r,'guard_action',guard)
    monkeypatch.setattr(r,'verify_standalone',standalone)
    monkeypatch.setattr(r,'verify_stage',current_stage)
    monkeypatch.setattr(r,'current_supervisor',identity)
    monkeypatch.setattr(r,'_unit',lambda _:{'ActiveState':'inactive','MainPID':'0'})
    kwargs={'start':True,'controller_stage':stage=='controller','adapters_stage':stage=='adapters'}
    if damage=='none':
        result=r.start_verified(*args,**kwargs)
        assert result['started'] and any(isinstance(e,tuple) and e[:2]==('systemctl','start') for e in events)
    else:
        with pytest.raises(ValueError):r.start_verified(*args,**kwargs)
        assert not any(isinstance(e,tuple) and e[:2]==('systemctl','start') for e in events)


def test_no_expensive_probe_follows_final_identity(recovery_start_fixture,monkeypatch):
    r,args,events,_=recovery_start_fixture
    def record(name,result):
        def call(*_,**__):events.append(name);return result
        return call
    monkeypatch.setattr(r,'guard_action',record('graph',{}))
    monkeypatch.setattr(r,'verify_standalone',record('standalone',{}))
    monkeypatch.setattr(r,'verify_stage',record('stage',{}))
    monkeypatch.setattr(r,'current_supervisor',record('identity',{}))
    monkeypatch.setattr(r,'verify_handover',record('pure-event-freshness',{}))
    r.start_verified(*args,start=True)
    assert events[-6:]==['graph','standalone','stage','identity','pure-event-freshness',('systemctl','start',r.WORKER)]


@pytest.fixture
def loaded_stop_manager(tmp_path,monkeypatch):
    graph=graph_fixture()
    for values in graph.values():
        for key in values:values[key]=sorted(values[key])
    activation=copy.deepcopy(graph)
    disk={'digest':'before'}
    anchor={'reverse':copy.deepcopy(graph),'activation':copy.deepcopy(activation),'protected':dict(disk)}
    path=tmp_path/'anchor.json';path.write_text(json.dumps(anchor))
    monkeypatch.setattr(lifecycle,'ANCHOR_PATH',path)
    monkeypatch.setattr(lifecycle,'ANCHOR_SHA256',hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr('recovery_service_anchor._root_file',lambda p:p.read_bytes())
    monkeypatch.setattr(lifecycle.os,'geteuid',lambda:0)
    settings={u:dict(lifecycle.STOP_SETTINGS) for u in lifecycle.UNITS}
    monkeypatch.setattr(lifecycle,'loaded_stop_settings',lambda u:settings[u])
    states={u:{'ActiveState':'active','MainPID':'42','ControlPID':'0','Job':''} for u in lifecycle.UNITS}
    commands=[]
    def show(unit,properties):
        if properties==tuple(lifecycle.STOP_SETTINGS):return settings[unit]
        if all(k in lifecycle.PROPERTIES for k in properties):
            return {k:' '.join(graph[unit].get(k,[])) for k in properties}
        return {k:states[unit].get(k,'') for k in properties}
    monkeypatch.setattr(lifecycle,'show',show)
    monkeypatch.setattr(lifecycle,'loaded_show',show)
    monkeypatch.setattr(lifecycle,'loaded_objects',lambda:{u:lifecycle._object_path(u) for u in lifecycle.UNITS})
    monkeypatch.setattr(lifecycle,'protected_config',lambda:dict(disk))
    monkeypatch.setattr(lifecycle.dependencies,'capture_dependencies',lambda **_:copy.deepcopy(activation))
    monkeypatch.setattr(lifecycle.dependencies,'verify_dependencies',lambda:None)
    def run(argv):
        assert argv[:2]==['systemctl','stop'] and argv[2] in lifecycle.UNITS
        commands.append(tuple(argv));states[argv[2]].update(ActiveState='inactive',MainPID='0')
    monkeypatch.setattr(lifecycle,'stop_loaded_unit',lambda unit:run(['systemctl','stop',unit]))
    return graph,activation,disk,settings,states,commands,run


@pytest.mark.parametrize('drift',['unloaded-file','forward-start-only','unreadable-config'])
def test_stop_remains_available_when_start_readiness_fails(loaded_stop_manager,monkeypatch,drift):
    graph,activation,disk,settings,states,commands,run=loaded_stop_manager
    lifecycle.verify_lifecycle()
    if drift=='unloaded-file':disk['digest']='changed-but-not-loaded'
    elif drift=='forward-start-only':activation[lifecycle.WORKER]['Wants']=['unused-fixture.service']
    else:
        def fail():raise ValueError('activation config unreadable')
        monkeypatch.setattr(lifecycle,'protected_config',fail)
    with pytest.raises(ValueError):lifecycle.verify_lifecycle()
    receipt=lifecycle.stop_declared()
    assert receipt['disposition']=='DECLARED_SERVICES_PAUSED'
    assert commands==[('systemctl','stop',u) for u in lifecycle.UNITS]
    assert all(s['ActiveState']=='inactive' and s['MainPID']=='0' for s in states.values())


@pytest.mark.parametrize('edge',lifecycle.STOP_PROPERTIES)
@pytest.mark.parametrize('indirect',[False,True])
def test_loaded_external_stop_or_reactivation_edge_blocks_first_command(loaded_stop_manager,edge,indirect):
    graph,_,_,_,_,commands,run=loaded_stop_manager
    unit=lifecycle.ADAPTERS[0] if indirect else lifecycle.CONTROLLER
    graph[unit][edge]=['outside.service']
    graph['outside.service']={key:[] for key in lifecycle.PROPERTIES}
    with pytest.raises(ValueError):lifecycle.stop_declared()
    assert commands==[]


@pytest.mark.parametrize('property',list(lifecycle.STOP_SETTINGS))
@pytest.mark.parametrize('damage',['changed','missing'])
def test_loaded_stop_hooks_and_kill_policy_must_be_safe(loaded_stop_manager,property,damage):
    _,_,_,settings,_,commands,run=loaded_stop_manager
    last=settings[lifecycle.CONTROLLER]
    if damage=='changed':last[property]='unexpected-fixture'
    else:last.pop(property)
    with pytest.raises(ValueError):lifecycle.stop_declared()
    assert commands==[]


def test_late_loaded_edge_blocks_remaining_stops_without_reload_or_restart(loaded_stop_manager,monkeypatch):
    graph,_,_,_,_,commands,run=loaded_stop_manager
    def mutate_after_first(argv):
        run(argv)
        graph[lifecycle.CONTROLLER]['RequiredBy'].append('outside.service')
        graph['outside.service']={key:[] for key in lifecycle.PROPERTIES}
    monkeypatch.setattr(lifecycle,'stop_loaded_unit',lambda unit:mutate_after_first(['systemctl','stop',unit]))
    with pytest.raises(ValueError):lifecycle.stop_declared()
    assert commands==[('systemctl','stop',lifecycle.WORKER)]


def test_stop_failure_does_not_report_paused_or_restart(loaded_stop_manager,monkeypatch):
    _,_,_,_,_,commands,run=loaded_stop_manager
    def fail(argv):
        if argv[-1]==lifecycle.ADAPTERS[0]:raise ValueError('fake service failed to stop')
        run(argv)
    monkeypatch.setattr(lifecycle,'stop_loaded_unit',lambda unit:fail(['systemctl','stop',unit]))
    with pytest.raises(ValueError):lifecycle.stop_declared()
    assert commands==[('systemctl','stop',lifecycle.WORKER)]


@pytest.mark.parametrize('damage',['none','missing-object','wrong-object','missing-hooks','wrong-type','nonempty-hooks'])
def test_typed_empty_stop_hooks_are_proven_without_interactive_or_activation_calls(monkeypatch,damage):
    from types import SimpleNamespace
    unit=lifecycle.WORKER;path='/org/freedesktop/systemd1/unit/'+'1'*32
    monkeypatch.setattr(lifecycle,'_invocation_path',lambda _:path)
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        assert '--auto-start=no' in argv and '--allow-interactive-authorization=no' in argv
        assert kwargs['check'] and kwargs['timeout']==10
        assert argv[0]=='busctl' and 'LoadUnit' not in argv and 'show' not in argv
        if 'ListUnits' in argv:
            payload=[{'type':'a(ssssssouso)','data':[[[unit,'','loaded','active','running','',lifecycle._object_path(unit),0,'','/']]]}]
            if damage=='missing-object':payload[0]['data']=[]
            if damage=='wrong-object':payload[0]['data'][0][0][6]='/wrong'
        else:
            assert path in argv
            interface=next(a for a in argv if a in ('org.freedesktop.systemd1.Unit','org.freedesktop.systemd1.Service'))
            keys=argv[argv.index(interface)+1:]
            types=lifecycle.UNIT_TYPES if interface.endswith('.Unit') else lifecycle.SERVICE_TYPES
            payload=[typed_property(types[k],unit if k=='Id' else lifecycle.STOP_SETTINGS[k]) for k in keys]
            if 'ExecStop' in keys:
                idx=keys.index('ExecStop')
                if damage=='missing-hooks':payload.pop(idx)
                if damage=='wrong-type':payload[idx]['type']='s'
                if damage=='nonempty-hooks':payload[idx]['data']=['fake command']
        return SimpleNamespace(stdout='\n'.join(json.dumps(p) for p in payload))
    monkeypatch.setattr(lifecycle.subprocess,'run',run)
    monkeypatch.setattr(lifecycle,'show',lambda *_:pytest.fail('loading show-by-name is forbidden'))
    if damage=='none':assert lifecycle.loaded_stop_settings(lifecycle.WORKER)==lifecycle.STOP_SETTINGS
    else:
        with pytest.raises(ValueError):lifecycle.loaded_stop_settings(lifecycle.WORKER)
    assert not any('set-property' in c or 'StartUnit' in c or 'StopUnit' in c for c in calls)


def typed_property(signature,value):
    if signature=='b':value=value=='yes'
    elif signature in {'i','u','t'}:value=int(value)
    elif signature=='a(sasbttttuii)':value=[] if value=='' else ['unsafe-hook']
    elif signature=='(uo)':value=[0,'/'] if value=='' else [1,'/org/freedesktop/systemd1/job/1']
    elif signature=='as':value=value if isinstance(value,list) else value.split()
    return {'type':signature,'data':value}


@pytest.fixture
def nonloading_manager(tmp_path,monkeypatch):
    from types import SimpleNamespace
    graph=graph_fixture()
    for values in graph.values():
        for k in values:values[k]=sorted(values[k])
    anchor=tmp_path/'anchor.json';anchor.write_text(json.dumps({'reverse':graph}))
    monkeypatch.setattr(lifecycle,'ANCHOR_PATH',anchor)
    monkeypatch.setattr(lifecycle,'ANCHOR_SHA256',hashlib.sha256(anchor.read_bytes()).hexdigest())
    monkeypatch.setattr('recovery_service_anchor._root_file',lambda p:p.read_bytes())
    monkeypatch.setattr(lifecycle.os,'geteuid',lambda:0)
    objects={u:'/org/freedesktop/systemd1/unit/'+format(i+1,'032x') for i,u in enumerate(lifecycle.UNITS)}
    monkeypatch.setattr(lifecycle,'_invocation_path',lambda u:objects[u])
    states={u:{'ActiveState':'active','MainPID':'42','ControlPID':'0','Job':''} for u in lifecycle.UNITS}
    state={'time':0.,'delay':31.,'gc_after_stop':False,'stops':[],'calls':[],'objects':objects,'states':states,'graph':graph}
    finish={}
    def sleep(seconds):state['time']+=seconds
    monkeypatch.setattr(lifecycle,'time',SimpleNamespace(monotonic=lambda:state['time'],sleep=sleep))
    monkeypatch.setattr(lifecycle,'show',lambda *_:pytest.fail('show-by-name would load disk drift'))
    def bus(*args):
        state['calls'].append(args)
        assert not any(a in {'LoadUnit','StopUnit','StartUnit','ListUnitsByNames','show','Reload'} for a in args)
        for u,t in list(finish.items()):
            if state['time']>=t:
                states[u].update(lifecycle.PAUSED)
                if state['gc_after_stop']:objects.pop(u,None)
        if args[-1]=='ListUnits':
            return [{'type':'a(ssssssouso)','data':[[[u,'','loaded',states[u]['ActiveState'],'dead' if states[u]['ActiveState']=='inactive' else 'running','',lifecycle._object_path(u),0,'','/'] for u,p in objects.items()]]}]
        unit=next(u for u,p in objects.items() if p==args[2])
        if args[0]=='call':
            assert args[3:] == ('org.freedesktop.systemd1.Unit','Stop','s','replace')
            state['stops'].append(unit);finish[unit]=state['time']+state['delay']
            states[unit].update(ActiveState='deactivating',Job='pending')
            return [{'type':'o','data':['/org/freedesktop/systemd1/job/1']}]
        assert args[0]=='get-property'
        types=lifecycle.UNIT_TYPES if args[3].endswith('.Unit') else lifecycle.SERVICE_TYPES
        values={**lifecycle.STOP_SETTINGS,**states[unit],'Id':unit}
        values.update({k:[v for v in graph[unit].get(k,[]) if v in objects or v not in lifecycle.UNITS] for k in lifecycle.STOP_PROPERTIES})
        return [typed_property(types[k],values[k]) for k in args[4:]]
    monkeypatch.setattr(lifecycle,'_bus',bus)
    return state


@pytest.mark.parametrize('delay',[0,31,89])
@pytest.mark.parametrize('garbage_collection',['none','before','after'])
def test_real_default_stop_path_never_loads_disk_and_waits_for_safe_slow_stop(nonloading_manager,delay,garbage_collection):
    m=nonloading_manager;m['delay']=delay
    if garbage_collection=='before':m['objects'].pop(lifecycle.WORKER)
    m['gc_after_stop']=garbage_collection=='after'
    receipt=lifecycle.stop_declared()
    assert receipt['disposition']=='DECLARED_SERVICES_PAUSED'
    assert m['stops']==[u for u in lifecycle.UNITS if not (garbage_collection=='before' and u==lifecycle.WORKER)]
    assert m['time']>=delay*len(m['stops'])
    assert receipt['restarted'] is False


def test_default_stop_timeout_preserves_pending_job_and_does_not_continue(nonloading_manager):
    m=nonloading_manager;m['delay']=121
    with pytest.raises(ValueError,match='deadline'):lifecycle.stop_declared()
    assert m['stops']==[lifecycle.WORKER]
    assert m['states'][lifecycle.WORKER]['Job']=='pending'
    assert m['time']==120


def test_default_nonloading_probe_still_rejects_external_stop_edge(nonloading_manager):
    m=nonloading_manager;m['graph'][lifecycle.CONTROLLER]['OnFailure']=['outside.service']
    with pytest.raises(ValueError):lifecycle.stop_declared()
    assert m['stops']==[]


@pytest.mark.parametrize('damage',['none','writable-directory','directory-link','wrong-owner','not-link','bad-id','zero-id'])
def test_invocation_address_uses_protected_runtime_link_only(monkeypatch,damage):
    import stat
    from pathlib import Path
    from types import SimpleNamespace
    original_stat=Path.lstat;original_link=lifecycle.os.readlink
    target='/run/systemd/units/invocation:'+lifecycle.CONTROLLER
    def info(path,*args,**kwargs):
        name=str(path)
        if name not in {'/run','/run/systemd','/run/systemd/units',target}:
            return original_stat(path,*args,**kwargs)
        mode=stat.S_IFLNK|0o777 if name==target else stat.S_IFDIR|0o755
        uid=0
        if damage=='writable-directory' and name=='/run/systemd':mode|=0o020
        if damage=='directory-link' and name=='/run/systemd':mode=stat.S_IFLNK|0o777
        if damage=='wrong-owner' and name==target:uid=999
        if damage=='not-link' and name==target:mode=stat.S_IFREG|0o644
        return SimpleNamespace(st_mode=mode,st_uid=uid)
    def link(path,*args,**kwargs):
        if str(path)!=target:return original_link(path,*args,**kwargs)
        return 'bad' if damage=='bad-id' else ('0'*32 if damage=='zero-id' else '1'*32)
    monkeypatch.setattr(Path,'lstat',info)
    monkeypatch.setattr(lifecycle.os,'readlink',link)
    if damage=='none':assert lifecycle._invocation_path(lifecycle.CONTROLLER)=='/org/freedesktop/systemd1/unit/'+'1'*32
    else:
        with pytest.raises(ValueError):lifecycle._invocation_path(lifecycle.CONTROLLER)


def test_invocation_disappearing_is_not_reloaded_or_retargeted(nonloading_manager,monkeypatch):
    import subprocess
    m=nonloading_manager;original=lifecycle._bus
    def gone(*args):
        if args[0]=='get-property':
            raise subprocess.CalledProcessError(1,['busctl'],stderr='No unit for invocation')
        return original(*args)
    monkeypatch.setattr(lifecycle,'_bus',gone)
    with pytest.raises(subprocess.CalledProcessError):lifecycle.stop_declared()
    assert m['stops']==[]


def test_loaded_reverse_edge_appearing_during_settings_read_blocks_first_stop(loaded_stop_manager,monkeypatch):
    graph,_,_,settings,_,commands,run=loaded_stop_manager
    def mutate(unit):
        if unit==lifecycle.CONTROLLER:
            graph[unit]['RequiredBy'].append('outside.service')
            graph['outside.service']={k:[] for k in lifecycle.PROPERTIES}
        return settings[unit]
    monkeypatch.setattr(lifecycle,'loaded_stop_settings',mutate)
    with pytest.raises(ValueError):lifecycle.stop_declared()
    assert commands==[]
