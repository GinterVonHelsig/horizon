"""P44's four-unit lifecycle boundary, including reverse stop propagation.

systemd.unit(5): Requires/BindsTo/PartOf reverse edges propagate stops;
UpheldBy/TriggeredBy can undo a deliberate pause. No live dependency injection.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import time
from pathlib import Path

import recovery_dependencies as dependencies

CONTROLLER = 'top-delivery-controller.service'
WORKER = 'top-delivery-worker.service'
ADAPTERS = ('top-delivery-signal-adapter.service', 'top-delivery-hermes.service')
UNITS = (WORKER, *ADAPTERS, CONTROLLER)  # Stop clients before their controller.
SUPERVISOR = 'top-delivery-supervisor.service'
PROTECTED = (*ADAPTERS, 'top-delivery-signal-daemon.service', 'top-delivery-auth.service')
STOP_EDGES = ('RequiredBy', 'RequisiteOf', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo')
OTHER_EDGES = ('UpheldBy', 'TriggeredBy', 'StopPropagatedFrom', 'ConflictedBy')
PROPERTIES = (*dependencies.ROOT_PROPERTIES, *STOP_EDGES, *OTHER_EDGES)
STOP_PROPERTIES = (*STOP_EDGES, 'UpheldBy', 'TriggeredBy', 'OnSuccess', 'OnFailure')
# These observed loaded settings stop process groups without external hooks or
# host power actions. They do not depend on source paths or on-disk unit bytes.
STOP_SETTINGS = {
    'LoadState':'loaded', 'ExecStop':'', 'ExecStopPost':'', 'KillMode':'control-group',
    'KillSignal':'15', 'FinalKillSignal':'9', 'SendSIGKILL':'yes', 'SendSIGHUP':'no',
    'TimeoutStopUSec':'90000000', 'TimeoutStopFailureMode':'terminate',
    'FailureAction':'none', 'SuccessAction':'none', 'JobTimeoutAction':'none',
    'RefuseManualStop':'no',
}
STOP_DEADLINE_SECONDS = 120.0
PAUSED = {'ActiveState':'inactive', 'MainPID':'0', 'ControlPID':'0', 'Job':''}
UNIT_TYPES = {**{key:'as' for key in STOP_PROPERTIES}, 'Id':'s', 'LoadState':'s',
    'ActiveState':'s', 'Job':'(uo)', 'FailureAction':'s', 'SuccessAction':'s',
    'JobTimeoutAction':'s', 'RefuseManualStop':'b', 'SubState':'s',
    'InvocationID':'ay', 'NeedDaemonReload':'b'}
SERVICE_TYPES = {'ExecStop':'a(sasbttttuii)', 'ExecStopPost':'a(sasbttttuii)',
    'KillMode':'s', 'KillSignal':'i', 'FinalKillSignal':'i', 'SendSIGKILL':'b',
    'SendSIGHUP':'b', 'TimeoutStopUSec':'t', 'TimeoutStopFailureMode':'s',
    'MainPID':'u', 'ControlPID':'u'}
ANCHOR_PATH = Path('/opt/operator-harness/artifacts/20260912T-p44-horizon-final-activation-safety-NOT_AUTHORIZED/lifecycle-before.json')
ANCHOR_SHA256 = '7c39a66228bd3fca513b523bd92d841f4b3c78637cae46581f89fb1cbb4a8bd7'


def show(unit: str, properties: tuple[str, ...]) -> dict:
    result = subprocess.run(['systemctl', 'show', '--all', '--property='+','.join(properties), '--', unit],
        env={'PATH':'/usr/bin:/bin'}, capture_output=True, text=True, timeout=15, check=True)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def edges(unit: str) -> dict:
    data = show(unit, PROPERTIES)
    if not all(key in data for key in PROPERTIES):
        raise ValueError('systemd omitted a required lifecycle property')
    return {key:sorted(shlex.split(data[key])) for key in PROPERTIES}


def capture_reverse(reader=edges) -> dict:
    pending, graph = list(UNITS), {}
    while pending:
        unit = pending.pop()
        if unit in graph:
            continue
        if len(graph) >= 256:
            raise ValueError('reverse lifecycle closure exceeds bounded inventory')
        values = reader(unit)
        graph[unit] = {key:sorted(values.get(key, [])) for key in PROPERTIES}
        for key in (*STOP_EDGES, 'UpheldBy', 'TriggeredBy'):
            pending.extend(values.get(key, []))
    return graph


def assert_declared_graph(graph: dict) -> None:
    for unit, values in graph.items():
        if unit not in UNITS:
            raise ValueError('reverse lifecycle reaches unauthorized unit: '+unit)
        for key in (*STOP_EDGES, 'UpheldBy', 'TriggeredBy', 'OnSuccess', 'OnFailure'):
            for target in values.get(key, []):
                if target not in UNITS:
                    raise ValueError(f'undeclared lifecycle edge: {unit} {key} {target}')
        # No trigger/upholder is accepted even within the set: rollback must
        # remain paused, not be autonomously restarted by another scoped unit.
        if values.get('UpheldBy') or values.get('TriggeredBy'):
            raise ValueError('automatic reactivation prevents a paused rollback: '+unit)


def protected_config() -> dict:
    from recovery_service_anchor import UNIT_PROPERTIES, _root_file, normalized_unit
    result = {}
    for unit in PROTECTED:
        data = show(unit, UNIT_PROPERTIES)
        paths = {Path(data['FragmentPath'])}
        paths.update(Path(p) for p in shlex.split(data.get('DropInPaths', '')))
        paths.update(Path(p) for p in shlex.split(data.get('EnvironmentFiles', '')) if p.startswith('/'))
        # Detect unloaded adapter/auth/daemon drop-ins without exposing content.
        for root in ('/etc/systemd/system', '/run/systemd/system', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system'):
            for name in ('service.d', 'top-.service.d', 'top-delivery-.service.d', unit+'.d'):
                paths.update(Path(root, name).glob('*.conf'))
        files = {}
        for path in sorted(paths):
            raw, info = _root_file(path), path.lstat()
            files[str(path)] = {'sha256':hashlib.sha256(raw).hexdigest(),
                'mode':stat.S_IMODE(info.st_mode), 'uid':info.st_uid, 'gid':info.st_gid}
        normalized = normalized_unit(data, unit, Path('/P44_NO_NORMALIZATION'))
        result[unit] = {'files':files, 'settings_sha256':hashlib.sha256(
            json.dumps(normalized, sort_keys=True).encode()).hexdigest()}
    return result


def capture_lifecycle() -> dict:
    graph = capture_reverse()
    assert_declared_graph(graph)
    return {'reverse':graph,
            'activation':dependencies.capture_dependencies(roots=UNITS),
            'protected':protected_config()}


def verify_lifecycle() -> dict:
    from recovery_service_anchor import _root_file
    raw = _root_file(ANCHOR_PATH)
    if hashlib.sha256(raw).hexdigest() != ANCHOR_SHA256:
        raise ValueError('protected lifecycle anchor differs')
    current = capture_lifecycle()
    if current != json.loads(raw):
        raise ValueError('systemd lifecycle/config drift before stop/start/rollback')
    dependencies.verify_dependencies()  # Preserve P43's independent 83-unit anchor.
    return current


def _bus(*args) -> list:
    result = subprocess.run(['busctl', '--system', '--json=short', '--auto-start=no',
        '--allow-interactive-authorization=no', '--timeout=5', *args],
        env={'PATH':'/usr/bin:/bin'}, capture_output=True, text=True, timeout=10, check=True)
    return [json.loads(line) for line in result.stdout.splitlines()]


def _object_path(unit: str) -> str:
    if unit not in UNITS:
        raise ValueError('stop observation outside declared units: '+unit)
    return '/org/freedesktop/systemd1/unit/' + ''.join(
        chr(b) if chr(b).isalnum() else '_'+format(b,'02x') for b in unit.encode('ascii'))


def _invocation_path(unit: str) -> str:
    _object_path(unit)
    root = Path('/run/systemd/units')
    for directory in (Path('/run'), Path('/run/systemd'), root):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('untrusted runtime invocation directory')
    link = root / ('invocation:'+unit)
    info = link.lstat()
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
        raise ValueError('untrusted runtime invocation link')
    identity = os.readlink(link)
    if not re.fullmatch('[0-9a-f]{32}', identity) or identity == '0'*32:
        raise ValueError('invalid active invocation identity')
    # systemd257 manager_load_unit_from_dbus_path looks up a 128-bit invocation
    # in memory and errors if absent; it NEVER falls back to loading by name.
    return '/org/freedesktop/systemd1/unit/' + identity


def loaded_objects(*, retry_missing: bool = True) -> dict:
    # ListUnits enumerates only in-memory units. Inactive/dead/no-job units are
    # already quiescent and need no property read or Stop operation. All others
    # are addressed by invocation ID, NOT the auto-loading name-object path.
    reply = _bus('call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
                 'org.freedesktop.systemd1.Manager', 'ListUnits')
    if (len(reply) != 1 or reply[0].get('type') != 'a(ssssssouso)'
            or not isinstance(reply[0].get('data'), list) or len(reply[0]['data']) != 1
            or not isinstance(reply[0]['data'][0], list)):
        raise ValueError('unverified loaded-unit inventory')
    result, seen = {}, set()
    for row in reply[0]['data'][0]:
        if not isinstance(row, list) or len(row) != 10 or not isinstance(row[0], str):
            raise ValueError('invalid loaded-unit inventory row')
        unit = row[0]
        if unit in UNITS:
            if unit in seen or row[6] != _object_path(unit) or row[5] != '':
                raise ValueError('duplicate/aliased/wrong loaded service object')
            seen.add(unit)
            if row[3:5] == ['inactive','dead'] and type(row[7]) is int and row[7] == 0 and row[9] == '/':
                continue
            try:
                result[unit] = _invocation_path(unit)
            except FileNotFoundError:
                # A normal exit can remove the link after ListUnits. Repeat
                # only the non-loading inventory once; never recreate a unit.
                if retry_missing: return loaded_objects(retry_missing=False)
                raise ValueError('non-quiescent unit lost runtime invocation') from None
    return result


def _property_value(item: dict, signature: str) -> str:
    if not isinstance(item, dict) or item.get('type') != signature or 'data' not in item:
        raise ValueError('missing or mistyped loaded property')
    value = item['data']
    if signature == 's' and isinstance(value, str): return value
    if signature == 'b' and type(value) is bool: return 'yes' if value else 'no'
    if signature in {'i','u','t'} and type(value) is int: return str(value)
    if (signature == 'ay' and isinstance(value, list) and len(value) == 16
            and all(type(v) is int and 0 <= v <= 255 for v in value)):
        return bytes(value).hex()
    if signature == 'as' and isinstance(value,list) and all(isinstance(v,str) for v in value):
        return shlex.join(value)
    if signature == 'a(sasbttttuii)' and value == []: return ''
    if (signature == '(uo)' and isinstance(value,list) and len(value) == 2
            and type(value[0]) is int and isinstance(value[1],str)):
        return '' if value == [0,'/'] else str(value)
    raise ValueError('invalid or unsafe loaded property value')


def loaded_show(unit: str, properties: tuple[str, ...]) -> dict | None:
    _object_path(unit)  # Reject external targets even if not currently loaded.
    path = loaded_objects().get(unit)
    if path is None: return None  # Confirmed GC-unloaded: no process/job to stop.
    result = {}
    for interface, types in (('Unit', UNIT_TYPES), ('Service', SERVICE_TYPES)):
        keys = tuple(k for k in ('Id', *properties) if k in types)
        if not keys: continue
        try:
            values = _bus('get-property', 'org.freedesktop.systemd1', path,
                          'org.freedesktop.systemd1.'+interface, *keys)
        except subprocess.CalledProcessError:
            if unit not in loaded_objects(): return None
            raise
        if len(values) != len(keys): raise ValueError('missing loaded property output')
        result.update({k:_property_value(v,types[k]) for k,v in zip(keys,values)})
    if result.pop('Id',None) != unit or set(result) != set(properties):
        raise ValueError('loaded object identity/properties differ')
    return result


def stop_edges(unit: str) -> dict:
    data = loaded_show(unit, STOP_PROPERTIES)
    return {key:sorted(shlex.split(data[key])) if data is not None else [] for key in STOP_PROPERTIES}


def loaded_stop_settings(unit: str) -> dict | None:
    return loaded_show(unit, tuple(STOP_SETTINGS))


def verify_stop_safety() -> dict:
    """Actual LOADED stop behavior, not failed start/config readiness.

    The immutable review anchor is still trusted; restorable unit/source/env
    files, protected_config() and forward activation inventory are not read.
    """
    from recovery_service_anchor import _root_file
    raw = _root_file(ANCHOR_PATH)
    if hashlib.sha256(raw).hexdigest() != ANCHOR_SHA256:
        raise ValueError('protected lifecycle anchor differs')
    objects = loaded_objects()
    graph = capture_reverse(reader=stop_edges)
    assert_declared_graph(graph)
    def projection(value):
        return {u:{key:value[u][key] for key in STOP_PROPERTIES} for u in value}
    actual = projection(graph)
    actual = {u:{k:[v for v in values[k] if v not in UNITS or v in objects]
                 for k in STOP_PROPERTIES} for u,values in actual.items()}
    expected = projection(json.loads(raw)['reverse'])
    # Garbage collection removes a unit and its reverse references. It is
    # already quiescent; never reload it merely to stop it. No other drift is
    # accepted, and unexpected external references still fail above.
    expected = {u:{k:[v for v in values[k] if v in objects] if u in objects else []
                   for k in STOP_PROPERTIES} for u,values in expected.items()}
    if actual != expected:
        raise ValueError('loaded stop/reactivation closure changed')
    settings = {}
    for unit in UNITS:
        state = loaded_stop_settings(unit)
        if state != (STOP_SETTINGS if unit in objects else None):
            raise ValueError('loaded stop behavior differs: '+unit)
        settings[unit] = state
    final_graph = capture_reverse(reader=stop_edges)
    assert_declared_graph(final_graph)
    final = {u:{k:[v for v in values[k] if v not in UNITS or v in objects]
                for k in STOP_PROPERTIES} for u,values in projection(final_graph).items()}
    if final != actual or loaded_objects() != objects:
        raise ValueError('loaded stop closure changed while checking stop behavior')
    return {'reverse':actual, 'settings':settings, 'loaded_objects':objects}


def verify_standalone() -> dict:
    state = show(SUPERVISOR, ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'ControlPID', 'Job'))
    required = {'LoadState':'loaded', 'ActiveState':'inactive', 'SubState':'dead',
                'UnitFileState':'disabled', 'MainPID':'0', 'ControlPID':'0'}
    if any(state.get(key) != value for key, value in required.items()) or state.get('Job') != '':
        raise ValueError('standalone supervisor must be loaded, disabled, inactive, PID0 and have no job')
    return state


def verify_stage(stage: str) -> dict:
    if stage not in {'controller', 'adapters', 'worker'}:
        raise ValueError('unknown lifecycle stage')
    active = set() if stage == 'controller' else {CONTROLLER}
    if stage == 'worker':
        active.update(ADAPTERS)
    states = {}
    for unit in UNITS:
        state = show(unit, ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlPID', 'Job', 'InvocationID'))
        if state.get('LoadState') != 'loaded' or state.get('ControlPID') != '0' or state.get('Job') != '':
            raise ValueError('pending/invalid unit at '+stage+' stage: '+unit)
        if unit in active:
            if (state.get('ActiveState') != 'active' or state.get('SubState') != 'running'
                    or not state.get('MainPID', '').isdecimal() or int(state['MainPID']) <= 1
                    or not state.get('InvocationID')):
                raise ValueError('required active unit is not stable: '+unit)
        elif state.get('ActiveState') != 'inactive' or state.get('SubState') != 'dead' or state.get('MainPID') != '0':
            raise ValueError('required paused unit is not inactive/PID0: '+unit)
        states[unit] = state
    return states


def verify_final_stage(stage: str, before_stage: dict) -> dict:
    """Non-loading last observation; a GC-unloaded expected unit is a denial.

    The full earlier stage check proved PIDs/configuration, including for paused
    units. Here ListUnits proves their inactive/dead/no-job state without loading
    disk configuration. Active units additionally retain exact invocation/PIDs.
    These reads and the later start are not an atomic systemd transaction.
    """
    if stage not in {'controller', 'adapters', 'worker'} or set(before_stage) != set(UNITS):
        raise ValueError('invalid final stage baseline')
    reply = _bus('call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
                 'org.freedesktop.systemd1.Manager', 'ListUnits')
    if (len(reply) != 1 or reply[0].get('type') != 'a(ssssssouso)'
            or not isinstance(reply[0].get('data'), list) or len(reply[0]['data']) != 1
            or not isinstance(reply[0]['data'][0], list)):
        raise ValueError('unverified final loaded-unit inventory')
    states = {}
    for row in reply[0]['data'][0]:
        if not isinstance(row, list) or len(row) != 10 or not isinstance(row[0], str):
            raise ValueError('invalid final loaded-unit row')
        unit = row[0]
        if unit not in (*UNITS, SUPERVISOR):
            continue
        path = '/org/freedesktop/systemd1/unit/' + ''.join(
            chr(b) if chr(b).isalnum() else '_'+format(b, '02x') for b in unit.encode('ascii'))
        if (unit in states or row[6] != path or row[5] != '' or row[2] != 'loaded'
                or type(row[7]) is not int or row[7] != 0 or row[9] != '/'):
            raise ValueError('changed/aliased/pending final stage unit: '+unit)
        states[unit] = {'LoadState':row[2], 'ActiveState':row[3], 'SubState':row[4], 'Job':''}
    if not set(UNITS) <= set(states):
        raise ValueError('expected unit disappeared from final loaded inventory')
    for unit in UNITS:
        before = before_stage[unit]
        if any(before.get(k) != v for k, v in states[unit].items()):
            raise ValueError('lifecycle stage changed during final activation checks')
        if before.get('ActiveState') == 'active':
            current = loaded_show(unit, (*before, 'NeedDaemonReload'))
            if current is None or current.pop('NeedDaemonReload', None) != 'no' or current != before:
                raise ValueError('active invocation/config changed at final stage: '+unit)
        elif (before.get('ActiveState') != 'inactive' or before.get('SubState') != 'dead'
                or before.get('MainPID') != '0' or before.get('ControlPID') != '0'):
            raise ValueError('invalid paused baseline at final stage: '+unit)
    standalone = states.get(SUPERVISOR)
    if standalone is not None and standalone != {'LoadState':'loaded', 'ActiveState':'inactive', 'SubState':'dead', 'Job':''}:
        raise ValueError('standalone supervisor became active/pending at final stage')
    # Manager.GetUnitFileState queries enablement, not LoadUnit or a name-object
    # property lookup. It cannot reload a garbage-collected service as a side effect.
    enabled = _bus('call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
                   'org.freedesktop.systemd1.Manager', 'GetUnitFileState', 's', SUPERVISOR)
    if enabled != [{'type':'s', 'data':['disabled']}]:
        raise ValueError('standalone supervisor is not disabled at final stage')
    # Disabled standalone is normally garbage-collected on this host. Its
    # absence proves no live process/job; never load it merely to report status.
    return {**(standalone or {'LoadState':'not-in-loaded-inventory'}),
            'UnitFileState':'disabled', 'quiescent':True, 'observation':'non-loading final inventory',
            'paused_pid_proof':'earlier full stage plus unchanged inactive/dead/no-job state'}


def start_transaction(graph: dict, units: tuple[str, ...], state_reader) -> dict:
    """Conservative projection of systemd257's normal start transaction.

    Inspect ALL forward nodes, including behind active units, for pending jobs.
    Then remove redundant active START jobs and collect unreferenced dependencies,
    as transaction_drop_redundant/transaction_collect_garbage do. An inactive
    dependency behind a removed active job is not an activation. Retained cycles
    or any out-of-stage job are rejected, not guessed safe. No ignore-dependencies.
    """
    activation = ('Requires', 'Wants', 'BindsTo', 'Upholds')
    pending, states, links = list(units), {}, {}
    while pending:
        unit = pending.pop()
        if unit in states:
            continue
        if unit not in graph:
            raise ValueError('incomplete transitive dependency inventory: '+unit)
        state = state_reader(unit, ('ActiveState', 'Job'))
        if state.get('Job') != '' or state.get('ActiveState') not in {'active', 'inactive', 'failed'}:
            raise ValueError('pending/unstable transitive start target: '+unit)
        states[unit] = state
        links[unit] = set()
        for key in activation:
            links[unit].update(graph[unit].get(key, []))
        pending.extend(links[unit])
        for target in graph[unit].get('Requisite', []):
            requisite = state_reader(target, ('ActiveState', 'Job'))
            if requisite != {'ActiveState':'active', 'Job':''}:
                raise ValueError('inactive/pending Requisite: '+target)
    remaining = set(units) | {u for u,s in states.items() if s['ActiveState'] != 'active'}
    while True:
        referenced = set(units)
        for unit in remaining:
            referenced.update(links[unit] & remaining)
        orphaned = remaining - referenced
        if not orphaned:
            break
        remaining -= orphaned
    outside = remaining - set(units)
    if outside:
        raise ValueError('start would retain out-of-stage jobs: '+','.join(sorted(outside)))
    return {'inspected_nodes':len(states), 'retained_start_jobs':sorted(remaining),
            'pruned_inactive_nodes':sorted(u for u,s in states.items() if s['ActiveState'] != 'active' and u not in remaining)}


def guard_action(action: str, units: tuple[str, ...]) -> dict:
    if action not in {'start', 'stop'} or not units or not set(units) <= set(UNITS):
        raise ValueError('action outside the four authorized units')
    if action == 'stop':
        return {'action':action, 'units':list(units), 'lifecycle_anchor_sha256':ANCHOR_SHA256,
                'loaded_stop_safety':verify_stop_safety(), 'transaction':None}
    graph = verify_lifecycle()
    if action == 'start':
        for unit in UNITS:
            if show(unit, ('NeedDaemonReload',)).get('NeedDaemonReload') != 'no':
                raise ValueError('unloaded unit changes before activation: '+unit)
        for unit in units:
            for key in ('Conflicts', 'ConflictedBy'):
                for target in graph['reverse'][unit].get(key, []):
                    state = show(target, ('ActiveState', 'Job'))
                    if state.get('ActiveState') != 'inactive' or state.get('Job') != '':
                        raise ValueError('start would stop a conflicting unit: '+target)
        transaction = start_transaction(graph['activation'], units, show)
    else:
        transaction = None
    return {'action':action, 'units':list(units), 'lifecycle_anchor_sha256':ANCHOR_SHA256,
            'transaction':transaction}


def stop_loaded_unit(unit: str) -> dict:
    """Stop the existing object, never Manager.StopUnit's load-by-name path.

    The method queues a job promptly; polling allows the pinned 90-second
    systemd stop timeout plus 30 seconds. Each D-Bus read is independently
    bounded. A timeout preserves the real job/state and never claims pause.
    """
    _object_path(unit)
    path = loaded_objects().get(unit)
    if path is None: return {'unit':unit, 'already_quiescent':True}
    identity = _bus('get-property', 'org.freedesktop.systemd1', path,
                    'org.freedesktop.systemd1.Unit', 'Id')
    if identity != [{'type':'s','data':unit}]:
        raise ValueError('stop invocation belongs to a different unit')
    try:
        reply = _bus('call', 'org.freedesktop.systemd1', path,
                     'org.freedesktop.systemd1.Unit', 'Stop', 's', 'replace')
    except subprocess.CalledProcessError:
        if unit not in loaded_objects(): return {'unit':unit, 'already_quiescent':True}
        raise
    if (len(reply) != 1 or reply[0].get('type') != 'o'
            or not isinstance(reply[0].get('data'),list) or len(reply[0]['data']) != 1
            or not isinstance(reply[0]['data'][0],str)
            or not reply[0]['data'][0].startswith('/org/freedesktop/systemd1/job/')):
        raise ValueError('unverified stop job; preserve real manager state')
    started = time.monotonic()
    while time.monotonic() - started < STOP_DEADLINE_SECONDS:
        state = loaded_show(unit, tuple(PAUSED))
        if state is None or state == PAUSED:
            return {'unit':unit, 'job':reply[0]['data'][0], 'paused':True,
                    'elapsed_seconds':time.monotonic()-started}
        time.sleep(0.25)
    raise ValueError('loaded unit did not pause within bounded stop deadline: '+unit)


def stop_declared() -> dict:
    """Used for both cutover and rollback, BEFORE any config/pointer restoration."""
    if os.geteuid() != 0:
        raise ValueError('root coordinator required')
    guard_action('stop', UNITS)  # Full closure before the FIRST stop.
    stopped = []
    for unit in UNITS:
        guard_action('stop', (unit,))
        stopped.append(stop_loaded_unit(unit))
    for unit in UNITS:
        state = loaded_show(unit, tuple(PAUSED))
        if state is not None and state != PAUSED:
            raise ValueError('declared service did not reach paused state: '+unit)
    return {'disposition':'DECLARED_SERVICES_PAUSED', 'units':list(UNITS),
            'stopped':stopped, 'restarted':False}
