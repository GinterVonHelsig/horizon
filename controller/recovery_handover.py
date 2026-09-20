"""Prove that this live supervisor, not its predecessor, completed a fenced tick."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

from supervisor_identity import process_identity
from recovery_lifecycle import loaded_show

CONTROLLER = 'top-delivery-controller.service'
PARENT = 'goal-3eb7b972ec15809e'


def _controller() -> dict:
    values = loaded_show(CONTROLLER, ('MainPID', 'ActiveState', 'SubState',
                                      'InvocationID', 'ControlPID', 'Job', 'NeedDaemonReload'))
    if values is None or values.pop('NeedDaemonReload', None) != 'no':
        raise ValueError('controller invocation disappeared or requires reload')
    if (values.get('ActiveState') != 'active' or values.get('SubState') != 'running'
            or values.get('ControlPID') != '0' or values.get('Job') != ''
            or int(values.get('MainPID', '0')) <= 1
            or not re.fullmatch('[0-9a-f]{32}', values.get('InvocationID', ''))):
        raise ValueError('no stable systemd controller invocation')
    return values


def current_supervisor(release: Path) -> dict:
    unit = _controller()
    parent = process_identity(int(unit['MainPID']))
    candidates = []
    for pid in Path(f"/proc/{parent['pid']}/task/{parent['pid']}/children").read_text().split():
        command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        if command[:2] == [b'/usr/bin/python3', os.fsencode(release/'controller/supervisor_cli.py')]:
            candidates.append(int(pid))
    if len(candidates) != 1:
        raise ValueError('expected exactly one reviewed supervisor child')
    pid = candidates[0]
    child = process_identity(pid)
    env = dict(item.split(b'=', 1) for item in Path(f'/proc/{pid}/environ').read_bytes().split(b'\0') if b'=' in item)
    # Only these nonsecret identity fields leave the process-environment reader.
    owner = env.get(b'TOP_DELIVERY_CONTROLLER_OWNER', b'').decode()
    interval = float(env.get(b'TOP_DELIVERY_HEARTBEAT_SECONDS', b'300'))
    if (child['ppid'] != parent['pid'] or not owner or not 0 < interval <= 300
            or env.get(b'TOP_DELIVERY_RUN_ID') != PARENT.encode()
            or env.get(b'INVOCATION_ID') != unit['InvocationID'].encode()
            or _controller() != unit or process_identity(pid) != child
            or process_identity(parent['pid']) != parent):
        raise ValueError('supervisor identity changed or differs from the pinned parent')
    return {'supervisor':child, 'controller':parent,
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'invocation_id':unit['InvocationID'], 'owner':owner, 'run_id':PARENT,
        'interval_seconds':interval}


def verify_handover(queue: dict, identity: dict) -> dict:
    lease, event = queue.get('lease') or {}, queue.get('supervisor_tick') or {}
    detail = event.get('detail') or {}
    for key in ('supervisor', 'controller', 'boot_id', 'invocation_id', 'owner', 'run_id', 'interval_seconds'):
        if key not in identity or detail.get(key) != identity[key]:
            raise ValueError('no completed tick from the current supervisor identity')
    epoch = lease.get('current_epoch')
    age = event.get('age_seconds')
    completed = detail.get('completed_monotonic_ns')
    if (queue.get('lease_live') is not True or lease.get('owner') != identity['owner']
            or lease.get('run_id') != PARENT or not isinstance(epoch, int) or epoch <= 0
            or event.get('controller_epoch') != epoch or detail.get('controller_epoch') != epoch
            or not event.get('event_id') or not isinstance(age, (int, float))
            or not 0 <= age <= identity['interval_seconds'] * 2 + 5
            or not isinstance(completed, int)
            or not 0 <= time.monotonic_ns() - completed <= int((identity['interval_seconds'] * 2 + 5) * 1e9)
            or completed < identity['supervisor']['start_ticks'] * 1_000_000_000 // os.sysconf('SC_CLK_TCK')):
        raise ValueError('stale, wrong-owner or wrong-epoch supervisor handover')
    return {'identity':identity, 'event_id':event['event_id'], 'event_seq':event['event_seq'],
            'controller_epoch':epoch, 'lease_expires_at':lease['lease_expires_at'],
            'observed_age_seconds':age}
