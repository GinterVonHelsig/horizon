"""Non-secret process identity for a completed supervisor tick (no lease writes)."""
from __future__ import annotations

import os
import time
from pathlib import Path


def process_identity(pid: int) -> dict:
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    if fields[0] in {'Z', 'X'}:
        raise ValueError('supervisor/controller process is not running')
    return {'pid': pid, 'ppid': int(fields[1]), 'start_ticks': int(fields[19])}


def own_identity() -> dict:
    return {'supervisor': process_identity(os.getpid()),
            'controller': process_identity(os.getppid()),
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'invocation_id': os.environ.get('INVOCATION_ID', '')}


def tick_with_identity(supervisor, run_id: str, interval: float) -> None:
    """Emit handover evidence only AFTER the actual fenced tick succeeds."""
    identity = own_identity()
    epoch = supervisor.controller_epoch(run_id)
    supervisor.emit(run_id, 'supervisor_heartbeat', {'interval_seconds': interval})
    supervisor.tick(run_id)
    if supervisor.controller_epoch(run_id) != epoch or own_identity() != identity:
        # A normal lease-term boundary can advance the epoch. Let the next
        # completed tick prove it; do not invent a cross-epoch completion.
        return
    supervisor.emit(run_id, 'supervisor_tick_completed', {
        **identity, 'run_id': run_id, 'owner': supervisor.controller_owner,
        'controller_epoch': epoch, 'completed_monotonic_ns': time.monotonic_ns(),
        'interval_seconds': interval,
    })
