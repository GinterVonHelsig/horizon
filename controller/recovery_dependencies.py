"""Pin systemd activation dependencies, including transitive worker-start edges."""
from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from pathlib import Path

ANCHOR_PATH = Path('/opt/operator-harness/artifacts/20260912T-p43-horizon-p40-activation-closure-NOT_AUTHORIZED/service-dependencies-before.json')
ANCHOR_SHA256 = 'f317fa789f65532940ec9cacc91dba31f5ac217ea0448b88b70c71011a43fe08'
ROOTS = ('top-delivery-controller.service', 'top-delivery-worker.service')
ACTIVATION = ('Requires', 'Requisite', 'Wants', 'BindsTo', 'Upholds', 'OnFailure', 'OnSuccess', 'Triggers')
ROOT_PROPERTIES = (*ACTIVATION, 'PartOf', 'Conflicts', 'Before', 'After', 'TriggeredBy')


def read_dependencies(unit: str) -> dict:
    result = subprocess.run(['systemctl', 'show', '--property=' + ','.join(ROOT_PROPERTIES), '--', unit],
                            capture_output=True, text=True, timeout=15, check=True)
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    return {key: sorted(shlex.split(values.get(key, ''))) for key in ROOT_PROPERTIES}


def capture_dependencies(reader=read_dependencies, *, roots=ROOTS) -> dict:
    pending, graph = list(roots), {}
    while pending:
        unit = pending.pop()
        if unit in graph:
            continue
        if len(graph) >= 256:
            raise ValueError('systemd activation closure exceeds bounded inventory')
        values = reader(unit)
        # Ordering of systemctl's sets is not stable. Capture full edges for the
        # two changed services; downstream nodes need their activation edges, not
        # dynamic reverse ordering against unrelated session/scope services.
        graph[unit] = {key: sorted(values.get(key, []))
                       for key in (ROOT_PROPERTIES if unit in roots else ACTIVATION)}
        for key in ACTIVATION:
            pending.extend(values.get(key, []))
    return graph


def verify_dependencies() -> None:
    from recovery_service_anchor import _root_file
    raw = _root_file(ANCHOR_PATH)
    if hashlib.sha256(raw).hexdigest() != ANCHOR_SHA256:
        raise ValueError('saved systemd activation dependency anchor differs')
    if capture_dependencies() != json.loads(raw):
        raise ValueError('systemd activation dependency drift before service start')
