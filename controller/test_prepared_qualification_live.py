"""NOT INVOKED by CI. One separately authorized five-session qualification only.

Execution identity is a private test seam; actual Cursor/model use does not
qualify installed systemd services, general Gateway or unified Comms Relay.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import pytest
import test_packaged_qualification as chain
from test_historical_upgrade import db_url
from test_only.isolation import require_isolation

consumer=chain.consumer
server=chain.server


@pytest.fixture
def qualification_inputs():
    source=os.environ.get('HORIZON_PREPARED_QUALIFICATION')
    if not source:
        pytest.skip('live qualification not authorized or invoked')
    require_isolation(os.environ.get('TOP_DELIVERY_PG_ADMIN_URL',''))
    path=Path(source)
    raw=path.read_bytes()
    if os.environ.get('HORIZON_QUALIFICATION_AUTHORIZATION')!='operator-authorized:'+hashlib.sha256(raw).hexdigest():
        raise ValueError('exact prepared live plan authorization required')
    value=json.loads(raw)
    root=Path(__file__).resolve().parents[1]
    sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    if sha!=value['source_commit'] or subprocess.check_output(['git','status','--porcelain'],cwd=root):
        raise ValueError('live source is not the exact clean reviewed candidate')
    for name in ('submission_release','review_release'):
        manifest=Path(value[name])/'manifest.json'
        if hashlib.sha256(manifest.read_bytes()).hexdigest()!=value[name+'_manifest_sha256']:
            raise ValueError('prepared package changed')
        metadata=json.loads(manifest.read_text())
        if metadata['source_commit']!=sha or metadata['source_state']!='committed':
            raise ValueError('live qualification requires committed packages')
        for name,expected in metadata['files'].items():
            relative=Path(name)
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('package path escapes release')
            target=manifest.parent/relative
            if any(p.is_symlink() for p in (target,*target.parents)) or hashlib.sha256(target.read_bytes()).hexdigest()!=expected:
                raise ValueError('package input changed before import')
    spec=importlib.util.spec_from_file_location('prepared_gate',Path(value['submission_release'])/'tools/qualification/session_gate.py')
    gate=importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
    gate.validate_prepared(path,hashlib.sha256(raw).hexdigest(),value['gate_config'])
    return value


@pytest.fixture
def built(qualification_inputs):
    return Path(qualification_inputs['submission_release'])


def test_one_authorized_prepared_qualification(consumer, server, db_url, qualification_inputs):
    chain.test_packaged_submission_to_durable_whole_goal(consumer,server,db_url,'direct',qualification_inputs)
