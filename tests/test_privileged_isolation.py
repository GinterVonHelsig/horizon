"""Host-safe regressions: forbidden paths are only modeled, never written."""
import os
from pathlib import Path
import subprocess
import sys

import pytest
from test_only import isolation
from test_only.historical_package import verified_sources

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ['/tmp', '/run', '/etc/top-delivery', '/var/lib/top-delivery-submission-bundles']


def mounts(targets):
    return '\n'.join(f'{i+10} 1 0:2 / {p} rw - tmpfs tmpfs rw' for i,p in enumerate(targets))


def test_original_missing_host_store_mount_fails_before_database(monkeypatch):
    original = Path.read_text
    monkeypatch.setattr(Path, 'read_text', lambda p,*a,**k: mounts(TARGETS[:-1])
                        if str(p)=='/proc/self/mountinfo' else original(p,*a,**k))
    def forbidden(*a,**k):
        pytest.fail('database touched before submission-store isolation')
    monkeypatch.setattr('psycopg2.connect', forbidden)
    with pytest.raises(isolation.UnsafeTestEnvironment, match='submission-bundles'):
        isolation.require_isolation('postgresql://root@127.0.0.1:5432/postgres')


@pytest.mark.parametrize('bad', ['shared:44', 'master:44', 'nested'])
def test_bind_or_shared_store_rejected(monkeypatch,bad):
    content=mounts(TARGETS)
    content=content+'\n99 13 0:4 / /var/lib/top-delivery-submission-bundles/runs rw - ext4 /dev/fake rw' if bad=='nested' else content.replace(' rw - ', ' rw '+bad+' - ')
    monkeypatch.setattr(Path,'read_text',lambda *a,**k:content)
    with pytest.raises(isolation.UnsafeTestEnvironment):
        isolation.require_filesystem_isolation()


def test_direct_privileged_fixture_refuses_without_wrapper_before_writes(tmp_path):
    # No pytest controller fixtures run in this process. Invoke only the guarded
    # fixture in a subprocess; tripwires prove it never reaches trust/role writes.
    code = '''
import runpy
from pathlib import Path
from unittest.mock import patch
from test_only.isolation import UnsafeTestEnvironment
ns=runpy.run_path('controller/conftest.py')
original_open=Path.open
def guarded_open(path,mode='r',*args,**kwargs):
    if any(x in mode for x in 'wax+'): raise AssertionError('write before isolation')
    return original_open(path,mode,*args,**kwargs)
with patch('pathlib.Path.open',guarded_open), patch('psycopg2.connect',side_effect=AssertionError('DB before isolation')):
    try: next(ns['serialize_disposable_trust_state'].__wrapped__())
    except UnsafeTestEnvironment: print('REFUSED_BEFORE_WRITE')
    else: raise AssertionError('unguarded fixture')
'''
    env={k:v for k,v in os.environ.items() if not k.startswith('HORIZON_TEST_OUTER_')}
    env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(ROOT/'controller'))
    result=subprocess.run([sys.executable,'-c',code],cwd=ROOT,env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert 'REFUSED_BEFORE_WRITE' in result.stdout


def test_packaged_historical_sources_all_hash_match():
    sources=verified_sources()
    assert len(sources)==37
    assert any(str(p)=='migrations/versions/014_requeue_blocked_parent_task.py' for p,_ in sources)


def test_package_refuses_materialization_before_verification(monkeypatch):
    from test_only import historical_package
    def deny(*a): raise isolation.UnsafeTestEnvironment('not isolated')
    monkeypatch.setattr(historical_package,'require_isolation',deny)
    monkeypatch.setattr(historical_package.tempfile,'mkdtemp',lambda **kw:pytest.fail('write before isolation'))
    with pytest.raises(isolation.UnsafeTestEnvironment):
        historical_package.materialize('postgresql://root@127.0.0.1:5432/postgres')


@pytest.mark.parametrize('url', [
    'postgresql://root@/postgres?host=/run/postgresql',
    'postgresql://root@192.168.0.1:5432/postgres',
    'postgresql://root@127.0.0.1:5432/top_delivery_control_p1',
    'postgresql://root@127.0.0.1:5432/postgres?host=other',
])
def test_admin_endpoint_rejected_before_connect(monkeypatch,url):
    monkeypatch.setattr(isolation,'require_filesystem_isolation',lambda:None)
    monkeypatch.setattr('psycopg2.connect',lambda *a,**kw:pytest.fail('unsafe DB connect'))
    with pytest.raises(isolation.UnsafeTestEnvironment): isolation.require_isolation(url)


@pytest.mark.parametrize('directory,address,port', [
    ('/var/lib/postgresql/17/main','127.0.0.1',5432),
    ('/tmp/horizon-recovery-pg.synthetic','192.168.0.1',5432),
    ('/tmp/horizon-recovery-pg.synthetic','127.0.0.1',5433),
])
def test_read_only_probe_rejects_wrong_cluster(monkeypatch,directory,address,port):
    from unittest.mock import MagicMock
    monkeypatch.setattr(isolation,'require_filesystem_isolation',lambda:None)
    connect=MagicMock()
    connect.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value.fetchone.return_value=(directory,address,port)
    monkeypatch.setattr('psycopg2.connect',connect)
    with pytest.raises(isolation.UnsafeTestEnvironment,match='private cluster'):
        isolation.require_isolation('postgresql://root@127.0.0.1:5432/postgres')
    assert connect.call_args.kwargs['options']=='-c default_transaction_read_only=on'


def test_corrupt_packaged_bytes_refused_before_copy(monkeypatch):
    from test_only import historical_package
    original=Path.read_bytes
    monkeypatch.setattr(historical_package,'require_isolation',lambda _:None)
    monkeypatch.setattr(Path,'read_bytes',lambda p:original(p)+b'changed'
        if p.name=='014_requeue_blocked_parent_task.py' else original(p))
    monkeypatch.setattr(historical_package.tempfile,'mkdtemp',lambda **kw:pytest.fail('copy before hash validation'))
    with pytest.raises(ValueError,match='hash mismatch'):
        historical_package.materialize('postgresql://root@127.0.0.1:5432/postgres')


def test_forged_inside_entry_refused_before_mount(tmp_path):
    # A tripwire replaces mount even on an unfixed wrapper: this regression must
    # never perform the dangerous host overmount it is designed to detect.
    marker=tmp_path/'mount-called'
    mount=tmp_path/'mount'
    mount.write_text('#!/bin/sh\nprintf invoked > "$ISOLATION_TEST_MARKER"\nexit 99\n')
    mount.chmod(0o700)
    env=dict(os.environ,PATH=str(tmp_path)+':'+os.environ['PATH'],
             ISOLATION_TEST_MARKER=str(marker),HORIZON_TEST_OUTER_MNT='forged',
             HORIZON_TEST_OUTER_NET='forged',HORIZON_TEST_OUTER_PID='forged')
    result=subprocess.run(['bash',str(ROOT/'scripts/test-recovery-isolated.sh'),'--inside'],
                          cwd=ROOT,env=env,capture_output=True,text=True,timeout=10)
    assert result.returncode==64,result.stderr
    assert not marker.exists()


def test_public_wrapper_always_unshares_before_setup(tmp_path):
    marker=tmp_path/'unshare-args'
    unshare=tmp_path/'unshare'
    unshare.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ISOLATION_TEST_MARKER"\nexit 77\n')
    unshare.chmod(0o700)
    env=dict(os.environ,PATH=str(tmp_path)+':'+os.environ['PATH'],
             ISOLATION_TEST_MARKER=str(marker),HORIZON_TEST_OUTER_MNT='forged',
             HORIZON_TEST_OUTER_NET='forged',HORIZON_TEST_OUTER_PID='forged')
    result=subprocess.run(['bash',str(ROOT/'scripts/test-recovery-isolated.sh'),'-q','tests/fake.py'],
                          cwd=ROOT,env=env,capture_output=True,text=True,timeout=10)
    assert result.returncode==77,result.stderr
    assert marker.read_text().splitlines()==['--mount','--net','--pid','--cgroup','--fork','--mount-proc','bash','-s','--','-q','tests/fake.py']


def test_historical_git_blob_provenance_matches_current_sources():
    import hashlib,json
    from test_only.historical_package import PACKAGE
    provenance=json.loads((PACKAGE/'base-source-provenance.json').read_text())
    assert provenance['historical_sha']=='f2658c33c9f881be59f25608038f4f585641e0a5'
    assert 'comparison_at_repair_sha' in provenance
    assert len(provenance['sources'])==13
    for item in provenance['sources']:
        content=(ROOT/'controller/migrations/versions'/f"{item['revision']}.py").read_bytes()
        git_blob=hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        assert git_blob==item['historical_git_blob']==item['current_git_blob']
