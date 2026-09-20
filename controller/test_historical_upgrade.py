"""Recovered historical source -> pre018 -> exact repair, private PostgreSQL only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import psycopg2
import pytest
from authority_service_server import AuthorityServiceServer
REPO_ROOT=Path(__file__).resolve().parents[1]
from db import create_disposable_database,drop_database,alembic_command as _alembic_command,current_database_revision
from authority_pins import MIGRATION_SOURCE_PROVENANCE_PATH,COMMS01_ATTESTATION_PATH
from test_goal_completion import chain
from test_goal_completion import (
    test_missing_successor_reconciles_after_commit_crash,
    test_concurrent_finalizers_and_stale_epoch,
    test_adoption_commit_crash_does_not_duplicate_or_replay,
    test_database_outage_before_reconcile_never_executes,
    test_existing_intent_never_bypassed_for_prerequisite,
    test_tampered_completed_evidence_is_not_cli_success,
    test_child_graph_completion_is_not_whole_parent,
    test_default_projection_denies_direct_graph_mutation,
    test_paused_run_refuses_new_graph_bind,
    test_sql_finalizer_requires_executor_evidence,
)

from test_only.historical_package import materialize
from test_only.isolation import require_isolation

EXPECTED=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO_ROOT,text=True).strip()
STAGES=[]

def alembic_command(url,operation,revision):
    try:
        return _alembic_command(url,operation,revision)
    except subprocess.CalledProcessError as exc:
        from harness_adapters.redaction import redact_text
        reason=redact_text(str(exc.stderr or exc.output or 'no captured diagnostic'))[-7500:]
        # Surface sanitized errors without writing into source or host paths.
        raise RuntimeError(revision+': '+reason) from exc

def checked(path,digest):
    assert hashlib.sha256(path.read_bytes()).hexdigest()==digest,str(path)
    return path

def stage(name,url):
    revision=current_database_revision(url)
    STAGES.append({'boundary':name,'revision':revision})
    # pytest retains boundary assertions; optional evidence is written to tmp_path.
    return revision

def bootstrap(url, output, support, standalone=False):
    require_isolation(support.ADMIN_URL)
    assert url.rsplit('/',1)[1].startswith('td_test_')
    OLD = REC = materialize(support.ADMIN_URL)
    checked(OLD/'migrations/versions/014_requeue_blocked_parent_task.py','be05d24299ae93dc3d0c5244d9a10266c2b098327a644adbf575dde954ee672c')
    checked(OLD/'migrations/versions/013_cleanup_expired_attempt.py','911d718a54a36148d1b4410fbce75e1107f569dde99dfcf7c9c1711e32fc4e7b')
    alembic_command(url,'upgrade','013_cleanup_expired_attempt')
    assert stage('canonical013',url)=='013_cleanup_expired_attempt'
    # Use original source, original hard-coded source verifier/catalog and its
    # actual Alembic environment. Only private test trust metadata changes here.
    anchor=Path(MIGRATION_SOURCE_PROVENANCE_PATH)
    saved=anchor.read_bytes()
    data=json.loads(saved)
    data['legacy_source_digests']['014_requeue_blocked_parent_task']='be05d24299ae93dc3d0c5244d9a10266c2b098327a644adbf575dde954ee672c'
    attestation=Path(COMMS01_ATTESTATION_PATH)
    saved_attestation=attestation.read_bytes()
    historical_attestation=json.loads(saved_attestation)
    try:
        anchor.write_text(json.dumps(data))
        # Historical runner predates the current test-seam issuer. Use its measured
        # runtime fingerprint, not a fabricated host or disabled identity check.
        env=dict(os.environ,PYTHONPATH=str(OLD),PYTHONDONTWRITEBYTECODE='1')
        measured=subprocess.check_output([sys.executable,'-c',
            'from attestation import _runtime_host_fingerprint; print(_runtime_host_fingerprint())'],cwd=OLD,env=env,text=True).strip()
        historical_attestation['host_fingerprint']=measured
        attestation.write_text(json.dumps(historical_attestation))
        env=dict(os.environ,PYTHONPATH=str(OLD),PYTHONDONTWRITEBYTECODE='1')
        result=subprocess.run([sys.executable,'-c',
            'import sys; from db import alembic_command; alembic_command(sys.argv[1],"upgrade","014_requeue_blocked_parent_task")',url],
            cwd=OLD,env=env,capture_output=True,text=True,timeout=300)
        if result.returncode:
            from harness_adapters.redaction import redact_text
            raise RuntimeError('original014: '+redact_text(result.stderr)[-6000:])
    finally:
        try:
            anchor.write_bytes(saved)
        finally:
            attestation.write_bytes(saved_attestation)
    assert stage('original014',url)=='014_requeue_blocked_parent_task'
    from sqlalchemy import create_engine
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext
    for revision,digest,sqlhash in [
        ('015_recover_executor_contract_failure','c14a8f9b43c1410abc0d9e1ac3637f8e42377306a9beaa9c902a6bc79040f225','c05232aead7d048b5b3b4b9f4f4976af8e0a23a9c582a74378b6e821d52a3071'),
        ('016_recover_exhausted_executor_contract_once','83ea3e9d957df81cc961896973a7a1925bd7270c1af06dee8cb260b894730113','bc1530d6e127d5bad6175bf23fc8e392ea4e8dd2111c9d9d6c890e96b190082b')]:
        path=checked(REC/'migrations/candidates'/f'{revision}.py',digest)
        checked(REC/'sql'/f'{revision}.sql',sqlhash)
        spec=importlib.util.spec_from_file_location(revision,path)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Archived phase_apply_015_016.py executes as postgres, not the root
        # test administrator. Preserve that historical function-owner context.
        from sqlalchemy.engine import make_url
        engine=create_engine(make_url(url).set(username='postgres'))
        try:
            with engine.begin() as conn:
                with Operations.context(MigrationContext.configure(conn)):
                    module.upgrade() # its own target guard and transactional CAS
        finally:
            engine.dispose()
        assert stage(revision,url)==revision
    checked(REPO_ROOT/'controller/migrations/versions/017_parent_rollback_routine.py','30ae5700613aabc5f4c40788e78ad5290cacba2335aca9a474d3b61f6394e103')
    checked(REPO_ROOT/'controller/sql/017_park_disabled_parent_retries.sql','083198476db4dc4504c811516061afefd20024655c0fcd7dae74e69822e4cb2e')
    # Populate the historical schema before upgrade via its ordinary fenced SQL
    # interfaces. These are synthetic rows, not production fixtures or dumps.
    workflow,_authority=support.provision_role_users(support.ADMIN_URL,url.rsplit('/',1)[1])
    seeded=['goal-d15c000000000001','goal-d15c000000000002','goal-d15c000000000003']
    with psycopg2.connect(workflow) as conn:
        with conn.cursor() as cur:
            for run,state in zip(seeded,['paused','failed','active']):
                cur.execute('SELECT longspan_register_run(%s,%s)',(run,state))
            cur.execute('SELECT longspan_acquire_controller(%s,%s,%s,%s,%s)',(seeded[2],'disposable-seed-owner',300,None,False))
            epoch=cur.fetchone()[0]
            cur.execute('SELECT controller_fence_token FROM controller_control WHERE run_id=%s',(seeded[2],))
            fence=cur.fetchone()[0]
            cur.execute('SELECT longspan_schedule_goal_task(%s,%s,%s,%s,clock_timestamp(),%s,%s,%s)',
                (seeded[2],seeded[2]+'-ws-01','Synthetic pre-upgrade queued task',1,epoch,'disposable-seed-owner',fence))
    def snapshot():
        with psycopg2.connect(url) as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM supervisor_runs r WHERE run_id=ANY(%s)',(seeded,))
                runs=cur.fetchone()[0]
                cur.execute('SELECT jsonb_agg(to_jsonb(c) ORDER BY run_id) FROM controller_control c WHERE run_id=ANY(%s)',(seeded,))
                controls=cur.fetchone()[0]
                cur.execute('SELECT jsonb_agg(to_jsonb(t) ORDER BY task_id) FROM parent_tasks t WHERE run_id=ANY(%s)',(seeded,))
                tasks=cur.fetchone()[0]
        return {'runs':runs,'controllers':controls,'tasks':tasks}
    before=snapshot()
    if standalone:
        alembic_command(url,'upgrade','017_parent_rollback_routine')
        assert stage('standalone017',url)=='017_parent_rollback_routine'
        assert snapshot()==before
    # Full target must also traverse 017 directly from 016 when standalone=False.
    alembic_command(url,'upgrade','021_goal_completion')
    assert stage('guarded_016_through_017_to_exact_repair021',url)=='021_goal_completion'
    after=snapshot()
    assert after==before
    (output/'synthetic-data-preservation.json').write_text(json.dumps({'unchanged':True,
        'source':'synthetic rows created through historical fenced SQL before upgrade',
        'before':before,'after':after},indent=2)+'\n')
    with psycopg2.connect(url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM supervisor_runs")
            assert cur.fetchone()[0]==3
            cur.execute("SELECT proname,pg_get_function_identity_arguments(p.oid),pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND proname IN ('longspan_cleanup_expired_parent_attempt','longspan_requeue_blocked_parent_task','longspan_recover_executor_contract_failure','longspan_recover_exhausted_executor_contract_once','longspan_park_disabled_parent_retries') ORDER BY proname")
            rows=cur.fetchall()
            assert len(rows)==5
            for row in rows:
                if row[0].startswith('longspan_recover_'):
                    assert row[2]=='postgres'
                else:
                    assert row[2]=='top_delivery_migration'
            (output/'recovered-routines-after-upgrade.json').write_text(json.dumps(rows,indent=2)+'\n')

@pytest.fixture
def db_url(request, tmp_path, controller_test_support):
    support=controller_test_support
    name='td_test_recovered_'+uuid.uuid4().hex
    support.install_capability(operation='create_database',database_name=name)
    url=create_disposable_database(support.ADMIN_URL,name)
    server=None
    try:
        bootstrap(url, tmp_path, support, standalone=getattr(request,"param",False))
        workflow,authority=support.provision_role_users(support.ADMIN_URL,name)
        support.write_workflow_service_target(workflow,name)
        support.write_authority_service_target(authority,name)
        server=AuthorityServiceServer(repo_root=REPO_ROOT)
        server.start()
        yield workflow
    finally:
        if server: server.close()
        support.install_capability(operation='drop_database',database_name=name)
        drop_database(support.ADMIN_URL,name)

@pytest.mark.parametrize("db_url", [False, True], indirect=True, ids=["full-016-to-021", "standalone017-then021"])
def test_recovered_pre018_upgrade_and_parent_chain(chain, tmp_path):
    parent,worker,receipt,writer,author,*_=chain
    run=receipt.run_id
    assert worker.run_once(run,'gate').terminal_state=='handoff_waiting'
    assert worker.run_once(run,'provider').terminal_state=='handoff_completed'
    assert parent.durable_goal_status(run)['exit_code']!=0
    assert worker.run_once(run,'parent').terminal_state=='verified'
    assert worker.run_once(run,'successor').terminal_state=='verified'
    assert parent.durable_goal_status(run)['exit_code']==0
    assert author.calls==1 and writer.calls==2
    with pytest.raises(Exception,match='permission denied'):
        with parent._repo.transaction() as cur:
            cur.execute('UPDATE horizon_goal_graphs SET outcome=NULL WHERE run_id=%s',(run,))
    (tmp_path/'chain-result.json').write_text(json.dumps({'sha':EXPECTED,'models':'SIMULATED',
        'baseline':'recovered original source, no production rows or schema dumps',
        'status':parent.durable_goal_status(run)},indent=2)+'\n')


def test_unmodified_fresh_live_replay_remains_restricted(controller_test_support):
    support=controller_test_support
    require_isolation(support.ADMIN_URL)
    name='td_test_denied_'+uuid.uuid4().hex
    support.install_capability(operation='create_database',database_name=name)
    url=create_disposable_database(support.ADMIN_URL,name)
    try:
        with pytest.raises(subprocess.CalledProcessError) as caught:
            _alembic_command(url,'upgrade','021_goal_completion')
        diagnostic=str(caught.value.stderr or caught.value.output)
        assert '014_requeue_blocked_parent_task is already applied on live; do not re-apply' in diagnostic
        assert current_database_revision(url)!='021_goal_completion'
    finally:
        support.install_capability(operation='drop_database',database_name=name)
        drop_database(support.ADMIN_URL,name)


def test_fingerprint_failure_restores_both_private_trust_files(controller_test_support,tmp_path,monkeypatch):
    support=controller_test_support
    require_isolation(support.ADMIN_URL)
    paths=[Path(MIGRATION_SOURCE_PROVENANCE_PATH),Path(COMMS01_ATTESTATION_PATH)]
    saved=[p.read_bytes() for p in paths]
    name='td_test_fingerprint_'+uuid.uuid4().hex
    support.install_capability(operation='create_database',database_name=name)
    url=create_disposable_database(support.ADMIN_URL,name)
    original=subprocess.check_output
    def fail_fingerprint(argv,*args,**kwargs):
        if any('_runtime_host_fingerprint' in str(arg) for arg in argv):
            raise RuntimeError('injected fingerprint failure')
        return original(argv,*args,**kwargs)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(subprocess,'check_output',fail_fingerprint)
            with pytest.raises(RuntimeError,match='injected fingerprint failure'):
                bootstrap(url,tmp_path,support)
        assert [p.read_bytes() for p in paths]==saved
        assert current_database_revision(url)=='013_cleanup_expired_attempt'
    finally:
        support.install_capability(operation='drop_database',database_name=name)
        drop_database(support.ADMIN_URL,name)
