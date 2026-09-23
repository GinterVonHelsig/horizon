"""Actual submission/provider/worker/database, SIMULATED model execution only."""
import json
import uuid
from pathlib import Path
import pytest

from goal_submitter import GoalSubmitter, TaskRoutingSnapshot
from parent_controller import ParentController
from worker import TaskWorker
from test_only.recovery_fakes import SimulatedAdapter, route_config
from test_bounded_delivery import configuration, SimulatedCursor
from bounded_delivery import BoundedDeliveryAdapter


@pytest.fixture
def chain(db_url, artifact_root, tmp_path, monkeypatch):
    monkeypatch.setattr("worker.preflight_adapters", lambda *a, **k: None)
    config = route_config()
    config["adapters"].extend(configuration()["adapters"])
    parent = ParentController(db_url, artifact_root=artifact_root, adapter_config=config)
    spec = configuration()["adapters"][0]["delivery_spec"]
    prompt = tmp_path / "goal.md"
    prompt.write_text("# Completion\n\n**Objective:** Verify all nodes.\n\n## Mission\n\nDisposable simulated task.\n\n## P0 authority envelope\n\nAllowed:\n\n- Disposable workspace.\n\nForbidden without a new explicit authority envelope:\n\n- Production changes.\n\n## Ordered workstreams\n\n### 1. Parent\n\n### 2. Successor\n\n## Cross-workstream acceptance matrix\n\n| Item | Required terminal disposition |\n|---|---|\n| 1. Parent | `PASS/ONE` |\n| 2. Successor | `PASS/TWO` |\n")
    submitter = GoalSubmitter(parent, artifact_root, task_routing=TaskRoutingSnapshot("simulated-writer","simulated-reviewer"), prerequisites={1:[spec]})
    receipt = submitter.submit(prompt)
    writer = SimulatedAdapter("simulated-writer")
    reviewer = SimulatedAdapter("simulated-reviewer", review=True)
    author = SimulatedCursor("gateway-delivery-disposable-file","composer-2.5",spec)
    audit = SimulatedCursor("cursor-independent-review","cursor-grok-4.6-high",spec,review=True)
    adapters = {a.adapter_id:a for a in [writer,reviewer,BoundedDeliveryAdapter(author,spec),audit]}
    worker = TaskWorker(parent,artifact_root,adapters,adapter_config=config)
    worker._preflight_adapters=lambda:None
    yield parent,worker,receipt,writer,author,submitter,prompt
    parent.close()


def test_full_chain_durable_completion(chain, artifact_root):
    parent,worker,receipt,writer,author,_,_ = chain
    run = receipt.run_id
    assert worker.run_once(run,"first").terminal_state=="handoff_waiting"
    assert writer.calls==author.calls==0
    assert not list((artifact_root/"execution-intents").glob("*.json"))
    assert worker.run_once(run,"provider").terminal_state=="handoff_completed"
    assert parent.durable_goal_status(run)["status"]!="complete"
    assert worker.run_once(run,"resumed").terminal_state=="verified"
    assert worker.run_once(run,"successor").terminal_state=="verified"
    assert parent.durable_goal_status(run)["status"]=="complete"
    assert writer.calls==2 and author.calls==1
    assert worker.run_once(run,"again") is None
    with parent._repo.transaction() as cur:
        cur.execute("SELECT count(*) AS n FROM horizon_prerequisite_adoptions")
        assert cur.fetchone()["n"]==1
        cur.execute("SELECT outcome FROM horizon_goal_graphs WHERE run_id=%s",(run,))
        assert cur.fetchone()["outcome"]["status"]=="complete"


def test_immutable_spec_and_pause(chain):
    parent,worker,receipt,writer,author,submitter,prompt=chain
    submitter._prerequisites["1"][0]["content"]="changed"
    with pytest.raises(ValueError): submitter.submit(prompt)
    parent.persist_goal_state(receipt.run_id,"WAITING_OPERATOR")
    assert worker.run_once(receipt.run_id,"paused") is None
    assert writer.calls==author.calls==0
    assert parent.durable_goal_status(receipt.run_id)["exit_code"]==78


def finish(chain):
    parent,worker,receipt,*_=chain
    for _ in range(4): worker.run_once(receipt.run_id,"bounded-test")
    return parent,worker,receipt.run_id


def test_missing_successor_reconciles_after_commit_crash(chain, monkeypatch):
    from exceptions import DependencyScheduleError
    parent,worker,receipt,writer,*_=chain
    worker.run_once(receipt.run_id,"gate")
    worker.run_once(receipt.run_id,"provider")
    original = parent.reconcile_goal_graph
    calls = [0]
    def crash_after_commit(run):
        calls[0]+=1
        if calls[0]==2: raise ConnectionError("simulated process death after verified commit")
        return original(run)
    def missing(*a): raise DependencyScheduleError("injected scheduling outage")
    with monkeypatch.context() as m:
        m.setattr(parent,"schedule_dependency_successors",missing)
        m.setattr(parent,"reconcile_goal_graph",crash_after_commit)
        with pytest.raises(ConnectionError): worker.run_once(receipt.run_id,"parent")
    assert writer.calls==1
    assert receipt.task_ids[1] not in parent._repo.list_parent_task_states(receipt.run_id)
    worker.run_once(receipt.run_id,"restart")
    assert writer.calls==2
    assert parent.durable_goal_status(receipt.run_id)["status"]=="complete"


def test_concurrent_finalizers_and_stale_epoch(chain, db_url):
    from concurrent.futures import ThreadPoolExecutor
    parent,worker,receipt,*_=chain
    run=receipt.run_id
    for _ in range(3): worker.run_once(run,"progress")
    task=parent.claim_next(run,"last-before-finalizers")
    assert worker._run_claimed_task(task,"last-before-finalizers").terminal_state=="verified"
    with parent._repo.transaction() as cur:
        cur.execute("SELECT outcome FROM horizon_goal_graphs WHERE run_id=%s",(run,))
        assert cur.fetchone()["outcome"] is None
    def finalize(_):
        other=ParentController(db_url,artifact_root=parent.artifact_root,lease_holder=False)
        try: return other.reconcile_goal_graph(run)
        finally: other.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert all(r["status"]=="complete" for r in pool.map(finalize,range(2)))
    with parent._repo.transaction() as cur:
        cur.execute("SELECT * FROM horizon_goal_graphs WHERE run_id=%s",(run,))
        graph=cur.fetchone()
    with pytest.raises(Exception,match="stale controller"):
        with parent._repo.transaction() as cur:
            cur.execute("SELECT horizon_complete_graph(%s,%s,%s,%s,%s::jsonb)",
                (run,run,graph["digest"],-1,json.dumps(graph["outcome"])))


def test_adoption_commit_crash_does_not_duplicate_or_replay(chain, monkeypatch):
    import goal_completion
    parent,worker,receipt,writer,*_=chain
    worker.run_once(receipt.run_id,"gate")
    worker.run_once(receipt.run_id,"provider")
    task=parent.claim_next(receipt.run_id,"manual-continuation")
    context=worker._task_context(receipt.run_id,task)
    assert not parent.prepare_prerequisites(task,context)
    assert not parent.prepare_prerequisites(task,worker._task_context(receipt.run_id,task))
    with parent._repo.transaction() as cur:
        cur.execute("SELECT count(*) AS n FROM horizon_prerequisite_adoptions")
        assert cur.fetchone()["n"]==1
    assert writer.calls==0
    # Continue the already owned attempt, not a second claim.
    assert worker._run_claimed_task(task,"manual-continuation").terminal_state=="verified"
    worker.run_once(receipt.run_id,"next")
    assert parent.durable_goal_status(receipt.run_id)["status"]=="complete"


def test_database_outage_before_reconcile_never_executes(chain,monkeypatch):
    import psycopg2
    parent,worker,receipt,writer,author,*_=chain
    with monkeypatch.context() as m:
        m.setattr(parent,"reconcile_goal_graph",lambda *a: (_ for _ in ()).throw(psycopg2.OperationalError("simulated offline")))
        with pytest.raises(psycopg2.OperationalError): worker.run_once(receipt.run_id,"offline")
    assert writer.calls==author.calls==0
    assert worker.run_once(receipt.run_id,"restored").terminal_state=="handoff_waiting"


def test_existing_intent_never_bypassed_for_prerequisite(chain,artifact_root):
    parent,worker,receipt,writer,author,*_=chain
    path=worker._execution_intent_path(receipt.run_id,receipt.task_ids[0])
    path.parent.mkdir()
    path.write_text('{"state":"execution_intent"}')
    assert worker.run_once(receipt.run_id,"unknown").terminal_state.startswith("blocked")
    assert writer.calls==author.calls==0 and path.exists()
    assert parent.durable_goal_status(receipt.run_id)["exit_code"]==78


def test_completion_requires_evidence_after_task_commit(chain,monkeypatch,artifact_root):
    parent,worker,receipt,*_=chain
    for _ in range(3): worker.run_once(receipt.run_id,"progress")
    original=parent.reconcile_goal_graph
    calls=[0]
    def crash(run):
        calls[0]+=1
        if calls[0]==2: raise ConnectionError("before completion")
        return original(run)
    with monkeypatch.context() as m:
        m.setattr(parent,"reconcile_goal_graph",crash)
        with pytest.raises(ConnectionError): worker.run_once(receipt.run_id,"last")
    path=next(artifact_root.glob("runs/*/attempts/*/auditor/stdout.txt"))
    path.write_text("tampered")
    with pytest.raises(ValueError): parent.reconcile_goal_graph(receipt.run_id)
    assert parent.durable_goal_status(receipt.run_id)["status"]!="complete"


def test_goal_cli_exit_is_whole_graph_not_provider(chain,monkeypatch,capsys):
    import goal_cli
    parent,worker,receipt,*_=chain
    class ReadOnlyView:
        def durable_goal_status(self,run): return parent.durable_goal_status(run)
        def close(self): pass
    monkeypatch.setattr(goal_cli,"build_controller",lambda *a,**k:ReadOnlyView())
    args=["status","--run-id",receipt.run_id,"--artifact-root",str(parent.artifact_root),"--database-url","disposable-test-only"]
    assert goal_cli.main(args)==2
    capsys.readouterr()
    worker.run_once(receipt.run_id,"gate")
    worker.run_once(receipt.run_id,"provider")
    assert goal_cli.main(args)==2
    capsys.readouterr()
    worker.run_once(receipt.run_id,"parent")
    worker.run_once(receipt.run_id,"successor")
    assert goal_cli.main(args)==0
    assert json.loads(capsys.readouterr().out)["status"]=="complete"


def test_completed_outcome_survives_lost_response(chain,monkeypatch):
    import goal_completion
    parent,worker,receipt,writer,*_=chain
    for _ in range(3): worker.run_once(receipt.run_id,"progress")
    original=goal_completion.status
    with monkeypatch.context() as m:
        m.setattr(goal_completion,"status",lambda *a: (_ for _ in ()).throw(ConnectionError("lost committed response")))
        # First status is the pre-claim reconciliation; explicitly finish the
        # owned task then inject loss in the post-commit completion projection.
        task=parent.claim_next(receipt.run_id,"last")
        assert worker._run_claimed_task(task,"last").terminal_state=="verified"
        with pytest.raises(ConnectionError): parent.reconcile_goal_graph(receipt.run_id)
    assert parent.reconcile_goal_graph(receipt.run_id)["status"]=="complete"
    assert writer.calls==2


def test_tampered_completed_evidence_is_not_cli_success(chain,artifact_root):
    parent,worker,run=finish(chain)
    next(artifact_root.glob("runs/*/attempts/*/auditor/stdout.txt")).write_text("changed")
    assert parent.durable_goal_status(run)["exit_code"]==78


def test_child_graph_completion_is_not_whole_parent(chain,monkeypatch):
    parent,worker,receipt,writer,author,submitter,prompt=chain
    monkeypatch.setenv("TOP_DELIVERY_REQUIRE_TRUSTED_SUBMISSIONS","1")
    # Each DB fixture is distinct; the private trusted store spans the session.
    # Do not collide when this same regression runs against both schema lineages.
    unrelated="goal-"+uuid.uuid4().hex[:16]
    parent.register_run(unrelated)
    prompt.write_text(prompt.read_text()+"\nDistinct child submission identity.\n")
    child=submitter.submit(prompt,existing_parent=unrelated)
    assert child.run_id==unrelated
    for _ in range(4): worker.run_once(unrelated,"child-only")
    status=parent.durable_goal_status(unrelated)
    assert status["status"]=="incomplete" and status["exit_code"]==2
    assert len(status["graphs"])==1
    assert status["graphs"][0]["id"]==child.submission_run_id
    assert status["graphs"][0]["id"]!=unrelated
    assert all(graph["complete"] for graph in status["graphs"])


def test_default_projection_denies_direct_graph_mutation(chain):
    parent,worker,receipt,*_=chain
    with pytest.raises(Exception,match="permission denied"):
        with parent._repo.transaction() as cur:
            cur.execute("UPDATE horizon_goal_graphs SET outcome=NULL WHERE run_id=%s",(receipt.run_id,))


def test_paused_run_refuses_new_graph_bind(chain):
    from copy import deepcopy
    from goal_completion import graphs
    parent,worker,receipt,*_=chain
    spec=deepcopy(graphs(parent,receipt.run_id)[0]["spec"])
    spec["run_id"]="new-disposable-graph"
    parent.persist_goal_state(receipt.run_id,"WAITING_OPERATOR")
    with pytest.raises(ValueError,match="paused run"):
        parent.bind_goal_graph(receipt.run_id,spec)
    assert len(graphs(parent,receipt.run_id))==1


def test_sql_finalizer_requires_executor_evidence(chain,monkeypatch):
    import goal_completion
    parent,worker,receipt,*_=chain
    for _ in range(3): worker.run_once(receipt.run_id,"progress")
    task=parent.claim_next(receipt.run_id,"last")
    original=parent.record_evidence
    # Simulate a deficient caller that omits executor index entries; never
    # disable the append-only database guard or mutate existing evidence.
    def omit_executor(**kwargs):
        if kwargs["producer"]!="executor": return original(**kwargs)
    with monkeypatch.context() as m:
        m.setattr(parent,"record_evidence",omit_executor)
        assert worker._run_claimed_task(task,"last").terminal_state=="verified"
    graph=goal_completion.graphs(parent,receipt.run_id)[0]
    with pytest.raises(Exception,match="missing verified executor evidence"):
        with parent._repo.transaction() as cur:
            cur.execute("SELECT horizon_complete_graph(%s,%s,%s,%s,%s::jsonb)",
                (receipt.run_id,receipt.run_id,graph["digest"],parent._ensure_epoch(receipt.run_id),'{"status":"complete"}'))


# Recovered live-lineage full-chain and denied-direct-write assertions are in
# test_historical_upgrade.py, alongside an explicit fresh-replay rejection test.
