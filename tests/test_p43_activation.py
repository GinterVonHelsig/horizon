"""P43 negative activation tests. No host service mutation or control DB writes."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import recovery_acceptance as acceptance
import recovery_db as db
import recovery_dependencies as dependencies
import recovery_service_anchor as anchor
import recovery_start as start
from test_p40_root_cause_repair import recovery_source, recovery_start_fixture

REAL_ACCEPTED_SOURCE = acceptance.accepted_source


@pytest.fixture
def external_acceptance(recovery_source, monkeypatch):
    repo, release, sha, tree = recovery_source
    base = release.parent
    packet = base / "packet.md"
    packet.write_text("Frozen candidate " + sha + " tree " + tree)
    def artifact(path):
        path.chmod(0o444)
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    reviews = []
    for seat, model in (("1.5", "sol-fixture"), ("1.6", "glm-fixture")):
        path = base / (seat + ".json")
        path.write_text(json.dumps({"status": "ok", "verdict": "approve-with-minors", "model": model}))
        reviews.append({"seat": seat, **artifact(path)})
    receipt = {"schema": "p46-source-acceptance-v1", "approved": True, "host": "comms-01",
        "parent": acceptance.PARENT, "prompt_sha256": acceptance.PROMPT_SHA256,
        "candidate_sha": sha, "tree": tree, "packet": artifact(packet), "reviews": reviews}
    ci = base / 'ci.json'
    ci.write_text(json.dumps({'run': {'repository':'GinterVonHelsig/TOP-DELIVERY','head_sha':sha,
        'status':'completed','conclusion':'success','path':'.github/workflows/ci.yml'},
        'jobs':[{'name':'focused-unit','head_sha':sha,'status':'completed','conclusion':'success'}],
        'tested_sha':sha,'tested_tree':tree}))
    log = base / 'ci.log'
    log.write_text('focused-unit\tVerify exact reviewed source\t2026-09-13T00:00:00Z P44_TESTED_SHA='+sha+'\n'
                   +'focused-unit\tVerify exact reviewed source\t2026-09-13T00:00:00Z P44_TESTED_TREE='+tree+'\n')
    receipt.update(ci=artifact(ci), ci_log=artifact(log))
    path = base / "accepted-source.json"
    path.write_text(json.dumps(receipt))
    path.chmod(0o444)
    monkeypatch.setattr(acceptance, "ACCEPTANCE_PATH", path)
    monkeypatch.setattr(acceptance.socket, "gethostname", lambda: "comms-01")
    monkeypatch.setattr(acceptance, "accepted_source", REAL_ACCEPTED_SOURCE)
    return receipt, path, recovery_source


@pytest.mark.parametrize("damage", ["none", "tree", "host", "parent", "authority", "seat-order", "review", "packet", "writable"])
def test_fixed_out_of_tree_acceptance_requires_actual_ordered_reviews(external_acceptance, damage):
    receipt, path, source = external_acceptance
    if damage in {"tree", "host", "parent"}:
        receipt[damage] = "wrong"
    elif damage == "authority":
        receipt["prompt_sha256"] = "wrong"
    elif damage == "seat-order":
        receipt["reviews"].reverse()
    elif damage == "review":
        Path(receipt["reviews"][0]["path"]).write_text('{"verdict":"changes-required"}')
    elif damage == "packet":
        Path(receipt["packet"]["path"]).write_text("another packet")
    if damage != "none":
        path.write_text(json.dumps(receipt))
    if damage == "writable":
        path.chmod(0o666)
    if damage == "none":
        assert acceptance.accepted_source() == receipt
        assert start.verify_source(*source) == 2
    else:
        with pytest.raises(ValueError):
            acceptance.accepted_source()


def test_self_consistent_alternate_main_is_not_review_authority(external_acceptance, monkeypatch):
    _, _, (repo, release, _sha, _tree) = external_acceptance
    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                              text=True, check=True).stdout.strip()
    (repo / "controller/worker.py").write_text("# unreviewed but self-consistent\n")
    git("add", "controller/worker.py")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "unreviewed")
    alternate, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    git("update-ref", "refs/remotes/origin/main", alternate)
    (release / "controller/worker.py").write_bytes((repo / "controller/worker.py").read_bytes())
    runner = MagicMock()
    monkeypatch.setattr(start, "_run", runner)
    with pytest.raises(ValueError, match="independently accepted"):
        start.verify_source(repo, release, alternate, tree)
    runner.assert_not_called()  # Even git, reload and start are unreachable.


@pytest.mark.parametrize("damage", ["empty-directory", "fifo", "private-file", "private-directory", "setuid", "socket"])
def test_every_release_entry_and_service_readable_mode_is_checked(recovery_source, damage):
    repo, release, sha, tree = recovery_source
    sock = None
    if damage == "empty-directory":
        (release / "extra-empty").mkdir(mode=0o777)
    elif damage == "fifo":
        os.mkfifo(release / "extra-fifo")
    elif damage == "private-file":
        (release / "controller/worker.py").chmod(0o600)
    elif damage == "private-directory":
        (release / "controller").chmod(0o700)
    elif damage == "setuid":
        (release / "controller/worker.py").chmod(0o4644)
    else:
        import socket
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(release / "extra-socket"))
    try:
        with pytest.raises(ValueError):
            start.verify_source(repo, release, sha, tree)
    finally:
        if sock:
            sock.close()


def test_actual_service_uid_read_catches_private_ancestor(recovery_source):
    _, release, _, _ = recovery_source
    release.parent.chmod(0o700)
    with pytest.raises(ValueError, match="actual service identity"):
        start.verify_service_readability(release)


@pytest.mark.parametrize("failure", ["source", "config", "effective", "active", "database", "none"])
def test_controller_stage_proves_source_and_config_before_either_start(recovery_start_fixture, monkeypatch, failure):
    r, args, events, queue = recovery_start_fixture
    monkeypatch.setattr(r, "_unit", lambda name: {"ActiveState": "inactive", "MainPID": "0"})
    def fail(*args, **kwargs):
        raise ValueError("fixture drift")
    if failure == "source":
        monkeypatch.setattr(r, "verify_source", fail)
    elif failure == "config":
        monkeypatch.setattr(anchor, "verify_installed_config", fail)
    elif failure == "effective":
        monkeypatch.setattr(r, "verify_units", fail)
    elif failure == "active":
        monkeypatch.setattr(r, "_unit", lambda name: {"ActiveState": "active", "MainPID": "123"})
    elif failure == "database":
        monkeypatch.setattr(r, "read_queue", fail)
    if failure == "none":
        assert r.start_verified(*args, start=True, controller_stage=True)["disposition"] == "CONTROLLER_STARTED_NOT_ACCEPTED"
        assert events == ["actual-source", "installed-config", ("systemctl", "daemon-reload"),
                          "effective-units", "queue", ("systemctl", "start", r.CONTROLLER)]
    else:
        with pytest.raises(ValueError):
            r.start_verified(*args, start=True, controller_stage=True)
        assert not any(isinstance(event, tuple) and event[:2] == ("systemctl", "start") for event in events)
        if failure in {"source", "config"}:
            assert ("systemctl", "daemon-reload") not in events


@pytest.mark.parametrize("command", ["ExecStartPre", "ExecStartPost"])
def test_installed_command_drift_fails_even_with_stale_systemd_cache(tmp_path, monkeypatch, command):
    fragment = tmp_path / "controller.service"
    fragment.write_text("[Service]\nExecStart=/reviewed\n")
    release = tmp_path / "release"
    baseline = anchor._file_closure(release, {fragment}, None) if os.geteuid() == 0 else None
    if baseline is None:
        pytest.skip("protected root file test")
    monkeypatch.setattr(anchor, "_saved_anchor", lambda: {"files": baseline})
    proof = tmp_path / "proof.conf"
    proof.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/python3 " + str(release / "controller/worker_cli.py")
                     + f" --once --run-id {anchor.PARENT} --expected-task-id {start.TASKS[0]}\nRestart=no\n")
    monkeypatch.setattr(anchor, "PROOF_DROPIN", proof)
    fragment.write_text(fragment.read_text() + command + "=/unreviewed\n")
    with pytest.raises(ValueError, match="before daemon-reload"):
        anchor.verify_installed_config(release, start.TASKS[0])


def test_query_process_is_env_clean_and_explicit(monkeypatch):
    captured = []
    for key in ("PGPORT", "PGSERVICE", "PGUSER", "PGOPTIONS", "PGHOST", "PGPASSFILE"):
        monkeypatch.setenv(key, "spoofed")
    def run(argv, **kwargs):
        captured.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, '{"ok":true}', "")
    monkeypatch.setattr(db.subprocess, "run", run)
    assert db._query(["fixture"], payload="stdin-only") == {"ok": True}
    assert not any(key.startswith("PG") for key in captured[0][1]["env"])
    assert captured[0][1]["cwd"] == "/"
    assert "public.parent_tasks" in db.QUEUE_SQL and "public.task_attempts" in db.QUEUE_SQL
    assert "public.controller_control" in db.QUEUE_SQL and "SET LOCAL search_path=pg_catalog" in db.QUEUE_SQL


@pytest.mark.parametrize("spoof", ["system_identifier", "port", "role", "database", "address", "application-server", "none"])
def test_wrong_cluster_or_application_endpoint_never_authorizes(spoof, monkeypatch):
    identity = {"database": "td_test_p43", "role": "postgres", "port": 6543, "address": None,
                "system_identifier": "111", "data_directory": "/disposable", "in_recovery": False}
    config = {"observer": {"socket": "/fixture", "port": 6543, "role": "postgres", "database": "td_test_p43"},
              "identity": identity}
    target = {"database_name": "td_test_p43", "database_role": "fixture", "database_endpoint": "127.0.0.1", "database_port": 6543,
              "database_url": "postgresql://fixture:fixture-only@127.0.0.1:6543/td_test_p43"}
    result = {"identity": dict(identity), "database": "td_test_p43", "postmaster_started": "fixed", "database_oid": "123",
              "head": start.TASKS[0], "active": 0, "lease_live": True}
    app = {"database": "td_test_p43", "role": "fixture", "address": "127.0.0.1", "port": 6543,
           "postmaster_started": "fixed", "database_oid": "123"}
    if spoof in identity:
        result["identity"][spoof] = "wrong"
    elif spoof == "application-server":
        app["postmaster_started"] = "other-server"
    monkeypatch.setattr(db, "approved_target", lambda: (config, target))
    calls = []
    def query(argv, **kwargs):
        calls.append(argv)
        return result if len(calls) == 1 else app
    monkeypatch.setattr(db, "_query", query)
    if spoof == "none":
        assert db.read_queue()["application_endpoint_verified"]
    else:
        with pytest.raises(ValueError):
            db.read_queue()
    argv = calls[0]
    for flag, value in (("-h", "/fixture"), ("-p", "6543"), ("-U", "postgres"), ("-d", "td_test_p43")):
        assert argv[argv.index(flag) + 1] == value
    assert "-X" in argv and "-w" in argv


def test_static_anchor_does_not_require_or_read_a_running_process(monkeypatch):
    monkeypatch.setattr(dependencies, 'verify_dependencies', lambda: None)
    baseline = {"units": {}, "files": {}, "auth_path": "/auth", "controller_environments": {"old": "hash"}}
    monkeypatch.setattr(anchor, "_saved_anchor", lambda: dict(baseline))
    def capture(*args, **kwargs):
        assert kwargs["static"] is True
        return {key: value for key, value in baseline.items() if key != "controller_environments"}
    monkeypatch.setattr(anchor, "capture_service_anchor", capture)
    runner = MagicMock()
    anchor.verify_service_anchor(Path("/accepted"), start.TASKS[0], MagicMock(), runner, static=True)
    runner.assert_not_called()


@pytest.mark.parametrize('damage', ['missing','wrong-head','failed','wrong-workflow','missing-job','failed-job','changed-log'])
def test_source_acceptance_requires_exact_passing_ci(external_acceptance, damage):
    receipt, path, _source = external_acceptance
    if damage == 'missing':
        receipt.pop('ci')
    elif damage == 'changed-log':
        Path(receipt['ci_log']['path']).write_text('changed log')
    else:
        ci_path = Path(receipt['ci']['path'])
        ci = json.loads(ci_path.read_text())
        if damage == 'wrong-head': ci['run']['head_sha'] = 'f' * 40
        elif damage == 'failed': ci['run']['conclusion'] = 'failure'
        elif damage == 'wrong-workflow': ci['run']['path'] = '.github/workflows/unrelated.yml'
        elif damage == 'missing-job': ci['jobs'] = []
        elif damage == 'failed-job': ci['jobs'][0]['conclusion'] = 'failure'
        ci_path.write_text(json.dumps(ci))
        receipt['ci']['sha256'] = hashlib.sha256(ci_path.read_bytes()).hexdigest()
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError):
        acceptance.accepted_source()


@pytest.mark.parametrize('edge', ['Requires','Wants','BindsTo','Upholds','OnFailure','OnSuccess','Triggers'])
@pytest.mark.parametrize('indirect', [False, True])
def test_added_activation_edge_is_rejected_before_controller_start(recovery_start_fixture, monkeypatch, edge, indirect):
    r, args, events, _queue = recovery_start_fixture
    root, worker = dependencies.ROOTS
    original = {root:{'Wants':['network-online.target']},worker:{},'network-online.target':{}}
    baseline = dependencies.capture_dependencies(lambda unit: original[unit])
    changed = {key:dict(value) for key,value in original.items()}
    changed['network-online.target' if indirect else root][edge] = [worker]
    actual = dependencies.capture_dependencies(lambda unit: changed[unit])
    assert actual != baseline
    raw = json.dumps(baseline).encode()
    monkeypatch.setattr(anchor, '_root_file', lambda path: raw)
    monkeypatch.setattr(dependencies, 'ANCHOR_SHA256', hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(dependencies, 'capture_dependencies', lambda: actual)
    monkeypatch.setattr(r, '_unit', lambda unit:{'ActiveState':'inactive','MainPID':'0'})
    monkeypatch.setattr(r, 'verify_units', lambda *args,**kwargs: dependencies.verify_dependencies())
    with pytest.raises(ValueError, match='dependency drift'):
        r.start_verified(*args, start=True, controller_stage=True)
    assert not any(isinstance(event,tuple) and event[:2] == ('systemctl','start') for event in events)


def test_dependency_capture_normalizes_order_and_follows_activation_only():
    root, worker = dependencies.ROOTS
    graph = {root:{'Requires':['a.target','b.target'],'After':['unrelated.scope']},worker:{},
             'a.target':{'Wants':['b.target']},'b.target':{}}
    first = dependencies.capture_dependencies(lambda unit:graph[unit])
    graph[root]['Requires'].reverse()
    assert dependencies.capture_dependencies(lambda unit:graph[unit]) == first
    assert 'unrelated.scope' not in first


@pytest.mark.skipif(os.geteuid() != 0 or os.environ.get("P43_DISPOSABLE_PG") != "1",
                    reason="explicit local disposable-cluster rehearsal only")
def test_disposable_clusters_ignore_spoofed_port_and_search_path(recovery_start_fixture, monkeypatch):
    """Two private Unix-only clusters; td_test_p43 only; no installed DB writes."""
    import pwd
    import socket
    import tempfile
    pg = Path("/usr/lib/postgresql/17/bin")
    if not (pg / "initdb").is_file():
        pytest.skip("PostgreSQL17 fixture binaries unavailable")
    account = pwd.getpwnam("postgres")
    def run(argv):
        result = subprocess.run(["/usr/sbin/runuser", "-u", "postgres", "--", *map(str, argv)],
            env=db.CLEAN_ENV, cwd="/", capture_output=True, text=True, timeout=40)
        assert result.returncode == 0, "disposable PostgreSQL command failed (no secrets)"
        return result.stdout
    def free_port():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="p43-db-test-", dir="/var/lib") as temp:
        base = Path(temp)
        os.chown(base, account.pw_uid, account.pw_gid)
        base.chmod(0o700)
        socket_dir = base / "sockets"
        socket_dir.mkdir()
        os.chown(socket_dir, account.pw_uid, account.pw_gid)
        ports = [free_port(), free_port()]
        assert ports[0] != ports[1]
        started = []
        try:
            for index, port in enumerate(ports):
                data = base / ("cluster" + str(index))
                run([pg / "initdb", "-D", data, "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=reject"])
                run([pg / "pg_ctl", "-D", data, "-l", base / (str(index) + ".log"),
                     "-o", f"-h '' -k {socket_dir} -p {port}", "-w", "start"])
                started.append(data)
                run([pg / "createdb", "-h", socket_dir, "-p", port, "-U", "postgres", "td_test_p43"])
                seed = f"""CREATE TABLE public.parent_tasks(task_id text,run_id text,state text,available_at timestamptz,priority int);
CREATE TABLE public.task_attempts(run_id text,status text);
CREATE TABLE public.controller_control(run_id text,scheduling_enabled bool,lease_expires_at timestamptz,owner text,current_epoch int);
CREATE TABLE public.supervisor_events(event_id text,event_seq bigint,run_id text,controller_epoch int,event_type text,occurred_at timestamptz,detail_json text);
INSERT INTO public.parent_tasks VALUES('{start.TASKS[0]}','{start.PARENT}','queued',now(),2);
INSERT INTO public.controller_control VALUES('{start.PARENT}',true,now()+interval '1 hour','fixture-owner',1);
CREATE SCHEMA spoof;
CREATE TABLE spoof.parent_tasks AS SELECT * FROM public.parent_tasks;
UPDATE spoof.parent_tasks SET task_id='spoofed-head';"""
                run([pg / "psql", "-X", "-w", "-h", socket_dir, "-p", port, "-U", "postgres",
                     "-d", "td_test_p43", "-v", "ON_ERROR_STOP=1", "-c", seed])
            observer = {"socket": str(socket_dir), "port": ports[0], "role": "postgres", "database": "td_test_p43"}
            argv = ["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-X", "-w", "-qAt",
                    "-h", str(socket_dir), "-p", str(ports[0]), "-U", "postgres", "-d", "td_test_p43",
                    "-v", "ON_ERROR_STOP=1", "-c", db.QUEUE_SQL]
            first = db._query(argv)
            config = {"observer": observer, "identity": first["identity"]}
            target = {"database_name": "td_test_p43", "database_role": "fixture", "database_endpoint": "127.0.0.1", "database_port": ports[0]}
            monkeypatch.setattr(db, "approved_target", lambda: (config, target))
            actual_query = db._query
            def query(command, **kwargs):
                if command[0] == "/usr/sbin/runuser":
                    return actual_query(command, **kwargs)
                # The TCP link is independently tested above and live read-only;
                # these private Unix-only clusters exercise port/schema/server ID.
                return {"database": "td_test_p43", "role": "fixture", "address": "127.0.0.1", "port": ports[0],
                        "postmaster_started": first["postmaster_started"], "database_oid": first["database_oid"]}
            monkeypatch.setattr(db, "_query", query)
            monkeypatch.setenv("PGPORT", str(ports[1]))
            monkeypatch.setenv("PGOPTIONS", "-c search_path=spoof,public")
            monkeypatch.setenv("PGSERVICE", "nonexistent-spoof")
            assert db.read_queue()["head"] == start.TASKS[0]
            observer["port"] = ports[1]
            with pytest.raises(ValueError, match="server/database identity"):
                db.read_queue()
            r, args, events, _queue = recovery_start_fixture
            monkeypatch.setattr(r, "read_queue", db.read_queue)
            with pytest.raises(ValueError, match="server/database identity"):
                r.start_verified(*args, start=True)
            assert ("systemctl", "start", r.WORKER) not in events
        finally:
            for data in reversed(started):
                run([pg / "pg_ctl", "-D", data, "-m", "fast", "-w", "stop"])
