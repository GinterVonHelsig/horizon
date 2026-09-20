"""Durable graph reconciliation. No models, replay authorization or release actions."""
import hashlib
import json
from pathlib import Path

from subworkflow_handoff import digest_value, validate_product


def validate_graph(spec):
    nodes = spec.get("workstreams", [])
    if not nodes or len({n["task_id"] for n in nodes}) != len(nodes):
        raise ValueError("nonempty unique graph required")
    numbers = {n["number"] for n in nodes}
    if len(numbers) != len(nodes):
        raise ValueError("duplicate graph number")
    done = set()
    while len(done) < len(nodes):
        ready = {n["number"] for n in nodes if set(n["dependencies"]) <= done}
        if ready <= done:
            raise ValueError("cyclic or missing graph dependency")
        done |= ready
    from bounded_delivery import validate_spec
    for node in nodes:
        ids = []
        for prerequisite in node.get("prerequisites", []):
            validate_spec(prerequisite)
            ids.append(prerequisite["prerequisite_id"])
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate prerequisite identity")


def bind_graph(controller, run_id, spec):
    validate_graph(spec)
    with controller._goal_state_store.lock(run_id):
        if controller._goal_state_store.is_paused(run_id):
            raise ValueError("paused run cannot accept a graph binding")
        with controller._repo.transaction() as cur:
            cur.execute("SELECT horizon_bind_graph(%s,%s,%s::jsonb,%s)",
                        (run_id, spec["run_id"], json.dumps(spec), digest_value(spec)))


def graphs(controller, run_id):
    with controller._repo.transaction() as cur:
        cur.execute("SELECT * FROM horizon_goal_graphs WHERE run_id=%s ORDER BY graph_id", (run_id,))
        return list(cur.fetchall())


def checked_product(controller, row):
    # Products are immutable, scoped to the provider's verified attempt and
    # matched to the exact persisted digest, not selected by a model's path.
    verified_evidence(controller,row["run_id"],row["provider_task_id"])
    with controller._repo.transaction() as cur:
        cur.execute("SELECT attempt_id FROM task_attempts WHERE run_id=%s AND task_id=%s AND status='verified'",
                    (row["run_id"], row["provider_task_id"]))
        attempts = list(cur.fetchall())
    matches = []
    for attempt in attempts:
        path = controller.artifact_root / "runs" / row["run_id"] / "attempts" / attempt["attempt_id"] / "work" / "handoff-product.json"
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == row["product_digest"]:
            result = validate_product(path, row["request_json"], controller.artifact_root)
            if result["validated_product"] != row["product_json"]:
                raise ValueError("durable product differs")
            matches.append((path, result))
    if len(matches) != 1:
        raise ValueError("unique verified prerequisite product required")
    return matches[0]


def prepare_prerequisites(controller, task, context):
    required = context.get("prerequisites", [])
    if not required:
        return False
    pinned = [n for g in graphs(controller,task.run_id) for n in g["spec"]["workstreams"] if n["task_id"]==task.task_id]
    if len(pinned)!=1 or pinned[0].get("prerequisites")!=required:
        raise ValueError("prerequisites require immutable submitted graph")
    intent = controller.artifact_root / "execution-intents" / (hashlib.sha256(f"{task.run_id}:{task.task_id}".encode()).hexdigest()+".json")
    if intent.exists():
        raise ValueError("prerequisite continuation cannot bypass execution intent")
    adopted = []
    for spec in required:
        with controller._repo.transaction() as cur:
            cur.execute("SELECT * FROM subworkflow_handoffs WHERE run_id=%s AND parent_task_id=%s AND request_json->'handoff_context'->>'prerequisite_node_id'=%s",
                        (task.run_id, task.task_id, spec["prerequisite_id"]))
            rows = list(cur.fetchall())
        if not rows:
            attempt, fence = controller.resolve_parent_attempt(task.task_id, task.generation)
            controller.create_subworkflow_handoff(run_id=task.run_id, parent_task_id=task.task_id,
                parent_attempt_id=attempt, parent_fence_token=fence, failure_code="BLOCKED_HORIZON_PREREQ_MISSING",
                handoff_context={"delivery_profile":spec["profile"], "delivery_spec_digest":digest_value(spec),
                                 "prerequisite_node_id":spec["prerequisite_id"]})
            return True
        if len(rows)!=1 or rows[0]["state"]!="completed":
            raise ValueError("prerequisite is unresolved; no replacement repair")
        row = rows[0]
        if row["request_json"]["handoff_context"]["delivery_spec_digest"] != digest_value(spec):
            raise ValueError("prerequisite specification conflict")
        path, product = checked_product(controller, row)
        with controller._repo.transaction() as cur:
            cur.execute("SELECT horizon_adopt_prerequisite(%s,%s,%s,%s,%s,%s)",
                        (task.run_id,task.task_id,spec["prerequisite_id"],row["handoff_id"],row["product_digest"],controller._ensure_epoch(task.run_id)))
        adopted.append({"prerequisite_id":spec["prerequisite_id"],"product_path":str(path),
                        "product_sha256":product["product_sha256"]})
    context["adopted_prerequisites"] = adopted
    context["prompt"] = context.get("prompt", "") + "\nVALIDATED PREREQUISITE PRODUCTS\n" + json.dumps(adopted, sort_keys=True)
    return False


def verified_evidence(controller, run_id, task_id):
    with controller._repo.transaction() as cur:
        cur.execute("SELECT x.* FROM evidence_index x JOIN task_attempts a USING(attempt_id) WHERE x.run_id=%s AND x.task_id=%s AND a.status='verified' AND x.result='pass' ORDER BY x.evidence_id",
                    (run_id,task_id))
        rows = list(cur.fetchall())
    if not {"executor","auditor"} <= {r["producer"] for r in rows}:
        raise ValueError("verified execution and review evidence required")
    for row in rows:
        path = controller.artifact_root / row["artifact_path"]
        if any(p.is_symlink() for p in (path,*path.parents)) or not path.resolve().is_relative_to(controller.artifact_root.resolve()):
            raise ValueError("untrusted completion evidence")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=row["sha256"]:
            raise ValueError("completion evidence missing or changed")
    return [{"id":r["evidence_id"],"sha256":r["sha256"]} for r in rows]


def reconcile(controller, run_id):
    # Serialize pause writes and the evidence-check/finalization interval.
    with controller._goal_state_store.lock(run_id):
        return _reconcile_locked(controller,run_id)


def _reconcile_locked(controller, run_id):
    stored = graphs(controller, run_id)
    if not stored:
        return {"status":"untracked", "run_id":run_id}
    state = controller._repo.controller_state(run_id)
    with controller._repo.transaction() as cur:
        cur.execute("SELECT state FROM supervisor_runs WHERE run_id=%s", (run_id,))
        run_state = cur.fetchone()["state"]
    if not state["scheduling_enabled"] or run_state!="active" or controller._goal_state_store.is_paused(run_id):
        return {"status":"paused_or_stopped","run_id":run_id}
    epoch = controller._ensure_epoch(run_id)
    outcomes = []
    for graph in stored:
        spec = graph["spec"]
        # Pin to DB authority even when the filesystem is service-writable.
        from goal_dependencies import goal_spec_for_task
        observed = goal_spec_for_task(controller.artifact_root,run_id,spec["workstreams"][0]["task_id"])
        if observed != spec or digest_value(observed)!=graph["digest"]:
            raise ValueError("immutable graph differs from durable submission")
        states = controller._repo.list_parent_task_states(run_id)
        by_number = {n["number"]:n for n in spec["workstreams"]}
        for node in spec["workstreams"]:
            if node["task_id"] not in states and all(states.get(by_number[d]["task_id"])=="verified" for d in node["dependencies"]):
                controller.schedule_task(run_id,node["task_id"],node["title"],priority=len(by_number)-node["number"]+1)
        if not all(states.get(n["task_id"])=="verified" for n in spec["workstreams"]):
            continue
        evidence = {n["task_id"]:verified_evidence(controller,run_id,n["task_id"]) for n in spec["workstreams"]}
        with controller._repo.transaction() as cur:
            cur.execute("SELECT * FROM subworkflow_handoffs WHERE run_id=%s AND parent_task_id=ANY(%s)",
                        (run_id,[n["task_id"] for n in spec["workstreams"]]))
            handoffs = list(cur.fetchall())
        for handoff in handoffs:
            if handoff["state"]!="completed":
                raise ValueError("unresolved goal handoff")
            checked_product(controller,handoff)
        receipt = {"status":"complete", "run_id":run_id,"graph_id":graph["graph_id"],
                   "spec_digest":graph["digest"],"evidence":evidence,
                   "handoffs":{h["handoff_id"]:h["product_digest"] for h in handoffs}}
        with controller._repo.transaction() as cur:
            cur.execute("SELECT horizon_complete_graph(%s,%s,%s,%s,%s::jsonb) AS outcome",
                        (run_id,graph["graph_id"],graph["digest"],epoch,json.dumps(receipt)))
            outcomes.append(cur.fetchone()["outcome"])
    return status(controller,run_id)


def status(controller,run_id):
    stored = graphs(controller,run_id)
    if not stored:
        return {"run_id":run_id,"status":"untracked","exit_code":2}
    states = controller._repo.list_parent_task_states(run_id)
    control = controller._repo.controller_state(run_id)
    with controller._repo.transaction() as cur:
        cur.execute("SELECT state FROM supervisor_runs WHERE run_id=%s",(run_id,))
        run_state = cur.fetchone()["state"]
    disabled = not control["scheduling_enabled"] or run_state!="active" or controller._goal_state_store.is_paused(run_id)
    complete = all(g["outcome"] is not None for g in stored) and all(s=="verified" for s in states.values())
    # No registered root graph means bundle completion, not whole-parent completion.
    complete = complete and any(g["graph_id"]==run_id for g in stored)
    if complete:
        try:
            for graph in stored:
                from goal_dependencies import goal_spec_for_task
                spec=goal_spec_for_task(controller.artifact_root,run_id,graph["spec"]["workstreams"][0]["task_id"])
                if digest_value(spec)!=graph["digest"]:
                    raise ValueError("completion graph changed")
                for node in graph["spec"]["workstreams"]:
                    verified_evidence(controller,run_id,node["task_id"])
            with controller._repo.transaction() as cur:
                cur.execute("SELECT * FROM subworkflow_handoffs WHERE run_id=%s",(run_id,))
                handoffs=list(cur.fetchall())
            for handoff in handoffs:
                if handoff["state"]!="completed":
                    raise ValueError("unresolved handoff")
                checked_product(controller,handoff)
        except (ValueError,OSError):
            return {"run_id":run_id,"status":"blocked","reason":"completion_evidence_invalid","exit_code":78}
    label = "paused_or_stopped" if disabled else "complete" if complete else "blocked" if any(s in {"blocked","failed","parked"} for s in states.values()) else "incomplete"
    return {"run_id":run_id,"status":label,"exit_code":0 if label=="complete" else 78 if label in {"blocked","paused_or_stopped"} else 2,
            "graphs":[{"id":g["graph_id"],"complete":g["outcome"] is not None} for g in stored]}
