"""Immutable goal graphs, prerequisite adoption and fenced completion.

Revision ID: 021_goal_completion
Revises: 020_horizon_prereq_corr_live
"""
from alembic import op
from authority_pins import WORKFLOW_DATABASE_ROLE, MIGRATION_SOURCE_PROVENANCE_PATH
from migration_source_anchor import verify_migration_source_anchor

revision = "021_goal_completion"
down_revision = "020_horizon_prereq_corr_live"
branch_labels = None
depends_on = None


def upgrade():
    name = str(op.get_bind().exec_driver_sql("SELECT current_database()").scalar_one())
    if not (name.startswith("td_test_") or name == "top_delivery_control_p1"):
        raise RuntimeError("goal completion migration requires approved database target")
    verify_migration_source_anchor(revision, source_path=__file__, anchor_path=MIGRATION_SOURCE_PROVENANCE_PATH)
    op.execute("SET LOCAL ROLE top_delivery_migration")
    op.execute(f"""
    CREATE TABLE horizon_goal_graphs (
        run_id TEXT NOT NULL REFERENCES supervisor_runs(run_id),
        graph_id TEXT NOT NULL,
        spec JSONB NOT NULL,
        digest TEXT NOT NULL,
        outcome JSONB,
        PRIMARY KEY(run_id,graph_id)
    );
    CREATE TABLE horizon_prerequisite_adoptions (
        run_id TEXT NOT NULL,
        task_id TEXT NOT NULL REFERENCES parent_tasks(task_id),
        prerequisite_id TEXT NOT NULL,
        handoff_id TEXT NOT NULL REFERENCES subworkflow_handoffs(handoff_id),
        product_digest TEXT NOT NULL,
        PRIMARY KEY(run_id,task_id,prerequisite_id)
    );
    REVOKE ALL ON horizon_goal_graphs,horizon_prerequisite_adoptions FROM PUBLIC;
    GRANT SELECT ON horizon_goal_graphs,horizon_prerequisite_adoptions TO {WORKFLOW_DATABASE_ROLE};

    CREATE FUNCTION horizon_bind_graph(r TEXT,g TEXT,s JSONB,d TEXT) RETURNS VOID
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE old horizon_goal_graphs%ROWTYPE;
    BEGIN
      IF session_user <> '{WORKFLOW_DATABASE_ROLE}' THEN RAISE EXCEPTION 'workflow principal required'; END IF;
      PERFORM 1 FROM controller_control WHERE run_id=r FOR UPDATE;
      IF NOT FOUND THEN RAISE EXCEPTION 'unknown run'; END IF;
      SELECT * INTO old FROM horizon_goal_graphs WHERE run_id=r AND graph_id=g;
      IF FOUND THEN
        IF old.spec <> s OR old.digest <> d THEN RAISE EXCEPTION 'immutable graph conflict'; END IF;
        RETURN;
      END IF;
      IF NOT EXISTS(SELECT 1 FROM supervisor_runs sr JOIN controller_control cc USING(run_id)
          WHERE sr.run_id=r AND sr.state='active' AND cc.scheduling_enabled) THEN
        RAISE EXCEPTION 'disabled run cannot accept new graph';
      END IF;
      IF jsonb_typeof(s->'workstreams') <> 'array' OR jsonb_array_length(s->'workstreams')=0
          OR s->>'run_id' <> g OR d !~ '^[a-f0-9]{{64}}$' THEN RAISE EXCEPTION 'invalid graph'; END IF;
      INSERT INTO horizon_goal_graphs VALUES(r,g,s,d,NULL);
    END $$;

    CREATE FUNCTION horizon_adopt_prerequisite(r TEXT,t TEXT,p TEXT,h TEXT,d TEXT,e BIGINT)
    RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE c controller_control%ROWTYPE; old horizon_prerequisite_adoptions%ROWTYPE;
    BEGIN
      IF session_user <> '{WORKFLOW_DATABASE_ROLE}' THEN RAISE EXCEPTION 'workflow principal required'; END IF;
      SELECT * INTO c FROM controller_control WHERE run_id=r FOR UPDATE;
      IF NOT FOUND OR c.current_epoch<>e OR NOT c.scheduling_enabled OR c.lease_expires_at<=clock_timestamp()
        OR NOT EXISTS(SELECT 1 FROM supervisor_runs WHERE run_id=r AND state='active')
        THEN RAISE EXCEPTION 'inactive or stale controller'; END IF;
      IF NOT EXISTS(SELECT 1 FROM subworkflow_handoffs WHERE handoff_id=h AND run_id=r
        AND parent_task_id=t AND state='completed' AND product_digest=d
        AND request_json->'handoff_context'->>'prerequisite_node_id'=p)
        THEN RAISE EXCEPTION 'unresolved prerequisite'; END IF;
      SELECT * INTO old FROM horizon_prerequisite_adoptions WHERE run_id=r AND task_id=t AND prerequisite_id=p;
      IF FOUND AND (old.handoff_id<>h OR old.product_digest<>d) THEN RAISE EXCEPTION 'adoption conflict'; END IF;
      INSERT INTO horizon_prerequisite_adoptions VALUES(r,t,p,h,d) ON CONFLICT DO NOTHING;
    END $$;

    CREATE FUNCTION horizon_complete_graph(r TEXT,g TEXT,d TEXT,e BIGINT,receipt JSONB)
    RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE c controller_control%ROWTYPE; graph horizon_goal_graphs%ROWTYPE; node JSONB;
    BEGIN
      IF session_user <> '{WORKFLOW_DATABASE_ROLE}' THEN RAISE EXCEPTION 'workflow principal required'; END IF;
      SELECT * INTO c FROM controller_control WHERE run_id=r FOR UPDATE;
      IF NOT FOUND OR c.current_epoch<>e THEN RAISE EXCEPTION 'stale controller'; END IF;
      SELECT * INTO graph FROM horizon_goal_graphs WHERE run_id=r AND graph_id=g FOR UPDATE;
      IF NOT FOUND OR graph.digest<>d THEN RAISE EXCEPTION 'unknown or changed graph'; END IF;
      IF graph.outcome IS NOT NULL THEN RETURN graph.outcome; END IF;
      IF NOT c.scheduling_enabled OR c.lease_expires_at<=clock_timestamp()
        OR NOT EXISTS(SELECT 1 FROM supervisor_runs WHERE run_id=r AND state='active')
        THEN RAISE EXCEPTION 'inactive controller'; END IF;
      FOR node IN SELECT value FROM jsonb_array_elements(graph.spec->'workstreams') LOOP
        IF NOT EXISTS(SELECT 1 FROM parent_tasks WHERE run_id=r AND task_id=node->>'task_id'
          AND state='verified') THEN RAISE EXCEPTION 'unverified graph node'; END IF;
        IF EXISTS(SELECT 1 FROM task_attempts WHERE run_id=r AND task_id=node->>'task_id' AND status='running')
          THEN RAISE EXCEPTION 'active graph attempt'; END IF;
        IF EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(node->'prerequisites','[]'::jsonb)) p
          WHERE NOT EXISTS(SELECT 1 FROM horizon_prerequisite_adoptions a JOIN subworkflow_handoffs h USING(handoff_id)
            WHERE a.run_id=r AND a.task_id=node->>'task_id' AND a.prerequisite_id=p->>'prerequisite_id'
            AND h.state='completed' AND h.product_digest=a.product_digest))
          THEN RAISE EXCEPTION 'unadopted prerequisite'; END IF;
        IF NOT EXISTS(SELECT 1 FROM evidence_index x JOIN task_attempts a USING(attempt_id)
          WHERE x.run_id=r AND x.task_id=node->>'task_id' AND a.status='verified' AND x.result='pass'
          AND x.producer='auditor') THEN RAISE EXCEPTION 'missing verified audit evidence'; END IF;
        IF NOT EXISTS(SELECT 1 FROM evidence_index x JOIN task_attempts a USING(attempt_id)
          WHERE x.run_id=r AND x.task_id=node->>'task_id' AND a.status='verified' AND x.result='pass'
          AND x.producer='executor') THEN RAISE EXCEPTION 'missing verified executor evidence'; END IF;
      END LOOP;
      IF EXISTS(SELECT 1 FROM subworkflow_handoffs h WHERE h.run_id=r AND h.state<>'completed'
        AND h.parent_task_id IN (SELECT value->>'task_id' FROM jsonb_array_elements(graph.spec->'workstreams')))
        THEN RAISE EXCEPTION 'unresolved handoff'; END IF;
      UPDATE horizon_goal_graphs SET outcome=receipt WHERE run_id=r AND graph_id=g;
      RETURN receipt;
    END $$;
    REVOKE ALL ON FUNCTION horizon_bind_graph(TEXT,TEXT,JSONB,TEXT),
      horizon_adopt_prerequisite(TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT),
      horizon_complete_graph(TEXT,TEXT,TEXT,BIGINT,JSONB) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION horizon_bind_graph(TEXT,TEXT,JSONB,TEXT),
      horizon_adopt_prerequisite(TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT),
      horizon_complete_graph(TEXT,TEXT,TEXT,BIGINT,JSONB) TO {WORKFLOW_DATABASE_ROLE};
    """)


def downgrade():
    raise RuntimeError("retain graph/adoption audit state; downgrade requires a separately reviewed preservation procedure")
