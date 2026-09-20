"""Credential-silent, read-only probes of the protected Comms-01 database target."""
from __future__ import annotations

import hashlib
import json
import socket
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

ANCHOR_PATH = Path("/opt/operator-harness/artifacts/20260912T-p43-horizon-p40-activation-closure-NOT_AUTHORIZED/database-anchor.json")
ANCHOR_SHA256 = "698ac9f774cedc15206e398065a756bc8994bf7d4ac4d0886648e5145e352b6c"
TARGET_PATH = Path("/etc/top-delivery/comms01-workflow-db-target.json")
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
PARENT = "goal-3eb7b972ec15809e"
IDENTITY_SQL = """json_build_object('database',current_database(),'role',current_user,
 'port',current_setting('port')::int,'address',inet_server_addr(),
 'system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
 'data_directory',current_setting('data_directory'),'in_recovery',pg_is_in_recovery())"""
QUEUE_SQL = f"""BEGIN READ ONLY; SET LOCAL search_path=pg_catalog;
SELECT json_build_object('identity',{IDENTITY_SQL},'database',current_database(),
 'postmaster_started',pg_postmaster_start_time()::text,
 'database_oid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'head',(SELECT task_id FROM public.parent_tasks WHERE run_id='{PARENT}' AND state='queued'
   AND available_at<=clock_timestamp() ORDER BY priority DESC,available_at,task_id LIMIT 1),
 'active',(SELECT count(*) FROM public.task_attempts WHERE run_id='{PARENT}' AND status='running'),
 'lease',(SELECT json_build_object('run_id',run_id,'owner',owner,'current_epoch',current_epoch,
   'lease_expires_at',lease_expires_at) FROM public.controller_control WHERE run_id='{PARENT}'),
 'supervisor_tick',(SELECT json_build_object('event_id',event_id,'event_seq',event_seq,
   'controller_epoch',controller_epoch,'occurred_at',occurred_at,
   'age_seconds',extract(epoch from clock_timestamp()-occurred_at),'detail',detail_json::json)
   FROM public.supervisor_events WHERE run_id='{PARENT}' AND event_type='supervisor_tick_completed'
   ORDER BY event_seq DESC LIMIT 1),
 'lease_live',(SELECT scheduling_enabled AND lease_expires_at>clock_timestamp()
   FROM public.controller_control WHERE run_id='{PARENT}')); COMMIT;"""


def approved_target() -> tuple[dict, dict]:
    from recovery_service_anchor import _root_file
    raw = _root_file(ANCHOR_PATH)
    if hashlib.sha256(raw).hexdigest() != ANCHOR_SHA256:
        raise ValueError("database identity anchor differs")
    anchor = json.loads(raw)
    raw_target = _root_file(TARGET_PATH)
    if hashlib.sha256(raw_target).hexdigest() != anchor["target_sha256"] or socket.gethostname() != anchor["host"]:
        raise ValueError("protected database target/host differs")
    target = json.loads(raw_target)
    if any(target.get(key) != value for key, value in anchor["application_target"].items()):
        raise ValueError("database target fields differ")
    url = urlsplit(target["database_url"])
    if (url.scheme != "postgresql" or url.hostname != target["database_endpoint"]
            or url.port != target["database_port"] or unquote(url.username or "") != target["database_role"]
            or unquote(url.path[1:]) != target["database_name"] or url.query or url.fragment):
        raise ValueError("protected database URL and approved target disagree")
    return anchor, target


def _query(argv: list[str], *, payload: str | None = None) -> dict:
    # No inherited PGPORT/PGSERVICE/PGOPTIONS/PGPASSFILE, no psqlrc, no password
    # in argv or error output. All connection parameters are explicit.
    result = subprocess.run(argv, input=payload, capture_output=True, text=True,
                            env=CLEAN_ENV, cwd="/", timeout=30)
    if result.returncode:
        raise ValueError("read-only database identity/queue probe failed")
    return json.loads(result.stdout)


def read_queue() -> dict:
    anchor, target = approved_target()
    observer = anchor["observer"]
    result = _query(["/usr/sbin/runuser", "-u", observer["role"], "--", "/usr/bin/psql",
        "-X", "-w", "-qAt", "-h", observer["socket"], "-p", str(observer["port"]),
        "-U", observer["role"], "-d", observer["database"], "-v", "ON_ERROR_STOP=1", "-c", QUEUE_SQL])
    if result.get("identity") != anchor["identity"]:
        raise ValueError("observed PostgreSQL server/database identity differs")
    # Link the protected application's TCP endpoint to the same observed server,
    # without granting it pg_control_system or exposing its credential. Existing
    # workflow role performs SELECT only; subprocess gets secret via stdin only.
    code = """import json,sys,psycopg2
from urllib.parse import urlsplit,unquote
t=json.load(sys.stdin);u=urlsplit(t['database_url'])
c=psycopg2.connect(host=t['database_endpoint'],port=t['database_port'],
 dbname=t['database_name'],user=t['database_role'],password=unquote(u.password or ''),
 connect_timeout=10,options='-c search_path=pg_catalog -c default_transaction_read_only=on')
try:
 with c.cursor() as q:
  q.execute("SELECT json_build_object('database',current_database(),'role',current_user,'address',inet_server_addr(),'port',inet_server_port(),'postmaster_started',pg_postmaster_start_time()::text,'database_oid',(SELECT oid::text FROM pg_database WHERE datname=current_database()))")
  print(json.dumps(q.fetchone()[0]))
finally:
 c.rollback();c.close()
"""
    app = _query(["/usr/bin/python3", "-I", "-B", "-c", code], payload=json.dumps(target))
    expected_app = {"database": target["database_name"], "role": target["database_role"],
        "address": target["database_endpoint"], "port": target["database_port"],
        "postmaster_started": result["postmaster_started"], "database_oid": result["database_oid"]}
    if app != expected_app:
        raise ValueError("application endpoint does not match the pinned observed PostgreSQL server")
    result["application_endpoint_verified"] = True
    return result
