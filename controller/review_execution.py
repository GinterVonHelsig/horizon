"""Trusted source/author/result bindings for executable external review selection."""
import hashlib
import json
import os
from pathlib import Path
from dataclasses import replace
from model_routing import REVIEW_PHASES, RoutingRecord, resolve_phase_route


def _artifact(root, ref):
    path = root / ref["path"]
    if any(p.is_symlink() for p in (path,*path.parents)) or not path.resolve().is_relative_to(root):
        raise ValueError("review history path escapes trusted root")
    stat=path.stat()
    if stat.st_uid!=os.geteuid() or stat.st_mode & 0o022:
        raise ValueError("review history must be owned and non-writable by other principals")
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=ref["sha256"]:
        raise ValueError("review history digest mismatch")
    return data


def select_review(routing,seat,context,root,run_id):
    if seat not in REVIEW_PHASES:
        raise ValueError('external reviewer requires an independent review seat')
    root=Path(root).resolve()
    if context.get("run_id")!=run_id or context.get("max_calls")!=1 or context.get("fallback_calls")!=0:
        raise ValueError("one-call bound review context required")
    subject=_artifact(root,context["subject"])
    digest=hashlib.sha256(subject).hexdigest()
    authors=[]
    reviews=[]
    for kind,records in (("authors",authors),("reviews",reviews)):
        for ref in context.get(kind,[]):
            entry=json.loads(_artifact(root,ref))
            if entry.get("run_id")!=run_id or entry.get("subject_sha256")!=digest:
                raise ValueError("history not bound to reviewed run and source")
            result=json.loads(_artifact(root,entry["result"]))
            if result.get("status")!="success" or result.get("exit_code")!=0 or result.get("error_classification"):
                raise ValueError("history lacks successful execution result")
            record=RoutingRecord(**entry["route"])
            from harness_adapters.identity import canonical_model
            actual_model=str(result.get("model","")).lower().replace(" ","-")
            if result.get("provider")!=record.provider or canonical_model(actual_model)!=canonical_model(record.model):
                raise ValueError("actual history identity mismatch")
            if kind=="reviews":
                verdict=(result.get("structured_payload") or {}).get("verdict")
                allowed={"approve":"pass","approve-with-minors":"pass_with_minors","pass":"pass","pass_with_minors":"pass_with_minors"}
                if verdict not in allowed:
                    raise ValueError("prior review did not pass")
                record=replace(record,verdict=allowed[verdict])
            else:
                record=replace(record,verdict=None)
            records.append(record)
    inventory=context.get("available_routes",[])
    if any(r.get("provider")!="cursor" for r in inventory):
        raise ValueError("external subscription profile permits explicit Cursor routes only")
    if context.get("on_demand_disabled_operator_confirmed") is not True:
        raise ValueError("included-subscription account confirmation required")
    return resolve_phase_route(routing,seat,author_routes=tuple(authors),prior_review_routes=tuple(reviews),
        available_routes=frozenset((r["provider"],r["model"]) for r in inventory))
