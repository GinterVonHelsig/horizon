"""Source-owned launcher executable path; all transports simulated."""
import importlib.util
import json
import hashlib
import sys
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("source_owned_host_review",ROOT/"tools/host_review/host_review.py")
launcher=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=launcher
spec.loader.exec_module(launcher)


def context(root,author="composer-2.5"):
    from model_routing import RoutingRecord
    def artifact(name,value):
        data=value if isinstance(value,bytes) else json.dumps(value).encode()
        (root/name).write_bytes(data)
        return {"path":name,"sha256":hashlib.sha256(data).hexdigest()}
    subject=artifact("subject.diff",b"reviewed patch")
    result=artifact("author-result.json",{"status":"success","exit_code":0,"provider":"cursor","model":author})
    route=RoutingRecord("3A","actual-author","cursor",author,"cursor-agent","subscription","default","none").to_dict()
    entry=artifact("author.json",{"run_id":"review-test","subject_sha256":subject["sha256"],"result":result,"route":route})
    return {"run_id":"review-test","subject":subject,"authors":[entry],"reviews":[],"max_calls":1,"fallback_calls":0,
            "on_demand_disabled_operator_confirmed":True,"available_routes":[{"provider":"cursor","model":"cursor-grok-4.6-high"}]}


def policy():
    from model_routing import load_model_routing
    p=load_model_routing(ROOT/"architecture/model-routing.yaml")
    p["phases"]["4"]={"provider":"cursor","model":"cursor-grok-4.6-high","effort":"high","fallbacks":[]}
    return p


@pytest.mark.parametrize("fault",[None,"collision","tamper","missing","failure"])
def test_real_launcher_selects_once_or_stops(tmp_path,fault):
    ctx=context(tmp_path,"cursor-grok-4.6-high" if fault=="collision" else "composer-2.5")
    if fault=="tamper": (tmp_path/"subject.diff").write_text("changed")
    if fault=="missing": ctx["available_routes"]=[]
    calls=[]
    def transport(provider,model,effort,max_tokens):
        calls.append((provider,model))
        return launcher.TransportResult(http_status=200,model_returned=model,
            content='{"verdict":"approve","findings":[],"suggestions":[]}',finish_reason="stop",completion_tokens=10,
            error="TimeoutError" if fault=="failure" else None)
    kwargs=dict(seat="4",routing=policy(),artifact_root=tmp_path,run_id="review-test",transport=transport,review_context=ctx)
    if fault in {"collision","tamper","missing"}:
        with pytest.raises(ValueError): launcher.run_seat(**kwargs)
        assert calls==[]
    else:
        result=launcher.run_seat(**kwargs)
        assert len(calls)==1
        assert result.verdict==("approve" if fault is None else None)
        assert len(list((tmp_path/"review-history").glob("*.json")))==(1 if fault is None else 0)
        with pytest.raises(FileExistsError): launcher.run_seat(**kwargs)
        assert len(calls)==1


def test_prior_identity_without_bound_passing_result_stops(tmp_path):
    ctx=context(tmp_path)
    ctx["reviews"]=ctx["authors"]
    with pytest.raises(ValueError,match="prior review"):
        launcher.run_seat(seat="1.6",routing=policy(),artifact_root=tmp_path,run_id="review-test",
                          transport=lambda *a:pytest.fail("no call allowed"),review_context=ctx)
