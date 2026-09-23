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


@pytest.mark.parametrize("verdict",["changes-required","fail"])
def test_rejected_bound_prior_review_cannot_authorize_next_seat(tmp_path,verdict):
    ctx=context(tmp_path)
    entry=json.loads((tmp_path/"author.json").read_text())
    result=json.loads((tmp_path/"author-result.json").read_text())
    result["structured_payload"]={"verdict":verdict}
    data=json.dumps(result).encode()
    (tmp_path/"review-result.json").write_bytes(data)
    entry["result"]={"path":"review-result.json","sha256":hashlib.sha256(data).hexdigest()}
    data=json.dumps(entry).encode()
    (tmp_path/"prior-review.json").write_bytes(data)
    ctx["reviews"]=[{"path":"prior-review.json","sha256":hashlib.sha256(data).hexdigest()}]
    with pytest.raises(ValueError,match="prior review did not pass"):
        launcher.run_seat(seat="1.6",routing=policy(),artifact_root=tmp_path,run_id="review-test",
            transport=lambda *a:pytest.fail("no call allowed"),review_context=ctx)


@pytest.mark.parametrize("actual",["Cursor Grok 4.6 High","grok-4.6","Composer 2.5"])
def test_stream_identity_preserved_in_result_and_history(tmp_path,monkeypatch,actual):
    from types import SimpleNamespace
    calls=[]
    def run(cmd,**kwargs):
        calls.append(cmd)
        events=[{"type":"system","subtype":"init","model":actual,"session_id":"simulated-only"},
                {"type":"result","subtype":"success","is_error":False,"result":'{"verdict":"approve","findings":[],"suggestions":[]}'}]
        return SimpleNamespace(returncode=0,stdout="\n".join(map(json.dumps,events)),stderr="")
    monkeypatch.setattr(launcher.subprocess,"run",run)
    transport=launcher.composite_transport("read only","reviewed patch")
    result=launcher.run_seat(seat="4",routing=policy(),artifact_root=tmp_path,run_id="review-test",
        transport=transport,review_context=context(tmp_path))
    assert len(calls)==1
    assert "--mode" in calls[0] and "ask" in calls[0] and "--sandbox" in calls[0]
    if actual=="Composer 2.5":
        assert result.verdict is None
        assert not list((tmp_path/"review-history").glob("*.json"))
    else:
        assert result.model==actual
        saved=json.loads(next((tmp_path/"review-results").glob("*.json")).read_text())
        history=json.loads(next((tmp_path/"review-history").glob("*.json")).read_text())
        assert saved["model"]==actual
        assert history["route"]["model"]==actual.lower().replace(" ","-")


def test_no_non_cursor_transport_or_smoke_bypass(tmp_path,monkeypatch):
    assert not hasattr(launcher,"_load_key")
    assert not hasattr(launcher,"live_transport")
    assert not hasattr(launcher,"openai_transport")
    assert not hasattr(launcher,"smoke_model")
    monkeypatch.setattr(launcher.subprocess,"run",lambda *a,**k:pytest.fail("no subprocess"))
    with pytest.raises(launcher.ReviewPolicyError):
        launcher.composite_transport("review","patch")("openrouter","x-ai/grok-4.6","high",10)
    with pytest.raises(launcher.ReviewPolicyError,match="smoke execution is disabled"):
        launcher.main(["--artifact-root",str(tmp_path),"--smoke-model","cursor-grok-4.6-high"])


@pytest.mark.parametrize("tamper",[False,True])
def test_cli_review_packet_is_the_bound_subject(tmp_path,monkeypatch,tamper):
    import yaml
    from types import SimpleNamespace
    ctx=context(tmp_path)
    (tmp_path/"context.json").write_text(json.dumps(ctx))
    (tmp_path/"routing.yaml").write_text(yaml.safe_dump(policy()))
    (tmp_path/"system.md").write_text("Review read-only.")
    (tmp_path/"packet.md").write_text("different patch" if tamper else "reviewed patch")
    calls=[]
    def run(cmd,**kwargs):
        calls.append(cmd)
        assert "reviewed patch" in cmd[-1]
        events=[{"type":"system","subtype":"init","model":"Cursor Grok 4.6 High"},
                {"type":"result","subtype":"success","is_error":False,"result":'{"verdict":"approve","findings":[],"suggestions":[]}'}]
        return SimpleNamespace(returncode=0,stdout="\n".join(map(json.dumps,events)),stderr="")
    monkeypatch.setattr(launcher.subprocess,"run",run)
    args=["--seat","4","--run-id","review-test","--artifact-root",str(tmp_path),
          "--review-context",str(tmp_path/"context.json"),"--routing-yaml",str(tmp_path/"routing.yaml"),
          "--system-file",str(tmp_path/"system.md"),"--user-file",str(tmp_path/"packet.md")]
    if tamper:
        with pytest.raises(launcher.ReviewPolicyError,match="packet differs"):
            launcher.main(args)
        assert calls==[]
    else:
        assert launcher.main(args)==0
        assert len(calls)==1
