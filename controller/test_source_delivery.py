"""Real bounded recipe/provider/handoff; SIMULATED author and review calls."""
import hashlib
import json
from pathlib import Path
import pytest
from parent_controller import ParentController
from bounded_delivery import BoundedDeliveryAdapter
from harness_adapters.contract import HarnessResult
from subworkflow_handoff import digest_value,validate_product
from worker import TaskWorker
from test_bounded_delivery import configuration,SimulatedCursor
import source_test_recipe

SPEC={"profile":source_test_recipe.PROFILE,"prerequisite_id":"increment","filename":"solution.py",
      "recipe":source_test_recipe.RECIPE,"function":"increment","argument":"x",
      "cases":[{"input":0,"expected":1},{"input":7,"expected":8},{"input":-2,"expected":-1}]}


@pytest.mark.parametrize("source,passes",[("def increment(x):\n    return x + 1\n",True),
    ("def increment(x):\n    return x + 2\n",False),
    ("import os\ndef increment(x):\n    return x + 1\n",False),
    ("def increment(x):\n    return __import__('os').system('false')\n",False)])
def test_recipe(source,passes):
    if passes: assert source_test_recipe.test_source(source,SPEC)["passed"]
    else:
        with pytest.raises(ValueError): source_test_recipe.test_source(source,SPEC)


@pytest.mark.parametrize("wrong,reject",[(False,False),(True,False),(False,True)])
def test_source_delivery_contract(db_url,artifact_root,monkeypatch,wrong,reject):
    monkeypatch.setattr("worker.preflight_adapters",lambda *a,**k:None)
    config=configuration()
    config["adapters"][0]["id"]="gateway-delivery-source-test"
    config["adapters"][0]["delivery_spec"]=SPEC
    config["routes"]["default_executor"]="gateway-delivery-source-test"
    parent=ParentController(db_url,artifact_root=artifact_root,adapter_config=config)
    try:
        parent.register_run("source-test")
        parent.schedule_task("source-test","parent","bounded source recipe")
        task=parent.claim_next("source-test","gate")
        attempt,fence=parent.resolve_parent_attempt(task.task_id,task.generation)
        handoff=parent.create_subworkflow_handoff(run_id=task.run_id,parent_task_id=task.task_id,
            parent_attempt_id=attempt,parent_fence_token=fence,failure_code="BLOCKED_HORIZON_PREREQ_MISSING",
            handoff_context={"delivery_profile":SPEC["profile"],"delivery_spec_digest":digest_value(SPEC),"prerequisite_node_id":SPEC["prerequisite_id"]})
        class Writer:
            provider="cursor"
            model="composer-2.5"
            adapter_id="gateway-delivery-source-test"
            def cancel(self): pass
            def execute(self,request):
                Path(request.cwd,"solution.py").write_text("def increment(x):\n    return x + "+("2" if wrong else "1")+"\n")
                root=Path(request.artifact_dir)
                root.mkdir(parents=True,exist_ok=True)
                data=b'{"disposition":"IMPLEMENTED"}'
                (root/"stdout.txt").write_bytes(data)
                return HarnessResult(self.adapter_id,"cursor_cli",self.model,self.provider,"success",0,.01,
                    "stdout.txt",hashlib.sha256(data).hexdigest(),None,None,json.loads(data),None,False)
        executor=BoundedDeliveryAdapter(Writer(),SPEC)
        auditor=SimulatedCursor("cursor-independent-review","cursor-grok-4.6-high",SPEC,review=True,reject=reject)
        worker=TaskWorker(parent,artifact_root,{executor.adapter_id:executor,auditor.adapter_id:auditor},adapter_config=config)
        worker._preflight_adapters=lambda:None
        result=worker.run_once(task.run_id,"worker")
        if wrong or reject:
            assert result.terminal_state.startswith("blocked")
            assert not list(artifact_root.rglob("handoff-product.json"))
        else:
            assert result.terminal_state=="handoff_completed"
            product=next(artifact_root.rglob("handoff-product.json"))
            request=json.loads((artifact_root/handoff["request_path"]).read_text())
            assert validate_product(product,request,artifact_root)["disposition"]=="PASS_BOUNDED_SOURCE_TEST_VERIFIED"
            report=json.loads((product.parent/"acceptance.json").read_text())
            assert report["recipe_result"]["passed"] and len(report["recipe_result"]["cases"])==3
            assert not report["exact_content_verified"]
    finally: parent.close()
