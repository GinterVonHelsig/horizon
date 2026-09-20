"""Out-of-tree source acceptance for this operator-authorized P46 activation.

Root is the trusted publisher. This is a fixed protected receipt, not a caller
boolean, mutable Git ref, self-referential tree hash, or new signing service.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
from pathlib import Path

ACCEPTANCE_PATH = Path("/opt/operator-harness/artifacts/20260913T-p46-horizon-runtime-minor-closure-and-existing-task-activation-NOT_AUTHORIZED/accepted-source.json")
PROMPT_SHA256 = "6ab839242433a5ddd56c1ec9da463c298bba6fbb77961e97384b028c05d59e66"
PARENT = "goal-3eb7b972ec15809e"
PASS = {"pass", "pass_with_minors", "approve", "approve-with-minors"}


def accepted_source() -> dict:
    from recovery_service_anchor import _root_file
    receipt = json.loads(_root_file(ACCEPTANCE_PATH))
    if (receipt.get("schema") != "p46-source-acceptance-v1" or receipt.get("approved") is not True
            or receipt.get("host") != "comms-01" or socket.gethostname() != receipt["host"]
            or receipt.get("parent") != PARENT or receipt.get("prompt_sha256") != PROMPT_SHA256):
        raise ValueError("source acceptance is not bound to this host/parent/authority")
    for key in ("candidate_sha", "tree"):
        if not isinstance(receipt.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}", receipt[key]):
            raise ValueError("source acceptance requires exact candidate/tree")
    reviews = receipt.get("reviews", [])
    if [item.get("seat") for item in reviews] != ["1.5", "1.6"]:
        raise ValueError("source acceptance requires two ordered independent seats")
    models = []
    captured = {}
    for artifact in [receipt["packet"], receipt.get("ci", {}), receipt.get("ci_log", {}), *reviews]:
        if not isinstance(artifact.get("path"), str) or not artifact.get("sha256"):
            raise ValueError("source acceptance requires complete packet/review/CI artifacts")
        data = _root_file(Path(artifact["path"]))
        if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            raise ValueError("accepted packet/review digest differs")
        captured[artifact["path"]] = data
        if "seat" in artifact:
            review = json.loads(data)
            if review.get("status") != "ok" or review.get("verdict") not in PASS:
                raise ValueError("acceptance receipt references a non-passing review")
            models.append(review.get("model"))
    if not all(models) or len(set(models)) != 2:
        raise ValueError("source acceptance requires independent reviewer identities")
    ci = json.loads(captured[receipt["ci"]["path"]])
    log = captured[receipt['ci_log']['path']].decode()
    tested_sha = re.findall(r'^.*\t[^\t\n]*\t\S+ P44_TESTED_SHA=([0-9a-f]{40})\r?$', log, re.MULTILINE)
    tested_tree = re.findall(r'^.*\t[^\t\n]*\t\S+ P44_TESTED_TREE=([0-9a-f]{40})\r?$', log, re.MULTILINE)
    if (tested_sha != [receipt['candidate_sha']] or tested_tree != [receipt['tree']]
            or ci.get('tested_sha') != receipt['candidate_sha'] or ci.get('tested_tree') != receipt['tree']):
        raise ValueError('CI did not execute the exact reviewed candidate SHA/tree')
    run, jobs = ci.get("run", {}), ci.get("jobs", [])
    if (run.get("repository") != "GinterVonHelsig/TOP-DELIVERY"
            or run.get("head_sha") != receipt["candidate_sha"]
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("path") != ".github/workflows/ci.yml"
            or len(jobs) != 1 or jobs[0].get("name") != "focused-unit"
            or jobs[0].get("status") != "completed" or jobs[0].get("conclusion") != "success"
            or jobs[0].get("head_sha") != receipt["candidate_sha"]):
        raise ValueError("source acceptance lacks passing exact-head GitHub CI")
    return receipt
