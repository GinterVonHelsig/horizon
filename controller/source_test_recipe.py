"""Versioned safe source/test recipe: a bounded integer Python function.

No eval/exec/import/subprocess: tests interpret the explicitly supported Python
AST subset. This is not a general Python test runner or arbitrary repository repair.
"""
import ast
import operator
import re

PROFILE="gateway-delivery-source-test.v1"
RECIPE="python-integer-function.v1"


def validate_spec(spec):
    keys={"profile","prerequisite_id","filename","recipe","function","argument","cases"}
    if not isinstance(spec,dict) or set(spec)!=keys or spec["profile"]!=PROFILE or spec["recipe"]!=RECIPE:
        raise ValueError("unsupported bounded source/test specification")
    for key in ("prerequisite_id","function","argument"):
        if not isinstance(spec[key],str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,40}",spec[key]):
            raise ValueError("invalid source/test identifier")
    if spec["filename"]!="solution.py":
        raise ValueError("source recipe permits solution.py only")
    cases=spec["cases"]
    if not isinstance(cases,list) or not 1<=len(cases)<=32:
        raise ValueError("bounded test cases required")
    for case in cases:
        if not isinstance(case,dict) or set(case)!={"input","expected"} or any(type(v)!=int or abs(v)>1000000 for v in case.values()):
            raise ValueError("bounded integer test cases required")
    return spec


def test_source(source,spec):
    validate_spec(spec)
    if len(source.encode())>4096:
        raise ValueError("source recipe size exceeded")
    tree=ast.parse(source)
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):
        raise ValueError("one function only")
    fn=tree.body[0]
    args=fn.args
    if (fn.name!=spec["function"] or fn.decorator_list or fn.returns or len(fn.body)!=1
        or not isinstance(fn.body[0],ast.Return) or len(args.args)!=1 or args.args[0].arg!=spec["argument"]
        or args.args[0].annotation or args.posonlyargs or args.kwonlyargs or args.defaults or args.kw_defaults or args.vararg or args.kwarg
        or getattr(fn,"type_params",[])):
        raise ValueError("unsupported function signature or statements")
    operators={ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul}
    def evaluate(node,value,depth=0):
        if depth>16: raise ValueError("expression depth exceeded")
        if isinstance(node,ast.Name) and node.id==spec["argument"]: result=value
        elif isinstance(node,ast.Constant) and type(node.value)==int: result=node.value
        elif isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.USub): result=-evaluate(node.operand,value,depth+1)
        elif isinstance(node,ast.BinOp) and type(node.op) in operators:
            result=operators[type(node.op)](evaluate(node.left,value,depth+1),evaluate(node.right,value,depth+1))
        else: raise ValueError("unsupported source expression")
        if abs(result)>1000000000000: raise ValueError("integer bound exceeded")
        return result
    results=[]
    for case in spec["cases"]:
        observed=evaluate(fn.body[0].value,case["input"])
        results.append({**case,"observed":observed,"passed":observed==case["expected"]})
    if not all(r["passed"] for r in results):
        raise ValueError("source recipe tests failed")
    return {"recipe":RECIPE,"cases":results,"passed":True,"general_test_suite_run":False}
