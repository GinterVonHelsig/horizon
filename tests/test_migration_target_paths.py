"""Inspect migration admission without importing/executing Alembic's environment."""
import ast
from pathlib import Path


def test_every_standalone_live_target_has_exact_full_chain_prefix():
    source=Path(__file__).resolve().parents[1]/'controller/migrations/env.py'
    tree=ast.parse(source.read_text())
    selected=[]
    for node in tree.body:
        if isinstance(node,ast.Assign):
            names={n.id for target in node.targets for n in ast.walk(target) if isinstance(n,ast.Name)}
            if names & {'_UPGRADE_SOURCE_PATHS','_live_chain'}: selected.append(node)
        elif isinstance(node,ast.For) and isinstance(node.target,ast.Name) and node.target.id=='_revision':
            selected.append(node)
    namespace={}
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(source),'exec'),namespace)
    paths=namespace['_UPGRADE_SOURCE_PATHS']
    live=paths['021_goal_completion']
    for revision in live:
        assert paths[revision]==live[:live.index(revision)+1]
    assert paths['017_parent_rollback_routine'][-2:]==('016_recover_exhausted_executor_contract_once','017_parent_rollback_routine')
    guard=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_guard_upgrade')
    admission=next(n for n in guard.body if isinstance(n,ast.If))
    assert ast.unparse(admission.test)=='target not in _UPGRADE_SOURCE_PATHS'
