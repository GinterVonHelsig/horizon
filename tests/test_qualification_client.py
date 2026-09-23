"""No transport calls: qualification client keeps Cursor semantics explicit."""
import importlib.util
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('qualification_client',Path(__file__).resolve().parents[1]/'tools/qualification/client.py')
client=importlib.util.module_from_spec(spec); spec.loader.exec_module(client)


def test_both_cursor_protocols_preserve_model_and_mode():
    request=client.request(['-p','task','--output-format','stream-json','--model','composer-2.5','--force','--sandbox','enabled','--trust'],'/unused')
    assert request['model']=='composer-2.5' and request['prompt']=='task'
    request=client.request(['agent','--mode','ask','--model','cursor-grok-4.6-high','-p','--output-format','stream-json','--sandbox','enabled','review packet'],'/explicit/standalone')
    assert request=={'model':'cursor-grok-4.6-high','prompt':'review packet','cwd':'/explicit/standalone'}


@pytest.mark.parametrize('extra',[
    ['--model','openrouter/x-ai/grok-4.6','--mode','ask'],
    ['--model','cursor-grok-4.6-high','--mode','agent'],
    ['--model','cursor-grok-4.6-high','--mode','ask','--force'],
    ['--model','cursor-grok-4.6-high','--mode','ask','--resume','old-session'],
    ['--model','composer-2.5','--force','--worktree','/production'],
])
def test_incompatible_invocation_never_reaches_socket(monkeypatch,extra):
    def forbidden(*a,**k): raise AssertionError('transport reached')
    monkeypatch.setattr(client.socket,'socket',forbidden)
    assert client.main('/unused','/unused',['-p','task','--output-format','stream-json','--sandbox','enabled',*extra])==78
