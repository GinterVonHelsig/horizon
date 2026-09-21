"""An explicit disposable profile does not change September production routing."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from qualification_profile import PROFILE, worker_policy, admit_profile
from harness_adapters.registry import validate_registry_config
from model_routing import load_model_routing, authorize_task_review

ROOT = Path(__file__).resolve().parents[1]

def configuration():
    config = json.loads((ROOT/'systemd/adapters.gateway-delivery-disposable.json.example').read_text())
    author = {k:v for k,v in config['adapters'][0].items() if k not in {'delivery_spec','subscription_only','on_demand_disabled'}}
    author.update(id='cursor-parent-composer', kind='cursor_cli', cursor_mode='agent')
    config['adapters'].append(author)
    config['routes']['default_executor'] = author['id']
    config['qualification_profile'] = PROFILE
    return config

def test_profile_is_explicit_scoped_and_does_not_mutate_production():
    config = configuration()
    original = load_model_routing(ROOT/'architecture/model-routing.yaml')
    snapshot = deepcopy(original)
    policy = worker_policy(original, config, PROFILE, 'postgresql://test@127.0.0.1:5432/td_test_profile')
    assert original == snapshot and policy != original
    validate_registry_config(config, validate_executables=False)
    assert policy['phases']['4']['fallbacks'] == []
    assert policy['phases']['4']['provider'] == 'cursor'
    route=authorize_task_review(policy, ('cursor','composer-2.5'), ('cursor','cursor-grok-4.6-high'))
    assert route.provider == 'cursor' and route.model == 'cursor-grok-4.6-high'
    with pytest.raises(ValueError, match='independent reviewer'):
        authorize_task_review(policy, ('cursor','cursor-grok-4.6-high'), ('cursor','cursor-grok-4.6-high'))
    with pytest.raises(ValueError, match='explicit qualification'):
        admit_profile(config, None, 'postgresql://test@127.0.0.1:5432/td_test_profile')
    with pytest.raises(ValueError, match='disposable'):
        admit_profile(config, PROFILE, 'postgresql://test@127.0.0.1:5432/production')

@pytest.mark.parametrize('fault', ['provider','model','mode','same_author','credentials','unknown'])
def test_incompatible_profile_rejected(fault):
    config = configuration()
    reviewer = config['adapters'][1]
    if fault == 'provider': reviewer['provider'] = 'openrouter'
    if fault == 'model': reviewer['model'] = 'other-model'
    if fault == 'mode': reviewer['cursor_mode'] = 'agent'
    if fault == 'same_author': reviewer.update(model='composer-2.5', cursor_mode='agent')
    if fault == 'credentials': reviewer['credential_env'] = ['OPENROUTER_API_KEY']
    if fault == 'unknown': config['qualification_profile'] = 'production-override'
    with pytest.raises(ValueError): validate_registry_config(config, validate_executables=False)
