"""Explicit disposable Cursor profile; never modifies the September production policy."""
from copy import deepcopy
from urllib.parse import urlsplit

PROFILE = 'cursor-disposable-v1'


def validate_profile(config):
    selected = config.get('qualification_profile')
    if selected is None:
        return
    if selected != PROFILE:
        raise ValueError('unknown qualification profile')
    for adapter in config['adapters']:
        model = adapter.get('model')
        if adapter.get('provider') != 'cursor' or adapter.get('credential_env') != []:
            raise ValueError('qualification permits explicit Cursor subscription routes only')
        if adapter.get('kind') not in {'cursor_cli', 'gateway_delivery'}:
            raise ValueError('unsupported qualification transport')
        if model not in {'composer-2.5', 'cursor-grok-4.6-high'}:
            raise ValueError('unsupported qualification model')
        if model == 'cursor-grok-4.6-high' and (adapter['kind'] != 'cursor_cli' or adapter.get('cursor_mode') != 'ask'):
            raise ValueError('qualification reviewer must be read-only')
        if model == 'composer-2.5' and adapter['kind'] == 'cursor_cli' and adapter.get('cursor_mode') != 'agent':
            raise ValueError('qualification author must use explicit agent mode')
    by_id = {a['id']: a for a in config['adapters']}
    if (by_id[config['routes']['default_executor']]['model'] != 'composer-2.5'
            or by_id[config['routes']['default_auditor']]['model'] != 'cursor-grok-4.6-high'):
        raise ValueError('qualification requires Composer author and independent Grok reviewer')


def admit_profile(config, requested, database_url):
    validate_profile(config)
    if requested != config.get('qualification_profile'):
        raise ValueError('explicit qualification profile must match registry')
    if requested is not None:
        parsed = urlsplit(database_url)
        if (not parsed.path.lstrip('/').startswith('td_test_')
                or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}
                or parsed.port != 5432 or parsed.query or parsed.fragment):
            raise ValueError('qualification requires an explicit disposable local database')
    # Normal connection/capability/namespace checks still apply; this is no bypass.


def worker_policy(production_policy, config, requested, database_url):
    admit_profile(config, requested, database_url)
    if requested is None:
        return production_policy
    policy = deepcopy(production_policy)
    policy['phases']['4'] = {'role': 'disposable-independent-review', 'provider': 'cursor',
        'model': 'cursor-grok-4.6-high', 'effort': 'high', 'fallbacks': []}
    policy['independence']['author_failover_by_model'] = {}
    return policy
