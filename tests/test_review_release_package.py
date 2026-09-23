"""Real relocated entry points, fake pinned Cursor process; no model/network calls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review_package', ROOT / 'tools/host_review/package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def staged(tmp_path):
    built = tmp_path / 'build'
    package.stage(built, allow_uncommitted=True)
    # Neither entry point may retain the original staging path or checkout path.
    release = tmp_path / 'relocated release'
    built.rename(release)
    evidence = tmp_path / 'evidence'
    evidence.mkdir(mode=0o700)
    fake = tmp_path / 'fake-cursor'
    fake.write_text('''#!/usr/bin/python3 -I
import json, pathlib, sys
root = pathlib.Path(__file__).parent
with (root / 'calls.jsonl').open('a') as out:
    out.write(json.dumps(sys.argv[1:]) + '\\n')
case = json.loads((root / 'fake-result.json').read_text())
if case.get('exit'):
    raise SystemExit(case['exit'])
print(json.dumps({'type':'system','subtype':'init','model':case['model']}))
print(json.dumps({'type':'result','subtype':'success','is_error':False,
    'result':json.dumps({'verdict':case['verdict'],'findings':[],'suggestions':[]})}))
''')
    fake.chmod(0o755)
    (tmp_path / 'fake-result.json').write_text(json.dumps({'model':'Cursor Grok 4.6 High','verdict':'approve'}))
    # Explicit consumer policy for this SIMULATED test only; the shipped September
    # policy is byte-for-byte unchanged. There is no runtime provider translation.
    policy = yaml.safe_load((release / 'architecture/model-routing.yaml').read_text())
    policy['phases']['4'] = {'provider':'cursor','model':'cursor-grok-4.6-high','effort':'high','fallbacks':[]}
    routing = tmp_path / 'consumer-routing.yaml'
    routing.write_text(yaml.safe_dump(policy))
    config = tmp_path / 'consumer.json'
    config.write_text(json.dumps({'schema':'horizon-review-consumer.v1','enabled':True,'transport':'cursor',
        'cursor_executable':str(fake),'cursor_sha256':digest(fake),
        'routing_yaml':routing.name,'routing_sha256':digest(routing)}))
    def artifact(name, value):
        path = evidence / name
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return {'path':name, 'sha256':digest(path)}
    subject = artifact('packet.md', b'review exactly this disposable patch')
    result = artifact('author-result.json', {'status':'success','exit_code':0,'provider':'cursor','model':'composer-2.5'})
    from model_routing import RoutingRecord
    author = artifact('author.json', {'run_id':'package-test','subject_sha256':subject['sha256'],
        'result':result, 'route':RoutingRecord('3A','actual-author','cursor','composer-2.5','cursor-agent','subscription','default','none').to_dict()})
    artifact('context.json', {'run_id':'package-test','subject':subject,'authors':[author],'reviews':[],
        'max_calls':1,'fallback_calls':0,'on_demand_disabled_operator_confirmed':True,
        'available_routes':[{'provider':'cursor','model':'cursor-grok-4.6-high'}]})
    artifact('system.md', b'Read-only independent review. No execution.')
    return release, evidence, config


def invoke(staged, entry='cursor-independent-review', extra=()):
    release, evidence, config = staged
    env = {'PATH':str(Path(sys.executable).parent) + ':/usr/bin:/bin', 'HOME':str(evidence),
           'PYTHONPATH':'/nonexistent/development-checkout', 'PYTHONDONTWRITEBYTECODE':'1'}
    return subprocess.run([str(release / 'bin' / entry), '--consumer-config', str(config),
        '--seat','4','--run-id','package-test','--artifact-root',str(evidence),
        '--review-context',str(evidence / 'context.json'), '--system-file',str(evidence / 'system.md'),
        '--user-file',str(evidence / 'packet.md'), *extra],
        cwd=evidence, env=env, text=True, capture_output=True, timeout=20)


@pytest.mark.parametrize('entry', ['cursor-independent-review','openrouter-review'])
def test_packaged_entries_relocate_and_forward_bound_consumer(staged, entry):
    release, evidence, config = staged
    result = invoke(staged, entry)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload['provider'] == 'cursor' and payload['model'] == 'Cursor Grok 4.6 High'
    assert payload['transport'] == 'cursor-agent'
    calls = [json.loads(line) for line in (config.parent / 'calls.jsonl').read_text().splitlines()]
    assert len(calls) == 1
    assert calls[0][:6] == ['agent','--mode','ask','--model','cursor-grok-4.6-high','-p']
    assert '--sandbox' in calls[0] and '--force' not in calls[0]
    assert 'review exactly this disposable patch' in calls[0][-1]
    assert len(list((evidence / 'review-history').glob('*.json'))) == 1
    # Switching compatibility command cannot bypass the durable execution intent.
    replay = invoke(staged, 'openrouter-review' if entry == 'cursor-independent-review' else 'cursor-independent-review')
    assert replay.returncode == 78
    assert len((config.parent / 'calls.jsonl').read_text().splitlines()) == 1
    manifest = json.loads((release / 'manifest.json').read_text())
    assert not any('migration' in name or 'test_only' in name for name in manifest['files'])
    assert (release / 'architecture/model-routing.yaml').read_bytes() == (ROOT / 'architecture/model-routing.yaml').read_bytes()


@pytest.mark.parametrize('fault', ['disabled','unknown_config','bad_executable_hash','bad_routing_hash',
    'missing_context','packet_tamper','missing_route','author_collision','billing_unconfirmed',
    'non_cursor_inventory','rejected_prior','package_tamper','missing_dependency','override_routing',
    'writable_config','symlink_config','non_review_seat','unmodified_september_policy'])
def test_packaged_consumer_refuses_before_transport(staged, fault):
    release, evidence, config = staged
    consumer = json.loads(config.read_text())
    context = json.loads((evidence / 'context.json').read_text())
    extra = ()
    if fault == 'disabled': consumer['enabled'] = False
    if fault == 'unknown_config': consumer['extra'] = True
    if fault == 'bad_executable_hash': consumer['cursor_sha256'] = '0'*64
    if fault == 'bad_routing_hash': consumer['routing_sha256'] = '0'*64
    if fault == 'missing_route': context['available_routes'] = []
    if fault == 'billing_unconfirmed': context['on_demand_disabled_operator_confirmed'] = False
    if fault == 'non_cursor_inventory': context['available_routes'][0]['provider'] = 'openrouter'
    if fault == 'rejected_prior': context['reviews'] = context['authors']  # no passing review result
    if fault == 'non_review_seat': extra = ('--seat', '3A')
    if fault == 'unmodified_september_policy':
        routing = config.parent / 'consumer-routing.yaml'
        routing.write_bytes((release / 'architecture/model-routing.yaml').read_bytes())
        consumer['routing_sha256'] = digest(routing)
    if fault == 'author_collision':
        result = evidence / 'author-result.json'
        result.write_text(json.dumps({'status':'success','exit_code':0,'provider':'cursor','model':'cursor-grok-4.6-high'}))
        entry = json.loads((evidence / 'author.json').read_text())
        entry['route']['model'] = 'cursor-grok-4.6-high'
        entry['result']['sha256'] = digest(result)
        (evidence / 'author.json').write_text(json.dumps(entry))
        context['authors'][0]['sha256'] = digest(evidence / 'author.json')
    (evidence / 'context.json').write_text(json.dumps(context))
    config.write_text(json.dumps(consumer))
    if fault == 'missing_context': (evidence / 'context.json').unlink()
    if fault == 'packet_tamper': (evidence / 'packet.md').write_text('different patch')
    if fault == 'package_tamper': (release / 'controller/model_routing.py').write_text('raise RuntimeError("tampered")')
    if fault == 'missing_dependency': (release / 'controller/model_routing.py').unlink()
    if fault == 'override_routing': extra = ('--routing-yaml', str(config.parent / 'consumer-routing.yaml'))
    if fault == 'writable_config': config.chmod(0o666)
    if fault == 'symlink_config':
        target = config.with_suffix('.target')
        config.rename(target)
        config.symlink_to(target)
    result = invoke(staged, extra=extra)
    assert result.returncode == 78, result.stderr
    assert not (config.parent / 'calls.jsonl').exists()
    assert not (evidence / 'review-intents').exists()


@pytest.mark.parametrize('case', [
    {'model':'Cursor Grok 4.6 High','verdict':'changes-required'},
    {'model':'Cursor Grok 4.6 High','verdict':'fail'},
    {'model':'Composer 2.5','verdict':'approve'},
    {'model':'Cursor Grok 4.6 High','verdict':'approve','exit':1},
])
def test_packaged_rejection_or_uncertain_result_never_success_or_retry(staged, case):
    _, evidence, config = staged
    (config.parent / 'fake-result.json').write_text(json.dumps(case))
    result = invoke(staged)
    assert result.returncode == 2, result.stderr
    assert len((config.parent / 'calls.jsonl').read_text().splitlines()) == 1
    assert invoke(staged).returncode == 78
    assert len((config.parent / 'calls.jsonl').read_text().splitlines()) == 1


def test_stage_refuses_overwrite_and_symlink(tmp_path):
    target = tmp_path / 'existing'
    target.mkdir()
    with pytest.raises(FileExistsError): package.stage(target, allow_uncommitted=True)
    link = tmp_path / 'link'
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'): package.stage(link / 'new', allow_uncommitted=True)


def test_default_config_is_disabled(staged):
    release, evidence, _ = staged
    result = invoke((release, evidence, release / 'tools/host_review/consumer.example.json'))
    assert result.returncode == 78


@pytest.mark.parametrize('entry', ['cursor-independent-review','openrouter-review'])
@pytest.mark.parametrize('transport', [None, 'openrouter'])
def test_legacy_name_requires_explicit_cursor_semantics(staged, entry, transport):
    _, _, config = staged
    value = json.loads(config.read_text())
    if transport is None:
        del value['transport']
    else:
        value['transport'] = transport
    config.write_text(json.dumps(value))
    assert invoke(staged, entry).returncode == 78
    assert not (config.parent / 'calls.jsonl').exists()


def test_uncommitted_inputs_refuse_before_output_and_are_labelled(tmp_path, monkeypatch):
    original = package.subprocess.run
    def changed_git_blob(args, **kwargs):
        result = original(args, **kwargs)
        if args[:2] == ['git', 'show']:
            result.stdout = b'simulated different committed bytes'
        return result
    monkeypatch.setattr(package.subprocess, 'run', changed_git_blob)
    output = tmp_path / 'release'
    with pytest.raises(ValueError, match='uncommitted'):
        package.stage(output)
    assert not output.exists()
    manifest = package.stage(output, allow_uncommitted=True)
    assert manifest['source_state'] == 'TEST_ONLY_UNCOMMITTED'
    assert set(manifest['uncommitted_inputs']) == set(package.SOURCES)
