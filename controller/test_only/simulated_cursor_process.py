#!/usr/bin/python3 -I
"""Deterministic subprocess protocol fixture; no transport, credentials or models."""
import json
from pathlib import Path
import sys

if sys.argv[1:] == ['--list-models']:
    print('composer-2.5\ncursor-grok-4.6-high')
    raise SystemExit(0)
model = sys.argv[sys.argv.index('--model')+1]
prompt = sys.argv[sys.argv.index('-p')+1]
if model == 'composer-2.5':
    if prompt.startswith('Create exactly one UTF-8 file'):
        spec = json.loads(prompt.split('\n')[1])
        Path(spec['filename']).write_text(spec['content'])
        result = {'disposition': 'IMPLEMENTED'}
    else:
        assignment = json.JSONDecoder().raw_decode(prompt.split('\n', 1)[1])[0]
        result = {k: assignment[k] for k in ('run_id', 'task_id', 'attempt_id')}
        result.update(disposition='PASS/PARENT', evidence_summary='SIMULATED parent continuation completed')
        adopted=json.loads(prompt.rsplit('\nVALIDATED PREREQUISITE PRODUCTS\n',1)[1])
        assert len(adopted)==1
        result['adopted_product_sha256']=adopted[0]['product_sha256']
        Path(assignment['result_file']).write_text(json.dumps(result))
elif model == 'cursor-grok-4.6-high':
    if prompt.startswith('AUDIT OBJECTIVE'):
        criteria = json.loads(prompt.split('ACCEPTANCE CRITERIA\n')[1].split('\n\nEXECUTOR EVIDENCE')[0])
        evidence = json.loads(prompt.split('EXECUTOR EVIDENCE\n')[1].split('\n\nTRUSTED EVIDENCE')[0])
        assert evidence['model'] == 'composer-2.5'
        result = {'verdict': 'approve', 'criteria': [
            {'criterion': c, 'met': True, 'rationale': 'SIMULATED independent evidence check',
             'evidence_refs': [{'name': a['stream'], 'sha256': a['sha256']} for a in evidence['artifacts']]}
            for c in criteria]}
    else:
        result = {'verdict':'approve','findings':[],'suggestions':[]}
else:
    raise ValueError('unexpected simulated model')
print(json.dumps({'type': 'system', 'subtype': 'init', 'model': model, 'session_id': 'simulated-session'}))
print(json.dumps({'type': 'assistant', 'message': {'content': json.dumps(result)}}))
print(json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False, 'result':json.dumps(result)}))
