"""Source-owned host submission transport. No controller/model execution on import."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 65536
SUN_PATH_BYTES = 108  # Linux sockaddr_un.sun_path, including terminating NUL.
RUN = re.compile(r'goal-[0-9a-f]{16}')
SHA = re.compile(r'[0-9a-f]{64}')
HOST_ONLY = re.compile(r"(?:do not|don't|not)\s+(?:(?:run|invoke)\s+)?`?(?:goal_cli(?:\.py)?\s+submit|\$top-delivery)", re.I)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unix_socket_path(path):
    """Validate the final pathname address before writes, launch, bind, or connect."""
    path = Path(path)
    encoded_path = os.fsencode(str(path))
    if not path.is_absolute():
        raise ValueError('absolute socket path required')
    if b'\0' in encoded_path or len(encoded_path) >= SUN_PATH_BYTES:
        raise ValueError('Unix socket path exceeds Linux sockaddr_un limit')
    trusted(path.parent, directory=True)
    return path


def trusted(path, *, directory=False, private=False):
    path = Path(path).absolute()
    if '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('symlink in trusted path')
    info = path.stat()
    if info.st_uid not in {0, os.geteuid()} or info.st_mode & (0o077 if private else 0o022):
        raise ValueError('untrusted ownership or permissions')
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError('wrong trusted object type')
    return path


def pinned(path, expected):
    data = trusted(path).read_bytes()
    if not isinstance(expected, str) or not SHA.fullmatch(expected) or digest(data) != expected:
        raise ValueError('digest mismatch')
    return data


def load_config(path):
    config = json.loads(trusted(path).read_bytes())
    keys = {'schema', 'enabled', 'release_root', 'release_commit', 'release_manifest_sha256',
        'prompt_root', 'runs_root', 'journal_root', 'socket_path', 'service_uid', 'socket_gid',
        'allowed_uids', 'systemd_run', 'systemd_run_sha256', 'python', 'python_sha256',
        'environment_file', 'adapter_config', 'adapter_sha256', 'canary_binding'}
    required_keys = keys - {'canary_binding'}
    if not required_keys <= set(config) or set(config) - keys or config['schema'] != 'horizon-submission-consumer.v1' or type(config['enabled']) is not bool:
        raise ValueError('invalid consumer configuration')
    release = trusted(config['release_root'], directory=True)
    if release != ROOT or not re.fullmatch(r'[0-9a-f]{40}', config['release_commit']):
        raise ValueError('invoked package differs from configured immutable release')
    manifest = json.loads(pinned(release / 'manifest.json', config['release_manifest_sha256']))
    if manifest.get('schema') != 'horizon-submission-release.v1' or manifest.get('source_commit') != config['release_commit']:
        raise ValueError('release identity mismatch')
    if not {'controller/goal_cli.py', 'controller/prompt_ingest.py'} <= manifest['files'].keys():
        raise ValueError('missing canonical release entry points')
    for name, expected in manifest['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('manifest escape')
        pinned(release / name, expected)
    for name in ('prompt_root', 'runs_root', 'journal_root'):
        trusted(config[name], directory=True, private=name == 'journal_root')
    unix_socket_path(config['socket_path'])
    for key in ('service_uid', 'socket_gid'):
        if type(config[key]) is not int or config[key] < 0:
            raise ValueError('explicit service identity required')
    if not config['allowed_uids'] or any(type(uid) is not int or uid < 0 for uid in config['allowed_uids']):
        raise ValueError('explicit peer allowlist required')
    for name in ('systemd_run', 'python'):
        if not Path(config[name]).is_absolute() or not os.access(config[name], os.X_OK):
            raise ValueError('absolute executable required')
        pinned(config[name], config[name + '_sha256'])
    trusted(config['environment_file'])  # Do not read/export credentials.
    pinned(config['adapter_config'], config['adapter_sha256'])
    binding = config.get('canary_binding')
    if binding is not None:
        if not isinstance(binding, dict) or set(binding) != {'run_id','workspace_root','workspace_dev','workspace_ino','executor_route','reviewer_route','max_sessions'}:
            raise ValueError('invalid canary binding')
        if not RUN.fullmatch(binding['run_id']) or not isinstance(binding['workspace_root'], str) or not Path(binding['workspace_root']).is_absolute():
            raise ValueError('invalid canary identity')
        if any(type(binding[k]) is not int or binding[k] < 0 for k in ('workspace_dev','workspace_ino')) or type(binding['max_sessions']) is not int or not 1 <= binding['max_sessions'] <= 5:
            raise ValueError('invalid canary limits')
        if not all(isinstance(binding[k], str) and binding[k] for k in ('executor_route','reviewer_route')):
            raise ValueError('invalid canary routes')
    return config


def enforce_canary_binding(config, parsed, artifact_root):
    """Bind a staged canary to one run and one inode; do not relax path trust."""
    binding = config.get('canary_binding')
    if binding is None:
        return
    if parsed.run_id != binding['run_id']:
        raise ValueError('canary run identity mismatch')
    from harness_adapters.registry import load_registry_config, validate_task_routes
    registry = load_registry_config(Path(config['adapter_config']), validate_executables=False)
    validate_task_routes(registry, binding['executor_route'], binding['reviewer_route'])
    workspace = trusted(binding['workspace_root'], directory=True, private=True)
    info = workspace.stat()
    if (info.st_dev, info.st_ino) != (binding['workspace_dev'], binding['workspace_ino']):
        raise ValueError('canary workspace identity changed')
    artifact = Path(artifact_root).absolute()
    if not artifact.is_relative_to(workspace) or any(p.is_symlink() for p in (artifact, *artifact.parents)):
        raise ValueError('canary artifact outside bound workspace')


def atomic(path, value):
    """Replace a journal record durably while holding its exclusive request lock."""
    data = value if isinstance(value, bytes) else encoded(value)
    temporary = path.with_suffix(path.suffix + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError('journal write failed')
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prompt(config, request):
    path = trusted(request['prompt_path'])
    if path.suffix != '.md' or not path.is_relative_to(Path(config['prompt_root'])):
        raise ValueError('prompt outside allowlist')
    data = path.read_bytes()
    if len(data) > LIMIT or HOST_ONLY.search(data.decode('utf-8')):
        raise ValueError('oversized or host-only prompt')
    if request.get('prompt_sha256') != digest(data):
        raise ValueError('immutable prompt digest required')
    from prompt_ingest import parse_prompt_bytes
    parsed = parse_prompt_bytes(data, source=str(path))
    return data, parsed


def receipt(raw, identity):
    if len(raw) > LIMIT:
        raise ValueError('oversized receipt')
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get('mode') != 'durable' or value.get('prompt_digest') != identity['prompt_sha256']
        or value.get('run_id') != (identity['existing_parent'] or identity['submission_run_id'])
        or value.get('status') not in {'created', 'existing', 'preserved_disabled', 'awaiting_controller'}
        or value.get('task_ids') != identity['task_ids']):
        raise ValueError('invalid durable receipt')
    if identity['existing_parent'] and (value.get('parent_run_id') != identity['existing_parent']
        or value.get('submission_run_id') != identity['submission_run_id']):
        raise ValueError('parent receipt mismatch')
    paths = value.get('artifact_paths', {})
    if not isinstance(paths, dict) or set(paths) - {'prompt_snapshot', 'goal_spec'}:
        raise ValueError('unexpected artifact references')
    for path in paths.values():
        if not isinstance(path, str) or not Path(path).is_absolute() or '..' in Path(path).parts or not Path(path).is_relative_to(identity['artifact_root']):
            raise ValueError('artifact reference outside bound root')
    # Return only known bounded fields, never arbitrary child stdout/stderr.
    return {'status': 'ok' if value['status'] in {'created', 'existing'} else 'blocked',
        'operation': 'submit', 'run_id': value['run_id'], 'submission_run_id': identity['submission_run_id'],
        'parent_run_id': identity['existing_parent'], 'prompt_sha256': identity['prompt_sha256'],
        'task_ids': value['task_ids'], 'mode': 'durable', 'submission_status': value['status'],
        'release_commit': identity['release_commit'], 'artifact_paths': paths}


def prerequisites(config, request, parsed):
    path, expected = request.get('prerequisites_path'), request.get('prerequisites_sha256')
    if path is None and expected is None:
        return None
    if not path or not expected:
        raise ValueError('prerequisites require path and immutable digest')
    path = trusted(path)
    if not path.is_relative_to(config['prompt_root']) or path.suffix != '.json':
        raise ValueError('prerequisites outside prompt allowlist')
    data = pinned(path, expected)
    if len(data) > LIMIT:
        raise ValueError('oversized prerequisites')
    value = json.loads(data)
    if not isinstance(value, dict) or set(value) - {str(w.number) for w in parsed.workstreams}:
        raise ValueError('unknown prerequisite workstream')
    from bounded_delivery import validate_spec, validate_binding
    from subworkflow_handoff import build_handoff_request, digest_value
    from harness_adapters.registry import load_registry_config, validate_task_routes
    registry = load_registry_config(Path(config['adapter_config']), validate_executables=False)
    for specs in value.values():
        if not isinstance(specs, list) or not specs:
            raise ValueError('nonempty prerequisite list required')
        seen = set()
        for spec in specs:
            validate_spec(spec)
            if spec['prerequisite_id'] in seen:
                raise ValueError('duplicate prerequisite identity')
            seen.add(spec['prerequisite_id'])
            handoff = build_handoff_request(run_id=parsed.run_id, parent_task_id='admission',
                parent_attempt_id='admission', failure_code='BLOCKED_HORIZON_PREREQ_MISSING',
                request_artifact_root='admission', handoff_context={'delivery_profile':spec['profile'],
                    'delivery_spec_digest':digest_value(spec), 'prerequisite_node_id':spec['prerequisite_id']})
            validate_task_routes(registry, handoff['executor_adapter'], handoff['auditor_adapter'])
            validate_binding(registry, handoff)
    return data


def submit(config, request, data, parsed):
    if os.geteuid() != config['service_uid']:
        raise ValueError('submission must run as configured service identity')
    prerequisite_bytes = prerequisites(config, request, parsed)
    from harness_adapters.registry import load_registry_config, validate_task_routes
    registry = load_registry_config(Path(config['adapter_config']), validate_executables=False)
    validate_task_routes(registry, registry['routes']['default_executor'], registry['routes']['default_auditor'])
    parent = request.get('existing_parent')
    if parent is not None and (not isinstance(parent, str) or not RUN.fullmatch(parent)):
        raise ValueError('invalid existing parent')
    root = Path(config['runs_root'])
    if parent:
        trusted(root / parent / 'artifacts', directory=True)
    artifact = Path(request.get('artifact_root') or root / parsed.run_id / 'artifacts').absolute()
    if '..' in artifact.parts or not artifact.is_relative_to(root) or any(p.is_symlink() for p in (artifact, *artifact.parents)):
        raise ValueError('artifact root outside configured runs root')
    enforce_canary_binding(config, parsed, artifact)
    identity = {'prompt_sha256': digest(data), 'submission_run_id': parsed.run_id,
        'task_ids': [w.task_id for w in parsed.workstreams], 'existing_parent': parent,
        'artifact_root': str(artifact), 'release_commit': config['release_commit'],
        'release_manifest_sha256': config['release_manifest_sha256'], 'consumer_digest': digest(encoded(config))}
    if prerequisite_bytes is not None:
        identity['prerequisites_sha256'] = digest(prerequisite_bytes)
    key = digest(encoded([identity['prompt_sha256'], parent]))
    directory = Path(config['journal_root']) / key
    directory.mkdir(mode=0o700, exist_ok=True)
    trusted(directory, directory=True, private=True)
    parent_fd = os.open(directory.parent, os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    lock = os.open(directory / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    dispatch = None
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        binding = directory / 'request.json'
        if binding.exists():
            if json.loads(trusted(binding).read_bytes()) != identity:
                raise ValueError('immutable submission configuration conflict')
        else:
            atomic(binding, identity)
        snapshot = directory / 'prompt.md'
        if snapshot.exists() and trusted(snapshot).read_bytes() != data:
            raise ValueError('immutable prompt conflict')
        if not snapshot.exists():
            atomic(snapshot, data)
        prerequisite_snapshot = directory / 'prerequisites.json'
        if prerequisite_bytes is not None:
            if prerequisite_snapshot.exists() and trusted(prerequisite_snapshot).read_bytes() != prerequisite_bytes:
                raise ValueError('immutable prerequisite conflict')
            if not prerequisite_snapshot.exists():
                atomic(prerequisite_snapshot, prerequisite_bytes)
        result_file = directory / 'receipt.json'
        if result_file.exists():
            return receipt(trusted(result_file).read_bytes(), identity)
        state_file = directory / 'state.json'
        if state_file.exists():
            return {'status': 'blocked', 'operation': 'submit', 'reason': 'submission_outcome_unknown_no_replay', 'request_id': key}
        # The attested systemd entrypoint name is fixed: serialize different
        # prompts too, without changing the service identity or waiting forever.
        dispatch = os.open(Path(config['journal_root']) / 'dispatch.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(dispatch, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'status':'blocked','operation':'submit','reason':'dispatch_busy_before_effect_safe_to_retry'}
        fence = Path(config['journal_root']) / 'dispatch.json'
        if fence.exists():
            owner = json.loads(trusted(fence).read_bytes())
            if set(owner) != {'request_id', 'identity_sha256'} or not SHA.fullmatch(owner['request_id']):
                raise ValueError('invalid durable dispatch fence')
            owner_dir = directory.parent / owner['request_id']
            owner_identity = json.loads(trusted(owner_dir / 'request.json').read_bytes())
            if digest(encoded(owner_identity)) != owner['identity_sha256']:
                raise ValueError('dispatch fence identity mismatch')
            if not (owner_dir / 'receipt.json').exists():
                return {'status':'blocked','operation':'submit','reason':'global_dispatch_outcome_unknown_no_replay'}
            receipt(trusted(owner_dir / 'receipt.json').read_bytes(), owner_identity)
            # Only a validated receipt written after the synchronous child exit
            # reconciles the global fence. Never erase a per-request intent.
        # GoalSubmitter requires this directory before it can register anything.
        # Create each bound component privately; failure is still before intent.
        current = root
        for part in artifact.relative_to(root).parts:
            current = current / part
            current.mkdir(mode=0o700, exist_ok=True)
            trusted(current, directory=True)
        command = [config['systemd_run'], '--wait', '--collect', '--pipe',
            '--unit=top-delivery-entrypoint@top-delivery-controller', '--service-type=oneshot',
            f'--working-directory={ROOT / "controller"}', f'--property=EnvironmentFile={config["environment_file"]}',
            config['python'], str(ROOT / 'controller/goal_cli.py'), 'submit', '--prompt', str(snapshot),
            '--artifact-root', str(artifact), '--adapter-config', config['adapter_config']]
        if parent:
            command += ['--existing-parent', parent, '--runtime-artifact-root', str(root / parent / 'artifacts')]
        if prerequisite_bytes is not None:
            command += ['--prerequisites-json', str(prerequisite_snapshot)]
        if registry.get('qualification_profile'):
            command += ['--qualification-profile', registry['qualification_profile']]
        atomic(state_file, {'state': 'dispatch_intent', 'request_id': key})
        atomic(fence, {'request_id': key, 'identity_sha256': digest(encoded(identity))})
        # One call only. systemd may outlive timeout/process death: retain intent.
        try:
            child = subprocess.run(command, cwd=ROOT / 'controller', capture_output=True, text=True,
                timeout=120, env={'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8'})
            if child.returncode != 0:
                return {'status':'blocked', 'operation':'submit', 'reason':'child_failed_outcome_unknown', 'request_id':key}
            result = receipt(child.stdout, identity)
            # Persist only validated fields, not arbitrary child diagnostics.
            atomic(result_file, {'mode':'durable', 'status':result['submission_status'],
                'run_id':result['run_id'], 'submission_run_id':result['submission_run_id'],
                'parent_run_id':result['parent_run_id'], 'prompt_digest':result['prompt_sha256'],
                'task_ids':result['task_ids'], 'artifact_paths':result['artifact_paths']})
            atomic(state_file, {'state':'receipt_recorded', 'request_id':key})
            return result
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return {'status':'blocked', 'operation':'submit', 'reason':'submission_outcome_unknown_no_replay', 'request_id':key}
    finally:
        if dispatch is not None:
            os.close(dispatch)
        os.close(lock)


def handle(config, request, uid):
    if uid not in config['allowed_uids']:
        return {'status':'denied', 'reason':'peer_not_allowed'}
    if not isinstance(request, dict) or set(request) - {'operation','prompt_path','prompt_sha256','artifact_root','existing_parent','dry_run','prerequisites_path','prerequisites_sha256'}:
        raise ValueError('unknown request fields')
    operation = request.get('operation')
    if 'dry_run' in request and operation != 'execute-recovery':
        raise ValueError('dry-run submission is not supported by socket protocol; use inspect')
    if operation == 'health':
        return {'status':'ok', 'operation':'health', 'durable_submission_enabled':config['enabled'],
            'release_commit':config['release_commit'], 'recovery_dispatch_enabled':False}
    if operation == 'execute-recovery':
        return {'status':'blocked', 'reason':'historical_recovery_dispatch_not_authorized'}
    if operation not in {'inspect','submit'}:
        raise ValueError('unknown operation')
    data, parsed = prompt(config, request)
    if operation == 'inspect':
        extra = prerequisites(config, request, parsed)
        result = {'status':'ok','mode':'inspect','run_id':parsed.run_id,'prompt_digest':digest(data),
            'title':parsed.title,'task_ids':[w.task_id for w in parsed.workstreams],
            'workstream_count':len(parsed.workstreams),'release_commit':config['release_commit']}
        if extra is not None:
            result['prerequisites_sha256'] = digest(extra)
        return result
    if not config['enabled']:
        return {'status':'blocked','reason':'durable_submission_disabled'}
    return submit(config, request, data, parsed)


def peer_uid(connection):
    if not hasattr(socket, 'SO_PEERCRED'):
        raise ValueError('peer credentials unavailable')
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def receive(connection, timeout=5):
    connection.settimeout(timeout)
    data = b''
    while not data.endswith(b'\n'):
        chunk = connection.recv(min(4096, LIMIT + 1 - len(data)))
        if not chunk:
            raise ValueError('incomplete frame')
        data += chunk
        if len(data) > LIMIT:
            raise ValueError('frame too large')
    return json.loads(data)


def serve(config_path):
    config = load_config(config_path)
    if os.geteuid() != config['service_uid']:
        raise ValueError('wrong service identity')
    path = unix_socket_path(config['socket_path'])
    # Never unlink an existing listener or stale path implicitly.
    if os.path.lexists(path):
        raise ValueError('submission socket collision or stale listener evidence')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        os.chmod(path, 0o660)
        os.chown(path, config['service_uid'], config['socket_gid'])
        inode = path.stat().st_ino
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        try:
            server.listen(16)
            while True:
                connection, _ = server.accept()
                with connection:
                    try:
                        # Reverify immutable release/config for every request.
                        fresh = load_config(config_path)
                        if fresh != config:
                            raise ValueError('consumer changed; restart under operator control')
                        result = handle(config, receive(connection), peer_uid(connection))
                    except (ValueError, OSError, KeyError, TypeError):
                        result = {'status':'blocked','reason':'invalid_request_or_configuration'}
                    try:
                        connection.sendall(encoded(result))
                    except OSError:
                        pass  # Durable receipt/intent survives a disconnected client.
        finally:
            if path.exists() and path.stat().st_ino == inode:
                path.unlink()


def main(entry, argv=None):
    parser = argparse.ArgumentParser(prog=entry, allow_abbrev=False)
    parser.add_argument('--config', type=Path, required=True)
    if entry == 'top-delivery-host-gateway-server':
        args = parser.parse_args(argv)
        try:
            serve(args.config)
            return 0
        except (ValueError, OSError, KeyError, TypeError):
            print(json.dumps({'status':'blocked','reason':'invalid_service_configuration'}))
            return 78
    if entry == 'top-delivery-submit':
        parser.add_argument('--inspect', '--dry-run', action='store_true')
        parser.add_argument('prompt', type=Path)
        parser.add_argument('--artifact-root')
        parser.add_argument('--existing-parent')
    else:
        parser.add_argument('operation', choices=['health','inspect','submit','execute-recovery'])
        parser.add_argument('--prompt', type=Path)
        parser.add_argument('--artifact-root')
        parser.add_argument('--existing-parent')
        parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--prerequisites-json', type=Path)
    parser.add_argument('--prerequisites-sha256')
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        operation = ('inspect' if args.inspect else 'submit') if entry == 'top-delivery-submit' else args.operation
        if entry != 'top-delivery-submit' and args.dry_run and operation != 'execute-recovery':
            raise ValueError('socket dry-run is not submit authority; use inspect')
        request = {'operation':operation}
        if operation in {'inspect','submit','execute-recovery'}:
            if args.prompt is None:
                raise ValueError('prompt required')
            source = trusted(args.prompt)
            request.update(prompt_path=str(source), prompt_sha256=digest(source.read_bytes()))
        for key in ('artifact_root','existing_parent'):
            if getattr(args, key):
                request[key] = getattr(args, key)
        if args.prerequisites_json is not None or args.prerequisites_sha256 is not None:
            if operation not in {'inspect', 'submit'} or args.prerequisites_json is None or args.prerequisites_sha256 is None:
                raise ValueError('prerequisite path and hash required for submit or inspect')
            request.update(prerequisites_path=str(args.prerequisites_json.absolute()), prerequisites_sha256=args.prerequisites_sha256)
        if entry != 'top-delivery-submit':
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(130)
                client.connect(config['socket_path'])
                if peer_uid(client) != config['service_uid']:
                    raise ValueError('wrong server identity')
                client.sendall(encoded(request))
                result = receive(client, timeout=130)
        else:
            result = handle(config, request, os.geteuid())
        print(encoded(result).decode(), end='')
        return 0 if result.get('status') == 'ok' else 78
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps({'status':'blocked','reason':'invalid_request_or_configuration'}))
        return 78


if __name__ == '__main__':
    raise SystemExit(main(Path(sys.argv[0]).name))
