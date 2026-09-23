"""Explicit Cursor-only client for the isolated qualification broker."""
import json
import os
from pathlib import Path
import socket
import sys


def request(argv, standalone_workspace):
    args=list(argv)
    standalone=args[:1]==['agent']
    if standalone: args.pop(0)
    values={}; flags=set(); prompt=None
    while args:
        arg=args.pop(0)
        if arg in {'--model','--mode','--sandbox','--output-format'}:
            if arg in values or not args: raise ValueError('duplicate or missing option')
            values[arg]=args.pop(0)
        elif arg in {'-p','--force','--trust'}:
            if arg in flags: raise ValueError('duplicate flag')
            flags.add(arg)
            if arg=='-p' and args and not args[0].startswith('--'):
                prompt=args.pop(0)
        elif not arg.startswith('-') and prompt is None:
            prompt=arg
        else:
            raise ValueError('unsupported Cursor invocation')
    model=values.get('--model')
    if (values.get('--output-format')!='stream-json' or values.get('--sandbox')!='enabled'
            or '-p' not in flags or not prompt):
        raise ValueError('explicit sandboxed Cursor request required')
    if model=='cursor-grok-4.6-high':
        if values.get('--mode')!='ask' or '--force' in flags:
            raise ValueError('independent reviewer must be read-only')
    elif model=='composer-2.5':
        if standalone or '--force' not in flags or '--mode' in values:
            raise ValueError('explicit Composer author required')
    else:
        raise ValueError('unsupported qualification model')
    return {'model':model,'prompt':prompt,'cwd':str(standalone_workspace if standalone else Path.cwd())}


def main(socket_path, standalone_workspace, argv=None):
    args=sys.argv[1:] if argv is None else argv
    # Fixed profile inventory, not a live catalog/model call. Live availability
    # is proven only by the subsequent attributable init event, never by this list.
    if args==['--list-models']:
        print('composer-2.5\ncursor-grok-4.6-high')
        return 0
    try:
        payload=request(args,standalone_workspace)
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(930)
            connection.connect(str(socket_path))
            connection.sendall((json.dumps(payload)+'\n').encode())
            data=b''
            while not data.endswith(b'\n'):
                chunk=connection.recv(65536)
                if not chunk or len(data)+len(chunk)>4*1024*1024:
                    raise ValueError('incomplete or oversized broker response')
                data+=chunk
        result=json.loads(data)
        if result['exit']==0:
            sys.stdout.write(result['stdout'])
            return 0
    except (ValueError,OSError,KeyError,TypeError):
        pass
    print('qualification blocked; reconcile durable session ledger, never retry automatically',file=sys.stderr)
    return 78
