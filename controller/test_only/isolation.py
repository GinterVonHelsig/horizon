"""Fail-closed preflight for privileged fixtures; never a production bypass.

No writes, environment opt-out, or host database connection is permitted here.
Verify private mount/network/PID boundaries before the read-only DB probe.
"""
from __future__ import annotations

import os
import socket
from pathlib import Path
from urllib.parse import urlsplit


class UnsafeTestEnvironment(RuntimeError):
    pass


def require_filesystem_isolation() -> None:
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        mounts[fields[4]] = (fields[3], right.split()[0], fields[6:], fields[0], fields[1])
    for target in ('/tmp', '/run', '/etc/top-delivery',
                   '/var/lib/top-delivery-submission-bundles'):
        item = mounts.get(target)
        if (item is None or item[:2] != ('/', 'tmpfs')
                or any(x.startswith(('shared:', 'master:')) for x in item[2])):
            raise UnsafeTestEnvironment('privileged tests require private tmpfs: ' + target)
        # Mountinfo also lists old mounts hidden by our overmount (e.g. host
        # /run/credentials). Only descendants attached to the private mount are
        # visible; reject those, not hidden descendants of the old host mount.
        if any(p.startswith(target + '/') and child[4] == item[3]
               for p, child in mounts.items()):
            raise UnsafeTestEnvironment('unexpected nested mount below private test root: ' + target)
    # This detects wrapper omission even on a host whose /run happens to be tmpfs.
    # Wrapper IDs are comparison evidence, not permission to skip mount checks.
    for kind in ('mnt', 'net', 'pid'):
        outer = os.environ.get('HORIZON_TEST_OUTER_' + kind.upper())
        current = os.readlink('/proc/self/ns/' + kind)
        if not outer or outer == current:
            raise UnsafeTestEnvironment('privileged tests require a distinct ' + kind + ' namespace')
    # ioctl/netlink view of the current net namespace, not inherited host sysfs.
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise UnsafeTestEnvironment('privileged tests require loopback-only networking')


def require_isolation(admin_url: str) -> None:
    require_filesystem_isolation()
    parsed = urlsplit(admin_url)
    if (parsed.scheme != 'postgresql' or parsed.hostname != '127.0.0.1'
            or parsed.port != 5432 or parsed.path != '/postgres'
            or parsed.query or parsed.fragment):
        raise UnsafeTestEnvironment('privileged tests require private loopback admin database')
    import psycopg2
    with psycopg2.connect(admin_url, connect_timeout=3,
                         options='-c default_transaction_read_only=on') as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_setting('data_directory'), host(inet_server_addr()), inet_server_port()")
            directory, address, port = cur.fetchone()
    data = Path(directory)
    if (data.parent != Path('/tmp') or not data.name.startswith('horizon-recovery-pg.')
            or data.resolve() != data or address != '127.0.0.1' or port != 5432):
        raise UnsafeTestEnvironment('database is not the disposable private cluster')
    # The postmaster must be visible in this PID namespace and use this private
    # data directory; a forwarded host endpoint is not a disposable cluster.
    pid = int((data / 'postmaster.pid').read_text().splitlines()[0])
    proc = Path('/proc') / str(pid)
    argv = (proc / 'cmdline').read_bytes().split(b'\0')
    if (Path(os.readlink(proc / 'exe')).name != 'postgres'
            or str(data).encode() not in argv
            or os.readlink(proc / 'ns/net') != os.readlink('/proc/self/ns/net')
            or os.readlink(proc / 'ns/pid') != os.readlink('/proc/self/ns/pid')):
        raise UnsafeTestEnvironment('postmaster does not belong to private test namespaces')
