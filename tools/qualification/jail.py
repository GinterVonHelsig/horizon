"""Linux-only disposable Cursor filesystem jail. Invoked by the session broker.

No installed mounts/files are changed: mount and PID namespaces are mandatory.
Authentication is a read-only bind, never a copied credential.
"""
import ctypes
import errno
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
import tempfile

CHILD_WORKSPACE = '/workspace'


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def pivot_root_into(root):
    """Make the private tmpfs root authoritative and detach the host root.

    The syscall numbers below are deliberately guarded: this qualification
    jail is currently supported only on x86_64.  An unknown architecture must
    fail closed instead of invoking a different syscall by number.
    """
    if platform.machine() != 'x86_64':
        raise OSError(errno.ENOTSUP, 'pivot_root unsupported architecture')
    libc = ctypes.CDLL(None, use_errno=True)
    os.chdir(root)
    (Path('oldroot')).mkdir()
    if libc.syscall(155, b'.', b'oldroot') != 0:  # pivot_root(2), x86_64
        raise OSError(ctypes.get_errno(), 'pivot_root failed')
    os.chdir('/')
    if libc.syscall(166, b'/oldroot', 2) != 0:  # umount2(MNT_DETACH)
        raise OSError(ctypes.get_errno(), 'detaching old root failed')
    # Removal is part of the confinement invariant.  Do not swallow failure:
    # a reachable old root makes the child outcome unsafe and must stop setup.
    Path('/oldroot').rmdir()


def enter(config, cwd, model, prompt):
    # Refuse direct entry into the host mount/PID namespaces.
    if any(os.readlink('/proc/self/ns/'+kind) == config['outer_'+kind] for kind in ('mnt','pid')):
        raise ValueError('private jail namespaces required')
    command('/usr/bin/mount', '--make-rprivate', '/')
    root = Path(tempfile.mkdtemp(prefix='jail-',dir=config['state_root']))
    command('/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=0700', 'tmpfs', str(root))

    def bind(source, destination, writable=False):
        source = Path(source)
        target = root / destination.lstrip('/')
        if source.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch()
        command('/usr/bin/mount', '--bind', str(source), str(target))
        if not writable:
            command('/usr/bin/mount', '-o', 'remount,bind,ro,nosuid,nodev', str(target))

    for path in ('/usr/bin','/usr/lib','/usr/share/ca-certificates'):
        bind(path,path)
    if Path('/usr/lib64').is_symlink():
        (root/'usr/lib64').symlink_to(os.readlink('/usr/lib64'))
    elif Path('/usr/lib64').exists():
        bind('/usr/lib64','/usr/lib64')
    for path in ('/lib', '/lib64', '/bin'):
        if Path(path).is_symlink():
            (root/path.lstrip('/')).symlink_to(os.readlink(path))
        elif Path(path).exists():
            bind(path,path)
    for path in ('/etc/ssl/certs', '/etc/ssl/openssl.cnf', '/etc/resolv.conf', '/etc/hosts', '/etc/nsswitch.conf'):
        if path == '/etc/resolv.conf' and not Path(path).exists() and config['execution'] == 'simulated':
            # Private test /run deliberately hides the host resolver symlink.
            (root/'etc/resolv.conf').touch()
        else:
            bind(path, path)
    # Minimal identity metadata for the mapped disposable UID only.  These are
    # generated inside the private root; no host account or sub-ID database is
    # copied.  Empty sub-ID files deliberately grant no subordinate ranges.
    (root/'etc/passwd').write_text('nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n')
    (root/'etc/group').write_text('nogroup:x:65534:\n')
    (root/'etc/subuid').write_text('')
    (root/'etc/subgid').write_text('')
    for name in ('passwd', 'group', 'subuid', 'subgid'):
        (root/f'etc/{name}').chmod(0o644)
    for path in ('/dev/null','/dev/urandom','/dev/random'):
        bind(path, path, writable=True)
    bind(config['runtime_root'], '/cursor-runtime')
    # Keep the durable host workspace path in the request/ledger and preserve
    # that exact absolute name for prompts which carry result/evidence paths.
    # Also expose a short private alias to the vendor. Cursor's trust marker
    # slug replaces separators with hyphens without truncating; a long cwd
    # would exceed Linux NAME_MAX during `.workspace-trusted` creation. Both
    # mounts target the same authorized directory and share its write policy.
    writable = model == 'composer-2.5'
    bind(cwd, cwd, writable=writable)
    bind(cwd, CHILD_WORKSPACE, writable=writable)
    for name in ('tmp','proc','cursor-home','cache'):
        (root/name).mkdir(mode=0o700, exist_ok=True)
    bind(config['auth_file'], '/cursor-home/.config/cursor/auth.json')
    command('/usr/bin/mount', '-t', 'proc', '-o', 'nosuid,nodev,noexec', 'proc', str(root/'proc'))
    pivot_root_into(root)
    os.chdir(CHILD_WORKSPACE)
    libc = ctypes.CDLL(None, use_errno=True)
    # Root inside the jail has no capabilities and cannot acquire them via exec.
    for cap in range(41):
        if libc.prctl(24, cap, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
            raise OSError('cannot drop capability bounding set')
    header = (ctypes.c_uint32*2)(0x20080522, 0)
    data = (ctypes.c_uint32*6)(0,0,0,0,0,0)
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0 or libc.prctl(38,1,0,0,0) != 0:
        raise OSError('cannot drop jail privileges')
    # Cursor's own HTTPS transport needs TCP/443. Other TCP connections and
    # listeners (including host/private PostgreSQL) are denied by the kernel.
    # This is a port boundary, not a claim of domain-level network isolation.
    if libc.syscall(444, 0, 0, 1) < 4:  # landlock_create_ruleset VERSION
        raise OSError('Landlock network confinement unavailable')
    rules=(ctypes.c_uint64*2)(0,3)  # handled TCP bind/connect
    fd=libc.syscall(444,ctypes.byref(rules),ctypes.sizeof(rules),0)
    access=(ctypes.c_uint64*2)(2,443)  # CONNECT_TCP only
    if fd<0:
        raise OSError('cannot create network confinement')
    try:
        if libc.syscall(445,fd,2,ctypes.byref(access),0)!=0 or libc.syscall(446,fd,0)!=0:
            raise OSError('cannot enforce network confinement')
    finally:
        os.close(fd)
    argv = ['/cursor-runtime/'+config['runtime_entry'], '-p', prompt,
            '--output-format','stream-json','--model',model,'--sandbox','enabled','--trust']
    argv += ['--mode','ask'] if model == 'cursor-grok-4.6-high' else ['--force']
    env = {'PATH':'/usr/bin:/bin','HOME':'/cursor-home','CURSOR_HOME':'/cursor-home',
           'XDG_CONFIG_HOME':'/cursor-home/.config','CURSOR_CONFIG_DIR':'/cursor-home/.config/cursor',
           'XDG_CACHE_HOME':'/cache','TMPDIR':'/tmp','LANG':'C.UTF-8'}
    os.execve(argv[0], argv, env)


if __name__ == '__main__':
    request = json.load(sys.stdin)
    enter(request['config'], request['cwd'], request['model'], request['prompt'])
