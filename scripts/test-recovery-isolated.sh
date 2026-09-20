#!/usr/bin/env bash
# Fresh network/mount/PID namespaces: never connect to host PostgreSQL or trust files.
set -euo pipefail
if [[ ${1:-} == --inside ]]; then
  echo 'private setup has no public --inside entry point' >&2
  exit 64
fi
export HORIZON_TEST_OUTER_MNT="$(readlink /proc/self/ns/mnt)"
export HORIZON_TEST_OUTER_NET="$(readlink /proc/self/ns/net)"
export HORIZON_TEST_OUTER_PID="$(readlink /proc/self/ns/pid)"
# Every entry goes through the kernel's unshare, even with forged/inherited env.
# The setup body is stdin of the new process, not a re-enterable script branch.
exec unshare --mount --net --pid --cgroup --fork --mount-proc bash -s -- "$@" <<'ISOLATED_TEST_BODY'
set -euo pipefail
# Comparison evidence remains useful, but is not permission to skip unshare.
test -n "${HORIZON_TEST_OUTER_MNT:-}"
test -n "${HORIZON_TEST_OUTER_NET:-}"
test -n "${HORIZON_TEST_OUTER_PID:-}"
test "$HORIZON_TEST_OUTER_MNT" != "$(readlink /proc/self/ns/mnt)"
test "$HORIZON_TEST_OUTER_NET" != "$(readlink /proc/self/ns/net)"
test "$HORIZON_TEST_OUTER_PID" != "$(readlink /proc/self/ns/pid)"
mount --make-rprivate /
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
# Existing mount point required; never copy host credentials into the sandbox.
test -d /etc/top-delivery
mount -t tmpfs -o mode=0755 tmpfs /etc/top-delivery
test -d /var/lib/top-delivery-submission-bundles
mount -t tmpfs -o mode=0755 tmpfs /var/lib/top-delivery-submission-bundles
install -m 600 tests/fixtures/recovery-attestation.json /etc/top-delivery/comms01-attestation.json
mkdir -p /run/postgresql /run/top-delivery
chown postgres:postgres /run/postgresql
ip link set lo up
pgbin=$(pg_config --bindir)
pgdata=$(mktemp -d /tmp/horizon-recovery-pg.XXXXXX)
chown postgres:postgres "$pgdata"
runuser -u postgres -- "$pgbin/initdb" -D "$pgdata" --auth=trust >/dev/null
runuser -u postgres -- "$pgbin/pg_ctl" -D "$pgdata" -l "$pgdata/server.log" -o '-k /run/postgresql -h 127.0.0.1 -p 5432' -w start >/dev/null
trap 'runuser -u postgres -- "$pgbin/pg_ctl" -D "$pgdata" -m immediate -w stop >/dev/null' EXIT
runuser -u postgres -- "$pgbin/createuser" -h /run/postgresql --superuser root
export TOP_DELIVERY_PG_ADMIN_URL='postgresql://root@127.0.0.1:5432/postgres'
export TOP_DELIVERY_OPENROUTER_RELAY_TOKEN_FILE=/tmp/nonexistent-relay
unset TOP_DELIVERY_DATABASE_URL TOP_DELIVERY_ADAPTER_CONFIG TOP_DELIVERY_RUN_ID TOP_DELIVERY_ARTIFACT_ROOT
export PYTHONPATH="$PWD/controller"
export PYTHONDONTWRITEBYTECODE=1
python3 -m pytest "$@"
ISOLATED_TEST_BODY
