#!/usr/bin/env bash
# Fresh network/mount/PID namespaces: never connect to host PostgreSQL or trust files.
set -euo pipefail
if [[ ${1:-} != --inside ]]; then
  exec unshare --mount --net --pid --cgroup --fork --mount-proc bash "$0" --inside "$@"
fi
shift
mount --make-rprivate /
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
# Existing mount point required; never copy host credentials into the sandbox.
test -d /etc/top-delivery
mount -t tmpfs -o mode=0755 tmpfs /etc/top-delivery
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
python3 -m pytest "$@"
