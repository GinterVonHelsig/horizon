#!/usr/bin/env bash
# Explicit opt-in only. Private DB/network; only Cursor gets host network access.
set -euo pipefail
test "${HORIZON_CURSOR_INCLUDED_ONLY_CONFIRMED:-}" = operator-confirmed-on-demand-disabled
test -n "${HORIZON_PROVIDER_LIVE_EVIDENCE:-}"
test -n "${HORIZON_PROVIDER_CURSOR_EXECUTABLE:-}"
if [[ ${1:-} != --capture && ${1:-} != --inside ]]; then
  exec unshare --mount --pid --cgroup --fork --mount-proc bash "$0" --capture
fi
if [[ ${HORIZON_PROVIDER_CATALOG_ONLY:-} == 1 && $1 == --inside ]]; then
  "$HORIZON_PROVIDER_CURSOR_EXECUTABLE" --list-models
  exit
fi
if [[ $1 == --capture ]]; then
  mount --make-rprivate /
  # Ubuntu's resolv.conf points into /run; retain only that public resolver
  # configuration, not host runtime sockets, trust files or database state.
  exec 9</etc/resolv.conf
  mount -t tmpfs tmpfs /tmp
  mount -t tmpfs tmpfs /run
  mkdir -p /run/systemd/resolve
  install -m 644 /dev/null /run/systemd/resolve/stub-resolv.conf
  # Do not canonicalize the fd back to its now-shadowed pathname.
  mount --no-canonicalize --bind /proc/self/fd/9 /run/systemd/resolve/stub-resolv.conf
  mount -o remount,bind,ro /run/systemd/resolve/stub-resolv.conf
  exec 9<&-
  test -d /etc/top-delivery
  mount -t tmpfs -o mode=0755 tmpfs /etc/top-delivery
  install -m 600 /dev/null /run/horizon-cursor-host-network
  mount --bind /proc/self/ns/net /run/horizon-cursor-host-network
  exec unshare --net bash "$0" --inside
fi
install -m 600 tests/fixtures/recovery-attestation.json /etc/top-delivery/comms01-attestation.json
mkdir -p /run/postgresql /run/top-delivery
chown postgres:postgres /run/postgresql
ip link set lo up
pgbin=$(pg_config --bindir)
pgdata=$(mktemp -d /tmp/horizon-provider-live-pg.XXXXXX)
chown postgres:postgres "$pgdata"
runuser -u postgres -- "$pgbin/initdb" -D "$pgdata" --auth=trust >/dev/null
runuser -u postgres -- "$pgbin/pg_ctl" -D "$pgdata" -l "$pgdata/server.log" -o '-k /run/postgresql -h 127.0.0.1 -p 5432' -w start >/dev/null
trap 'runuser -u postgres -- "$pgbin/pg_ctl" -D "$pgdata" -m immediate -w stop >/dev/null' EXIT
runuser -u postgres -- "$pgbin/createuser" -h /run/postgresql --superuser root
export TOP_DELIVERY_PG_ADMIN_URL='postgresql://root@127.0.0.1:5432/postgres'
export TOP_DELIVERY_OPENROUTER_RELAY_TOKEN_FILE=/tmp/nonexistent-relay
unset TOP_DELIVERY_DATABASE_URL TOP_DELIVERY_ADAPTER_CONFIG TOP_DELIVERY_RUN_ID
export PYTHONPATH="$PWD/controller"
python3 -m pytest -q -ra --tb=short controller/test_bounded_delivery_live.py
