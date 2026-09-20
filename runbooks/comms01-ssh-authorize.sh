#!/usr/bin/env bash
set -euo pipefail
key=$(cat /tmp/prod-root.pub)
install -d -m 700 /home/debian/.ssh
touch /home/debian/.ssh/authorized_keys
grep -qxF "$key" /home/debian/.ssh/authorized_keys || printf '%s\n' "$key" >> /home/debian/.ssh/authorized_keys
chown -R debian:debian /home/debian/.ssh
chmod 600 /home/debian/.ssh/authorized_keys
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
grep -qxF "$key" /root/.ssh/authorized_keys || printf '%s\n' "$key" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
rm -f /tmp/prod-root.pub /tmp/comms01-ssh-authorize.sh
