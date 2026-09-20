#!/usr/bin/env bash
set -euo pipefail

VENV=/home/debian/preset-worker-venv
sudo "$VENV/bin/pip" install pyotp psycopg2-binary fastapi uvicorn
sudo -u postgres createuser --createdb topdelivery_auth 2>/dev/null || true
sudo -u postgres createdb -O topdelivery_auth top_delivery_auth 2>/dev/null || true
dbpass=$(openssl rand -hex 24)
internal=$(openssl rand -hex 32)
totp=$($VENV/bin/python -c 'import pyotp; print(pyotp.random_base32())')
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER ROLE topdelivery_auth PASSWORD '$dbpass';"
sudo install -d -m 0755 /opt/top-delivery-auth
sudo tar -xzf /tmp/top-delivery-auth.tgz -C /opt/top-delivery-auth --strip-components=1
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin topdelivery 2>/dev/null || true
sudo chown -R topdelivery:topdelivery /opt/top-delivery-auth
sudo install -m 0644 /opt/top-delivery-auth/top-delivery-auth.service /etc/systemd/system/top-delivery-auth.service
sudo install -d -m 0750 /etc/top-delivery
sudo sh -c "printf '%s\\n' 'DATABASE_URL=postgresql://topdelivery_auth:$dbpass@127.0.0.1:5432/top_delivery_auth' 'INTERNAL_TOKEN=$internal' 'TOTP_SECRET=$totp' > /etc/top-delivery/auth.env"
sudo chmod 0640 /etc/top-delivery/auth.env
sudo chown root:topdelivery /etc/top-delivery/auth.env
sudo sed -i 's#EnvironmentFile=/etc/top-delivery/auth.env#EnvironmentFile=/etc/top-delivery/auth.env#' /etc/systemd/system/top-delivery-auth.service
sudo systemctl daemon-reload
sudo systemctl enable --now top-delivery-auth
sudo systemctl is-active top-delivery-auth
