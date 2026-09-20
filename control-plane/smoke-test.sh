#!/usr/bin/env bash
set -euo pipefail
set -a
. /etc/top-delivery/auth.env
set +a
h=$(printf '%s' test-action | sha256sum | cut -d' ' -f1)
payload=$(printf '{"action_id":"test-action","action_hash":"%s","scope":"test"}' "$h")
r=$(curl -fsS -H "X-Internal-Token: $INTERNAL_TOKEN" -H 'Content-Type: application/json' -d "$payload" http://127.0.0.1:8787/v1/challenges)
id=$(printf '%s' "$r" | jq -r .challenge_id)
code=$(/opt/top-delivery-venv/bin/python -c "import pyotp; print(pyotp.TOTP('$TOTP_SECRET').now())")
auth=$(printf '{"code":"%s","action_hash":"%s"}' "$code" "$h" | curl -fsS -H "X-Internal-Token: $INTERNAL_TOKEN" -H 'Content-Type: application/json' -d @- "http://127.0.0.1:8787/v1/challenges/$id/authorize")
test "$(printf '%s' "$auth" | jq -r .authorized)" = true
replay=$(printf '{"code":"%s","action_hash":"%s"}' "$code" "$h" | curl -s -o /dev/null -w '%{http_code}' -H "X-Internal-Token: $INTERNAL_TOKEN" -H 'Content-Type: application/json' -d @- "http://127.0.0.1:8787/v1/challenges/$id/authorize")
test "$replay" = 409
echo 'challenge_authorization=pass replay_protection=pass'
