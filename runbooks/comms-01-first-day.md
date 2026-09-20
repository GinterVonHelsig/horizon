# comms-01 first-day runbook

## Before provisioning

- Confirm home05 capacity, storage, CPU and memory reservations.
- Select a non-conflicting IP from the existing subnet; do not create a new
  subnet or alter routing.
- Confirm the VM is isolated from production database and broker credentials.
- Create an encrypted Synology backup target and test restore.

## VM services

- `top-delivery-controller`: queue/checkpoint/state API;
- `top-delivery-worker`: leased child execution;
- `top-delivery-notifier`: Telegram/Signal outbound notifications;
- optional reverse proxy only on the private management boundary.

## Remote access

Use a dedicated Telegram bot or Signal identity, allowlisted to the operator.
Store no broker credentials in the bot environment. Every command carries an
authenticated principal, idempotency key and audit record.

## Acceptance

- reboot preserves queue, leases and evidence;
- duplicate message does not duplicate work;
- expired lease is fenced and safely reclaimed;
- notification retry is idempotent;
- PostgreSQL restore reproduces the controller state;
- child completion cannot declare release completion;
- production remains untouched in all tests.
