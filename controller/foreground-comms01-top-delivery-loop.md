# P1-FOREGROUND-TOP-DELIVERY-COMMS01

Run this outcome in the foreground under TOP-DELIVERY/Terra Delivery. Do not delegate the work into an opaque background run, do not hand off a continuation prompt, and do not stop merely because a routine provider, dependency, test, service, or transport failure occurs. Show each meaningful action, command result, phase transition, retry, acceptance decision, and blocker in the active session.

## Outcome

Make `comms-01` a functioning private TOP-DELIVERY control plane:

1. Connect the real TOP-DELIVERY controller to the existing dedicated Signal account.
2. Install a persistent localhost-only Signal receive/send adapter.
3. Install a persistent Hermes command adapter.
4. Support read-only Signal commands:
   - `status`
   - `architecture-summary`
   - `latest-evidence`
   - `active-runs`
   - `next-step`
5. Support only explicitly authorized, action-bound 2FA queue commands after read-only acceptance passes.
6. Send status updates every 15 minutes and immediately on start, retry, phase transition, acceptance, rejection, stale-worker recovery, and terminal state.

## Foreground execution rules

- Work directly from the accepted isolated worktree for run `20260810T004319Z-b626467e`.
- Preserve all accepted patches and rejected patch evidence.
- Clear stale writer state before each retry and record the reason.
- Use Luna `openai/gpt-5.6-luna` xhigh as the approved fallback for unavailable Cursor capacity.
- Split large work into bounded, testable batches; never accept incomplete or contract-incompatible model output.
- After every batch, run focused tests, compile checks, and a read-only scope audit before continuing.
- Write a status event at least every five minutes. Treat ten minutes without a status event as stale, clear the writer, preserve evidence, and restart the same bounded batch.
- Never claim active progress from a heartbeat alone; verify worker/process activity and artifact freshness.

## Signal and Hermes requirements

- Use only the dedicated TOP-DELIVERY Signal account on `comms-01`.
- Allow only the verified operator identity and pinned Signal identity fingerprint.
- Reject groups, unknown senders, changed fingerprints, malformed envelopes, replayed message IDs, and rate-limit violations.
- Bind every reply to a run ID and evidence paths.
- Never include credentials, TOTP codes, private keys, raw prompts, action payloads or sensitive infrastructure data in notifications.
- Keep transport bound to localhost or the approved private control path.
- Read-only commands must never invoke a shell, model, worker, broker, ledger, database mutation, deployment, or network change.
- Mutating commands must create a 60-second single-use action-bound challenge and return only an inert queue receipt after successful authorization.

## Acceptance loop

Continue visibly through:

1. Existing-interface contract repair.
2. Unit and API tests.
3. Signal envelope, identity, replay, rate-limit and restart tests.
4. Hermes command parser and read-only response tests.
5. Local Unix-socket end-to-end tests.
6. Comms-01 installation and service-start validation.
7. Signal one-to-one status delivery.
8. Authenticated read-only command acceptance from Signal.
9. Expired, wrong-hash, wrong-code, replay and unauthorized-sender rejection.
10. Service restart recovery and stale-worker recovery.
11. Independent review and final foreground QA.

Retry and remediate all routine failures. Create child experiments only when their results are shown and rejoined in the active foreground loop. Stop only for credential compromise, wrong target, data loss, cryptographic failure, rollback failure, or catastrophic infrastructure failure. Do not modify production, brokers, ledger data, production databases, network routing, staging state, origin branches, or prior runs.

## Final report

Show the exact changed files, tests, service units and PIDs, Signal delivery evidence, supported commands, 2FA evidence, rollback state, residual risks, and the next project outcome. A service is not considered functional merely because systemd reports `active`; prove an end-to-end Signal command and response.
