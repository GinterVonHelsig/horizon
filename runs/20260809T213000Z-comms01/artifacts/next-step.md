# Next step: Comms-01 action-bound 2FA

## Current verified state

- Comms-01: VM9104 on home05.
- Static address: `192.168.0.91`.
- SSH: verified with run-scoped known hosts.
- Console: standard VGA; no `serial0`.
- RTX 3090 passthrough and CUDA/PyTorch: verified.
- TOP-DELIVERY private vault and Synology encrypted archives: verified.
- Production, broker, ledger and network trading state: unchanged.

## Proposed work

1. Install the Comms-01 control-plane service.
2. Implement Signal notification and allowlisted operator identity.
3. Implement TOTP or WebAuthn action-bound authorization.
4. Enforce 60-second expiry, one-time consumption, replay protection and
   challenge/action hash binding.
5. Store only non-secret authorization metadata in PostgreSQL.
6. Keep TOTP seed/passkey material on the operator device.
7. Add read-only status, question, pause and resume commands.
8. Ensure deployment, database, credential and infrastructure actions require
   2FA plus Terra’s existing gates.
9. Prohibit broker-order authorization through Comms-01.
10. Test restart recovery, duplicate messages, expired codes, wrong action
    hashes, rate limits, audit evidence and rollback.

## Acceptance

- Valid code authorizes only its exact action.
- Expired, reused, wrong-scope or wrong-hash codes fail.
- No secret is written to GitHub, Synology, production or the prompt.
- Signal notifications reach only the allowlisted operator.
- Restart preserves audit and pending-state safety.
- No broker, ledger, production database or network mutation occurs.

## Short execution prompt

```text
Use $top-delivery and the required role skills.

Read this next-step artifact and implement Comms-01 action-bound 2FA on VM9104.
Use Signal for notifications and personal-device TOTP or WebAuthn for 60-second
single-use challenges bound to the exact action hash. Add audit evidence,
replay protection, restart recovery, rate limits and rollback tests. Keep Terra
as release authority; never authorize broker orders or bypass database,
credential, provenance, backup or rollback gates. Loop routine remediation and
finish with verified authenticated messaging and acceptance evidence.
```

## Decision

Proceed? **[YES / NO]**
