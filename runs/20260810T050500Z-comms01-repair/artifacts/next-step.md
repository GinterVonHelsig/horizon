Next step: complete the two live transport assertions without touching trading.

1. Send `status` to the dedicated TOP-DELIVERY Signal account and verify the
   reply is produced by the real receive adapter, is sourced from the current
   controller manifest, and is recorded in the adapter audit store.
2. Send `queue-next-prompt`, receive the action-bound challenge, and authorize
   it with the operator's six-digit TOTP within 60 seconds. Verify exactly one
   `pending-parent` intent and reject replay, wrong hash, expiry, and unknown
   sender cases.
3. Re-run the restart and stale-lease drill, then obtain independent review of
   commits 46315c9, cdcb67d, 00714b9, and 7a32615 before deciding transport.

The old run `20260810T004319Z-b626467e` remains immutable and blocked at its
original phase-3A gate. This run records the remediation rather than rewriting
that history.
