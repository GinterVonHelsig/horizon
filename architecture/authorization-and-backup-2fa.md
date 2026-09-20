# TOP-DELIVERY authorization and backup security

## Decision

Comms-01 will implement authorization as its first functional capability.
The six-digit code authorizes one specific, hash-bound action for 60 seconds.
After a successful `next` authorization, Comms-01 may retain a seven-day
operator session for the low-risk `queue_next_prompt` intent only. That session
is not a general bypass and never replaces broker, database, provenance,
backup, rollback, P0 or P1 gates.

## Authentication flow

1. Top-Delivery creates a challenge containing outcome ID, action ID, scope,
   expiry, and a hash of the exact proposed action.
2. The challenge is sent through Signal to the allowlisted operator identity.
3. The operator supplies a TOTP code from a personal authenticator, or later a
   WebAuthn/passkey assertion, through the authenticated control channel.
4. The server verifies the code, challenge hash, expiry, audience, replay status,
   and authorization policy.
5. The challenge is consumed atomically and cannot authorize another action.
6. The approval and resulting action are recorded in append-only audit evidence.

Signal is the notification and transport channel; it is not treated as the
sole cryptographic second factor. TOTP seed material remains on the personal
authenticator and is not stored in GitHub, Synology, the trading VM, or the
workflow prompt.

## Risk tiers

- Read-only status: authenticated Signal identity; no 2FA required.
- Routine `next` queue requests: one successful TOTP challenge establishes a
  seven-day session for that low-risk intent; the session is persisted,
  audited, scoped to the operator and Comms-01 target, and expires
  automatically.
- P0/P1, production database, deployment, credential, broker or network
  actions: a fresh, explicit action-bound 2FA challenge for each action, plus
  all existing Terra gates. The seven-day session can never satisfy these
  tiers.
- Broker order placement: not authorized by this project and cannot be enabled
  by a 2FA code.

No code, message, model, child agent, or retry loop may mint its own approval.

## Backup key separation

Automated archives do not need the private age identity. Store only the public
age recipient in `/etc/top-delivery/age-recipient.txt` or an equivalent
Synology-mounted configuration path. The private age identity remains offline
or in an operator-controlled recovery location and is required only for
decryption/restore. Restore additionally requires action-bound 2FA.

The current `/root/.config/age/keys.txt` is therefore removed from the daily
archive requirement. It must not be copied to Synology or GitHub.

## Recovery requirements

- two independent recovery administrators or an operator-held recovery key;
- tested TOTP seed backup or passkey recovery;
- offline age identity backup;
- revocation procedure for Signal device, TOTP seed, and sessions;
- a `next` session revocation/expiry check before any future high-impact
  command is exposed;
- rate limiting, replay protection, clock-skew tolerance, and audit alerts;
- restore rehearsal proving the archive can be decrypted and verified.
