Use $terra-delivery and the required role skills.

P1-COMMS01-HERMES-TOP-DELIVERY

Create a separate persistent autonomous run concurrent with the staging run. Install and configure Hermes on comms-01, using the existing dedicated TOP-DELIVERY Signal identity and localhost-only Signal daemon. Connect Hermes to the TOP-DELIVERY controller and its durable run/artifact records.

Implement read-only commands first: current run status, architecture-summary, artifact lookup, active child/run list, latest evidence, and next-step report. Require structured responses with run ID, phase, status, evidence paths, blockers, and next action. Then implement 2FA-protected execution commands, including creation and execution of the next TOP-DELIVERY prompt. Every mutating action must be action-bound, single-use, six-digit, 60-second authorization with replay protection, append-only evidence, allowlist enforcement, and explicit dry-run/target confirmation.

Use comms-01's local RTX 3090 only for approved local inference; do not copy production credentials, broker access, production DB access, or private keys. Keep Signal localhost-only, permit only the verified operator identity, reject groups and unknown senders, and isolate Hermes tools from production mutation. Add service units, restart recovery, rate limits, command audit, child-agent cleanup, and failure-injection tests. Verify Signal delivery, unauthorized sender rejection, expired/replayed/wrong-action codes, daemon restart recovery, read-only status accuracy, and safe command queuing.

Run adversarial review, implementation, disposable validation, authenticated QA and rollback rehearsal. Automatically retry queueable failures and spawn bounded child remediation loops. Never change production, brokers, ledger, network, staging run state, or prior runs. Finish when comms-01 can reliably answer status/architecture queries and safely queue 2FA-authorized TOP-DELIVERY actions; report exact files, service state, tests, evidence and the next outcome.
