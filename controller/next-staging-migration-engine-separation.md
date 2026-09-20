Use $terra-delivery and the required role skills.

P1-STAGING-MIGRATION-ENGINE-SEPARATION

Create one persistent autonomous run for the next major outcome: reproducible staging on home05 and independent UI/API versus trading-engine operation.

Read the current master architecture documents, TOP-DELIVERY state, and latest run artifacts. Generate the complete internal workflow under the new run artifacts directory. Provision only isolated staging resources on home05, resource-safe and separate from production: VM, PostgreSQL, Redis namespace, secrets, service names, and broker simulation credentials. Use the VM creation standard: IDs in the 9000 range, standard VGA/SSH console, qemu guest agent, static host identity, and no serial-only console.

Implement and verify strategy-instance identity and leases, PostgreSQL/SQLite parity gates, Alembic-only ownership, Redis coordination and restart durability, worker crash recovery, durable fencing, emergency stop/resume/cancel/flatten semantics, and exact-SHA staging-to-production promotion. Separate UI/API/Auth from the trading engine so UI changes do not restart or mutate engine state. Add no-broker adapters, readiness endpoints, failure-injection tests, rollback rehearsal, and authenticated browser QA.

Use Claude and Fable adversarial review, Cursor for isolated code, Terra for disposable infrastructure, Luna for release orchestration, and Chromium for QA. Retry queueable failures and spawn bounded child remediation loops; only the Auditor may mark durable acceptance state. Preserve evidence, hashes, backups, provenance, and rollback throughout.

Never use production credentials in staging, place broker orders, mutate production DB/ledger/strategy state, change network configuration, deploy unreviewed code, or weaken cryptographic, wrong-target, backup, rollback, or provenance gates. Do not promote to production until every staging assertion passes. Continue until staging is reproducible and the exact reviewed release package is promotion-ready; finish with the run ID, VM/database details, SHAs, tests, rollback evidence, residual risks, and next outcome.
