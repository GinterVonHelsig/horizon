Use $terra-delivery, $adversarial-review-1, $adversarial-review-2, $code-and-remediation, $infra-db-and-qa, and $merge-deploy-verify-rollback.

P1-TOP-DELIVERY-COMMS01

Read `/root/TOP-DELIVERY/architecture/top-delivery-implementation-spec.md`
`/root/TOP-DELIVERY/architecture/authorization-and-backup-2fa.md`,
`/root/TOP-DELIVERY/architecture/longspan-self-improvement.md`, and
`/root/TOP-DELIVERY/runbooks/vm-creation-standard.md`, then
create one persistent outcome run to implement the controller on an
isolated comms-01 VM on home05. Use the Manager/Executor/Auditor child name
`longspan`; keep Terra Delivery as the sole release authority. Import and
hash historical manifests read-only. Make action-bound 2FA authorization the
first functional delivery item: Signal notifications, personal-device TOTP
or WebAuthn, 60-second single-use challenge expiry, replay protection, and
append-only authorization evidence. Then provision only disposable
PostgreSQL/Redis state, authenticated private messaging, leases, checkpoints,
retry queues, evidence indexing and child cleanup. Configure automated
Synology archives using a public age recipient only; validate encrypted
archive and restore before enabling the daily timer. Publish the private
TOP-DELIVERY GitHub vault and verify private visibility. Run Claude Opus, Fable,
Antigravity Gemini 3.8 Flash (High), Kimi K3 and Qwen reviews with retries and
raw evidence; do not silently substitute incomplete reviewers.

Use the Manager/Executor/Auditor self-improvement loop: every failure becomes
an evidence-backed observation and, where useful, a bounded child experiment;
only the Auditor may update durable state, and no child may alter authority,
acceptance gates, model routing, or production policy.

Do not use production credentials, broker access, production DB, network
changes, or deployment authority. Loop queueable failures and child
remediation automatically. Stop only for wrong-target, credential, cryptographic,
data-loss, rollback or catastrophic infrastructure failure. Finish with the
committed spec, VM/service details, migration/restore/failure-injection tests,
messaging QA, model evidence, rollback evidence and next outcome.

Initial queueable work must include: disposable PostgreSQL/Redis; universal
staging broker isolation; strategy lease enforcement across all engine write
paths; verified read-only database grants; VM100 service/browser validation;
candidate commit/PR/provenance transport; and reconciliation of the reversible
unused-VG change on home05. Treat these as child tasks while retaining
parent-owned target, credential, backup, provenance, rollback and release
gates.
