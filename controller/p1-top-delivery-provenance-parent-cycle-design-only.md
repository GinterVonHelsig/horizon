# P1-TOP-DELIVERY-PROVENANCE-PARENT-CYCLE-DESIGN-ONLY

Use `$top-delivery` as the project manager and front door, with
`$terra-delivery` as the mandatory child delivery executor and release
authority. Use `$infra-db-and-qa`, `$merge-deploy-verify-rollback`, and the
required role skills.

Read and execute autonomously:

- `/root/TOP-DELIVERY/controller/p1-top-delivery-provenance-cycle-and-staging.md`
- `/root/TOP-DELIVERY/architecture/PRODUCTION-SPLIT-TARGET-ARCHITECTURE.md`
- `/root/TOP-DELIVERY/architecture/TRADING_SYSTEM_ADVANCEMENT_MASTER_PLAN.md`
- `/root/TOP-DELIVERY/architecture/project-status.json`
- `/root/TOP-DELIVERY/architecture/model-routing.yaml`
- the latest Section-0 and Comms-02 SSH/KAT acceptance artifacts.

TOP-DELIVERY owns the project objective, dependency graph, queue, child
leases, retries, evidence index, Signal status and next-outcome decision.
Terra retains authority for infrastructure/database changes, review,
provenance, backup/restore, rollback, merge and release acceptance.

## Required outcomes

1. Reconcile the live Comms-01 wrapper, systemd unit, `WorkingDirectory`,
   `PYTHONPATH`, child processes, manifest and deployed checkout to one exact
   reviewed SHA. Preserve the current accepted release and use timestamped
   backups and predefined rollback.
2. Transport the updated architecture design, project status and model-routing
   documentation through a clean isolated worktree, compact review, exact-SHA
   CI, normal non-force merge and documentation release evidence. Do not
   include unrelated dirty TOP-DELIVERY material or secrets.
3. Prove one disposable parent queue → fenced child lease → fresh Executor →
   Terra delivery → independent Auditor → evidence ledger → parent return cycle,
   including retry, duplicate, stale-lease, restart, cleanup, Signal status and
   rollback assertions.
4. Validate staging capacity, host placement, naming, service boundaries,
   database/coordination contracts and RAM recommendations from the new
   architecture document.

## Explicit no-provisioning boundary

This run is **design and provenance only**. It must not:

- create, clone, delete, resize, repartition or restart any staging VM;
- create `staging-edge-01`, `staging-control-01`,
  `staging-broker-01` through `04`, `staging-db-01`, or
  `staging-coordination-01`;
- change Proxmox allocations, storage, network, routing, VLANs or firewall
  configuration;
- modify production, production PostgreSQL/Redis, brokers, ledger, strategies
  or live engine state;
- change Comms-01/Comms-02 RAM or disk allocation.

The result must be a reviewed, capacity-checked, implementation-ready design
and a later provisioning plan—not a provisioned staging environment.

## Acceptance

Finish only when:

- Comms-01 service metadata and child processes agree on one exact SHA;
- architecture and routing documents are reconciled and transported cleanly;
- the full parent-to-Terra audited return cycle passes independently;
- the multi-VM design uses vendor-neutral broker names and
  `staging-coordination-01`;
- Comms-01 10 GiB and Comms-02 8 GiB recommendations are explicitly marked
  provisional and backed by a measurement plan;
- zero new staging VMs, VM resizes, network changes, production changes,
  broker actions or ledger mutations occurred;
- backups, hashes, rollback and browser/control-plane QA evidence are complete.

Retry routine model, transport, dependency and test failures with compact
packets and preserved evidence. Stop only for wrong-target ambiguity,
credential exposure, provenance/cryptographic failure, unrecoverable
backup/rollback failure or a production-boundary violation. Do not turn
ordinary queueable failures into a terminal blocker.
