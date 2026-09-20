# Trading System Advancement — Master Plan

Status: reconstructed canonical roadmap, reconciled 2026-08-18.

This document is the project roadmap and status index. Terra Delivery run
manifests, reviewed SHAs, database/backup evidence and acceptance artifacts
remain release authority. TOP-DELIVERY owns project continuity and next-outcome
selection; it cannot override Terra gates.

## Current anchors

- TOP-DELIVERY `origin/main` is `1616f86c5fae4a0e53e24a264542adeb07b5ab8a`.
- Comms-01 child controller processes execute from the matching clean
  `1616f86c...` checkout; the service unit metadata still requires a separate
  provenance reconciliation before reproducibility is claimed.
- Production is outside this design-only outcome and must not be changed.
- The production-shaped staging topology is documented in
  `architecture/PRODUCTION-SPLIT-TARGET-ARCHITECTURE.md`; no staging VMs have
  been provisioned by this outcome.

## Program tree

```text
Trading Platform Advancement
├─ 0. TOP-DELIVERY/Terra delivery fabric                 ACTIVE/PARTIAL
│  ├─ project state, evidence and next outcome            ACTIVE
│  ├─ durable parent scheduler and child leases            PARTIAL
│  ├─ fresh Executor and independent Auditor              PARTIAL
│  ├─ retry, stale lease, restart and cleanup              PARTIAL
│  └─ exact-SHA, backup, rollback and browser QA           ACTIVE
├─ 1. Production stabilization                            ACTIVE
│  ├─ PostgreSQL authority and broker safety               DONE/PARTIAL
│  ├─ accounting and reconciliation                        ACTIVE
│  └─ canonical reproducibility                            INCONSISTENT until provenance repair
├─ 2. Data architecture                                   ACTIVE/PARTIAL
│  ├─ Alembic ownership/runtime DDL cleanup                ACTIVE
│  ├─ strategy instances, leases and fencing               NOT_STARTED/PARTIAL
│  ├─ intents/events/fills/positions and outbox             PARTIAL
│  └─ Redis/coordination and PostgreSQL HA                 DEFERRED
├─ 3. Production-shaped staging                           NOT_STARTED
│  ├─ edge/control/broker execution cells                  DESIGN COMPLETE
│  ├─ database and coordination tiers                      DESIGN COMPLETE
│  ├─ separate credentials and promotion gates             NOT_STARTED
│  └─ VM provisioning                                      DEFERRED to explicit later outcome
├─ 4. UI/API versus trading-engine separation              NOT_STARTED/PARTIAL
├─ 5. Security, access, audit and recovery                 ACTIVE/PARTIAL
├─ 6. Comms, PMO and operational reporting                 ACTIVE/PARTIAL
├─ 7. Strategy research and GPU workers                    ACTIVE/PARTIAL
└─ 8. Cloud, scale and HA                                 PLANNED
```

## Staging target and naming

The planned vendor-neutral cells are:

- `staging-edge-01`
- `staging-control-01`
- `staging-broker-01` through `staging-broker-04`
- `staging-db-01`
- `staging-coordination-01` (as-built 2026-09-05: NATS JetStream
  `BRIDGE_EVENTS` on VMID 9017 / 192.168.0.108 — message bus, not the books;
  Redis/Valkey omitted. Durable events/intents stay on `staging-db-01`.)

Broker cells are intentionally not named after OANDA, Alpaca, OKX or Binance.
The first assignments are configuration, not infrastructure identity.

## Dependency order

1. Reconcile Comms-01 provenance and prove the parent-to-Terra audited cycle.
2. Validate staging capacity and contracts without provisioning.
3. Provision isolated staging under a separate approved infrastructure outcome.
4. Prove migration, parity, leases, fencing, worker crash recovery and
   rollback in staging.
5. Separate edge/UI/API from control and broker execution cells.
6. Expand security, reporting, research, cloud and HA only after the above
   gates remain green.

## Release rules

No child or model may change acceptance criteria, authority, database target,
broker safety, provenance, backup, rollback or deployment scope. Every release
requires a clean exact-SHA checkout, independent review, disposable
validation, restorable backup evidence and post-deployment acceptance.
