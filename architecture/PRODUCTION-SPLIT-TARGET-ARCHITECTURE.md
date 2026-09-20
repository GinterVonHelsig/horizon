# Production-Split Target Architecture

Status: proposed design plus **as-built staging lab (2026-09-05)**. Production
VM 9005 and live Comms-01 SHA `f2658c33` remain unchanged. Staging guests
9010–9017 exist on home03/home04/home07 only. See also
`/opt/operator-harness/docs/architecture/staging-as-built-20260905.md`.

## Design objective

Separate the trading data plane from the UI/control plane so that UI, API,
authentication, Hermes, Comms, reporting and workflow changes can be developed
and deployed without restarting or mutating live trading engines.

The current production VM remains unchanged until this design is implemented
and proven in a production-shaped staging environment.

## Production-shaped staging topology

```text
                         LAN edge / TLS
                               │
                     staging-edge-01
                         │       │
             read models/API   signed commands
                         │       │
                   staging-control-01
             desired state, scheduler, leases
                         │
                  durable intents/outbox
          ┌──────────────┼──────────────┐
          │              │              │
 staging-broker-01  staging-broker-02  staging-broker-03
     execution cell       execution cell       future venue
          │
 staging-broker-04  future venue / adapter cell

 staging-db-01          durable database source of truth (books)
 staging-coordination-01 message bus (not the books)
```

The broker names intentionally describe execution cells rather than vendors:

- `staging-broker-01`
- `staging-broker-02`
- `staging-broker-03`
- `staging-broker-04`

The first two cells may initially host the OANDA and Alpaca adapters, but the
VM identities must not encode those vendors. Cells can later be reassigned or
replaced without renaming infrastructure or changing the control-plane model.

The database name is `staging-db-01`, not `staging-postgres-01`, because the
durable store may later be PostgreSQL-compatible managed storage or a cluster.

The coordination service is `staging-coordination-01`, not
`staging-redis-01`, because Redis is an implementation choice. As-built
2026-09-05: Redis/Valkey is **omitted**. `staging-coordination-01` (VMID 9017,
192.168.0.108, home04) is the **message bus**, not the books. Postgres on
`staging-db-01` (VMID 9016, 192.168.0.107, home04, database `orb_bot_staging`)
is the source of truth (events, later intents/fills/positions). 9017 is
ephemeral coordination: pub/sub, so control, edge, and broker cells can hear
the same stream without calling each other. Today that is **NATS JetStream**
(`BRIDGE_EVENTS` / `BRIDGE.events.>`). Locks, heartbeats, and fanout belong
here. **Orders and balances do not.**

A runtime proof must hit **both** 9017 (NATS consume) and 9016 (new row). If
9017 were gone, cells would have no shared live stream. If you used it as the
database, a NATS restart would lose trading truth. Proven
`PASS_STAGING_RUNTIME_PROVEN` on 2026-09-05 (event
`411f68be-dea1-4439-a994-202638dc4439`).

## Production target naming

The eventual production cells should follow the same vendor-neutral pattern:

- `production-edge-01` and later `production-edge-02`;
- `production-control-01`;
- `production-broker-01` through `production-broker-04`;
- `production-db-01` and later a replica/HA pair;
- `production-coordination-01` and later a redundant coordination pair.

Comms-01 remains the external workflow/control-plane VM. It must not be part
of the broker execution data plane and must not hold production broker
credentials.

## Service boundaries

1. Edge: TLS, reverse proxy, UI, API, authentication and read-model access.
2. Control: scheduler, desired strategy state, worker leases, emergency stop,
   fencing and signed command dispatch.
3. Broker cells: strategy runtime, market-data adapter, risk gate and broker
   submission boundary for one execution cell at a time.
4. Reconciliation: broker truth versus durable intent/event/position truth.
5. Database: durable state, order intents, broker events, fills, positions,
   audit and migration-owned schema.
6. Coordination: ephemeral locks, lease cache, heartbeats, rate limits and
   fanout only. As-built: NATS JetStream on 9017. Not order/balance truth;
   that stays on `staging-db-01`.

The UI must never call a broker directly. A UI action becomes an authenticated
and scope-bound command; the control plane validates it and emits a durable,
idempotent intent. Broker cells submit only fenced intents and record
acknowledgment, rejection, unknown and fill events. Reconciliation must repair
unknown states rather than silently ending a pipeline.

## Comms memory recommendation

The current single-GPU Comms-01 workload does not inherently require 20 GiB of
guest RAM. The Qwen3.8-27B Q4 model is primarily constrained by the RTX 3090's
24 GiB VRAM; guest RAM covers Ollama/runtime overhead, KV spill, Open WebUI,
Hermes, controller services, logging and concurrent requests.

Recommended starting allocations, subject to measurement:

- Comms-01: **10 GiB RAM**, 4 vCPU. This is the preferred lower allocation for
  one GPU and Qwen only. Eight GiB is possible only after proving that the
  model remains fully GPU-resident and controller/browser workloads do not
  swap or OOM.
- Comms-02: **8 GiB RAM**, 4 vCPU. This is a reasonable minimum for KAT-Coder
  on one RTX 3090 Ti with bounded coding requests. Ten to twelve GiB is more
  comfortable when tests, compilers or concurrent requests run inside the VM.

The former 20 GiB Comms-01 allocation was conservative headroom from the
dual-GPU and local-model experiments, not a demonstrated requirement. It may
be reduced only after recording host/guest memory, GPU residency, swap, OOM,
latency and concurrent-request evidence, with a reversible VM configuration
backup. No resize is authorized in the current architecture-review outcome.

## Capacity and placement rule

The architecture is multi-VM, but home05 must not be overcommitted. Based on
the last recorded inventory, home05 has 32 GiB host RAM and Comms-01 has used
approximately 20 GiB. A full eight-VM staging topology therefore requires a
fresh capacity inventory and either distribution across hosts or additional
capacity. The next run may produce a placement/resource plan, but may not
create or resize staging VMs.

## Migration sequence

1. Prove contracts, schemas, leases, fencing and emergency controls in an
   isolated harness.
2. Validate this topology and resource plan without provisioning.
3. Provision the production-shaped staging cells only under a later explicit
   infrastructure outcome.
4. Extract edge/UI/API from the monolith.
5. Extract control/scheduler and durable desired state.
6. Run broker cells in no-broker mode, then with practice credentials.
7. Promote one execution cell at a time through exact-SHA staging gates.
8. Operate with a burn-in and rollback window before retiring the monolith.

No production split, broker migration, network redesign or VM creation is
approved by this design document.
