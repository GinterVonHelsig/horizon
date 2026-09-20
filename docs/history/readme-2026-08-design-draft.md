# Historical README (August 2026 design draft)

Parked on 2026-09-07 when the repository homepage was rewritten as a
walk-away product page. Kept for paper trail only. Names, model pins, and
status in this file are obsolete.

---

# TOP-DELIVERY

Top-delivery is the project-level outcome controller for the trading-platform
program. It owns long-horizon planning, dependency tracking, task leases,
questions, recommendations, and evidence indexing. It does not own release
authority.

The release boundary remains `$terra-delivery`. Production database, broker,
provenance, backup, rollback, merge, deployment, and acceptance gates remain
enforced there.

## Controller hierarchy

```text
TOP-DELIVERY / Outcome Controller
  ├─ Project Manager: objective, roadmap, dependencies, questions, priorities
  ├─ Queue: typed tasks, retries, child leases, checkpoints, parked work
  ├─ Evidence index: immutable artifact references and status reconciliation
  └─ Child lifecycle: start, pause, resume, retry, audit, close, reap
       ↓
  TERRA-DELIVERY / Release Authority
       ├─ delivery phases, model routing, exact-SHA transport
       ├─ backup, broker, database, provenance, rollback and deployment gates
       └─ final acceptance authority
            ↓
  LONGSPAN / Isolated Task Loop
       ├─ Manager: decompose one queueable task
       ├─ Executor: perform isolated work
       └─ Auditor: verify the task and produce raw evidence
```

`longspan` is the selected name for the adapted LongHorizon-style child.
Alternatives considered: `longarc`, `longscope`, `longbridge`, and `longforge`.

## Current status

This directory contains the design and implementation authority draft only.
The historical `/root/.codex/sol-runs` directory remains untouched and is the
source of prior evidence. No production, broker, database, VM, or network
mutation is authorized by this design artifact.

The private GitHub mirror is:

`https://github.com/GinterVonHelsig/TOP-DELIVERY`

The daily Synology archive job is included in this repository, but activation
is pending validation of the operator-provided age identity. The current
`/root/.config/age/keys.txt` does not parse as an age identity, so encrypted
archiving is intentionally not enabled until that key is corrected.

Model-call accounting is defined in
`runbooks/model-call-accounting.md`. Reviewer attempts are recorded in an
append-only, redacted ledger with UTC timestamps and a checkpoint every ten
calls; the ledger is separate from raw model artifacts and never stores
prompts, response bodies or credentials.

Comms-01 now provides the bounded local coding companion defined in
`architecture/model-routing.yaml`. The active route is the pinned
Qwen3.8-27B Q4_K_M Ollama model. It handles mechanical Longspan execution,
artifact/test triage, documentation, status formatting, and evidence indexing.
It has no authority over acceptance criteria, brokers, databases, migrations,
releases, or final review; ambiguous work escalates to Cursor and still passes
Terra's normal gates. The previous Qwen3-Coder and Qwen2.5-Coder local routes
remain documented as restore-by-repull options, not silently active fallbacks.

## Model placement

```text
Terra Manager / coordinator
        ↓ bounded-task classification
Comms-01 Ollama — Qwen3.8-27B Q4_K_M
        ↓ persisted analysis packet + digests
Comms-02 Ollama — KAT-Coder V2.5 Q4
        ↓ isolated implementation + focused tests
Independent Terra Auditor
        ↓ if Terra is unavailable: Claude Opus 5, then Claude Fable 5
Terra release, provenance, rollback and deployment gates
```

Qwen3.8 and KAT-Coder form a coordinated Executor team, not a second release
authority. Qwen prepares the task packet and KAT performs bounded isolated
implementation; they never write the same worktree concurrently. The
deterministic controller owns leases, retries, evidence and terminal state.
Only an independent Auditor can record task completion, and Terra remains the
authority for migration, broker, provenance, rollback, merge, deployment and
acceptance decisions.

## First implementation target

Deploy the controller and evidence index on `comms-01` as a control-plane
service. Telegram or Signal may be added as authenticated message transports,
but they can submit intents and read status only. They cannot directly approve
or bypass release gates.
