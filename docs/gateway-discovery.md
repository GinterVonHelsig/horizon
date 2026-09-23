# Gateway discovery — Comms-01, 2026-09-20

Naming update, authorized after this discovery: the shared communications layer
is **Comms Relay** (`comms-relay`). Gateway Delivery remains `gateway-delivery`.
Historical architecture quotations, installed interface names and hashes below
are retained as evidence, not current naming recommendations. See
[Comms Relay migration](comms-relay-migration.md). The bounded disposable provider
implementation is documented in [its contract](bounded-delivery-provider.md);
the absence findings below describe the discovery baseline, not later source.

## Finding and scope

The remembered architecture has documentary support, but **communications
Gateway**, **Gateway Delivery**, and Horizon's **adapter identifiers** are
different contracts. There are real implementations of individual pieces, not
evidence of one completed shared service or executable delivery provider.
No production call, controller submission, live database inspection, model call,
service mutation or installed-file repair was used in this discovery.

Source baseline: GinterVonHelsig/horizon
`cdd7989cbc332293a823b4d4bdb60ea056b3986c`, branch
`codex/repair-horizon-recovery`, PR #1. The discovery follow-up at
`5114ab118dd3aa73f3373eb085b631b2f403545d` changed only documentation, tests and CI.
Later commits add runtime provider code; the earlier independent runtime review
does not cover those later changes.

## Intent versus implementation

The local archived specification
`/opt/operator-harness/artifacts/20260909T-gateway-horizon-v1-program-baseline/horizon-v1-contract.md`
labels itself **1.0.0-draft, specification baseline — not runtime qualification**.
Its section 3 explicitly assigns:

| Component | Responsibility |
| --- | --- |
| Horizon Cascade | Program/dependency decisions, delegation, evidence adoption and completion |
| Gateway Delivery | Phases 0–7.5, independent reviews, release/rollback and delivery receipts |
| Local Delivery / other execution profiles | Bounded implementation, no self-acceptance |
| Longspan | Durable task/attempt execution and audit |
| Communications gateway | Authenticated transport, correlation, status/Q&A/2FA delivery |

Section 7 specifies run/request correlation. The adjacent historical
`master-program-v1.md` marked communications ATS-COM-001 partial and Gateway
subworkflow ATS-DEL-002 candidate/not deployed. Those are historical dispositions,
not an assertion that the later correlation or handoff code is absent.
The September 8 naming-lock design in
`/opt/operator-harness/docs/superpowers/specs/2026-09-08-horizon-cascade-naming-lock-design.md`
is a naming change, not a repository/service migration. Archived instructions
and demonstration prompts were read as evidence, not invoked.

## Concrete implementations and provenance

| Component | Actual implementation / entry point | Observed limitation |
| --- | --- | --- |
| Host submission gateway | `/usr/local/lib/top_delivery_host_gateway/server.py`, `/opt/operator-harness/bin/top-delivery-host-gateway`, `/etc/systemd/system/top-delivery-host-gateway.service` | Unix-socket operations health/inspect/submit/execute-recovery; delegates goal CLI through systemd-run; not an executor/reviewer |
| Separate submission CLI | `/usr/local/sbin/top-delivery-submit` imports `/usr/local/lib/top-delivery/comms01_submit_gateway.py` | Pins old d7305d4f controller path, unlike socket gateway's `current`; confirmed source split, not proof of a particular runtime failure |
| Gateway Delivery | `/opt/operator-harness/homes/.codex/skills/gateway-delivery/SKILL.md` | Coordinator instructions, not registered executable; stale August model prose is not September runtime-policy proof |
| External review launcher | `/opt/operator-harness/bin/openrouter-review` → `/opt/operator-harness/lib/top_delivery_host_review/host_openrouter_review.py` | Real Cursor/OpenAI/OpenRouter transport code, but direct phase-seat/fallback iteration; Horizon selector/history integration still absent |
| Local Delivery candidate | `/opt/operator-harness/worktrees/20260826T-local-delivery-integration/goal-runner/controller/local_delivery/` | Real callback sequencer and writer lease; candidate registry explicitly `not_live_runtime_registry: true`; not in reviewed Horizon tree or searched active skill directories |
| Auth service | `/opt/top-delivery-auth/app.py` | Installed challenge/authorization/attestation endpoints; different from tracked `control-plane/app.py`, not a universal delivery API |
| Signal/Hermes integration | Horizon `control-plane/signal_adapter.py`, `hermes_adapter.py`, `controller/parent_socket.py` | Controller wire schema is exactly text/sender_id/is_group; it does not carry Horizon correlation request IDs |
| Durable correlation | `controller/correlation_store.py`, `ParentController.record_correlation_status/get_correlation_status`, migrations 016/020 | Real database-backed library; no transport call site found for these ParentController methods outside tests |
| Prerequisite handoff | `controller/subworkflow_handoff.py`, `parent_controller.py` | Real request/product contracts, persistence and fencing; rejects missing executable bindings before creating a provider task |

The installed Hermes framework at `/opt/hermes-local/src` reports package
`hermes-agent` 0.20.0. It is not the entry point in
`top-delivery-hermes.service`, which runs the thin custom control-plane adapter.
Package presence is not evidence of an integrated shared Gateway service.

No Git metadata was found for the installed host gateway, operator-harness root,
the inspected historical Local Delivery candidate, or the Hermes source copy.
Accessible repository-name inventory found Horizon and TOP-DELIVERY, not an
authoritative Gateway repository. This is a provenance limitation, not a claim
that no inaccessible repository exists. Installed source digests are therefore
more defensible than inventing a Git version:

| Source | SHA-256 |
| --- | --- |
| Host gateway server | `a885084e939ef493e07e65c6ac1d4244425363da774ea3bc33744388a364f9cf` |
| Separate submit module | `f208b237907b1a0939e6efd76c9e70bb32d9ab8d023100c1c791e5724d555117` |
| Gateway Delivery skill | `1f1bbbfe162a19afb43d940f1bb8d646a0701a020b630bc74d3ed11b6d388af8` |
| External review launcher | `469197b9d6c4385c3787bb243addd8697383b78da2bbd430f3e1fd1638c5e4c9` |
| Local Delivery team.py candidate | `3da3f3db320e633e946148071440d156817e69c6abbebc8388ab6b4b53a16732` |
| Installed auth app | `8fbcc59716fd412b3cffbae250aa0d154d85ea1453d10b942f96a5d0abb5f511` |

## Earliest missing integration boundary

Runtime `/etc/top-delivery/adapters.json` registers codex-cli, cursor-cli,
cursor-grok, cursor-luna and openrouter-claude-auditor. Its default pair is
cursor-cli/openrouter-claude-auditor. It registers neither `gateway-delivery`
nor `openrouter-independent-review`. The latter are requested by the Horizon
prerequisite provider contract, not names of installed services.

`ParentController.create_subworkflow_handoff` validates these routes before
writing the handoff request or scheduling its provider task. That is the earliest
demonstrated blocking boundary for this configuration. A host submit command
cannot satisfy it: it submits another goal, rather than consuming the bounded
HarnessRequest and returning the required product, execution identity and review
evidence. A skill name or a model alias is equally insufficient. No substitution
or registration was made.

The host readiness file currently says durable submissions enabled while the
Horizon controller is inactive. That historical readiness flag is not live
execution qualification. It was not changed. Likewise, the pinned d7305d4f
submit wrapper is a separate deployment inconsistency; it does not explain away
the missing provider binding.

## Smallest coherent implementation, and what needs a scope decision

Two separable integrations are missing; neither should masquerade as the other.

**Bounded Horizon delivery provider (necessary for the requested prerequisite).**
Version a real provider in Horizon or an explicitly owned integration repository.
Implement the existing request/product and executor lifecycle contracts using
the current durable task/intent/lease machinery, rather than a recursive goal
submission. It needs a bounded phase journal, authorized workspace/scope checks,
real execution and independently selected review seats, passing prior verdicts,
trusted author/history evidence, exact artifact/request binding, cancellation,
timeout/attempt limits and uncertain-outcome reconciliation. Produce a delivery
receipt and handoff product only after the required phases pass. Register both
provider and review routes only after implementation/capability validation.
The existing worker's one-task review is useful infrastructure, not proof of the
full Gateway Delivery phase contract. No new PostgreSQL schema is established
as necessary by this discovery; design against existing durable state first.

Proposed source surface: a new bounded provider module under `controller/`, an
explicit adapter implementation under `controller/harness_adapters/`, capability
admission in its registry, and provider lifecycle/receipt tests. Keep the existing
`subworkflow_handoff.py` binding and validation as the receiving contract. The
external launcher's source must first have an agreed version-controlled home;
then replace its independent `seat_chain` decisions with the shared selector and
verified completed history. Do not patch its installed copy. Model availability
and subscription/billing eligibility must be checked separately from registration.

**Shared communications integration (separate from executing the prerequisite).**
Version the installed transport sources before deployment changes. Define an
authenticated, versioned envelope carrying operator/run/request identity; wire
Signal/Hermes/host callers to durable correlation with request-content conflict
checks and restart/replay tests. Connect challenge/grant references without
putting secrets in receipts; retain scope/TTL/reuse restrictions and explicit
unresolved policy choices. Reconcile the two host submission source paths in a
separate proposed deployment change. Existing Signal/auth code and persistence
can be reused; a new universal communications platform is not a prerequisite for
a disposable Horizon child-task demonstration.

Building either cross-component integration is substantive new implementation,
not repairing an adapter spelling. Recommended decision: authorize the bounded
provider first, preserving Gateway's required phase/review gates; keep shared
communications convergence as a separate source-owned work item. The proposed
provider implementation, external review-launcher ownership/selector integration,
and qualification tests must be reviewed before installation. This discovery
does not authorize production activation or replace that decision with an alias.

## Reproduction and regression changes

Initial private-PostgreSQL run: correlation test passed; prerequisite positive
test failed with `ValueError: missing adapter configuration for executable task`.
Earliest boundary: its ParentController fixture omitted adapter configuration.
This was an outdated fixture, not a reason to remove route validation.

The fixture now explicitly uses `test_only.recovery_fakes.route_config` under
the contract's route names. No fake implementation is installed or exported to
runtime. Negative tests cover no configuration and an unrelated configured pair:
both must leave zero handoffs, zero child tasks and no handoff directory.
The original parent task is preserved. Positive idempotence and correlation
tests, plus both missing-binding cases, are added to disposable CI.

The expanded local suite passed **148 tests**, including existing recovery,
worker, submission and provider-contract coverage plus isolated Signal/auth
checks. There were no skips in this run; two pre-existing Python tar extraction
deprecation warnings remain. The narrow before/after result was 2 passed / 1
failed, then 5 passed with the added negative cases. No network-connected adapter
was used. The required focused CI list also passed locally: **549 passed,
1 skipped** (the explicit PostgreSQL two-cluster rehearsal is opt-in; not rerun
for this test/docs-only change). Prior cdd7989 evidence covers that rehearsal,
not this follow-up commit. Reproduction from the checkout:

```sh
rtk proxy bash scripts/test-recovery-isolated.sh -q -ra --tb=short \
  tests/test_review_remediation.py tests/test_comms01_release_deploy.py \
  tests/test_worker.py tests/test_worker_cleanup.py \
  tests/test_worker_integration.py tests/test_worker_service.py \
  tests/test_goal_submitter.py controller/test_recovery_acceptance.py \
  controller/test_subworkflow_handoff.py \
  controller/test_subworkflow_handoff_integration.py \
  controller/test_correlation_store_integration.py \
  controller/test_prerequisite_orchestration_integration.py \
  control-plane/tests/test_signal_bridge.py control-plane/tests/test_authorization.py
```

The historical baseline-file comparison remains a local check because it reads
an operator artifact outside the checkout. CI selects the portable integration
tests explicitly, rather than weakening or silently skipping that assertion.
These are **simulated binding/persistence tests**, not live Gateway validation.
Test evidence is in `/opt/operator-harness/artifacts/20260920-gateway-discovery/`.

## Preserved state and activation

Comms-01 `/opt/top-delivery-p1/current` still resolves to
`/opt/top-delivery-p1/f10c88295daec8bc45f636c4fbac41ad67209475-goal-runner`.
`top-delivery-controller.service` and `top-delivery-supervisor.service` are
inactive/dead; `top-delivery-worker.service` is failed/stopped. Existing
`top-delivery-host-gateway.service`, `top-delivery-auth.service` and
`top-delivery-signal-daemon.service` are active and were preserved.
`top-delivery-signal-adapter.service` and `top-delivery-hermes.service` are inactive.
No parked goal, deployed file, `/opt/top-delivery-auth`, live database or Quant
infrastructure was changed. No billing call was made.

There is nothing to activate from this documentation/test-only follow-up and no
schema rollback. Reverting its commit removes only its tests/docs/CI additions.
The broader conditional activation/rollback procedure remains
[recovery-activation.md](recovery-activation.md); its unresolved integration and
live-validation gates remain closed. The independent review of cdd7989 is not
represented as a review of a later commit.
