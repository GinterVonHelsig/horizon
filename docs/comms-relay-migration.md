# Comms Relay naming, compatibility and deferred deployment

Comms Relay (`comms-relay`) is the shared communications layer across Comms-01/02.
It replaces the architectural name “communications Gateway,” not Gateway Delivery
(`gateway-delivery`), Local Delivery (`local-delivery`), Horizon, or network
gateway `192.168.0.1`. Unified Comms Relay integration remains incomplete.

## Inventory and coverage

`architecture/comms-relay.yaml` is the maintained name/compatibility inventory.
The maintained program test fixture and submission-bundle/runbook descriptions
use Comms Relay. Prior discovery notes explicitly map the old name to the new.
Historical operator artifacts, reviewed hashes, snapshots, error strings, protocol
identifiers and historical evidence are not rewritten. Delivery handoff schemas
`gateway-subworkflow-*` and `gateway-*` provider keys are delivery identifiers,
not communications names. `terra_gateway_mac` describes a network gateway and
is unchanged. This is selective coverage, not a blanket replacement.

## Existing submission paths (neither is a delivery executor)

1. `top-delivery-host-gateway.service` runs
   `/usr/local/lib/top_delivery_host_gateway/server.py`; client
   `/opt/operator-harness/bin/top-delivery-host-gateway`; socket
   `/run/top-delivery-host-gateway/gateway.sock`. It resolves
   `/opt/top-delivery-p1/current/controller/goal_cli.py` for submission.
2. `/usr/local/sbin/top-delivery-submit` imports
   `/usr/local/lib/top-delivery/comms01_submit_gateway.py`; both wrapper/module
   pin `/opt/top-delivery-p1/d7305d4f41ccb7ca451873a5ebe3ece89636fbc5-goal-runner/controller`.
   This differs from the observed current f10c8829 release.

The Unix peer-credential checks, prompt allowlist and digest/attestation checks
must survive migration. Preserve API operations and keys, including the readiness
file `/opt/operator-harness/etc/top-delivery-gateway-readiness.json`. Its enabled
flag is not proof of current controller readiness. No installed change is made.

## Proposed migration — NOT AUTHORIZED FOR DEPLOYMENT

First establish a version-controlled home and provenance for installed transport
sources; independently review the exact source before proposing package changes.
Resolve the old pinned submit path against a separately approved release manifest,
not an arbitrary working tree. Generate both entry points from that same approved
source reference; test inspect/reject/submit argv with fake systemd-run/goal CLI,
without submitting any parked or new production goal.

Introduce `comms-relay` as a new CLI alias in that future package, forwarding to
the same implementation. Keep the old CLI, systemd unit, socket path, API keys,
readiness path and authentication identity until all consumers have been inventoried
and compatibility-tested. Do not start a second listener or create competing
service state merely for naming. If a canonical systemd unit is eventually renamed,
ship an alias and preserve the existing socket as a compatibility endpoint only
after operator approval and a planned maintenance window. Document consumer
cutover separately; no Comms-02 changes are implied by this source rename.

Rollback the future package, wrappers and config together to the captured exact
pre-migration hashes/pin. Keep the legacy endpoint available throughout the
compatibility window; remove only new aliases after consumers revert. Do not
reactivate a controller, resume goals or reset durable execution state during
rollback. This source-only task needs no live database migration or service rollback.

## Remaining gaps

Transport request/run correlation is not wired end-to-end; authentication/grant
references and durable replay/conflict handling still need integration. The new
bounded delivery provider does not implement them. The external installed review
launcher remains untouched; the provider's own executable worker path now owns
its explicit author-aware Cursor review. The external source-owned launcher now
integrates the shared selector/history and has a relocatable package with simulated
entry-point tests; see [reviewer-release-package.md](reviewer-release-package.md).
Installed launcher and consumer cutover remain deferred deployment, not an
unfinished selector source fix.
