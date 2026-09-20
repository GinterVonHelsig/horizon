# Bounded Gateway Delivery provider — implementation contract

Authorized 2026-09-20. This is direct Codex development on Comms-01, not a
submission to a delivery controller. Comms Relay communications integration is
separate. Installed files, services, parked goals and Quant are out of scope.

## Interface and acceptance recorded before implementation

The first supported profile is `gateway-delivery-disposable-file.v1`: deliver
one explicitly specified UTF-8 file inside a fresh disposable task workspace.
It is deliberately not a general release/deployment workflow. Unsupported
profiles fail; this does not claim full Gateway Delivery phases 0–7.5.
The operator-approved specification supplies filename and expected content;
its digest must appear in the immutable prerequisite handoff context alongside
the prerequisite node ID. No executable test commands or production targets
are accepted by this profile.

Sequence: validate request/spec/scope/routes -> durable execution intent ->
Cursor implementation -> deterministic exact-file acceptance -> independent
read-only Cursor review of bound evidence -> deterministic product/receipt ->
Horizon fenced handoff finalization. No self-authored PASS product substitutes
for independent review. No model fallback, automatic remediation or second
execution after an uncertain outcome. Horizon retains claim, lease, epoch,
intent and cleanup ownership; no nested parent submission is used.

Executable IDs: `gateway-delivery` (new bounded provider implementation, not the
host submission command) and `cursor-independent-review` (explicit Cursor
transport). Existing legacy OpenRouter-named requests remain legacy and are
not silently interpreted as Cursor. New profile selection is digest-bound.

Required tests: valid end-to-end task/product/finalization; absent route,
wrong profile/spec/digest, wrong-provider product, reviewer-author collision,
rejection/malformed result, artifact mutation, paused run, duplicate execution,
worker death/uncertain outcome and restart; truthful terminal state and bounded
timeouts. Model calls in deterministic tests must be labeled simulated.
Live proof requires separately recorded included-subscription calls, with
On-Demand disabled as confirmed by the operator; no OpenRouter calls.

Review history must derive from actual execution identity and persisted result
digests. An uncompleted or rejected review cannot authorize product publication.
The existing full workflow's prior-review gate remains intact; this profile
has one required code-review seat, not fabricated proposal review approvals.

## Naming inventory (before edits)

- Shared communications role: `Communications gateway + auth` in maintained
  program fixture; canonical new name **Comms Relay**, technical `comms-relay`.
- Submission transport: `top-delivery-host-gateway` command/service/socket and
  separate `top-delivery-submit` are compatibility interfaces, retained.
- `gateway-delivery`, `gateway-subworkflow-*`, provider keys and product schemas
  describe the delivery workflow, not communications; retained.
- `terra_gateway_mac` and `192.168.0.1` describe the network gateway; retained.
- Historical artifacts, source hashes, prior diagnosis and quoted architecture
  names remain evidence. Maintained documentation gets an explicit mapping,
  not a retrospective rewrite of those records.
- Local Delivery/local-delivery and Horizon are unchanged. No Comms-02 host
  mutation or unified Comms Relay implementation is authorized.

Deployment remains prohibited; compatibility/migration instructions will be
recorded separately. New source defaults are not installed configuration.
