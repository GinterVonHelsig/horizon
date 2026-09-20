# September routing reconciliation — direct Comms-01 repair

Operator decision, 2026-09-20: use the September baseline; independent review
takes precedence over model preference. No controller invocation or production
activation is authorized. Source baseline: dca7638c40a9d15b360cd3daecbca340791f8a6d.

## Causal diagnosis and policy choices

Five existing test functions pinned earlier model/provider assignments. Those
failed at imported snapshot e6c0b131184869c720f8d180f36ddc48b8a774af as well as
the original recovery candidate. The earliest substantive defect is selection:
`resolve_phase_route` ignored author remapping; duplicated review metadata
contradicted executable phases. Transport labels could also manufacture an
apparently independent runtime auditor from the same underlying model.

Routing contract version 3 makes `phases` authoritative. `reviews` and
`independence.adversarial_slots` contain references, not separate assignments.
The duplicated Grok remap is removed; remaps now identify provider/model/effort
and always stop if no eligible configured route remains. Phase 1.6 is Astra high,
matching the September operator assignment note and former review metadata,
rather than the contradictory medium setting. Phase 1.5 retains the executable
September Sol primary, not the stale Kimi metadata. The month is corrected to
September; an OpenRouter base URL is removed from the OpenAI coordinator entry.
No new model assignment is invented. The August validation artifact remains
historical evidence, not certification of this contract.

## Selection contract and independence

`resolve_phase_route` and `build_routing_records` are selection APIs, not model
executors. Review selection now requires actual author records and an explicit
qualified availability inventory. Missing history, unknown model family,
missing availability, disabled seats, uninvoked optional seats and exhausted
eligible routes raise `IndependentReviewBlocked`. Phase 1.6 additionally requires
the preceding phase 1.5 review identity. Callers must supply all actual authors
(including specification and code authors), not infer them from planned routes.
Callers remain responsible for durable history provenance and passing verdicts;
`review_sequence_allows_next` continues to reject failed prior reviews.

The existing independent-family requirement is applied conservatively to known
upstream families: Sol, Astra and Luna are OpenAI, regardless of transport or
effort. Known transport prefixes, OpenRouter variants and effort aliases cannot
establish independence. Prior required reviewers exclude their family too.
Configured author remaps are tried first, followed only by eligible configured
primary/fallback routes in deterministic order. Selection retains the reason;
explicit fallback indices cannot bypass independence. Unknown families block
phase review selection. The generic worker retains support for opaque custom
adapter identities, but no longer permits identical normalized models across
providers or different models from the same known family.

For Astra-authored work, declared remaps are phase 1.6 Grok, phase 4 Qwen,
phase 6 GLM. All are rechecked against every author and prior review, and the
qualified inventory. If both Astra and Grok authored work, phase 1.6 uses the
configured GLM remap if eligible, otherwise stops. With OpenAI authors, phase
1.5's Sol preference loses to its eligible Gemini fallback. These are route
selections, never silent model calls or spending approval.

## Tests and local review

The five stale tests are updated together with positive/negative regression
proofs for remapping, missing history/availability, cross-transport and
same-family conflicts, first-seat history, exhausted routes, explicit fallback
bypass, optional/disabled seats, conflicting declarations, unknown contracts,
author-order determinism and rejection stopping the required review sequence.
Real TaskWorker tests verify conflicts block before either adapter is called.
CI now includes the identity tests alongside the already-required routing suite.
All model execution/qualification in these tests is SIMULATED.

Local source review found two additional gaps after the first test pass: unknown
availability was treated as eligible configuration, and same-family models could
still pass the runtime guard. Both were tightened with regression tests. The
first targeted run also exposed an old OpenRouter spelling for optional Astra
behind the fifth test's earlier failed assertion; direct-provider spelling was
corrected without changing the opt-in gate. Final commit/results are recorded in
the draft PR and sanitized Comms-01 artifact directory:
`/opt/operator-harness/artifacts/20260920-horizon-recovery-routing-decision/`.
This is local review, not independent external code review.

Supplemental adapter checks (outside the required CI command) found 23 passing
and two failing CLI fixture tests: `test_codex_home_is_passed_only_by_environment`
and `test_cli_resume_writes_checkpoint_and_executes`. Both failures reproduce
unchanged on e6c0b1. Their synthetic streams contain an empty agent object with
no terminal completion event; the subprocess exits zero but adapter normalization
does not classify that as successful executor completion. Neither the adapter
contract nor these unrelated fixtures were relaxed in the routing continuation.
These remain explicit baseline test debt, not a claim that every repository test
passes or that a real adapter has been validated.

## Compatibility, activation and rollback

Contract v2 files are explicitly rejected by the new selector. Consumers of
duplicate metadata must dereference `route_ref`; callers selecting reviews must
supply actual author/prior-review history and qualified availability. Any
executor/auditor pair using the same known family now fails admission and worker
validation. Existing Cursor Composer / OpenRouter Sol defaults remain distinct.
No database schema or deployed configuration is changed.

The installed external launcher
`/opt/operator-harness/lib/top_delivery_host_review/host_openrouter_review.py`
does not call this selector and must NOT be treated as compatible enforcement.
It is not tracked in Horizon and was not patched in place. Resolving the actual
Gateway executable binding must include adapting that consumer to this contract,
with end-to-end evidence; do not point it at v3 and claim the safeguards apply.

Keep the conditional procedure in recovery-activation.md gated on that binding,
external review and live validation. For source-only rollback, revert this
continuation on the review branch to dca7638c40a9d15b360cd3daecbca340791f8a6d,
preserving the earlier recovery fixes. Do not select either candidate in
production. No schema downgrade or live database operation is needed.

## Live adapter test and remaining blockers

The operator approved up to USD 1 total incremental metered spend for one
disposable file task and one independent review, with no retries, fallback or
remediation. No call was made: the existing $5/run and $50/month configuration
does not enforce this new ceiling. Worker accounting records estimates (default
$0.01); the configured HTTP adapter emits no maximum output-token parameter,
and the installed relay does not impose a monetary/token ceiling. No verified
account-level hard limit for this disposable operation has been established.
Do not spend until a real enforceable bound is verified; authorization alone is
not enforcement. A future Cursor/Sol test is adapter validation, not Gateway
integration validation.

Explicit blockers: actual Gateway executable binding (including external review
launcher integration/provenance), independent external code review, and bounded
live adapter validation. A green routing suite does not remove these blockers.
Production activation remains a separate operator decision. Parked goals,
deployed release, TOP-DELIVERY and Quant infrastructure remain untouched.
