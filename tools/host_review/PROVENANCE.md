# Source-owned external review integration

Imported from Comms-01
`/opt/operator-harness/lib/top_delivery_host_review/host_openrouter_review.py`,
SHA-256 `469197b9d6c4385c3787bb243addd8697383b78da2bbd430f3e1fd1638c5e4c9`.
No authoritative original Git revision was located. The imported source has
subsequently been modified in this review branch; that hash describes the original.
Installed files and `/opt/operator-harness/bin/openrouter-review` are untouched.

The new entry point is `python tools/host_review/host_review.py`; it requires
trusted actual-author/source/history bindings and explicit Cursor subscription
inventory. The shared Horizon selector is authoritative. One transport call,
no retry/fallback execution, no smoke bypass. Legacy model/phase identifiers
are not silently mapped from OpenRouter to Cursor. Missing authorized independent
routes fail; supported additional routes require explicit policy configuration.
The source-owned entry point contains only the Cursor transport. Non-Cursor
transports and their credential loader were removed after review: the inherited
composite constructor eagerly loaded an OpenRouter key even for a Cursor route.
The unchanged installed source and Git history preserve comparison provenance.
Observed stream-init identity is retained in result/history, not replaced with
the requested alias. The --user-file bytes must match the bound subject digest.

Release preparation now provides package.py, an explicit cursor-independent-review
entry point and an openrouter-review argv-compatibility shim. Both use the same
guarded runtime with explicit pinned consumer configuration; the shim does not
translate provider names. Relocated subprocess tests exercise both entries using
a fake pinned Cursor executable. See docs/reviewer-release-package.md. Python and
pinned PyYAML are explicit runtime prerequisites, not development-checkout imports.
Installation and actual consumer cutover remain deferred. Do not replace installed
sources or change consumers during this repair. Roll back package/shim/config and
runtime together; retain review history and no-replay markers. Review rejection
now exits nonzero even when the transport itself completed. No service restart is
needed for source review. This is not unified Comms Relay.
