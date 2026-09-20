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
The old transport functions remain for provenance/compatibility comparison, but
this entry point's admission permits only Cursor and does not call them.

Future deployment: package this exact reviewed module and controller dependencies,
add an explicitly Cursor-named command and compatibility shim that forwards the
required context; stage/test before installing. Do not replace installed sources
or change consumers during this repair. Roll back package/shim/config together;
retain review history and no-replay markers. No service restart is needed for
source review. This is not unified Comms Relay.
