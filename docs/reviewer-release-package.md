# Source-owned reviewer release package (preparation, not installation)

The package provides `bin/cursor-independent-review` and the argv-compatible
`bin/openrouter-review` shim. Both enter the same guarded Cursor-only runtime.
The old command's name does **not** enable OpenRouter, translate model/provider
names, grant subscription usage, or supply missing author/history context.
Existing callers that omit the new mandatory context must change or remain blocked.

## Build and relocate

From the approved, clean GinterVonHelsig/horizon repair checkout:

```sh
python3 tools/host_review/package.py --output /NEW/STAGING/PARENT/reviewer-release
```

The parent must exist and the output must not. The builder copies only its
explicit source/dependency allowlist, both entry points, September routing YAML,
a disabled consumer template, dependency requirements and provenance. No tests,
historical bootstrap, database runner, runtime evidence, credentials or installed
configuration are packaged. Symlinks and overwrite are rejected. The manifest
records the full Git SHA and every payload's SHA-256; compare its own SHA-256 with
the approved release receipt through a trusted channel. It is an integrity
inventory, not a signature or independent approval.

Package inputs must match that Git commit. `--allow-uncommitted` exists only for
local test development and labels the manifest `TEST_ONLY_UNCOMMITTED`; such a
package must never be installed. Rebuild without that option after committing.
The package can be moved: source imports are rooted at the package, not the
checkout, cwd or PYTHONPATH. Entry points use Python isolated mode and disable
bytecode writes. No runtime pip installation or dependency fallback occurs.

Runtime prerequisites are Python >=3.11 and PyYAML exactly 6.0.2. Python and PyYAML
are not vendored: provision a separately approved runtime (prefer a release-local
venv with an offline, hash-approved wheelhouse) before installation. The reviewer
does not require PostgreSQL drivers, a database URL or the development checkout.
Use that runtime explicitly rather than relying on an interactive shell PATH:

```sh
/APPROVED/RUNTIME/bin/python3 -I /STAGED/RELEASE/bin/cursor-independent-review \
  --consumer-config /STAGED/CONSUMER/reviewer.json \
  --seat 4 --run-id NEW_REVIEW_ID --artifact-root /DISPOSABLE/REVIEW_EVIDENCE \
  --review-context /DISPOSABLE/REVIEW_EVIDENCE/context.json \
  --system-file /DISPOSABLE/REVIEW_EVIDENCE/system.md \
  --user-file /DISPOSABLE/REVIEW_EVIDENCE/packet.md
```

This is an interface example, **not permission to make a model call**. Direct
execution of either entry point instead selects python3 from the caller's PATH;
the operator must control that PATH. The compatibility entry point accepts the
same arguments, required context, configured routes and exit codes.

## Consumer configuration and review context

Copy `tools/host_review/consumer.example.json` outside the immutable release to a
staged consumer directory. Keep it disabled until the operator approves all of:

- Absolute path and SHA-256 of the existing Cursor harness executable. Hashing a
  wrapper does not attest its transitive binaries or account settings; preserve
  their independently captured version/provenance and subscription confirmation.
- Explicit routing YAML path (relative to the consumer file or absolute) and
  SHA-256. The shipped September policy is unchanged. If a required seat has no
  eligible authorized Cursor route, it fails; a compatibility command cannot
  silently alter that policy. A test-only Cursor phase-4 policy is not production
  route approval.
- Required source/run-bound context: packet reference and hash, actual author
  result/history references and hashes, passing prior-review history when required,
  explicit eligible Cursor inventory, max_calls=1, fallback_calls=0 and truthful
  On-Demand-disabled operator confirmation. Flags record confirmation, not billing
  enforcement. Preserve review-intents/results/history across process restarts.

Consumer inputs and executable must be regular owned, non-group/world-writable
files with no symlink components. Render canonical paths if the existing harness
is reached through an alias. The config owns routing; argv cannot override it.
Run-specific packet/system/context paths remain explicit arguments; the package
never manufactures passing prior reviews or author identities for old consumers.

Entry exits: 0 means a passing independent verdict (`approve` or
`approve-with-minors`); 2 means a rejected/invalid/failed transport result; 78 means
blocked package/configuration/evidence/independence or retained no-replay intent.
Argparse errors may exit 2 before a call. A completed review that rejects changes
is not a successful acceptance. There is no automatic retry or fallback call.
Non-review phases (such as execution phase 3A) are rejected before dispatch;
they cannot be supplied as review seats to bypass author-independence selection.

## Validation and deployment boundary

`tests/test_review_release_package.py` builds and relocates the package, executes
both actual entry points as new isolated Python processes and uses a separately
pinned **fake Cursor executable**, not an in-process replacement for the CLI.
It supplies a real consumer config and bound artifacts. Tests cover approval,
compatibility forwarding, missing dependencies, tampering, author collision,
unavailable routes, missing billing confirmation, prior verdict failures, wrong
model identity, rejection exits and replay across the two commands. No model call
or live task is made. These tests are in required CI.

Installing this package, changing the installed wrapper/module, provisioning a
consumer policy or retargeting existing callers is a separate operator deployment.
First capture installed hashes, then install the reviewed immutable package and
runtime as one versioned unit. Keep existing services untouched during source
preparation. Roll back consumer config, wrappers and package together; retain
review history and execution-intent markers. See recovery-activation.md for the
combined database, worker, submission and release rollback requirements.
