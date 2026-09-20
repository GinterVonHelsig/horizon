---
name: top-delivery
description: Submit authority prompts to the TOP-DELIVERY parent controller via the canonical goal CLI. Use when an invocation names $top-delivery with a prompt path; never execute the prompt directly in the harness.
---

# TOP-DELIVERY

TOP-DELIVERY is the project-level manager and front door. Harnesses are submitters,
not execution engines.

## Required behavior

When an invocation names `$top-delivery` and provides a prompt path:

1. Read the prompt path only to confirm it exists.
2. Submit the complete authority prompt through the canonical controller command.
3. Report the returned `run_id`, task IDs, and artifact paths from the JSON receipt.
4. Do not execute the prompt yourself, spawn child agents for the full goal, run
   shell commands, perform Git operations, broker actions, deployments, or other
   production mutations from the harness.

## Canonical submission command

```bash
python3 controller/goal_cli.py submit \
  --prompt /absolute/path/to/prompt.md \
  --artifact-root "$TOP_DELIVERY_ARTIFACT_ROOT"
```

Environment variables:

- `TOP_DELIVERY_ARTIFACT_ROOT` — run artifact root (required unless `--artifact-root` is passed)
- `TOP_DELIVERY_DATABASE_URL` — parent controller database URL (required unless `--database-url` is passed)

Parse-only inspection without database access:

```bash
python3 controller/goal_cli.py inspect --prompt /absolute/path/to/prompt.md
```

## After submission

- Treat the controller receipt as the durable parent run identity.
- Do not reinterpret the prompt into a parallel run graph in the harness.
- Route downstream execution to the persistent parent controller, supervisor, and
  worker services—not to the interactive session that submitted the prompt.

## Safety

Never:

- bypass the canonical submission command;
- execute allowed/forbidden authority directly from the harness;
- claim a goal is running without a controller `run_id`;
- mutate production systems from the submission harness.

If submission fails, report the concise CLI error and stop. Do not improvise a
substitute execution path.
