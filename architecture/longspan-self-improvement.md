# Longspan self-improvement model

Self-improvement is an audited learning loop, not unrestricted self-modification.

```text
Manager reads verified state
  → proposes one improvement experiment
  → Executor performs it in an isolated child scope
  → Auditor measures environment and acceptance criteria
  → TOP-DELIVERY records outcome and updates the playbook
```

Only the Auditor may update durable completion state. The Executor cannot edit
its own acceptance criteria, release gates, model routing, authority envelope,
or audit result. Improvements are classified as:

- `observation`: better telemetry or diagnosis;
- `playbook`: reusable runbook/checklist improvement;
- `workflow`: proposed controller change requiring review;
- `code`: implementation candidate requiring Terra delivery;
- `policy`: never self-approved; requires operator decision and adversarial
  review.

Each experiment records hypothesis, baseline, scope, predicted benefit,
rollback, evidence, auditor verdict, and whether the change is adopted,
rejected, or parked. The system may learn from failures and propose better
strategies, but it cannot silently broaden authority or promote its own
changes into production.
