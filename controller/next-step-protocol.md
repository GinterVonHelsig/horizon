# TOP-DELIVERY next-step protocol

At the end of every outcome, TOP-DELIVERY must create a run-scoped
`artifacts/next-step.md` containing:

1. current verified state;
2. proposed next outcome;
3. exact work items and boundaries;
4. acceptance assertions;
5. risks and required credentials;
6. a short executable prompt;
7. an explicit decision request: `Proceed? [YES / NO]`.

The controller may prepare the artifact autonomously, but it must not advance
the next mutation phase until the operator answers `YES`. A `NO` parks the
proposal. Routine child remediation inside an already-approved outcome remains
autonomous; this checkpoint applies to the next broader outcome.
