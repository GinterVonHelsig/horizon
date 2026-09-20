# Comms-01 / Comms-02 local Executor team

This is a bounded execution team below Terra Delivery and TOP-DELIVERY.

```text
Terra Manager
   -> Qwen / Comms-01: evidence packet and task design
   -> KAT / Comms-02: isolated code implementation
   -> Qwen / Comms-01: mechanical consistency check
   -> Terra Auditor: independent verdict
```

Comms-01: `192.168.0.91`, Ollama Qwen3.8-27B Q4, revision `603ce507f0fd`.
Comms-02: `192.168.0.92`, Ollama KAT-Coder V2.5 Q4, revision
`685e7841abd4`.

The controller persists each prompt digest, response digest, model revision,
task attempt, worktree, changed-file manifest and test result before handing
work to the next lane. A local model failure is recorded and retried or
escalated; it is never silently replaced.

Neither local model is an auditor, authority, release approver, migration
owner, broker actor, ledger writer, strategy-state operator, or network/VM
administrator. Terra retains those responsibilities.

The local endpoints remain loopback-only. The controller reaches them through
the approved host path and never forwards production credentials or database
URLs. A task that requires shared-file mutation must use an isolated worktree
and a single writer lease.
