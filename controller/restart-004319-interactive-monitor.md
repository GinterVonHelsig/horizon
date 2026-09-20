Resume run 20260810T004319Z-b626467e from the last accepted phase-3A batch. Preserve all accepted patches and rejected-patch evidence. Clear the stale Luna writer lease before starting.

Use Luna xhigh as the approved Cursor-capacity fallback. Continue the isolated controller/Signal/Hermes API implementation, then review and validate it. Never apply an incomplete patch.

Add active monitoring, not heartbeat-only evidence: write a machine-readable status event at start, every 5 minutes, on every retry, phase transition, acceptance/rejection, and terminal state. Each status event must include run ID, phase, worker PID/generation, last accepted artifact, current action, elapsed time, retry count, next action and blocker. Mark the worker stale after 10 minutes without an event, clear writing_agent, preserve evidence and restart the same bounded batch.

Send the same concise status update through the verified TOP-DELIVERY Signal 1-to-1 channel every 15 minutes and immediately on phase transition, retry exhaustion, acceptance, rejection, or terminal failure. Do not include credentials, codes, private keys, raw prompts or sensitive payloads. If Signal is unavailable, persist the notification failure and continue local monitoring.

Run until the API adapter passes isolated tests, independent review, disposable validation and QA, or until a true integrity/credential/rollback/wrong-target failure occurs. Do not modify production, brokers, ledger, database, network, staging, or prior runs.
