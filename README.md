# TOP-DELIVERY

Give it a goal. Walk away. Come back to evidence, not a chat log.

TOP-DELIVERY is a **walk-away workflow** for long jobs: shipping software, writing a spec, running a release, keeping a second brain, or any other project you can describe as an outcome with a done-line. You write what “done” means. The system keeps working, retries what failed, parks what it cannot finish, and refuses to call something complete unless there is proof.

It is **not** a chatbot, **not** an IDE, and **not** locked to one AI company. Coding tools (Cursor, Claude Code, Codex, local models, or whatever you plug in) are workers. TOP-DELIVERY is the manager.

> **Where this is today:** the walk-away control plane runs in a real lab. The “drop this onto any laptop / any project / any coding tool” story is the destination. It is **in flight**, not finished. If you clone this repo expecting `npm install && it runs overnight on my side project`, you will be disappointed. If you want a workflow that does not trust a single model’s “all done,” you are in the right place.

## What you actually get

1. **A durable goal.** Closing the laptop does not cancel the work. The goal has an ID, a queue, retries, and a parked state when a human has to decide something.
2. **A coordinator with a spine.** Gateway Delivery (the middle layer; older docs said Terra or Sol — those names are retired) runs a fixed sequence: check authority → research → two independent reviews → decide what to do → implement → review again → only then accept.
3. **Workers who cannot grade their own homework.** The model that writes is not the model that signs the review. If a check cannot fail, it is not a check.
4. **Proof on disk.** Every important claim leaves a file: what ran, which model, which digest, pass or blocked. A thumbs-up in chat is not a result.
5. **Your models, your seats.** Each job (coordinator, reviewer, coder, auditor) is a *seat*. You pick the model for that seat. If that model is down or slow, the seat has fallbacks. A web UI for picking models per seat is **in progress**. Until that UI ships, seats are configured in a routing file.

## How to picture it

```
You
  → TOP-DELIVERY (parent: holds the goal, the queue, and “is this still the same job?”)
       → Gateway Delivery (coordinator: phases, reviews, accept/reject)
            → Longspan (one slice of work: do it, then audit it)
                 → coding tools you already use (Cursor, CLI agents, local models, …)
```

Local Delivery is an optional cheap helper for mechanical chores (summaries, test triage, docs). It never approves its own work and never bypasses a review seat.

## Seats and models (not a brand list)

Think “roles in a film,” not “we only work with vendor X.”

| Seat | Job | How you choose the actor |
|------|-----|--------------------------|
| Coordinator | Keep the plot. Do not skip gates. | User-selectable (UI in progress). Fallbacks if the first pick is unavailable. |
| Reviewer 1 and Reviewer 2 | Two different second opinions before a plan is allowed to become work. | User-selectable per seat, with fallbacks. They must not be the same as the writer. |
| Coder | Change files in an isolated copy of the project. | Live coding lane in the current lab: **Cursor Composer**, with **Cursor Grok** as the next option on that same screen, then other configured fallbacks. You will pick this in the UI. |
| Auditor | Say whether the slice actually met the done-line. | Independent from the coder. Fallbacks exist. |
| Local helper (optional) | Cheap, bounded chores. | Optional. Escalate to the coder seat when the job is not mechanical. |

The product promise is: **swap the actor, keep the seat.** That is model-agnostic. We are not fully there until the UI and adapters are finished. Today some seats still have lab defaults in a YAML file. That file is the current source of truth; the UI will write it instead of you editing it by hand.

## Walk-away, in practice

Two modes:

- **Checkpointed.** It pauses at named gates so you can say yes or no.
- **Autonomous.** It keeps going when the gates pass. It **stops cleanly** when it does not have authority or evidence. It does not invent permission.

If something is blocked, you get a named reason and a pointer back to the **same** goal, not a brand-new chat that forgets the last three days.

## Intended future: drop-in for any project

This is a **feature we are cementing**, even though it is not true yet:

- Drop TOP-DELIVERY onto **any** repo or long-horizon project (code, docs, release, research, personal knowledge / “second brain”).
- **Harness-agnostic:** Cursor, Claude Code, Codex, OpenHands, a local CLI, or a future tool should be attachable as a worker without rewriting the parent.
- **Model-agnostic:** seats stay; models change in the UI.

Until that lands, this repo is the control plane and the rules. The “any project” story is the north star. Do not advertise it as a one-click installer.

## What TOP-DELIVERY will not do

- Trust a single model that says “done.”
- Let the writer also be the only reviewer.
- Skip a gate because a fallback model is cheaper.
- Treat a missing proof file as success.
- Let chat, email, or a messenger **approve** a release. Those channels may submit a goal or ask “how is it going.” They do not bypass gates.

## Status (honest)

| Piece | State |
|-------|--------|
| Walk-away parent (goal ID, queue, worker, durable submit) | Running in lab |
| Gateway Delivery phases and dual review | Running in lab |
| Cursor Composer + Grok coding seat | Running in lab |
| Model picker web UI | In progress |
| Drop-in any project / any harness | In progress (destination) |
| Consumer-grade install | Not started |

## Names we retired

Older prompts say **Terra Delivery** or **Sol Delivery**. Those are old names for the coordinator. New language: **Gateway Delivery** under **TOP-DELIVERY**.

## Licence

See [LICENSE](LICENSE).
