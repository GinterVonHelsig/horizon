# GitHub development cycle

TOP-DELIVERY default branch is `main`. Production `trading` stays parked. Host `gh` is authorized on Comms-01/02; tokens never belong in this tree.

| Git step | Workflow phase |
| --- | --- |
| Isolated worktree | 3A / 3B |
| Local commits | 3A / 5 (author env only) |
| Push task branch | 3A/5 or 7 prep |
| PR against `main` | 7 (may open earlier for CI) |
| CI | GitHub Actions on the exact SHA |
| Merge | 7, Gateway Delivery release authority |
| Deploy | 7 after merge; 7.5 QA |

A host overlay of `/opt/top-delivery-p1/current` is not merge evidence.
