# ADR-008: An event-sourced session ledger, with budgets reserved before execution

**Status:** Accepted · **Date:** 2026-09-23 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
Through phase 2 the caller handed the gate a snapshot: labels, budgets, approvals. That means the
gate trusted the component it exists to constrain, and nothing proved the snapshot was real. It also
left a race in the open: a hundred concurrent refunds each read "nothing refunded yet" and every one
of them passes a per-session cap.

## Options considered
| Option | For | Against |
|---|---|---|
| Caller supplies the state (phases 1–2) | Simple, no storage | Unverifiable, and a forgetful or compromised caller keeps a session permanently clean |
| Query the business system at ingress | Real-time truth | Nondeterministic, so replay stops working; and it is still racy unless a transaction spans decide and execute |
| **Event-sourced ledger per session** | The snapshot is a fold of recorded events, so replay re-derives it; reservations make in-flight work visible | Per-session storage, and a crashed executor leaves a reservation behind |

## Decision
A hash-chained event log per session, folded by a pure function in `core/ledger.py`:
`session_opened`, `decided`, `reserved`, `settled`, `approval_granted`, `approval_consumed`.

- **Reserve, then settle.** A budget is reserved when a decision is ALLOWed and turned into committed
  spend when the tool reports success, or returned when it fails. An allowed-but-unexecuted refund
  still occupies the cap, which is the only way concurrent calls can be counted correctly.
- **One writer per session.** The lock spans reading the budget, deciding, and reserving against it.
  A budget read outside that critical section is a race by construction.
- **Labels are earned, not declared.** On commit, the session gains the `result_labels` the manifest
  gives the tool that actually ran. The caller cannot choose them, so the lethal trifecta in the demo
  is created by the agent's own CRM read and web fetch.
- **Approvals are single use.** The ALLOW that consumes one records `approval_consumed`, so the same
  signature cannot authorise a second execution.
- **Counters are declared, not built in.** The manifest names each counter and each tool says which
  argument feeds it. The core knows nothing about refunds.

## Consequences
- Replay now proves two things: the verdict follows from the snapshot, and the snapshot follows from
  the session's history. Deleting a settled spend and re-sealing the chain is caught, because later
  snapshots no longer fold to their recorded hashes.
- Facts loaded from outside (an account's frozen status) cannot come from the ledger, so they are
  recorded in the `decided` event and pinned by the snapshot hash. That half is recorded evidence
  rather than derived history; attesting to the source of facts is a later phase.
- Budgets are per session. A per-customer daily cap needs a shared writer across sessions, which is a
  different and heavier design.
- A crashed executor leaves a reservation outstanding, holding budget until it is released. Production
  needs a sweeper with a timeout; phase 4 is where that belongs, alongside the execution token.
- A session's calls serialise. That is the intent; separate sessions still run in parallel.

## Confidence and validation
High. The exit proof runs 100 concurrent EUR 200 refunds against a EUR 500 cap and expects exactly
two to execute, and `make mutants` moves the budget read outside the lock and confirms the test fails
(caught in 10 of 10 runs).
