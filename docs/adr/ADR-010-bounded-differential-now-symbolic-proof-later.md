# ADR-010: Bounded differential policy diffing now, symbolic proof as a named upgrade

**Status:** Accepted · **Date:** 2026-09-23 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
ADR-001 chose Cedar partly because `cedar-policy-symcc` can decide whether one policy set grants
permissions another does not, and return a concrete counterexample when it does. Phase 5 needs that
question answered on every policy pull request.

`cedar-policy-symcc` is a Rust crate that needs a current Rust toolchain and the cvc5 solver. This
repository is Python and uv; its CI has neither, and the distribution's packaged cargo (1.75) is
older than the Cedar crates require. So the check had to be built some other way, or deferred.

## Options considered
| Option | For | Against |
|---|---|---|
| Re-encode Cedar's semantics in Z3 from Python | No new toolchain, and a real proof | A second implementation of the semantics, which is exactly the drift this project exists to avoid. A wrong encoding produces confident, false assurance |
| Ship the symcc integration unexecuted | Matches ADR-001 as written | Untested code in the one place that must not be wrong, against this repository's standard of verifying by execution |
| **Bounded exhaustive differential using the real engine** | Every verdict comes from the engine that will decide in production; boundaries are mined from the policy's own integer literals, so an off-by-one widening is found by construction; counterexamples are concrete and reproducible | It finds widenings; it does not prove their absence outside the enumerated domain |

## Decision
Ship the bounded differential. `gatekeeper diff` answers the two questions that matter before a
change ships:

- **What does the candidate newly permit?** A request space is generated from the candidate's
  manifest: every tool, every enum value, every label subset, both approval states, facts present,
  absent and missing, and integer values taken from `{v-1, v, v+1}` for every literal appearing in
  either policy set. Hosts and domains come from the bundle's own configuration entities, plus a
  subdomain, a suffix splice that only looks allowlisted, and something unrelated. Each request is
  decided twice, by the real engine, and any request the candidate allows and the base does not is
  reported with the exact arguments and session state.
- **Which decisions already taken would change?** Recorded ledgers are folded and re-decided against
  the candidate. A ledger's own evolution does not depend on policy, so every historical snapshot is
  re-derived exactly, and the report names each recorded action whose verdict moves.

CI runs this on every pull request against the base branch and fails on a widening unless the change
says `--allow-widening` explicitly.

**The symbolic check stays a named upgrade, not a vague intention.** It needs: a current Rust
toolchain and a cvc5 binary in CI, a small Rust CLI wrapping symcc's implication check over the
schema this repo already generates from the manifest, and a JSON counterexample format matching what
`gatekeeper diff` prints today. The interface is the same either way, so it slots in behind the same
command.

## Consequences
- A widening reachable only through an input outside the enumerated domain would pass. The mitigations
  are that numbers come from the policy's own literals, hosts from its own entities, and history from
  real ledgers, but the honest statement is that this finds widenings rather than proving none exist.
- The probe space grows multiplicatively with the manifest, so a budget caps it (about 2,100 probes
  for the bank bundle). A bundle that outgrows the budget is a reason to do the symbolic work.
- The probe space is a pure function of the two bundles, so CI output is reproducible.
- `make mutants` includes a check that disables boundary-literal mining and confirms the one-unit
  widening test then fails, so the mechanism that does the catching is itself tested.

## Confidence and validation
High that realistic widenings are caught: deleting a guardrail, opening egress, and moving a cap by
one unit are each caught with a counterexample that the test suite re-decides to confirm it is real.
Medium as a guarantee of absence. The validating experiment is to run symcc over the same pull
requests once a toolchain exists and compare the counterexamples.
