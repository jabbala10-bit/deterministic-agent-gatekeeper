# ADR-001: Cedar, not Rego, as the decision engine

**Status:** Accepted · **Date:** 2026-09-22 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
`decide()` must be pure (no network, clock or randomness), must always terminate, and must support
proving that a policy change only tightens before it ships (invariant 5, phase 5). Orchestra AI
already uses OPA/Rego, so staying on Rego is the default to beat. Customers in AWS-heavy rooms
increasingly meet Cedar as the policy language of Amazon Bedrock AgentCore Policy.

## Options considered
| Option | For | Against |
|---|---|---|
| Rego / OPA | Already in Orchestra; large ecosystem; very expressive | Nondeterministic built-ins (`http.send`, `time.now_ns`, `rand.intn`) must be stripped via capabilities and kept stripped; no standard tooling that answers "does this change grant anything new?" |
| **Cedar** | No network, clock or randomness built-ins; no loops, so evaluation terminates; schema validation; formal model in Lean with differential testing of the production engine; symbolic analysis (`cedar-policy-symcc`) returns concrete counterexamples for widening changes | Less expressive: aggregates such as session totals must be precomputed into the snapshot; the Python binding (`cedarpy`) is a community wrapper; two engine behaviours must be contained (see ADR-004 and the README) |
| Hand-written Python rules | Total control, no dependency | No formal semantics and no analysis; every rule becomes code review |

## Decision
Use Cedar through `cedarpy`, pinned to exactly `4.12.0`. The engine version is part of every
decision's gate identity, so an engine upgrade is a visible, replay-detectable event.

## Consequences
- Aggregates (refund totals, rate counts) move into the session ledger (phase 3), which keeps policies
  simple and makes those numbers part of the recorded snapshot.
- The gate must contain three engine behaviours: errors skip policies, reasons arrive in a per-process
  random order, and default policy ids are file positions. Each is contained and tested.
- Phase 5 needs a Rust toolchain in CI for `cedar-policy-symcc`.
- Security: policies cannot reach the network, so a compromised policy cannot exfiltrate.
  Maintainability: policies are declarative and schema-checked at load.

## Confidence and validation
High for determinism, with 274 golden vectors reproduced across processes. Medium for the symbolic
tooling until the phase 5 spike. Two results would validate it: a widening PR that fails CI with a
counterexample, and the phase 6 cross-platform replay matrix.
