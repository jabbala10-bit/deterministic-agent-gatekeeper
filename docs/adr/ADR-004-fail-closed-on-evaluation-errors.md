# ADR-004: Fail closed on any evaluation error; validate at load

**Status:** Accepted · **Date:** 2026-09-22 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
Cedar skips a policy whose evaluation errors and reports the error only as a diagnostic. When the
skipped policy is a `forbid`, a deny silently becomes an allow. Reproduced twice:
- **Overflow.** A session-cap `forbid` overflowed on `i64::MAX` and was skipped.
- **Missing entity.** The shell omitted an `Account` entity. The frozen-account `forbid` errored with
  "entity does not exist", and the engine returned **Allow**.

The second case is realistic: the agent chooses the account id.

## Options considered
| Option | For | Against |
|---|---|---|
| Trust the engine's decision | Simple | Guardrails vanish silently exactly when data is missing or odd |
| Validate and bound inputs only | Removes most errors early | Missing entities and some arithmetic cannot be caught statically |
| **Validate at load, bound inputs, and fail closed at runtime** | Errors move to deploy time where possible; the rest deny with a precise reason | A buggy permit can cause denials (an availability cost) |

## Decision
- A Cedar schema is generated from the tool manifest. Policies are validated against it when the bundle
  loads, so a typo such as `context.args.amount` fails the deploy.
- Canonicalisation bounds every argument before the engine sees it.
- At runtime, any diagnostic error, or any engine decision other than Allow or Deny, yields
  `DENY` with reason `EVAL_ERROR:<policy @id>`.

## Consequences
- Availability risk becomes a visible, attributable signal. Monitor the `EVAL_ERROR` rate as an SLO.
- Engine error messages never enter records, because they can contain agent-controlled data. Only
  stable policy ids do.
- `tests/test_invariants.py::test_I4_gate_denies_where_the_raw_engine_fails_open` pins both halves:
  the raw engine says Allow, and the gate says DENY.

## Confidence and validation
High. Validation data: the `EVAL_ERROR` rate during the phase 6 AgentDojo runs.
