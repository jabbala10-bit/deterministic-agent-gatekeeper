# ADR-005: Policy configuration and runtime facts travel separately

**Status:** Accepted · **Date:** 2026-09-22 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
Cedar reads both kinds of data as entities. Some entities are policy: recipient allowlists and group
membership. Others are facts: an account's frozen status. If both could arrive in the per-decision
snapshot, a buggy or compromised shell path could widen policy by injecting one allowlist entry, and
no policy review would ever see it.

## Options considered
| Option | For | Against |
|---|---|---|
| All entities in the snapshot | Flexible | Policy can be widened at runtime, outside review |
| All entities in the bundle | Everything reviewed | Facts go stale; the bundle churns on every account change |
| **Typed split declared in the manifest** | Configuration is reviewed and hashed into `policy_hash`; facts are loaded fresh and hashed per decision | Two loading paths |

## Decision
The manifest declares `config_entity_types`, which may appear only in the bundle, and
`snapshot_entity_types`, which may appear only in snapshots and have typed attributes. A snapshot that
carries a configuration type is denied with `INVALID_SNAPSHOT:entity_type_not_allowed`.

## Consequences
- Changing an allowlist is a policy change. It is reviewed, hashed, and diffable against history in
  phase 5. This is intended.
- The shell must load every fact a decision needs. When it does not, ADR-004 turns the resulting
  error into a denial.

## Confidence and validation
High. Pinned by the golden vector `invalid-snapshot/config-entity-smuggled-in`.
