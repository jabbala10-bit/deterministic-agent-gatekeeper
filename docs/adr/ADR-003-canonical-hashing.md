# ADR-003: Canonical hashing: RFC 8785 over a float-free domain

**Status:** Accepted · **Date:** 2026-09-22 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
Two things depend on hashes. Approvals bind to an action hash, and replay compares decision hashes.
Any representation ambiguity is either a bypass (an approval that transfers to a different action) or a
false alarm (a replay mismatch caused by whitespace). Cross-language agreement matters (ADR-002).

## Options considered
| Option | For | Against |
|---|---|---|
| Hash raw request bytes only | Trivial | Formatting changes the hash; an approval breaks on whitespace |
| `json.dumps(sort_keys=True)` | Convenient | Python-specific: code-point key order, float repr, escaping |
| Full RFC 8785 | Standard | Numbers use ECMAScript double formatting, the classic cross-language hazard |
| **RFC 8785 over a float-free domain** | Standard bytes, trivially identical in every language | Money must be integer minor units; out-of-range literals are refused |

## Decision
- **Two hashes, two jobs.**
  - `input_hash` covers the raw argument text exactly as received, so the record shows what the agent sent.
  - `action_hash` covers the canonical action, which is what executes and what approvals bind to.
- **Value domain.** Canonical JSON is RFC 8785 restricted to null, booleans, integers with |n| ≤ 2^53−1,
  strings, arrays and objects. Floats, `NaN`, `Infinity`, duplicate keys and lone surrogates are
  rejected at parse time. Object keys are ordered by UTF-16 code units, as the RFC requires.
- **Text.** Text is NFC-normalised, and code points unassigned in the gate's Unicode version are refused,
  because Unicode's normalisation stability guarantee covers only assigned characters. The Unicode
  version is part of the gate identity.
- **Digest.** SHA-256 with domain-separation tags (`dag/action/v1`, `dag/snapshot/v1`, ...), so objects
  of different kinds never share a digest.

## Consequences
- Four formattings of one refund share one `action_hash` and have four distinct `decision_hash`es. The
  canonical action is fixed; the audit record keeps exactly what arrived.
- Non-ASCII email addresses are refused until IDNA arrives in phase 2. Refusal, not a guess.
- Policy `Long` literals beyond 2^53 cannot be hashed and fail bundle load, which is explicit.
- The canonical form is versioned (`canon: 1`). Changing it is a gate-identity change.

## Confidence and validation
High. Validation: a second implementation reproducing the corpus digest; the RFC 8785 key-ordering
vector in `tests/test_strictjson.py`.
