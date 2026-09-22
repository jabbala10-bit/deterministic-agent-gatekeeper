# ADR-002: Python for phase 1; the golden corpus is the contract

**Status:** Accepted · **Date:** 2026-09-22 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
The build plan preferred a small Rust core. Phase 1 values iteration speed and immediate embedding in
Orchestra AI (Python 3.12, uv). The deliverable is a proof, not throughput: tool calls take hundreds of
milliseconds, so a sub-millisecond gate is not the bottleneck.

## Options considered
| Option | For | Against |
|---|---|---|
| Rust core now | Native access to the reference engine and `symcc`; single-binary MCP proxy; lowest latency | Slower iteration; needs a PyO3 binding before Orchestra can use it |
| **Python now** | Fastest iteration; drops into Orchestra directly; `cedarpy` wraps the same Rust engine | Python-specific determinism hazards must be engineered out; p50 of about 0.46 ms |
| Go (TrustOS target) | Matches TrustOS production | `cedar-go` is a separate implementation of the language, so its semantics would need differential testing against the Rust reference |

## Decision
Build phase 1 in Python. Define every observable output as language-neutral bytes (RFC 8785 plus
SHA-256, see ADR-003) and pin them in the golden corpus (`spec/vectors/`). Any later port must
reproduce the corpus digest bit for bit before it may replace this implementation.

## Consequences
- Each Python hazard is handled explicitly and tested:
  - `bool` is an `int` subclass: integers are type-checked exactly.
  - `json` accepts `NaN` and duplicate keys: the parser rejects both.
  - `str` hashing is randomised per process: tests run fresh processes under several `PYTHONHASHSEED` values.
  - `unicodedata` follows the interpreter's Unicode version: unassigned code points are refused.
- Technical debt: a Rust port or a PyO3 binding if phase 6 shows latency matters. The corpus makes that
  port a mechanical exercise with an objective finish line.
- Risk: `cedarpy` maintenance. Mitigated by the exact pin and by the corpus detecting any engine
  behaviour change.

## Confidence and validation
High that the corpus makes a port safe. Medium on whether a port is needed at all. The phase 6 latency
numbers under realistic MCP load will settle it.
