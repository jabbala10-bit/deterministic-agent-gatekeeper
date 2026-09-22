# Deterministic Agent Gatekeeper

**The model proposes, a pure function disposes, and every decision can be re-derived bit for bit.**

Per-call policy checks in front of agent tools are now table stakes. This project is about the property
that makes such a gate trustworthy to an examiner: **determinism you can prove**.

- Any past decision can be re-derived from its record on another machine, hash-exact.
- Any policy change can be measured against history before it ships (phase 5).
- What executes is provably what was checked (phase 4).

In the portfolio, Orchestra AI is the runtime, TrustOS is the enforcement boundary, and the Gatekeeper
is the decision core that proves it decides the same way every time.

This repository is **phase 1: the pure core**. It contains the canonical action type, RFC 8785 hashing,
`decide()` with three verdicts, stable policy identities, hash-chained decision records, replay, and a
274-vector golden corpus.

## What phase 1 proves (measured in this repo)

| Exit criterion | Result |
|---|---|
| 200+ golden vectors | **274**: 93 ALLOW, 100 DENY, 81 REQUIRE_APPROVAL, including 30 bypass attempts |
| Identical decision hashes across 10k runs | **10,000** randomised decisions reproduced exactly, each also matching an independent oracle |
| Identical across separate processes | Fresh processes under `PYTHONHASHSEED` 0, 1, 42 and random reproduce corpus digest `sha256:422c0165…` |
| Stated intent, not just stable output | The corpus generator refuses to write if the gate disagrees with `spec/oracle.py`, which is written without Cedar |
| Tests catch real regressions | `make mutants` removes the reason sort, the fail-closed rule, or core purity in a scratch copy; the suite catches all three |
| Latency (1 vCPU sandbox, Python 3.12) | p50 **0.46 ms**, p99 **1.0 ms** per decision. About 0.1 ms per engine evaluation (up to two per decision); the rest is Python hashing |

## Quickstart

```bash
uv sync
make verify          # 67 tests (~20 s), then the demo and a replay of its log
make mutants         # sabotage the core three ways; each must be caught
uv run gatekeeper bench
```

`make demo` runs the scripted EU bank-servicing walkthrough and replays its log:

```
 #  step                                           verdict           reasons
 1  Refund EUR 150.00                              ALLOW             refund-auto
 2  Refund EUR 400.00                              REQUIRE_APPROVAL  refund-approved
 3  Same refund after a human approved its hash    ALLOW             refund-approved
 4  Agent nudges it to EUR 450.00 after sign-off   REQUIRE_APPROVAL  refund-approved
 5  Refund to a frozen account                     DENY              no-refund-to-frozen-account
 6  Refund to an account the shell never loaded    DENY              EVAL_ERROR:no-refund-to-frozen-account
 7  Amount sent as 100.00 (a float)                DENY              INVALID_ARGUMENTS:float_not_allowed
 8  Email the customer after a CRM read            ALLOW             egress-allowlisted
 9  Injected: forward statements to an outsider    DENY              no-egress-after-untrusted-with-private
10  ...even with a human approval bound to it      DENY              no-egress-after-untrusted-with-private

replay PASS: 10/10 decisions re-derived hash-exact; chain intact
```

Other commands:
- `gatekeeper replay <log>` re-derives any log.
- `gatekeeper decide --tool … --args '<raw json>' --snapshot snap.json` decides a single proposal.
- `gatekeeper schema` prints the Cedar schema generated from the manifest.

## How a decision is made

```
agent (untrusted) ──tool + raw JSON──▶ shell: stamp clock once, load snapshot at ledger seq N
                                          │
             Envelope + Snapshot + PolicyBundle
                                          ▼
                 decide()  ── pure: no I/O, no clock, no randomness ──
                   1. snapshot facts typed and allowed?        else DENY INVALID_SNAPSHOT:*
                   2. strict parse + canonicalise arguments     else DENY INVALID_ARGUMENTS:* / UNKNOWN_TOOL
                   3. evaluate: any engine error                →    DENY EVAL_ERROR:<policy id>
                                permit, no forbid               →    ALLOW
                                a forbid matched                →    DENY <forbid id>   (final)
                   4. default deny only: re-evaluate with an approval bound to this action hash
                                a permit now matches            →    REQUIRE_APPROVAL
                                                                     otherwise DENY NO_MATCHING_PERMIT
                                          ▼
                 Decision { verdict, sorted reasons, action/input/snapshot/policy hashes, gate identity }
                                          ▼
                 hash-chained JSONL record (each line is its own RFC 8785 form)
```

## The five invariants

| # | Invariant | Enforced by | Proven by |
|---|---|---|---|
| 1 | **Purity**: `decide()` does no I/O, reads no clock, draws no randomness | `core/` imports nothing that can; time and state enter as recorded inputs | AST lint over `core/`; fresh-process corpus replays |
| 2 | **Replayability**: every record re-derives to the same decision hash | Records carry the full envelope, snapshot, policy hash and gate identity | 274 golden vectors; demo-log replay; forged-log tests |
| 3 | **Check equals execute**: only the canonical action runs | `action_hash` over the canonical action; approvals bind to it | Four formattings share one `action_hash`; an approval for EUR 400 does not cover EUR 450. Executor tokens arrive in phase 4 |
| 4 | **Fail closed**: errors, missing data and unknown tools deny | Any engine diagnostic, `NoDecision`, invalid input or snapshot means DENY with a code | Test in which the raw engine says Allow and the gate says DENY; 30 bypass vectors |
| 5 | **Monotone guardrails**: no permit or approval overrides a forbid | A forbid short-circuits before the approval path | An approved exfiltration is still denied. The symbolic widening check arrives in phase 5 |

## Engine behaviours this design contains (all reproduced here)

1. **Erroring policies are skipped, not failed.** A snapshot without the `Account` entity makes the
   frozen-account `forbid` error, and cedarpy 4.12.0 returns **Allow**. The error appears only in
   diagnostics. Contained by ADR-004.
2. **Reason order is random per process.** Two matching permits came back as `[policy1, policy2]` in
   5 of 12 processes and reversed in 7. Unsorted, the decision hash would change from run to run.
   Reasons are sorted, and removing the sort fails the fresh-process tests.
3. **Default policy ids are file positions.** Reordering the file renames every reason. The gate maps
   positions to `@id` annotations and hashes policies keyed by `@id`. Reversing and reformatting the
   file leaves the policy hash and every decision hash unchanged, while `policy0` moves from the egress
   forbid to `reads-allowed`.
4. **Results carry timing metrics.** They never reach a record or a hash.

The Python-side hazards are listed in ADR-002 (`bool` is an `int`, `NaN` and duplicate keys in `json`,
per-process `str` hashing, Unicode version drift). Each is closed and tested.

## The golden corpus is the contract

`spec/vectors/golden.jsonl` pins every input byte and every expected hash. Each line is its own RFC 8785
form. `spec/vectors/meta.json` records the policy hash, the gate identity and a corpus digest. Any
future implementation (Rust core, Go, PyO3) must reproduce the digest before it replaces this one
(ADR-002).

To regenerate after an intended behaviour change, run `make vectors` and review the diff. The
generator refuses to write if any computed verdict disagrees with `spec/oracle.py`.

## Layout

```
src/gatekeeper/core/     pure: strictjson (RFC 8785), digest, model, manifest (→ Cedar schema),
                         canonical, bundle (stable ids, load-time validation), decide
src/gatekeeper/shell/    impure: loader, hash-chained log, replay, gate (clock), demo
policies/bank-servicing/ manifest.json · entities.json (config only) · policies.cedar
spec/                    oracle (intent without Cedar) · scenarios · corpus · gen_vectors · vectors/
tests/                   one test module per concern; invariants named I1–I5
docs/adr/                ADR-001 … ADR-005
```

## Limitations (deliberate, and on the roadmap)

- **No ledger yet.** Snapshots are built by hand in the demo and the tests. Session labels are coarse by
  design: once tainted, a session stays tainted. Finer-grained approaches exist, including FIDES
  (confidentiality and integrity labels) and CaMeL (control/data-flow separation). Over-blocking will be
  measured in phase 6, not hidden.
- **Records are chained, not signed.** Replay catches a forged input whose recorded decision does not
  follow from it, even when the whole chain has been re-sealed (tested). A forger who also recomputes
  the decisions is stopped only by the signatures that arrive in phase 4.
- **Narrow canonicalisers.** Email addresses are ASCII-only for now, and URLs are refused rather than
  guessed at, until phase 2.
- **Replay needs the same gate identity.** Hash-exact replay requires the same gate, canonical form,
  engine and Unicode versions. Records from a different identity are reported separately, and
  comparing them is phase 5's `diff`.
- **The oracle shares the author's assumptions.** It catches policies that drift from stated intent. It
  cannot catch a wrong intent.

## Regulatory mapping (relevant to, not a compliance claim)

| EU AI Act | What this repo provides |
|---|---|
| Art. 12, record-keeping | Tamper-evident decision records that re-derive hash-exact, citing stable policy ids |
| Art. 14, human oversight | `REQUIRE_APPROVAL` with approvals bound to the exact canonical action; forbids no approval can override |

## Roadmap

| Phase | Deliverable | Exit proof |
|---|---|---|
| 2 | URL, money and recipient canonicalisers; templates for everything else | Known-bypass corpus 100% denied; differential tests against each tool's own parser |
| 3 | Session ledger: labels, reserve→commit budgets, one writer per session | 100 parallel EUR 200 refunds against a EUR 500 cap: exactly two execute |
| 4 | MCP proxy on `tools/call`; single-use signed tokens; approval CLI | Works unmodified with Claude Code; arguments edited after approval are rejected |
| 5 | `replay` and `diff` in CI; symbolic tightening check | A widening PR fails with a concrete counterexample |
| 6 | AgentDojo with and without the gate; latency; cross-platform replay matrix | Published numbers, including where it over-blocks |

## Decisions

- [ADR-001](docs/adr/ADR-001-cedar-as-the-decision-engine.md): Cedar, not Rego, as the decision engine
- [ADR-002](docs/adr/ADR-002-python-first-with-vectors-as-the-contract.md): Python for phase 1; the golden corpus is the contract
- [ADR-003](docs/adr/ADR-003-canonical-hashing.md): Canonical hashing: RFC 8785 over a float-free domain
- [ADR-004](docs/adr/ADR-004-fail-closed-on-evaluation-errors.md): Fail closed on any evaluation error; validate at load
- [ADR-005](docs/adr/ADR-005-separate-policy-configuration-from-runtime-facts.md): Policy configuration and runtime facts travel separately
