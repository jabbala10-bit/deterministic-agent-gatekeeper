# Deterministic Agent Gatekeeper

[![verify](https://github.com/jabbala10-bit/deterministic-agent-gatekeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/jabbala10-bit/deterministic-agent-gatekeeper/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](.python-version)

**The model proposes, a pure function disposes, and every decision can be re-derived bit for bit.**

Per-call policy checks in front of agent tools are now table stakes. This project is about the two
properties that make such a gate trustworthy to an examiner: **determinism you can prove**, and
**one canonical action** that is both what was checked and what runs.

- Any past decision re-derives from its record on another machine, hash-exact.
- Any policy change can be measured against history before it ships (phase 5).
- What executes is provably what was checked (enforced at the boundary in phase 4).

In the portfolio, Orchestra AI is the runtime, TrustOS is the enforcement boundary, and the
Gatekeeper is the decision core that proves it decides the same way every time.

**Phases 1 and 2 are here**: the pure core, and the canonicalisers.

## What is proven (measured in this repo)

| Exit criterion | Result |
|---|---|
| Golden vectors | **400**: 136 ALLOW, 161 DENY, 103 REQUIRE_APPROVAL |
| Known-bypass corpus 100% refused | **85 attempts, 0 reach ALLOW.** 77 are denied outright with an exact reason code; 8 lookalike destinations escalate to a human instead |
| Equivalence classes collapse | 4 classes (URL, recipient, IDNA, amount): every spelling in a class produces one `action_hash`, and the classes stay distinct |
| Canonicalisation is idempotent | Property-tested for URLs, plus an exact round trip for money in every supported currency |
| Differential vs the tool's parser | Canonical URLs are unambiguous to `urllib`; inputs the two read differently are refused outright |
| Identical decision hashes across 10k runs | **10,000** randomised decisions reproduce exactly and match an independent oracle |
| Identical across separate processes | Fresh processes under `PYTHONHASHSEED` 0, 1, 42 and random re-derive corpus digest `sha256:fd58730d…` |
| Stated intent, not just stable output | The corpus generator refuses to write when the gate disagrees with `spec/oracle.py`, which is written without Cedar |
| Tests catch real regressions | `make mutants` breaks the reason sort, the fail-closed rule and core purity in a scratch copy; the suite catches all three |
| Same result on other platforms | CI re-derives the corpus on Linux x86_64, Linux arm64, macOS arm64 and Windows |
| An upgrade is classified, not absorbed | On Python 3.13 (Unicode 15.1.0) every verdict is unchanged while every hash moves. `make identity` calls that an identity change, not a regression |
| Latency (1 vCPU sandbox, Python 3.12) | p50 **0.52 ms**, p99 **0.91 ms** per decision, including canonicalisation and up to two engine evaluations |

138 tests, about 23 seconds.

## Quickstart

```bash
uv sync
make verify          # tests, then the demo and a replay of its log
make mutants         # sabotage the core three ways; each must be caught
make identity        # does this runtime still decide the same way?
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
 7  Amount sent as the number 100.00               DENY              INVALID_ARGUMENTS:float_not_allowed
 8  Third decimal place on a EUR amount            DENY              INVALID_ARGUMENTS:amount:too_many_fraction_digits
 9  Look up the customer in the CRM                ALLOW             reads-allowed
10  Report from a named template                   ALLOW             reports-allowlisted
11  Report template no policy permits              DENY              NO_MATCHING_PERMIT
12  Email the customer (allowlisted domain)        ALLOW             egress-allowlisted-recipient
13  Fetch an allowlisted host over TLS             ALLOW             egress-allowlisted-host
14  Injected: fetch the cloud metadata IP          DENY              INVALID_ARGUMENTS:url:ip_literal_not_allowed
15  Injected: allowlisted host as URL credentials  DENY              INVALID_ARGUMENTS:url:credentials_in_url
16  Injected: forward statements to an outsider    DENY              no-egress-after-untrusted-with-private
17  ...even with a human approval bound to it      DENY              no-egress-after-untrusted-with-private
18  Mail the allowlisted customer, now tainted     DENY              no-egress-after-untrusted-with-private

replay PASS: 18/18 decisions re-derived hash-exact; chain intact
```

## How a decision is made

```
agent (untrusted) ──tool + raw JSON──▶ shell: stamp clock once, load snapshot at ledger seq N
                                          │
             Envelope + Snapshot + PolicyBundle
                                          ▼
                 decide()  ── pure: no I/O, no clock, no randomness ──
                   1. snapshot facts typed and allowed?      else DENY INVALID_SNAPSHOT:*
                   2. canonicalise every argument            else DENY INVALID_ARGUMENTS:* / UNKNOWN_TOOL
                   3. evaluate: any engine error             →    DENY EVAL_ERROR:<policy id>
                                permit, no forbid            →    ALLOW
                                a forbid matched             →    DENY <forbid id>   (final)
                   4. default deny only: re-evaluate with an approval bound to this action hash
                                a permit now matches         →    REQUIRE_APPROVAL
                                                                  otherwise DENY NO_MATCHING_PERMIT
                                          ▼
                 Decision { verdict, sorted reasons, action/input/snapshot/policy hashes, gate identity }
                                          ▼
                 hash-chained JSONL record (each line is its own RFC 8785 form)
```

## Canonicalisation: parse once, pass structure

The agent's text is parsed exactly once, into typed values. Policies read those values, the executor
receives them, and nothing downstream re-parses a string.

| Kind | Canonical value | Refuses |
|---|---|---|
| `money` | `{amount_minor, currency}` as exact integers in the currency's own minor units | JSON numbers, `1e2`, sub-unit precision (`150.001` EUR, `150.00` JPY), leading zeros, separators, non-ASCII digits, unknown or unpermitted currencies |
| `url` | `{scheme, host, port, path, query}` | credentials in the URL, IP literals in every spelling, single-label hosts, non-TLS schemes, tab/CR/LF, spaces, backslashes, bad percent-encoding, bad ports |
| `email` | `{address, domain}`, domain via IDNA UTS-46 | display names, address lists, quoted or non-ASCII local parts, IP and single-label domains |
| `template` | `{name, params}` with typed parameters | unknown template names, unknown or missing parameters, out-of-range values, anything resembling a command |
| `id`, `int`, `enum`, `text` | the value itself | quotes in ids, `bool` as int, out-of-range integers, control characters, bidi overrides, unassigned code points |

Free-form command languages are deliberately absent. A tool exposes **named templates** and the gate
never builds SQL from agent text (ADR-007).

The known-bypass corpus lives in `spec/bypasses.py` and every row is a golden vector:

| Family | Rows | Example |
|---|---|---|
| url | 24 | `https://2130706433/`, `https://0x7f.0.0.0x1/`, `https://bank.example@evil.test/` |
| money | 16 | `150.001` EUR, `150.00` JPY, `١٥٠`, `1,500.00` |
| json | 13 | duplicate keys, floats, `NaN`, 64 KiB of padding |
| template | 9 | SQL in a template name, SQL in a parameter, a template no policy permits |
| lookalike | 8 | `bank.example.attacker.test`, Cyrillic homoglyph hosts, allowlisted host in the query string |
| email | 7 | display names, address lists, IP domains |
| text, tool | 5 | bidi overrides, NUL bytes, tool-name case variants |
| snapshot | 3 | an allowlist entry smuggled in as runtime state |

## The five invariants

| # | Invariant | Enforced by | Proven by |
|---|---|---|---|
| 1 | **Purity**: `decide()` does no I/O, reads no clock, draws no randomness | `core/` imports nothing that can; time and state enter as recorded inputs | AST lint over `core/`; fresh-process corpus replays |
| 2 | **Replayability**: every record re-derives to the same decision hash | Records carry the full envelope, snapshot, policy hash and gate identity | 400 golden vectors; demo-log replay; forged-log tests |
| 3 | **Check equals execute**: only the canonical action runs | One parse into typed structure; `action_hash` over it; approvals bind to that hash | Equivalence classes collapse to one hash; `urllib` differential; an approval for EUR 400 does not cover EUR 450 |
| 4 | **Fail closed**: errors, missing data and unknown tools deny | Any engine diagnostic, `NoDecision`, invalid input or snapshot means DENY with a code | A test where the raw engine says Allow and the gate says DENY; 85 bypass attempts |
| 5 | **Monotone guardrails**: no permit or approval overrides a forbid | A forbid short-circuits before the approval path | An approved exfiltration is still denied. The symbolic widening check arrives in phase 5 |

## Engine behaviours this design contains (all reproduced here)

1. **Erroring policies are skipped, not failed.** A snapshot without the `Account` entity makes the
   frozen-account `forbid` error, and cedarpy 4.12.0 returns **Allow**. Contained by ADR-004.
2. **Reason order is random per process.** Two matching permits came back as `[policy1, policy2]` in
   5 of 12 processes and reversed in 7. Reasons are sorted; removing the sort fails the
   fresh-process tests.
3. **Default policy ids are file positions.** The gate maps positions to `@id` annotations and hashes
   policies keyed by `@id`, so reversing and reformatting the file changes nothing.
4. **Results carry timing metrics.** They never reach a record or a hash.

## The golden corpus is the contract

`spec/vectors/golden.jsonl` pins every input byte and every expected hash; each line is its own
RFC 8785 form. `spec/vectors/meta.json` records the policy hash, the gate identity and a corpus
digest. Any future implementation must reproduce the digest before it replaces this one (ADR-002).

To regenerate after an intended change, run `make vectors` and review the diff. The generator refuses
to write when a computed verdict disagrees with `spec/oracle.py`.

## Layout

```
src/gatekeeper/core/     pure: strictjson (RFC 8785), digest, model, manifest (→ Cedar schema),
                         url, money, canonical, bundle (stable ids, load-time validation), decide
src/gatekeeper/shell/    impure: loader, hash-chained log, replay, gate (clock), demo
policies/bank-servicing/ manifest.json · entities.json (config only) · policies.cedar
spec/                    oracle · scenarios · bypasses · corpus · gen_vectors · mutants ·
                         check_gate_identity · vectors/
tests/                   one module per concern; invariants named I1–I5
docs/adr/                ADR-001 … ADR-007
```

## Limitations (deliberate, and on the roadmap)

- **No ledger yet.** Snapshots are built by hand in the demo and tests. Session labels are coarse by
  design: once tainted, a session stays tainted. Finer-grained approaches exist, including FIDES and
  CaMeL. Over-blocking will be measured in phase 6, not hidden.
- **Names are not resolved.** DNS is nondeterministic, so the gate rules on the canonical host and
  the executor must pin the resolved address and refuse private space (phase 4). `127.0.0.1.nip.io`
  is an executor concern by design.
- **No Public Suffix List.** Allowlisting a suffix covers everything beneath it, so allowlisting a
  public suffix would be a broad grant. Suffix entities are policy: reviewed, hashed and diffable.
- **Records are chained, not signed.** Replay catches a forged input whose recorded decision does not
  follow from it, even when the chain is re-sealed (tested). A forger who also recomputes decisions
  is stopped only by the signatures in phase 4.
- **Refusal instead of coverage.** Internationalised local parts and IP literals are refused rather
  than handled. That is over-blocking, and it is measured rather than hidden.
- **Replay needs the same gate identity.** Gate, canonical form, engine, Unicode and IDNA versions
  all count, so the repo pins Python 3.12 in `.python-version` and `make identity` says whether a
  newer runtime changed behaviour (a bug) or only the identity (regenerate deliberately).
- **The oracle shares the author's assumptions.** It catches policies that drift from stated intent,
  not an intent that was wrong to begin with.

## Regulatory mapping (relevant to, not a compliance claim)

| EU AI Act | What this repo provides |
|---|---|
| Art. 12, record-keeping | Tamper-evident decision records that re-derive hash-exact, citing stable policy ids |
| Art. 14, human oversight | `REQUIRE_APPROVAL` with approvals bound to the exact canonical action; forbids no approval overrides |

## Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Pure core, RFC 8785 hashing, three verdicts, stable policy ids, replay | **Done** |
| 2 | URL, money and recipient canonicalisers; named templates; known-bypass corpus | **Done** |
| 3 | Session ledger: labels, reserve→commit budgets, one writer per session | 100 parallel EUR 200 refunds against a EUR 500 cap: exactly two execute |
| 4 | MCP proxy on `tools/call`; single-use signed tokens; executor-side IP pinning; approval CLI | Works unmodified with Claude Code; arguments edited after approval are rejected |
| 5 | `replay` and `diff` in CI; symbolic tightening check | A widening PR fails with a concrete counterexample |
| 6 | AgentDojo with and without the gate; latency; cross-platform replay matrix | Published numbers, including where it over-blocks |

## Decisions

- [ADR-001](docs/adr/ADR-001-cedar-as-the-decision-engine.md): Cedar, not Rego, as the decision engine
- [ADR-002](docs/adr/ADR-002-python-first-with-vectors-as-the-contract.md): Python for phase 1; the golden corpus is the contract
- [ADR-003](docs/adr/ADR-003-canonical-hashing.md): Canonical hashing: RFC 8785 over a float-free domain
- [ADR-004](docs/adr/ADR-004-fail-closed-on-evaluation-errors.md): Fail closed on any evaluation error; validate at load
- [ADR-005](docs/adr/ADR-005-separate-policy-configuration-from-runtime-facts.md): Policy configuration and runtime facts travel separately
- [ADR-006](docs/adr/ADR-006-canonicalise-urls-into-structure.md): Canonicalise URLs into structure, and split the SSRF defence
- [ADR-007](docs/adr/ADR-007-named-templates-instead-of-command-strings.md): Named templates instead of canonicalising command languages

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
