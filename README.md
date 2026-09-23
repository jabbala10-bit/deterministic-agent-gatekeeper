# Deterministic Agent Gatekeeper

[![verify](https://github.com/jabbala10-bit/deterministic-agent-gatekeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/jabbala10-bit/deterministic-agent-gatekeeper/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](.python-version)

**The model proposes, a pure function disposes, and every decision can be re-derived bit for bit.**

Per-call policy checks in front of agent tools are now table stakes. This project is about the two
properties that make such a gate trustworthy to an examiner: **determinism you can prove**, and
**one canonical action** that is both what was checked and what runs.

- Any past decision re-derives from its record on another machine, hash-exact.
- Any policy change is measured against history and against a generated request space before it ships.
- What executes is provably what was checked, enforced at the MCP boundary with a signed token.

In the portfolio, Orchestra AI is the runtime, TrustOS is the enforcement boundary, and the
Gatekeeper is the decision core that proves it decides the same way every time.

**All six phases are here**: the pure core, the canonicalisers, the session ledger, the
enforcement point, policy CI, and the evaluation.

## What is proven (measured in this repo)

| Exit criterion | Result |
|---|---|
| Golden vectors | **401**: 136 ALLOW, 162 DENY, 103 REQUIRE_APPROVAL |
| Measured against a benchmark I did not design | AgentDojo v1.2 banking, 16 user tasks x 9 injection tasks. With approvals: **all 16 legitimate tasks complete** (7 unattended, 9 needing a human, 10 approvals) and **144/144 attack pairs stopped**, 0 attacker calls executed |
| The over-blocking is published, not hidden | The strict variant **refuses 12 of 16 legitimate tasks** and stops no attack the approval variant did not already stop. Reading a bill is what forbids paying it |
| A widening policy change fails CI | `gatekeeper diff` moves the auto-refund cap from EUR 200.00 to EUR 200.01 and fails with a **concrete counterexample** at exactly that boundary, mined from the policy's own literal |
| A tightening names what it would have refused | The same command re-decides recorded ledgers and reports each past action whose verdict moves, by action hash |
| Enforcement against a server we did not write | The proxy runs in front of the published `@modelcontextprotocol/server-filesystem`: its **14 tools are filtered to the 3** the manifest declares, a sandbox escape never reaches it, and a file lands on disk **only after a human approves that exact call**, once |
| Execution is the checked action | The gate rebuilds the canonical action from its own record, so the executor is handed `{"amount":"150.00"}` even when the agent wrote `"150.0"`; tokens are single-use, bound to one action, and expire |
| Signatures catch a coherent forgery | A forger who rewrites an argument, recomputes the decision honestly and re-seals every hash produces a ledger that replays cleanly, and fails signature verification |
| Budget spent exactly once under load | **100 concurrent EUR 200 refunds against a EUR 500 cap: exactly 2 execute**, 98 escalate, EUR 400 committed |
| Snapshots are derived, not trusted | Replay folds the ledger and re-derives every snapshot; deleting a settled spend and re-sealing the chain is caught |
| Known-bypass corpus 100% refused | **85 attempts, 0 reach ALLOW.** 77 are denied outright with an exact reason code; 8 lookalike destinations escalate to a human instead |
| Equivalence classes collapse | 4 classes (URL, recipient, IDNA, amount): every spelling in a class produces one `action_hash`, and the classes stay distinct |
| Canonicalisation is idempotent | Property-tested for URLs, plus an exact round trip for money in every supported currency |
| Differential vs the tool's parser | Canonical URLs are unambiguous to `urllib`; inputs the two read differently are refused outright |
| Identical decision hashes across 10k runs | **10,000** randomised decisions reproduce exactly and match an independent oracle |
| Identical across separate processes | Fresh processes under `PYTHONHASHSEED` 0, 1, 42 and random re-derive corpus digest `sha256:7661a483…` |
| Stated intent, not just stable output | The corpus generator refuses to write when the gate disagrees with `spec/oracle.py`, which is written without Cedar |
| Tests catch real regressions | `make mutants` breaks the reason sort, fail-closed, core purity, the session lock, single-use tokens, egress pinning and the diff's boundary mining in a scratch copy; the suite catches all seven |
| Same result on other platforms | CI re-derives the corpus on Linux x86_64, Linux arm64, macOS arm64 and Windows |
| An upgrade is classified, not absorbed | On Python 3.13 (Unicode 15.1.0) every verdict is unchanged while every hash moves. `make identity` calls that an identity change, not a regression |
| Latency (1 vCPU sandbox, Python 3.12) | p50 **0.53 ms**, p99 **0.91 ms** per decision, including canonicalisation and up to two engine evaluations |

230 tests, about 35 seconds. The seven that drive a real MCP server skip when `npx` is absent,
and the benchmark replay skips without the `evals` dependency group.

## Quickstart

```bash
uv sync
make verify          # tests, then the demo and a replay of its log
make mutants         # sabotage the core three ways; each must be caught
make identity        # does this runtime still decide the same way?
make mcp             # drive a real published MCP server through the proxy (needs npx)
make diff CANDIDATE=/tmp/candidate    # what would this policy change do?
make evals           # replay AgentDojo's trajectories through the gate
```

`make demo` runs the scripted EU bank-servicing walkthrough and replays its ledger:

```
 #  step                                                     verdict           reasons
 1  Refund EUR 150.00                                        ALLOW             refund-auto
 2  Refund EUR 400.00                                        REQUIRE_APPROVAL  refund-approved
 3  Same refund once a human approved its hash               ALLOW             refund-approved
 4  The same refund a second time (approval was single-use)  REQUIRE_APPROVAL  refund-approved
 5  Refund EUR 150.00 with the session cap reached           REQUIRE_APPROVAL  refund-approved
 6  Refund to a frozen account                               DENY              no-refund-to-frozen-account
 7  Refund to an account the shell never loaded              DENY              EVAL_ERROR:no-refund-to-frozen-account
 8  Amount sent as the number 100.00                         DENY              INVALID_ARGUMENTS:float_not_allowed
 9  Look up the customer in the CRM                          ALLOW             reads-allowed
10  Report from a named template                             ALLOW             reports-allowlisted
11  Report template no policy permits                        DENY              NO_MATCHING_PERMIT
12  Email the customer (allowlisted domain)                  ALLOW             egress-allowlisted-recipient
13  Fetch an allowlisted host over TLS                       ALLOW             egress-allowlisted-host
14  Email the same customer after that fetch                 DENY              no-egress-after-untrusted-with-private
15  Injected: fetch the cloud metadata IP                    DENY              INVALID_ARGUMENTS:url:ip_literal_not_allowed
16  Injected: forward statements to an outsider              DENY              no-egress-after-untrusted-with-private
17  ...even after a human approved that exact action         DENY              no-egress-after-untrusted-with-private

session sess-demo-001: 33 events, labels ['private_data', 'untrusted_input'], counters {'refunded_minor': 55000}
replay PASS: 17/17 decisions re-derived hash-exact, 17/17 snapshots re-derived from the ledger
```

Nothing in that run hand-builds a snapshot. Step 5 escalates because steps 1 and 3 spent the session
cap; step 4 escalates because the approval from step 3 was single-use; and step 14 is refused because
the agent's own CRM read and web fetch labelled the session, not because a test set a flag.

Other commands: `gatekeeper submit`, `approve`, `settle`, `state` and `replay` drive a session
directly, and `gatekeeper schema` prints the Cedar schema generated from the manifest.

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

## The session ledger

A session is an append-only, hash-chained event log, and its snapshot is a pure fold over those
events. Nothing about a session is taken on the caller's word.

| Event | Effect on the fold |
|---|---|
| `session_opened` | fixes the principal |
| `decided` | records the envelope, the facts the shell loaded and the decision |
| `reserved` | holds a budget against the cap before the tool runs, keyed by the deciding event |
| `settled` | commits the reservation and applies the tool's result labels, or releases it and applies nothing |
| `approval_granted` / `approval_consumed` | a human approval appears, and is spent by the ALLOW that used it |

Three properties fall out of that shape:

- **A budget cannot be spent twice.** The reservation happens inside the same lock as the budget
  read, so an allowed-but-unexecuted refund already counts. 100 concurrent EUR 200 refunds against a
  EUR 500 cap let exactly two through.
- **Labels are earned.** They come from the manifest's `result_labels` for the tool that actually
  ran, applied on commit. A caller cannot keep a session clean by forgetting to mention what it did.
- **History cannot be edited.** Replay folds the ledger from the beginning and re-derives every
  snapshot, so deleting a settled spend and re-sealing the whole chain is still caught.

Counters are declared in the manifest and each tool names the argument that feeds one, so the core
knows nothing about refunds (ADR-008).

## The enforcement point

The agent talks to the proxy and to nothing else. The proxy speaks newline-delimited JSON-RPC to an
**unmodified** MCP server, relays everything except `tools/call`, and filters `tools/list` to the
tools the manifest declares, so the agent is never shown a tool it could not call.

```
agent ──tools/call──▶ proxy ──▶ gate.submit()  ──ALLOW──▶ signed token
                                     │                        │
                                  DENY / REQUIRE_APPROVAL     ▼
                                     │              gate.execute(token)
                                     ▼                  rebuilds the canonical action
                        isError result, reason           pins the resolved address
                        codes only, correlation id       ──▶ unmodified MCP server
```

A token is an Ed25519 signature over `{action_hash, expires_ms, reservation, session_id}`. Redeeming
it does not take arguments: the gate rebuilds the canonical action from its own record, so the
caller cannot execute anything other than what was checked. It is single use, because the
reservation it names closes on settlement, and it expires, so `gatekeeper sweep` can return the
budget a crashed executor left held.

What a refusal tells the agent is deliberately narrow:

```
gatekeeper: INVALID_ARGUMENTS:path:path_outside_sandbox (decision sha256:f583f480576d)
gatekeeper: APPROVAL_REQUIRED for action sha256:2e2004da... (decision sha256:a91c...)
gatekeeper: DENIED (decision sha256:d2275eea1472)
```

Faults in the agent's own input come back verbatim, because they help it correct itself. Policy
outcomes collapse to `DENIED` or `APPROVAL_REQUIRED` with a correlation id: an injected agent must
not be able to use denials to map the policy. The reasons stay in the ledger (ADR-009).

### Putting it in front of a real server

```bash
gatekeeper proxy --bundle policies/filesystem --session sess-local \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp/gatekeeper-fs-demo
```

`policies/filesystem/` is a bundle for that published server: reads inside a sandbox are allowed,
paths are canonicalised and confined before the server sees them, writes need a human approval, and
once the session has read a file (untrusted input) writes are refused outright. To wire it into an
MCP client such as Claude Code, register that same command as the server:

```bash
claude mcp add banking -- uv run --directory /path/to/deterministic-agent-gatekeeper \
  gatekeeper proxy --bundle policies/filesystem --session sess-local \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp/gatekeeper-fs-demo
```

The proxy is exercised against the real server by `make mcp`; the Claude Code registration above
follows its documented `claude mcp add` form but has not been run in this repository's CI.

## What it costs and what it buys

The only useful evaluation reports both sides. `evals/` replays AgentDojo's own ground-truth
trajectories through the gate: for each user task the calls a correct agent makes, and for each
injection task the calls the attacker wants, run in the same session so the injection arrives the
way it really does, through a tool result.

| | approval variant | strict variant |
|---|---|---|
| legitimate tasks completed with no human | 7 | 4 |
| legitimate tasks needing a human | 9 | 0 |
| **legitimate tasks blocked outright** | **0** | **12** |
| approvals asked of the human | 10 | 2 |
| attack pairs stopped | 144/144 | 144/144 |
| attacker calls that executed | 0 | 0 |

**The strict variant costs three quarters of the workload and buys nothing here.** Forbidding
sensitive actions once a session has read untrusted content sounds like the right guardrail until
you notice that paying a bill means reading the bill first. That is the finding worth taking from
this project, and it is why the shipped default escalates to a human instead of refusing.

The attack column reads perfectly because every injection in this suite ends in a payment to an
account the user has never paid, or a password change, and the policy requires a human for both. An
attacker who could route money to an already-known payee under the cap would not be stopped.
`evals/RESULTS.md` carries that caveat and the rest; CI regenerates it and fails if it drifts.

Latency, on one vCPU: `decide()` runs in about 0.3 ms, a durable append about 0.1 ms, and a full
submission about 1.8 ms. The policy engine is not the bottleneck; canonical JSON and hashing are
roughly a quarter of a submission, the fsync per event about a fifth, and Cedar itself about 7%.

```bash
make evals   # needs the evals dependency group; writes evals/RESULTS.md
```

## Before a policy ships

Two questions decide whether a policy change is safe, and `gatekeeper diff` answers both:

```bash
gatekeeper diff --base policies/bank-servicing --candidate /tmp/candidate \
                --history spec/history/bank-servicing
```

**What does it newly permit?** A request space is generated from the manifest: every tool, every enum
value, every subset of session labels, both approval states, facts present, absent and missing, and
integer values taken from `{v-1, v, v+1}` for **every literal in either policy set**. Hosts and
domains come from the bundle's own entities, plus a subdomain, a suffix splice that only looks
allowlisted, and something unrelated. Each request is decided twice by the real engine.

Moving the auto-refund cap by one cent is therefore caught by construction:

```
  WIDENING: 16 probe(s) the candidate allows and the base does not
    - payments.refund {"account_id":"probe-1","amount":{"amount":"200.01","currency":"EUR"}}
      session: labels none; counters refunded_minor=0; no approval
      base REQUIRE_APPROVAL ['refund-approved'] -> candidate ALLOW ['refund-auto']

FAIL: this change lets the agent do something it could not do before.
      If that is intended, say so explicitly with --allow-widening.
```

**Which past decisions would change?** Recorded ledgers are folded and re-decided against the
candidate. A ledger's evolution does not depend on policy, so every historical snapshot is re-derived
exactly and each affected action is named:

```
history: 17 recorded decisions, 1 would change
    - sess-demo-001 seq 1 payments.refund: ALLOW -> REQUIRE_APPROVAL ['refund-approved']
      (action sha256:40970841292e...)
```

CI runs this on every pull request against the base branch, per bundle. `spec/history/` holds a
committed, byte-identical session so the historical half always has something to report against; it
is generated by `make history` from a fixed clock and a published test seed.

This finds widenings. It does not prove their absence outside the enumerated domain: that needs the
symbolic check, and ADR-010 states exactly what it would take.

## The five invariants

| # | Invariant | Enforced by | Proven by |
|---|---|---|---|
| 1 | **Purity**: `decide()` does no I/O, reads no clock, draws no randomness | `core/` imports nothing that can; time and state enter as recorded inputs | AST lint over `core/`; fresh-process corpus replays |
| 2 | **Replayability**: every decision re-derives, and every snapshot is re-derived from the session's own events | Hash-chained ledger; the snapshot is a pure fold plus the recorded facts | 401 golden vectors; demo-ledger replay; forged and truncated ledgers |
| 3 | **Check equals execute**: only the canonical action runs | One parse into typed structure; a signed single-use token; execution rebuilds the action from the record rather than from the caller | Equivalence classes collapse to one hash; the executor receives canonical arguments; a token cannot be repointed, reused or outlived |
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
                         url, money, canonical, ledger (fold), bundle, decide, diff
src/gatekeeper/shell/    impure: loader, signed event log, session (one writer), gate (clock,
                         reserve/settle, tokens), tokens (Ed25519), executor (address pinning),
                         proxy (MCP), replay, demo
policies/filesystem/     a bundle for the published MCP filesystem server
examples/                a minimal MCP server, used by the proxy tests
policies/bank-servicing/ manifest.json · entities.json (config only) · policies.cedar
spec/                    oracle · scenarios · bypasses · corpus · gen_vectors · mutants ·
                         check_gate_identity · gen_history · vectors/ · history/
evals/                   agentdojo_eval · RESULTS.md · results.json
policies/agentdojo-banking[-strict]/   two policy variants, measured against each other
tests/                   one module per concern; invariants named I1–I5
docs/adr/                ADR-001 … ADR-007
```

## Limitations (deliberate, and on the roadmap)

- **Session labels are coarse.** Once tainted, a session stays tainted; there is no declassification.
  Finer-grained approaches exist, including FIDES and CaMeL. Over-blocking gets measured in phase 6.
- **Facts are recorded, not derived.** An account's frozen status comes from outside the ledger, so
  replay uses the facts recorded in the decision event. That half is evidence, not history.
- **Budgets are per session, and reservations can leak.** A crashed executor holds budget until its
  reservation is released; production needs a sweeper, which belongs with phase 4's execution token.
  Cross-session caps need a shared writer and are not attempted here.
- **Names are not resolved.** DNS is nondeterministic, so the gate rules on the canonical host and
  the executor must pin the resolved address and refuse private space (phase 4). `127.0.0.1.nip.io`
  is an executor concern by design.
- **No Public Suffix List.** Allowlisting a suffix covers everything beneath it, so allowlisting a
  public suffix would be a broad grant. Suffix entities are policy: reviewed, hashed and diffable.
- **Signing keys are generated, never rotated.** The gate mints a key on first use; rotation, escrow
  and revocation are not implemented, and the ledger is local files with no external anchoring.
- **The proxy is in the request path.** No rate limiting, no backpressure, no upstream health checks.
- **Sweeping is manual.** `gatekeeper sweep` releases expired reservations; nothing schedules it.
- **The evaluation measures decisions, not agents.** It replays recorded trajectories with no model
  in the loop, so an agent that reaches the same goal by another route is not modelled, and the
  modelled human always approves correctly.
- **The policy diff finds widenings, it does not prove their absence.** It enumerates a bounded
  request space built from the policy's own literals and the bundle's own entities. A widening
  reachable only outside that domain would pass (ADR-010).
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
| 3 | Session ledger: labels, reserve→commit budgets, one writer per session | **Done** |
| 4 | MCP proxy on `tools/call`; signed execution tokens; executor-side IP pinning; reservation sweeper | **Done** |
| 5 | `replay` and `diff` in CI; bounded widening check with counterexamples | **Done** (symbolic proof deferred, ADR-010) |
| 6 | AgentDojo replay with and without the gate; latency breakdown; cross-platform replay | **Done** ([results](evals/RESULTS.md)) |

## Decisions

- [ADR-001](docs/adr/ADR-001-cedar-as-the-decision-engine.md): Cedar, not Rego, as the decision engine
- [ADR-002](docs/adr/ADR-002-python-first-with-vectors-as-the-contract.md): Python for phase 1; the golden corpus is the contract
- [ADR-003](docs/adr/ADR-003-canonical-hashing.md): Canonical hashing: RFC 8785 over a float-free domain
- [ADR-004](docs/adr/ADR-004-fail-closed-on-evaluation-errors.md): Fail closed on any evaluation error; validate at load
- [ADR-005](docs/adr/ADR-005-separate-policy-configuration-from-runtime-facts.md): Policy configuration and runtime facts travel separately
- [ADR-006](docs/adr/ADR-006-canonicalise-urls-into-structure.md): Canonicalise URLs into structure, and split the SSRF defence
- [ADR-007](docs/adr/ADR-007-named-templates-instead-of-command-strings.md): Named templates instead of canonicalising command languages
- [ADR-008](docs/adr/ADR-008-session-ledger-with-reserve-then-settle.md): An event-sourced session ledger, with budgets reserved before execution
- [ADR-009](docs/adr/ADR-009-enforcement-at-the-mcp-boundary.md): Enforce at the MCP boundary, with a signed token per checked action
- [ADR-010](docs/adr/ADR-010-bounded-differential-now-symbolic-proof-later.md): Bounded differential policy diffing now, symbolic proof as a named upgrade
- [ADR-011](docs/adr/ADR-011-evaluate-against-recorded-trajectories.md): Evaluate against recorded trajectories, and publish where it over-blocks

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
