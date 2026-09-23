# ADR-009: Enforce at the MCP boundary, with a signed token per checked action

**Status:** Accepted · **Date:** 2026-09-23 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
Phases 1 to 3 produce decisions and a ledger, and nothing yet stops a caller from ignoring a DENY or
from executing arguments other than the ones that were checked. "What executes is what was checked"
was still a promise rather than a mechanism.

## Options considered
| Option | For | Against |
|---|---|---|
| A library the agent framework calls | Simple, no protocol work | The thing being constrained decides whether to call the gate; a compromised or careless caller simply doesn't |
| Patch each MCP server to consult the gate | Enforcement lives next to execution | Every server has to be modified and kept in step, which does not scale and rules out servers you do not own |
| **A proxy on the MCP boundary, plus a signed token** | The agent talks to the proxy and nothing else; the token proves a specific canonical action was allowed | One more hop, and the proxy becomes a component that must itself be correct |

## Decision
An MCP proxy speaks newline-delimited JSON-RPC to the client on one side and to an **unmodified** MCP
server on the other. `tools/call` is intercepted; everything else is relayed, and `tools/list` is
filtered to the tools the manifest declares, so the agent is never shown a tool it could not call.

On ALLOW the gate mints an Ed25519 **execution token** over `{action_hash, expires_ms, reservation,
session_id}`. To execute, the token is redeemed:

- the gate **rebuilds the canonical action from its own record**, so the caller does not supply
  arguments at all and cannot execute anything other than what was checked;
- the token is **single use**, because the reservation it names is closed on settlement;
- it **expires**, so a forgotten one cannot be redeemed later, and a sweeper releases the budget;
- URL arguments are **pinned at connect time**: the resolved address must be public, which is the
  executor half of the SSRF split from ADR-006.

Ed25519 is deterministic, so a signature is a pure function of the payload and the key. The ledger
records the payload and never stores the signature. Every ledger event is signed the same way, which
is what catches a forger who rewrites an input, recomputes the decision honestly and re-seals the
entire chain: that forgery is internally coherent and replays cleanly, and it has no valid signature.

**What a refusal tells the agent.** Faults in its own input come back verbatim, because they help it
correct itself. Policy outcomes collapse to `DENIED` or `APPROVAL_REQUIRED` plus a correlation id.
An injected agent must not be able to use denials as an oracle for mapping the policy; the reasons
stay in the ledger where a human reads them.

## Consequences
- The gate now has a key to manage. It is generated on first use next to the sessions it authorises,
  and rotation is a real operational task that this phase does not solve.
- The proxy is in the request path, so its failure is the agent's failure. It is deliberately small.
- A tool whose arguments the manifest does not model cannot be called through the proxy at all. That
  is intended, and it means adopting a server starts with writing its manifest.
- Token TTL trades safety against long-running tools; the default is two minutes and a slow tool
  needs a longer one rather than an unbounded one.

## Confidence and validation
High. Seven integration tests run the proxy in front of the published
`@modelcontextprotocol/server-filesystem`: its fourteen tools are filtered to three, a sandbox escape
is refused before the server sees it, and a file appears on disk only after a human approves that
exact call, once. `make mutants` removes the single-use check and the egress pin and confirms the
suite fails in both cases.
