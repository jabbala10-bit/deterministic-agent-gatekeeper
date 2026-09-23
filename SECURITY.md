# Security

## Status of this code

Research and portfolio software, built in phases. **Phases 1 to 4 give a decision core, a session
ledger and an enforcement point.** It is still not a supported product, and these gaps are real:

- the gate's signing key is generated on first use and **never rotated**. Key rotation, escrow and
  revocation are not implemented;
- the ledger is **local files**. There is no external anchoring, so an attacker who owns the host
  and the key owns the history;
- the proxy is **in the request path**, so if it fails the agent fails. It has no rate limiting,
  no backpressure and no upstream health checking;
- **denials are coarse by design.** An agent learns only that it was denied, which means an operator
  has to read the ledger to know why;
- a tool whose arguments the manifest does not model **cannot be called at all** through the proxy;
- **sweeping is manual.** `gatekeeper sweep` releases expired reservations; nothing runs it for you.

Do not put it in front of real money or real customer data without solving key management, ledger
durability and operational monitoring first.

## Threat model

The agent is assumed to be fully compromised: it may propose any tool, any arguments, and any
encoding of them. The trusted parts are the shell that authenticates the principal and stamps time,
the policy bundle, and the snapshot the shell loads. Denial reasons are stable codes and never carry
policy text or engine error messages, so an injected agent cannot use denials to map the policy.

## Reporting

Open a GitHub issue for defects. For anything you believe is exploitable, use GitHub's private
vulnerability reporting on this repository instead of a public issue.
