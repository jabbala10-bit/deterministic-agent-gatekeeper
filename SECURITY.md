# Security

## Status of this code

Research and portfolio software, built in phases. **Phase 1 is a decision core, not a deployed
control.** Until phase 4 lands, it does not enforce anything by itself:

- decision records are hash-chained but **not signed**, so a forger who rewrites inputs, recomputes
  the decisions and re-seals the chain is not caught by hashing alone;
- there is **no enforcement point** yet, so nothing stops a caller from ignoring a DENY;
- canonicalisers cover ids, bounded integers, enums, text and ASCII email addresses. URLs and
  internationalised addresses are **refused**, not handled.

Do not put it in front of real money or real customer data before phases 2 to 4.

## Threat model

The agent is assumed to be fully compromised: it may propose any tool, any arguments, and any
encoding of them. The trusted parts are the shell that authenticates the principal and stamps time,
the policy bundle, and the snapshot the shell loads. Denial reasons are stable codes and never carry
policy text or engine error messages, so an injected agent cannot use denials to map the policy.

## Reporting

Open a GitHub issue for defects. For anything you believe is exploitable, use GitHub's private
vulnerability reporting on this repository instead of a public issue.
