# Security

## Status of this code

Research and portfolio software, built in phases. **Phases 1 to 3 are a decision core with a session
ledger, not a deployed control.** Until phase 4 lands, it does not enforce anything by itself:

- ledger events are hash-chained but **not signed**, so a forger with write access who rewrites
  inputs, recomputes the decisions and re-seals the whole chain is not caught by hashing alone;
- there is **no enforcement point** yet, so nothing stops a caller from ignoring a DENY, or from
  executing a tool and never settling the reservation;
- a crashed executor **leaks its reservation**, holding budget until something releases it. There is
  no sweeper yet;
- names are **not resolved**. The gate rules on the canonical host; pinning the resolved address and
  refusing private space at connect time is the executor's job in phase 4, which is why a name such
  as 127.0.0.1.nip.io is out of scope here.

Do not put it in front of real money or real customer data before phase 4.

## Threat model

The agent is assumed to be fully compromised: it may propose any tool, any arguments, and any
encoding of them. The trusted parts are the shell that authenticates the principal and stamps time,
the policy bundle, and the snapshot the shell loads. Denial reasons are stable codes and never carry
policy text or engine error messages, so an injected agent cannot use denials to map the policy.

## Reporting

Open a GitHub issue for defects. For anything you believe is exploitable, use GitHub's private
vulnerability reporting on this repository instead of a public issue.
