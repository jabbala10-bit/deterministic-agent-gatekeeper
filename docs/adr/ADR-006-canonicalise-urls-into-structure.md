# ADR-006: Canonicalise URLs into structure, and split the SSRF defence

**Status:** Accepted · **Date:** 2026-09-23 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
URLs carry more representation tricks than every other argument combined: credentials that move the
real host past a reader, numeric address spellings the resolver accepts, tabs that one parser strips
and another keeps, percent-encoding that can invent a path separator. A gate that hands a URL string
to an executor has checked a different thing from the one that runs.

## Options considered
| Option | For | Against |
|---|---|---|
| Pass the string, match it in policy | Simple, no new code | Every trick in the corpus works; a substring check reads `bank.example` in `https://bank.example@evil.test/` |
| Reuse a convenience parser (urllib, a WHATWG implementation) | Free, well tested | Ties the gate's view to one library's quirks while the tool may use another; browser-style parsers silently strip tab, CR and LF and accept backslash as a separator |
| **Own strict grammar producing typed fields** | The gate and the executor exchange structure, and anything ambiguous is refused rather than guessed at | More code, and it refuses some legitimate inputs |

## Decision
Parse with the gate's own RFC 3986 grammar into `{scheme, host, port, path, query}` and pass that.
Specifically:
- scheme allowlisted per tool; no userinfo at all; fragment dropped, because it never reaches the server;
- host through IDNA UTS-46, lower-cased A-labels, trailing dot removed, and the IDNA version recorded
  in the gate identity exactly as the Unicode version already was;
- IP literals refused unless a tool opts in, and the final label must be alphabetic or punycode. That
  last rule is what refuses `0x7f.0.0.0x1`, `127.1` and `2130706433`, which Python's `ipaddress`
  rejects as addresses while the OS resolver happily reads them as 127.0.0.1;
- percent-encoding normalised by decoding only unreserved characters, so `%2F` stays encoded and can
  never become a path separator, then dot segments removed, so `%2e%2e%2f` is handled too;
- control characters, raw spaces and backslashes refused.

**The DNS half stays out of the core.** Resolution is nondeterministic, so `decide()` rules on the
canonical host and the executor pins the resolved address and refuses private space at connect time
(phase 4). A name such as `127.0.0.1.nip.io` is therefore an executor concern by design, not a gap in
the parser.

**Suffix hierarchy.** The resource entity is hung under every right-hand suffix of its host, so a
bundle allowlists `bank.example` and covers `docs.bank.example` with no string matching, while
`bank.example.attacker.test` lands nowhere near it.

## Consequences
- Refusal replaces guessing, so some legitimate inputs are rejected: internationalised local parts,
  IP literals, unusual but valid characters. That is over-blocking and gets measured in phase 6.
- There is no Public Suffix List, so allowlisting a public suffix such as `co.uk` would be a very
  broad grant. Suffix entities are policy: they are reviewed, hashed and diffable, and a PSL guard is
  a candidate for a later phase.
- The gate identity now includes the IDNA version, so upgrading that library is a deliberate corpus
  regeneration rather than a silent change of meaning.

## Confidence and validation
High for the parser: 24 URL rows in the known-bypass corpus, an idempotence property, and a
differential test against `urllib`. Medium for suffix allowlisting until a PSL guard exists.
