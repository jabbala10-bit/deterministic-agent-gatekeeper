# ADR-007: Named templates instead of canonicalising command languages

**Status:** Accepted · **Date:** 2026-09-23 · **Decider:** Gunasekar Jabbala (architect/owner)

## Context
Phase 2 canonicalises URLs, money and recipients. SQL and shell cannot be canonicalised on the same
terms: comments, string escapes, dialect differences and encodings give the same text more than one
meaning, and the gate's reading would have to match the database's exactly, forever.

## Options considered
| Option | For | Against |
|---|---|---|
| Free-form SQL with pattern matching in policy | No tool changes | A bypass zoo, and the gate becomes a weak WAF |
| Parse SQL properly and analyse the tree | Precise in principle | A second SQL implementation to keep in step with the database's own; a gate-versus-engine parser differential with real consequences |
| **Named templates with typed parameters** | Nothing the agent writes is ever interpreted as a command | Every new query needs a manifest change |

## Decision
A tool exposes named templates. The manifest declares each template and the type of every parameter,
and the canonical action carries `{name, params}`. The gate validates the name against the manifest
and each parameter against its type; the executor renders the template with bound parameters.

The policy sees only the template name. A Cedar record is closed and typed, and parameter shapes vary
per template, so exposing them would mean one context type per template. Parameters are still
validated and still covered by the action hash, so an approval binds to exact parameter values.

## Consequences
- Adding a query is a reviewable manifest change. That friction is the feature.
- `'; DROP TABLE` in a parameter is refused by the parameter's type, not by pattern matching, and a
  template name that is not in the manifest never reaches the tool.
- Policies cannot yet express per-parameter rules such as "only this session's customer". The session
  ledger in phase 3 is the natural place for that, and it would need per-template context types.

## Confidence and validation
High. Nine template rows in the known-bypass corpus, including SQL in a name, SQL in a parameter, an
unknown template, and a template that exists but no policy permits.
