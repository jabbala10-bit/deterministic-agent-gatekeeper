"""The pure decision function.

decide(envelope, snapshot, bundle) performs no I/O, reads no clock and draws no randomness; the
shell supplies time inside the envelope and state inside the snapshot. The same inputs therefore
yield the same Decision, byte for byte, in any process on any machine with the same gate identity.

Three verdicts from two evaluations:
  ALLOW             the request as-is satisfies a permit and no forbid;
  DENY              a forbid matched, evaluation errored, input was invalid, or nothing permits it;
  REQUIRE_APPROVAL  denied only by default, and a human approval bound to this exact action hash
                    would satisfy a permit. Forbids are never re-evaluated away.
"""

from __future__ import annotations

import unicodedata
from typing import Any

import idna

from .bundle import PolicyBundle
from .canonical import CanonicalAction, canonicalize, context_args
from .digest import digest
from .errors import Rejection
from .model import Decision, Envelope, Snapshot

GATE_VERSION = "0.3.0"
CANON_VERSION = 3


def gate_identity(bundle: PolicyBundle) -> dict[str, Any]:
    return {
        "canon": CANON_VERSION,
        "engine": bundle.engine,
        "gate": GATE_VERSION,
        # Host canonicalisation depends on the IDNA tables, exactly as text depends on Unicode's.
        "idna": idna.__version__,
        "unicode": unicodedata.unidata_version,
    }


def build_context(env: Envelope, snap: Snapshot, action: CanonicalAction, action_hash: str,
                  bundle: PolicyBundle) -> dict[str, Any]:
    context: dict[str, Any] = {
        "action_hash": action_hash,
        "args": context_args(bundle.manifest.tools[action.tool], action.args),
        "now_ms": env.t_ms,
        "session": {
            "counters": dict(snap.counters),
            "labels": list(snap.labels),
            "ledger_seq": snap.ledger_seq,
        },
    }
    if action_hash in snap.approvals:
        context["approval"] = {"action_hash": action_hash}
    return context


def decide(env: Envelope, snap: Snapshot, bundle: PolicyBundle) -> Decision:
    gate = gate_identity(bundle)
    snapshot_hash = snap.digest()
    input_hash = digest("dag/input/v1", {
        "envelope": env.to_json(),
        "policy_hash": bundle.policy_hash,
        "snapshot_hash": snapshot_hash,
    })

    def finish(verdict: str, reasons: Any, action_hash: str | None = None) -> Decision:
        ordered = tuple(sorted(set(reasons)))
        body = {
            "action_hash": action_hash,
            "gate": gate,
            "input_hash": input_hash,
            "reasons": list(ordered),
            "verdict": verdict,
        }
        return Decision(verdict, ordered, action_hash, input_hash, snapshot_hash, bundle.policy_hash,
                        gate, digest("dag/decision/v1", body))

    if env.session_id != snap.session_id:
        return finish("DENY", ["INVALID_SNAPSHOT:session_mismatch"])
    try:
        bundle.manifest.check_snapshot(snap)
    except Rejection as err:
        return finish("DENY", [f"INVALID_SNAPSHOT:{err.code}"])
    try:
        action = canonicalize(env, bundle.manifest)
    except Rejection as err:
        return finish("DENY", [err.code])

    action_hash = action.digest()
    context = build_context(env, snap, action, action_hash, bundle)
    already_approved = "approval" in context

    first = bundle.evaluate(action, context, snap.entities)
    if first.errors:  # invariant 4: the engine skips erroring policies; the gate fails closed
        return finish("DENY", [f"EVAL_ERROR:{e}" for e in first.errors], action_hash)
    if first.allowed:
        return finish("ALLOW", first.reasons, action_hash)
    if first.reasons:  # an explicit forbid matched: final, no approval path (invariant 5)
        return finish("DENY", first.reasons, action_hash)
    if already_approved:
        return finish("DENY", ["NO_MATCHING_PERMIT"], action_hash)

    # Denied by default only. Would an approval bound to this exact action make a permit match?
    second = bundle.evaluate(action, {**context, "approval": {"action_hash": action_hash}}, snap.entities)
    if second.errors:
        return finish("DENY", [f"EVAL_ERROR:{e}" for e in second.errors], action_hash)
    if second.allowed:
        return finish("REQUIRE_APPROVAL", second.reasons, action_hash)
    return finish("DENY", second.reasons or ["NO_MATCHING_PERMIT"], action_hash)
