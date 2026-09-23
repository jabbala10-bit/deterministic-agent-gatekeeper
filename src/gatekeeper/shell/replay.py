"""Replay a session.

Phase 1 proved a verdict follows from its snapshot. This also proves the snapshot follows from the
session's own history, so nothing in the record can have been invented: the events are folded from
the beginning and each decision's snapshot is re-derived from the state that preceded it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core import Envelope, EntityRecord, LedgerError, PolicyBundle, Snapshot, apply, decide, initial_state
from ..core.ledger import Event
from .log import verify_chain


@dataclass
class ReplayReport:
    records: int = 0
    decisions: int = 0
    exact: int = 0
    snapshots_derived: int = 0
    chain_problems: list[str] = field(default_factory=list)
    ledger_problems: list[str] = field(default_factory=list)
    policy_mismatch: int = 0
    gate_mismatch: int = 0
    mismatches: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (self.records > 0 and self.decisions > 0 and self.exact == self.decisions
                and self.snapshots_derived == self.decisions
                and not (self.chain_problems or self.ledger_problems or self.mismatches))


def replay(records: list[dict[str, Any]], bundle: PolicyBundle, session_id: str | None = None,
           verifier: Any = None) -> ReplayReport:
    report = ReplayReport(records=len(records), chain_problems=verify_chain(records, verifier))
    if not records:
        return report
    session_id = session_id or records[0].get("body", {}).get("session_id", "")
    counters = tuple(sorted(bundle.manifest.counters))
    try:
        state = initial_state(session_id, counters)
    except LedgerError as err:
        report.ledger_problems.append(f"session: {err.code}")
        return report

    for index, record in enumerate(records):
        try:
            event = Event(record["seq"], record["kind"], record["body"])
        except (KeyError, TypeError, LedgerError) as err:
            report.ledger_problems.append(f"event {index}: unreadable ({err})")
            break
        if event.kind == "decided":
            report.decisions += 1
            _check_decision(report, index, event, state, bundle)
        try:
            state = apply(state, event, counters)
        except LedgerError as err:
            report.ledger_problems.append(f"event {index}: {err.code}")
            break
    return report


def _check_decision(report: ReplayReport, index: int, event: Event, state: Any, bundle: PolicyBundle) -> None:
    body = event.body
    try:
        envelope = Envelope.from_json(body["envelope"])
        facts = tuple(EntityRecord.from_json(fact) for fact in body["facts"])
        recorded = body["decision"]
    except (KeyError, TypeError, ValueError) as err:
        report.mismatches.append(f"event {index}: unreadable decision ({type(err).__name__})")
        return

    # The snapshot is not taken on trust: it is re-derived from the events that came before.
    derived = state.snapshot(facts)
    if derived.digest() == recorded.get("snapshot_hash"):
        report.snapshots_derived += 1
    else:
        report.mismatches.append(f"event {index}: snapshot does not follow from the ledger")
        return

    if recorded.get("policy_hash") != bundle.policy_hash:
        report.policy_mismatch += 1  # a different policy: that is a diff (phase 5), not a replay
        return
    fresh = decide(envelope, derived, bundle).to_json()
    if fresh == recorded:
        report.exact += 1
    elif fresh["gate"] != recorded.get("gate"):
        report.gate_mismatch += 1
    else:
        report.mismatches.append(
            f"event {index}: recorded {recorded.get('verdict')} {recorded.get('reasons')}, "
            f"re-derived {fresh['verdict']} {fresh['reasons']}")


def snapshot_at(records: list[dict[str, Any]], bundle: PolicyBundle, session_id: str, upto: int) -> Snapshot:
    """The snapshot the session would have produced after `upto` events. Used by tests and tooling."""
    counters = tuple(sorted(bundle.manifest.counters))
    state = initial_state(session_id, counters)
    for record in records[:upto]:
        state = apply(state, Event(record["seq"], record["kind"], record["body"]), counters)
    return state.snapshot()
