"""Session ledger: the event log a snapshot is folded from.

A decision record proves the verdict follows from the snapshot. This module proves the snapshot
follows from the session's own history, so a whole session replays rather than one call at a time.

The fold is pure. Appending, locking and fsync live in the shell; everything here is a function of
the events and the facts recorded alongside them.

Budgets are reserved before a tool runs and settled afterwards, because a decision that has been
allowed but not yet executed still has to count against the cap: otherwise a hundred concurrent
requests each see an empty budget and all of them pass."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .errors import Rejection
from .model import EntityRecord, Snapshot
from .strictjson import MAX_SAFE_INT
from .syntax import HASH_RE, ID_RE, NAME_RE, matches

EVENT_KINDS = ("approval_consumed", "approval_granted", "decided", "reserved", "session_opened", "settled")
OUTCOMES = ("committed", "released")


class LedgerError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class Event:
    seq: int
    kind: str
    body: dict[str, Any]

    def __post_init__(self) -> None:
        if type(self.seq) is not int or not 0 <= self.seq <= MAX_SAFE_INT:
            raise LedgerError("bad_sequence")
        if self.kind not in EVENT_KINDS:
            raise LedgerError("unknown_event_kind")
        if type(self.body) is not dict:
            raise LedgerError("bad_body")

    def to_json(self) -> dict[str, Any]:
        return {"body": dict(self.body), "kind": self.kind, "seq": self.seq}

    @classmethod
    def from_json(cls, obj: Any) -> "Event":
        if type(obj) is not dict or sorted(obj) != ["body", "kind", "seq"]:
            raise LedgerError("bad_event")
        return cls(obj["seq"], obj["kind"], obj["body"])


@dataclass(frozen=True, slots=True)
class LedgerState:
    """Everything the session knows about itself, folded from its events."""

    session_id: str
    principal: str | None
    seq: int
    labels: tuple[str, ...]
    committed: tuple[tuple[str, int], ...]
    reserved: tuple[tuple[int, str, tuple[tuple[str, int], ...]], ...]  # (reservation, action hash, deltas)
    approvals: tuple[str, ...]

    def counters(self) -> dict[str, int]:
        """Committed spend plus everything currently reserved: what a cap must be measured against."""
        totals = dict(self.committed)
        for _, _, deltas in self.reserved:
            for name, amount in deltas:
                totals[name] = totals.get(name, 0) + amount
        return totals

    def snapshot(self, facts: Iterable[EntityRecord] = ()) -> Snapshot:
        return Snapshot.build(
            session_id=self.session_id,
            ledger_seq=self.seq,
            labels=self.labels,
            counters=self.counters(),
            approvals=self.approvals,
            entities=tuple(facts),
        )


def initial_state(session_id: str, counter_names: Sequence[str]) -> LedgerState:
    if not matches(ID_RE, session_id):
        raise LedgerError("bad_session_id")
    return LedgerState(
        session_id=session_id,
        principal=None,
        seq=0,
        labels=(),
        committed=tuple(sorted((name, 0) for name in counter_names)),
        reserved=(),
        approvals=(),
    )


def _deltas(body: Any, counter_names: Sequence[str]) -> tuple[tuple[str, int], ...]:
    amounts = body.get("counters")
    if type(amounts) is not dict:  # a tool without a budget still reserves, with nothing in it
        raise LedgerError("bad_reservation")
    for name, amount in amounts.items():
        if name not in counter_names or type(amount) is not int or not 0 <= amount <= MAX_SAFE_INT:
            raise LedgerError("bad_reservation")
    return tuple(sorted(amounts.items()))


def _action_hash(body: Any) -> str:
    value = body.get("action_hash")
    if not matches(HASH_RE, value):
        raise LedgerError("bad_action_hash")
    return value


def apply(state: LedgerState, event: Event, counter_names: Sequence[str]) -> LedgerState:
    """One event, one deterministic state transition. Rejects any sequence that cannot have happened."""
    if event.seq != state.seq:
        raise LedgerError("sequence_gap")
    body = event.body
    seq = state.seq + 1

    if event.kind == "session_opened":
        if state.principal is not None or state.seq != 0:
            raise LedgerError("session_already_open")
        principal = body.get("principal")
        if not matches(ID_RE, principal) or body.get("session_id") != state.session_id:
            raise LedgerError("bad_session_opened")
        return _replace(state, seq=seq, principal=principal)

    if state.principal is None:
        raise LedgerError("session_not_open")

    if event.kind == "decided":
        if sorted(body) != ["decision", "envelope", "facts"]:
            raise LedgerError("bad_decided")
        return _replace(state, seq=seq)

    if event.kind == "reserved":
        # Reservations are keyed by the sequence of the decision that created them, so the same
        # canonical action can legitimately run twice in one session.
        action_hash = _action_hash(body)
        reservation = body.get("reservation")
        if type(reservation) is not int or reservation < 0:
            raise LedgerError("bad_reservation")
        if any(existing == reservation for existing, _, _ in state.reserved):
            raise LedgerError("already_reserved")
        deltas = _deltas(body, counter_names)
        reserved = tuple(sorted(state.reserved + ((reservation, action_hash, deltas),)))
        return _replace(state, seq=seq, reserved=reserved)

    if event.kind == "settled":
        reservation = body.get("reservation")
        outcome = body.get("outcome")
        if outcome not in OUTCOMES:
            raise LedgerError("bad_outcome")
        labels = body.get("labels", [])
        if type(labels) is not list or not all(matches(NAME_RE, label) for label in labels):
            raise LedgerError("bad_labels")
        match = [deltas for existing, _, deltas in state.reserved if existing == reservation]
        if not match:
            raise LedgerError("nothing_reserved")
        remaining = tuple(entry for entry in state.reserved if entry[0] != reservation)
        committed = dict(state.committed)
        new_labels = state.labels
        if outcome == "committed":
            for name, amount in match[0]:
                committed[name] = committed.get(name, 0) + amount
            new_labels = tuple(sorted(set(state.labels) | set(labels)))
        elif labels:
            raise LedgerError("released_actions_apply_no_labels")
        return _replace(state, seq=seq, labels=new_labels, reserved=remaining,
                        committed=tuple(sorted(committed.items())))

    if event.kind == "approval_granted":
        action_hash = _action_hash(body)
        if not matches(ID_RE, body.get("approver", "")):
            raise LedgerError("bad_approver")
        return _replace(state, seq=seq, approvals=tuple(sorted(set(state.approvals) | {action_hash})))

    if event.kind == "approval_consumed":
        action_hash = _action_hash(body)
        if action_hash not in state.approvals:
            raise LedgerError("no_such_approval")
        return _replace(state, seq=seq, approvals=tuple(a for a in state.approvals if a != action_hash))

    raise LedgerError("unknown_event_kind")


def fold(session_id: str, counter_names: Sequence[str], events: Iterable[Event]) -> LedgerState:
    state = initial_state(session_id, counter_names)
    for event in events:
        state = apply(state, event, counter_names)
    return state


def budget_reservation(action: Any, tool: Any) -> dict[str, int]:
    """What a tool's budget declaration reserves for this canonical action."""
    if tool.budget_counter is None:
        return {}
    value = action.args[tool.budget_from]
    if tool.budget_field:
        value = value[tool.budget_field]
    if type(value) is not int or value < 0:
        raise Rejection("bad_budget_value")
    return {tool.budget_counter: value}


def _replace(state: LedgerState, **changes: Any) -> LedgerState:
    fields = {
        "session_id": state.session_id, "principal": state.principal, "seq": state.seq,
        "labels": state.labels, "committed": state.committed, "reserved": state.reserved,
        "approvals": state.approvals,
    }
    fields.update(changes)
    return LedgerState(**fields)
