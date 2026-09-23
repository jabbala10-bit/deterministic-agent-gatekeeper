"""The imperative shell around the pure core.

submit() reads the clock once, folds the session, calls decide(), and records the outcome. On ALLOW
it reserves the budget inside the same lock, so a decision that has been allowed but not yet
executed already counts against the cap."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from ..core import Decision, EntityRecord, Envelope, PolicyBundle, budget_reservation, canonicalize, decide
from ..core.errors import Rejection
from .session import Session, SessionStore


@dataclass(frozen=True)
class Ticket:
    """What the caller gets back. `reservation` is the handle it must settle once the tool ran."""

    decision: Decision
    reservation: int | None

    @property
    def verdict(self) -> str:
        return self.decision.verdict

    @property
    def action_hash(self) -> str | None:
        return self.decision.action_hash


class Gate:
    def __init__(self, bundle: PolicyBundle, directory: str | Path,
                 clock_ns: Callable[[], int] = time.time_ns) -> None:
        self._bundle = bundle
        self._store = SessionStore(directory, bundle)
        self._clock_ns = clock_ns

    @property
    def store(self) -> SessionStore:
        return self._store

    def open(self, session_id: str, principal: str) -> Session:
        return self._store.open(session_id, principal)

    def submit(self, *, session_id: str, principal: str, tool: str, arguments: str,
               facts: Iterable[EntityRecord] = ()) -> Ticket:
        session = self._store.open(session_id, principal)
        facts = tuple(facts)
        with session.transaction():
            snapshot = session.state.snapshot(facts)
            envelope = Envelope(tool=tool, arguments=arguments, principal=principal,
                                session_id=session_id, t_ms=self._clock_ns() // 1_000_000)
            decision = decide(envelope, snapshot, self._bundle)
            decided = session.append("decided", {
                "decision": decision.to_json(),
                "envelope": envelope.to_json(),
                "facts": [fact.to_json() for fact in facts],
            })
            if decision.verdict != "ALLOW":
                return Ticket(decision, None)
            if decision.action_hash in snapshot.approvals:
                session.append("approval_consumed", {"action_hash": decision.action_hash})
            session.append("reserved", {
                "action_hash": decision.action_hash,
                "counters": self._reservation(envelope),
                "reservation": decided.seq,
            })
            return Ticket(decision, decided.seq)

    def settle(self, *, session_id: str, reservation: int, outcome: str) -> None:
        """Called once the tool has run. Labels come from the manifest for the tool that actually
        ran, never from the caller, so a session cannot be kept clean by a forgetful executor."""
        session = self._store.open(session_id, "unknown")
        with session.transaction():
            labels: list[str] = []
            if outcome == "committed":
                labels = sorted(self._bundle.manifest.tools[self._tool_of(session, reservation)].result_labels)
            session.append("settled", {"labels": labels, "outcome": outcome, "reservation": reservation})

    def approve(self, *, session_id: str, action_hash: str, approver: str) -> None:
        session = self._store.open(session_id, approver)
        session.append("approval_granted", {"action_hash": action_hash, "approver": approver})

    def _reservation(self, envelope: Envelope) -> dict[str, int]:
        tool = self._bundle.manifest.tools[envelope.tool]
        try:
            return budget_reservation(canonicalize(envelope, self._bundle.manifest), tool)
        except Rejection:  # unreachable for an ALLOW, but a reservation must never guess
            return {}

    @staticmethod
    def _tool_of(session: Session, reservation: int) -> str:
        record: Any = session._log.records[reservation]
        return record["body"]["envelope"]["tool"]
