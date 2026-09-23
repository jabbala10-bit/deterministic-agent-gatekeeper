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
from ..core.canonical import wire_arguments
from ..core.errors import Rejection
from .executor import Resolver, egress_pins, system_resolver
from .session import Session, SessionStore
from .tokens import KeyRing, TokenError, TokenPayload


DEFAULT_TOKEN_TTL_MS = 120_000


@dataclass(frozen=True)
class Ticket:
    """What the caller gets back. On ALLOW it carries the single-use token the executor must present."""

    decision: Decision
    reservation: int | None
    token: str | None = None

    @property
    def verdict(self) -> str:
        return self.decision.verdict

    @property
    def action_hash(self) -> str | None:
        return self.decision.action_hash


class Gate:
    def __init__(self, bundle: PolicyBundle, directory: str | Path,
                 clock_ns: Callable[[], int] = time.time_ns, keyring: KeyRing | None = None,
                 token_ttl_ms: int = DEFAULT_TOKEN_TTL_MS, resolver: Resolver = system_resolver) -> None:
        self._bundle = bundle
        self._keyring = keyring or KeyRing.load_or_create(Path(directory) / "gate-key.pem")
        self._store = SessionStore(directory, bundle, self._keyring)
        self._clock_ns = clock_ns
        self._ttl_ms = token_ttl_ms
        self._resolver = resolver

    @property
    def key_id(self) -> str:
        return self._keyring.key_id

    @property
    def verifier(self):
        return self._keyring.verifier

    def now_ms(self) -> int:
        return self._clock_ns() // 1_000_000

    @property
    def bundle(self) -> PolicyBundle:
        return self._bundle

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
            expires_ms = envelope.t_ms + self._ttl_ms
            session.append("reserved", {
                "action_hash": decision.action_hash,
                "counters": self._reservation(envelope),
                "expires_ms": expires_ms,
                "reservation": decided.seq,
            })
            token = self._keyring.mint(TokenPayload(decision.action_hash, expires_ms, decided.seq, session_id))
            return Ticket(decision, decided.seq, token)

    def execute(self, token: str, runner: Callable[[str, dict[str, Any]], Any]) -> Any:
        """Redeem a token: the gate rebuilds the canonical action from its own record and hands the
        runner that, so the caller cannot execute anything other than what was checked."""
        payload = self._keyring.verifier.verify(token, now_ms=self.now_ms())
        session = self._store.get(payload.session_id)
        with session.transaction():
            open_reservations = {entry[0]: entry for entry in session.state.reserved}
            if payload.reservation not in open_reservations:
                raise TokenError("reservation_not_open")  # already settled, released or swept: single use
            _, action_hash, _, _ = open_reservations[payload.reservation]
            if action_hash != payload.action_hash:
                raise TokenError("action_mismatch")
            envelope = Envelope.from_json(session.record(payload.reservation)["body"]["envelope"])
            action = canonicalize(envelope, self._bundle.manifest)
            if action.digest() != payload.action_hash:
                raise TokenError("action_mismatch")
            tool = self._bundle.manifest.tools[action.tool]
            arguments = wire_arguments(tool, action.args)
            egress_pins(tool, action.args, self._resolver)  # refuses non-public addresses
        try:
            result = runner(action.tool, arguments)
        except Exception:
            self.settle(session_id=payload.session_id, reservation=payload.reservation, outcome="released")
            raise
        self.settle(session_id=payload.session_id, reservation=payload.reservation, outcome="committed")
        return result

    def sweep(self, session_id: str, *, now_ms: int | None = None) -> list[int]:
        """Release reservations whose token has expired. A crashed executor must not hold budget."""
        now = self.now_ms() if now_ms is None else now_ms
        session = self._store.get(session_id)
        released: list[int] = []
        with session.transaction():
            for reservation, _, _, expires_ms in list(session.state.reserved):
                if expires_ms < now:
                    session.append("settled", {"labels": [], "outcome": "released", "reservation": reservation})
                    released.append(reservation)
        return released

    def pending(self, session_id: str) -> list[dict[str, Any]]:
        """Decisions still waiting on a human, newest last."""
        session = self._store.get(session_id)
        with session.transaction():
            approved = set(session.state.approvals)
            out = []
            for record in session.records():
                if record["kind"] != "decided":
                    continue
                decision = record["body"]["decision"]
                if decision["verdict"] == "REQUIRE_APPROVAL" and decision["action_hash"] not in approved:
                    out.append({"action_hash": decision["action_hash"], "decided": record["seq"],
                                "reasons": decision["reasons"], "tool": record["body"]["envelope"]["tool"]})
            return out

    def settle(self, *, session_id: str, reservation: int, outcome: str) -> None:
        """Called once the tool has run. Labels come from the manifest for the tool that actually
        ran, never from the caller, so a session cannot be kept clean by a forgetful executor."""
        session = self._store.get(session_id)
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
        return session.record(reservation)["body"]["envelope"]["tool"]
