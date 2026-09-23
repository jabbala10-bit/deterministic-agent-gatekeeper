"""Phase 3 exit proof: one writer per session, and a budget that cannot be spent twice."""

import collections
import itertools
import json
import threading
import time

from gatekeeper.core import EntityRecord
from gatekeeper.core.ledger import fold
from gatekeeper.shell import Gate, events_of, read_log, replay

FACTS = (EntityRecord.build("Account", "acc-1001", {"frozen": False}),)
TWO_HUNDRED = json.dumps({"account_id": "acc-1001", "amount": {"amount": "200.00", "currency": "EUR"}})
WORKERS = 100


def slow_clock(ticks=itertools.count(1_790_000_000_000_000_000, 1_000_000)):
    """A clock that dawdles, so the window between reading a budget and reserving against it is wide.

    The correct gate reads the clock inside the session lock, so this only makes the test slower. An
    implementation that reads the budget outside the lock lets every thread through that window, which
    is what turns a rare interleaving into a reliable failure."""
    time.sleep(0.002)
    return next(ticks)


def test_a_hundred_parallel_refunds_spend_the_cap_exactly_once(bundle, tmp_path):
    """EUR 200 each against a EUR 500 auto cap: two fit, and the rest must escalate rather than race."""
    gate = Gate(bundle, tmp_path, clock_ns=slow_clock)
    start = threading.Barrier(WORKERS)
    verdicts: list[str] = []
    guard = threading.Lock()

    def worker() -> None:
        start.wait()
        ticket = gate.submit(session_id="race", principal="support-bot", tool="payments.refund",
                             arguments=TWO_HUNDRED, facts=FACTS)
        with guard:
            verdicts.append(ticket.verdict)
        if ticket.verdict == "ALLOW":
            gate.settle(session_id="race", reservation=ticket.reservation, outcome="committed")

    threads = [threading.Thread(target=worker) for _ in range(WORKERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    counts = collections.Counter(verdicts)
    assert counts["ALLOW"] == 2, counts
    assert counts["REQUIRE_APPROVAL"] == WORKERS - 2, counts

    state = gate.store.open("race", "support-bot").state
    assert state.counters() == {"refunded_minor": 40_000}

    # The ledger written under contention is still a valid chain that replays exactly.
    records = list(read_log(gate.store.path_for("race")))
    report = replay(records, bundle, "race")
    assert report.ok
    assert report.decisions == WORKERS and report.exact == WORKERS
    assert report.snapshots_derived == WORKERS


def test_released_reservations_return_to_the_budget(bundle, tmp_path):
    gate = Gate(bundle, tmp_path)
    tickets = []
    for _ in range(2):
        ticket = gate.submit(session_id="rollback", principal="support-bot", tool="payments.refund",
                             arguments=TWO_HUNDRED, facts=FACTS)
        tickets.append(ticket)
        assert ticket.verdict == "ALLOW"
    # The cap is now fully reserved, so a third refund escalates.
    assert gate.submit(session_id="rollback", principal="support-bot", tool="payments.refund",
                       arguments=TWO_HUNDRED, facts=FACTS).verdict == "REQUIRE_APPROVAL"
    # One tool call failed: releasing it frees the budget again.
    gate.settle(session_id="rollback", reservation=tickets[1].reservation, outcome="released")
    assert gate.submit(session_id="rollback", principal="support-bot", tool="payments.refund",
                       arguments=TWO_HUNDRED, facts=FACTS).verdict == "ALLOW"


def test_labels_come_from_the_manifest_not_the_caller(bundle, tmp_path):
    gate = Gate(bundle, tmp_path)
    ticket = gate.submit(session_id="labels", principal="support-bot", tool="crm.lookup",
                         arguments=json.dumps({"customer_id": "cust-42"}))
    assert ticket.verdict == "ALLOW"
    assert gate.store.open("labels", "support-bot").state.labels == ()  # not applied until it ran
    gate.settle(session_id="labels", reservation=ticket.reservation, outcome="committed")
    state = fold("labels", tuple(sorted(bundle.manifest.counters)),
                 events_of(list(read_log(gate.store.path_for("labels")))))
    assert state.labels == ("private_data",)
