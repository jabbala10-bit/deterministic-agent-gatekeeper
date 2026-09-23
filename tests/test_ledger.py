"""Invariant 2, extended: a snapshot has to follow from the session's own history."""

import pytest

from gatekeeper.core import EntityRecord, Event, LedgerError, apply, fold, initial_state
from gatekeeper.core.ledger import budget_reservation
from gatekeeper.core.canonical import canonicalize
from spec import scenarios as sc

COUNTERS = ("refunded_minor",)


def events(*pairs):
    return [Event(seq, kind, body) for seq, (kind, body) in enumerate(pairs)]


def opened(session="sess-1", principal="support-bot"):
    return ("session_opened", {"principal": principal, "session_id": session})


def test_a_fresh_session_has_zeroed_counters_and_no_labels():
    state = initial_state("sess-1", COUNTERS)
    assert state.counters() == {"refunded_minor": 0}
    assert state.labels == () and state.approvals == () and state.principal is None


def test_reserved_money_counts_before_it_is_committed():
    # The whole point of reserve-then-settle: an allowed but unexecuted refund still occupies budget.
    state = fold("sess-1", COUNTERS, events(
        opened(),
        ("decided", {"decision": {}, "envelope": {}, "facts": []}),
        ("reserved", {"action_hash": "sha256:" + "11" * 32, "counters": {"refunded_minor": 20000}, "reservation": 1}),
    ))
    assert state.counters() == {"refunded_minor": 20000}
    assert state.committed == (("refunded_minor", 0),)


def test_committing_moves_a_reservation_and_applies_labels():
    state = fold("sess-1", COUNTERS, events(
        opened(),
        ("reserved", {"action_hash": "sha256:" + "11" * 32, "counters": {"refunded_minor": 20000}, "reservation": 1}),
        ("settled", {"labels": ["private_data"], "outcome": "committed", "reservation": 1}),
    ))
    assert state.counters() == {"refunded_minor": 20000}
    assert state.committed == (("refunded_minor", 20000),) and state.reserved == ()
    assert state.labels == ("private_data",)


def test_releasing_returns_the_budget_and_applies_nothing():
    state = fold("sess-1", COUNTERS, events(
        opened(),
        ("reserved", {"action_hash": "sha256:" + "11" * 32, "counters": {"refunded_minor": 20000}, "reservation": 1}),
        ("settled", {"labels": [], "outcome": "released", "reservation": 1}),
    ))
    assert state.counters() == {"refunded_minor": 0} and state.labels == ()


def test_labels_only_ever_accumulate():
    state = fold("sess-1", COUNTERS, events(
        opened(),
        ("reserved", {"action_hash": "sha256:" + "11" * 32, "counters": {}, "reservation": 1}),
        ("settled", {"labels": ["private_data"], "outcome": "committed", "reservation": 1}),
        ("reserved", {"action_hash": "sha256:" + "22" * 32, "counters": {}, "reservation": 3}),
        ("settled", {"labels": ["untrusted_input"], "outcome": "committed", "reservation": 3}),
    ))
    assert state.labels == ("private_data", "untrusted_input")


def test_an_approval_is_single_use():
    action = "sha256:" + "33" * 32
    granted = fold("sess-1", COUNTERS, events(opened(), ("approval_granted", {"action_hash": action, "approver": "duty-officer"})))
    assert granted.approvals == (action,)
    consumed = apply(granted, Event(2, "approval_consumed", {"action_hash": action}), COUNTERS)
    assert consumed.approvals == ()


@pytest.mark.parametrize("bad, code", [
    ([("settled", {"labels": [], "outcome": "committed", "reservation": 9})], "nothing_reserved"),
    ([("reserved", {"action_hash": "sha256:" + "11" * 32, "counters": {"wire_minor": 1}, "reservation": 1})], "bad_reservation"),
    ([("approval_consumed", {"action_hash": "sha256:" + "44" * 32})], "no_such_approval"),
    ([("reserved", {"action_hash": "sha256:" + "11" * 32, "counters": {}, "reservation": 1}),
      ("settled", {"labels": ["private_data"], "outcome": "released", "reservation": 1})], "released_actions_apply_no_labels"),
])
def test_impossible_histories_are_refused(bad, code):
    with pytest.raises(LedgerError) as err:
        fold("sess-1", COUNTERS, events(opened(), *bad))
    assert err.value.code == code


def test_events_before_the_session_is_open_are_refused():
    with pytest.raises(LedgerError) as err:
        fold("sess-1", COUNTERS, events(("decided", {"decision": {}, "envelope": {}, "facts": []})))
    assert err.value.code == "session_not_open"


def test_a_sequence_gap_is_refused():
    state = fold("sess-1", COUNTERS, events(opened()))
    with pytest.raises(LedgerError) as err:
        apply(state, Event(7, "approval_granted", {"action_hash": "sha256:" + "55" * 32, "approver": "x"}), COUNTERS)
    assert err.value.code == "sequence_gap"


def test_the_budget_reservation_comes_from_the_canonical_action(bundle):
    scenario = sc.refund_scenario(bundle.manifest, 45_000, "EUR", 0, "none", "ok")
    action = canonicalize(scenario.envelope, bundle.manifest)
    assert budget_reservation(action, bundle.manifest.tools["payments.refund"]) == {"refunded_minor": 45_000}
    assert budget_reservation(action, bundle.manifest.tools["email.send"]) == {}


def test_the_snapshot_is_a_function_of_the_state_and_the_facts():
    fact = EntityRecord.build("Account", "acc-1001", {"frozen": False})
    state = fold("sess-1", COUNTERS, events(
        opened(),
        ("reserved", {"action_hash": "sha256:" + "11" * 32, "counters": {"refunded_minor": 15000}, "reservation": 1}),
    ))
    snapshot = state.snapshot((fact,))
    assert snapshot.counters == (("refunded_minor", 15000),)
    assert snapshot.ledger_seq == state.seq == 2
    assert snapshot.digest() == state.snapshot((fact,)).digest()
