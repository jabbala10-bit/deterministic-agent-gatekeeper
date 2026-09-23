"""Invariant 2: replayability, and what the hash chain does and does not protect against."""

import itertools

import pytest

from conftest import bundle_with_policies
from gatekeeper.core import Event
from gatekeeper.shell import GENESIS, EventLog, read_log, replay, seal
from gatekeeper.shell.demo import SESSION, run_demo


@pytest.fixture
def demo_ledger(bundle, tmp_path):
    ticks = itertools.count(1_790_000_000_000_000_000, 7_000_000)
    _, path = run_demo(bundle, tmp_path, clock_ns=lambda: next(ticks))
    return path, list(read_log(path))


def reseal(records):
    """Recompute sequence numbers and the whole chain, as a forger with write access would."""
    out, prev = [], GENESIS
    for seq, record in enumerate(records):
        sealed = seal(Event(seq, record["kind"], record["body"]), prev)
        out.append(sealed)
        prev = sealed["record_hash"]
    return out


def test_replay_rederives_every_decision_and_every_snapshot(bundle, demo_ledger):
    _, records = demo_ledger
    report = replay(records, bundle, SESSION)
    assert report.ok
    assert report.decisions == 17 and report.exact == 17 and report.snapshots_derived == 17
    assert report.records == 33  # decisions, reservations, settlements and approvals


def test_editing_a_recorded_verdict_is_caught_twice(bundle, demo_ledger):
    _, records = demo_ledger
    decided = next(r for r in records if r["kind"] == "decided" and r["body"]["decision"]["verdict"] == "DENY")
    decided["body"]["decision"]["verdict"] = "ALLOW"
    report = replay(records, bundle, SESSION)
    assert not report.ok
    assert report.chain_problems and report.mismatches


def test_a_consistently_resealed_forgery_still_fails_replay(bundle, demo_ledger):
    # Rewrite the first refund to EUR 900,000.00 and recompute the whole chain: hashing alone cannot
    # tell. Replay can, because the recorded decision no longer follows from the recorded inputs.
    # (A forger who also recomputes decisions is stopped by signatures, which arrive in phase 4.)
    _, records = demo_ledger
    decided = next(r for r in records if r["kind"] == "decided")
    decided["body"]["envelope"]["arguments"] = decided["body"]["envelope"]["arguments"].replace('"150.00"', '"900000.00"')
    forged = reseal(records)
    report = replay(forged, bundle, SESSION)
    assert not report.ok and report.mismatches


def test_a_spend_cannot_be_deleted_from_history(bundle, demo_ledger):
    """Drop a settlement and re-seal: the chain verifies, but later snapshots no longer follow."""
    _, records = demo_ledger
    without_settlement = [r for r in records if r["kind"] != "settled"][:]
    forged = reseal(without_settlement)
    assert replay(forged, bundle, SESSION).ok is False


def test_a_different_policy_is_reported_as_a_diff_not_a_replay(bundle, demo_ledger, policies_text):
    _, records = demo_ledger
    other = bundle_with_policies(policies_text.replace("<= 20000", "<= 30000"))
    report = replay(records, other, SESSION)
    assert report.policy_mismatch == report.decisions and not report.ok


def test_the_log_refuses_to_append_to_a_broken_chain(demo_ledger):
    path, _ = demo_ledger
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="broken chain"):
        EventLog(path)
