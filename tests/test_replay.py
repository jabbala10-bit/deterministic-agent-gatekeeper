"""Invariant 2: replayability, and what the hash chain does and does not protect against."""

import itertools

import pytest

from conftest import bundle_with_policies
from gatekeeper.shell import GENESIS, DecisionLog, read_log, replay, seal, verify_chain
from gatekeeper.shell.demo import run_demo


@pytest.fixture
def demo_records(bundle, tmp_path):
    ticks = itertools.count(1_790_000_000_000_000_000, 7_000_000)
    path = tmp_path / "decisions.jsonl"
    run_demo(bundle, path, clock_ns=lambda: next(ticks))
    return path, list(read_log(path))


def reseal(records):
    out, prev = [], GENESIS
    for seq, record in enumerate(records):
        sealed = seal(seq, prev, record["envelope"], record["snapshot"], record["decision"])
        out.append(sealed)
        prev = sealed["record_hash"]
    return out


def test_replay_rederives_every_recorded_decision_exactly(bundle, demo_records):
    _, records = demo_records
    report = replay(records, bundle)
    assert report.ok and report.exact == report.records == 18


def test_editing_a_recorded_verdict_is_caught_twice(bundle, demo_records):
    _, records = demo_records
    records[4]["decision"]["verdict"] = "ALLOW"
    report = replay(records, bundle)
    assert not report.ok
    assert report.chain_problems and report.mismatches


def test_a_consistently_resealed_forgery_still_fails_replay(bundle, demo_records):
    # Rewrite the first refund to EUR 900,000.00 and recompute the whole chain: hashing alone cannot
    # tell. Replay can, because the recorded decision no longer follows from the recorded inputs.
    # (A forger who also recomputes decisions is stopped by signatures, which arrive in phase 4.)
    _, records = demo_records
    records[0]["envelope"]["arguments"] = records[0]["envelope"]["arguments"].replace('"150.00"', '"900000.00"')
    forged = reseal(records)
    assert verify_chain(forged) == []
    report = replay(forged, bundle)
    assert not report.ok and report.mismatches


def test_a_different_policy_is_reported_as_a_diff_not_a_replay(demo_records, policies_text):
    _, records = demo_records
    report = replay(records, bundle_with_policies(policies_text.replace("<= 20000", "<= 30000")))
    assert report.policy_mismatch == report.records and not report.ok


def test_the_log_refuses_to_append_to_a_broken_chain(demo_records):
    path, _ = demo_records
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="broken chain"):
        DecisionLog(path)
