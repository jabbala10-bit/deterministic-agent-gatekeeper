import collections

from gatekeeper.core import Envelope, Snapshot, decide
from spec.corpus import corpus_digest, load_meta, load_vectors

VECTORS = load_vectors()


def test_corpus_is_large_unique_and_bound_to_this_bundle(bundle):
    meta = load_meta()
    assert meta["count"] == len(VECTORS) >= 200
    assert len({v["name"] for v in VECTORS}) == len(VECTORS)
    assert meta["policy_hash"] == bundle.policy_hash


def test_every_verdict_is_exercised():
    counts = collections.Counter(v["expect"]["verdict"] for v in VECTORS)
    assert set(counts) == {"ALLOW", "DENY", "REQUIRE_APPROVAL"}
    assert min(counts.values()) >= 50


def test_every_golden_vector_reproduces_byte_for_byte(bundle):
    failures = []
    for vector in VECTORS:
        decision = decide(Envelope.from_json(vector["envelope"]), Snapshot.from_json(vector["snapshot"]), bundle)
        got = {
            "action_hash": decision.action_hash,
            "decision_hash": decision.decision_hash,
            "input_hash": decision.input_hash,
            "reasons": list(decision.reasons),
            "snapshot_hash": decision.snapshot_hash,
            "verdict": decision.verdict,
        }
        if got != vector["expect"]:
            failures.append(vector["name"])
    assert not failures, failures[:10]


def test_corpus_fingerprint_matches(bundle):
    assert corpus_digest(bundle) == load_meta()["corpus_digest"]


def test_formatting_variants_are_one_canonical_action():
    group = [v for v in VECTORS if v["name"].startswith("format/")]
    assert len(group) == 4
    assert len({v["expect"]["action_hash"] for v in group}) == 1      # what executes is identical
    assert len({v["expect"]["decision_hash"] for v in group}) == 4    # what was received is recorded exactly


def test_every_bypass_attempt_is_denied():
    attempts = [v for v in VECTORS if v["name"].startswith(("invalid/", "invalid-snapshot/"))]
    assert len(attempts) >= 30
    assert all(v["expect"]["verdict"] == "DENY" for v in attempts)
