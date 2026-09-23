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


def test_equivalence_classes_collapse_to_one_canonical_action():
    """Every spelling in a class must execute as the same action, and classes must stay distinct."""
    classes: dict[str, list[dict]] = collections.defaultdict(list)
    for vector in VECTORS:
        if vector["name"].startswith("equivalence/"):
            classes[vector["name"].split("/")[1]].append(vector)
    assert set(classes) == {"amount", "idna", "recipient", "url"}
    canonical = {}
    for family, group in classes.items():
        assert len(group) >= 3, family
        hashes = {v["expect"]["action_hash"] for v in group}
        assert len(hashes) == 1, (family, [v["name"] for v in group])
        # the raw bytes still differ, so each decision records exactly what arrived
        assert len({v["expect"]["decision_hash"] for v in group}) == len(group), family
        canonical[family] = hashes.pop()
    assert len(set(canonical.values())) == len(canonical)


def test_no_known_bypass_reaches_allow():
    attempts = [v for v in VECTORS if v["name"].startswith(("bypass/", "invalid-snapshot/"))]
    assert len(attempts) >= 80
    assert not [v["name"] for v in attempts if v["expect"]["verdict"] == "ALLOW"]
    refused_outright = [v for v in attempts if v["expect"]["verdict"] == "DENY"]
    assert len(refused_outright) >= 70
