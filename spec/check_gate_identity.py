"""Re-decide the golden corpus under the current runtime and report how it relates to the record.

Hash-exact replay is defined for one gate identity: gate version, canonical form, engine version and
Unicode version. Run this after upgrading Python or cedarpy. It separates the two things an upgrade
can do:

  * behaviour changed  -> a real regression; exits 1;
  * only the identity changed -> every verdict and reason is unchanged and every hash moved together,
    so regenerate the corpus deliberately with `make vectors`; exits 0 and says so.

Python's Unicode version is part of the identity (3.12 carries Unicode 15.0.0, 3.13 carries 15.1.0),
which is why the repo pins 3.12 in .python-version.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gatekeeper.core import Envelope, Snapshot, decide, gate_identity  # noqa: E402
from gatekeeper.shell import load_bundle  # noqa: E402
from spec.corpus import BUNDLE_DIR, load_meta, load_vectors  # noqa: E402


def main() -> int:
    bundle = load_bundle(BUNDLE_DIR)
    meta, vectors = load_meta(), load_vectors()
    recorded, current = meta["gate"], gate_identity(bundle)

    exact = behaviour_ok = 0
    drifted: list[str] = []
    for vector in vectors:
        decision = decide(Envelope.from_json(vector["envelope"]), Snapshot.from_json(vector["snapshot"]), bundle)
        expect = vector["expect"]
        if (decision.verdict, list(decision.reasons)) == (expect["verdict"], expect["reasons"]):
            behaviour_ok += 1
        else:
            drifted.append(f"{vector['name']}: {expect['verdict']} {expect['reasons']} -> {decision.verdict} {list(decision.reasons)}")
        exact += decision.decision_hash == expect["decision_hash"]

    print(f"recorded gate: {recorded}")
    print(f"current  gate: {current}")
    print(f"{len(vectors)} vectors: {exact} hash-exact, {behaviour_ok} with unchanged verdict and reasons")
    if recorded.get("policy_hash", meta["policy_hash"]) != meta["policy_hash"]:  # defensive, never expected
        print("corpus metadata is inconsistent", file=sys.stderr)
        return 1
    if drifted:
        print(f"BEHAVIOUR CHANGED in {len(drifted)} vectors:", file=sys.stderr)
        for line in drifted[:10]:
            print("  " + line, file=sys.stderr)
        return 1
    if current == recorded:
        if exact != len(vectors):
            print("same gate identity but hashes moved: that is nondeterminism, not an upgrade", file=sys.stderr)
            return 1
        print("PASS: same gate identity, every decision hash reproduced")
        return 0
    print(f"PASS: gate identity changed, behaviour unchanged ({exact} hashes still exact). "
          f"Regenerate the corpus deliberately with `make vectors` if you intend to adopt this runtime.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
