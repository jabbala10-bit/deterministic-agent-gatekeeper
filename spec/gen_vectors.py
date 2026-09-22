"""Regenerate the golden corpus.

Refuses to write anything if the gate disagrees with the oracle on any scenario, so the corpus can
only ever freeze behaviour that matches stated intent. Review the diff before committing."""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gatekeeper.core import decide, gate_identity  # noqa: E402
from gatekeeper.core.strictjson import jcs  # noqa: E402
from gatekeeper.shell import load_bundle  # noqa: E402
from spec import scenarios  # noqa: E402
from spec.corpus import BUNDLE_DIR, META_PATH, VECTORS_PATH, corpus_digest_of  # noqa: E402


def main() -> int:
    bundle = load_bundle(BUNDLE_DIR)
    grid = scenarios.build(bundle.manifest)
    names = [s.name for s in grid]
    if len(set(names)) != len(names):
        print("duplicate scenario names", file=sys.stderr)
        return 1
    lines, hashes, disagreements = [], [], []
    verdicts: collections.Counter[str] = collections.Counter()
    for s in grid:
        d = decide(s.envelope, s.snapshot, bundle)
        if (d.verdict, d.reasons) != (s.verdict, s.reasons):
            disagreements.append(f"{s.name}: oracle {s.verdict} {list(s.reasons)} / gate {d.verdict} {list(d.reasons)}")
            continue
        verdicts[d.verdict] += 1
        hashes.append(d.decision_hash)
        lines.append(jcs({
            "envelope": s.envelope.to_json(),
            "expect": {
                "action_hash": d.action_hash,
                "decision_hash": d.decision_hash,
                "input_hash": d.input_hash,
                "reasons": list(d.reasons),
                "snapshot_hash": d.snapshot_hash,
                "verdict": d.verdict,
            },
            "name": s.name,
            "snapshot": s.snapshot.to_json(),
        }))
    if disagreements:
        print(f"{len(disagreements)} scenarios disagree with the oracle; nothing written:", file=sys.stderr)
        for line in disagreements[:20]:
            print("  " + line, file=sys.stderr)
        return 1
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    meta = {
        "corpus_digest": corpus_digest_of(hashes),
        "count": len(lines),
        "gate": gate_identity(bundle),
        "policy_hash": bundle.policy_hash,
        "verdicts": dict(sorted(verdicts.items())),
    }
    META_PATH.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} vectors  {dict(sorted(verdicts.items()))}")
    print(f"corpus {meta['corpus_digest']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
