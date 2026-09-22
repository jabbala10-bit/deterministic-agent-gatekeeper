"""Loading and fingerprinting the golden corpus (used by tests and by fresh processes)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gatekeeper.core import Envelope, PolicyBundle, Snapshot, decide
from gatekeeper.core.digest import digest
from gatekeeper.core.strictjson import loads_strict
from gatekeeper.shell import load_bundle

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_DIR = ROOT / "policies" / "bank-servicing"
VECTORS_PATH = ROOT / "spec" / "vectors" / "golden.jsonl"
META_PATH = ROOT / "spec" / "vectors" / "meta.json"


def load_vectors() -> list[dict[str, Any]]:
    return [loads_strict(line, max_bytes=1 << 20) for line in VECTORS_PATH.read_text(encoding="utf-8").splitlines()]


def load_meta() -> dict[str, Any]:
    return json.loads(META_PATH.read_text(encoding="utf-8"))


def corpus_digest_of(decision_hashes: list[str]) -> str:
    return digest("dag/corpus/v1", decision_hashes)


def corpus_digest(bundle: PolicyBundle | None = None) -> str:
    """Re-derive every golden decision in this process and fingerprint the results."""
    bundle = bundle or load_bundle(BUNDLE_DIR)
    return corpus_digest_of([
        decide(Envelope.from_json(v["envelope"]), Snapshot.from_json(v["snapshot"]), bundle).decision_hash
        for v in load_vectors()
    ])
