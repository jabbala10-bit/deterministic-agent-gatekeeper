"""Regenerate the committed history corpus.

Policy CI needs history to report against, so a deterministic session is committed to the
repository. The clock is fixed and the signing key comes from a published test seed, which means
the ledger is byte-identical on every machine.

THE SEED BELOW IS NOT A SECRET and must never authorise anything real."""

from __future__ import annotations

import itertools
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gatekeeper.shell import load_bundle  # noqa: E402
from gatekeeper.shell.demo import SESSION, run_demo  # noqa: E402
from gatekeeper.shell.tokens import KeyRing  # noqa: E402
from spec.corpus import BUNDLE_DIR  # noqa: E402

TEST_SEED = b"gatekeeper-history-fixture-seed!"  # exactly 32 bytes, public on purpose
HISTORY = Path(__file__).resolve().parents[1] / "spec" / "history" / "bank-servicing"


def keyring() -> KeyRing:
    return KeyRing.from_seed(TEST_SEED)


def main() -> int:
    bundle = load_bundle(BUNDLE_DIR)
    if HISTORY.exists():
        shutil.rmtree(HISTORY)
    HISTORY.mkdir(parents=True)
    ticks = itertools.count(1_790_000_000_000_000_000, 7_000_000)
    steps, path = run_demo(bundle, HISTORY, clock_ns=lambda: next(ticks), keyring=keyring())
    (HISTORY / "gate-key.pem").unlink(missing_ok=True)  # the seed is in this file, not on disk
    print(f"wrote {path.name}: {len(steps)} decisions, key {keyring().key_id}")
    print(f"policy {bundle.policy_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
