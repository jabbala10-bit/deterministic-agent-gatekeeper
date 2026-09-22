import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))  # makes the spec package importable

from gatekeeper.core import PolicyBundle  # noqa: E402
from gatekeeper.shell import engine_identity, load_bundle  # noqa: E402

BUNDLE_DIR = ROOT / "policies" / "bank-servicing"


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def bundle() -> PolicyBundle:
    return load_bundle(BUNDLE_DIR)


@pytest.fixture(scope="session")
def policies_text() -> str:
    return (BUNDLE_DIR / "policies.cedar").read_text(encoding="utf-8")


def bundle_with_policies(text: str) -> PolicyBundle:
    return PolicyBundle.from_sources(
        policies_text=text,
        entities_text=(BUNDLE_DIR / "entities.json").read_text(encoding="utf-8"),
        manifest_text=(BUNDLE_DIR / "manifest.json").read_text(encoding="utf-8"),
        engine=engine_identity(),
    )
