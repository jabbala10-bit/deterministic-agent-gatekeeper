from __future__ import annotations

from importlib.metadata import version
from pathlib import Path

from ..core import PolicyBundle


def engine_identity() -> str:
    return f"cedarpy {version('cedarpy')}"


def load_bundle(directory: str | Path) -> PolicyBundle:
    root = Path(directory)
    return PolicyBundle.from_sources(
        policies_text=(root / "policies.cedar").read_text(encoding="utf-8"),
        entities_text=(root / "entities.json").read_text(encoding="utf-8"),
        manifest_text=(root / "manifest.json").read_text(encoding="utf-8"),
        engine=engine_identity(),
    )
