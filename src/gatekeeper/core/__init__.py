"""Functional core. Nothing in this package may perform I/O, read a clock or use randomness;
tests/test_invariants.py enforces that with an AST lint."""

from .bundle import BundleError, Evaluation, PolicyBundle
from .canonical import CanonicalAction, canonicalize
from .decide import CANON_VERSION, GATE_VERSION, build_context, decide, gate_identity
from .errors import Rejection
from .model import VERDICTS, Decision, EntityRecord, Envelope, Snapshot

__all__ = [
    "BundleError", "CANON_VERSION", "CanonicalAction", "Decision", "EntityRecord", "Envelope",
    "Evaluation", "GATE_VERSION", "PolicyBundle", "Rejection", "Snapshot", "VERDICTS",
    "build_context", "canonicalize", "decide", "gate_identity",
]
