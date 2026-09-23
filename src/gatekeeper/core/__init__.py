"""Functional core. Nothing in this package may perform I/O, read a clock or use randomness;
tests/test_invariants.py enforces that with an AST lint."""

from .bundle import BundleError, Evaluation, PolicyBundle
from .canonical import CanonicalAction, canonicalize
from .decide import CANON_VERSION, GATE_VERSION, build_context, decide, gate_identity
from .diff import DiffReport, Divergence, compare, mine_literals, structural_diff
from .errors import Rejection
from .ledger import Event, LedgerError, LedgerState, apply, budget_reservation, fold, initial_state
from .model import VERDICTS, Decision, EntityRecord, Envelope, Snapshot

__all__ = [
    "BundleError", "CANON_VERSION", "CanonicalAction", "Decision", "DiffReport", "Divergence",
    "EntityRecord", "Envelope",
    "Evaluation", "Event", "GATE_VERSION", "LedgerError", "LedgerState", "PolicyBundle", "Rejection",
    "Snapshot", "VERDICTS", "apply", "budget_reservation", "build_context", "canonicalize", "decide",
    "compare", "fold", "gate_identity", "initial_state",
    "mine_literals", "structural_diff",
]
