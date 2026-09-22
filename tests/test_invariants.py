"""One test (or more) per invariant, plus the engine behaviours the design exists to contain."""

import ast
from pathlib import Path

import cedarpy
import pytest

from conftest import bundle_with_policies
from gatekeeper.core import BundleError, EntityRecord, Envelope, Snapshot, build_context, canonicalize, decide
from spec import scenarios as sc
from spec.corpus import load_vectors

CORE = Path(__file__).resolve().parents[1] / "src" / "gatekeeper" / "core"
FORBIDDEN_MODULES = {
    "asyncio", "datetime", "http", "httpx", "importlib", "io", "logging", "multiprocessing", "os",
    "pathlib", "random", "requests", "secrets", "select", "shutil", "signal", "socket", "sqlite3",
    "ssl", "subprocess", "sys", "tempfile", "threading", "time", "urllib", "uuid",
}
FORBIDDEN_CALLS = {"__import__", "breakpoint", "compile", "eval", "exec", "hash", "id", "input", "open", "print"}


# Invariant 1: purity -------------------------------------------------------------------------

def test_I1_core_performs_no_io_reads_no_clock_and_draws_no_randomness():
    problems = []
    for path in sorted(CORE.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            modules = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module]
            problems += [f"{path.name}: imports {m}" for m in modules if m.split(".")[0] in FORBIDDEN_MODULES]
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
                problems.append(f"{path.name}:{node.lineno}: calls {node.func.id}()")
    assert not problems, problems


# Invariant 4: fail closed --------------------------------------------------------------------

def test_I4_gate_denies_where_the_raw_engine_fails_open(bundle):
    s = sc.refund_scenario(bundle.manifest, 15_000, "EUR", 0, "none", "missing")
    action = canonicalize(s.envelope, bundle.manifest)
    raw = bundle.evaluate(action, build_context(s.envelope, s.snapshot, action, action.digest()), s.snapshot.entities)
    # The engine skips the erroring forbid and says Allow; the error is only a diagnostic.
    assert raw.engine_decision == "Allow"
    assert raw.errors == ("no-refund-to-frozen-account",)
    decision = decide(s.envelope, s.snapshot, bundle)
    assert (decision.verdict, decision.reasons) == ("DENY", ("EVAL_ERROR:no-refund-to-frozen-account",))


def test_I4_snapshot_cannot_smuggle_policy_configuration(bundle):
    # An allowlist entry arriving through runtime state would silently widen policy (ADR-005).
    smuggled = sc.snapshot(extra=(EntityRecord.build("Recipient", "attacker.example", {}),))
    env = sc.envelope("email.send", sc.compact({"to": "exfil@attacker.example", "subject": "s", "body": "b"}))
    decision = decide(env, smuggled, bundle)
    assert (decision.verdict, decision.reasons) == ("DENY", ("INVALID_SNAPSHOT:entity_type_not_allowed",))


# Invariant 5: monotone guardrails -------------------------------------------------------------

def test_I5_a_forbid_outranks_a_human_approval(bundle):
    s = sc.email_scenario(bundle.manifest, "exfil@attacker.example", "attacker.example",
                          ("private_data", "untrusted_input"), "bound")
    assert s.snapshot.approvals, "a human approved this exact action"
    decision = decide(s.envelope, s.snapshot, bundle)
    assert (decision.verdict, decision.reasons) == ("DENY", ("no-egress-after-untrusted-with-private",))


def test_I5_an_approval_does_not_transfer_to_a_different_action(bundle):
    approved = sc.refund_scenario(bundle.manifest, 40_000, "EUR", 0, "bound", "ok")
    nudged = sc.refund_scenario(bundle.manifest, 45_000, "EUR", 0, "none", "ok")
    reused = sc.snapshot(approvals=approved.snapshot.approvals)
    assert decide(approved.envelope, approved.snapshot, bundle).verdict == "ALLOW"
    assert decide(nudged.envelope, reused, bundle).verdict == "REQUIRE_APPROVAL"


# Stable policy identity (supports invariant 2) ------------------------------------------------

def _policy_blocks(text: str) -> list[str]:
    return [block for block in text.split("\n\n") if "@id(" in block]


def test_reordering_and_reformatting_policies_changes_nothing(bundle, policies_text):
    reordered = cedarpy.format_policies("\n\n".join(reversed(_policy_blocks(policies_text))))
    other = bundle_with_policies(reordered)
    assert other.policy_hash == bundle.policy_hash
    for vector in load_vectors()[::5]:  # positional ids all moved; decisions must not
        d = decide(Envelope.from_json(vector["envelope"]), Snapshot.from_json(vector["snapshot"]), other)
        assert d.decision_hash == vector["expect"]["decision_hash"], vector["name"]


def test_a_semantic_change_changes_the_policy_hash(bundle, policies_text):
    assert bundle_with_policies(policies_text.replace("<= 20000", "<= 20001")).policy_hash != bundle.policy_hash


def test_reasons_are_sorted_stable_ids_not_engine_order(bundle):
    s = sc.refund_scenario(bundle.manifest, 15_000, "EUR", 0, "bound", "ok")
    assert decide(s.envelope, s.snapshot, bundle).reasons == ("refund-approved", "refund-auto")


# Errors shifted to load time -------------------------------------------------------------------

def test_the_validator_rejects_a_typo_at_load(policies_text):
    with pytest.raises(BundleError, match="validation failed"):
        bundle_with_policies(policies_text.replace("context.args.amount_minor <= 20000", "context.args.amount <= 20000"))


def test_every_policy_needs_a_stable_id(policies_text):
    with pytest.raises(BundleError, match="@id"):
        bundle_with_policies(policies_text.replace('@id("reads-allowed")\n', ""))


def test_duplicate_ids_are_rejected(policies_text):
    with pytest.raises(BundleError, match="duplicate @id"):
        bundle_with_policies(policies_text.replace('@id("egress-approved")', '@id("egress-allowlisted")'))
