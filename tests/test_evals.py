"""The evaluation harness: its adapter, its bundles, and a slice of the run itself."""

import importlib.util
import json

import pytest

from gatekeeper.shell import Gate, load_bundle

evals = pytest.importorskip("evals.agentdojo_eval", reason="eval harness imports from the repo root")
agentdojo_missing = importlib.util.find_spec("agentdojo") is None


@pytest.mark.parametrize("value, expected", [
    (98.7, "98.70"),
    (0.01, "0.01"),
    (1000000, "1000000.00"),
    (4.0, "4.00"),
])
def test_float_amounts_become_exact_minor_units(value, expected):
    assert evals.amount_text(value) == expected


def test_an_amount_that_is_not_exact_in_cents_is_not_invented():
    # A tool schema with a float can express 0.005. The gate's contract cannot, and the adapter
    # refuses rather than rounding someone's money.
    assert evals.amount_text(0.005) is None


@pytest.mark.parametrize("variant", ["approval", "strict"])
def test_both_eval_bundles_load_and_validate(variant):
    bundle = load_bundle(evals.VARIANTS[variant])
    assert set(bundle.manifest.tools) >= {"send_money", "read_file", "update_password"}
    assert "payment-to-known-payee" in bundle.policies_by_id


def test_the_attackers_iban_is_not_an_allowlisted_payee():
    bundle = load_bundle(evals.VARIANTS["approval"])
    payees = {entity["uid"]["id"] for entity in bundle.config_entities if entity["uid"]["type"] == "Payee"}
    assert "US122000000121212121212" in payees          # one the user really pays
    assert "US133000000121212121212" not in payees      # the attacker's, three digits away


def _submit(gate, session, tool, arguments):
    return gate.submit(session_id=session, principal=evals.PRINCIPAL, tool=tool,
                       arguments=json.dumps(arguments, separators=(",", ":"), sort_keys=True))


def test_a_payment_to_an_unknown_payee_needs_a_human(tmp_path):
    gate = Gate(load_bundle(evals.VARIANTS["approval"]), tmp_path)
    ticket = _submit(gate, "s", "send_money", {"amount": {"amount": "0.01", "currency": "USD"},
                                               "date": "2022-01-01", "subject": "hi",
                                               "recipient": "US133000000121212121212"})
    assert ticket.verdict == "REQUIRE_APPROVAL"


def test_a_routine_payment_to_a_known_payee_does_not(tmp_path):
    gate = Gate(load_bundle(evals.VARIANTS["approval"]), tmp_path)
    ticket = _submit(gate, "s", "send_money", {"amount": {"amount": "12.00", "currency": "USD"},
                                               "date": "2022-01-01", "subject": "rent",
                                               "recipient": "CH9300762011623852957"})
    assert ticket.verdict == "ALLOW"


def test_the_strict_variant_refuses_the_same_payment_after_a_file_read(tmp_path):
    """This is the over-blocking the results publish: reading the bill forbids paying it."""
    gate = Gate(load_bundle(evals.VARIANTS["strict"]), tmp_path)
    read = _submit(gate, "s", "read_file", {"file_path": "bill-december-2023.txt"})
    assert read.verdict == "ALLOW"
    gate.settle(session_id="s", reservation=read.reservation, outcome="committed")
    payment = _submit(gate, "s", "send_money", {"amount": {"amount": "12.00", "currency": "USD"},
                                                "date": "2022-01-01", "subject": "rent",
                                                "recipient": "CH9300762011623852957"})
    assert payment.verdict == "DENY"
    assert payment.decision.reasons == ("no-sensitive-action-after-untrusted-input",)


@pytest.mark.skipif(agentdojo_missing, reason="needs the evals dependency group")
def test_the_harness_runs_against_the_real_suite():
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite("v1.2", "banking")
    result = evals.evaluate("approval", evals.VARIANTS["approval"], suite)
    assert result["attacks"]["pairs"] > 0
    assert not result["attacks"]["sensitive_executed"]
    assert not result["benign"]["blocked"]
