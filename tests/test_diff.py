"""Phase 5: what a policy change would do, before it ships."""

import pytest

from conftest import bundle_with_policies
from gatekeeper.core import compare, decide, mine_literals, structural_diff
from gatekeeper.shell import history_impact, load_bundle, read_log, replay
from gatekeeper.shell.demo import SESSION
from spec.gen_history import HISTORY, keyring

BUDGET = 1200


@pytest.fixture(scope="module")
def history_records():
    return list(read_log(HISTORY / f"{SESSION}.jsonl"))


def candidate(policies_text, old, new):
    assert old in policies_text
    return bundle_with_policies(policies_text.replace(old, new))


def test_the_literals_a_policy_turns_on_are_found(bundle):
    assert set(mine_literals(bundle.policies_by_id)) >= {20_000, 50_000, 500_000}


def test_an_unchanged_bundle_diverges_nowhere(bundle, policies_text):
    report = compare(bundle, bundle_with_policies(policies_text), budget=BUDGET)
    assert report.probes > 500
    assert not report.widened and not report.tightened and report.reasons_only == 0
    assert not report.structural.any


def test_reformatting_and_reordering_is_not_a_change(bundle, policies_text):
    import cedarpy
    blocks = [block for block in policies_text.split("\n\n") if "@id(" in block]
    other = bundle_with_policies(cedarpy.format_policies("\n\n".join(reversed(blocks))))
    report = compare(bundle, other, budget=BUDGET)
    assert not report.structural.any and not report.widened and not report.tightened


def test_raising_a_cap_by_one_unit_is_caught(bundle, policies_text):
    report = compare(bundle, candidate(policies_text, "<= 20000", "<= 20001"), budget=BUDGET)
    assert report.widens
    assert report.structural.changed == ("refund-auto",)
    amounts = {divergence.arguments for divergence in report.widened}
    assert any('"200.01"' in arguments for arguments in amounts)  # the boundary, found from the literal


def test_a_reported_counterexample_is_real(bundle, policies_text):
    """The report is not a claim: re-decide the example and both verdicts come out as stated."""
    from gatekeeper.core import Envelope
    from gatekeeper.core.diff import PROBE_PRINCIPAL, PROBE_SESSION, PROBE_T_MS
    other = candidate(policies_text, "<= 20000", "<= 20001")
    report = compare(bundle, other, budget=BUDGET)
    example = report.widened[0]
    envelope = Envelope(tool=example.tool, arguments=example.arguments, principal=PROBE_PRINCIPAL,
                        session_id=PROBE_SESSION, t_ms=PROBE_T_MS)
    assert decide(envelope, example.snapshot, bundle).verdict == example.base_verdict
    assert decide(envelope, example.snapshot, other).verdict == example.candidate_verdict
    assert example.candidate_verdict == "ALLOW" and example.base_verdict != "ALLOW"


def test_lowering_a_cap_is_a_tightening_not_a_widening(bundle, policies_text):
    report = compare(bundle, candidate(policies_text, "<= 20000", "<= 10000"), budget=BUDGET)
    assert report.tightened and not report.widens


def test_deleting_a_guardrail_is_a_widening(bundle, policies_text):
    without_forbid = policies_text.replace(
        'forbid (principal, action == Action::"payments.refund", resource is Account)\nwhen { resource.frozen };',
        'forbid (principal, action == Action::"payments.refund", resource is Account)\nwhen { false };')
    report = compare(bundle, bundle_with_policies(without_forbid), budget=BUDGET)
    assert report.widens
    assert any(divergence.base_verdict == "DENY" for divergence in report.widened)


def test_opening_egress_is_a_widening(bundle, policies_text):
    loosened = policies_text.replace(
        '@id("egress-allowlisted-host")\npermit (principal is Agent, action == Action::"web.fetch", resource is Host)\nwhen {\n  resource in HostGroup::"egress-allowlist" &&\n  context.args.url.scheme == "https"\n};',
        '@id("egress-allowlisted-host")\npermit (principal is Agent, action == Action::"web.fetch", resource is Host);')
    report = compare(bundle, bundle_with_policies(loosened), budget=BUDGET)
    assert report.widens
    assert any(divergence.tool == "web.fetch" for divergence in report.widened)


def test_structural_diff_names_what_moved(bundle, policies_text):
    other = candidate(policies_text, '@id("reads-allowed")\npermit (principal is Agent, action in Action::"Read", resource);', "")
    diff = structural_diff(bundle.policies_by_id, other.policies_by_id)
    assert diff.removed == ("reads-allowed",) and not diff.added


# --- history --------------------------------------------------------------------------------

def test_the_committed_history_replays_against_its_fixture_key(bundle, history_records):
    report = replay(history_records, bundle, SESSION, keyring().verifier)
    assert report.ok and report.decisions == 17


def test_an_unchanged_policy_changes_no_history(bundle, history_records, policies_text):
    assert history_impact(history_records, bundle_with_policies(policies_text), SESSION) == []


def test_a_tightening_names_the_past_calls_it_would_have_refused(bundle, history_records, policies_text):
    changes = history_impact(history_records, candidate(policies_text, "<= 20000", "<= 10000"), SESSION)
    assert [(change["tool"], change["recorded"]["verdict"], change["candidate"]["verdict"])
            for change in changes] == [("payments.refund", "ALLOW", "REQUIRE_APPROVAL")]
    assert changes[0]["action_hash"].startswith("sha256:")


def test_removing_the_trifecta_guardrail_shows_up_in_history(bundle, history_records, policies_text):
    loosened = policies_text.replace(
        'context.session.labels.contains("untrusted_input") &&\n  context.session.labels.contains("private_data")',
        "false")
    changes = history_impact(history_records, bundle_with_policies(loosened), SESSION)
    assert len(changes) >= 3  # the demo's blocked exfiltration attempts would have gone through
    assert all(change["recorded"]["verdict"] == "DENY" for change in changes)
