"""Invariant 3, enforced: a token redeems one checked action, once, and nothing else."""

import json

import pytest

from gatekeeper.core import EntityRecord
from gatekeeper.shell import EgressRefused, Gate, egress_pins, pin_host, read_log, replay
from gatekeeper.shell.tokens import TokenError, TokenPayload

FACTS = (EntityRecord.build("Account", "acc-1001", {"frozen": False}),)
PUBLIC = lambda host: ["93.184.216.34"]


def refund(amount: str) -> str:
    return json.dumps({"account_id": "acc-1001", "amount": {"amount": amount, "currency": "EUR"}})


def gate_for(bundle, tmp_path, **kwargs):
    return Gate(bundle, tmp_path, resolver=PUBLIC, **kwargs)


def allow(gate, amount="150.00", session="s1"):
    ticket = gate.submit(session_id=session, principal="support-bot", tool="payments.refund",
                         arguments=refund(amount), facts=FACTS)
    assert ticket.verdict == "ALLOW"
    return ticket


def test_the_runner_is_handed_the_canonical_action_not_the_agents_text(bundle, tmp_path):
    gate = gate_for(bundle, tmp_path)
    ticket = gate.submit(session_id="s1", principal="support-bot", tool="payments.refund",
                         arguments='{"amount":{"currency":"EUR","amount":"150.0"},"account_id":"acc-1001"}',
                         facts=FACTS)
    seen = {}
    gate.execute(ticket.token, lambda tool, args: seen.update(tool=tool, args=args))
    assert seen["args"] == {"account_id": "acc-1001", "amount": {"amount": "150.00", "currency": "EUR"}}


def test_a_token_is_single_use(bundle, tmp_path):
    gate = gate_for(bundle, tmp_path)
    ticket = allow(gate)
    gate.execute(ticket.token, lambda tool, args: "ran")
    with pytest.raises(TokenError) as err:
        gate.execute(ticket.token, lambda tool, args: "ran again")
    assert err.value.code == "reservation_not_open"


def _forge(payload: TokenPayload, signature_from: str) -> str:
    """A payload of the forger's choosing, carrying a signature that was issued for another one."""
    import base64

    from gatekeeper.core.strictjson import jcs
    body = base64.urlsafe_b64encode(jcs(payload.to_json()).encode()).decode().rstrip("=")
    return f"dag1.{body}.{signature_from.split('.')[2]}"


def test_a_token_cannot_be_repointed_at_another_action(bundle, tmp_path):
    """The EUR 150 refund was checked; the EUR 200 one was checked separately. Neither token can be
    edited into the other, because the signature covers the whole payload."""
    gate = gate_for(bundle, tmp_path)
    cheap, dear = allow(gate, "150.00"), allow(gate, "200.00")
    swapped = TokenPayload(dear.decision.action_hash, 1_999_999_999_999, cheap.reservation, "s1")
    with pytest.raises(TokenError) as err:
        gate.execute(_forge(swapped, cheap.token), lambda tool, args: "ran")
    assert err.value.code == "bad_signature"


def test_a_valid_token_cannot_redeem_a_different_reservation(bundle, tmp_path):
    """Even a properly signed token is bound to the one reservation it names."""
    gate = gate_for(bundle, tmp_path)
    cheap, dear = allow(gate, "150.00"), allow(gate, "200.00")
    gate.execute(dear.token, lambda tool, args: "ran")          # closes the dear reservation
    seen = {}
    gate.execute(cheap.token, lambda tool, args: seen.update(args=args))
    assert seen["args"]["amount"]["amount"] == "150.00"          # still its own action, not the other


def test_an_expired_token_cannot_be_redeemed(bundle, tmp_path):
    clock = iter([1_790_000_000_000_000_000, 1_790_000_300_000_000_000, 1_790_000_300_000_000_000])
    gate = gate_for(bundle, tmp_path, clock_ns=lambda: next(clock), token_ttl_ms=1_000)
    ticket = allow(gate)
    with pytest.raises(TokenError) as err:
        gate.execute(ticket.token, lambda tool, args: "ran")
    assert err.value.code == "token_expired"


def test_a_failing_tool_releases_its_budget(bundle, tmp_path):
    gate = gate_for(bundle, tmp_path)
    ticket = allow(gate, "200.00")

    def boom(tool, args):
        raise RuntimeError("upstream exploded")

    with pytest.raises(RuntimeError):
        gate.execute(ticket.token, boom)
    assert gate.store.get("s1").state.counters() == {"refunded_minor": 0}


def test_a_leaked_reservation_is_swept(bundle, tmp_path):
    clock = iter([1_790_000_000_000_000_000] * 3)
    gate = gate_for(bundle, tmp_path, clock_ns=lambda: next(clock), token_ttl_ms=1_000)
    allow(gate, "200.00")  # never executed, never settled: a crashed executor
    assert gate.store.get("s1").state.counters() == {"refunded_minor": 20_000}
    released = gate.sweep("s1", now_ms=1_790_000_600_000)
    assert len(released) == 1
    assert gate.store.get("s1").state.counters() == {"refunded_minor": 0}


def test_pending_lists_what_a_human_still_has_to_decide(bundle, tmp_path):
    gate = gate_for(bundle, tmp_path)
    ticket = gate.submit(session_id="s1", principal="support-bot", tool="payments.refund",
                         arguments=refund("400.00"), facts=FACTS)
    assert ticket.verdict == "REQUIRE_APPROVAL"
    pending = gate.pending("s1")
    assert [entry["action_hash"] for entry in pending] == [ticket.decision.action_hash]
    gate.approve(session_id="s1", action_hash=ticket.decision.action_hash, approver="duty-officer")
    assert gate.pending("s1") == []


def test_execution_is_recorded_and_the_session_still_replays(bundle, tmp_path):
    gate = gate_for(bundle, tmp_path)
    gate.execute(allow(gate).token, lambda tool, args: "ran")
    report = replay(list(read_log(gate.store.path_for("s1"))), bundle, "s1")
    assert report.ok and report.decisions == 1


def test_signatures_catch_a_forgery_that_hashing_alone_cannot(bundle, tmp_path):
    """A forger with write access can rewrite an argument, recompute the decision honestly and
    re-seal every hash. The chain still verifies. What they cannot do is sign."""
    from gatekeeper.core import Envelope, EntityRecord, Event, decide, fold
    from gatekeeper.shell import events_of, seal, verify_chain
    from gatekeeper.shell.log import GENESIS
    from gatekeeper.shell.tokens import KeyRing

    gate = gate_for(bundle, tmp_path)
    allow(gate, "150.00")
    records = list(read_log(gate.store.path_for("s1")))
    counters = tuple(sorted(bundle.manifest.counters))

    index = next(i for i, record in enumerate(records) if record["kind"] == "decided")
    body = records[index]["body"]
    envelope = Envelope.from_json(body["envelope"])
    facts = tuple(EntityRecord.from_json(fact) for fact in body["facts"])
    forged_envelope = Envelope(tool=envelope.tool, principal=envelope.principal, t_ms=envelope.t_ms,
                               session_id=envelope.session_id,
                               arguments=envelope.arguments.replace('"150.00"', '"200.00"'))
    snapshot = fold("s1", counters, events_of(records[:index])).snapshot(facts)
    body["envelope"] = forged_envelope.to_json()
    body["decision"] = decide(forged_envelope, snapshot, bundle).to_json()
    for record in records:  # keep the reservation consistent with the rewritten amount
        if record["kind"] == "reserved":
            record["body"]["counters"] = {"refunded_minor": 20_000}

    forged, prev = [], GENESIS
    for seq, record in enumerate(records):
        sealed = seal(Event(seq, record["kind"], record["body"]), prev)
        forged.append(sealed)
        prev = sealed["record_hash"]

    assert verify_chain(forged) == []                       # internally consistent
    assert replay(forged, bundle, "s1").ok                  # and it replays, because it is coherent
    verifier = KeyRing.load_or_create(tmp_path / "gate-key.pem").verifier
    problems = verify_chain(forged, verifier)
    assert problems and all("unsigned" in problem for problem in problems)
    assert not replay(forged, bundle, "s1", verifier).ok    # the signature is what gives it away


def test_an_honest_ledger_verifies_against_the_gate_key(bundle, tmp_path):
    gate = gate_for(bundle, tmp_path)
    gate.execute(allow(gate).token, lambda tool, args: "ran")
    records = list(read_log(gate.store.path_for("s1")))
    assert replay(records, bundle, "s1", gate.verifier).ok


# --- executor-side egress control ------------------------------------------------------------

@pytest.mark.parametrize("address, code", [
    ("127.0.0.1", "non_public_address:loopback"),
    ("10.0.0.5", "non_public_address:private"),
    ("169.254.169.254", "non_public_address:link_local"),
    ("::1", "non_public_address:loopback"),
])
def test_a_host_that_resolves_into_private_space_is_refused(address, code):
    with pytest.raises(EgressRefused) as err:
        pin_host("rebind.example", resolver=lambda host: [address])
    assert err.value.code == code


def test_every_answer_must_be_public():
    # A host answering with one public and one private address is refused, not sorted through.
    with pytest.raises(EgressRefused):
        pin_host("split.example", resolver=lambda host: ["93.184.216.34", "127.0.0.1"])


def test_a_public_host_is_pinned_to_the_address_that_was_resolved():
    assert pin_host("docs.bank.example", resolver=lambda host: ["93.184.216.34"]) == "93.184.216.34"


def test_url_arguments_are_pinned_before_the_tool_runs(bundle, tmp_path):
    gate = Gate(bundle, tmp_path, resolver=lambda host: ["127.0.0.1"])
    ticket = gate.submit(session_id="s1", principal="support-bot", tool="web.fetch",
                         arguments=json.dumps({"url": "https://docs.bank.example/a"}))
    assert ticket.verdict == "ALLOW"  # the canonical host is allowlisted...
    with pytest.raises(EgressRefused):   # ...but it resolves into loopback, so it never runs
        gate.execute(ticket.token, lambda tool, args: "fetched")


def test_pins_are_computed_for_every_url_argument(bundle):
    from gatekeeper.core.canonical import canonicalize
    from gatekeeper.core import Envelope
    envelope = Envelope(tool="web.fetch", arguments=json.dumps({"url": "https://docs.bank.example/a"}),
                        principal="support-bot", session_id="s1", t_ms=0)
    action = canonicalize(envelope, bundle.manifest)
    pins = egress_pins(bundle.manifest.tools["web.fetch"], action.args, PUBLIC)
    assert pins == {"docs.bank.example": "93.184.216.34"}
