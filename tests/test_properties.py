import json
import random

from hypothesis import given, settings
from hypothesis import strategies as st

from gatekeeper.core import VERDICTS, decide
from spec import oracle
from spec import scenarios as sc

AMOUNT = st.integers(1, 100_000_000)
CURRENCY = st.sampled_from(["EUR", "USD"])
HOSTS = st.sampled_from(["docs.bank.example", "bank.example", "sepa-directory.example",
                         "evil.example", "bank.example.attacker.test", "a.b.customer.example"])


@settings(max_examples=300, deadline=None)
@given(amount=AMOUNT, currency=CURRENCY, order=st.permutations(["account_id", "amount"]),
       seps=st.sampled_from([(",", ":"), (", ", ": "), (",\n  ", " : ")]))
def test_formatting_never_changes_the_action_or_the_verdict(bundle, amount, currency, order, seps):
    args = {"account_id": "acc-1001", "amount": {"amount": sc.amount_text(amount, currency), "currency": currency}}
    shuffled = "{" + seps[0].join(f"{json.dumps(k)}{seps[1]}{json.dumps(args[k])}" for k in order) + "}"
    a = decide(sc.envelope("payments.refund", sc.compact(args)), sc.snapshot(), bundle)
    b = decide(sc.envelope("payments.refund", shuffled), sc.snapshot(), bundle)
    assert (a.action_hash, a.verdict, a.reasons) == (b.action_hash, b.verdict, b.reasons)


@settings(max_examples=1500, deadline=None)
@given(amount=AMOUNT | st.integers(1, 60_000), currency=CURRENCY, refunded=st.integers(0, 600_000),
       approval=st.sampled_from(["none", "bound", "other"]), account=st.sampled_from(["ok", "ok", "frozen", "missing"]))
def test_refund_decisions_match_the_oracle(bundle, amount, currency, refunded, approval, account):
    s = sc.refund_scenario(bundle.manifest, amount, currency, refunded, approval, account)
    d = decide(s.envelope, s.snapshot, bundle)
    assert (d.verdict, d.reasons) == (s.verdict, s.reasons)


@settings(max_examples=400, deadline=None)
@given(local=st.from_regex(r"[a-z0-9]{1,12}", fullmatch=True),
       domain=st.sampled_from(["customer.example", "mail.customer.example", "bank.example",
                               "attacker.example", "customer.example.attacker.test"]),
       labels=st.sets(st.sampled_from(["private_data", "untrusted_input"])), approved=st.booleans())
def test_email_decisions_match_the_oracle(bundle, local, domain, labels, approved):
    ordered = tuple(sorted(labels))
    s = sc.email_scenario(bundle.manifest, f"{local}@{domain}", domain, ordered, "bound" if approved else "none")
    d = decide(s.envelope, s.snapshot, bundle)
    assert (d.verdict, d.reasons) == (s.verdict, s.reasons)


@settings(max_examples=400, deadline=None)
@given(host=HOSTS, path=st.from_regex(r"/[a-z0-9/]{0,20}", fullmatch=True),
       labels=st.sets(st.sampled_from(["private_data", "untrusted_input"])), approved=st.booleans())
def test_fetch_decisions_match_the_oracle(bundle, host, path, labels, approved):
    s = sc.fetch_scenario(bundle.manifest, f"https://{host}{path}", host, tuple(sorted(labels)),
                          "bound" if approved else "none")
    d = decide(s.envelope, s.snapshot, bundle)
    assert (d.verdict, d.reasons) == (s.verdict, s.reasons)


TEXT = st.text(st.characters(blacklist_categories=("Cs",)), max_size=200)
JSONISH = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | TEXT,
    lambda c: st.lists(c, max_size=3) | st.dictionaries(TEXT, c, max_size=3),
    max_leaves=8,
)
TOOLS = st.sampled_from(["payments.refund", "email.send", "web.fetch", "db.report", "crm.lookup", "inbox.read"])


@settings(max_examples=1000, deadline=None)
@given(tool=TOOLS | TEXT, arguments=TEXT | JSONISH.map(json.dumps))
def test_agent_input_can_never_crash_the_gate(bundle, tool, arguments):
    d = decide(sc.envelope(tool, arguments), sc.snapshot(), bundle)
    assert d.verdict in VERDICTS
    if tool not in bundle.manifest.tools:
        assert d.reasons == ("UNKNOWN_TOOL",)


def test_ten_thousand_decisions_are_reproducible_and_match_the_oracle(bundle):
    rng = random.Random(20260922)
    for _ in range(10_000):
        amount = rng.choice([rng.randint(1, 60_000), rng.randint(1, 100_000_000)])
        s = sc.refund_scenario(bundle.manifest, amount, rng.choice(["EUR", "USD"]),
                               rng.choice([0, rng.randint(0, 600_000)]), rng.choice(["none", "bound", "other"]),
                               rng.choice(["ok", "ok", "ok", "frozen", "missing"]))
        first, second = decide(s.envelope, s.snapshot, bundle), decide(s.envelope, s.snapshot, bundle)
        assert first == second
        assert (first.verdict, first.reasons) == (s.verdict, s.reasons)
