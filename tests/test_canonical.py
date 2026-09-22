import pytest

from gatekeeper.core import Envelope, Rejection, canonicalize
from gatekeeper.core.canonical import canonical_email, canonical_text


@pytest.mark.parametrize("raw, address, domain", [
    ("alice@customer.example", "alice@customer.example", "customer.example"),
    ("Alice@CUSTOMER.Example.", "Alice@customer.example", "customer.example"),
    ("ops+refunds@bank.example", "ops+refunds@bank.example", "bank.example"),
])
def test_email_canonical_form(raw, address, domain):
    assert canonical_email(raw) == (address, domain)


@pytest.mark.parametrize("raw, code", [
    ("alice@cust\u00f6mer.example", "non_ascii_address"),
    ("a@b@c.example", "bad_address"),
    ("\"a b\"@c.example", "bad_local_part"),
    (".alice@c.example", "bad_local_part"),
    ("alice@localhost", "bad_domain"),
    ("alice@127.0.0.1", "bad_domain"),
    ("alice@-bad.example", "bad_domain"),
])
def test_email_rejections(raw, code):
    with pytest.raises(Rejection) as err:
        canonical_email(raw)
    assert err.value.code == code


def test_text_is_nfc_normalised_and_keeps_newlines():
    assert canonical_text("Cafe\u0301\n\tok", 100) == "Caf\u00e9\n\tok"


def test_normalisation_happens_before_the_length_check():
    assert canonical_text("e\u0301" * 5, 5) == "\u00e9" * 5


def _refund(bundle, *, principal="support-bot", session="sess-1", amount=100):
    env = Envelope(tool="payments.refund", principal=principal, session_id=session, t_ms=0,
                   arguments=f'{{"account_id":"acc-1","amount_minor":{amount},"currency":"EUR"}}')
    return canonicalize(env, bundle.manifest).digest()


def test_action_hash_binds_principal_session_and_every_argument(bundle):
    base = _refund(bundle)
    assert base == _refund(bundle)
    assert len({base, _refund(bundle, principal="other-bot"), _refund(bundle, session="sess-2"),
                _refund(bundle, amount=101)}) == 4
