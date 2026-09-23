import pytest
from hypothesis import given
from hypothesis import strategies as st

from gatekeeper.core.errors import Rejection
from gatekeeper.core.money import CURRENCY_EXPONENT, canonical_money, format_minor

ALLOWED = ("EUR", "JPY", "KWD", "USD")


def canon(amount, currency="EUR", min_minor=1, max_minor=10**9):
    return canonical_money({"amount": amount, "currency": currency}, currencies=ALLOWED,
                           min_minor=min_minor, max_minor=max_minor)


@pytest.mark.parametrize("amount, currency, minor", [
    ("150.00", "EUR", 15000),
    ("150.0", "EUR", 15000),
    ("150", "EUR", 15000),      # one equivalence class: three spellings, one integer
    ("0.01", "EUR", 1),
    ("150", "JPY", 150),        # no minor units at all
    ("1.234", "KWD", 1234),     # three of them
])
def test_exact_minor_units_per_currency(amount, currency, minor):
    assert canon(amount, currency) == {"amount_minor": minor, "currency": currency}


@pytest.mark.parametrize("amount, currency, code", [
    (150.0, "EUR", "amount_must_be_a_decimal_string"),
    (15000, "EUR", "amount_must_be_a_decimal_string"),
    ("1e2", "EUR", "bad_amount"),
    ("150.001", "EUR", "too_many_fraction_digits"),
    ("150.00", "JPY", "too_many_fraction_digits"),
    ("-5.00", "EUR", "bad_amount"),
    ("0150.00", "EUR", "bad_amount"),
    ("1,500.00", "EUR", "bad_amount"),
    (" 150.00", "EUR", "bad_amount"),
    ("\u0661\u0665\u0660", "EUR", "bad_amount"),  # Arabic-Indic digits
    ("150.00", "eur", "bad_currency"),
    ("150.00", "XBT", "unknown_currency"),
    ("150.00", "GBP", "currency_not_allowed"),
])
def test_rejections(amount, currency, code):
    with pytest.raises(Rejection) as err:
        canon(amount, currency)
    assert err.value.code == code


def test_bounds_are_checked_in_minor_units():
    with pytest.raises(Rejection) as err:
        canon("0.00")
    assert err.value.code == "out_of_bounds"


@given(minor=st.integers(1, 10**9), currency=st.sampled_from(ALLOWED))
def test_formatting_round_trips_exactly(minor, currency):
    assert canon(format_minor(minor, currency).split()[0], currency)["amount_minor"] == minor


def test_every_allowed_currency_has_an_exponent():
    assert all(code in CURRENCY_EXPONENT for code in ALLOWED)
