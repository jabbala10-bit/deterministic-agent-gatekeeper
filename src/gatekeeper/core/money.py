"""Money canonicalisation: exact integers in the currency's own minor units.

Amounts arrive as decimal strings and never as JSON numbers, because a JSON number invites the
float path that ADR-003 removed. Conversion is integer arithmetic against the ISO 4217 exponent, so
"150.00" EUR and "150" JPY are both exact and neither can be widened by a rounding step."""

from __future__ import annotations

import re

from .errors import Rejection

# ISO 4217 minor-unit exponents. Not every currency is two decimals, and assuming so is a classic
# payments bug: JPY has none, KWD has three.
CURRENCY_EXPONENT: dict[str, int] = {
    "AUD": 2, "BHD": 3, "CAD": 2, "CHF": 2, "CZK": 2, "DKK": 2, "EUR": 2, "GBP": 2, "HUF": 2,
    "INR": 2, "ISK": 0, "JOD": 3, "JPY": 0, "KRW": 0, "KWD": 3, "NOK": 2, "OMR": 3, "PLN": 2,
    "SEK": 2, "SGD": 2, "TND": 3, "USD": 2,
}

# ASCII digits only: Arabic-Indic and full-width digits are refused rather than silently mapped.
_AMOUNT_RE = re.compile(r"(0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?\Z")
_CURRENCY_RE = re.compile(r"[A-Z]{3}\Z")


def canonical_money(value: object, *, currencies: tuple[str, ...], min_minor: int, max_minor: int) -> dict[str, object]:
    if type(value) is not dict or sorted(value) != ["amount", "currency"]:
        raise Rejection("expected_amount_and_currency")
    amount, currency = value["amount"], value["currency"]
    if type(currency) is not str or _CURRENCY_RE.match(currency) is None:
        raise Rejection("bad_currency")
    if currency not in CURRENCY_EXPONENT:
        raise Rejection("unknown_currency")
    if currency not in currencies:
        raise Rejection("currency_not_allowed")
    if type(amount) is not str:
        raise Rejection("amount_must_be_a_decimal_string")
    match = _AMOUNT_RE.match(amount)
    if match is None:
        raise Rejection("bad_amount")
    exponent = CURRENCY_EXPONENT[currency]
    whole, fraction = match.group(1), match.group(2) or ""
    if len(fraction) > exponent:
        raise Rejection("too_many_fraction_digits")
    minor = int(whole) * 10**exponent + int(fraction.ljust(exponent, "0") or "0")
    if not min_minor <= minor <= max_minor:
        raise Rejection("out_of_bounds")
    return {"amount_minor": minor, "currency": currency}


def format_minor(amount_minor: int, currency: str) -> str:
    """Canonical decimal text, for demo output and executor-facing rendering."""
    exponent = CURRENCY_EXPONENT[currency]
    if exponent == 0:
        return f"{amount_minor} {currency}"
    whole, fraction = divmod(amount_minor, 10**exponent)
    return f"{whole}.{fraction:0{exponent}d} {currency}"
