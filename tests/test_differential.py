"""Differential tests: the gate parses with its own strict grammar, so it has to be compared with
the parser a tool would actually reach for.

Invariant 3 says what executes is what was checked. That holds only if the canonical action is
unambiguous to the executor's parser, and if every input the two parsers read differently is
refused outright."""

import pytest
from email.utils import parseaddr
from hypothesis import given
from hypothesis import strategies as st
from urllib.parse import urlsplit

from gatekeeper.core.canonical import canonical_email
from gatekeeper.core.errors import Rejection
from gatekeeper.core.url import SCHEME_DEFAULT_PORT, canonical_url, rebuild

HTTPS = ("https",)
ACCEPTED = [
    "https://docs.bank.example/a/c?x=1",
    "HTTPS://DOCS.Bank.Example:443/a/./b/../c?x=1",
    "https://docs.bank.example./%61/c",
    "https://b\u00fccher.example/x?q=%20",
    "https://sepa-directory.example:8443/iban/DE89",
]


@pytest.mark.parametrize("raw", ACCEPTED)
def test_the_canonical_url_is_unambiguous_to_a_standard_parser(raw):
    canonical = canonical_url(raw, schemes=HTTPS)
    parts = urlsplit(rebuild(canonical))
    assert parts.scheme == canonical["scheme"]
    assert parts.hostname == canonical["host"]
    assert (parts.port or SCHEME_DEFAULT_PORT[parts.scheme]) == canonical["port"]
    assert parts.path == canonical["path"]
    assert parts.query == canonical["query"]


@given(host=st.sampled_from(["a.example", "docs.bank.example", "x.y.example"]),
       path=st.from_regex(r"/[a-z0-9/._~-]{0,20}", fullmatch=True),
       port=st.sampled_from([None, 443, 8443]))
def test_executor_would_reach_the_host_the_gate_checked(host, path, port):
    raw = f"https://{host}{':' + str(port) if port else ''}{path}"
    canonical = canonical_url(raw, schemes=HTTPS)
    assert urlsplit(rebuild(canonical)).hostname == canonical["host"]


# Inputs two readers disagree about. Each row records what urllib sees; the comment is what a
# checker reading the raw string would conclude. The gate refuses every one, so the disagreement
# can never turn into a decision.
DISPUTED = [
    # the string says bank.example, urllib connects to evil.test
    ("credentials", "https://bank.example@evil.test/", "evil.test"),
    ("backslash-userinfo", "https://bank.example\\@evil.test/", "evil.test"),
    # the string says bank.ex<tab>ample, urllib strips the tab and connects to bank.example
    ("tab-stripped", "https://bank.ex\tample/", "bank.example"),
    # urllib reports a hostname the resolver would read as 127.0.0.1
    ("decimal-ip", "https://2130706433/", "2130706433"),
]


@pytest.mark.parametrize("name, raw, urllib_host", DISPUTED)
def test_inputs_two_parsers_read_differently_are_refused(name, raw, urllib_host):
    assert urlsplit(raw).hostname == urllib_host  # what a tool using urllib would reach
    with pytest.raises(Rejection):
        canonical_url(raw, schemes=HTTPS)


def test_the_credentials_form_points_somewhere_other_than_it_reads():
    raw = "https://bank.example@evil.test/"
    assert raw.startswith("https://bank.example")   # what a reviewer reads first
    assert urlsplit(raw).hostname == "evil.test"    # where the request would actually go
    with pytest.raises(Rejection):
        canonical_url(raw, schemes=HTTPS)


def test_display_name_form_is_refused_rather_than_unwrapped():
    # parseaddr quietly unwraps this to an address that is not the string anyone reviewed.
    raw = "Alice <alice@customer.example>"
    assert parseaddr(raw)[1] == "alice@customer.example" != raw
    with pytest.raises(Rejection):
        canonical_email(raw)


def test_address_list_is_refused_rather_than_silently_emptied():
    # parseaddr returns nothing at all here, so a tool using it would send to no one, or to both.
    raw = "alice@customer.example,exfil@attacker.test"
    assert parseaddr(raw)[1] == ""
    with pytest.raises(Rejection):
        canonical_email(raw)


def test_canonical_address_survives_a_mail_library_round_trip():
    canonical = canonical_email("Alice@CUSTOMER.Example.")
    assert parseaddr(canonical["address"])[1] == canonical["address"]
