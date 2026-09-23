import pytest
from hypothesis import given
from hypothesis import strategies as st

from gatekeeper.core.errors import Rejection
from gatekeeper.core.url import canonical_url, host_suffixes, rebuild

HTTPS = ("https",)


def canon(url: str, **kwargs):
    return canonical_url(url, schemes=HTTPS, **kwargs)


@pytest.mark.parametrize("raw, expected", [
    ("https://docs.bank.example/a/c?x=1", "https://docs.bank.example/a/c?x=1"),
    ("HTTPS://DOCS.Bank.Example/a/c?x=1", "https://docs.bank.example/a/c?x=1"),
    ("https://docs.bank.example:443/a/c?x=1", "https://docs.bank.example/a/c?x=1"),
    ("https://docs.bank.example/a/./b/../c?x=1", "https://docs.bank.example/a/c?x=1"),
    ("https://docs.bank.example./a/c?x=1#section", "https://docs.bank.example/a/c?x=1"),
    ("https://docs.bank.example/%61/%2e%2e/a/c?x=1", "https://docs.bank.example/a/c?x=1"),
    ("https://b\u00fccher.example", "https://xn--bcher-kva.example/"),
    ("https://docs.bank.example:8443/x", "https://docs.bank.example:8443/x"),
])
def test_equivalent_spellings_reach_one_canonical_url(raw, expected):
    assert rebuild(canon(raw)) == expected


def test_encoded_slash_never_becomes_a_separator():
    # %2F is a literal slash inside a segment. Decoding it would invent a path boundary.
    assert canon("https://a.example/p%2fq")["path"] == "/p%2Fq"
    assert canon("https://a.example/p%2f../q")["path"] == "/p%2F../q"


def test_dot_segments_cannot_escape_the_root():
    assert canon("https://a.example/../../../etc/passwd")["path"] == "/etc/passwd"


@pytest.mark.parametrize("raw, code", [
    ("https://2130706433/", "ip_literal_not_allowed"),
    ("https://0x7f.0.0.0x1/", "ip_literal_not_allowed"),
    ("https://127.1/", "ip_literal_not_allowed"),
    ("https://169.254.169.254/", "ip_literal_not_allowed"),
    ("https://[::1]/", "ip_literal_not_allowed"),
    ("https://localhost/", "bad_host"),
    ("https://bank.example@evil.test/", "credentials_in_url"),
    ("http://docs.bank.example/", "scheme_not_allowed"),
    ("file:///etc/passwd", "scheme_not_allowed"),
    ("https://a.example/x\ty", "control_character"),
    ("https://a.example/x y", "illegal_character"),
    ("https://a.example\\@evil.test/", "illegal_character"),
    ("https://a.example/%zz", "invalid_percent_encoding"),
    ("https://a.example:0/", "bad_port"),
    ("https://a.example:99999/", "bad_port"),
    ("docs.bank.example/x", "malformed_url"),
])
def test_rejections(raw, code):
    with pytest.raises(Rejection) as err:
        canon(raw)
    assert err.value.code == code


def test_ip_literals_are_available_when_a_tool_opts_in():
    assert canon("https://127.0.0.1/x", allow_ip=True)["host"] == "127.0.0.1"


@pytest.mark.parametrize("host, expected", [
    ("docs.bank.example", ["docs.bank.example", "bank.example"]),
    ("bank.example", ["bank.example"]),
    ("a.b.c.example", ["a.b.c.example", "b.c.example", "c.example"]),
])
def test_host_suffixes(host, expected):
    assert host_suffixes(host) == expected


def test_a_suffix_is_never_a_left_hand_match():
    # The whole point: bank.example.attacker.test must not land under bank.example.
    assert "bank.example" not in host_suffixes("bank.example.attacker.test")


URLS = st.builds(
    lambda host, path, query, port: f"https://{host}{':' + str(port) if port else ''}{path}{query}",
    host=st.sampled_from(["a.example", "docs.bank.example", "x.y.z.example", "xn--bcher-kva.example"]),
    path=st.from_regex(r"/[a-z0-9/%20._~-]{0,24}", fullmatch=True),
    query=st.sampled_from(["", "?a=1", "?a=1&b=two", "?q=%20"]),
    port=st.sampled_from([None, 443, 8443]),
)


@given(URLS)
def test_canonicalisation_is_idempotent(raw):
    try:
        once = canon(raw)
    except Rejection:
        return  # the property is about URLs the gate accepts; refusal is the other tests' business
    assert canon(rebuild(once)) == once
