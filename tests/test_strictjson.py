import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gatekeeper.core.strictjson import MAX_SAFE_INT, StrictJSONError, jcs, loads_strict


def test_rfc8785_orders_keys_by_utf16_code_units():
    # RFC 8785 section 3.2.3. U+1F600 is a surrogate pair in UTF-16 (0xD83D...), so it sorts
    # before U+FB33 even though its code point is larger. Code-point sorting gets this wrong.
    obj = {"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
           "1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control",
           "\u00f6": "Latin Small Letter O With Diaeresis"}
    keys = list(json.loads(jcs(obj)))
    assert keys == ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001F600", "\ufb33"]
    assert keys != sorted(obj)


def test_string_escaping_matches_ecmascript():
    assert jcs("a\u0000\u001f\"\\\n\t\u007f\u2028\u00e9") == '"a\\u0000\\u001f\\"\\\\\\n\\t\u007f\u2028\u00e9"'


def test_canonical_form_has_no_insignificant_whitespace():
    assert jcs({"b": [1, True, None], "a": {"y": "z"}}) == '{"a":{"y":"z"},"b":[1,true,null]}'


@pytest.mark.parametrize("text, code", [
    ('{"a": 1.0}', "float_not_allowed"),
    ('{"a": 1e2}', "float_not_allowed"),
    ('{"a": NaN}', "non_finite_number"),
    ('{"a": -Infinity}', "non_finite_number"),
    ('{"a": 1, "a": 2}', "duplicate_key"),
    ('{"o": {"a": 1, "a": 2}}', "duplicate_key"),
    ('{"a": 9007199254740992}', "integer_out_of_range"),
    ('{"a": "\\ud800"}', "lone_surrogate"),
    ('{"a": 1,}', "malformed_json"),
    ('\ufeff{}', "malformed_json"),
    ("[" * 40 + "]" * 40, "too_deep"),
])
def test_rejects_json_whose_meaning_parsers_disagree_on(text, code):
    with pytest.raises(StrictJSONError) as err:
        loads_strict(text)
    assert err.value.code == code


def test_accepts_the_largest_safe_integer():
    assert loads_strict(f'{{"a": {MAX_SAFE_INT}, "b": -{MAX_SAFE_INT}}}') == {"a": MAX_SAFE_INT, "b": -MAX_SAFE_INT}


@pytest.mark.parametrize("value", [1.5, (1, 2), {1, 2}, b"x", {1: "int key"}, 2**53, "\ud800"])
def test_jcs_refuses_values_outside_the_domain(value):
    with pytest.raises(StrictJSONError):
        jcs(value)


TEXT = st.text(st.characters(blacklist_categories=("Cs",)), max_size=16)
JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers(-MAX_SAFE_INT, MAX_SAFE_INT) | TEXT,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(TEXT, children, max_size=4),
    max_leaves=16,
)


@given(JSON_VALUES)
def test_canonical_json_round_trips_and_is_a_fixed_point(value):
    text = jcs(value)
    assert loads_strict(text, max_bytes=1 << 20) == value
    assert jcs(loads_strict(text, max_bytes=1 << 20)) == text
