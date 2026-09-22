"""Strict JSON in, RFC 8785 (JCS) canonical JSON out, over a float-free value domain.

RFC 8785 serialises numbers with ECMAScript double formatting, which is where cross-language
canonicalisation bugs live. Money is integer minor units, so the gate refuses floats, NaN and
Infinity outright and caps integers at the I-JSON safe range. Inside that domain the canonical
form is simple and identical in every language.

Parsing also refuses duplicate keys: parsers disagree on which duplicate wins, which is a
classic gate-versus-tool parser differential.
"""

from __future__ import annotations

import json
import re
from typing import Any

MAX_SAFE_INT = 2**53 - 1
_MAX_INT_DIGITS = 16
_MAX_DEPTH = 32


class StrictJSONError(ValueError):
    """Carries a stable machine-readable code; never echoes the offending input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject_float(_: str) -> Any:
    raise StrictJSONError("float_not_allowed")


def _reject_constant(_: str) -> Any:
    raise StrictJSONError("non_finite_number")


def _parse_int(literal: str) -> int:
    if len(literal.lstrip("-")) > _MAX_INT_DIGITS:
        raise StrictJSONError("integer_out_of_range")
    value = int(literal)
    if abs(value) > MAX_SAFE_INT:
        raise StrictJSONError("integer_out_of_range")
    return value


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise StrictJSONError("duplicate_key")
        obj[key] = value
    return obj


_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _has_surrogate(text: str) -> bool:
    return _SURROGATE_RE.search(text) is not None


def _check_strings(value: Any, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise StrictJSONError("too_deep")
    if isinstance(value, str):
        if _has_surrogate(value):
            raise StrictJSONError("lone_surrogate")
    elif isinstance(value, list):
        for item in value:
            _check_strings(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            if _has_surrogate(key):
                raise StrictJSONError("lone_surrogate")
            _check_strings(item, depth + 1)


def loads_strict(text: str, *, max_bytes: int = 64 * 1024) -> Any:
    """Parse JSON text, refusing every construct whose meaning parsers disagree on."""
    if not isinstance(text, str):
        raise StrictJSONError("not_text")
    if len(text.encode("utf-8", "surrogatepass")) > max_bytes:
        raise StrictJSONError("too_large")
    try:
        value = json.loads(
            text,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
            object_pairs_hook=_no_duplicates,
        )
    except StrictJSONError:
        raise
    except (ValueError, RecursionError):
        raise StrictJSONError("malformed_json") from None
    _check_strings(value)
    return value


def _quote(text: str) -> str:
    if _has_surrogate(text):
        raise StrictJSONError("lone_surrogate")
    # Python's escaping with ensure_ascii=False matches ECMAScript JSON.stringify exactly:
    # short escapes for \b \t \n \f \r, \u00xx (lowercase) for other C0 controls, " and \ escaped,
    # everything else (including U+007F and U+2028) emitted raw.
    return json.dumps(text, ensure_ascii=False)


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _emit(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif type(value) is int:
        if abs(value) > MAX_SAFE_INT:
            raise StrictJSONError("integer_out_of_range")
        out.append(str(value))
    elif type(value) is str:
        out.append(_quote(value))
    elif type(value) is list:
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _emit(item, out)
        out.append("]")
    elif type(value) is dict:
        if any(type(key) is not str for key in value):
            raise StrictJSONError("non_string_key")
        out.append("{")
        # RFC 8785 orders members by UTF-16 code units, not code points.
        for index, key in enumerate(sorted(value, key=_utf16_key)):
            if index:
                out.append(",")
            out.append(_quote(key))
            out.append(":")
            _emit(value[key], out)
        out.append("}")
    else:
        raise StrictJSONError("unsupported_type")


def jcs(value: Any) -> str:
    """RFC 8785 canonical JSON for values in the float-free domain."""
    out: list[str] = []
    _emit(value, out)
    return "".join(out)
