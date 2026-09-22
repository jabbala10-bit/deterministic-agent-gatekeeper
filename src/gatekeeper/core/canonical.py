"""Canonicalisation: turn the agent's raw proposal into the one structure that is both checked
and executed. Most real gate bypasses are representation tricks, so every argument is parsed
once, strictly, into a typed canonical value; anything that cannot be canonicalised is refused.

Phase 1 covers ids, bounded integers, enums, text and ASCII email addresses. URLs, IDNA and
templated commands arrive in phase 2; until then they are refused rather than guessed at."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any

from .digest import digest
from .errors import Rejection
from .manifest import ArgSpec, Manifest
from .model import Envelope
from .strictjson import StrictJSONError, loads_strict
from .syntax import DOMAIN_LABEL_RE, ID_RE, LOCAL_PART_RE

MAX_ARGUMENTS_BYTES = 64 * 1024
# Explicit bidi embeddings, overrides and isolates ("Trojan Source"). Marks such as U+200E stay legal.
_BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


@dataclass(frozen=True, slots=True)
class CanonicalAction:
    tool: str
    principal_type: str
    principal: str
    resource_type: str
    resource_id: str
    session_id: str
    args: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "args": dict(self.args),
            "principal": {"id": self.principal, "type": self.principal_type},
            "resource": {"id": self.resource_id, "type": self.resource_type},
            "session_id": self.session_id,
            "tool": self.tool,
        }

    def digest(self) -> str:
        """The hash an approval binds to and the executor re-checks (invariant 3)."""
        return digest("dag/action/v1", self.to_json())


def canonicalize(env: Envelope, manifest: Manifest) -> CanonicalAction:
    spec = manifest.tools.get(env.tool)
    if spec is None:
        raise Rejection("UNKNOWN_TOOL")
    try:
        raw = loads_strict(env.arguments, max_bytes=MAX_ARGUMENTS_BYTES)
    except StrictJSONError as err:
        raise Rejection(f"INVALID_ARGUMENTS:{err.code}") from None
    if type(raw) is not dict:
        raise Rejection("INVALID_ARGUMENTS:not_an_object")
    if any(name not in spec.args for name in raw):
        raise Rejection("INVALID_ARGUMENTS:unknown_argument")
    if any(name not in raw for name in spec.args):
        raise Rejection("INVALID_ARGUMENTS:missing_argument")

    args: dict[str, Any] = {}
    resource_id = ""
    for name in sorted(spec.args):
        try:
            value, resource_candidate = _canonical_value(spec.args[name], raw[name])
        except Rejection as err:
            # Argument names come from the manifest, never from the agent, so they are safe to cite.
            raise Rejection(f"INVALID_ARGUMENTS:{name}:{err.code}") from None
        args[name] = value
        if name == spec.resource_from:
            resource_id = resource_candidate or ""

    return CanonicalAction(
        tool=spec.name,
        principal_type=manifest.principal_type,
        principal=env.principal,
        resource_type=spec.resource_type,
        resource_id=resource_id,
        session_id=env.session_id,
        args=args,
    )


def _canonical_value(spec: ArgSpec, value: Any) -> tuple[Any, str | None]:
    if spec.kind == "id":
        if type(value) is not str or ID_RE.match(value) is None:
            raise Rejection("bad_id")
        return value, value
    if spec.kind == "int":
        if type(value) is not int:  # bool is an int subclass in Python; type() excludes it
            raise Rejection("not_integer")
        assert spec.min is not None and spec.max is not None
        if not spec.min <= value <= spec.max:
            raise Rejection("out_of_bounds")
        return value, None
    if spec.kind == "enum":
        if type(value) is not str or value not in spec.values:
            raise Rejection("not_in_enum")
        return value, None
    if spec.kind == "text":
        assert spec.max_len is not None
        return canonical_text(value, spec.max_len), None
    if spec.kind == "email":
        return canonical_email(value)
    raise Rejection("unsupported_kind")


def canonical_text(value: Any, max_len: int) -> str:
    if type(value) is not str:
        raise Rejection("not_text")
    for ch in value:
        # Unassigned code points are refused so NFC stays stable across Unicode versions:
        # normalisation of assigned characters is guaranteed stable, unassigned ones are not.
        if unicodedata.category(ch) == "Cn":
            raise Rejection("unassigned_code_point")
    text = unicodedata.normalize("NFC", value)
    for ch in text:
        code = ord(ch)
        if (code < 0x20 and ch not in "\t\n") or 0x7F <= code <= 0x9F:
            raise Rejection("control_character")
        if ch in _BIDI_CONTROLS:
            raise Rejection("bidi_control")
    if len(text) > max_len:
        raise Rejection("too_long")
    return text


def canonical_email(value: Any) -> tuple[str, str]:
    """Returns (address, domain). Domain is lower-cased with any trailing dot removed; the local
    part is kept byte-for-byte because RFC 5321 leaves its case significance to the receiver."""
    if type(value) is not str:
        raise Rejection("not_text")
    if not value.isascii():
        raise Rejection("non_ascii_address")  # IDNA and internationalised addresses: phase 2
    if value.count("@") != 1:
        raise Rejection("bad_address")
    local, domain = value.split("@")
    if LOCAL_PART_RE.match(local) is None or local.startswith(".") or local.endswith(".") or ".." in local:
        raise Rejection("bad_local_part")
    domain = domain.lower()
    if domain.endswith("."):
        domain = domain[:-1]
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or labels[-1].isdigit():
        raise Rejection("bad_domain")
    if not all(DOMAIN_LABEL_RE.match(label) for label in labels):
        raise Rejection("bad_domain")
    return f"{local}@{domain}", domain
