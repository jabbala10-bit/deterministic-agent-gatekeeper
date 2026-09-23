"""Canonicalisation: turn the agent's raw proposal into the one structure that is both checked and
executed.

Most real gate bypasses are representation tricks, so every argument is parsed once, strictly, into
a typed canonical value. Anything that cannot be canonicalised is refused rather than guessed at.

Free-form command languages (SQL, shell) are deliberately absent. They are not canonicalised at all;
a tool exposes named templates with typed parameters instead, and the gate passes the template name
and parameters rather than a string an executor would have to re-parse."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any

from .digest import digest
from .errors import Rejection
from .manifest import ArgSpec, Manifest, ToolSpec
from .model import Envelope
from .money import canonical_money
from .strictjson import StrictJSONError, loads_strict
from .syntax import DOMAIN_LABEL_RE, ID_RE, LOCAL_PART_RE, NAME_RE, matches
from .url import canonical_host, canonical_url, host_suffixes

MAX_ARGUMENTS_BYTES = 64 * 1024
# Explicit bidi embeddings, overrides and isolates ("Trojan Source"). Marks such as U+200E stay legal.
_BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_DERIVATIONS = {"host_suffixes": host_suffixes}


@dataclass(frozen=True, slots=True)
class CanonicalAction:
    tool: str
    principal_type: str
    principal: str
    resource_type: str
    resource_id: str
    resource_parents: tuple[tuple[str, str], ...]
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
        """The hash an approval binds to and the executor re-checks (invariant 3).

        Derived parents are not hashed: they are a deterministic function of the resource id."""
        return digest("dag/action/v1", self.to_json())

    def context_args(self) -> dict[str, Any]:
        return dict(self.args)


def canonicalize(env: Envelope, manifest: Manifest) -> CanonicalAction:
    tool = manifest.tools.get(env.tool)
    if tool is None:
        raise Rejection("UNKNOWN_TOOL")
    try:
        raw = loads_strict(env.arguments, max_bytes=MAX_ARGUMENTS_BYTES)
    except StrictJSONError as err:
        raise Rejection(f"INVALID_ARGUMENTS:{err.code}") from None
    if type(raw) is not dict:
        raise Rejection("INVALID_ARGUMENTS:not_an_object")
    if any(name not in tool.args for name in raw):
        raise Rejection("INVALID_ARGUMENTS:unknown_argument")
    if any(name not in raw for name in tool.args):
        raise Rejection("INVALID_ARGUMENTS:missing_argument")

    args: dict[str, Any] = {}
    for name in sorted(tool.args):
        try:
            args[name] = _canonical_value(tool.args[name], raw[name])
        except Rejection as err:
            # Argument names come from the manifest, never from the agent, so they are safe to cite.
            raise Rejection(f"INVALID_ARGUMENTS:{name}:{err.code}") from None

    resource_id = args[tool.resource_from]
    if tool.resource_field:
        resource_id = resource_id[tool.resource_field]
    if not matches(ID_RE, resource_id):
        raise Rejection("INVALID_ARGUMENTS:bad_resource_id")
    parents: tuple[tuple[str, str], ...] = ()
    if tool.parent_type:
        derive = _DERIVATIONS[tool.parent_derivation]
        parents = tuple((tool.parent_type, suffix) for suffix in derive(resource_id))

    return CanonicalAction(
        tool=tool.name,
        principal_type=manifest.principal_type,
        principal=env.principal,
        resource_type=tool.resource_type,
        resource_id=resource_id,
        resource_parents=parents,
        session_id=env.session_id,
        args=args,
    )


def context_value(spec: ArgSpec, value: Any) -> Any:
    """What a policy may read. Template parameters are validated but not exposed: their shape varies
    per template, and a closed Cedar record cannot describe them. They stay in the action hash."""
    if spec.kind == "template":
        return {"name": value["name"]}
    return value


def context_args(tool: ToolSpec, args: dict[str, Any]) -> dict[str, Any]:
    return {name: context_value(tool.args[name], value) for name, value in args.items()}


def _canonical_value(spec: ArgSpec, value: Any) -> Any:
    if spec.kind == "id":
        if type(value) is not str or ID_RE.match(value) is None:
            raise Rejection("bad_id")
        return value
    if spec.kind == "int":
        if type(value) is not int:  # bool is an int subclass in Python; type() excludes it
            raise Rejection("not_integer")
        if not spec.min <= value <= spec.max:
            raise Rejection("out_of_bounds")
        return value
    if spec.kind == "enum":
        if type(value) is not str or value not in spec.values:
            raise Rejection("not_in_enum")
        return value
    if spec.kind == "text":
        return canonical_text(value, spec.max_len)
    if spec.kind == "email":
        return canonical_email(value)
    if spec.kind == "money":
        return canonical_money(value, currencies=spec.currencies, min_minor=spec.min_minor, max_minor=spec.max_minor)
    if spec.kind == "url":
        return canonical_url(value, schemes=spec.schemes, allow_ip=spec.allow_ip)
    if spec.kind == "template":
        return _canonical_template(spec, value)
    raise Rejection("unsupported_kind")


def _canonical_template(spec: ArgSpec, value: Any) -> dict[str, Any]:
    if type(value) is not dict or sorted(value) != ["name", "params"]:
        raise Rejection("expected_name_and_params")
    name = value["name"]
    if type(name) is not str or not matches(NAME_RE, name):
        raise Rejection("bad_template_name")
    params_spec = spec.templates.get(name)
    if params_spec is None:
        raise Rejection("unknown_template")
    params = value["params"]
    if type(params) is not dict:
        raise Rejection("expected_params_object")
    if any(key not in params_spec for key in params):
        raise Rejection("unknown_parameter")
    if any(key not in params for key in params_spec):
        raise Rejection("missing_parameter")
    canonical = {}
    for key in sorted(params_spec):
        try:
            canonical[key] = _canonical_value(params_spec[key], params[key])
        except Rejection as err:
            raise Rejection(f"{key}:{err.code}") from None
    return {"name": name, "params": canonical}


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


def canonical_email(value: Any) -> dict[str, str]:
    """Returns {"address", "domain"}. The domain goes through the same IDNA path as a URL host; the
    local part keeps its case, because RFC 5321 leaves that to the receiving server."""
    if type(value) is not str:
        raise Rejection("not_text")
    if "<" in value or ">" in value or "," in value:
        raise Rejection("bad_address")  # display names and lists are two addresses waiting to happen
    if value.count("@") != 1:
        raise Rejection("bad_address")
    local, domain = value.split("@")
    if not local.isascii() or LOCAL_PART_RE.match(local) is None or local.startswith(".") or local.endswith(".") or ".." in local:
        raise Rejection("bad_local_part")  # internationalised local parts (SMTPUTF8) are not supported
    domain = canonical_host(domain)
    if not all(DOMAIN_LABEL_RE.match(label) for label in domain.split(".")):
        raise Rejection("bad_domain")
    return {"address": f"{local}@{domain}", "domain": domain}
