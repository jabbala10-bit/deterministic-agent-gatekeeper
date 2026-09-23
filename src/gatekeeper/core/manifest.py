"""Tool manifest: the single source of truth for arguments, resources, templates and labels.

The Cedar schema is generated from it, so every policy is type-checked at load time against exactly
the request context the gate will build."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import Rejection
from .money import CURRENCY_EXPONENT
from .strictjson import MAX_SAFE_INT
from .syntax import BUNDLE_RE, CURRENCY_RE, ID_RE, NAME_RE, SCHEME_RE, TOOL_RE, TYPE_RE, matches

ARG_KINDS = ("email", "enum", "id", "int", "money", "path", "template", "text", "url")
PARAM_KINDS = ("enum", "id", "int", "text")  # what a template parameter may be
RESOURCE_ARG_KINDS = ("email", "id", "path", "template", "url")
ATTR_KINDS = {"bool": "Boolean", "int": "Long", "string": "String"}
URL_SCHEMES = ("http", "https")
DERIVATIONS = ("host_suffixes",)
_STRING, _LONG = {"type": "String"}, {"type": "Long"}
# The shape each canonical value takes in the request context. Records are closed, so a policy can
# only read fields the gate actually puts there.
_CONTEXT_TYPES: dict[str, Any] = {
    "email": {"type": "Record", "attributes": {"address": _STRING, "domain": _STRING}},
    "int": _LONG,
    "money": {"type": "Record", "attributes": {"amount_minor": _LONG, "currency": _STRING}},
    "template": {"type": "Record", "attributes": {"name": _STRING}},
    "url": {"type": "Record", "attributes": {
        "host": _STRING, "path": _STRING, "port": _LONG, "query": _STRING, "scheme": _STRING}},
}


class ManifestError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def _keys(obj: Any, required: set[str], where: str) -> None:
    _require(type(obj) is dict, f"{where}: expected an object")
    _require(obj.keys() == required, f"{where}: expected exactly the keys {sorted(required)}")


def _names(values: Any, pattern: Any, where: str) -> tuple[str, ...]:
    _require(type(values) is list and all(matches(pattern, v) for v in values), f"{where}: bad entries")
    _require(len(set(values)) == len(values), f"{where}: duplicate entries")
    return tuple(sorted(values))


@dataclass(frozen=True, slots=True)
class ArgSpec:
    kind: str
    min: int | None = None
    max: int | None = None
    values: tuple[str, ...] = ()
    max_len: int | None = None
    currencies: tuple[str, ...] = ()
    min_minor: int | None = None
    max_minor: int | None = None
    schemes: tuple[str, ...] = ()
    allow_ip: bool = False
    templates: dict[str, dict[str, "ArgSpec"]] = field(default_factory=dict)
    under: str | None = None
    optional: bool = False

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.kind}
        if self.optional:
            out["optional"] = True
        if self.kind == "int":
            out.update(min=self.min, max=self.max)
        elif self.kind == "enum":
            out["values"] = list(self.values)
        elif self.kind == "text":
            out["max_len"] = self.max_len
        elif self.kind == "money":
            out.update(currencies=list(self.currencies), min_minor=self.min_minor, max_minor=self.max_minor)
        elif self.kind == "url":
            out.update(allow_ip=self.allow_ip, schemes=list(self.schemes))
        elif self.kind == "path" and self.under:
            out["under"] = self.under
        elif self.kind == "template":
            out["templates"] = {name: {"params": {p: s.to_json() for p, s in params.items()}}
                                for name, params in self.templates.items()}
        return out

    def context_type(self) -> Any:
        return _CONTEXT_TYPES.get(self.kind, _STRING)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    groups: tuple[str, ...]
    resource_type: str
    resource_from: str
    resource_field: str | None
    parent_type: str | None
    parent_derivation: str | None
    args: dict[str, ArgSpec]
    result_labels: tuple[str, ...]
    budget_counter: str | None = None
    budget_from: str | None = None
    budget_field: str | None = None

    def to_json(self) -> dict[str, Any]:
        resource: dict[str, Any] = {"from": self.resource_from, "type": self.resource_type}
        if self.resource_field:
            resource["field"] = self.resource_field
        if self.parent_type:
            resource["parents"] = {"derive": self.parent_derivation, "type": self.parent_type}
        out: dict[str, Any] = {
            "args": {name: spec.to_json() for name, spec in self.args.items()},
            "groups": list(self.groups),
            "resource": resource,
            "result_labels": list(self.result_labels),
        }
        if self.budget_counter:
            out["budget"] = {"counter": self.budget_counter, "field": self.budget_field, "from": self.budget_from}
        return out


def _parse_params(spec: Any, where: str) -> dict[str, ArgSpec]:
    _keys(spec, {"params"}, where)
    _require(type(spec["params"]) is dict and len(spec["params"]) > 0, f"{where}.params: expected a non-empty object")
    params: dict[str, ArgSpec] = {}
    for name in sorted(spec["params"]):
        _require(matches(NAME_RE, name), f"{where}: bad parameter name {name!r}")
        parsed = _parse_arg(spec["params"][name], f"{where}.params.{name}")
        _require(parsed.kind in PARAM_KINDS, f"{where}.params.{name}: must be one of {PARAM_KINDS}")
        params[name] = parsed
    return params


def _parse_arg(spec: Any, where: str) -> ArgSpec:
    _require(type(spec) is dict and spec.get("type") in ARG_KINDS, f"{where}: type must be one of {ARG_KINDS}")
    optional = spec.get("optional", False)
    _require(type(optional) is bool, f"{where}.optional: expected a boolean")
    spec = {key: value for key, value in spec.items() if key != "optional"}
    kind = spec["type"]
    if optional:
        return _replace_optional(_parse_arg_inner(spec, where))
    return _parse_arg_inner(spec, where)


def _replace_optional(parsed: ArgSpec) -> ArgSpec:
    return ArgSpec(parsed.kind, parsed.min, parsed.max, parsed.values, parsed.max_len, parsed.currencies,
                   parsed.min_minor, parsed.max_minor, parsed.schemes, parsed.allow_ip, parsed.templates,
                   parsed.under, True)


def _parse_arg_inner(spec: Any, where: str) -> ArgSpec:
    kind = spec["type"]
    if kind == "int":
        _keys(spec, {"type", "min", "max"}, where)
        low, high = spec["min"], spec["max"]
        _require(type(low) is int and type(high) is int and -MAX_SAFE_INT <= low <= high <= MAX_SAFE_INT, f"{where}: bad bounds")
        return ArgSpec(kind, min=low, max=high)
    if kind == "enum":
        _keys(spec, {"type", "values"}, where)
        values = spec["values"]
        ok = type(values) is list and values and all(type(v) is str and v.isascii() and v.isprintable() for v in values)
        _require(bool(ok) and len(set(values)) == len(values), f"{where}: bad enum values")
        return ArgSpec(kind, values=tuple(sorted(values)))
    if kind == "text":
        _keys(spec, {"type", "max_len"}, where)
        _require(type(spec["max_len"]) is int and 1 <= spec["max_len"] <= 1 << 20, f"{where}: bad max_len")
        return ArgSpec(kind, max_len=spec["max_len"])
    if kind == "money":
        _keys(spec, {"type", "currencies", "min_minor", "max_minor"}, where)
        currencies = _names(spec["currencies"], CURRENCY_RE, f"{where}.currencies")
        _require(all(code in CURRENCY_EXPONENT for code in currencies), f"{where}: unknown ISO 4217 code")
        low, high = spec["min_minor"], spec["max_minor"]
        _require(type(low) is int and type(high) is int and 0 <= low <= high <= MAX_SAFE_INT, f"{where}: bad minor-unit bounds")
        return ArgSpec(kind, currencies=currencies, min_minor=low, max_minor=high)
    if kind == "url":
        _keys(spec, {"type", "schemes", "allow_ip"}, where)
        schemes = _names(spec["schemes"], SCHEME_RE, f"{where}.schemes")
        _require(all(scheme in URL_SCHEMES for scheme in schemes), f"{where}: schemes must be within {URL_SCHEMES}")
        _require(type(spec["allow_ip"]) is bool, f"{where}.allow_ip: expected a boolean")
        return ArgSpec(kind, schemes=schemes, allow_ip=spec["allow_ip"])
    if kind == "path":
        _require(spec.keys() <= {"type", "under"} and "type" in spec, f"{where}: bad keys")
        under = spec.get("under")
        _require(under is None or (type(under) is str and under.startswith("/") and len(under) < 4096),
                 f"{where}.under: expected an absolute path")
        return ArgSpec(kind, under=under)
    if kind == "template":
        _keys(spec, {"type", "templates"}, where)
        _require(type(spec["templates"]) is dict and len(spec["templates"]) > 0, f"{where}.templates: expected a non-empty object")
        templates: dict[str, dict[str, ArgSpec]] = {}
        for name in sorted(spec["templates"]):
            _require(matches(NAME_RE, name), f"{where}: bad template name {name!r}")
            templates[name] = _parse_params(spec["templates"][name], f"{where}.templates.{name}")
        return ArgSpec(kind, templates=templates)
    _keys(spec, {"type"}, where)
    return ArgSpec(kind)


def _parse_tool(name: str, spec: Any, groups: tuple[str, ...], labels: tuple[str, ...],
                principal: str, config_types: dict[str, tuple[str, ...]],
                counters: dict[str, int]) -> ToolSpec:
    where = f"tools.{name}"
    _require(matches(TOOL_RE, name), f"{where}: bad tool name")
    _require(type(spec) is dict and spec.keys() <= {"groups", "resource", "args", "result_labels", "budget"}
             and {"groups", "resource", "args", "result_labels"} <= spec.keys(), f"{where}: bad keys")
    tool_groups = _names(spec["groups"], TYPE_RE, f"{where}.groups")
    _require(all(group in groups for group in tool_groups), f"{where}: unknown action group")

    resource = spec["resource"]
    _require(type(resource) is dict and resource.keys() <= {"type", "from", "field", "parents"}
             and {"type", "from"} <= resource.keys(), f"{where}.resource: bad keys")
    resource_type, resource_from = resource["type"], resource["from"]
    _require(matches(TYPE_RE, resource_type) and resource_type != principal, f"{where}: bad resource type")

    _require(type(spec["args"]) is dict and len(spec["args"]) > 0, f"{where}.args: expected a non-empty object")
    args: dict[str, ArgSpec] = {}
    for arg_name in sorted(spec["args"]):
        _require(matches(NAME_RE, arg_name), f"{where}: bad argument name {arg_name!r}")
        args[arg_name] = _parse_arg(spec["args"][arg_name], f"{where}.args.{arg_name}")
    _require(resource_from in args and args[resource_from].kind in RESOURCE_ARG_KINDS,
             f"{where}: resource.from must name an argument of kind {RESOURCE_ARG_KINDS}")

    resource_field = resource.get("field")
    record_kinds = {"email", "template", "url"}
    if args[resource_from].kind in record_kinds:
        _require(matches(NAME_RE, resource_field), f"{where}: resource.field is required for a record-valued argument")
        allowed = set(args[resource_from].context_type()["attributes"])
        _require(resource_field in allowed, f"{where}: resource.field must be one of {sorted(allowed)}")
    else:
        _require(resource_field is None, f"{where}: resource.field applies to record-valued arguments only")

    parent_type = parent_derivation = None
    if "parents" in resource:
        _keys(resource["parents"], {"type", "derive"}, f"{where}.resource.parents")
        parent_type, parent_derivation = resource["parents"]["type"], resource["parents"]["derive"]
        _require(parent_type in config_types, f"{where}: resource.parents.type must be a config entity type")
        _require(parent_derivation in DERIVATIONS, f"{where}: derive must be one of {DERIVATIONS}")

    result_labels = _names(spec["result_labels"], NAME_RE, f"{where}.result_labels")
    _require(all(label in labels for label in result_labels), f"{where}: unknown result label")

    budget_counter = budget_from = budget_field = None
    if "budget" in spec:
        _keys(spec["budget"], {"counter", "from", "field"}, f"{where}.budget")
        budget_counter, budget_from, budget_field = (spec["budget"][k] for k in ("counter", "from", "field"))
        _require(budget_counter in counters, f"{where}.budget: unknown counter")
        _require(budget_from in args, f"{where}.budget: from must name an argument")
        kind = args[budget_from].kind
        if kind == "int":
            _require(budget_field is None, f"{where}.budget: field applies to record-valued arguments only")
            _require(args[budget_from].min >= 0, f"{where}.budget: a reserved amount cannot be negative")
        else:
            attributes = args[budget_from].context_type().get("attributes", {})
            _require(matches(NAME_RE, budget_field) and attributes.get(budget_field) == _LONG,
                     f"{where}.budget: field must name an integer field of {budget_from}")
    return ToolSpec(name, tool_groups, resource_type, resource_from, resource_field,
                    parent_type, parent_derivation, args, result_labels,
                    budget_counter, budget_from, budget_field)


def _attr_ok(kind: str, value: Any) -> bool:
    if kind == "bool":
        return type(value) is bool
    if kind == "int":
        return type(value) is int and abs(value) <= MAX_SAFE_INT
    return type(value) is str


@dataclass(frozen=True, slots=True)
class Manifest:
    bundle: str
    principal_type: str
    labels: tuple[str, ...]
    counters: dict[str, int]
    action_groups: tuple[str, ...]
    config_entity_types: dict[str, tuple[str, ...]]
    snapshot_entity_types: dict[str, dict[str, str]]
    tools: dict[str, ToolSpec]

    @classmethod
    def parse(cls, obj: Any) -> "Manifest":
        _keys(obj, {"manifest_version", "bundle", "principal_type", "labels", "counters", "action_groups",
                    "config_entity_types", "snapshot_entity_types", "tools"}, "manifest")
        _require(obj["manifest_version"] == 3, "manifest_version must be 3")
        _require(matches(BUNDLE_RE, obj["bundle"]), "bundle: bad name")
        principal = obj["principal_type"]
        _require(matches(TYPE_RE, principal), "principal_type: bad type name")
        labels = _names(obj["labels"], NAME_RE, "labels")
        groups = _names(obj["action_groups"], TYPE_RE, "action_groups")

        _require(type(obj["counters"]) is dict, "counters: expected an object")  # a bundle may have no budgets
        counters: dict[str, int] = {}
        for counter_name in sorted(obj["counters"]):
            _require(matches(NAME_RE, counter_name), f"counters: bad name {counter_name!r}")
            entry = obj["counters"][counter_name]
            _keys(entry, {"max"}, f"counters.{counter_name}")
            _require(type(entry["max"]) is int and 0 < entry["max"] <= MAX_SAFE_INT, f"counters.{counter_name}: bad max")
            counters[counter_name] = entry["max"]

        config: dict[str, tuple[str, ...]] = {}
        _require(type(obj["config_entity_types"]) is dict, "config_entity_types: expected an object")
        for type_name in sorted(obj["config_entity_types"]):
            _require(matches(TYPE_RE, type_name) and type_name != principal, f"config_entity_types: bad type {type_name!r}")
            entry = obj["config_entity_types"][type_name]
            _keys(entry, {"member_of"}, f"config_entity_types.{type_name}")
            config[type_name] = _names(entry["member_of"], TYPE_RE, f"{type_name}.member_of")
        for type_name, parents in config.items():
            _require(all(parent in config for parent in parents), f"{type_name}: member_of must name config entity types")

        snapshot_types: dict[str, dict[str, str]] = {}
        _require(type(obj["snapshot_entity_types"]) is dict, "snapshot_entity_types: expected an object")
        for type_name in sorted(obj["snapshot_entity_types"]):
            attrs = obj["snapshot_entity_types"][type_name]
            _require(matches(TYPE_RE, type_name) and type_name not in config and type_name != principal,
                     f"snapshot_entity_types: bad or clashing type {type_name!r}")
            _require(type(attrs) is dict and all(matches(NAME_RE, a) and k in ATTR_KINDS for a, k in attrs.items()),
                     f"{type_name}: attributes must map names to one of {sorted(ATTR_KINDS)}")
            snapshot_types[type_name] = {a: attrs[a] for a in sorted(attrs)}

        _require(type(obj["tools"]) is dict and len(obj["tools"]) > 0, "tools: expected a non-empty object")
        tools = {name: _parse_tool(name, obj["tools"][name], groups, labels, principal, config, counters)
                 for name in sorted(obj["tools"])}
        for tool in tools.values():
            # A derived resource entity must not collide with config or snapshot data.
            if tool.parent_type is not None:
                _require(tool.resource_type not in config and tool.resource_type not in snapshot_types,
                         f"tools.{tool.name}: a resource with derived parents needs its own entity type")
        return cls(obj["bundle"], principal, labels, counters, groups, config, snapshot_types, tools)

    def to_json(self) -> dict[str, Any]:
        """Normalised form used for hashing: reordering sets in the source never changes it."""
        return {
            "action_groups": list(self.action_groups),
            "bundle": self.bundle,
            "config_entity_types": {t: {"member_of": list(p)} for t, p in self.config_entity_types.items()},
            "counters": {name: {"max": limit} for name, limit in self.counters.items()},
            "labels": list(self.labels),
            "manifest_version": 3,
            "principal_type": self.principal_type,
            "snapshot_entity_types": {t: dict(a) for t, a in self.snapshot_entity_types.items()},
            "tools": {name: tool.to_json() for name, tool in self.tools.items()},
        }

    def cedar_schema(self) -> dict[str, Any]:
        entity_types: dict[str, Any] = {self.principal_type: {}}
        for type_name, parents in self.config_entity_types.items():
            entity_types[type_name] = {"memberOfTypes": list(parents)} if parents else {}
        for type_name, attrs in self.snapshot_entity_types.items():
            entity_types[type_name] = {"shape": {"type": "Record", "attributes": {
                name: {"type": ATTR_KINDS[kind]} for name, kind in attrs.items()}}}
        for tool in self.tools.values():
            existing = entity_types.setdefault(tool.resource_type, {})
            if tool.parent_type:
                existing["memberOfTypes"] = sorted(set(existing.get("memberOfTypes", [])) | {tool.parent_type})
        actions: dict[str, Any] = {group: {} for group in self.action_groups}
        for tool in self.tools.values():
            action: dict[str, Any] = {"appliesTo": {
                "principalTypes": [self.principal_type],
                "resourceTypes": [tool.resource_type],
                "context": self._context_type(tool),
            }}
            if tool.groups:
                action["memberOf"] = [{"id": group} for group in tool.groups]
            actions[tool.name] = action
        return {"": {"entityTypes": entity_types, "actions": actions}}

    def _context_type(self, tool: ToolSpec) -> dict[str, Any]:
        return {"type": "Record", "attributes": {
            "action_hash": _STRING,
            "now_ms": _LONG,
            "session": {"type": "Record", "attributes": {
                "counters": {"type": "Record", "attributes": {name: _LONG for name in self.counters}},
                "labels": {"type": "Set", "element": _STRING},
                "ledger_seq": _LONG,
            }},
            "approval": {"type": "Record", "required": False, "attributes": {"action_hash": _STRING}},
            "args": {"type": "Record", "attributes": {
                name: (dict(spec.context_type(), required=False) if spec.optional else spec.context_type())
                for name, spec in tool.args.items()}},
        }}

    def check_snapshot(self, snap: Any) -> None:
        """Snapshots carry runtime facts only. Policy configuration (allowlists, group membership)
        can never arrive through a snapshot, so a compromised shell path cannot widen policy."""
        for label in snap.labels:
            if label not in self.labels:
                raise Rejection("unknown_label")
        counters = dict(snap.counters)
        if sorted(counters) != sorted(self.counters):
            raise Rejection("counter_mismatch")
        for name, value in counters.items():
            if value > self.counters[name]:
                raise Rejection("counter_over_maximum")
        for entity in snap.entities:
            spec = self.snapshot_entity_types.get(entity.type)
            if spec is None:
                raise Rejection("entity_type_not_allowed")
            attrs = dict(entity.attrs)
            if sorted(attrs) != list(spec):
                raise Rejection("entity_attrs_mismatch")
            if not all(_attr_ok(kind, attrs[name]) for name, kind in spec.items()):
                raise Rejection("entity_attr_type")

    def check_config_entities(self, entities: Any) -> list[dict[str, Any]]:
        _require(type(entities) is list, "entities: expected a list")
        out: list[dict[str, Any]] = []
        for entity in entities:
            _keys(entity, {"uid", "attrs", "parents"}, "entity")
            _keys(entity["uid"], {"type", "id"}, "entity.uid")
            type_name, entity_id = entity["uid"]["type"], entity["uid"]["id"]
            where = f"entity {type_name}::{entity_id}"
            _require(type_name in self.config_entity_types, f"{where}: only config entity types belong in a bundle")
            _require(matches(ID_RE, entity_id), f"{where}: bad id")
            _require(entity["attrs"] == {}, f"{where}: config entities carry no attributes")
            _require(type(entity["parents"]) is list, f"{where}: parents must be a list")
            parents = []
            for parent in entity["parents"]:
                _keys(parent, {"type", "id"}, f"{where}.parent")
                _require(parent["type"] in self.config_entity_types[type_name] and matches(ID_RE, parent["id"]),
                         f"{where}: parent not allowed")
                parents.append({"type": parent["type"], "id": parent["id"]})
            out.append({"uid": {"type": type_name, "id": entity_id}, "attrs": {},
                        "parents": sorted(parents, key=lambda p: (p["type"], p["id"]))})
        out.sort(key=lambda e: (e["uid"]["type"], e["uid"]["id"]))
        uids = [(e["uid"]["type"], e["uid"]["id"]) for e in out]
        _require(all(a != b for a, b in zip(uids, uids[1:])), "entities: duplicate uid")
        return out
