"""Tool manifest: the single source of truth for arguments, resources and session labels.

The Cedar schema is generated from it, so every policy is type-checked at load time against
exactly the request context the gate will build."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import Rejection
from .strictjson import MAX_SAFE_INT
from .syntax import BUNDLE_RE, ID_RE, NAME_RE, TOOL_RE, TYPE_RE, matches

ARG_KINDS = ("email", "enum", "id", "int", "text")
RESOURCE_ARG_KINDS = ("email", "id")
ATTR_KINDS = {"bool": "Boolean", "int": "Long", "string": "String"}


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

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.kind}
        if self.kind == "int":
            out.update(min=self.min, max=self.max)
        elif self.kind == "enum":
            out["values"] = list(self.values)
        elif self.kind == "text":
            out["max_len"] = self.max_len
        return out


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    groups: tuple[str, ...]
    resource_type: str
    resource_from: str
    args: dict[str, ArgSpec]
    result_labels: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "args": {name: spec.to_json() for name, spec in self.args.items()},
            "groups": list(self.groups),
            "resource": {"from": self.resource_from, "type": self.resource_type},
            "result_labels": list(self.result_labels),
        }


def _parse_arg(spec: Any, where: str) -> ArgSpec:
    _require(type(spec) is dict and spec.get("type") in ARG_KINDS, f"{where}: type must be one of {ARG_KINDS}")
    kind = spec["type"]
    if kind == "int":
        _keys(spec, {"type", "min", "max"}, where)
        lo, hi = spec["min"], spec["max"]
        _require(type(lo) is int and type(hi) is int and -MAX_SAFE_INT <= lo <= hi <= MAX_SAFE_INT, f"{where}: bad bounds")
        return ArgSpec(kind, min=lo, max=hi)
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
    _keys(spec, {"type"}, where)
    return ArgSpec(kind)


def _parse_tool(name: str, spec: Any, groups: tuple[str, ...], labels: tuple[str, ...], principal: str) -> ToolSpec:
    where = f"tools.{name}"
    _require(matches(TOOL_RE, name), f"{where}: bad tool name")
    _keys(spec, {"groups", "resource", "args", "result_labels"}, where)
    tool_groups = _names(spec["groups"], TYPE_RE, f"{where}.groups")
    _require(all(g in groups for g in tool_groups), f"{where}: unknown action group")
    _keys(spec["resource"], {"type", "from"}, f"{where}.resource")
    resource_type, resource_from = spec["resource"]["type"], spec["resource"]["from"]
    _require(matches(TYPE_RE, resource_type) and resource_type != principal, f"{where}: bad resource type")
    _require(type(spec["args"]) is dict and len(spec["args"]) > 0, f"{where}.args: expected a non-empty object")
    args: dict[str, ArgSpec] = {}
    for arg_name in sorted(spec["args"]):
        _require(matches(NAME_RE, arg_name), f"{where}: bad argument name {arg_name!r}")
        args[arg_name] = _parse_arg(spec["args"][arg_name], f"{where}.args.{arg_name}")
    _require(resource_from in args and args[resource_from].kind in RESOURCE_ARG_KINDS, f"{where}: resource.from must name an id or email argument")
    result_labels = _names(spec["result_labels"], NAME_RE, f"{where}.result_labels")
    _require(all(label in labels for label in result_labels), f"{where}: unknown result label")
    return ToolSpec(name, tool_groups, resource_type, resource_from, args, result_labels)


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
    action_groups: tuple[str, ...]
    config_entity_types: dict[str, tuple[str, ...]]
    snapshot_entity_types: dict[str, dict[str, str]]
    tools: dict[str, ToolSpec]

    @classmethod
    def parse(cls, obj: Any) -> "Manifest":
        _keys(obj, {"manifest_version", "bundle", "principal_type", "labels", "action_groups",
                    "config_entity_types", "snapshot_entity_types", "tools"}, "manifest")
        _require(obj["manifest_version"] == 1, "manifest_version must be 1")
        _require(matches(BUNDLE_RE, obj["bundle"]), "bundle: bad name")
        principal = obj["principal_type"]
        _require(matches(TYPE_RE, principal), "principal_type: bad type name")
        labels = _names(obj["labels"], NAME_RE, "labels")
        groups = _names(obj["action_groups"], TYPE_RE, "action_groups")

        config: dict[str, tuple[str, ...]] = {}
        _require(type(obj["config_entity_types"]) is dict, "config_entity_types: expected an object")
        for type_name in sorted(obj["config_entity_types"]):
            _require(matches(TYPE_RE, type_name) and type_name != principal, f"config_entity_types: bad type {type_name!r}")
            spec = obj["config_entity_types"][type_name]
            _keys(spec, {"member_of"}, f"config_entity_types.{type_name}")
            config[type_name] = _names(spec["member_of"], TYPE_RE, f"{type_name}.member_of")
        for type_name, parents in config.items():
            _require(all(p in config for p in parents), f"{type_name}: member_of must name config entity types")

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
        tools = {name: _parse_tool(name, obj["tools"][name], groups, labels, principal) for name in sorted(obj["tools"])}
        return cls(obj["bundle"], principal, labels, groups, config, snapshot_types, tools)

    def to_json(self) -> dict[str, Any]:
        """Normalised form used for hashing: reordering sets in the source never changes it."""
        return {
            "action_groups": list(self.action_groups),
            "bundle": self.bundle,
            "config_entity_types": {t: {"member_of": list(p)} for t, p in self.config_entity_types.items()},
            "labels": list(self.labels),
            "manifest_version": 1,
            "principal_type": self.principal_type,
            "snapshot_entity_types": {t: dict(a) for t, a in self.snapshot_entity_types.items()},
            "tools": {name: tool.to_json() for name, tool in self.tools.items()},
        }

    def cedar_schema(self) -> dict[str, Any]:
        """Cedar JSON schema for exactly the requests decide() builds. Records are closed, so a
        context field the gate did not put there fails validation instead of being evaluated."""
        entity_types: dict[str, Any] = {self.principal_type: {}}
        for type_name, parents in self.config_entity_types.items():
            entity_types[type_name] = {"memberOfTypes": list(parents)} if parents else {}
        for type_name, attrs in self.snapshot_entity_types.items():
            entity_types[type_name] = {"shape": {"type": "Record", "attributes": {
                name: {"type": ATTR_KINDS[kind]} for name, kind in attrs.items()}}}
        for tool in self.tools.values():
            entity_types.setdefault(tool.resource_type, {})
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

    @staticmethod
    def _context_type(tool: ToolSpec) -> dict[str, Any]:
        string, long = {"type": "String"}, {"type": "Long"}
        return {"type": "Record", "attributes": {
            "action_hash": string,
            "now_ms": long,
            "session": {"type": "Record", "attributes": {
                "labels": {"type": "Set", "element": string},
                "ledger_seq": long,
                "refunded_minor": long,
            }},
            "approval": {"type": "Record", "required": False, "attributes": {"action_hash": string}},
            "args": {"type": "Record", "attributes": {
                name: (long if spec.kind == "int" else string) for name, spec in tool.args.items()}},
        }}

    def check_snapshot(self, snap: Any) -> None:
        """Snapshots carry runtime facts only. Policy configuration (allowlists, groups) can never
        arrive through a snapshot, so a compromised shell path cannot widen policy."""
        for label in snap.labels:
            if label not in self.labels:
                raise Rejection("unknown_label")
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
        """Validate and normalise the bundle's configuration entities."""
        _require(type(entities) is list, "entities: expected a list")
        out: list[dict[str, Any]] = []
        for entity in entities:
            _keys(entity, {"uid", "attrs", "parents"}, "entity")
            _keys(entity["uid"], {"type", "id"}, "entity.uid")
            type_name, entity_id = entity["uid"]["type"], entity["uid"]["id"]
            where = f"entity {type_name}::{entity_id}"
            _require(type_name in self.config_entity_types, f"{where}: only config entity types belong in a bundle")
            _require(matches(ID_RE, entity_id), f"{where}: bad id")
            _require(entity["attrs"] == {}, f"{where}: config entities carry no attributes in phase 1")
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
