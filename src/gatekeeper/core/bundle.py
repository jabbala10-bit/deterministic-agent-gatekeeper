"""Policy bundle: Cedar policies, configuration entities and the tool manifest, validated at load
and identified by one content hash.

Two engine behaviours drive this module (both reproduced in tests):
  * default policy ids are positions in the file, so reordering renames every reason; the bundle
    maps positions to each policy's @id annotation and refuses policies without one;
  * the engine returns reasons in a per-process random order; they are sorted before hashing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from cedarpy import Entities, PolicySet, Schema, is_authorized, policies_to_json_str, validate_policies

from .canonical import CanonicalAction
from .digest import digest
from .manifest import Manifest
from .model import EntityRecord
from .strictjson import StrictJSONError, loads_strict
from .syntax import POLICY_ID_RE

_ERROR_POLICY_RE = re.compile(r"policy `([^`]+)`")


class BundleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Evaluation:
    allowed: bool
    reasons: tuple[str, ...]  # stable @ids, sorted
    errors: tuple[str, ...]   # stable @ids of policies that errored, sorted
    engine_decision: str      # what the raw engine said, kept for diagnostics and tests


class PolicyBundle:
    """Immutable after construction. Build with PolicyBundle.from_sources()."""

    __slots__ = ("manifest", "policy_hash", "engine", "_policy_set", "_schema", "_base_entities", "_ids")

    def __init__(self, *, manifest: Manifest, policy_hash: str, engine: str, policy_set: Any,
                 schema: Any, base_entities: Any, ids: dict[str, str]) -> None:
        self.manifest = manifest
        self.policy_hash = policy_hash
        self.engine = engine
        self._policy_set = policy_set
        self._schema = schema
        self._base_entities = base_entities
        self._ids = ids

    @classmethod
    def from_sources(cls, *, policies_text: str, entities_text: str, manifest_text: str, engine: str) -> "PolicyBundle":
        try:
            manifest = Manifest.parse(loads_strict(manifest_text, max_bytes=1 << 20))
            config_entities = manifest.check_config_entities(loads_strict(entities_text, max_bytes=1 << 20))
        except StrictJSONError as err:
            raise BundleError(f"bundle JSON rejected: {err.code}") from None
        schema_json = manifest.cedar_schema()

        # Shift errors to load time wherever the validator can see them (typos, type mismatches).
        validation = validate_policies(policies_text, schema_json)
        if not validation.validation_passed:
            raise BundleError("policy validation failed: " + "; ".join(str(e) for e in validation.errors))

        est = json.loads(policies_to_json_str(policies_text))
        if est.get("templates") or est.get("templateLinks"):
            raise BundleError("policy templates are not supported in phase 1")
        ids: dict[str, str] = {}
        by_id: dict[str, Any] = {}
        for position, policy in est["staticPolicies"].items():
            stable = (policy.get("annotations") or {}).get("id")
            if type(stable) is not str or POLICY_ID_RE.match(stable) is None:
                raise BundleError(f"{position}: every policy needs an @id(\"kebab-case\") annotation")
            if stable in by_id:
                raise BundleError(f"duplicate @id {stable!r}")
            ids[position] = stable
            by_id[stable] = policy

        # Hash semantic content keyed by stable id: comments, formatting and ordering do not count.
        try:
            policy_hash = digest("dag/policy/v1", {
                "entities": config_entities,
                "manifest": manifest.to_json(),
                "policies": by_id,
            })
        except StrictJSONError as err:
            raise BundleError(f"bundle cannot be canonicalised: {err.code}") from None

        schema = Schema.from_json_str(json.dumps(schema_json))
        return cls(
            manifest=manifest,
            policy_hash=policy_hash,
            engine=engine,
            policy_set=PolicySet.from_str(policies_text),
            schema=schema,
            base_entities=Entities.from_json_str(json.dumps(config_entities), schema),
            ids=ids,
        )

    def evaluate(self, action: CanonicalAction, context: dict[str, Any], facts: tuple[EntityRecord, ...]) -> Evaluation:
        request = {
            "principal": {"type": action.principal_type, "id": action.principal},
            "action": {"type": "Action", "id": action.tool},
            "resource": {"type": action.resource_type, "id": action.resource_id},
            "context": context,
        }
        extra = [fact.to_cedar() for fact in facts]
        if action.resource_parents:
            # The resource entity is derived from the canonical action, never from the snapshot, so a
            # bundle can allowlist a domain suffix and reach every host beneath it.
            extra.append({
                "uid": {"type": action.resource_type, "id": action.resource_id},
                "attrs": {},
                "parents": [{"type": kind, "id": identifier} for kind, identifier in action.resource_parents],
            })
        try:
            entities = self._base_entities
            if extra:
                entities = entities.with_added_json_str(json.dumps(extra), self._schema)
            result = is_authorized(request, self._policy_set, entities, self._schema)
        except Exception:  # the engine refused its input: fail closed with a stable code
            return Evaluation(False, (), ("engine_exception",), "Exception")
        # result.metrics carries timings; it must never reach a record or a hash.
        errors = tuple(sorted({self._attribute(str(e)) for e in result.diagnostics.errors}))
        engine_decision = result.decision.name
        if engine_decision not in ("Allow", "Deny") and not errors:
            errors = ("no_decision",)
        reasons = tuple(sorted(self._ids.get(r, "unattributed") for r in result.diagnostics.reasons))
        return Evaluation(engine_decision == "Allow" and not errors, reasons, errors, engine_decision)

    def _attribute(self, message: str) -> str:
        match = _ERROR_POLICY_RE.search(message)
        return self._ids.get(match.group(1), "unattributed") if match else "unattributed"
