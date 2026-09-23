"""Comparing two policy bundles.

Two questions matter before a policy change ships:

  1. does the candidate permit anything the base did not? A widening is the dangerous direction, and
     it should never happen by accident;
  2. which decisions already taken would come out differently? A tightening is usually intended, and
     the point is to see whose past calls it would have refused.

The second question is answered exactly, by re-deciding recorded history against the candidate.

The first is answered by enumerating a bounded request space and comparing verdicts. Integer
boundaries are mined from the literals in both policy sets, so changing a cap from 20000 to 20001
produces a counterexample by construction. This finds widenings; it does not prove their absence
outside the enumerated domain. ADR-010 says what a proof would take."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterator

from .decide import decide
from .manifest import ArgSpec, Manifest, ToolSpec
from .model import EntityRecord, Envelope, Snapshot
from .money import CURRENCY_EXPONENT, decimal_text

RANK = {"DENY": 0, "REQUIRE_APPROVAL": 1, "ALLOW": 2}
PROBE_SESSION = "diff-probe"
PROBE_PRINCIPAL = "probe-agent"
PROBE_T_MS = 1_790_000_000_000
PROBE_ID = "probe-1"
MISSING_ID = "probe-absent"
MAX_PER_DIMENSION = 8


@dataclass(frozen=True)
class Divergence:
    tool: str
    arguments: str
    snapshot: Snapshot
    base_verdict: str
    base_reasons: tuple[str, ...]
    candidate_verdict: str
    candidate_reasons: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "arguments": self.arguments,
            "base": {"reasons": list(self.base_reasons), "verdict": self.base_verdict},
            "candidate": {"reasons": list(self.candidate_reasons), "verdict": self.candidate_verdict},
            "snapshot": self.snapshot.to_json(),
            "tool": self.tool,
        }

    def describe(self) -> str:
        labels = "+".join(self.snapshot.labels) or "none"
        counters = ", ".join(f"{name}={value}" for name, value in self.snapshot.counters) or "none"
        approval = "approved" if self.snapshot.approvals else "no approval"
        return (f"{self.tool} {self.arguments}\n"
                f"      session: labels {labels}; counters {counters}; {approval}\n"
                f"      base {self.base_verdict} {list(self.base_reasons)} -> "
                f"candidate {self.candidate_verdict} {list(self.candidate_reasons)}")


@dataclass
class StructuralDiff:
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()

    @property
    def any(self) -> bool:
        return bool(self.added or self.removed or self.changed)


@dataclass
class DiffReport:
    structural: StructuralDiff = field(default_factory=StructuralDiff)
    probes: int = 0
    widened: list[Divergence] = field(default_factory=list)
    tightened: list[Divergence] = field(default_factory=list)
    reasons_only: int = 0
    history_decisions: int = 0
    history_changed: list[dict[str, Any]] = field(default_factory=list)
    tools_added: tuple[str, ...] = ()
    tools_removed: tuple[str, ...] = ()

    @property
    def widens(self) -> bool:
        return bool(self.widened or self.tools_added)


def structural_diff(base_policies: dict[str, Any], candidate_policies: dict[str, Any]) -> StructuralDiff:
    """Which policies were added, removed or altered, by stable @id."""
    added = tuple(sorted(set(candidate_policies) - set(base_policies)))
    removed = tuple(sorted(set(base_policies) - set(candidate_policies)))
    changed = tuple(sorted(
        name for name in set(base_policies) & set(candidate_policies)
        if json.dumps(base_policies[name], sort_keys=True) != json.dumps(candidate_policies[name], sort_keys=True)))
    return StructuralDiff(added, removed, changed)


def mine_literals(*policy_sets: dict[str, Any]) -> tuple[int, ...]:
    """Every integer that appears in either policy set: the numbers the rules actually turn on."""
    found: set[int] = set()

    def walk(node: Any) -> None:
        if type(node) is bool:
            return
        if type(node) is int:
            found.add(node)
        elif type(node) is dict:
            for value in node.values():
                walk(value)
        elif type(node) is list:
            for value in node:
                walk(value)

    for policies in policy_sets:
        walk(policies)
    return tuple(sorted(found))


def _boundaries(low: int, high: int, literals: tuple[int, ...]) -> list[int]:
    values = {low, high}
    for literal in literals:
        for candidate in (literal - 1, literal, literal + 1):
            if low <= candidate <= high:
                values.add(candidate)
    ordered = sorted(values)
    if len(ordered) <= MAX_PER_DIMENSION:
        return ordered
    step = len(ordered) / MAX_PER_DIMENSION
    return [ordered[min(len(ordered) - 1, int(index * step))] for index in range(MAX_PER_DIMENSION)]


def _suffix_values(manifest: Manifest, parent_type: str | None, config_ids: dict[str, tuple[str, ...]]) -> list[str]:
    """Hosts and domains worth probing: what the bundle allowlists, something beneath it, a splice
    that only looks like it, and something unrelated."""
    known = list(config_ids.get(parent_type or "", ()))[:2]
    out: list[str] = []
    for name in known:
        out.extend([name, f"sub.{name}", f"{name}.attacker.test"])
    out.append("unlisted.test")
    return out[:MAX_PER_DIMENSION]


def _arg_values(spec: ArgSpec, tool: ToolSpec, manifest: Manifest, literals: tuple[int, ...],
                config_ids: dict[str, tuple[str, ...]], resource_is_fact: bool) -> list[Any]:
    if spec.kind == "bool":
        return [False, True]
    if spec.kind == "int":
        assert spec.min is not None and spec.max is not None
        return _boundaries(spec.min, spec.max, literals)
    if spec.kind == "enum":
        return list(spec.values)[:MAX_PER_DIMENSION]
    if spec.kind == "text":
        return ["probe"]
    if spec.kind == "id":
        if resource_is_fact:
            return [PROBE_ID, MISSING_ID]
        known = config_ids.get(tool.resource_type, ())
        return ([known[0], PROBE_ID] if known else [PROBE_ID])
    if spec.kind == "money":
        assert spec.min_minor is not None and spec.max_minor is not None
        amounts = _boundaries(max(spec.min_minor, 1), spec.max_minor, literals)
        return [{"amount": decimal_text(minor, currency), "currency": currency}
                for currency in spec.currencies[:3] for minor in amounts
                if minor % 10 ** (2 - CURRENCY_EXPONENT[currency]) == 0 or CURRENCY_EXPONENT[currency] == 2]
    if spec.kind == "email":
        return [f"probe@{domain}" for domain in _suffix_values(manifest, tool.parent_type, config_ids)]
    if spec.kind == "url":
        hosts = _suffix_values(manifest, tool.parent_type, config_ids)
        return [f"{scheme}://{host}/probe" for scheme in spec.schemes for host in hosts]
    if spec.kind == "path":
        root = (spec.under or "/probe").rstrip("/")
        return [f"{root}/probe.txt", root]
    if spec.kind == "template":
        out = []
        for name, params in spec.templates.items():
            rendered = {}
            for param, param_spec in params.items():
                values = _arg_values(param_spec, tool, manifest, literals, config_ids, False)
                rendered[param] = values[0] if values else "probe"
            out.append({"name": name, "params": rendered})
        return out[:MAX_PER_DIMENSION]
    return ["probe"]


def _fact_variants(manifest: Manifest, tool: ToolSpec) -> list[tuple[EntityRecord, ...]]:
    attrs = manifest.snapshot_entity_types.get(tool.resource_type)
    if attrs is None:
        return [()]
    variants = []
    for flag in (False, True):
        values: dict[str, Any] = {}
        for name, kind in attrs.items():
            values[name] = flag if kind == "bool" else (1 if kind == "int" else "probe")
        variants.append((EntityRecord.build(tool.resource_type, PROBE_ID, values),))
    variants.append(())  # the fact the shell never loaded: fail-closed territory
    return variants


def _label_sets(manifest: Manifest) -> list[tuple[str, ...]]:
    labels = list(manifest.labels)[:3]
    out: list[tuple[str, ...]] = [()]
    for index in range(1, 1 << len(labels)):
        out.append(tuple(sorted(label for position, label in enumerate(labels) if index >> position & 1)))
    return out


def probes(manifest: Manifest, config_ids: dict[str, tuple[str, ...]], literals: tuple[int, ...],
           budget: int) -> Iterator[tuple[Envelope, Snapshot, bool]]:
    """A bounded, deterministic request space. The bool says whether to bind an approval."""
    counter_values = {name: _boundaries(0, limit, literals)[:4] for name, limit in manifest.counters.items()}
    for tool_name in sorted(manifest.tools):
        tool = manifest.tools[tool_name]
        resource_is_fact = tool.resource_type in manifest.snapshot_entity_types
        per_arg = {name: _arg_values(spec, tool, manifest, literals, config_ids,
                                     resource_is_fact and name == tool.resource_from)
                   for name, spec in tool.args.items()}
        names = sorted(per_arg)
        combinations: list[dict[str, Any]] = [{}]
        for name in names:
            combinations = [dict(base, **{name: value}) for base in combinations for value in per_arg[name]]
            if len(combinations) > budget:
                combinations = combinations[:budget]
        counters = [dict(zip(counter_values, values)) for values in _product(counter_values)] or [{}]
        emitted = 0
        for arguments in combinations:
            for facts in _fact_variants(manifest, tool):
                for labels in _label_sets(manifest):
                    for counter_set in counters:
                        for approved in (False, True):
                            if emitted >= budget:
                                break
                            envelope = Envelope(tool=tool_name, principal=PROBE_PRINCIPAL,
                                                session_id=PROBE_SESSION, t_ms=PROBE_T_MS,
                                                arguments=json.dumps(arguments, separators=(",", ":"), sort_keys=True))
                            snapshot = Snapshot.build(session_id=PROBE_SESSION, ledger_seq=1, labels=labels,
                                                      counters=counter_set, entities=facts)
                            emitted += 1
                            yield envelope, snapshot, approved


def _product(values: dict[str, list[int]]) -> list[tuple[int, ...]]:
    out: list[tuple[int, ...]] = [()]
    for options in values.values():
        out = [row + (option,) for row in out for option in options]
    return out[:8]


def compare(base: Any, candidate: Any, *, budget: int = 4000, max_examples: int = 3) -> DiffReport:
    """Enumerate, decide twice, and classify every divergence."""
    report = DiffReport(structural=structural_diff(base.policies_by_id, candidate.policies_by_id))
    report.tools_added = tuple(sorted(set(candidate.manifest.tools) - set(base.manifest.tools)))
    report.tools_removed = tuple(sorted(set(base.manifest.tools) - set(candidate.manifest.tools)))
    literals = mine_literals(base.policies_by_id, candidate.policies_by_id)
    config_ids = _config_ids(candidate)
    shared = set(base.manifest.tools) & set(candidate.manifest.tools)

    for envelope, snapshot, approved in probes(candidate.manifest, config_ids, literals, budget):
        if envelope.tool not in shared:
            continue
        if approved:
            from .canonical import canonicalize
            from .errors import Rejection
            try:
                action_hash = canonicalize(envelope, candidate.manifest).digest()
            except Rejection:
                continue
            snapshot = Snapshot.build(session_id=snapshot.session_id, ledger_seq=snapshot.ledger_seq,
                                      labels=snapshot.labels, counters=dict(snapshot.counters),
                                      approvals=(action_hash,), entities=snapshot.entities)
        report.probes += 1
        before, after = decide(envelope, snapshot, base), decide(envelope, snapshot, candidate)
        if before.verdict == after.verdict:
            if before.reasons != after.reasons:
                report.reasons_only += 1
            continue
        divergence = Divergence(envelope.tool, envelope.arguments, snapshot, before.verdict,
                                before.reasons, after.verdict, after.reasons)
        target = report.widened if RANK[after.verdict] > RANK[before.verdict] else report.tightened
        if len(target) < max_examples or target is report.widened:
            target.append(divergence)
    return report


def _config_ids(bundle: Any) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for entity in bundle.config_entities:
        grouped.setdefault(entity["uid"]["type"], []).append(entity["uid"]["id"])
    return {kind: tuple(sorted(ids)) for kind, ids in grouped.items()}
