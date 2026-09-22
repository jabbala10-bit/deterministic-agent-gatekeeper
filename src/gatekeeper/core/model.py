"""Inputs and outputs of the pure decision function.

Envelope and Snapshot are everything a decision depends on besides the policy bundle. Both are
recorded verbatim, which is what makes any past decision re-derivable."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .digest import digest
from .strictjson import MAX_SAFE_INT
from .syntax import HASH_RE, ID_RE, NAME_RE, TYPE_RE, matches

VERDICTS = ("ALLOW", "DENY", "REQUIRE_APPROVAL")


def _utf8_text(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _safe_nonnegative(value: Any) -> bool:
    return type(value) is int and 0 <= value <= MAX_SAFE_INT


def _strictly_sorted(items: list[Any] | tuple[Any, ...]) -> bool:
    return all(a < b for a, b in zip(items, items[1:]))


def _exact_keys(obj: Any, keys: tuple[str, ...], where: str) -> dict[str, Any]:
    if type(obj) is not dict or sorted(obj) != sorted(keys):
        raise ValueError(f"{where}: expected exactly the keys {sorted(keys)}")
    return obj


@dataclass(frozen=True, slots=True)
class Envelope:
    """One proposed tool call, as assembled by the trusted shell at ingress.

    tool and arguments come from the untrusted agent. They are validated only inside decide(),
    so bad values become recorded DENY decisions rather than exceptions. principal, session_id
    and t_ms come from the shell (authenticated identity, one clock read) and are checked here.
    """

    tool: str
    arguments: str
    principal: str
    session_id: str
    t_ms: int

    def __post_init__(self) -> None:
        if not _utf8_text(self.tool) or len(self.tool) > 256:
            raise ValueError("tool must be UTF-8 text of at most 256 characters")
        if not _utf8_text(self.arguments) or len(self.arguments) > 1 << 20:
            raise ValueError("arguments must be UTF-8 text of at most 1 MiB")
        if not matches(ID_RE, self.principal) or not matches(ID_RE, self.session_id):
            raise ValueError("principal and session_id must be canonical ids")
        if not _safe_nonnegative(self.t_ms):
            raise ValueError("t_ms must be a non-negative safe integer")

    def to_json(self) -> dict[str, Any]:
        return {
            "arguments": self.arguments,
            "principal": self.principal,
            "session_id": self.session_id,
            "t_ms": self.t_ms,
            "tool": self.tool,
        }

    @classmethod
    def from_json(cls, obj: Any) -> "Envelope":
        obj = _exact_keys(obj, ("arguments", "principal", "session_id", "t_ms", "tool"), "envelope")
        return cls(**obj)


@dataclass(frozen=True, slots=True)
class EntityRecord:
    """A runtime fact the shell loaded for this decision, such as an Account and its status."""

    type: str
    id: str
    attrs: tuple[tuple[str, bool | int | str], ...]

    def __post_init__(self) -> None:
        if not matches(TYPE_RE, self.type) or not matches(ID_RE, self.id):
            raise ValueError("entity type or id is not canonical")
        if type(self.attrs) is not tuple:
            raise ValueError("entity attrs must be a tuple of (name, value) pairs")
        names = [name for name, _ in self.attrs]
        if not all(matches(NAME_RE, n) for n in names) or not _strictly_sorted(names):
            raise ValueError("entity attr names must be canonical, sorted and unique")
        for _, value in self.attrs:
            ok = type(value) is bool or (type(value) is int and abs(value) <= MAX_SAFE_INT) or _utf8_text(value)
            if not ok:
                raise ValueError("entity attr values must be bool, safe int or text")

    @classmethod
    def build(cls, type_: str, id_: str, attrs: dict[str, Any]) -> "EntityRecord":
        return cls(type_, id_, tuple(sorted(attrs.items())))

    def to_json(self) -> dict[str, Any]:
        return {"attrs": dict(self.attrs), "id": self.id, "type": self.type}

    @classmethod
    def from_json(cls, obj: Any) -> "EntityRecord":
        obj = _exact_keys(obj, ("attrs", "id", "type"), "entity")
        if type(obj["attrs"]) is not dict:
            raise ValueError("entity attrs must be an object")
        return cls.build(obj["type"], obj["id"], obj["attrs"])

    def to_cedar(self) -> dict[str, Any]:
        return {"uid": {"type": self.type, "id": self.id}, "attrs": dict(self.attrs), "parents": []}


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Every stateful fact the decision reads, captured by the shell at one ledger position.

    Canonical by construction: labels, approvals and entities must already be sorted and unique.
    Use Snapshot.build() to normalise."""

    session_id: str
    ledger_seq: int
    labels: tuple[str, ...]
    refunded_minor: int
    approvals: tuple[str, ...]
    entities: tuple[EntityRecord, ...]

    def __post_init__(self) -> None:
        if not matches(ID_RE, self.session_id):
            raise ValueError("session_id is not a canonical id")
        if not _safe_nonnegative(self.ledger_seq) or not _safe_nonnegative(self.refunded_minor):
            raise ValueError("ledger_seq and refunded_minor must be non-negative safe integers")
        if type(self.labels) is not tuple or not all(matches(NAME_RE, x) for x in self.labels):
            raise ValueError("labels must be a tuple of canonical names")
        if type(self.approvals) is not tuple or not all(matches(HASH_RE, x) for x in self.approvals):
            raise ValueError("approvals must be a tuple of action hashes")
        if type(self.entities) is not tuple or not all(type(e) is EntityRecord for e in self.entities):
            raise ValueError("entities must be a tuple of EntityRecord")
        keys = [(e.type, e.id) for e in self.entities]
        if not (_strictly_sorted(self.labels) and _strictly_sorted(self.approvals) and _strictly_sorted(keys)):
            raise ValueError("labels, approvals and entities must be sorted and unique (use Snapshot.build)")

    @classmethod
    def build(
        cls,
        *,
        session_id: str,
        ledger_seq: int = 0,
        labels: tuple[str, ...] | list[str] = (),
        refunded_minor: int = 0,
        approvals: tuple[str, ...] | list[str] = (),
        entities: tuple[EntityRecord, ...] | list[EntityRecord] = (),
    ) -> "Snapshot":
        return cls(
            session_id=session_id,
            ledger_seq=ledger_seq,
            labels=tuple(sorted(set(labels))),
            refunded_minor=refunded_minor,
            approvals=tuple(sorted(set(approvals))),
            entities=tuple(sorted(entities, key=lambda e: (e.type, e.id))),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "approvals": list(self.approvals),
            "entities": [e.to_json() for e in self.entities],
            "labels": list(self.labels),
            "ledger_seq": self.ledger_seq,
            "refunded_minor": self.refunded_minor,
            "session_id": self.session_id,
        }

    @classmethod
    def from_json(cls, obj: Any) -> "Snapshot":
        obj = _exact_keys(obj, ("approvals", "entities", "labels", "ledger_seq", "refunded_minor", "session_id"), "snapshot")
        for key in ("approvals", "entities", "labels"):
            if type(obj[key]) is not list:
                raise ValueError(f"snapshot.{key} must be a list")
        return cls(
            session_id=obj["session_id"],
            ledger_seq=obj["ledger_seq"],
            labels=tuple(obj["labels"]),
            refunded_minor=obj["refunded_minor"],
            approvals=tuple(obj["approvals"]),
            entities=tuple(EntityRecord.from_json(e) for e in obj["entities"]),
        )

    def digest(self) -> str:
        return digest("dag/snapshot/v1", self.to_json())


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: str
    reasons: tuple[str, ...]
    action_hash: str | None
    input_hash: str
    snapshot_hash: str
    policy_hash: str
    gate: dict[str, Any]
    decision_hash: str

    def to_json(self) -> dict[str, Any]:
        return {
            "action_hash": self.action_hash,
            "decision_hash": self.decision_hash,
            "gate": dict(self.gate),
            "input_hash": self.input_hash,
            "policy_hash": self.policy_hash,
            "reasons": list(self.reasons),
            "snapshot_hash": self.snapshot_hash,
            "verdict": self.verdict,
        }
