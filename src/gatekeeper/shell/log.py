"""Append-only, hash-chained event log. Each line is the RFC 8785 form of one sealed event, so any
implementation in any language can recompute every hash from the bytes on disk. Newlines are written
as LF on every platform, so a log is byte-identical wherever it was produced.

Phase 3 chains events; phase 4 adds Ed25519 signatures (with the decision tokens), which is what
stops a forger who rewrites inputs, recomputes the decisions and re-seals the whole chain."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

from ..core import Event
from ..core.digest import digest
from ..core.strictjson import jcs, loads_strict

GENESIS = "sha256:" + "0" * 64
_BODY_KEYS = ("body", "kind", "prev", "seq")


def seal(event: Event, prev: str) -> dict[str, Any]:
    body = {"body": dict(event.body), "kind": event.kind, "prev": prev, "seq": event.seq}
    return {**body, "record_hash": digest("dag/event/v1", body)}


def verify_chain(records: list[dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    prev = GENESIS
    for index, record in enumerate(records):
        try:
            body = {key: record[key] for key in _BODY_KEYS}
            recomputed = digest("dag/event/v1", body)
        except Exception:
            problems.append(f"event {index}: malformed")
            prev = None
            continue
        if record["seq"] != index:
            problems.append(f"event {index}: sequence gap")
        if record["prev"] != prev:
            problems.append(f"event {index}: broken link to previous event")
        if record.get("record_hash") != recomputed:
            problems.append(f"event {index}: record hash does not match contents")
        prev = record.get("record_hash")
    return problems


def read_log(path: str | Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield loads_strict(line, max_bytes=4 << 20)


def events_of(records: list[dict[str, Any]]) -> list[Event]:
    return [Event(record["seq"], record["kind"], record["body"]) for record in records]


class EventLog:
    """One file, one chain. Callers hold the session lock; this class only appends."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.records: list[dict[str, Any]] = []
        self._prev = GENESIS
        if self.path.exists():
            self.records = list(read_log(self.path))
            problems = verify_chain(self.records)
            if problems:
                raise ValueError(f"refusing to append to a broken chain: {problems[0]}")
            if self.records:
                self._prev = self.records[-1]["record_hash"]

    @property
    def seq(self) -> int:
        return len(self.records)

    def append(self, event: Event) -> dict[str, Any]:
        record = seal(event, self._prev)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(jcs(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.records.append(record)
        self._prev = record["record_hash"]
        return record
