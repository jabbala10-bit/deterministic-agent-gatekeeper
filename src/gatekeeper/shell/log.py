"""Append-only, hash-chained decision log. Each line is the RFC 8785 form of one record, so any
implementation in any language can recompute every hash from the bytes on disk.

Phase 1 chains records; phase 4 adds Ed25519 signatures (with the decision tokens), which is
what stops a forger who rewrites inputs, decisions and the whole chain consistently."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

from ..core import Decision, Envelope, Snapshot
from ..core.digest import digest
from ..core.strictjson import jcs, loads_strict

GENESIS = "sha256:" + "0" * 64
_BODY_KEYS = ("decision", "envelope", "prev", "seq", "snapshot")


def seal(seq: int, prev: str, envelope: dict[str, Any], snapshot: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    body = {"decision": decision, "envelope": envelope, "prev": prev, "seq": seq, "snapshot": snapshot}
    return {**body, "record_hash": digest("dag/record/v1", body)}


def verify_chain(records: list[dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    prev = GENESIS
    for index, record in enumerate(records):
        try:
            body = {key: record[key] for key in _BODY_KEYS}
            recomputed = digest("dag/record/v1", body)
        except Exception:
            problems.append(f"record {index}: malformed")
            prev = None
            continue
        if record["seq"] != index:
            problems.append(f"record {index}: sequence gap")
        if record["prev"] != prev:
            problems.append(f"record {index}: broken link to previous record")
        if record.get("record_hash") != recomputed:
            problems.append(f"record {index}: record hash does not match contents")
        prev = record.get("record_hash")
    return problems


def read_log(path: str | Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield loads_strict(line, max_bytes=4 << 20)


class DecisionLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev = 0, GENESIS
        if self.path.exists():
            records = list(read_log(self.path))
            problems = verify_chain(records)
            if problems:
                raise ValueError(f"refusing to append to a broken chain: {problems[0]}")
            if records:
                self._seq, self._prev = records[-1]["seq"] + 1, records[-1]["record_hash"]

    def append(self, envelope: Envelope, snapshot: Snapshot, decision: Decision) -> dict[str, Any]:
        record = seal(self._seq, self._prev, envelope.to_json(), snapshot.to_json(), decision.to_json())
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(jcs(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._seq, self._prev = self._seq + 1, record["record_hash"]
        return record
