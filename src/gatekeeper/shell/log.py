"""Append-only, hash-chained event log. Each line is the RFC 8785 form of one sealed event, so any
implementation in any language can recompute every hash from the bytes on disk. Newlines are written
as LF on every platform, so a log is byte-identical wherever it was produced.

Each event is also signed with the gate's Ed25519 key. The chain alone only proves internal
consistency: a forger with write access can rewrite an event, recompute the decisions and re-seal
every hash. The signature is what they cannot produce."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

from ..core import Event
from ..core.digest import digest
from ..core.strictjson import jcs, loads_strict
from .tokens import SIGNATURE_DOMAIN, KeyRing, Verifier, b64, unb64

GENESIS = "sha256:" + "0" * 64
_BODY_KEYS = ("body", "kind", "prev", "seq")


def seal(event: Event, prev: str, keyring: KeyRing | None = None) -> dict[str, Any]:
    body = {"body": dict(event.body), "kind": event.kind, "prev": prev, "seq": event.seq}
    record_hash = digest("dag/event/v1", body)
    sealed = {**body, "record_hash": record_hash}
    if keyring is not None:
        sealed["signature"] = b64(keyring.sign(SIGNATURE_DOMAIN + record_hash.encode("ascii")))
    return sealed


def verify_chain(records: list[dict[str, Any]], verifier: Verifier | None = None) -> list[str]:
    """Chain integrity, and signatures too when a public key is supplied."""
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
        if verifier is not None:
            signature = record.get("signature")
            if not isinstance(signature, str):
                problems.append(f"event {index}: unsigned")
            elif not verifier.verify_bytes(unb64(signature), SIGNATURE_DOMAIN + recomputed.encode("ascii")):
                problems.append(f"event {index}: signature does not verify")
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

    def __init__(self, path: str | Path, keyring: KeyRing | None = None) -> None:
        self.keyring = keyring
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
        record = seal(event, self._prev, self.keyring)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(jcs(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.records.append(record)
        self._prev = record["record_hash"]
        return record
