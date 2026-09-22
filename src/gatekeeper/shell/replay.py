"""Replay: re-derive every recorded decision from its recorded inputs and compare byte for byte."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core import Envelope, PolicyBundle, Snapshot, decide
from .log import verify_chain


@dataclass
class ReplayReport:
    records: int = 0
    exact: int = 0
    chain_problems: list[str] = field(default_factory=list)
    policy_mismatch: int = 0
    gate_mismatch: int = 0
    mismatches: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.records > 0 and self.exact == self.records and not self.chain_problems and not self.mismatches


def replay(records: list[dict[str, Any]], bundle: PolicyBundle) -> ReplayReport:
    report = ReplayReport(records=len(records), chain_problems=verify_chain(records))
    for index, record in enumerate(records):
        try:
            envelope = Envelope.from_json(record["envelope"])
            snapshot = Snapshot.from_json(record["snapshot"])
            recorded = record["decision"]
        except (KeyError, TypeError, ValueError) as err:
            report.mismatches.append(f"record {index}: unreadable ({type(err).__name__})")
            continue
        if recorded.get("policy_hash") != bundle.policy_hash:
            # Different policy: that is a diff (phase 5), not a replay.
            report.policy_mismatch += 1
            continue
        fresh = decide(envelope, snapshot, bundle).to_json()
        if fresh == recorded:
            report.exact += 1
        elif fresh["gate"] != recorded.get("gate"):
            report.gate_mismatch += 1
        else:
            report.mismatches.append(
                f"record {index}: recorded {recorded.get('verdict')} {recorded.get('reasons')}, "
                f"re-derived {fresh['verdict']} {fresh['reasons']}")
    return report
