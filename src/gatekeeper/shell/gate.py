from __future__ import annotations

import time
from typing import Callable

from ..core import Decision, Envelope, PolicyBundle, Snapshot, decide
from .log import DecisionLog


class Gate:
    """Reads the clock once per request, calls the pure core, appends the record.

    The ledger that produces snapshots arrives in phase 3; until then callers pass them in."""

    def __init__(self, bundle: PolicyBundle, log: DecisionLog | None = None,
                 clock_ns: Callable[[], int] = time.time_ns) -> None:
        self._bundle = bundle
        self._log = log
        self._clock_ns = clock_ns

    def submit(self, *, tool: str, arguments: str, principal: str, session_id: str, snapshot: Snapshot) -> Decision:
        envelope = Envelope(tool=tool, arguments=arguments, principal=principal, session_id=session_id,
                            t_ms=self._clock_ns() // 1_000_000)
        decision = decide(envelope, snapshot, self._bundle)
        if self._log is not None:
            self._log.append(envelope, snapshot, decision)
        return decision
