"""One writer per session.

The lock spans reading the budget, deciding, and reserving against it. A budget read that happens
outside the write is a race by construction: a hundred concurrent refunds would each see an empty
budget and every one of them would pass."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..core import Event, LedgerState, PolicyBundle, apply, fold
from .log import EventLog, events_of


class Session:
    def __init__(self, ledger_path: str | Path, session_id: str, bundle: PolicyBundle) -> None:
        self.session_id = session_id
        self._counters = tuple(sorted(bundle.manifest.counters))
        self._lock = threading.RLock()
        self._log = EventLog(ledger_path)
        self._state = fold(session_id, self._counters, events_of(self._log.records))

    @contextmanager
    def transaction(self) -> Iterator["Session"]:
        with self._lock:
            yield self

    @property
    def state(self) -> LedgerState:
        with self._lock:
            return self._state

    def append(self, kind: str, body: dict[str, Any]) -> Event:
        with self._lock:
            event = Event(self._log.seq, kind, body)
            # Fold first: an event the ledger would refuse never reaches the file.
            self._state = apply(self._state, event, self._counters)
            self._log.append(event)
            return event


class SessionStore:
    """Sessions are files; this keeps one writer object per session id in this process."""

    def __init__(self, directory: str | Path, bundle: PolicyBundle) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._bundle = bundle
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def path_for(self, session_id: str) -> Path:
        return self.directory / f"{session_id}.jsonl"

    def open(self, session_id: str, principal: str) -> Session:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = Session(self.path_for(session_id), session_id, self._bundle)
                self._sessions[session_id] = session
        if session.state.principal is None:
            session.append("session_opened", {"principal": principal, "session_id": session_id})
        return session
