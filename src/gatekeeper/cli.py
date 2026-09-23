"""gatekeeper: demo | replay | state | submit | approve | settle | bench | schema"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from .core import EntityRecord, Envelope, Snapshot, decide
from .core.ledger import fold
from .core.strictjson import loads_strict
from .shell import Gate, McpProxy, UpstreamServer, events_of, load_bundle, read_log, replay
from .shell.demo import run_demo
from .shell.tokens import KeyRing

DEFAULT_BUNDLE = "policies/bank-servicing"
DEFAULT_SESSIONS = ".out/sessions"


def _facts(path: str | None) -> tuple[EntityRecord, ...]:
    if not path:
        return ()
    raw = loads_strict(Path(path).read_text(encoding="utf-8"), max_bytes=1 << 20)
    return tuple(EntityRecord.from_json(entry) for entry in raw)


def _print_replay(report) -> int:
    status = "PASS" if report.ok else "FAIL"
    print(f"replay {status}: {report.exact}/{report.decisions} decisions re-derived hash-exact, "
          f"{report.snapshots_derived}/{report.decisions} snapshots re-derived from the ledger; "
          f"chain {'intact' if not report.chain_problems else 'BROKEN'} over {report.records} events")
    if report.policy_mismatch:
        print(f"  {report.policy_mismatch} decisions were made under a different policy bundle (use diff, phase 5)")
    if report.gate_mismatch:
        print(f"  {report.gate_mismatch} decisions were made by a different gate identity")
    for problem in (report.chain_problems[:5] + report.ledger_problems[:5] + report.mismatches[:5]):
        print(f"  {problem}")
    return 0 if report.ok else 1


def cmd_demo(args: argparse.Namespace) -> int:
    bundle = load_bundle(args.bundle)
    directory = Path(args.sessions)
    for stale in directory.glob("*.jsonl"):
        stale.unlink()
    steps, path = run_demo(bundle, directory)
    print(f"policy {bundle.policy_hash[:19]}...  engine {bundle.engine}\n")
    print(f" #  {'step':<56} {'verdict':<17} reasons")
    for number, (label, decision) in enumerate(steps, 1):
        print(f"{number:>2}  {label:<56} {decision.verdict:<17} {', '.join(decision.reasons)}")
    records = list(read_log(path))
    state = fold(args.session, tuple(sorted(bundle.manifest.counters)), events_of(records))
    print(f"\nsession {args.session}: {state.seq} events, labels {list(state.labels) or 'none'}, "
          f"counters {state.counters()}")
    print(f"ledger: {path}")
    return _print_replay(replay(records, bundle, args.session))


def _verifier(args: argparse.Namespace):
    key = Path(getattr(args, "key", None) or Path(args.sessions) / "gate-key.pem")
    return KeyRing.load_or_create(key).verifier if key.exists() else None


def cmd_replay(args: argparse.Namespace) -> int:
    verifier = _verifier(args)
    if verifier is None:
        print("note: no gate key found, so signatures are not checked")
    return _print_replay(replay(list(read_log(args.ledger)), load_bundle(args.bundle), args.session, verifier))


def cmd_proxy(args: argparse.Namespace) -> int:
    """Sit between an MCP client and an unmodified MCP server, enforcing the gate on tools/call."""
    upstream_command = [part for part in args.upstream if part != "--"]
    if not upstream_command:
        print("give the upstream server command after --", file=sys.stderr)
        return 2
    gate = Gate(load_bundle(args.bundle), args.sessions)
    upstream = UpstreamServer(upstream_command)
    proxy = McpProxy(gate, upstream, session_id=args.session, principal=args.principal)
    try:
        proxy.serve(sys.stdin, sys.stdout)
    finally:
        upstream.close()
    return 0


def cmd_pending(args: argparse.Namespace) -> int:
    pending = Gate(load_bundle(args.bundle), args.sessions).pending(args.session)
    print(json.dumps(pending, indent=2, sort_keys=True))
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    released = Gate(load_bundle(args.bundle), args.sessions).sweep(args.session)
    print(f"released {len(released)} expired reservation(s): {released}")
    return 0


def cmd_state(args: argparse.Namespace) -> int:
    bundle = load_bundle(args.bundle)
    records = list(read_log(args.ledger))
    state = fold(args.session, tuple(sorted(bundle.manifest.counters)), events_of(records))
    print(json.dumps({"approvals": list(state.approvals), "counters": state.counters(),
                      "labels": list(state.labels), "principal": state.principal,
                      "reserved": [{"action_hash": a, "counters": dict(d), "reservation": r} for r, a, d in state.reserved],
                      "seq": state.seq, "session_id": state.session_id}, indent=2, sort_keys=True))
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    gate = Gate(load_bundle(args.bundle), args.sessions)
    ticket = gate.submit(session_id=args.session, principal=args.principal, tool=args.tool,
                         arguments=args.args, facts=_facts(args.facts))
    print(json.dumps({"decision": ticket.decision.to_json(), "reservation": ticket.reservation},
                     indent=2, sort_keys=True))
    return 0 if ticket.verdict == "ALLOW" else 2


def cmd_approve(args: argparse.Namespace) -> int:
    Gate(load_bundle(args.bundle), args.sessions).approve(
        session_id=args.session, action_hash=args.action_hash, approver=args.approver)
    print(f"approved {args.action_hash} in {args.session}")
    return 0


def cmd_settle(args: argparse.Namespace) -> int:
    Gate(load_bundle(args.bundle), args.sessions).settle(
        session_id=args.session, reservation=args.reservation, outcome=args.outcome)
    print(f"reservation {args.reservation} {args.outcome}")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    bundle = load_bundle(args.bundle)
    cases = [(Envelope.from_json(v["envelope"]), Snapshot.from_json(v["snapshot"]))
             for v in (loads_strict(line, max_bytes=1 << 20)
                       for line in Path(args.vectors).read_text(encoding="utf-8").splitlines())]
    samples = []
    for _ in range(args.rounds):
        for envelope, snapshot in cases:
            start = time.perf_counter_ns()
            decide(envelope, snapshot, bundle)
            samples.append(time.perf_counter_ns() - start)
    samples.sort()
    pick = lambda q: samples[min(len(samples) - 1, int(q * len(samples)))] / 1000
    print(f"decide() over {len(cases)} golden vectors x {args.rounds} rounds = {len(samples)} calls")
    print(f"  p50 {pick(0.50):.0f} us   p99 {pick(0.99):.0f} us   mean {statistics.fmean(samples) / 1000:.0f} us")
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    print(json.dumps(load_bundle(args.bundle).manifest.cedar_schema(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gatekeeper", description="Deterministic Agent Gatekeeper (phase 3)")
    parser.add_argument("--bundle", default=DEFAULT_BUNDLE)
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, help_text: str, func):
        child = sub.add_parser(name, help=help_text)
        child.add_argument("--bundle", default=DEFAULT_BUNDLE)
        child.set_defaults(func=func)
        return child

    child = add("demo", "run the scripted walkthrough, then replay its ledger", cmd_demo)
    child.add_argument("--sessions", default=DEFAULT_SESSIONS)
    child.add_argument("--session", default="sess-demo-001")

    child = add("replay", "re-derive every decision and snapshot in a session ledger", cmd_replay)
    child.add_argument("ledger")
    child.add_argument("--session", required=True)
    child.add_argument("--sessions", default=DEFAULT_SESSIONS)
    child.add_argument("--key", help="gate public key file; signatures are checked when it is found")

    child = add("proxy", "enforce the gate in front of an unmodified MCP server", cmd_proxy)
    child.add_argument("--session", required=True)
    child.add_argument("--principal", default="support-bot")
    child.add_argument("--sessions", default=DEFAULT_SESSIONS)
    child.add_argument("upstream", nargs=argparse.REMAINDER, help="-- command to run the MCP server")

    child = add("pending", "list decisions waiting on a human", cmd_pending)
    child.add_argument("--session", required=True)
    child.add_argument("--sessions", default=DEFAULT_SESSIONS)

    child = add("sweep", "release reservations whose token has expired", cmd_sweep)
    child.add_argument("--session", required=True)
    child.add_argument("--sessions", default=DEFAULT_SESSIONS)

    child = add("state", "print the state folded from a session ledger", cmd_state)
    child.add_argument("ledger")
    child.add_argument("--session", required=True)

    child = add("submit", "submit one proposal; exit 0 on ALLOW, 2 otherwise", cmd_submit)
    child.add_argument("--session", required=True)
    child.add_argument("--principal", default="support-bot")
    child.add_argument("--tool", required=True)
    child.add_argument("--args", required=True, help="raw JSON arguments exactly as the agent sent them")
    child.add_argument("--facts", help="path to a JSON list of entity records the shell loaded")
    child.add_argument("--sessions", default=DEFAULT_SESSIONS)

    child = add("approve", "grant a single-use approval bound to an action hash", cmd_approve)
    child.add_argument("--session", required=True)
    child.add_argument("--action-hash", required=True)
    child.add_argument("--approver", default="duty-officer")
    child.add_argument("--sessions", default=DEFAULT_SESSIONS)

    child = add("settle", "commit or release a reservation once the tool has run", cmd_settle)
    child.add_argument("--session", required=True)
    child.add_argument("--reservation", type=int, required=True)
    child.add_argument("--outcome", choices=("committed", "released"), required=True)
    child.add_argument("--sessions", default=DEFAULT_SESSIONS)

    child = add("bench", "latency of decide() over the golden corpus", cmd_bench)
    child.add_argument("--vectors", default="spec/vectors/golden.jsonl")
    child.add_argument("--rounds", type=int, default=20)

    add("schema", "print the Cedar schema generated from the manifest", cmd_schema)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
