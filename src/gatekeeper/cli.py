"""gatekeeper: demo | replay | decide | bench | schema"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from .core import Envelope, Snapshot, decide
from .core.strictjson import loads_strict
from .shell import load_bundle, read_log, replay
from .shell.demo import run_demo
from .shell.log import DecisionLog
from .shell.gate import Gate

DEFAULT_BUNDLE = "policies/bank-servicing"


def _print_replay(report) -> int:
    status = "PASS" if report.ok else "FAIL"
    print(f"replay {status}: {report.exact}/{report.records} decisions re-derived hash-exact; "
          f"chain {'intact' if not report.chain_problems else 'BROKEN'}")
    if report.policy_mismatch:
        print(f"  {report.policy_mismatch} records were decided under a different policy bundle (use diff, phase 5)")
    if report.gate_mismatch:
        print(f"  {report.gate_mismatch} records were decided by a different gate identity")
    for problem in report.chain_problems[:5] + report.mismatches[:5]:
        print(f"  {problem}")
    return 0 if report.ok else 1


def cmd_demo(args: argparse.Namespace) -> int:
    bundle = load_bundle(args.bundle)
    log_path = Path(args.log)
    log_path.unlink(missing_ok=True)
    steps = run_demo(bundle, log_path)
    print(f"policy {bundle.policy_hash[:19]}...  engine {bundle.engine}\n")
    print(f" #  {'step':<46} {'verdict':<17} reasons")
    for number, (label, decision) in enumerate(steps, 1):
        print(f"{number:>2}  {label:<46} {decision.verdict:<17} {', '.join(decision.reasons)}")
    print(f"\nlog: {log_path}")
    return _print_replay(replay(list(read_log(log_path)), bundle))


def cmd_replay(args: argparse.Namespace) -> int:
    return _print_replay(replay(list(read_log(args.log)), load_bundle(args.bundle)))


def cmd_decide(args: argparse.Namespace) -> int:
    bundle = load_bundle(args.bundle)
    snapshot = Snapshot.from_json(loads_strict(Path(args.snapshot).read_text(encoding="utf-8"), max_bytes=1 << 20))
    gate = Gate(bundle, DecisionLog(args.log) if args.log else None)
    decision = gate.submit(tool=args.tool, arguments=args.args, principal=args.principal,
                           session_id=snapshot.session_id, snapshot=snapshot)
    print(json.dumps(decision.to_json(), indent=2, sort_keys=True))
    return 0 if decision.verdict == "ALLOW" else 2


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
    parser = argparse.ArgumentParser(prog="gatekeeper", description="Deterministic Agent Gatekeeper (phase 1)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo", help="run the scripted walkthrough, then replay its log")
    p.add_argument("--bundle", default=DEFAULT_BUNDLE)
    p.add_argument("--log", default=".out/demo.jsonl")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("replay", help="re-derive every decision in a log, hash-exact")
    p.add_argument("log")
    p.add_argument("--bundle", default=DEFAULT_BUNDLE)
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("decide", help="decide one proposal; exit 0 on ALLOW, 2 otherwise")
    p.add_argument("--tool", required=True)
    p.add_argument("--args", required=True, help="raw JSON arguments exactly as the agent sent them")
    p.add_argument("--snapshot", required=True, help="path to a snapshot JSON file")
    p.add_argument("--principal", default="support-bot")
    p.add_argument("--bundle", default=DEFAULT_BUNDLE)
    p.add_argument("--log")
    p.set_defaults(func=cmd_decide)

    p = sub.add_parser("bench", help="latency of decide() over the golden corpus")
    p.add_argument("--bundle", default=DEFAULT_BUNDLE)
    p.add_argument("--vectors", default="spec/vectors/golden.jsonl")
    p.add_argument("--rounds", type=int, default=20)
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("schema", help="print the Cedar schema generated from the manifest")
    p.add_argument("--bundle", default=DEFAULT_BUNDLE)
    p.set_defaults(func=cmd_schema)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
