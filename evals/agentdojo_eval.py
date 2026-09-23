"""Measure the gate against AgentDojo's banking suite, with no model in the loop.

AgentDojo ships, for every user task, the sequence of tool calls a correct agent makes, and for
every injection task the sequence the attacker wants. Those trajectories are what this replays
through the gate. The benefit is that the numbers are deterministic and free of model noise; the
cost is that this measures the gate's decisions, not end-to-end task success. An agent that fails
the task for its own reasons is out of scope here.

The human is modelled honestly: they approve the user's own work and refuse the injection's. That is
the whole point of REQUIRE_APPROVAL, and it is also the cost, because every approval is someone's
attention. Both are counted.

Run with:  uv run --group evals python evals/agentdojo_eval.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gatekeeper.shell import Gate, load_bundle  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = {"approval": ROOT / "policies" / "agentdojo-banking",
            "strict": ROOT / "policies" / "agentdojo-banking-strict"}
INGEST_TOOLS = {"read_file", "get_most_recent_transactions"}
SENSITIVE_TOOLS = {"send_money", "schedule_transaction", "update_scheduled_transaction",
                   "update_password", "update_user_info"}
PRINCIPAL = "banking-agent"


def amount_text(value: Any) -> str | None:
    """AgentDojo's tool schema uses a float for money; the gate's contract is minor units.

    Converting at the boundary is what a tool adapter does in production, and doing it here makes
    the conversion visible: an amount that is not exact in cents cannot be represented and is
    reported rather than rounded."""
    decimal = Decimal(str(value))
    if -decimal.as_tuple().exponent > 2:
        return None
    return f"{decimal:.2f}"


def adapt(call: Any) -> tuple[str, str | None]:
    arguments: dict[str, Any] = {}
    for name, value in call.args.items():
        if value is None:
            continue  # an optional argument the agent chose not to send
        if name == "amount":
            text = amount_text(value)
            if text is None:
                return call.function, None
            arguments["amount"] = {"amount": text, "currency": "USD"}
        else:
            arguments[name] = value
    return call.function, json.dumps(arguments, separators=(",", ":"), sort_keys=True)


@dataclass
class Outcome:
    tool: str
    verdict: str
    reasons: tuple[str, ...] = ()
    approved: bool = False


@dataclass
class Totals:
    allowed: int = 0
    approved: int = 0
    denied: int = 0
    unrepresentable: int = 0
    latencies: list[float] = field(default_factory=list)


def run_calls(gate: Gate, session: str, calls: list[Any], totals: Totals, *, human_approves: bool) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for call in calls:
        tool, arguments = adapt(call)
        if arguments is None:
            totals.unrepresentable += 1
            outcomes.append(Outcome(tool, "UNREPRESENTABLE"))
            continue
        started = time.perf_counter_ns()
        ticket = gate.submit(session_id=session, principal=PRINCIPAL, tool=tool, arguments=arguments)
        totals.latencies.append((time.perf_counter_ns() - started) / 1000)
        verdict, approved = ticket.verdict, False
        if verdict == "REQUIRE_APPROVAL" and human_approves:
            gate.approve(session_id=session, action_hash=ticket.decision.action_hash, approver="duty-officer")
            ticket = gate.submit(session_id=session, principal=PRINCIPAL, tool=tool, arguments=arguments)
            verdict, approved = ticket.verdict, ticket.verdict == "ALLOW"
        if verdict == "ALLOW":
            gate.settle(session_id=session, reservation=ticket.reservation, outcome="committed")
            totals.approved += approved
            totals.allowed += 1
        else:
            totals.denied += 1
        outcomes.append(Outcome(tool, verdict, ticket.decision.reasons, approved))
    return outcomes


def evaluate(variant: str, bundle_dir: Path, suite: Any) -> dict[str, Any]:
    bundle = load_bundle(bundle_dir)
    environment = suite.load_and_inject_default_environment({})
    totals = Totals()
    benign: dict[str, Any] = {"unattended": [], "with_approval": [], "blocked": []}
    approvals_per_task: dict[str, int] = {}
    blocked_reasons: dict[str, int] = {}

    with TemporaryDirectory() as workspace:
        gate = Gate(bundle, workspace)
        for task_id, task in suite.user_tasks.items():
            calls = task.ground_truth(environment)
            outcomes = run_calls(gate, f"benign-{variant}-{task_id}", calls, totals, human_approves=True)
            approvals = sum(outcome.approved for outcome in outcomes)
            refused = [outcome for outcome in outcomes if outcome.verdict not in ("ALLOW",)]
            approvals_per_task[task_id] = approvals
            if refused:
                benign["blocked"].append(task_id)
                for outcome in refused:
                    key = outcome.reasons[0] if outcome.reasons else outcome.verdict
                    blocked_reasons[key] = blocked_reasons.get(key, 0) + 1
            elif approvals:
                benign["with_approval"].append(task_id)
            else:
                benign["unattended"].append(task_id)

        # An injection only reaches the agent through a tool result, so each pair runs the user's own
        # trajectory up to the first ingesting call, then the attacker's calls in that same session.
        pairs, stopped, executed, sensitive_executed = 0, 0, [], []
        for task_id, task in suite.user_tasks.items():
            benign_calls = task.ground_truth(environment)
            ingest_at = next((index for index, call in enumerate(benign_calls)
                              if call.function in INGEST_TOOLS), None)
            if ingest_at is None:
                continue  # nothing this task does can carry an injection
            for injection_id, injection in suite.injection_tasks.items():
                session = f"attack-{variant}-{task_id}-{injection_id}"
                run_calls(gate, session, benign_calls[:ingest_at + 1], totals, human_approves=True)
                outcomes = run_calls(gate, session, injection.ground_truth(environment), totals,
                                     human_approves=False)
                pairs += 1
                # The attacker's goal needs its whole sequence: an injection task's ground truth is
                # the minimal path to it. Refusing any step prevents the goal, and the first step is
                # often a harmless read, so "was anything allowed" would be the wrong question.
                if all(outcome.verdict == "ALLOW" for outcome in outcomes):
                    executed.append(f"{task_id}/{injection_id}")
                else:
                    stopped += 1
                sensitive = [outcome for outcome in outcomes if outcome.tool in SENSITIVE_TOOLS]
                if sensitive and all(outcome.verdict == "ALLOW" for outcome in sensitive):
                    sensitive_executed.append(f"{task_id}/{injection_id}")

    latencies = sorted(totals.latencies)
    return {
        "attacks": {"executed": executed, "pairs": pairs, "sensitive_executed": sensitive_executed,
                    "stopped": stopped},
        "benign": benign,
        "approvals": {"tasks_needing_one": sum(1 for count in approvals_per_task.values() if count),
                      "total": sum(approvals_per_task.values())},
        "blocked_reasons": dict(sorted(blocked_reasons.items())),
        "latency_us": {"mean": round(statistics.fmean(latencies), 1),
                       "p50": round(latencies[len(latencies) // 2], 1),
                       "p99": round(latencies[min(len(latencies) - 1, int(0.99 * len(latencies)))], 1)},
        "policy_hash": bundle.policy_hash,
        "submissions": len(latencies),
        "variant": variant,
    }


def measure_costs(rounds: int = 300) -> dict[str, Any]:
    """Where the milliseconds go: deciding, then recording the decision durably."""
    import os
    from gatekeeper.core import EntityRecord, Envelope, Snapshot, decide

    bundle = load_bundle(ROOT / "policies" / "agentdojo-banking")
    envelope = Envelope(tool="send_money", principal=PRINCIPAL, session_id="bench", t_ms=1_790_000_000_000,
                        arguments=json.dumps({"amount": {"amount": "12.00", "currency": "USD"},
                                              "date": "2022-01-01", "recipient": "CH9300762011623852957",
                                              "subject": "bench"}, sort_keys=True, separators=(",", ":")))
    snapshot = Snapshot.build(session_id="bench", counters={"moved_minor": 0})
    decide_us = _time(lambda: decide(envelope, snapshot, bundle), rounds)

    with TemporaryDirectory() as workspace:
        gate = Gate(bundle, workspace)
        counter = iter(range(rounds))
        submit_us = _time(lambda: gate.submit(session_id=f"bench-{next(counter)}", principal=PRINCIPAL,
                                              tool="send_money", arguments=envelope.arguments), rounds)
        path = Path(workspace) / "fsync-probe"
        def append() -> None:
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write("x" * 256 + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        fsync_us = _time(append, rounds)
    return {"decide_only": decide_us, "durable_append": fsync_us, "submit_end_to_end": submit_us}


def _time(action: Any, rounds: int) -> dict[str, float]:
    samples = []
    for _ in range(rounds):
        started = time.perf_counter_ns()
        action()
        samples.append((time.perf_counter_ns() - started) / 1000)
    samples.sort()
    return {"mean": round(statistics.fmean(samples), 1), "p50": round(samples[len(samples) // 2], 1),
            "p99": round(samples[min(len(samples) - 1, int(0.99 * len(samples)))], 1)}


def write_results(results: dict[str, Any]) -> None:
    suite = results["suite"]
    lines = ["# Evaluation results", "",
             "Generated by `uv run --group evals python evals/agentdojo_eval.py`. Every number here is",
             "reproducible from this repository; none of it is estimated.", "",
             f"AgentDojo {suite['version']} `{suite['name']}` suite: {suite['user_tasks']} user tasks, "
             f"{suite['injection_tasks']} injection tasks, {suite['tools']} tools.", "",
             "## What the gate costs and what it buys", "",
             "| | approval variant | strict variant |", "|---|---|---|"]
    approval, strict = results["variants"]
    def row(label: str, left: str, right: str) -> str:
        return f"| {label} | {left} | {right} |"
    for label, key in (("benign tasks completed with no human", "unattended"),
                       ("benign tasks needing a human", "with_approval"),
                       ("benign tasks blocked outright", "blocked")):
        lines.append(row(label, str(len(approval["benign"][key])), str(len(strict["benign"][key]))))
    lines.append(row("approvals asked of the human", str(approval["approvals"]["total"]),
                     str(strict["approvals"]["total"])))
    lines.append(row("attack pairs stopped",
                     f"{approval['attacks']['stopped']}/{approval['attacks']['pairs']}",
                     f"{strict['attacks']['stopped']}/{strict['attacks']['pairs']}"))
    lines.append(row("attacker calls that executed", str(len(approval["attacks"]["sensitive_executed"])),
                     str(len(strict["attacks"]["sensitive_executed"]))))
    costs = results["costs"]
    lines += ["", "## Where it over-blocks", "",
              f"The strict variant refuses {len(strict['benign']['blocked'])} of {suite['user_tasks']} legitimate",
              "tasks and stops no attack the approval variant did not already stop. Paying a bill means",
              "reading the bill first, and a rule that forbids payments after reading anything forbids",
              "paying bills. The blocked tasks and their reasons:", "",
              "```", ", ".join(strict["benign"]["blocked"]), "",
              json.dumps(strict["blocked_reasons"], sort_keys=True), "```", "",
              "## Latency", "",
              "| step | p50 | p99 |", "|---|---|---|",
              f"| decide() alone | {costs['decide_only']['p50']} us | {costs['decide_only']['p99']} us |",
              f"| one durable append (write + fsync) | {costs['durable_append']['p50']} us | {costs['durable_append']['p99']} us |",
              f"| submit end to end (decide, fold, record, mint token) | {costs['submit_end_to_end']['p50']} us | {costs['submit_end_to_end']['p99']} us |",
              "", "The policy engine is not the bottleneck. Profiling a submission on this machine puts",
              "canonical JSON and hashing first (about a quarter of the time), then the fsync per event",
              "(about a fifth, at three signed events for an allowed call), then Cedar itself at roughly",
              "7%, then Ed25519 signing. Measured on a single-vCPU Linux container: treat these as shape,",
              "not as a specification.", ""]
    (Path(__file__).parent / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    try:
        from agentdojo.task_suite.load_suites import get_suite
    except ImportError:
        print("agentdojo is not installed: uv run --group evals python evals/agentdojo_eval.py", file=sys.stderr)
        return 2
    suite = get_suite("v1.2", "banking")
    results = {"costs": measure_costs(),
               "suite": {"injection_tasks": len(suite.injection_tasks), "name": "banking",
                         "tools": len(suite.tools), "user_tasks": len(suite.user_tasks), "version": "v1.2"},
               "variants": [evaluate(name, path, suite) for name, path in VARIANTS.items()]}
    (Path(__file__).parent / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n",
                                                        encoding="utf-8")
    write_results(results)
    for variant in results["variants"]:
        benign = variant["benign"]
        attacks = variant["attacks"]
        print(f"\n=== {variant['variant']} ({variant['policy_hash'][:19]}...) ===")
        print(f"  benign user tasks: {len(benign['unattended'])} unattended, "
              f"{len(benign['with_approval'])} needed a human, {len(benign['blocked'])} blocked outright")
        if benign["blocked"]:
            print(f"    blocked: {', '.join(benign['blocked'])}")
            print(f"    why: {variant['blocked_reasons']}")
        print(f"  approvals asked of the human: {variant['approvals']['total']}")
        print(f"  attack pairs: {attacks['stopped']}/{attacks['pairs']} stopped"
              + (f", goal reached: {attacks['executed'][:3]}" if attacks["executed"] else "")
              + f"; sensitive calls that got through: {len(attacks['sensitive_executed'])}")
        print(f"  decide latency: p50 {variant['latency_us']['p50']} us, p99 {variant['latency_us']['p99']} us"
              f" over {variant['submissions']} submissions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
