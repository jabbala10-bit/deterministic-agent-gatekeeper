"""Executable statement of intent, written without Cedar.

The golden corpus is labelled by this oracle and property tests compare decide() against it, so a
policy that drifts from the business rule fails CI even when it is perfectly valid Cedar."""

from __future__ import annotations

ALLOWLISTED_DOMAINS = frozenset({"bank.example", "customer.example"})
AUTO_PER_CALL_MINOR = 20_000          # EUR 200.00
AUTO_PER_SESSION_MINOR = 50_000       # EUR 500.00
APPROVED_PER_SESSION_MINOR = 500_000  # EUR 5,000.00
TRIFECTA = frozenset({"private_data", "untrusted_input"})


def expect_refund(*, amount: int, currency: str, refunded: int, approved: bool, account: str) -> tuple[str, list[str]]:
    if account == "missing":  # the frozen-account guardrail cannot be evaluated: fail closed
        return "DENY", ["EVAL_ERROR:no-refund-to-frozen-account"]
    if account == "frozen":
        return "DENY", ["no-refund-to-frozen-account"]
    auto = currency == "EUR" and amount <= AUTO_PER_CALL_MINOR and refunded + amount <= AUTO_PER_SESSION_MINOR
    with_approval = refunded + amount <= APPROVED_PER_SESSION_MINOR
    if approved:
        reasons = sorted(name for name, ok in (("refund-auto", auto), ("refund-approved", with_approval)) if ok)
        return ("ALLOW", reasons) if reasons else ("DENY", ["NO_MATCHING_PERMIT"])
    if auto:
        return "ALLOW", ["refund-auto"]
    if with_approval:
        return "REQUIRE_APPROVAL", ["refund-approved"]
    return "DENY", ["NO_MATCHING_PERMIT"]


def expect_email(*, domain: str, labels: tuple[str, ...], approved: bool) -> tuple[str, list[str]]:
    if TRIFECTA <= set(labels):
        return "DENY", ["no-egress-after-untrusted-with-private"]
    allowlisted = domain in ALLOWLISTED_DOMAINS
    if approved:
        return "ALLOW", sorted(["egress-approved"] + (["egress-allowlisted"] if allowlisted else []))
    if allowlisted:
        return "ALLOW", ["egress-allowlisted"]
    return "REQUIRE_APPROVAL", ["egress-approved"]


def expect_read() -> tuple[str, list[str]]:
    return "ALLOW", ["reads-allowed"]
