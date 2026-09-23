"""Executable statement of intent, written without Cedar.

The golden corpus is labelled by this oracle and property tests compare decide() against it, so a
policy that drifts from the business rule fails CI even when it is perfectly valid Cedar."""

from __future__ import annotations

ALLOWLISTED_DOMAINS = frozenset({"bank.example", "customer.example"})
ALLOWLISTED_HOSTS = frozenset({"bank.example", "sepa-directory.example"})
REPORT_TEMPLATES = frozenset({"customer_balance", "refund_summary"})
AUTO_PER_CALL_MINOR = 20_000          # EUR 200.00
AUTO_PER_SESSION_MINOR = 50_000       # EUR 500.00
APPROVED_PER_SESSION_MINOR = 500_000  # EUR 5,000.00
TRIFECTA = frozenset({"private_data", "untrusted_input"})


def under(host: str, allowed: frozenset[str]) -> bool:
    """A host is covered when one of its right-hand suffixes is allowlisted, so billing.bank.example
    is covered by bank.example while bank.example.attacker.test is not."""
    labels = host.split(".")
    return any(".".join(labels[index:]) in allowed for index in range(len(labels) - 1))


def expect_refund(*, amount_minor: int, currency: str, refunded: int, approved: bool, account: str) -> tuple[str, list[str]]:
    if account == "missing":  # the frozen-account guardrail cannot be evaluated: fail closed
        return "DENY", ["EVAL_ERROR:no-refund-to-frozen-account"]
    if account == "frozen":
        return "DENY", ["no-refund-to-frozen-account"]
    auto = currency == "EUR" and amount_minor <= AUTO_PER_CALL_MINOR and refunded + amount_minor <= AUTO_PER_SESSION_MINOR
    with_approval = refunded + amount_minor <= APPROVED_PER_SESSION_MINOR
    if approved:
        reasons = sorted(name for name, ok in (("refund-auto", auto), ("refund-approved", with_approval)) if ok)
        return ("ALLOW", reasons) if reasons else ("DENY", ["NO_MATCHING_PERMIT"])
    if auto:
        return "ALLOW", ["refund-auto"]
    if with_approval:
        return "REQUIRE_APPROVAL", ["refund-approved"]
    return "DENY", ["NO_MATCHING_PERMIT"]


def _egress(*, allowlisted: bool, allow_reason: str, labels: tuple[str, ...], approved: bool) -> tuple[str, list[str]]:
    if TRIFECTA <= set(labels):
        return "DENY", ["no-egress-after-untrusted-with-private"]
    if approved:
        return "ALLOW", sorted(["egress-approved"] + ([allow_reason] if allowlisted else []))
    if allowlisted:
        return "ALLOW", [allow_reason]
    return "REQUIRE_APPROVAL", ["egress-approved"]


def expect_email(*, domain: str, labels: tuple[str, ...], approved: bool) -> tuple[str, list[str]]:
    return _egress(allowlisted=under(domain, ALLOWLISTED_DOMAINS),
                   allow_reason="egress-allowlisted-recipient", labels=labels, approved=approved)


def expect_fetch(*, host: str, scheme: str, labels: tuple[str, ...], approved: bool) -> tuple[str, list[str]]:
    return _egress(allowlisted=under(host, ALLOWLISTED_HOSTS) and scheme == "https",
                   allow_reason="egress-allowlisted-host", labels=labels, approved=approved)


def expect_report(*, name: str) -> tuple[str, list[str]]:
    if name in REPORT_TEMPLATES:
        return "ALLOW", ["reports-allowlisted"]
    return "DENY", ["NO_MATCHING_PERMIT"]


def expect_read() -> tuple[str, list[str]]:
    return "ALLOW", ["reads-allowed"]
