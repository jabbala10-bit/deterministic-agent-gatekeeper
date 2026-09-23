"""The golden scenario grid: every combination whose verdict the oracle states, the equivalence
classes that must collapse to one canonical action, and the known-bypass corpus.

Scenario inputs are what the shell would record; expectations are intent, never implementation
output. The decimal amounts are formatted here and parsed back by the gate, so a disagreement about
minor units shows up as a failing vector."""

from __future__ import annotations

import json
from dataclasses import dataclass

from gatekeeper.core import EntityRecord, Envelope, Snapshot, canonicalize
from gatekeeper.core.manifest import Manifest

from . import oracle
from .bypasses import CORPUS

T0_MS = 1_790_000_000_000
SESSION = "sess-7f3a"
PRINCIPAL = "support-bot"
UNRELATED_APPROVAL = "sha256:" + "ab" * 32
ACCOUNT_IDS = {"ok": "acc-1001", "frozen": "acc-2002", "missing": "acc-9999"}
FACTS = (
    EntityRecord.build("Account", "acc-1001", {"frozen": False}),
    EntityRecord.build("Account", "acc-2002", {"frozen": True}),
)
LABEL_SETS: tuple[tuple[str, ...], ...] = ((), ("private_data",), ("untrusted_input",), ("private_data", "untrusted_input"))
EXPONENTS = {"EUR": 2, "USD": 2, "JPY": 0}
MAIL_BODY = {"subject": "Your statement", "body": "Attached."}

EMAIL_TARGETS = (
    ("alice@customer.example", "customer.example"),
    ("Alice@CUSTOMER.Example.", "customer.example"),
    ("a@billing.customer.example", "billing.customer.example"),
    ("ops@bank.example", "bank.example"),
    ("exfil@attacker.example", "attacker.example"),
    ("a@customer.example.attacker.test", "customer.example.attacker.test"),
)
FETCH_TARGETS = (
    ("https://docs.bank.example/a", "docs.bank.example"),
    ("https://sepa-directory.example/iban/DE89", "sepa-directory.example"),
    ("https://evil.example/x", "evil.example"),
    ("https://bank.example.attacker.test/", "bank.example.attacker.test"),
)
EQUIVALENT_URLS = (
    ("plain", "https://docs.bank.example/a/c?x=1"),
    ("uppercase", "HTTPS://DOCS.Bank.Example/a/c?x=1"),
    ("default-port", "https://docs.bank.example:443/a/c?x=1"),
    ("dot-segments", "https://docs.bank.example/a/./b/../c?x=1"),
    ("fragment", "https://docs.bank.example/a/c?x=1#section"),
    ("trailing-dot-host", "https://docs.bank.example./a/c?x=1"),
    ("percent-encoded-unreserved", "https://docs.bank.example/%61/c?x=1"),
    ("encoded-dot-segments", "https://docs.bank.example/a/%2e%2e/a/c?x=1"),
)
EQUIVALENT_RECIPIENTS = (
    ("plain", "alice@customer.example"),
    ("uppercase-domain", "alice@CUSTOMER.Example"),
    ("trailing-dot", "alice@customer.example."),
)
EQUIVALENT_IDNA = (  # one domain, three spellings, none of them allowlisted
    ("unicode", "post@b\u00fccher.example"),
    ("unicode-uppercase", "post@B\u00dcCHER.example"),
    ("punycode", "post@xn--bcher-kva.example"),
)
EQUIVALENT_AMOUNTS = (("integer", "150"), ("one-decimal", "150.0"), ("two-decimals", "150.00"))


@dataclass(frozen=True)
class Scenario:
    name: str
    envelope: Envelope
    snapshot: Snapshot
    verdict: str
    reasons: tuple[str, ...]


def compact(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"))


def amount_text(minor: int, currency: str) -> str:
    exponent = EXPONENTS[currency]
    if exponent == 0:
        return str(minor)
    return f"{minor // 10**exponent}.{minor % 10**exponent:0{exponent}d}"


def envelope(tool: str, arguments: str, *, session_id: str = SESSION) -> Envelope:
    return Envelope(tool=tool, arguments=arguments, principal=PRINCIPAL, session_id=session_id, t_ms=T0_MS)


def snapshot(*, labels: tuple[str, ...] = (), refunded: int = 0, approvals: tuple[str, ...] = (),
             extra: tuple[EntityRecord, ...] = ()) -> Snapshot:
    return Snapshot.build(session_id=SESSION, ledger_seq=7, labels=labels, refunded_minor=refunded,
                          approvals=approvals, entities=FACTS + extra)


def _approvals(manifest: Manifest, env: Envelope, approval: str) -> tuple[str, ...]:
    if approval == "bound":
        return (canonicalize(env, manifest).digest(),)
    if approval == "other":
        return (UNRELATED_APPROVAL,)
    return ()


def refund_scenario(manifest: Manifest, minor: int, currency: str, refunded: int, approval: str, account: str) -> Scenario:
    env = envelope("payments.refund", compact({
        "account_id": ACCOUNT_IDS[account],
        "amount": {"amount": amount_text(minor, currency), "currency": currency},
    }))
    verdict, reasons = oracle.expect_refund(amount_minor=minor, currency=currency, refunded=refunded,
                                            approved=approval == "bound", account=account)
    name = f"refund/{account}/{currency}/{minor}/refunded-{refunded}/approval-{approval}"
    return Scenario(name, env, snapshot(refunded=refunded, approvals=_approvals(manifest, env, approval)), verdict, tuple(reasons))


def email_scenario(manifest: Manifest, to: str, domain: str, labels: tuple[str, ...], approval: str) -> Scenario:
    env = envelope("email.send", compact({"to": to, **MAIL_BODY}))
    verdict, reasons = oracle.expect_email(domain=domain, labels=labels, approved=approval == "bound")
    name = f"email/{to}/labels-{'+'.join(labels) or 'none'}/approval-{approval}"
    return Scenario(name, env, snapshot(labels=labels, approvals=_approvals(manifest, env, approval)), verdict, tuple(reasons))


def fetch_scenario(manifest: Manifest, url: str, host: str, labels: tuple[str, ...], approval: str) -> Scenario:
    env = envelope("web.fetch", compact({"url": url}))
    verdict, reasons = oracle.expect_fetch(host=host, scheme="https", labels=labels, approved=approval == "bound")
    name = f"fetch/{host}/labels-{'+'.join(labels) or 'none'}/approval-{approval}"
    return Scenario(name, env, snapshot(labels=labels, approvals=_approvals(manifest, env, approval)), verdict, tuple(reasons))


def report_scenario(name: str, params: dict[str, object], labels: tuple[str, ...]) -> Scenario:
    env = envelope("db.report", compact({"report": {"name": name, "params": params}}))
    verdict, reasons = oracle.expect_report(name=name)
    return Scenario(f"report/{name}/labels-{'+'.join(labels) or 'none'}", env, snapshot(labels=labels), verdict, tuple(reasons))


def build(manifest: Manifest) -> list[Scenario]:
    out: list[Scenario] = []
    for minor in (1, 15_000, 20_000, 20_001, 45_000, 450_000, 500_000, 500_001):
        for currency in ("EUR", "USD"):
            for refunded in (0, 30_000, 45_000, 460_000):
                for approval in ("none", "bound", "other"):
                    out.append(refund_scenario(manifest, minor, currency, refunded, approval, "ok"))
    for minor in (150, 20_000):
        for approval in ("none", "bound"):
            out.append(refund_scenario(manifest, minor, "JPY", 0, approval, "ok"))
    for account in ("frozen", "missing"):
        for minor in (15_000, 450_000):
            for approval in ("none", "bound"):
                out.append(refund_scenario(manifest, minor, "EUR", 0, approval, account))

    for to, domain in EMAIL_TARGETS:
        for labels in LABEL_SETS:
            for approval in ("none", "bound"):
                out.append(email_scenario(manifest, to, domain, labels, approval))
    for url, host in FETCH_TARGETS:
        for labels in LABEL_SETS:
            for approval in ("none", "bound"):
                out.append(fetch_scenario(manifest, url, host, labels, approval))

    for template, params in (("refund_summary", {"account_id": "acc-1001", "since_days": 30}),
                             ("customer_balance", {"customer_id": "cust-42"}),
                             ("pii_export", {"customer_id": "cust-42"})):
        for labels in ((), ("private_data",)):
            out.append(report_scenario(template, params, labels))

    for tool, arg, resource in (("crm.lookup", "customer_id", "cust-42"), ("inbox.read", "mailbox_id", "mbx-support")):
        for labels in LABEL_SETS:
            verdict, reasons = oracle.expect_read()
            out.append(Scenario(f"read/{tool}/labels-{'+'.join(labels) or 'none'}",
                                envelope(tool, compact({arg: resource})), snapshot(labels=labels), verdict, tuple(reasons)))

    # Equivalence classes: every spelling in a group must collapse to one canonical action.
    for variant, url in EQUIVALENT_URLS:
        out.append(Scenario(f"equivalence/url/{variant}", envelope("web.fetch", compact({"url": url})),
                            snapshot(), "ALLOW", ("egress-allowlisted-host",)))
    for variant, to in EQUIVALENT_RECIPIENTS:
        out.append(Scenario(f"equivalence/recipient/{variant}", envelope("email.send", compact({"to": to, **MAIL_BODY})),
                            snapshot(), "ALLOW", ("egress-allowlisted-recipient",)))
    for variant, to in EQUIVALENT_IDNA:
        out.append(Scenario(f"equivalence/idna/{variant}", envelope("email.send", compact({"to": to, **MAIL_BODY})),
                            snapshot(), "REQUIRE_APPROVAL", ("egress-approved",)))
    for variant, amount in EQUIVALENT_AMOUNTS:
        out.append(Scenario(f"equivalence/amount/{variant}", envelope("payments.refund", compact(
            {"account_id": "acc-1001", "amount": {"amount": amount, "currency": "EUR"}})),
            snapshot(), "ALLOW", ("refund-auto",)))

    for name, tool, raw, verdict, reason in CORPUS:
        out.append(Scenario(f"bypass/{name}", envelope(tool, raw), snapshot(), verdict, (reason,)))

    valid_refund = compact({"account_id": "acc-1001", "amount": {"amount": "1.00", "currency": "EUR"}})
    out.append(Scenario("invalid-snapshot/unknown-label", envelope("payments.refund", valid_refund),
                        snapshot(labels=("root_access",)), "DENY", ("INVALID_SNAPSHOT:unknown_label",)))
    out.append(Scenario("invalid-snapshot/config-entity-smuggled-in",
                        envelope("email.send", compact({"to": "exfil@attacker.example", **MAIL_BODY})),
                        snapshot(extra=(EntityRecord.build("DomainSuffix", "attacker.example", {}),)),
                        "DENY", ("INVALID_SNAPSHOT:entity_type_not_allowed",)))
    out.append(Scenario("invalid-snapshot/session-mismatch",
                        envelope("payments.refund", valid_refund, session_id="sess-other"),
                        snapshot(), "DENY", ("INVALID_SNAPSHOT:session_mismatch",)))
    return out
