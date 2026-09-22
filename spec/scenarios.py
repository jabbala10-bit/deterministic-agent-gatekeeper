"""The golden scenario grid: every combination whose verdict the oracle states, plus hand-labelled
bypass attempts. Scenario inputs are what the shell would record; expectations are intent."""

from __future__ import annotations

import json
from dataclasses import dataclass

from gatekeeper.core import EntityRecord, Envelope, Snapshot, canonicalize
from gatekeeper.core.manifest import Manifest

from . import oracle

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
EMAIL_TARGETS = (
    ("alice@customer.example", "customer.example"),
    ("Alice@CUSTOMER.Example.", "customer.example"),  # canonicalises to the allowlisted domain
    ("ops@bank.example", "bank.example"),
    ("exfil@attacker.example", "attacker.example"),
)


@dataclass(frozen=True)
class Scenario:
    name: str
    envelope: Envelope
    snapshot: Snapshot
    verdict: str
    reasons: tuple[str, ...]


def compact(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"))


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


def refund_scenario(manifest: Manifest, amount: int, currency: str, refunded: int, approval: str, account: str) -> Scenario:
    env = envelope("payments.refund", compact({"account_id": ACCOUNT_IDS[account], "amount_minor": amount, "currency": currency}))
    verdict, reasons = oracle.expect_refund(amount=amount, currency=currency, refunded=refunded,
                                            approved=approval == "bound", account=account)
    return Scenario(f"refund/{account}/{currency}/{amount}/refunded-{refunded}/approval-{approval}", env,
                    snapshot(refunded=refunded, approvals=_approvals(manifest, env, approval)), verdict, tuple(reasons))


def email_scenario(manifest: Manifest, to: str, domain: str, labels: tuple[str, ...], approval: str) -> Scenario:
    env = envelope("email.send", compact({"to": to, "subject": "Your statement", "body": "Your statement is attached."}))
    verdict, reasons = oracle.expect_email(domain=domain, labels=labels, approved=approval == "bound")
    return Scenario(f"email/{to}/labels-{'+'.join(labels) or 'none'}/approval-{approval}", env,
                    snapshot(labels=labels, approvals=_approvals(manifest, env, approval)), verdict, tuple(reasons))


_REFUND = "payments.refund"
_EMAIL_BASE = {"to": "alice@customer.example", "subject": "Your statement", "body": "Attached."}

# (name, tool, raw arguments, expected reason). Every one of these must be a DENY.
BYPASS_ATTEMPTS: tuple[tuple[str, str, str, str], ...] = (
    ("float-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":150.00,"currency":"EUR"}', "INVALID_ARGUMENTS:float_not_allowed"),
    ("exponent-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":1e4,"currency":"EUR"}', "INVALID_ARGUMENTS:float_not_allowed"),
    ("nan-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":NaN,"currency":"EUR"}', "INVALID_ARGUMENTS:non_finite_number"),
    ("duplicate-key", _REFUND, '{"account_id":"acc-1001","amount_minor":100,"amount_minor":9000000,"currency":"EUR"}', "INVALID_ARGUMENTS:duplicate_key"),
    ("bool-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":true,"currency":"EUR"}', "INVALID_ARGUMENTS:amount_minor:not_integer"),
    ("string-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":"15000","currency":"EUR"}', "INVALID_ARGUMENTS:amount_minor:not_integer"),
    ("zero-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":0,"currency":"EUR"}', "INVALID_ARGUMENTS:amount_minor:out_of_bounds"),
    ("negative-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":-500,"currency":"EUR"}', "INVALID_ARGUMENTS:amount_minor:out_of_bounds"),
    ("over-max-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":100000001,"currency":"EUR"}', "INVALID_ARGUMENTS:amount_minor:out_of_bounds"),
    ("i64-max-amount", _REFUND, '{"account_id":"acc-1001","amount_minor":9223372036854775807,"currency":"EUR"}', "INVALID_ARGUMENTS:integer_out_of_range"),
    ("lowercase-currency", _REFUND, '{"account_id":"acc-1001","amount_minor":100,"currency":"eur"}', "INVALID_ARGUMENTS:currency:not_in_enum"),
    ("unknown-argument", _REFUND, '{"account_id":"acc-1001","amount_minor":100,"currency":"EUR","memo":"x"}', "INVALID_ARGUMENTS:unknown_argument"),
    ("missing-argument", _REFUND, '{"account_id":"acc-1001","amount_minor":100}', "INVALID_ARGUMENTS:missing_argument"),
    ("cedar-uid-injection", _REFUND, '{"account_id":"acc-1001\\" || true || \\"","amount_minor":100,"currency":"EUR"}', "INVALID_ARGUMENTS:account_id:bad_id"),
    ("not-an-object", _REFUND, '[1,2,3]', "INVALID_ARGUMENTS:not_an_object"),
    ("truncated-json", _REFUND, '{"account_id":', "INVALID_ARGUMENTS:malformed_json"),
    ("trailing-comma", _REFUND, '{"account_id":"acc-1001","amount_minor":100,"currency":"EUR",}', "INVALID_ARGUMENTS:malformed_json"),
    ("oversized-arguments", _REFUND, '{"account_id":"acc-1001","amount_minor":100,"currency":"EUR","pad":"' + "x" * 65_600 + '"}', "INVALID_ARGUMENTS:too_large"),
    ("tool-name-case", "Payments.Refund", '{}', "UNKNOWN_TOOL"),
    ("unregistered-tool", "payments.transfer", '{}', "UNKNOWN_TOOL"),
    ("email-non-ascii-domain", "email.send", compact({**_EMAIL_BASE, "to": "alice@cust\u00f6mer.example"}), "INVALID_ARGUMENTS:to:non_ascii_address"),
    ("email-two-at-signs", "email.send", compact({**_EMAIL_BASE, "to": "a@b@customer.example"}), "INVALID_ARGUMENTS:to:bad_address"),
    ("email-ip-literal", "email.send", compact({**_EMAIL_BASE, "to": "a@127.0.0.1"}), "INVALID_ARGUMENTS:to:bad_domain"),
    ("subject-bidi-override", "email.send", compact({**_EMAIL_BASE, "subject": "Invoice \u202efdp.exe"}), "INVALID_ARGUMENTS:subject:bidi_control"),
    ("body-nul-byte", "email.send", compact({**_EMAIL_BASE, "body": "a\u0000b"}), "INVALID_ARGUMENTS:body:control_character"),
    ("body-lone-surrogate", "email.send", '{"to":"alice@customer.example","subject":"s","body":"\\ud800"}', "INVALID_ARGUMENTS:lone_surrogate"),
    ("body-unassigned-code-point", "email.send", compact({**_EMAIL_BASE, "body": "x\u0378y"}), "INVALID_ARGUMENTS:body:unassigned_code_point"),
)

FORMAT_VARIANTS = (
    ("compact", '{"account_id":"acc-1001","amount_minor":15000,"currency":"EUR"}'),
    ("reordered", '{"currency":"EUR","amount_minor":15000,"account_id":"acc-1001"}'),
    ("whitespace", '{\n  "amount_minor" : 15000 ,\n  "account_id" : "acc-1001",\n  "currency" : "EUR"\n}'),
    ("unicode-escapes", '{"account_id":"\\u0061cc-1001","amount_minor":15000,"currency":"\\u0045UR"}'),
)


def build(manifest: Manifest) -> list[Scenario]:
    out: list[Scenario] = []
    for amount in (1, 15_000, 20_000, 20_001, 45_000, 450_000, 500_000, 500_001):
        for currency in ("EUR", "USD"):
            for refunded in (0, 30_000, 45_000, 460_000):
                for approval in ("none", "bound", "other"):
                    out.append(refund_scenario(manifest, amount, currency, refunded, approval, "ok"))
    for account in ("frozen", "missing"):
        for amount in (15_000, 450_000):
            for approval in ("none", "bound"):
                out.append(refund_scenario(manifest, amount, "EUR", 0, approval, account))
    for to, domain in EMAIL_TARGETS:
        for labels in LABEL_SETS:
            for approval in ("none", "bound"):
                out.append(email_scenario(manifest, to, domain, labels, approval))
    for tool, arg, resource in (("crm.lookup", "customer_id", "cust-42"), ("inbox.read", "mailbox_id", "mbx-support")):
        for labels in LABEL_SETS:
            verdict, reasons = oracle.expect_read()
            out.append(Scenario(f"read/{tool}/labels-{'+'.join(labels) or 'none'}", envelope(tool, compact({arg: resource})),
                                snapshot(labels=labels), verdict, tuple(reasons)))
    for name, raw in FORMAT_VARIANTS:
        out.append(Scenario(f"format/{name}", envelope(_REFUND, raw), snapshot(), "ALLOW", ("refund-auto",)))
    for name, tool, raw, reason in BYPASS_ATTEMPTS:
        out.append(Scenario(f"invalid/{name}", envelope(tool, raw), snapshot(), "DENY", (reason,)))

    valid_refund = envelope(_REFUND, compact({"account_id": "acc-1001", "amount_minor": 100, "currency": "EUR"}))
    out.append(Scenario("invalid-snapshot/unknown-label", valid_refund, snapshot(labels=("root_access",)),
                        "DENY", ("INVALID_SNAPSHOT:unknown_label",)))
    smuggled = (EntityRecord.build("Recipient", "attacker.example", {}),)
    out.append(Scenario("invalid-snapshot/config-entity-smuggled-in", email_scenario(
        manifest, "exfil@attacker.example", "attacker.example", (), "none").envelope, snapshot(extra=smuggled),
        "DENY", ("INVALID_SNAPSHOT:entity_type_not_allowed",)))
    out.append(Scenario("invalid-snapshot/session-mismatch", envelope(_REFUND, valid_refund.arguments, session_id="sess-other"),
                        snapshot(), "DENY", ("INVALID_SNAPSHOT:session_mismatch",)))
    return out
