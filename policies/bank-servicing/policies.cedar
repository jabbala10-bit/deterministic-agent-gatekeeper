// Bank servicing agent: policy bundle for the Deterministic Agent Gatekeeper.
// Every policy carries a stable @id; decision records cite these ids, never file positions.
// Tool arguments live under context.args so an argument can never shadow a gate-supplied field.

// Hard guardrail. Once a session holds private data AND has ingested untrusted content, nothing
// leaves the boundary, by mail or by fetch. No permit and no human approval overrides a forbid.
@id("no-egress-after-untrusted-with-private")
forbid (principal, action in Action::"Egress", resource)
when {
  context.session.labels.contains("untrusted_input") &&
  context.session.labels.contains("private_data")
};

// Hard guardrail. Frozen accounts never receive refunds. If the shell did not load the account's
// entity this policy errors; the engine would skip it, the gate denies instead.
@id("no-refund-to-frozen-account")
forbid (principal, action == Action::"payments.refund", resource is Account)
when { resource.frozen };

// Small EUR refunds pass without a human. Amounts are exact integers in the currency's minor units.
@id("refund-auto")
permit (principal is Agent, action == Action::"payments.refund", resource is Account)
when {
  context.args.amount.currency == "EUR" &&
  context.args.amount.amount_minor <= 20000 &&
  context.session.counters.refunded_minor + context.args.amount.amount_minor <= 50000
};

// Larger or non-EUR refunds need a human approval bound to this exact canonical action.
@id("refund-approved")
permit (principal is Agent, action == Action::"payments.refund", resource is Account)
when {
  context has approval &&
  context.approval.action_hash == context.action_hash &&
  context.session.counters.refunded_minor + context.args.amount.amount_minor <= 500000
};

// Mail to an allowlisted recipient domain. The resource hangs under every suffix of its domain, so
// allowlisting customer.example covers billing.customer.example without any string matching.
@id("egress-allowlisted-recipient")
permit (principal is Agent, action == Action::"email.send", resource is Recipient)
when { resource in RecipientGroup::"allowlisted" };

// Fetches to an allowlisted host suffix, TLS only.
@id("egress-allowlisted-host")
permit (principal is Agent, action == Action::"web.fetch", resource is Host)
when {
  resource in HostGroup::"egress-allowlist" &&
  context.args.url.scheme == "https"
};

// Any other egress needs an approval bound to this exact canonical action.
@id("egress-approved")
permit (principal is Agent, action in Action::"Egress", resource)
when {
  context has approval &&
  context.approval.action_hash == context.action_hash
};

// Named report templates the agent may run. Parameters are typed and validated by the gate, and
// covered by the action hash, but never reach the policy: no SQL is ever built from agent text.
@id("reports-allowlisted")
permit (principal is Agent, action == Action::"db.report", resource is Report)
when {
  ["customer_balance", "refund_summary"].contains(context.args.report.name)
};

// Reads are allowed; their results label the session (enforced from phase 3).
@id("reads-allowed")
permit (principal is Agent, action in Action::"Read", resource);
