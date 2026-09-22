// Bank servicing agent: policy bundle for the Deterministic Agent Gatekeeper.
// Every policy carries a stable @id; decision records cite these ids, never file positions.
// Tool arguments live under context.args so an argument can never shadow a gate-supplied field.

// Hard guardrail. Once a session holds private data AND has ingested untrusted content,
// nothing leaves the boundary. No permit and no human approval can override a forbid.
@id("no-egress-after-untrusted-with-private")
forbid (principal, action in Action::"Egress", resource)
when {
  context.session.labels.contains("untrusted_input") &&
  context.session.labels.contains("private_data")
};

// Hard guardrail. Frozen accounts never receive refunds. If the shell did not load the
// account's entity this policy errors; the engine would skip it, the gate denies instead.
@id("no-refund-to-frozen-account")
forbid (principal, action == Action::"payments.refund", resource is Account)
when { resource.frozen };

// Small EUR refunds pass without a human: per-call and per-session caps in minor units.
@id("refund-auto")
permit (principal is Agent, action == Action::"payments.refund", resource is Account)
when {
  context.args.currency == "EUR" &&
  context.args.amount_minor <= 20000 &&
  context.session.refunded_minor + context.args.amount_minor <= 50000
};

// Larger or non-EUR refunds need a human approval bound to this exact canonical action.
@id("refund-approved")
permit (principal is Agent, action == Action::"payments.refund", resource is Account)
when {
  context has approval &&
  context.approval.action_hash == context.action_hash &&
  context.session.refunded_minor + context.args.amount_minor <= 500000
};

// Egress to allowlisted recipient domains (configured in entities.json).
@id("egress-allowlisted")
permit (principal is Agent, action in Action::"Egress", resource is Recipient)
when { resource in RecipientGroup::"allowlisted" };

// Egress anywhere else needs an approval bound to this exact canonical action.
@id("egress-approved")
permit (principal is Agent, action in Action::"Egress", resource)
when {
  context has approval &&
  context.approval.action_hash == context.action_hash
};

// Reads are allowed; their results label the session (enforced from phase 3).
@id("reads-allowed")
permit (principal is Agent, action in Action::"Read", resource);
