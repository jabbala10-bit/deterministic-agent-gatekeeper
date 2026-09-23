// A bundle for AgentDojo's banking suite, so the gate can be measured against a benchmark it did
// not design. Payees are the accounts this user has actually paid before; the attacker's IBAN
// (US133...) differs from a known one (US122...) by three digits, which is why allowlisting matches
// exactly rather than by resemblance.

@id("reads-allowed")
permit (principal is Agent, action in Action::"Read", resource);

// Routine payments to an account the user already pays, under a per-payment and per-session cap.
@id("payment-to-known-payee")
permit (principal is Agent, action in Action::"Money", resource is Payee)
when {
  resource in PayeeGroup::"known" &&
  context.args has amount &&
  context.args.amount.amount_minor <= 200000 &&
  context.session.counters.moved_minor + context.args.amount.amount_minor <= 500000
};

// Anything else that moves money or changes the account needs a human, bound to this exact call.
@id("sensitive-action-approved")
permit (principal is Agent, action in Action::"Sensitive", resource)
when {
  context has approval &&
  context.approval.action_hash == context.action_hash
};

// The strict variant: once the session has ingested untrusted content, sensitive actions are refused
// outright rather than escalated. This is what the eval measures the cost of.
@id("no-sensitive-action-after-untrusted-input")
forbid (principal, action in Action::"Sensitive", resource)
when { context.session.labels.contains("untrusted_input") };
