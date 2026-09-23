// Filesystem agent: a bundle for the published MCP filesystem server, to show that the gate is
// domain-agnostic and sits in front of a server it did not write and does not modify.

// Hard guardrail. A file the agent has read is untrusted input: whatever it contained may have been
// written by someone else. Once a session has read one, it may not write files any more.
@id("no-write-after-reading-a-file")
forbid (principal, action in Action::"Write", resource)
when { context.session.labels.contains("untrusted_input") };

// Reads inside the sandbox are allowed. The path argument is canonicalised and confined by the
// manifest, so the gate refuses an escape before the server ever sees it.
@id("reads-allowed")
permit (principal is Agent, action in Action::"Read", resource);

// Writes always need a human approval bound to this exact canonical action.
@id("write-approved")
permit (principal is Agent, action in Action::"Write", resource)
when {
  context has approval &&
  context.approval.action_hash == context.action_hash
};
