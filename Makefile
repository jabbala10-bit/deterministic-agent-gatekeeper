BUNDLE := policies/bank-servicing
SESSIONS := .out/sessions

.PHONY: verify test vectors demo bench mutants identity mcp proxy

verify: test demo

test:
	uv run pytest

vectors:
	uv run python spec/gen_vectors.py

demo:
	uv run gatekeeper demo --bundle $(BUNDLE) --sessions $(SESSIONS)

replay:
	uv run gatekeeper replay $(SESSIONS)/sess-demo-001.jsonl --bundle $(BUNDLE) --session sess-demo-001

state:
	uv run gatekeeper state $(SESSIONS)/sess-demo-001.jsonl --bundle $(BUNDLE) --session sess-demo-001

bench:
	uv run gatekeeper bench --bundle $(BUNDLE)

mutants:
	uv run python spec/mutants.py

identity:
	uv run python spec/check_gate_identity.py

mcp:
	uv run pytest tests/test_mcp_integration.py -v

proxy:
	@echo "usage: uv run gatekeeper proxy --bundle $(BUNDLE) --session <id> -- <mcp server command>"
