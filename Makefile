BUNDLE := policies/bank-servicing

.PHONY: verify test vectors demo bench mutants identity

verify: test demo

test:
	uv run pytest

vectors:
	uv run python spec/gen_vectors.py

demo:
	uv run gatekeeper demo --bundle $(BUNDLE) --log .out/demo.jsonl

bench:
	uv run gatekeeper bench --bundle $(BUNDLE)

mutants:
	uv run python spec/mutants.py

identity:
	uv run python spec/check_gate_identity.py
