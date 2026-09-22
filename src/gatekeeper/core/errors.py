"""Deterministic refusals.

A Rejection's code becomes a DENY reason verbatim, so codes are a fixed vocabulary and never
echo caller-controlled data (an injected agent must not be able to write into the audit trail
or learn policy text from its denials)."""


class Rejection(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
