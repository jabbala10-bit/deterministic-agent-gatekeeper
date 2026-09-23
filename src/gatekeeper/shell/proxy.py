"""An MCP proxy that enforces the gate on `tools/call`.

The proxy speaks newline-delimited JSON-RPC on both sides: a client (Claude Code, say) on stdio, and
an unmodified MCP server as a subprocess. Everything except `tools/call` is relayed untouched;
`tools/list` is filtered to the tools the manifest declares, so the agent is not even told about
tools it could not call.

What the agent learns from a refusal is deliberately narrow. Faults in its own input come back
verbatim, because they help it correct itself. Policy outcomes collapse to DENIED or
APPROVAL_REQUIRED with a correlation id: an injected agent must not be able to use denials to map
the policy. The reasons stay in the ledger, where a human can read them."""

from __future__ import annotations

import json
import subprocess
from typing import Any, Callable, Iterable, TextIO

from ..core import Decision, EntityRecord
from .gate import Gate

SELF_EXPLANATORY = ("INVALID_ARGUMENTS", "UNKNOWN_TOOL", "INVALID_SNAPSHOT")


class ProtocolError(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ProtocolError("duplicate key in JSON-RPC frame")
        seen[key] = value
    return seen


def parse_frame(line: str) -> dict[str, Any]:
    return json.loads(line, object_pairs_hook=_no_duplicate_keys)


def agent_message(decision: Decision) -> str:
    """One line for the agent. Policy structure is not part of it."""
    correlation = decision.decision_hash[:19]
    own_fault = [reason for reason in decision.reasons if reason.startswith(SELF_EXPLANATORY)]
    if own_fault:
        return f"gatekeeper: {', '.join(own_fault)} (decision {correlation})"
    if decision.verdict == "REQUIRE_APPROVAL":
        return (f"gatekeeper: APPROVAL_REQUIRED for action {decision.action_hash} "
                f"(decision {correlation}). A human must approve this exact call.")
    return f"gatekeeper: DENIED (decision {correlation})"


def refusal_result(decision: Decision) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": agent_message(decision)}], "isError": True}


class UpstreamServer:
    """An unmodified MCP server, run as a subprocess and spoken to over stdio."""

    def __init__(self, command: Iterable[str]) -> None:
        self.process = subprocess.Popen(list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def receive(self) -> dict[str, Any] | None:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            return None
        return parse_frame(line)

    def request(self, message: dict[str, Any]) -> dict[str, Any]:
        self.send(message)
        while True:
            reply = self.receive()
            if reply is None:
                raise ProtocolError("upstream server closed the connection")
            if reply.get("id") == message.get("id"):
                return reply

    def close(self) -> None:
        try:
            if self.process.stdin:
                self.process.stdin.close()
            self.process.wait(timeout=5)
        except Exception:
            self.process.kill()


class McpProxy:
    def __init__(self, gate: Gate, upstream: UpstreamServer, *, session_id: str, principal: str,
                 facts: Iterable[EntityRecord] = (), filter_tools: bool = True) -> None:
        self._gate = gate
        self._upstream = upstream
        self._session_id = session_id
        self._principal = principal
        self._facts = tuple(facts)
        self._filter_tools = filter_tools
        self._next_id = 1_000_000

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        if method == "tools/call" and "id" in message:
            return self._handle_call(message)
        if "id" not in message:  # a notification: relay and expect nothing back
            self._upstream.send(message)
            return None
        reply = self._upstream.request(message)
        if method == "tools/list" and self._filter_tools:
            reply = self._filter(reply)
        return reply

    def serve(self, stdin: TextIO, stdout: TextIO) -> None:
        for line in stdin:
            if not line.strip():
                continue
            try:
                message = parse_frame(line)
            except (ValueError, ProtocolError) as err:
                stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32700, "message": f"parse error: {err}"}}) + "\n")
                stdout.flush()
                continue
            reply = self.handle(message)
            if reply is not None:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()

    def _filter(self, reply: dict[str, Any]) -> dict[str, Any]:
        tools = reply.get("result", {}).get("tools")
        if not isinstance(tools, list):
            return reply
        declared = self._gate.bundle.manifest.tools
        reply["result"]["tools"] = [tool for tool in tools if tool.get("name") in declared]
        return reply

    def _handle_call(self, message: dict[str, Any]) -> dict[str, Any]:
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments", {})
        try:
            arguments_text = json.dumps(arguments, separators=(",", ":"), allow_nan=False, sort_keys=True)
        except ValueError:
            arguments_text = "null"  # non-finite numbers: let the gate refuse it and record why
        ticket = self._gate.submit(session_id=self._session_id, principal=self._principal,
                                   tool=name if isinstance(name, str) else "", arguments=arguments_text,
                                   facts=self._facts)
        if ticket.verdict != "ALLOW":
            return {"jsonrpc": "2.0", "id": message["id"], "result": refusal_result(ticket.decision)}
        result = self._gate.execute(ticket.token, self._call_upstream)
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def _call_upstream(self, tool: str, arguments: dict[str, Any]) -> Any:
        self._next_id += 1
        reply = self._upstream.request({"jsonrpc": "2.0", "id": self._next_id, "method": "tools/call",
                                        "params": {"name": tool, "arguments": arguments}})
        if "error" in reply:
            raise ProtocolError(str(reply["error"]))
        return reply.get("result")
