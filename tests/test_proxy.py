"""The enforcement point: an MCP proxy in front of an unmodified server."""

import json
import sys
from pathlib import Path

import pytest

from gatekeeper.shell import Gate, McpProxy, UpstreamServer, read_log, replay
from gatekeeper.shell.loader import load_bundle
from gatekeeper.shell.proxy import ProtocolError, agent_message, parse_frame

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = "/tmp/gatekeeper-fs-demo"


@pytest.fixture(scope="session")
def filesystem_bundle():
    return load_bundle(ROOT / "policies" / "filesystem")


@pytest.fixture
def proxy(filesystem_bundle, tmp_path):
    upstream = UpstreamServer([sys.executable, str(ROOT / "examples" / "echo_mcp_server.py")])
    gate = Gate(filesystem_bundle, tmp_path)
    try:
        yield McpProxy(gate, upstream, session_id="sess-proxy", principal="support-bot"), gate
    finally:
        upstream.close()


def call(proxy, tool, arguments, request_id=1):
    return proxy.handle({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                         "params": {"name": tool, "arguments": arguments}})


def test_the_handshake_and_tool_list_pass_through(proxy):
    client, _ = proxy
    reply = client.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "test", "version": "1"}}})
    assert reply["result"]["serverInfo"]["name"] == "echo-mcp-server"


def test_tools_list_is_filtered_to_the_manifest(proxy):
    client, _ = proxy
    reply = client.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [tool["name"] for tool in reply["result"]["tools"]]
    assert sorted(names) == ["list_directory", "read_text_file", "write_file"]
    assert "secret_tool" not in names  # the agent is never told about what it could not call


def test_an_allowed_call_reaches_the_server_with_canonical_arguments(proxy):
    client, _ = proxy
    reply = call(client, "list_directory", {"path": f"{SANDBOX}/./reports/../reports"})
    echoed = json.loads(reply["result"]["content"][0]["text"])
    assert echoed == {"path": f"{SANDBOX}/reports"}  # normalised before the server saw it


def test_a_path_escape_never_reaches_the_server(proxy):
    client, _ = proxy
    reply = call(client, "list_directory", {"path": f"{SANDBOX}/../../etc"})
    assert reply["result"]["isError"] is True
    assert "INVALID_ARGUMENTS:path:path_outside_sandbox" in reply["result"]["content"][0]["text"]


def test_a_write_needs_a_human_and_says_so_without_naming_policy(proxy):
    client, gate = proxy
    reply = call(client, "write_file", {"path": f"{SANDBOX}/notes.txt", "content": "hello"})
    text = reply["result"]["content"][0]["text"]
    assert reply["result"]["isError"] is True
    assert text.startswith("gatekeeper: APPROVAL_REQUIRED for action sha256:")
    assert "write-approved" not in text and "reads-allowed" not in text
    assert gate.pending("sess-proxy")[0]["tool"] == "write_file"


def test_a_forbidden_call_says_only_that_it_was_denied(proxy):
    client, _ = proxy
    call(client, "read_text_file", {"path": f"{SANDBOX}/inbox.txt"})  # taints the session
    reply = call(client, "write_file", {"path": f"{SANDBOX}/notes.txt", "content": "hello"}, request_id=3)
    text = reply["result"]["content"][0]["text"]
    assert text.startswith("gatekeeper: DENIED (decision sha256:")
    assert "no-write-after-reading-a-file" not in text  # the reason lives in the ledger, not here


def test_the_reason_is_in_the_ledger_even_though_the_agent_never_sees_it(proxy):
    client, gate = proxy
    call(client, "read_text_file", {"path": f"{SANDBOX}/inbox.txt"})
    call(client, "write_file", {"path": f"{SANDBOX}/notes.txt", "content": "x"}, request_id=4)
    records = list(read_log(gate.store.path_for("sess-proxy")))
    reasons = [record["body"]["decision"]["reasons"] for record in records if record["kind"] == "decided"]
    assert ["no-write-after-reading-a-file"] in reasons
    assert replay(records, gate.bundle, "sess-proxy").ok


def test_an_unknown_tool_is_refused_before_the_server_is_asked(proxy):
    client, _ = proxy
    reply = call(client, "secret_tool", {"path": SANDBOX})
    assert "UNKNOWN_TOOL" in reply["result"]["content"][0]["text"]


def test_a_frame_with_duplicate_keys_is_refused(proxy):
    with pytest.raises(ProtocolError):
        parse_frame('{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}')


def test_a_float_argument_is_refused_by_the_gate(proxy):
    client, _ = proxy
    reply = call(client, "read_text_file", {"path": f"{SANDBOX}/notes.txt", "head": 10.5})
    assert "INVALID_ARGUMENTS" in reply["result"]["content"][0]["text"]


def test_optional_arguments_may_be_sent_or_omitted(proxy):
    client, _ = proxy
    with_head = call(client, "read_text_file", {"path": f"{SANDBOX}/notes.txt", "head": 10})
    assert json.loads(with_head["result"]["content"][0]["text"]) == {"head": 10, "path": f"{SANDBOX}/notes.txt"}
    without = call(client, "read_text_file", {"path": f"{SANDBOX}/notes.txt"}, request_id=5)
    assert json.loads(without["result"]["content"][0]["text"]) == {"path": f"{SANDBOX}/notes.txt"}


def test_the_agent_message_carries_no_policy_detail_for_policy_outcomes(bundle, tmp_path):
    from gatekeeper.core import decide
    from spec import scenarios as sc
    scenario = sc.email_scenario(bundle.manifest, "exfil@attacker.example", "attacker.example",
                                 ("private_data", "untrusted_input"), "none")
    message = agent_message(decide(scenario.envelope, scenario.snapshot, bundle))
    assert message.startswith("gatekeeper: DENIED")
    assert "egress" not in message and "untrusted" not in message
