#!/usr/bin/env python3
"""A minimal MCP server over stdio: enough protocol for the proxy tests, and nothing else.

It echoes the arguments it is given, so a test can see exactly what the gate handed the tool. It
also advertises a tool the manifest does not declare, so the proxy's filtering of tools/list can be
observed."""

from __future__ import annotations

import json
import sys

_PATH = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
TOOLS = [
    {"name": "list_directory", "description": "List a directory", "inputSchema": _PATH},
    {"name": "read_text_file", "description": "Read a text file", "inputSchema": _PATH},
    {"name": "write_file", "description": "Write a file", "inputSchema": _PATH},
    {"name": "secret_tool", "description": "Not declared in any manifest", "inputSchema": _PATH},
]


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        method = message.get("method")
        if "id" not in message:
            continue  # a notification
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "echo-mcp-server", "version": "0.1.0"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            arguments = (message.get("params") or {}).get("arguments", {})
            result = {"content": [{"type": "text", "text": json.dumps(arguments, sort_keys=True)}]}
        else:
            result = {}
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
