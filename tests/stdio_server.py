"""Tiny MCP-shaped stdio server used by the CLI end-to-end tests."""
import json
import sys

TOOLS = [
    {"name": "read_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "delete_file"},
]

for line in sys.stdin.buffer:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message["method"]
    result = {"tools": TOOLS} if method == "tools/list" else {"content": [{"type": "text", "text": f"ran {method}"}]}
    sys.stdout.buffer.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode() + b"\n")
    sys.stdout.buffer.flush()
