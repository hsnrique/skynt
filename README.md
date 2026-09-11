# mcpgate

A policy-enforcing proxy that sits between an MCP client and an MCP server over stdio.
Every `tools/call` is checked against a TOML policy, validated against the schema the
server itself advertised, and written to an append-only JSONL audit log. Everything
else is forwarded byte-for-byte.

Zero runtime dependencies. Python 3.11+.

## Run

```bash
python -m mcpgate --policy policy.example.toml -- npx -y @modelcontextprotocol/server-filesystem .
```

Point your MCP client at that command instead of the server directly.

## Policy

```toml
default = "deny"                 # allow | deny | confirm
audit_log = "mcpgate-audit.jsonl"

[[rules]]                        # first match wins, case-sensitive glob on tool name
match = "read_*"
action = "allow"

[[rules]]
match = "execute_sql"
action = "allow"
deny_if_args_match = '(?i)\b(drop|truncate|delete|alter)\b'   # regex over the JSON-encoded arguments

[[rules]]
match = "delete_*"
action = "confirm"
```

## What gets blocked

- Tool not matched by any rule and `default = "deny"`.
- Tool the upstream never advertised in `tools/list` (fail closed).
- Arguments that fail the advertised schema (required keys, top-level types, additionalProperties).
- Arguments matching `deny_if_args_match`.
- `confirm` tools, until an interactive confirmation channel exists.

A blocked call returns an `isError` tool result explaining why, so the model can tell the user.

## Test

```bash
pip install pytest==9.1.1 hypothesis==6.168.0
python -m pytest
```
