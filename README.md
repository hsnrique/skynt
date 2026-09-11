# skynt

**Your AI works freely. You stay in control.**

skynt sits between any MCP client and any MCP server. The agent keeps every capability
you grant it and nothing you don't: each tool call is checked against your policy,
validated against the server's own schema, optionally approved by a human, and written
to an audit log. It works with any model and any client that speaks MCP.

Zero runtime dependencies. Python 3.11+.

## How it works

```
agent / MCP client  <-- stdio -->  skynt  <-- stdio -->  MCP server
                                     |
                              policy.toml  +  audit.jsonl
```

For every `tools/call`, skynt decides one of:

| Decision | What happens |
|----------|--------------|
| `allow` | Forwarded to the server. |
| `deny` | Answered locally with an error the model can read. The tool is also hidden from `tools/list`. |
| `confirm` | skynt asks the human through MCP elicitation, showing the exact tool and arguments. Only an explicit approval forwards the call. |

Calls are also refused when the tool was never advertised by the server, or when the
arguments break the server's advertised input schema.

## Install

```bash
pip install .
```

## Run

```bash
skynt --policy policy.toml -- npx -y @modelcontextprotocol/server-filesystem@2026.8.31 ./workspace
```

In a client config such as Claude Code's `.mcp.json`, replace the server command with skynt:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "skynt",
      "args": ["--policy", "policy.toml", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "./workspace"]
    }
  }
}
```

Remote (HTTP) servers go through the `mcp-remote` bridge as the upstream command:

```bash
skynt --policy policy.toml -- npx -y mcp-remote@0.13.5 https://example.com/mcp
```

Validate a policy without starting anything:

```bash
skynt --policy policy.toml --check
```

## Policy

```toml
default = "deny"                  # allow | deny | confirm, for tools no rule matches
audit_log = "skynt-audit.jsonl"

[[rules]]                         # first match wins; case-sensitive glob on the tool name
match = "read_*"
action = "allow"

[[rules]]
match = "execute_sql"
action = "allow"
deny_if_args_match = '(?i)\b(drop|truncate|delete|alter)\b'   # regex over the JSON arguments

[[rules]]
match = "write_*"
action = "confirm"
```

Unknown keys, missing actions and invalid regexes are rejected at startup, so a typo
never silently becomes a rule.

## Audit log

One JSON object per line, file created with `0600` permissions:

```json
{"ts": "2026-09-11T13:24:01+00:00", "request_id": 5, "tool": "write_file", "arguments": {"path": "a.txt"}, "decision": "confirmed", "reason": "human answer"}
```

If the audit write fails, the call is not forwarded.

## Guarantees

- **Fail closed.** Invalid JSON, JSON-RPC batches, oversized messages (4 MiB), malformed
  tool calls and internal errors are rejected, never forwarded.
- **No parser differentials.** The server only receives messages skynt re-serialized
  itself, so duplicate keys or odd encodings cannot make it run something other than
  what the policy evaluated.
- **Unforgeable approvals.** Confirmation requests use random ids, so a server cannot
  pre-send a look-alike question and harvest the user's answer.
- **What you approve is what runs.** Arguments are shown in full; calls whose arguments
  are too large to display are refused instead of truncated.

## Limits

- skynt governs MCP tools only. Built-in tools of the client (a shell, a file editor)
  bypass it; disable them in the client if you need full coverage.
- `deny_if_args_match` is a tripwire, not a security boundary: regexes over arguments
  can be evaded (dynamic SQL, encodings). For hard guarantees use `deny` or `confirm`,
  and give the server least-privilege credentials.
- Tool results are passed back unmodified. Prompt injection inside results is out of scope.
- Schema validation covers top-level `required`, `type` and `additionalProperties`.

## Development

```bash
pip install pytest==9.1.1 hypothesis==6.168.0
python -m pytest
```

The suite includes property-based tests (Hypothesis) that drive random mixes of allowed,
denied and confirmed calls, answered in random order, through real OS pipes.

## License

Apache-2.0. Copyright 2026 Henrique Martins. The name "skynt" is not covered by the
license; forks must use a different name. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
