# skynt

**Your AI works freely. You stay in control.**

AI agents don't just answer anymore. Through MCP tools they delete files, run SQL,
send messages and deploy code. skynt sits between your AI app and those tools, so
every action goes through your rules first: safe actions run, risky ones ask you,
and everything is logged. It works with any model and any app that speaks MCP.

## Quick start

You need Python 3.11 or newer. Then:

**1. Install**

```bash
pipx install skynt
```

Using [uv](https://docs.astral.sh/uv/)? `uv tool install skynt` works too. Plain `pip install skynt` also works.

**2. Protect your AI apps**

```bash
skynt protect
```

skynt finds the MCP configs of Claude Desktop, Cursor and Windsurf, plus the project configs
of Claude Code, Cursor and VS Code in the current folder, and routes every local MCP server
through itself. It saves a backup of each file first. Run it inside your project folder to
cover that project too.

**3. Restart your AI app.** That's it.

**4. See what your AI did**

```bash
skynt log
```

```
2026-09-11 11:05:07  allow               read_text_file               {"path": "hello.txt"}
2026-09-11 11:05:07  confirm             write_file                   {"path": "note.txt", "content": "hi"}
2026-09-11 11:05:07  confirmed           write_file                   {"path": "note.txt", "content": "hi"}
```

To undo everything: `skynt unprotect`.

## What happens to each action

Your rules live in `~/.skynt/policy.toml`, created on first use with the **balanced** preset:

| Your AI tries to... | skynt |
|---------------------|-------|
| Read, list, search, create or edit | Lets it run |
| Delete, drop, wipe, reset, revoke, kill | Asks you first |
| Run commands or SQL, send, push, merge, deploy, publish, pay | Asks you first |

Three possible decisions:

- **allow** runs the action normally.
- **confirm** shows you the exact action and its arguments, and runs it only if you approve.
  If your app cannot show that prompt, the action is blocked and the AI is told why.
- **deny** blocks the action and hides the tool from the AI entirely.

Want every non-read action to ask you? Switch to the strict preset:

```bash
skynt init --preset strict --force
```

## Change the rules

Open `~/.skynt/policy.toml` in any editor. Rules are checked top to bottom and the first
match wins. Tool names are matched ignoring case, and `*` means "anything".

```toml
default = "allow"                  # for tools no rule matches

[[rules]]
match = ["*delete*", "*drop*"]
action = "confirm"

[[rules]]
match = "execute_sql"
action = "allow"
deny_if_args_match = '(?i)\b(drop|truncate)\b'   # block when the arguments contain this

[[rules]]
match = "send_email"
action = "deny"
```

Check your file before restarting the app:

```bash
skynt check
```

## Apps and servers

- **Config files** are handled by `skynt protect`: `.mcp.json` (Claude Code), `.cursor/mcp.json`,
  `.vscode/mcp.json`, Claude Desktop, and Windsurf. Pass a path to protect any other file:
  `skynt protect path/to/mcp.json`.
- **Servers added with `claude mcp add`** go through skynt like this:

  ```bash
  claude mcp add filesystem -- skynt run -- npx -y @modelcontextprotocol/server-filesystem@2026.8.31 .
  ```

- **Remote servers** (a URL instead of a command) go through the `mcp-remote` bridge:

  ```bash
  skynt run -- npx -y mcp-remote@0.13.5 https://example.com/mcp
  ```

## Commands

| Command | What it does |
|---------|--------------|
| `skynt protect [files]` | Route the MCP servers of your AI apps through skynt |
| `skynt unprotect [files]` | Put the original configs back |
| `skynt log [-n 30]` | Show the latest actions and decisions |
| `skynt init [--preset balanced\|strict]` | Create the policy file |
| `skynt check` | Validate the policy file |
| `skynt run -- <command>` | Run one MCP server through skynt |

Every command takes `--policy path/to/policy.toml` to use a different policy.

## Guarantees

- **Fail closed.** Invalid JSON, JSON-RPC batches, oversized messages (4 MiB), malformed
  tool calls, audit write failures and internal errors are rejected, never forwarded.
- **What was checked is what runs.** The server only receives messages skynt re-serialized
  itself, so duplicate keys or odd encodings cannot smuggle a different call through.
- **Only real tools.** Calls to tools the server never advertised are refused, and
  arguments are validated against the server's own input schema.
- **Honest approvals.** You see the full arguments; calls too large to display are refused
  instead of truncated. Approval requests use random ids that a server cannot forge.
- **Private log.** The audit file is created readable only by you, and relative log paths
  resolve next to the policy file.

## Limits

- skynt covers MCP tools. Built-in tools of your app (its own shell or file editor) do not
  go through MCP, so review those in the app's own settings.
- `deny_if_args_match` is a tripwire, not a wall: text patterns can be worked around. For
  hard guarantees use `confirm` or `deny`, and give servers least-privilege credentials.
- Results coming back from tools are passed through unchanged.
- Configs written as JSON with comments are left untouched; protect those servers with `skynt run`.

## Development

```bash
pip install -e . pytest==9.1.1 hypothesis==6.168.0
python -m pytest
```

Zero runtime dependencies. The suite includes property-based tests that drive random mixes
of allowed, denied and confirmed calls, answered in random order, through real OS pipes.

## Security

Found a vulnerability? Please report it privately, see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. Copyright 2026 Henrique Martins. The name "skynt" is not covered by the
license; forks must use a different name. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
