# Changelog

## 1.2.0

- `skynt protect` warns when it runs from a project's virtual environment. Protected
  configs point at that environment, so deleting it would break every protected server.
  pipx and uv tool installs are recognized as safe.
- Running `skynt protect` again moves already protected servers to the current
  installation and policy, instead of skipping them.
- The README installs from PyPI: `pipx install skynt`.

## 1.1.0

- `skynt protect` and `skynt unprotect` route the MCP servers of Claude Code, Claude Desktop,
  Cursor, VS Code and Windsurf through skynt, with a backup of every file.
- Ready-made `balanced` and `strict` policies, created on first use.
- `skynt log` shows what your AI did.
- Rules accept lists of patterns and match tool names ignoring case.
- First release on PyPI.

## 1.0.0

- Stdio gateway that checks every MCP tool call against a policy: allow, deny, or confirm
  with the user through MCP elicitation.
- Denied tools are hidden from the AI. Calls are validated against the server's own schema.
- Append-only audit log. Fails closed on malformed input and internal errors.
