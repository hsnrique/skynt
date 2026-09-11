# Security policy

skynt is a security boundary, so reports are taken seriously.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private reporting instead:
**Security** tab, then **Report a vulnerability**.

Include what you did, what you expected, and what happened. A minimal policy file and
the JSON-RPC messages that trigger the problem help the most.

## Scope

In scope: any way to make a tool call reach the MCP server without the decision the
policy and the user made, to forge or bypass a confirmation, to crash the gateway, or to
make `skynt protect` damage a config file.

Out of scope: evading `deny_if_args_match` patterns, which the README documents as a
tripwire rather than a boundary.

## Supported versions

Only the latest release receives fixes.
