"""Usage: python -m mcpgate --policy policy.toml -- <upstream command...>"""
from __future__ import annotations

import argparse
import subprocess
import sys

from mcpgate.audit import Audit
from mcpgate.policy import Policy
from mcpgate.proxy import Gateway


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcpgate", description=__doc__)
    parser.add_argument("--policy", required=True, help="path to a TOML policy file")
    parser.add_argument("upstream", nargs=argparse.REMAINDER, help="upstream MCP server command")
    options = parser.parse_args(argv)
    command = [part for part in options.upstream if part != "--"]
    if not command:
        parser.error("missing upstream command after --")
    policy = Policy.from_toml(options.policy)
    upstream = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    Gateway(
        policy,
        Audit(policy.audit_log),
        client_in=sys.stdin.buffer,
        client_out=sys.stdout.buffer,
        upstream_in=upstream.stdin,
        upstream_out=upstream.stdout,
    ).run()
    return upstream.wait()


if __name__ == "__main__":
    sys.exit(main())
