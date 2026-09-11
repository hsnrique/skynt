"""Usage: skynt --policy policy.toml -- <upstream MCP server command...>"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

from skynt.audit import Audit
from skynt.policy import Policy
from skynt.proxy import Gateway

SHUTDOWN_GRACE_SECONDS = 5
EXIT_BAD_POLICY = 2
EXIT_UPSTREAM_NOT_FOUND = 127


def main(argv: list[str] | None = None) -> int:
    options = _parse_args(argv)
    try:
        policy = Policy.from_toml(options.policy)
    except (OSError, ValueError) as error:
        print(f"skynt: invalid policy {options.policy}: {error}", file=sys.stderr)
        return EXIT_BAD_POLICY
    if options.check:
        print(f"skynt: policy ok ({len(policy.rules)} rules, default {policy.default})")
        return 0
    return _serve(policy, options.upstream)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="skynt", description=__doc__)
    parser.add_argument("--policy", required=True, help="path to a TOML policy file")
    parser.add_argument("--check", action="store_true", help="validate the policy and exit")
    parser.add_argument("upstream", nargs=argparse.REMAINDER, help="upstream MCP server command, after --")
    options = parser.parse_args(argv)
    options.upstream = options.upstream[1:] if options.upstream[:1] == ["--"] else options.upstream
    if not options.check and not options.upstream:
        parser.error("missing upstream command after --")
    return options


def _serve(policy: Policy, command: list[str]) -> int:
    # which() resolves Windows shims such as npx.cmd that CreateProcess cannot find alone.
    executable = shutil.which(command[0]) or command[0]
    try:
        upstream = subprocess.Popen([executable, *command[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as error:
        print(f"skynt: cannot start upstream {command[0]!r}: {error}", file=sys.stderr)
        return EXIT_UPSTREAM_NOT_FOUND
    streams = {"client_in": sys.stdin.buffer, "client_out": sys.stdout.buffer}
    Gateway(policy, Audit(policy.audit_log), upstream_in=upstream.stdin, upstream_out=upstream.stdout, **streams).run()
    try:
        return upstream.wait(timeout=SHUTDOWN_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        upstream.kill()
        return upstream.wait()


if __name__ == "__main__":
    sys.exit(main())
