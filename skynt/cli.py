"""skynt command line."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from skynt import __version__, clients, logview, presets
from skynt.audit import Audit
from skynt.policy import Policy
from skynt.proxy import Gateway

SHUTDOWN_GRACE_SECONDS = 5
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_UPSTREAM_NOT_FOUND = 127
DISPOSABLE_VENV_WARNING = """\
skynt: warning: skynt is running from a virtual environment:
  {prefix}
Your AI apps will start skynt from there. If that environment is deleted, their MCP
servers stop working. To avoid this, install skynt on its own and protect again:
  pipx install skynt"""


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    return options.handler(options)


def cmd_init(options) -> int:
    path = _policy_path(options)
    if not presets.write_policy(path, options.preset, options.force):
        print(f"skynt: {path} already exists (use --force to replace it)")
        return EXIT_FAILURE
    print(f"skynt: created {path} ({options.preset} preset)")
    return 0


def cmd_protect(options) -> int:
    policy_path = _policy_path(options).resolve()
    if presets.write_policy(policy_path, "balanced"):
        print(f"skynt: created policy {policy_path} (balanced preset)")
    if _load_policy(policy_path) is None or not _launcher_works():
        return EXIT_USAGE
    if clients.in_disposable_venv(sys.prefix, sys.base_prefix):
        print(DISPOSABLE_VENV_WARNING.format(prefix=sys.prefix))
    launcher = clients.Launcher(sys.executable, str(policy_path))
    return _apply_to_configs(options, lambda path: clients.protect_file(path, launcher), "protected")


def cmd_unprotect(options) -> int:
    return _apply_to_configs(options, clients.unprotect_file, "restored")


def cmd_log(options) -> int:
    policy = _load_policy(_policy_path(options))
    if policy is None:
        return EXIT_USAGE
    audit = Path(policy.audit_log)
    if not audit.exists():
        print(f"skynt: no activity yet ({audit})")
        return 0
    sys.stdout.reconfigure(errors="replace")
    for record in logview.tail(audit, options.lines):
        print(logview.format_record(record))
    return 0


def cmd_check(options) -> int:
    path = _policy_path(options)
    policy = _load_policy(path)
    if policy is None:
        return EXIT_USAGE
    print(f"skynt: policy ok ({len(policy.rules)} rules, default {policy.default}) at {path}")
    return 0


def cmd_run(options) -> int:
    command = options.upstream[1:] if options.upstream[:1] == ["--"] else options.upstream
    if not command:
        print("skynt: missing MCP server command after --", file=sys.stderr)
        return EXIT_USAGE
    if options.policy is None and presets.write_policy(presets.default_policy_path(), "balanced"):
        print(f"skynt: created policy {presets.default_policy_path()} (balanced preset)", file=sys.stderr)
    policy = _load_policy(_policy_path(options), stream=sys.stderr)
    return EXIT_USAGE if policy is None else _serve(policy, command)


def _serve(policy: Policy, command: list[str]) -> int:
    # which() resolves Windows shims such as npx.cmd that CreateProcess cannot find alone.
    executable = shutil.which(command[0]) or command[0]
    try:
        upstream = subprocess.Popen([executable, *command[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as error:
        print(f"skynt: cannot start MCP server {command[0]!r}: {error}", file=sys.stderr)
        return EXIT_UPSTREAM_NOT_FOUND
    streams = {"client_in": sys.stdin.buffer, "client_out": sys.stdout.buffer}
    Gateway(policy, Audit(policy.audit_log), upstream_in=upstream.stdin, upstream_out=upstream.stdout, **streams).run()
    try:
        return upstream.wait(timeout=SHUTDOWN_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        upstream.kill()
        return upstream.wait()


def _apply_to_configs(options, change, verb: str) -> int:
    configs = [Path(p) for p in options.configs] or _discovered_configs()
    if not configs:
        print("skynt: no MCP config found. Pass one explicitly: skynt protect path/to/mcp.json")
        return EXIT_FAILURE
    failures = 0
    for path in configs:
        try:
            _print_report(change(path), verb)
        except clients.ConfigError as error:
            print(f"skynt: {error}")
            failures += 1
    print("\nRestart your AI app to apply the change. See what it does with: skynt log")
    return EXIT_FAILURE if failures else 0


def _print_report(report: clients.Report, verb: str) -> None:
    print(f"\n{report.path}")
    for name in report.changed:
        print(f"  {verb:<10} {name}")
    for name, reason in report.skipped:
        print(f"  {'skipped':<10} {name}: {reason}")
    if not report.changed and not report.skipped:
        print("  nothing to change")


def _discovered_configs() -> list[Path]:
    appdata = os.environ.get("APPDATA")
    return clients.known_configs(Path.home(), Path.cwd(), Path(appdata) if appdata else None)


def _launcher_works() -> bool:
    # A wrapped config runs `python -m skynt` from anywhere, so a source checkout that is not installed would break every server.
    probe = subprocess.run([sys.executable, "-m", "skynt", "--version"], cwd=tempfile.gettempdir(), capture_output=True)
    if probe.returncode != 0:
        print("skynt: skynt is not installed for this Python. Install it first (see README), then run protect again.")
    return probe.returncode == 0


def _policy_path(options) -> Path:
    return Path(options.policy).expanduser() if options.policy else presets.default_policy_path()


def _load_policy(path: Path, stream=sys.stdout) -> Policy | None:
    try:
        return Policy.from_toml(path)
    except FileNotFoundError:
        print(f"skynt: no policy at {path}. Create one with: skynt init", file=stream)
    except (OSError, ValueError) as error:
        print(f"skynt: invalid policy {path}: {error}", file=stream)
    return None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skynt", description="Stay in control of what your AI does through MCP.")
    parser.add_argument("--version", action="version", version=f"skynt {__version__}")
    parser.set_defaults(handler=lambda _: parser.print_help() or EXIT_USAGE)
    commands = parser.add_subparsers(title="commands", metavar="<command>")
    for name, handler, text in COMMANDS:
        command = commands.add_parser(name, help=text, description=text)
        command.add_argument("--policy", help=f"policy file (default: {presets.default_policy_path()})")
        command.set_defaults(handler=handler)
    choices = commands.choices
    choices["protect"].add_argument("configs", nargs="*", help="MCP config files (default: detect)")
    choices["unprotect"].add_argument("configs", nargs="*", help="MCP config files (default: detect)")
    choices["init"].add_argument("--preset", choices=sorted(presets.PRESETS), default="balanced")
    choices["init"].add_argument("--force", action="store_true", help="replace an existing policy")
    choices["log"].add_argument("-n", "--lines", type=int, default=30, help="how many entries to show")
    choices["run"].add_argument("upstream", nargs=argparse.REMAINDER, help="-- <MCP server command>")
    return parser


COMMANDS = [
    ("protect", cmd_protect, "put the MCP servers of your AI apps behind skynt"),
    ("unprotect", cmd_unprotect, "remove skynt from your AI apps"),
    ("init", cmd_init, "create a policy file"),
    ("log", cmd_log, "show what your AI did"),
    ("check", cmd_check, "validate the policy"),
    ("run", cmd_run, "run one MCP server behind skynt"),
]
