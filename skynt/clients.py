"""Put existing MCP client configs behind skynt, and take them back out.

Every client stores servers as {"command": ..., "args": [...]} under
"mcpServers" (VS Code uses "servers"), so one wrapper covers them all.
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

SERVER_KEYS = ("mcpServers", "servers")
REMOTE_TYPES = frozenset({"http", "sse", "streamable-http"})
BACKUP_SUFFIX = ".skynt-backup"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Launcher:
    python: str
    policy: str

    def wrap(self, entry: dict) -> dict:
        # The absolute interpreter path works even for GUI apps that do not inherit your shell PATH.
        args = ["-m", "skynt", "run", "--policy", self.policy, "--", entry["command"], *entry.get("args", [])]
        return {**entry, "command": self.python, "args": args}


@dataclass
class Report:
    path: Path
    changed: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)


def known_configs(home: Path, cwd: Path, appdata: Path | None) -> list[Path]:
    candidates = [
        cwd / ".mcp.json",
        cwd / ".cursor" / "mcp.json",
        cwd / ".vscode" / "mcp.json",
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        home / ".config" / "Claude" / "claude_desktop_config.json",
    ]
    if appdata:
        candidates.append(appdata / "Claude" / "claude_desktop_config.json")
    return [path for path in dict.fromkeys(candidates) if path.is_file()]


def is_wrapped(entry: dict) -> bool:
    args = entry.get("args")
    return isinstance(args, list) and args[:3] == ["-m", "skynt", "run"] and "--" in args


def unwrap(entry: dict) -> dict:
    args = entry["args"]
    original = args[args.index("--") + 1:]
    return {**entry, "command": original[0], "args": original[1:]}


def protect_file(path: Path, launcher: Launcher) -> Report:
    config = _load(path)
    report = Report(path)
    for name, entry in _servers(config).items():
        reason = _cannot_wrap(entry)
        if reason:
            report.skipped.append((name, reason))
            continue
        _servers(config)[name] = launcher.wrap(entry)
        report.changed.append(name)
    _save_if_changed(path, config, report)
    return report


def unprotect_file(path: Path) -> Report:
    config = _load(path)
    report = Report(path)
    for name, entry in _servers(config).items():
        if isinstance(entry, dict) and is_wrapped(entry):
            _servers(config)[name] = unwrap(entry)
            report.changed.append(name)
    _save_if_changed(path, config, report)
    return report


def _cannot_wrap(entry) -> str | None:
    if not isinstance(entry, dict):
        return "not a server entry"
    if is_wrapped(entry):
        return "already protected"
    if "url" in entry or entry.get("type") in REMOTE_TYPES:
        return "remote server, wrap it with mcp-remote (see README)"
    args = entry.get("args", [])
    if not isinstance(entry.get("command"), str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return "unrecognized command format"
    return None


def _load(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        # JSON with comments lands here too; rewriting it would drop the user's comments.
        raise ConfigError(f"{path}: cannot read as plain JSON ({error}); left untouched") from error
    if not isinstance(config, dict) or not any(isinstance(config.get(k), dict) for k in SERVER_KEYS):
        raise ConfigError(f"{path}: no MCP servers found; left untouched")
    return config


def _servers(config: dict) -> dict:
    return next(config[k] for k in SERVER_KEYS if isinstance(config.get(k), dict))


def _save_if_changed(path: Path, config: dict, report: Report) -> None:
    if not report.changed:
        return
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if not backup.exists():
        shutil.copy2(path, backup)  # keep the pristine original, never overwrite it
    temporary = path.with_name(path.name + ".skynt-tmp")
    temporary.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
