from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

ACTIONS = frozenset({"allow", "deny", "confirm"})


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str

    @property
    def forwards(self) -> bool:
        return self.action == "allow"


@dataclass(frozen=True)
class Rule:
    match: str
    action: str
    deny_if_args_match: re.Pattern | None = None

    @classmethod
    def from_dict(cls, raw: dict) -> "Rule":
        action = raw.get("action", "deny")
        if action not in ACTIONS:
            raise ValueError(f"rule {raw.get('match')!r}: unknown action {action!r}")
        pattern = raw.get("deny_if_args_match")
        return cls(
            match=str(raw["match"]),
            action=action,
            deny_if_args_match=re.compile(pattern) if pattern else None,
        )

    def evaluate(self, tool: str, args: dict) -> Decision:
        if self.deny_if_args_match and self.deny_if_args_match.search(json.dumps(args)):
            return Decision("deny", f"{tool}: arguments match denied pattern")
        return Decision(self.action, f"{tool}: rule {self.match!r} -> {self.action}")


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...] = ()
    default: str = "deny"
    audit_log: str = "mcpgate-audit.jsonl"

    @classmethod
    def from_toml(cls, path: Path | str) -> "Policy":
        return cls.from_dict(tomllib.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_dict(cls, raw: dict) -> "Policy":
        default = raw.get("default", "deny")
        if default not in ACTIONS:
            raise ValueError(f"unknown default action {default!r}")
        return cls(
            rules=tuple(Rule.from_dict(r) for r in raw.get("rules", [])),
            default=default,
            audit_log=raw.get("audit_log", cls.audit_log),
        )

    def decide(self, tool: str, args: dict) -> Decision:
        for rule in self.rules:
            if fnmatch.fnmatchcase(tool, rule.match):
                return rule.evaluate(tool, args)
        return Decision(self.default, f"{tool}: no rule matched, default {self.default}")
