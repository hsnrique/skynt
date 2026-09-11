from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

ACTIONS = frozenset({"allow", "deny", "confirm"})
RULE_KEYS = frozenset({"match", "action", "deny_if_args_match"})
POLICY_KEYS = frozenset({"default", "audit_log", "rules"})


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str


@dataclass(frozen=True)
class Rule:
    match: str
    action: str
    deny_if_args_match: re.Pattern | None = None

    @classmethod
    def from_dict(cls, raw: dict) -> "Rule":
        _reject_unknown_keys(raw, RULE_KEYS, f"rule {raw.get('match')!r}")
        if not isinstance(raw.get("match"), str):
            raise ValueError(f"rule {raw!r}: 'match' must be a string")
        action = _action(raw.get("action"), f"rule {raw['match']!r}")
        return cls(raw["match"], action, _regex(raw.get("deny_if_args_match")))

    def evaluate(self, tool: str, args: dict) -> Decision:
        if self.deny_if_args_match and self.deny_if_args_match.search(json.dumps(args, ensure_ascii=False)):
            return Decision("deny", f"{tool}: arguments match denied pattern")
        return Decision(self.action, f"{tool}: rule {self.match!r} -> {self.action}")


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...] = ()
    default: str = "deny"
    audit_log: str = "skynt-audit.jsonl"

    @classmethod
    def from_toml(cls, path: Path | str) -> "Policy":
        return cls.from_dict(tomllib.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_dict(cls, raw: dict) -> "Policy":
        _reject_unknown_keys(raw, POLICY_KEYS, "policy")
        return cls(
            rules=tuple(Rule.from_dict(r) for r in raw.get("rules", [])),
            default=_action(raw.get("default", "deny"), "default"),
            audit_log=str(raw.get("audit_log", cls.audit_log)),
        )

    def rule_for(self, tool: str) -> Rule | None:
        return next((rule for rule in self.rules if fnmatch.fnmatchcase(tool, rule.match)), None)

    def decide(self, tool: str, args: dict) -> Decision:
        rule = self.rule_for(tool)
        if rule is None:
            return Decision(self.default, f"{tool}: no rule matched, default {self.default}")
        return rule.evaluate(tool, args)

    def visible(self, tool: str) -> bool:
        rule = self.rule_for(tool)
        return (rule.action if rule else self.default) != "deny"


def _action(value, where: str) -> str:
    # A missing action is an error, not a silent deny: a typo must not look like a working rule.
    if value not in ACTIONS:
        raise ValueError(f"{where}: action must be one of {sorted(ACTIONS)}, got {value!r}")
    return value


def _regex(pattern) -> re.Pattern | None:
    if pattern is None:
        return None
    try:
        return re.compile(pattern)
    except (re.error, TypeError) as error:
        raise ValueError(f"invalid deny_if_args_match {pattern!r}: {error}") from error


def _reject_unknown_keys(raw: dict, allowed: frozenset, where: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"{where}: unknown keys {sorted(unknown)}")
