from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from dataclasses import dataclass, replace
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
    patterns: tuple[str, ...]
    action: str
    deny_if_args_match: re.Pattern | None = None

    @classmethod
    def from_dict(cls, raw: dict) -> "Rule":
        where = f"rule {raw.get('match')!r}"
        _reject_unknown_keys(raw, RULE_KEYS, where)
        return cls(_patterns(raw.get("match"), where), _action(raw.get("action"), where), _regex(raw.get("deny_if_args_match")))

    def pattern_for(self, tool: str) -> str | None:
        # Case-insensitive so one pattern covers delete_file, deleteFile and bulkDelete.
        name = tool.casefold()
        return next((p for p in self.patterns if fnmatch.fnmatchcase(name, p.casefold())), None)

    def evaluate(self, tool: str, args: dict, pattern: str) -> Decision:
        if self.deny_if_args_match and self.deny_if_args_match.search(json.dumps(args, ensure_ascii=False)):
            return Decision("deny", f"{tool}: arguments match denied pattern")
        return Decision(self.action, f"{tool}: rule {pattern!r} -> {self.action}")


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...] = ()
    default: str = "deny"
    audit_log: str = "skynt-audit.jsonl"

    @classmethod
    def from_toml(cls, path: Path | str) -> "Policy":
        path = Path(path)
        policy = cls.from_dict(tomllib.loads(path.read_text(encoding="utf-8")))
        # Relative to the policy file, because MCP clients start servers from unpredictable directories.
        audit = Path(policy.audit_log).expanduser()
        return replace(policy, audit_log=str(audit if audit.is_absolute() else path.resolve().parent / audit))

    @classmethod
    def from_dict(cls, raw: dict) -> "Policy":
        _reject_unknown_keys(raw, POLICY_KEYS, "policy")
        return cls(
            rules=tuple(Rule.from_dict(r) for r in raw.get("rules", [])),
            default=_action(raw.get("default", "deny"), "default"),
            audit_log=str(raw.get("audit_log", cls.audit_log)),
        )

    def decide(self, tool: str, args: dict) -> Decision:
        for rule in self.rules:
            pattern = rule.pattern_for(tool)
            if pattern is not None:
                return rule.evaluate(tool, args, pattern)
        return Decision(self.default, f"{tool}: no rule matched, default {self.default}")

    def visible(self, tool: str) -> bool:
        rule = next((r for r in self.rules if r.pattern_for(tool) is not None), None)
        return (rule.action if rule else self.default) != "deny"


def _patterns(value, where: str) -> tuple[str, ...]:
    patterns = [value] if isinstance(value, str) else value
    if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) and p for p in patterns):
        raise ValueError(f"{where}: 'match' must be a pattern or a non-empty list of patterns")
    return tuple(patterns)


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
