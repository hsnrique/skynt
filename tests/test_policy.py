from pathlib import Path

import pytest

from skynt.policy import Policy


def policy(**overrides) -> Policy:
    raw = {
        "default": "deny",
        "rules": [
            {"match": "read_*", "action": "allow"},
            {"match": "execute_sql", "action": "allow", "deny_if_args_match": r"(?i)\bdrop\b"},
            {"match": "delete_*", "action": "confirm"},
            {"match": "rm_*", "action": "deny"},
        ],
    }
    return Policy.from_dict({**raw, **overrides})


def test_first_matching_rule_wins():
    assert policy().decide("read_file", {}).action == "allow"
    assert policy().decide("delete_file", {}).action == "confirm"


def test_default_applies_when_nothing_matches():
    assert policy().decide("launch_missiles", {}).action == "deny"
    assert policy(default="allow").decide("launch_missiles", {}).action == "allow"


def test_argument_pattern_downgrades_to_deny():
    assert policy().decide("execute_sql", {"query": "select 1"}).action == "allow"
    assert policy().decide("execute_sql", {"query": "DROP TABLE users"}).action == "deny"


def test_argument_pattern_sees_unicode_unescaped():
    strict = Policy.from_dict({"rules": [{"match": "say", "action": "allow", "deny_if_args_match": "Straße"}]})
    assert strict.decide("say", {"text": "Straße"}).action == "deny"


def test_match_ignores_case():
    assert policy().decide("READ_file", {}).action == "allow"
    assert policy().decide("bulkDelete", {}).action == "deny"
    assert Policy.from_dict({"rules": [{"match": "*delete*", "action": "confirm"}]}).decide("bulkDelete", {}).action == "confirm"


def test_match_accepts_a_list_and_reports_the_pattern_that_hit():
    rules = Policy.from_dict({"rules": [{"match": ["*drop*", "*wipe*"], "action": "deny"}]})
    decision = rules.decide("wipe_disk", {})
    assert decision.action == "deny" and "'*wipe*'" in decision.reason


def test_visibility_hides_only_denied_tools():
    assert policy().visible("read_file") and policy().visible("delete_file") and policy().visible("execute_sql")
    assert not policy().visible("rm_rf") and not policy().visible("unknown")
    assert policy(default="confirm").visible("unknown")


@pytest.mark.parametrize("raw", [
    {"rules": [{"match": "x", "action": "maybe"}]},
    {"rules": [{"match": "x"}]},
    {"rules": [{"match": "x", "acton": "allow"}]},
    {"rules": [{"action": "allow"}]},
    {"rules": [{"match": [], "action": "allow"}]},
    {"rules": [{"match": ["ok", 3], "action": "allow"}]},
    {"rules": [{"match": "x", "action": "allow", "deny_if_args_match": "("}]},
    {"default": "maybe"},
    {"defualt": "allow"},
])
def test_invalid_policies_are_rejected(raw):
    with pytest.raises(ValueError):
        Policy.from_dict(raw)


def test_from_toml(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text('default = "allow"\naudit_log = "x.jsonl"\n[[rules]]\nmatch = "rm_*"\naction = "deny"\n')
    loaded = Policy.from_toml(path)
    assert loaded.audit_log == str(tmp_path.resolve() / "x.jsonl")
    assert loaded.decide("rm_rf", {}).action == "deny"
    assert loaded.decide("anything", {}).action == "allow"


def test_absolute_audit_path_is_kept(tmp_path):
    target = (tmp_path / "logs" / "a.jsonl").as_posix()
    path = tmp_path / "policy.toml"
    path.write_text(f'audit_log = "{target}"\n')
    assert Path(Policy.from_toml(path).audit_log) == Path(target)
