import pytest

from mcpgate.policy import Policy


def policy(**overrides) -> Policy:
    raw = {
        "default": "deny",
        "rules": [
            {"match": "read_*", "action": "allow"},
            {"match": "execute_sql", "action": "allow", "deny_if_args_match": r"(?i)\bdrop\b"},
            {"match": "delete_*", "action": "confirm"},
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


def test_match_is_case_sensitive_glob():
    assert policy().decide("READ_file", {}).action == "deny"


def test_invalid_actions_are_rejected():
    with pytest.raises(ValueError):
        Policy.from_dict({"rules": [{"match": "x", "action": "maybe"}]})
    with pytest.raises(ValueError):
        Policy.from_dict({"default": "maybe"})


def test_from_toml(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text('default = "allow"\naudit_log = "x.jsonl"\n[[rules]]\nmatch = "rm_*"\naction = "deny"\n')
    loaded = Policy.from_toml(path)
    assert loaded.audit_log == "x.jsonl"
    assert loaded.decide("rm_rf", {}).action == "deny"
    assert loaded.decide("anything", {}).action == "allow"
