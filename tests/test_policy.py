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


def test_match_is_case_sensitive_glob():
    assert policy().decide("READ_file", {}).action == "deny"


def test_visibility_hides_only_denied_tools():
    assert policy().visible("read_file") and policy().visible("delete_file") and policy().visible("execute_sql")
    assert not policy().visible("rm_rf") and not policy().visible("unknown")
    assert policy(default="confirm").visible("unknown")


@pytest.mark.parametrize("raw", [
    {"rules": [{"match": "x", "action": "maybe"}]},
    {"rules": [{"match": "x"}]},
    {"rules": [{"match": "x", "acton": "allow"}]},
    {"rules": [{"action": "allow"}]},
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
    assert loaded.audit_log == "x.jsonl"
    assert loaded.decide("rm_rf", {}).action == "deny"
    assert loaded.decide("anything", {}).action == "allow"
