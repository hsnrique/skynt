import tomllib

import pytest

from skynt import presets
from skynt.policy import Policy


def load(preset: str) -> Policy:
    return Policy.from_dict(tomllib.loads(presets.render(preset)))


@pytest.mark.parametrize("tool", ["delete_file", "bulkDelete", "drop_table", "execute_sql", "send_email", "push_files", "deploy"])
def test_both_presets_ask_before_risky_actions(tool):
    assert load("balanced").decide(tool, {}).action == "confirm"
    assert load("strict").decide(tool, {}).action == "confirm"


def test_balanced_lets_everything_else_run():
    assert load("balanced").decide("create_note", {}).action == "allow"
    assert load("balanced").decide("read_file", {}).action == "allow"


def test_strict_asks_for_anything_that_is_not_a_read():
    assert load("strict").decide("create_note", {}).action == "confirm"
    assert load("strict").decide("read_file", {}).action == "allow"
    assert load("strict").decide("listDirectory", {}).action == "allow"


def test_write_policy_never_overwrites_without_force(tmp_path):
    path = tmp_path / "nested" / "policy.toml"
    assert presets.write_policy(path, "balanced")
    path.write_text("# mine\n")
    assert not presets.write_policy(path, "strict")
    assert path.read_text() == "# mine\n"
    assert presets.write_policy(path, "strict", force=True)
    assert "strict preset" in path.read_text()


def test_home_can_be_redirected(monkeypatch, tmp_path):
    monkeypatch.setenv("SKYNT_HOME", str(tmp_path))
    assert presets.default_policy_path() == tmp_path / "policy.toml"
