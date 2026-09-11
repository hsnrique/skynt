import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from skynt import clients

LAUNCHER = clients.Launcher("/venv/bin/python", "/home/me/.skynt/policy.toml")
FILESYSTEM = {"command": "npx", "args": ["-y", "server-filesystem", "."], "env": {"A": "1"}}
REMOTE = {"type": "http", "url": "https://example.com/mcp"}


def write(tmp_path, config: dict, name: str = "mcp.json"):
    path = tmp_path / name
    path.write_text(json.dumps(config, indent=2))
    return path


def servers(path) -> dict:
    config = json.loads(path.read_text())
    return config.get("mcpServers") or config["servers"]


def test_protect_wraps_local_servers_and_keeps_everything_else(tmp_path):
    path = write(tmp_path, {"mcpServers": {"fs": FILESYSTEM, "remote": REMOTE}, "other": True})
    report = clients.protect_file(path, LAUNCHER)
    wrapped = servers(path)["fs"]
    assert report.changed == ["fs"] and report.skipped[0][0] == "remote"
    assert wrapped["command"] == "/venv/bin/python"
    assert wrapped["args"] == ["-m", "skynt", "run", "--policy", "/home/me/.skynt/policy.toml", "--", "npx", "-y", "server-filesystem", "."]
    assert wrapped["env"] == {"A": "1"}
    assert servers(path)["remote"] == REMOTE
    assert json.loads(path.read_text())["other"] is True


def test_protect_is_idempotent(tmp_path):
    path = write(tmp_path, {"mcpServers": {"fs": FILESYSTEM}})
    clients.protect_file(path, LAUNCHER)
    first = path.read_text()
    report = clients.protect_file(path, LAUNCHER)
    assert report.changed == [] and report.skipped == [("fs", "already protected")]
    assert path.read_text() == first


def test_unprotect_restores_the_original_entries(tmp_path):
    path = write(tmp_path, {"servers": {"fs": FILESYSTEM}})
    clients.protect_file(path, LAUNCHER)
    report = clients.unprotect_file(path)
    assert report.changed == ["fs"]
    assert servers(path) == {"fs": FILESYSTEM}


def test_backup_keeps_the_pristine_original(tmp_path):
    path = write(tmp_path, {"mcpServers": {"fs": FILESYSTEM}})
    original = path.read_text()
    clients.protect_file(path, LAUNCHER)
    clients.unprotect_file(path)
    clients.protect_file(path, LAUNCHER)
    assert (tmp_path / "mcp.json.skynt-backup").read_text() == original
    assert not (tmp_path / "mcp.json.skynt-tmp").exists()


def test_nothing_to_change_writes_nothing(tmp_path):
    path = write(tmp_path, {"mcpServers": {"remote": REMOTE}})
    clients.protect_file(path, LAUNCHER)
    assert not (tmp_path / "mcp.json.skynt-backup").exists()


@pytest.mark.parametrize("content", ['{"mcpServers": {} // comment\n}', "[]", '{"theme": "dark"}', ""])
def test_unreadable_or_foreign_files_are_left_untouched(tmp_path, content):
    path = tmp_path / "mcp.json"
    path.write_text(content)
    with pytest.raises(clients.ConfigError):
        clients.protect_file(path, LAUNCHER)
    assert path.read_text() == content


def test_unrecognized_entries_are_skipped(tmp_path):
    path = write(tmp_path, {"mcpServers": {"a": "npx", "b": {"command": ["npx"]}, "c": {"command": "x", "args": [1]}}})
    report = clients.protect_file(path, LAUNCHER)
    assert report.changed == [] and len(report.skipped) == 3


def test_known_configs_lists_only_existing_files(tmp_path):
    home, cwd, appdata = tmp_path / "home", tmp_path / "project", tmp_path / "appdata"
    for path in (cwd / ".mcp.json", home / ".cursor" / "mcp.json", appdata / "Claude" / "claude_desktop_config.json"):
        path.parent.mkdir(parents=True)
        path.write_text("{}")
    found = clients.known_configs(home, cwd, appdata)
    assert found == [cwd / ".mcp.json", home / ".cursor" / "mcp.json", appdata / "Claude" / "claude_desktop_config.json"]


arguments = st.lists(st.text(min_size=0, max_size=12), max_size=6)


@given(st.text(min_size=1, max_size=12), arguments, st.dictionaries(st.sampled_from(["env", "cwd", "type"]), st.text(max_size=5)))
def test_unwrap_inverts_wrap(command, args, extra):
    entry = {**extra, "command": command, "args": args}
    wrapped = LAUNCHER.wrap(entry)
    assert clients.is_wrapped(wrapped)
    assert clients.unwrap(wrapped) == entry
