import json
import os
import subprocess
import sys
from pathlib import Path

SERVER = Path(__file__).with_name("stdio_server.py")
ROOT = Path(__file__).parent.parent
TIMEOUT_SECONDS = 20


def environment(tmp_path) -> dict:
    # PYTHONPATH stands in for an installed package; SKYNT_HOME keeps tests away from the real ~/.skynt.
    return {**os.environ, "PYTHONPATH": str(ROOT), "SKYNT_HOME": str(tmp_path / "home")}


def skynt(tmp_path, *args) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "skynt", *args]
    return subprocess.run(command, capture_output=True, text=True, cwd=tmp_path, env=environment(tmp_path), timeout=TIMEOUT_SECONDS)


def talk(tmp_path, command: list[str]) -> list[dict]:
    gateway = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=tmp_path, env=environment(tmp_path))

    def ask(request: dict) -> dict:
        gateway.stdin.write(json.dumps(request).encode() + b"\n")
        gateway.stdin.flush()
        return json.loads(gateway.stdout.readline())

    replies = [
        ask({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ask({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "a"}}}),
        ask({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "delete_file", "arguments": {}}}),
    ]
    gateway.stdin.close()
    assert gateway.wait(timeout=TIMEOUT_SECONDS) == 0
    return replies


def test_run_against_a_real_subprocess(tmp_path):
    policy = tmp_path / "policy.toml"
    policy.write_text('default = "deny"\n[[rules]]\nmatch = "read_*"\naction = "allow"\n')
    command = [sys.executable, "-m", "skynt", "run", "--policy", str(policy), "--", sys.executable, str(SERVER)]
    listing, allowed, denied = talk(tmp_path, command)
    assert [t["name"] for t in listing["result"]["tools"]] == ["read_file"]
    assert allowed["result"]["content"][0]["text"] == "ran tools/call"
    assert denied["result"]["isError"] is True
    assert len((tmp_path / "skynt-audit.jsonl").read_text().splitlines()) == 2


def test_protect_then_run_the_wrapped_config_then_unprotect(tmp_path):
    config = tmp_path / ".mcp.json"
    original = {"mcpServers": {"demo": {"command": sys.executable, "args": [str(SERVER)]}}}
    config.write_text(json.dumps(original))
    # Always an explicit path: discovery would reach the real home directory.
    protect = skynt(tmp_path, "protect", str(config))
    assert protect.returncode == 0, protect.stdout
    assert "protected  demo" in protect.stdout and "created policy" in protect.stdout

    entry = json.loads(config.read_text())["mcpServers"]["demo"]
    _, allowed, confirm = talk(tmp_path, [entry["command"], *entry["args"]])
    assert allowed["result"]["content"][0]["text"] == "ran tools/call"
    assert "cannot show confirmation prompts" in confirm["result"]["content"][0]["text"]

    log = skynt(tmp_path, "log")
    assert "allow" in log.stdout and "read_file" in log.stdout and "confirm_unavailable" in log.stdout
    assert skynt(tmp_path, "unprotect", str(config)).returncode == 0
    assert json.loads(config.read_text()) == original


def test_run_without_policy_creates_the_default_one(tmp_path):
    command = [sys.executable, "-m", "skynt", "run", "--", sys.executable, str(SERVER)]
    _, allowed, _ = talk(tmp_path, command)
    assert allowed["result"]["content"][0]["text"] == "ran tools/call"
    assert "balanced preset" in (tmp_path / "home" / "policy.toml").read_text()


def test_protect_without_configs_explains_what_to_do(tmp_path):
    done = skynt(tmp_path, "protect", str(tmp_path / "missing.json"))
    assert done.returncode == 1 and "left untouched" in done.stdout


def test_init_and_check(tmp_path):
    assert skynt(tmp_path, "init", "--preset", "strict").returncode == 0
    assert skynt(tmp_path, "init").returncode == 1
    check = skynt(tmp_path, "check")
    assert check.returncode == 0 and "default confirm" in check.stdout


def test_bad_policy_exits_cleanly(tmp_path):
    policy = tmp_path / "policy.toml"
    policy.write_text('[[rules]]\nmatch = "x"\nacton = "allow"\n')
    done = skynt(tmp_path, "check", "--policy", str(policy))
    assert done.returncode == 2
    assert "unknown keys" in done.stdout and "Traceback" not in done.stderr


def test_missing_server_binary_exits_cleanly(tmp_path):
    policy = tmp_path / "policy.toml"
    policy.write_text('default = "deny"\n')
    done = skynt(tmp_path, "run", "--policy", str(policy), "--", "definitely-not-a-real-binary-xyz")
    assert done.returncode == 127
    assert "cannot start MCP server" in done.stderr


def test_no_command_shows_help(tmp_path):
    done = skynt(tmp_path)
    assert done.returncode == 2 and "protect" in done.stdout
