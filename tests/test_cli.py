import json
import subprocess
import sys
from pathlib import Path

SERVER = Path(__file__).with_name("stdio_server.py")
ROOT = Path(__file__).parent.parent
TIMEOUT_SECONDS = 20


def write_policy(tmp_path, body: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(body.replace("AUDIT", (tmp_path / "audit.jsonl").as_posix()), encoding="utf-8")
    return path


def skynt(*args, stdin: bytes = b"") -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "skynt", *args]
    return subprocess.run(command, input=stdin, capture_output=True, cwd=ROOT, timeout=TIMEOUT_SECONDS)


def test_end_to_end_against_a_real_subprocess(tmp_path):
    policy = write_policy(tmp_path, 'default = "deny"\naudit_log = "AUDIT"\n[[rules]]\nmatch = "read_*"\naction = "allow"\n')
    command = [sys.executable, "-m", "skynt", "--policy", str(policy), "--", sys.executable, str(SERVER)]
    gateway = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=ROOT)

    def ask(request: dict) -> dict:
        gateway.stdin.write(json.dumps(request).encode() + b"\n")
        gateway.stdin.flush()
        return json.loads(gateway.stdout.readline())

    listing = ask({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    allowed = ask({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "a"}}})
    denied = ask({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "delete_file", "arguments": {}}})
    gateway.stdin.close()
    assert gateway.wait(timeout=TIMEOUT_SECONDS) == 0
    assert [t["name"] for t in listing["result"]["tools"]] == ["read_file"]
    assert allowed["result"]["content"][0]["text"] == "ran tools/call"
    assert denied["result"]["isError"] is True
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == 2


def test_check_validates_policy(tmp_path):
    policy = write_policy(tmp_path, '[[rules]]\nmatch = "x"\naction = "allow"\n')
    done = skynt("--policy", str(policy), "--check")
    assert done.returncode == 0
    assert b"policy ok (1 rules, default deny)" in done.stdout


def test_bad_policy_exits_cleanly(tmp_path):
    policy = write_policy(tmp_path, '[[rules]]\nmatch = "x"\nacton = "allow"\n')
    done = skynt("--policy", str(policy), "--check")
    assert done.returncode == 2
    assert b"unknown keys" in done.stderr and b"Traceback" not in done.stderr


def test_missing_upstream_binary_exits_cleanly(tmp_path):
    policy = write_policy(tmp_path, 'default = "deny"\n')
    done = skynt("--policy", str(policy), "--", "definitely-not-a-real-binary-xyz")
    assert done.returncode == 127
    assert b"cannot start upstream" in done.stderr
