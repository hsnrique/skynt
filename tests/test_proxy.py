import json

from mcpgate.policy import Policy
from tests.harness import Session

POLICY = Policy.from_dict({
    "default": "deny",
    "rules": [{"match": "read_*", "action": "allow"}, {"match": "delete_*", "action": "confirm"}],
})


def call(request_id, tool, **arguments):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}


def test_allowed_call_reaches_upstream(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.list_tools()
        session.send(call(1, "read_file", path="x"))
        responses = session.finish()
    assert responses == [{"jsonrpc": "2.0", "id": 1, "result": {"echo": {"name": "read_file", "arguments": {"path": "x"}}}}]
    assert [m["method"] for m in session.upstream.seen] == ["tools/list", "tools/call"]


def test_unadvertised_tool_is_refused_even_when_policy_allows(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.send(call(1, "read_file", path="x"))
        responses = session.finish()
    assert session.upstream.seen == []
    assert "not advertised" in responses[0]["result"]["content"][0]["text"]


def test_denied_call_is_answered_locally(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.send(call(7, "rm_rf", path="/"))
        responses = session.finish()
    assert session.upstream.seen == []
    assert responses[0]["id"] == 7 and responses[0]["result"]["isError"] is True
    assert "blocked by policy" in responses[0]["result"]["content"][0]["text"]


def test_confirm_call_is_held_with_explanation(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.send(call(2, "delete_file", path="x"))
        responses = session.finish()
    assert session.upstream.seen == []
    assert "requires human confirmation" in responses[0]["result"]["content"][0]["text"]


def test_schema_from_tools_list_rejects_bad_arguments(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        listing = session.list_tools(1)
        session.send(call(2, "read_file", path=42))
        responses = session.finish()
    assert "tools" in listing["result"]
    assert "invalid arguments" in responses[0]["result"]["content"][0]["text"]
    assert [m["method"] for m in session.upstream.seen] == ["tools/list"]


def test_non_tool_traffic_is_forwarded_verbatim(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        session.send({"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {}})
        responses = session.finish()
    assert [m["method"] for m in session.upstream.seen] == ["notifications/initialized", "ping"]
    assert responses == [{"jsonrpc": "2.0", "id": 9, "result": {"echo": {}}}]


def test_every_decision_is_audited(tmp_path):
    audit = tmp_path / "audit.jsonl"
    with Session(POLICY, audit) as session:
        session.list_tools()
        session.send(call(1, "read_file", path="x"))
        session.send(call(2, "rm_rf"))
        session.finish()
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    assert [(r["tool"], r["decision"]) for r in records] == [("read_file", "allow"), ("rm_rf", "deny")]
    assert all("ts" in r for r in records)
