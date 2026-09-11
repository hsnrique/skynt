import json

from skynt import wire
from skynt.policy import Policy
from tests.harness import Session, call, is_response

POLICY = Policy.from_dict({
    "default": "deny",
    "rules": [
        {"match": "read_*", "action": "allow"},
        {"match": "delete_*", "action": "confirm"},
        {"match": "drop_*", "action": "deny"},
    ],
})


def only_response(session: Session) -> dict:
    return session.wait(is_response)[0]


def test_allowed_call_reaches_upstream(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.list_tools()
        response = session.request(call(1, "read_file", path="x"))
    assert response["result"] == {"echo": {"name": "read_file", "arguments": {"path": "x"}}}
    assert [m["method"] for m in session.upstream.seen] == ["tools/list", "tools/call"]


def test_unadvertised_tool_is_refused_even_when_policy_allows(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        response = session.request(call(1, "read_file", path="x"))
    assert session.upstream.seen == []
    assert "not advertised" in response["result"]["content"][0]["text"]


def test_denied_call_is_answered_locally(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.list_tools()
        response = session.request(call(7, "drop_thing"))
    assert session.upstream.calls() == []
    assert response["result"]["isError"] is True
    assert "blocked by policy" in response["result"]["content"][0]["text"]


def test_tools_list_hides_denied_tools(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        listing = session.list_tools()
    names = [tool["name"] for tool in listing["result"]["tools"]]
    assert names == ["read_file", "read_thing", "delete_file", "delete_thing"]


def test_schema_from_tools_list_rejects_bad_arguments(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.list_tools()
        response = session.request(call(2, "read_file", path=42))
    assert "invalid arguments" in response["result"]["content"][0]["text"]
    assert session.upstream.calls() == []


def test_upstream_request_sharing_the_tools_list_id_does_not_steal_it(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.upstream.push({"jsonrpc": "2.0", "id": "list", "method": "roots/list"})
        session.list_tools()
        response = session.request(call(1, "read_file", path="x"))
    assert "echo" in response["result"]


def test_non_tool_traffic_is_forwarded(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        response = session.request({"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {}})
    assert [m["method"] for m in session.upstream.seen] == ["notifications/initialized", "ping"]
    assert response == {"jsonrpc": "2.0", "id": 9, "result": {"echo": {}}}


def test_upstream_sees_only_what_the_policy_evaluated(tmp_path):
    duplicate_name = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_thing","name":"read_thing"}}\n'
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.list_tools()
        session.send_raw(duplicate_name)
        session.wait(lambda m: m.get("id") == 1)
    assert not any(b"drop_thing" in line for line in session.upstream.raw)


def test_batches_are_rejected_not_forwarded(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.send([call(1, "drop_thing")])
        response = only_response(session)
    assert response["error"]["code"] == wire.INVALID_REQUEST
    assert session.upstream.seen == []


def test_invalid_json_is_rejected_not_forwarded(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.send_raw(b'{"method": "tools/call", \n')
        response = only_response(session)
    assert response["error"]["code"] == wire.PARSE_ERROR
    assert session.upstream.seen == []


def test_oversized_line_is_rejected_and_stream_recovers(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl", max_line_bytes=256) as session:
        session.send(call(1, "read_file", path="x" * 1000))
        rejected = only_response(session)
        pong = session.request({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert rejected["error"]["code"] == wire.INVALID_REQUEST
    assert pong["result"] == {"echo": {}}
    assert [m["method"] for m in session.upstream.seen] == ["ping"]


def test_malformed_tool_call_params_are_rejected(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        bad = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": ["read_file"]}}
        response = session.request(bad)
    assert response["error"]["code"] == wire.INVALID_PARAMS
    assert session.upstream.seen == []


def test_audit_failure_blocks_the_call(tmp_path):
    with Session(POLICY, tmp_path) as session:
        session.list_tools()
        response = session.request(call(1, "read_file", path="x"))
    assert response["error"]["code"] == wire.INTERNAL_ERROR
    assert session.upstream.calls() == []


def test_every_decision_is_audited(tmp_path):
    audit = tmp_path / "audit.jsonl"
    with Session(POLICY, audit) as session:
        session.list_tools()
        session.request(call(1, "read_file", path="x"))
        session.request(call(2, "drop_thing"))
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    assert [(r["request_id"], r["tool"], r["decision"]) for r in records] == [(1, "read_file", "allow"), (2, "drop_thing", "deny")]
    assert all("ts" in r for r in records)
