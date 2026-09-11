"""Under any sequence, every request gets exactly one response carrying its
own id, and blocked calls never reach upstream."""
from hypothesis import given, settings
from hypothesis import strategies as st

from mcpgate.policy import Policy
from tests.harness import Session

POLICY = Policy.from_dict({"default": "deny", "rules": [{"match": "read_*", "action": "allow"}]})
ALLOWED, BLOCKED = "read_thing", "delete_thing"


@settings(max_examples=40, deadline=None)
@given(st.lists(st.sampled_from([ALLOWED, BLOCKED]), min_size=1, max_size=40))
def test_one_response_per_request_and_blocked_never_forwarded(tmp_path_factory, tools):
    audit = tmp_path_factory.mktemp("audit") / "audit.jsonl"
    with Session(POLICY, audit) as session:
        session.list_tools(request_id=-1)
        for request_id, tool in enumerate(tools):
            session.send({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": tool}})
        responses = session.finish()

    assert sorted(r["id"] for r in responses) == list(range(len(tools)))
    forwarded = [m["params"]["name"] for m in session.upstream.seen if m["method"] == "tools/call"]
    assert forwarded == [t for t in tools if t == ALLOWED]
    by_id = {r["id"]: r for r in responses}
    for request_id, tool in enumerate(tools):
        assert by_id[request_id]["result"].get("isError", False) == (tool == BLOCKED)
