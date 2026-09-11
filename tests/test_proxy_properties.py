"""Whatever the call mix, answer order and answers, every request gets exactly
one response, and upstream receives exactly the allowed plus approved calls."""
import json
import re

from hypothesis import given, settings
from hypothesis import strategies as st

from skynt.policy import Policy
from tests.harness import Session, answer, is_elicitation, is_response

POLICY = Policy.from_dict({
    "default": "deny",
    "rules": [{"match": "read_*", "action": "allow"}, {"match": "delete_*", "action": "confirm"}],
})
ALLOWED, CONFIRM, BLOCKED = "read_thing", "delete_thing", "drop_thing"
CALL_N = re.compile(r'"n": (\d+)')

scenarios = st.lists(st.tuples(st.sampled_from([ALLOWED, CONFIRM, BLOCKED]), st.booleans()), min_size=1, max_size=25)


@settings(max_examples=40, deadline=None)
@given(scenarios, st.data())
def test_exactly_one_response_and_only_permitted_calls_forwarded(tmp_path_factory, scenario, data):
    audit = tmp_path_factory.mktemp("audit") / "audit.jsonl"
    with Session(POLICY, audit) as session:
        session.initialize()
        session.list_tools()
        for n, (tool, _) in enumerate(scenario):
            session.send({"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": {"name": tool, "arguments": {"n": n}}})
        confirm_count = sum(tool == CONFIRM for tool, _ in scenario)
        elicitations = session.wait(is_elicitation, confirm_count) if confirm_count else []
        for elicitation in data.draw(st.permutations(elicitations)):
            n = int(CALL_N.search(elicitation["params"]["message"]).group(1))
            session.send(answer(elicitation, "accept", scenario[n][1]))
        responses = session.wait(lambda m: is_response(m) and isinstance(m.get("id"), int), len(scenario))

    assert sorted(r["id"] for r in responses) == list(range(len(scenario)))
    permitted = {n for n, (tool, approve) in enumerate(scenario) if tool == ALLOWED or (tool == CONFIRM and approve)}
    forwarded = [m["params"]["arguments"]["n"] for m in session.upstream.calls()]
    assert sorted(forwarded) == sorted(permitted)
    for response in responses:
        assert ("isError" in response["result"]) == (response["id"] not in permitted)
    assert session.gateway._confirmations.pending == 0
    assert len(audit.read_text().splitlines()) == len(scenario) + confirm_count
