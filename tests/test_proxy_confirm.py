import json

from skynt.policy import Policy
from tests.harness import Session, answer, call, is_elicitation, is_response

POLICY = Policy.from_dict({"default": "deny", "rules": [{"match": "delete_*", "action": "confirm"}]})


def confirm_flow(tmp_path, reply) -> tuple[Session, dict]:
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.initialize()
        session.list_tools()
        session.send(call(1, "delete_file", path="a.txt"))
        elicitation = session.wait(is_elicitation)[0]
        session.send(reply(elicitation))
        response = session.wait(lambda m: is_response(m) and m.get("id") == 1)[0]
    return session, response


def test_elicitation_shows_the_exact_call(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.initialize()
        session.list_tools()
        session.send(call(1, "delete_file", path="a.txt"))
        elicitation = session.wait(is_elicitation)[0]
    assert "`delete_file`" in elicitation["params"]["message"]
    assert '"path": "a.txt"' in elicitation["params"]["message"]
    assert elicitation["params"]["requestedSchema"]["required"] == ["approve"]
    assert session.upstream.calls() == []


def test_approved_call_is_forwarded_once(tmp_path):
    session, response = confirm_flow(tmp_path, lambda e: answer(e, "accept", True))
    assert response["result"] == {"echo": {"name": "delete_file", "arguments": {"path": "a.txt"}}}
    assert len(session.upstream.calls()) == 1


def test_accept_without_approve_is_a_decline(tmp_path):
    session, response = confirm_flow(tmp_path, lambda e: answer(e, "accept", False))
    assert "declined by the user" in response["result"]["content"][0]["text"]
    assert session.upstream.calls() == []


def test_decline_and_cancel_are_declines(tmp_path):
    for action in ("decline", "cancel"):
        session, response = confirm_flow(tmp_path, lambda e: answer(e, action))
        assert response["result"]["isError"] is True
        assert session.upstream.calls() == []


def test_client_error_answer_is_a_decline(tmp_path):
    reply = lambda e: {"jsonrpc": "2.0", "id": e["id"], "error": {"code": -1, "message": "no UI"}}
    session, response = confirm_flow(tmp_path, reply)
    assert response["result"]["isError"] is True
    assert session.upstream.calls() == []


def test_answer_to_an_upstream_request_is_never_an_approval(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.initialize()
        session.list_tools()
        session.send(call(1, "delete_file", path="a.txt"))
        session.wait(is_elicitation)
        session.send({"jsonrpc": "2.0", "id": "skynt-guess", "result": {"action": "accept", "content": {"approve": True}}})
        session.request({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert session.upstream.calls() == []


def test_client_without_elicitation_gets_an_explanation(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.initialize(elicitation=False)
        session.list_tools()
        response = session.request(call(1, "delete_file", path="a.txt"))
    assert "cannot show confirmation prompts" in response["result"]["content"][0]["text"]
    assert session.upstream.calls() == []


def test_arguments_too_large_to_show_are_refused(tmp_path):
    with Session(POLICY, tmp_path / "audit.jsonl") as session:
        session.initialize()
        session.list_tools()
        response = session.request(call(1, "delete_file", path="x" * 5000))
    assert "too large" in response["result"]["content"][0]["text"]
    assert not any(is_elicitation(m) for m in session.received)


def test_confirmation_outcome_is_audited(tmp_path):
    confirm_flow(tmp_path, lambda e: answer(e, "accept", True))
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [r["decision"] for r in records] == ["confirm", "confirmed"]
