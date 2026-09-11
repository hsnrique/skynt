from skynt.confirm import MAX_PROMPT_ARGUMENT_CHARS, Confirmations, fits_prompt

CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "rm", "arguments": {"path": "/"}}}


def reply(request_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def test_request_ids_are_unique_and_unguessable():
    confirmations = Confirmations()
    ids = {confirmations.request(CALL, "rm", {})["id"] for _ in range(100)}
    assert len(ids) == 100
    assert all(len(request_id) > 32 for request_id in ids)


def test_resolve_returns_the_original_call_once():
    confirmations = Confirmations()
    request = confirmations.request(CALL, "rm", {"path": "/"})
    resolution = confirmations.resolve(reply(request["id"], {"action": "accept", "content": {"approve": True}}))
    assert resolution.call is CALL and resolution.approved
    assert confirmations.resolve(reply(request["id"], {"action": "accept", "content": {"approve": True}})) is None
    assert confirmations.pending == 0


def test_only_explicit_accept_with_approve_true_counts():
    confirmations = Confirmations()
    for result in ({"action": "accept", "content": {"approve": "yes"}}, {"action": "accept"}, {"action": "decline"}, None):
        request = confirmations.request(CALL, "rm", {})
        assert confirmations.resolve(reply(request["id"], result)).approved is False


def test_unknown_ids_and_requests_are_ignored():
    confirmations = Confirmations()
    request = confirmations.request(CALL, "rm", {})
    assert confirmations.resolve(reply("skynt-other", {"action": "accept"})) is None
    assert confirmations.resolve({"id": request["id"], "method": "ping"}) is None
    assert confirmations.resolve({"id": ["x"]}) is None
    assert confirmations.pending == 1


def test_fits_prompt_limit():
    assert fits_prompt({"path": "x"})
    assert not fits_prompt({"path": "x" * MAX_PROMPT_ARGUMENT_CHARS})
