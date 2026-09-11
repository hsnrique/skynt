"""Human approval of tool calls over MCP elicitation.

Thread-confined: only the client pump creates and resolves confirmations,
because the human's answer arrives on the same stream as new calls. That is
why the pending map carries no lock.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

MAX_PROMPT_ARGUMENT_CHARS = 2000
APPROVAL_SCHEMA = {
    "type": "object",
    "properties": {"approve": {"type": "boolean", "title": "Approve this tool call", "default": False}},
    "required": ["approve"],
}


@dataclass(frozen=True)
class Resolution:
    call: dict
    approved: bool


class Confirmations:
    def __init__(self):
        self._pending: dict[str, dict] = {}

    def request(self, call: dict, tool: str, arguments: dict) -> dict:
        # An unguessable id stops an upstream from pre-sending its own request
        # under the same id and having the user's answer count as approval.
        request_id = f"skynt-{secrets.token_hex(16)}"
        self._pending[request_id] = call
        params = {"message": prompt(tool, arguments), "requestedSchema": APPROVAL_SCHEMA}
        return {"jsonrpc": "2.0", "id": request_id, "method": "elicitation/create", "params": params}

    def resolve(self, message: dict) -> Resolution | None:
        request_id = message.get("id")
        if "method" in message or not isinstance(request_id, str):
            return None
        call = self._pending.pop(request_id, None)
        return None if call is None else Resolution(call, _approved(message))

    @property
    def pending(self) -> int:
        return len(self._pending)


def fits_prompt(arguments: dict) -> bool:
    # Truncating would let the human approve something they cannot see.
    return len(_render(arguments)) <= MAX_PROMPT_ARGUMENT_CHARS


def prompt(tool: str, arguments: dict) -> str:
    return (
        f"An AI agent wants to run the tool `{tool}` with these arguments:\n\n"
        f"{_render(arguments)}\n\nApprove only if you expect this action."
    )


def _render(arguments: dict) -> str:
    return json.dumps(arguments, indent=2, ensure_ascii=False, sort_keys=True)


def _approved(message: dict) -> bool:
    result = message.get("result")
    if not isinstance(result, dict) or result.get("action") != "accept":
        return False
    content = result.get("content")
    return isinstance(content, dict) and content.get("approve") is True
