"""Newline-delimited JSON-RPC proxy that enforces a Policy on MCP tools/call.

Everything except tools/call is forwarded byte-for-byte, so the gateway can
never corrupt a message it does not understand.
"""
from __future__ import annotations

import json
import threading
from typing import BinaryIO

from mcpgate.audit import Audit
from mcpgate.policy import Policy
from mcpgate.schema import validate_args


class Gateway:
    def __init__(
        self,
        policy: Policy,
        audit: Audit,
        client_in: BinaryIO,
        client_out: BinaryIO,
        upstream_in: BinaryIO,
        upstream_out: BinaryIO,
    ):
        self._policy = policy
        self._audit = audit
        self._client_in, self._client_out = client_in, client_out
        self._upstream_in, self._upstream_out = upstream_in, upstream_out
        self._client_out_lock = threading.Lock()
        self._schemas: dict[str, dict] = {}
        self._schema_lock = threading.Lock()
        self._pending_tool_lists: set = set()

    def run(self) -> None:
        to_upstream = threading.Thread(target=self._pump_client, daemon=True)
        to_client = threading.Thread(target=self._pump_upstream, daemon=True)
        to_upstream.start()
        to_client.start()
        to_upstream.join()
        to_client.join()

    def _pump_client(self) -> None:
        for line in self._client_in:
            self._on_client_line(line)
        self._upstream_in.close()

    def _pump_upstream(self) -> None:
        for line in self._upstream_out:
            self._on_upstream_line(line)

    def _on_client_line(self, line: bytes) -> None:
        message = _parse(line)
        if message is None or message.get("method") != "tools/call":
            if message is not None and message.get("method") == "tools/list":
                self._pending_tool_lists.add(message.get("id"))
            self._forward_upstream(line)
            return
        params = message.get("params") or {}
        tool, args = str(params.get("name")), params.get("arguments") or {}
        reason = self._gate(tool, args)
        if reason is None:
            self._forward_upstream(line)
            return
        self._reply_blocked(message.get("id"), reason)

    def _gate(self, tool: str, args: dict) -> str | None:
        decision = self._policy.decide(tool, args)
        schema = self._schema_for(tool)
        errors = validate_args(schema, args) if decision.forwards and schema is not None else []
        outcome = "schema_rejected" if errors else decision.action
        if decision.forwards and schema is None:
            outcome = "unadvertised"
        self._audit.record(tool=tool, arguments=args, decision=outcome, reason=decision.reason, schema_errors=errors)
        if outcome == "unadvertised":
            return f"{tool}: not advertised by upstream tools/list, refusing to forward"
        if errors:
            return f"{tool}: invalid arguments: " + "; ".join(errors)
        if decision.forwards:
            return None
        if decision.action == "confirm":
            # ponytail: no interactive channel yet; upgrade to MCP elicitation/create.
            return f"{tool}: requires human confirmation. Ask the user to run it manually or allow it in the policy."
        return f"{tool}: blocked by policy ({decision.reason})"

    def _on_upstream_line(self, line: bytes) -> None:
        message = _parse(line)
        if message is not None and message.get("id") in self._pending_tool_lists:
            self._pending_tool_lists.discard(message.get("id"))
            self._remember_schemas(message.get("result") or {})
        self._forward_client(line)

    def _remember_schemas(self, result: dict) -> None:
        with self._schema_lock:
            for tool in result.get("tools", []):
                if isinstance(tool, dict) and "name" in tool:
                    self._schemas[tool["name"]] = tool.get("inputSchema") or {}

    def _schema_for(self, tool: str) -> dict | None:
        with self._schema_lock:
            return self._schemas.get(tool)

    def _forward_upstream(self, line: bytes) -> None:
        self._upstream_in.write(line)
        self._upstream_in.flush()

    def _forward_client(self, line: bytes) -> None:
        with self._client_out_lock:
            self._client_out.write(line)
            self._client_out.flush()

    def _reply_blocked(self, request_id, reason: str) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": f"mcpgate: {reason}"}], "isError": True},
        }
        self._forward_client(json.dumps(payload).encode() + b"\n")


def _parse(line: bytes) -> dict | None:
    try:
        message = json.loads(line)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None
