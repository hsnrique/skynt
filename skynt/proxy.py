"""Stdio proxy that enforces a Policy on MCP tools/call.

The upstream only ever receives bytes this gateway serialized itself, so a
parser differential (duplicate keys, odd encodings) cannot make the upstream
run something other than what the policy evaluated.
"""
from __future__ import annotations

import sys
import threading
from typing import BinaryIO

from skynt import wire
from skynt.audit import Audit
from skynt.confirm import Confirmations, Resolution, fits_prompt
from skynt.policy import Policy
from skynt.schema import validate_args


class Gateway:
    def __init__(
        self,
        policy: Policy,
        audit: Audit,
        *,
        client_in: BinaryIO,
        client_out: BinaryIO,
        upstream_in: BinaryIO,
        upstream_out: BinaryIO,
        max_line_bytes: int = wire.MAX_LINE_BYTES,
    ):
        self._policy, self._audit = policy, audit
        self._client_in, self._client_out = client_in, client_out
        self._upstream_in, self._upstream_out = upstream_in, upstream_out
        self._max_line_bytes = max_line_bytes
        self._client_out_lock, self._state_lock = threading.Lock(), threading.Lock()
        self._schemas: dict[str, dict] = {}
        self._pending_tool_lists: set = set()
        self._confirmations = Confirmations()
        self._client_can_elicit = False

    def run(self) -> None:
        """Serve until the upstream closes its stdout, which also follows client EOF."""
        threading.Thread(target=self._pump_client, name="client-pump", daemon=True).start()
        self._pump_upstream()

    # client -> upstream

    def _pump_client(self) -> None:
        try:
            for line in wire.read_lines(self._client_in, self._max_line_bytes):
                self._on_client_line(line)
        except (OSError, ValueError):
            pass  # client stream closed underneath us
        finally:
            _close_quietly(self._upstream_in)

    def _on_client_line(self, line: bytes | None) -> None:
        if line is None:
            self._send_client(wire.error(None, wire.INVALID_REQUEST, f"message exceeds {self._max_line_bytes} bytes"))
            return
        if not line.strip():
            return
        message = None
        try:
            message = wire.parse(line)
            self._route_client(message)
        except wire.ProtocolError as error:
            self._send_client(wire.error(error.request_id, error.code, str(error)))
        except Exception as error:  # a gateway bug must fail closed, never forward
            print(f"skynt: internal error: {error!r}", file=sys.stderr)
            if isinstance(message, dict) and "method" in message and "id" in message:
                self._send_client(wire.error(message["id"], wire.INTERNAL_ERROR, "skynt internal error"))

    def _route_client(self, message: dict) -> None:
        resolution = self._confirmations.resolve(message)
        if resolution is not None:
            self._finish_confirmation(resolution)
            return
        method = message.get("method")
        if method == "tools/call":
            self._gate(message)
            return
        if method == "initialize":
            capabilities = _params(message).get("capabilities")
            self._client_can_elicit = isinstance(capabilities, dict) and "elicitation" in capabilities
        elif method == "tools/list" and wire.is_request_id(message.get("id")):
            with self._state_lock:
                self._pending_tool_lists.add(message["id"])
        self._forward_upstream(message)

    def _gate(self, call: dict) -> None:
        tool, arguments = _tool_call_parts(call)
        verdict, reason = self._judge(tool, arguments)
        self._audit.record(request_id=call.get("id"), tool=tool, arguments=arguments, decision=verdict, reason=reason)
        if verdict == "allow":
            self._forward_upstream(call)
        elif verdict == "confirm":
            self._send_client(self._confirmations.request(call, tool, arguments))
        else:
            self._send_client(wire.tool_error(call.get("id"), reason))

    def _judge(self, tool: str, arguments: dict) -> tuple[str, str]:
        decision = self._policy.decide(tool, arguments)
        if decision.action == "deny":
            return "deny", f"{tool}: blocked by policy ({decision.reason})"
        schema = self._schema_for(tool)
        if schema is None:
            return "unadvertised", f"{tool}: not advertised by upstream tools/list, refusing to forward"
        errors = validate_args(schema, arguments)
        if errors:
            return "schema_rejected", f"{tool}: invalid arguments: " + "; ".join(errors)
        if decision.action == "confirm" and not self._client_can_elicit:
            return "confirm_unavailable", f"{tool}: needs your confirmation, but this app cannot show confirmation prompts (MCP elicitation). Set this tool to allow or deny in your skynt policy."
        if decision.action == "confirm" and not fits_prompt(arguments):
            return "confirm_unavailable", f"{tool}: arguments too large to show the user for confirmation"
        return decision.action, decision.reason

    def _finish_confirmation(self, resolution: Resolution) -> None:
        call = resolution.call
        tool, arguments = _tool_call_parts(call)
        decision = "confirmed" if resolution.approved else "declined"
        self._audit.record(request_id=call.get("id"), tool=tool, arguments=arguments, decision=decision, reason="human answer")
        if resolution.approved:
            self._forward_upstream(call)
        else:
            self._send_client(wire.tool_error(call.get("id"), f"{tool}: declined by the user"))

    # upstream -> client

    def _pump_upstream(self) -> None:
        try:
            for line in self._upstream_out:
                self._write_client(self._on_upstream_line(line))
        except (OSError, ValueError):
            pass  # client stream closed underneath us

    def _on_upstream_line(self, line: bytes) -> bytes:
        try:
            message = wire.try_parse(line)
            if message is None or "method" in message or not self._claim_tool_list(message.get("id")):
                return line
            return self._filter_tool_list(message) or line
        except Exception as error:  # hidden tools stay gated on call, so forwarding raw is safe
            print(f"skynt: internal error on upstream message: {error!r}", file=sys.stderr)
            return line

    def _filter_tool_list(self, response: dict) -> bytes | None:
        result = response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return None
        tools = [tool for tool in result["tools"] if isinstance(tool, dict) and isinstance(tool.get("name"), str)]
        with self._state_lock:
            self._schemas.update({tool["name"]: tool.get("inputSchema") or {} for tool in tools})
        result["tools"] = [tool for tool in tools if self._policy.visible(tool["name"])]
        return wire.encode(response)

    def _claim_tool_list(self, request_id) -> bool:
        if not wire.is_request_id(request_id):
            return False
        with self._state_lock:
            if request_id not in self._pending_tool_lists:
                return False
            self._pending_tool_lists.discard(request_id)
            return True

    def _schema_for(self, tool: str) -> dict | None:
        with self._state_lock:
            return self._schemas.get(tool)

    # io

    def _forward_upstream(self, message: dict) -> None:
        self._upstream_in.write(wire.encode(message))
        self._upstream_in.flush()

    def _send_client(self, message: dict) -> None:
        self._write_client(wire.encode(message))

    def _write_client(self, data: bytes) -> None:
        with self._client_out_lock:
            self._client_out.write(data)
            self._client_out.flush()


def _params(message: dict) -> dict:
    params = message.get("params")
    return params if isinstance(params, dict) else {}


def _tool_call_parts(call: dict) -> tuple[str, dict]:
    params = _params(call)
    tool, arguments = params.get("name"), params.get("arguments", {})
    if not isinstance(tool, str) or not isinstance(arguments, dict):
        raise wire.ProtocolError(wire.INVALID_PARAMS, "tools/call needs a string 'name' and object 'arguments'", call.get("id"))
    return tool, arguments


def _close_quietly(stream: BinaryIO) -> None:
    try:
        stream.close()
    except OSError:
        pass
