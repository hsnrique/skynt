"""Runs a Gateway against an in-process fake upstream over real OS pipes."""
from __future__ import annotations

import json
import os
import threading

from skynt import wire
from skynt.audit import Audit
from skynt.policy import Policy
from skynt.proxy import Gateway

TIMEOUT_SECONDS = 5
TOOL_SCHEMAS = [
    {"name": "read_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "read_thing"},
    {"name": "delete_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "delete_thing"},
    {"name": "drop_thing"},
]


def _pipe():
    read_fd, write_fd = os.pipe()
    return os.fdopen(read_fd, "rb"), os.fdopen(write_fd, "wb")


def is_response(message: dict) -> bool:
    return "method" not in message


def is_elicitation(message: dict) -> bool:
    return message.get("method") == "elicitation/create"


class FakeUpstream:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.raw: list[bytes] = []
        self.seen: list[dict] = []
        self._lock = threading.Lock()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def calls(self) -> list[dict]:
        return [m for m in self.seen if m.get("method") == "tools/call"]

    def push(self, message: dict) -> None:
        with self._lock:
            self.writer.write(json.dumps(message).encode() + b"\n")
            self.writer.flush()

    def _serve(self):
        for line in self.reader:
            self.raw.append(line)
            message = json.loads(line)
            self.seen.append(message)
            if "id" in message and "method" in message:
                self.push({"jsonrpc": "2.0", "id": message["id"], "result": self._result(message)})
        self.writer.close()

    def _result(self, message: dict) -> dict:
        if message["method"] == "tools/list":
            return {"tools": json.loads(json.dumps(TOOL_SCHEMAS))}
        return {"echo": message.get("params", {})}


class Session:
    def __init__(self, policy: Policy, audit_path, max_line_bytes: int = wire.MAX_LINE_BYTES):
        client_in_r, self._client_in = _pipe()
        self._client_out, client_out_w = _pipe()
        upstream_in_r, upstream_in_w = _pipe()
        upstream_out_r, upstream_out_w = _pipe()
        self.upstream = FakeUpstream(upstream_in_r, upstream_out_w)
        self.gateway = Gateway(
            policy, Audit(audit_path), client_in=client_in_r, client_out=client_out_w,
            upstream_in=upstream_in_w, upstream_out=upstream_out_r, max_line_bytes=max_line_bytes,
        )
        self.received: list[dict] = []
        self._arrived = threading.Condition()
        self._write_lock = threading.Lock()
        self._threads = [
            self.upstream.thread,
            threading.Thread(target=self._run_gateway, args=(client_out_w,), daemon=True),
            threading.Thread(target=self._read_client_out, daemon=True),
        ]

    def __enter__(self):
        for thread in self._threads:
            thread.start()
        return self

    def __exit__(self, *_):
        self.close()

    def send(self, message: dict) -> None:
        self.send_raw(json.dumps(message).encode() + b"\n")

    def send_raw(self, data: bytes) -> None:
        with self._write_lock:
            self._client_in.write(data)
            self._client_in.flush()

    def request(self, message: dict) -> dict:
        self.send(message)
        return self.wait(lambda m: is_response(m) and m.get("id") == message["id"])[0]

    def initialize(self, elicitation: bool = True) -> dict:
        capabilities = {"elicitation": {}} if elicitation else {}
        return self.request({"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {"capabilities": capabilities}})

    def list_tools(self, request_id="list") -> dict:
        return self.request({"jsonrpc": "2.0", "id": request_id, "method": "tools/list"})

    def wait(self, predicate, count: int = 1) -> list[dict]:
        with self._arrived:
            matched = lambda: [m for m in self.received if predicate(m)]
            if not self._arrived.wait_for(lambda: len(matched()) >= count, timeout=TIMEOUT_SECONDS):
                raise AssertionError(f"expected {count} matching messages, got {matched()}")
            return matched()

    def close(self) -> None:
        if not self._client_in.closed:
            self._client_in.close()
        for thread in self._threads:
            thread.join(timeout=TIMEOUT_SECONDS)

    def _run_gateway(self, client_out_w):
        self.gateway.run()
        client_out_w.close()

    def _read_client_out(self):
        for line in self._client_out:
            with self._arrived:
                self.received.append(json.loads(line))
                self._arrived.notify_all()


def call(request_id, tool, **arguments) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}


def answer(elicitation: dict, action: str = "accept", approve: bool = True) -> dict:
    result = {"action": action, "content": {"approve": approve}} if action == "accept" else {"action": action}
    return {"jsonrpc": "2.0", "id": elicitation["id"], "result": result}
