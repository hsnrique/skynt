"""Runs a Gateway against an in-process fake upstream over real OS pipes."""
from __future__ import annotations

import json
import os
import threading

from mcpgate.audit import Audit
from mcpgate.policy import Policy
from mcpgate.proxy import Gateway

TOOL_SCHEMAS = [
    {"name": "read_file", "inputSchema": {"properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "read_thing"},
]


def _pipe():
    read_fd, write_fd = os.pipe()
    return os.fdopen(read_fd, "rb"), os.fdopen(write_fd, "wb")


class FakeUpstream:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.seen: list[dict] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        for line in self.reader:
            message = json.loads(line)
            self.seen.append(message)
            if "id" in message:
                self._reply(message)
        self.writer.close()

    def _reply(self, message):
        result = {"tools": TOOL_SCHEMAS} if message["method"] == "tools/list" else {"echo": message.get("params", {})}
        self.writer.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode() + b"\n")
        self.writer.flush()


class Session:
    def __init__(self, policy: Policy, audit_path):
        client_in_r, self.client_in = _pipe()
        self.client_out, client_out_w = _pipe()
        upstream_in_r, upstream_in_w = _pipe()
        upstream_out_r, upstream_out_w = _pipe()
        self.upstream = FakeUpstream(upstream_in_r, upstream_out_w)
        self.gateway = Gateway(policy, Audit(audit_path), client_in_r, client_out_w, upstream_in_w, upstream_out_r)
        self.thread = threading.Thread(target=self._run, args=(client_out_w,), daemon=True)

    def _run(self, client_out_w):
        self.gateway.run()
        client_out_w.close()

    def send(self, message: dict):
        self.client_in.write(json.dumps(message).encode() + b"\n")
        self.client_in.flush()

    def list_tools(self, request_id=0) -> dict:
        self.send({"jsonrpc": "2.0", "id": request_id, "method": "tools/list"})
        return json.loads(self.client_out.readline())

    def finish(self) -> list[dict]:
        self.client_in.close()
        self.thread.join(timeout=5)
        self.upstream.thread.join(timeout=5)
        return [json.loads(line) for line in self.client_out]

    def __enter__(self):
        self.upstream.thread.start()
        self.thread.start()
        return self

    def __exit__(self, *_):
        return None
