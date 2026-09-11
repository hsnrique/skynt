"""JSON-RPC framing for the newline-delimited stdio transport."""
from __future__ import annotations

import json
from typing import BinaryIO, Iterator

MAX_LINE_BYTES = 4 * 1024 * 1024
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class ProtocolError(Exception):
    def __init__(self, code: int, message: str, request_id=None):
        super().__init__(message)
        self.code = code
        self.request_id = request_id


def read_lines(stream: BinaryIO, limit: int = MAX_LINE_BYTES) -> Iterator[bytes | None]:
    """Yield each line, or None in place of a line longer than `limit`."""
    while chunk := stream.readline(limit):
        if len(chunk) < limit or chunk.endswith(b"\n"):
            yield chunk
            continue
        while chunk and not chunk.endswith(b"\n"):
            chunk = stream.readline(limit)
        yield None


def parse(line: bytes) -> dict:
    try:
        message = json.loads(line, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as error:
        raise ProtocolError(PARSE_ERROR, "invalid JSON") from error
    if isinstance(message, list):
        raise ProtocolError(INVALID_REQUEST, "JSON-RPC batches are not supported")
    if not isinstance(message, dict) or not isinstance(message.get("method", ""), str):
        raise ProtocolError(INVALID_REQUEST, "expected a JSON-RPC message object")
    return message


def try_parse(line: bytes) -> dict | None:
    try:
        return parse(line)
    except ProtocolError:
        return None


def encode(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n"


def error(request_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def tool_error(request_id, text: str) -> dict:
    content = [{"type": "text", "text": f"skynt: {text}"}]
    return {"jsonrpc": "2.0", "id": request_id, "result": {"content": content, "isError": True}}


def is_request_id(value) -> bool:
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _reject_constant(name: str):
    raise ValueError(f"non-standard JSON constant {name}")
