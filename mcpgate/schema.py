"""Minimal JSON Schema check for tool arguments.

ponytail: top-level required/type/additionalProperties only; swap for the
`jsonschema` package if nested validation ever matters.
"""
from __future__ import annotations

JSON_TYPES = {
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


def validate_args(schema: dict | None, args: dict) -> list[str]:
    if not schema:
        return []
    errors = [f"missing required argument {key!r}" for key in schema.get("required", []) if key not in args]
    properties = schema.get("properties", {})
    errors += [_type_error(key, value, properties[key]) for key, value in args.items() if key in properties]
    if schema.get("additionalProperties") is False:
        errors += [f"unexpected argument {key!r}" for key in args if key not in properties]
    return [e for e in errors if e]


def _type_error(key: str, value, prop: dict) -> str:
    declared = prop.get("type")
    if declared is None:
        return ""
    expected = tuple(JSON_TYPES[t] for t in ([declared] if isinstance(declared, str) else declared))
    if isinstance(value, bool) and bool not in expected:
        return f"argument {key!r}: expected {declared}, got boolean"
    if isinstance(value, expected):
        return ""
    return f"argument {key!r}: expected {declared}, got {type(value).__name__}"
