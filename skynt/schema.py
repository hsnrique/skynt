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


def validate_args(schema, args: dict) -> list[str]:
    if not isinstance(schema, dict) or not schema:
        return []
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    errors = [f"missing required argument {key!r}" for key in required if key not in args]
    errors += [_type_error(key, value, properties[key]) for key, value in args.items() if key in properties]
    if schema.get("additionalProperties") is False:
        errors += [f"unexpected argument {key!r}" for key in args if key not in properties]
    return [e for e in errors if e]


def _type_error(key: str, value, prop) -> str:
    declared = prop.get("type") if isinstance(prop, dict) else None
    names = [declared] if isinstance(declared, str) else declared if isinstance(declared, list) else []
    known = [JSON_TYPES[name] for name in names if name in JSON_TYPES]
    if not known:
        return ""
    if isinstance(value, bool):
        return "" if bool in known else f"argument {key!r}: expected {declared}, got boolean"
    if any(isinstance(value, expected) for expected in known):
        return ""
    return f"argument {key!r}: expected {declared}, got {type(value).__name__}"
