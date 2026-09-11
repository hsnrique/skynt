from mcpgate.schema import validate_args

SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}, "flags": {"type": ["array", "null"]}},
    "required": ["path"],
    "additionalProperties": False,
}


def test_valid_arguments_pass():
    assert validate_args(SCHEMA, {"path": "a", "limit": 3, "flags": None}) == []


def test_missing_required_is_reported():
    assert validate_args(SCHEMA, {}) == ["missing required argument 'path'"]


def test_type_mismatch_is_reported():
    assert validate_args(SCHEMA, {"path": 1}) == ["argument 'path': expected string, got int"]


def test_bool_is_not_an_integer():
    assert validate_args(SCHEMA, {"path": "a", "limit": True}) == ["argument 'limit': expected integer, got boolean"]


def test_unexpected_argument_is_reported():
    assert validate_args(SCHEMA, {"path": "a", "evil": 1}) == ["unexpected argument 'evil'"]


def test_no_schema_means_no_checks():
    assert validate_args(None, {"anything": 1}) == []
    assert validate_args({}, {"anything": 1}) == []
