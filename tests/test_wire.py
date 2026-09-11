import io

import pytest

from skynt import wire


def lines(data: bytes, limit: int) -> list:
    return list(wire.read_lines(io.BufferedReader(io.BytesIO(data)), limit))


def test_read_lines_passes_lines_within_limit():
    assert lines(b"ab\ncd\n", 8) == [b"ab\n", b"cd\n"]


def test_read_lines_replaces_oversized_line_and_resyncs():
    assert lines(b"x" * 20 + b"\nok\n", 8) == [None, b"ok\n"]


def test_read_lines_accepts_line_of_exactly_limit_bytes():
    assert lines(b"1234567\n", 8) == [b"1234567\n"]


def test_read_lines_keeps_unterminated_last_line():
    assert lines(b"ab", 8) == [b"ab"]


@pytest.mark.parametrize("raw, code", [
    (b"not json", wire.PARSE_ERROR),
    (b'{"x": NaN}', wire.PARSE_ERROR),
    (b"\xff\xfe", wire.PARSE_ERROR),
    (b"[]", wire.INVALID_REQUEST),
    (b"42", wire.INVALID_REQUEST),
    (b'{"method": 1}', wire.INVALID_REQUEST),
])
def test_parse_rejects(raw, code):
    with pytest.raises(wire.ProtocolError) as caught:
        wire.parse(raw)
    assert caught.value.code == code


def test_parse_collapses_duplicate_keys_to_the_last_value():
    assert wire.parse(b'{"method": "ping", "method": "tools/call"}') == {"method": "tools/call"}


def test_encode_is_single_ascii_line():
    encoded = wire.encode({"text": "Straße\nline"})
    assert encoded.endswith(b"\n") and encoded.count(b"\n") == 1
    assert wire.parse(encoded) == {"text": "Straße\nline"}


def test_request_ids_exclude_bools_and_containers():
    assert wire.is_request_id(1) and wire.is_request_id("a")
    assert not wire.is_request_id(True) and not wire.is_request_id([1]) and not wire.is_request_id(None)
