import json

from skynt import logview


def test_tail_returns_the_last_records_and_skips_garbage(tmp_path):
    path = tmp_path / "audit.jsonl"
    lines = [json.dumps({"tool": f"t{i}"}) for i in range(5)] + ["not json"]
    path.write_text("\n".join(lines) + "\n")
    assert [r["tool"] for r in logview.tail(path, 3)] == ["t3", "t4"]


def test_format_record_is_one_readable_line():
    record = {"ts": "2026-09-11T13:24:01+00:00", "decision": "confirmed", "tool": "write_file", "arguments": {"path": "a.txt"}}
    line = logview.format_record(record)
    assert "confirmed" in line and "write_file" in line and '{"path": "a.txt"}' in line
    assert line.startswith("2026-09-1")


def test_long_lines_are_cut():
    record = {"ts": "", "decision": "allow", "tool": "t", "arguments": {"x": "y" * 500}}
    line = logview.format_record(record)
    assert len(line) == logview.LINE_WIDTH and line.endswith("...")
