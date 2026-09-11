"""Human-readable view of the audit log."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

LINE_WIDTH = 120


def tail(path: Path, count: int) -> list[dict]:
    # ponytail: reads the whole file; seek from the end if logs grow past a few hundred MB.
    records = []
    for line in path.read_text(encoding="utf-8").splitlines()[-count:]:
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    return records


def format_record(record: dict) -> str:
    when = _local_time(record.get("ts", ""))
    arguments = json.dumps(record.get("arguments", {}), ensure_ascii=False)
    line = f"{when}  {record.get('decision', '?'):<19} {record.get('tool', '?'):<28} {arguments}"
    return line if len(line) <= LINE_WIDTH else line[: LINE_WIDTH - 3] + "..."


def _local_time(timestamp: str) -> str:
    try:
        return datetime.fromisoformat(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return timestamp[:19]
