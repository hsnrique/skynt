from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class Audit:
    """Append-only JSONL log. A failed write raises, so the caller fails closed."""

    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._lock = threading.Lock()

    def record(self, **fields) -> None:
        line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **fields}, default=str)
        with self._lock:
            # 0o600 because arguments can hold sensitive data such as queries or file contents.
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
