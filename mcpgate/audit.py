from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class Audit:
    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._lock = threading.Lock()

    def record(self, **fields) -> None:
        line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **fields}, default=str)
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
