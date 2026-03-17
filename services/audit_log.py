from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class AuditLogService:
    """Append-only JSONL audit log."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    def update_path(self, path: str) -> None:
        self.path = path

    def record(self, event: dict[str, Any]) -> None:
        path = Path(self.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(payload + "\n")
