from __future__ import annotations

import threading
from typing import Any

from services.scan_jobs import ScanSession


class ActiveScanStore:
    def __init__(self, session: ScanSession | None = None, lock: threading.RLock | None = None):
        self._lock = lock or threading.RLock()
        self._session = session or ScanSession()
        self._session.state_lock = self._lock

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def current(self) -> ScanSession:
        with self._lock:
            return self._session

    def replace(self, session: ScanSession) -> ScanSession:
        session.state_lock = self._lock
        with self._lock:
            self._session = session
            return self._session

    def snapshot(self, *, include_status: bool = False, log_limit: int | None = None) -> dict[str, Any]:
        with self._lock:
            session = self._session
            log_lines = list(session.log_lines[-log_limit:]) if log_limit else list(session.log_lines)
            data = {
                "session": session,
                "scan_id": session.scan_id,
                "project_key": session.project_key,
                "repo_slugs": list(session.repo_slugs),
                "state": session.state,
                "started_at_utc": session.started_at_utc,
                "completed_at_utc": session.completed_at_utc,
                "scan_duration_s": session.scan_duration_s,
                "llm_model": session.llm_model,
                "llm_model_info": dict(session.llm_model_info or {}),
                "log_lines": log_lines,
                "report_paths": dict(session.report_paths or {}),
                "delta": dict(session.delta or {}),
                "inventory": dict(session.inventory or {}),
                "findings": list(session.findings),
                "suppressed_findings": list(session.suppressed_findings),
            }
            if include_status:
                data["status"] = session.to_status()
            return data
