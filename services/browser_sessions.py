from __future__ import annotations

import secrets
import threading
import time
from typing import Any


def parse_cookie_header(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for chunk in (cookie_header or "").split(";"):
        if "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name:
            cookies[name] = value
    return cookies


class BrowserSessionStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._sessions: dict[str, dict[str, Any]] = {}

    @property
    def sessions(self) -> dict[str, dict[str, Any]]:
        return self._sessions

    def issue(self) -> tuple[str, str]:
        session_id = secrets.token_urlsafe(24)
        csrf_token = secrets.token_urlsafe(24)
        with self._lock:
            self._sessions[session_id] = {
                "csrf_token": csrf_token,
                "issued_at": time.time(),
            }
        return session_id, csrf_token

    def rotate(self) -> tuple[str, str]:
        session_id = secrets.token_urlsafe(24)
        csrf_token = secrets.token_urlsafe(24)
        with self._lock:
            self._sessions.clear()
            self._sessions[session_id] = {
                "csrf_token": csrf_token,
                "issued_at": time.time(),
            }
        return session_id, csrf_token

    def extract_session_id(self, handler) -> str:
        headers = getattr(handler, "headers", {}) or {}
        raw = headers.get("Cookie", "") if hasattr(headers, "get") else ""
        return parse_cookie_header(raw or "").get("ai_scanner_session", "")

    def snapshot_for_handler(self, handler) -> dict[str, Any] | None:
        session_id = self.extract_session_id(handler)
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            return dict(session)

    def has_valid_session(self, handler) -> bool:
        return self.snapshot_for_handler(handler) is not None

    def csrf_token_for_handler(self, handler=None) -> str:
        if handler is None:
            return ""
        session = self.snapshot_for_handler(handler)
        if not session:
            return ""
        return str(session.get("csrf_token", "") or "")

    def csrf_matches(self, handler, body: dict) -> bool:
        session = self.snapshot_for_handler(handler)
        if not session:
            return False
        token = ""
        if isinstance(body, dict):
            token = str(body.get("csrf_token", "") or "")
        expected = str(session.get("csrf_token", "") or "")
        return bool(expected) and token == expected

    @staticmethod
    def queue_session_cookie(handler, session_id: str) -> None:
        handler._response_cookies = [
            f"ai_scanner_session={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200"
        ]
