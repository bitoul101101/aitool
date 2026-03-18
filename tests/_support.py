import tempfile
import threading
import time
from pathlib import Path


POLICY = {
    "approved_providers": ["azure_openai"],
    "restricted_providers": ["openai", "anthropic"],
    "banned_providers": ["some_banned_lib"],
}


def make_test_file(content: str, suffix: str = ".py") -> tuple[Path, str]:
    d = tempfile.mkdtemp()
    p = Path(d) / f"test{suffix}"
    p.write_text(content)
    return p.parent, p.name


def make_finding(provider: str = "openai", sev: int = 2, cat: str = "External AI API", context: str = "production") -> dict:
    return {
        "repo": "test-repo",
        "category": cat,
        "provider_or_lib": provider,
        "capability": "LLM",
        "severity": sev,
        "file": "app.py",
        "line": 10,
        "snippet": "import openai",
        "policy_status": "REVIEW",
        "is_notebook": False,
        "context": context,
        "description": "Test",
        "_hash": "abc123",
    }


def install_browser_session(srv, session_id: str = "valid-session", csrf_token: str = "expected-csrf") -> dict:
    original_sessions = dict(srv._browser_sessions)
    srv._browser_sessions.clear()
    srv._browser_sessions[session_id] = {
        "csrf_token": csrf_token,
        "issued_at": time.time(),
    }
    return original_sessions


def start_live_server(srv):
    server = srv.http.server.ThreadingHTTPServer(("127.0.0.1", 0), srv._Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    return server, thread
