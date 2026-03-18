import http.client
import json
import urllib.parse
from unittest.mock import patch

from services.access_control import ROLE_ADMIN, ROLE_VIEWER, UserContext
from services.single_user_state import SingleUserConfig, SingleUserState
from tests._support import install_browser_session, start_live_server


def test_login_page_is_server_rendered_and_does_not_embed_saved_pat():
    import app_server as srv

    with patch.object(srv, "load_pat", return_value="secret-token-123"):
        html = srv.render_login_page(
            bitbucket_url=srv.BITBUCKET_URL,
            has_saved_pat=True,
            csrf_token="csrf-demo",
        ).decode("utf-8")

    assert "secret-token-123" not in html
    assert "Saved token available: Yes" in html
    assert 'action="/login"' in html
    assert 'name="csrf_token" value="csrf-demo"' in html
    assert 'href="/assets/main.css"' in html
    assert "<style>" not in html


def test_login_redirects_to_new_scan_view():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.location = None
            self._response_cookies = []

        def _redirect(self, location: str):
            self.location = location

        def _render_login_page(self, *, notice: str = "", error: str = ""):
            raise AssertionError(error or "login page should not render on success")

    handler = DummyHandler()
    with patch.object(srv, "connect_operator", return_value={"ok": True}):
        srv._Handler._page_connect(handler, {"token": "demo-token"})

    assert handler.location == "/scan?new=1&notice=Connected+to+Bitbucket"
    assert any(cookie.startswith("ai_scanner_session=") for cookie in handler._response_cookies)


def test_do_post_rejects_missing_csrf_for_mutating_routes():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.path = "/scan/stop"
            self.headers = {"Cookie": "ai_scanner_session=valid-session"}
            self.error = None

        def _read_body(self):
            return {}

        def _err(self, status: int, msg: str):
            self.error = (status, msg)

        def _404(self):
            raise AssertionError("route should not fall through")

    original_sessions = install_browser_session(srv)
    try:
        handler = DummyHandler()
        srv._Handler.do_POST(handler)
        assert handler.error == (403, "CSRF validation failed")
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)


def test_do_get_protected_page_requires_browser_session():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.path = "/scan"
            self.headers = {}
            self.redirect = None

        def _require_browser_session(self):
            return srv._Handler._require_browser_session(self)

        def _redirect(self, location: str):
            self.redirect = location

        def _render_login_page(self, *, notice: str = "", error: str = ""):
            raise AssertionError("scan page should redirect instead of rendering login")

    handler = DummyHandler()
    with patch.object(srv, "_is_connected", return_value=True):
        srv._Handler.do_GET(handler)
    assert handler.redirect == "/login"


def test_multiple_browser_sessions_remain_valid():
    import app_server as srv

    class DummyHandler:
        def __init__(self, session_id):
            self.headers = {"Cookie": f"ai_scanner_session={session_id}"}

    original_sessions = dict(srv._browser_sessions)
    try:
        first_session, _ = srv._issue_browser_session()
        second_session, _ = srv._issue_browser_session()
        assert srv._has_valid_browser_session(DummyHandler(first_session)) is True
        assert srv._has_valid_browser_session(DummyHandler(second_session)) is True
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)


def test_sensitive_get_api_requires_browser_session():
    import app_server as srv

    class DummyHandler:
        path = "/api/history"

        def __init__(self):
            self.headers = {}
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})

    handler = DummyHandler()
    srv._Handler.do_GET(handler)
    assert handler.payload == (401, {"error": "Authentication required"})


def test_live_api_history_requires_browser_session():
    import app_server as srv

    server, thread = start_live_server(srv)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/api/history")
        resp = conn.getresponse()
        body = json.loads(resp.read().decode("utf-8"))
        assert resp.status == 401
        assert body["error"] == "Authentication required"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_live_api_ollama_requires_csrf_even_with_valid_session():
    import app_server as srv

    orig_state = srv._operator_state
    original_sessions = install_browser_session(srv)
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Security Engineer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Security Engineer",
                roles=(ROLE_VIEWER, ROLE_ADMIN),
                allowed_projects=("*",),
            ),
        )
    )
    server, thread = start_live_server(srv)
    try:
        with patch.object(srv._settings_service, "proxy_ollama", side_effect=AssertionError("proxy should not be called")):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            body = json.dumps({"prompt": "hello"})
            conn.request(
                "POST",
                "/api/ollama",
                body=body,
                headers={
                    "Cookie": "ai_scanner_session=valid-session",
                    "Content-Type": "application/json",
                },
            )
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 403
            assert payload["error"] == "CSRF validation failed"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_live_api_ollama_models_rejects_url_override():
    import app_server as srv

    orig_state = srv._operator_state
    original_sessions = install_browser_session(srv)
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Security Engineer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Security Engineer",
                roles=(ROLE_VIEWER,),
                allowed_projects=("*",),
            ),
        )
    )
    server, thread = start_live_server(srv)
    try:
        with patch.object(srv, "_ollama_snapshot", side_effect=AssertionError("snapshot should not be called")):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            path = "/api/ollama/models?" + urllib.parse.urlencode({"url": "http://evil.example", "refresh": "1"})
            conn.request("GET", path, headers={"Cookie": "ai_scanner_session=valid-session"})
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 400
            assert payload["error"] == "Overriding the Ollama URL is not allowed"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state
