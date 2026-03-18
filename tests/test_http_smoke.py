import http.client
import json
import tempfile
import time
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from services.access_control import ROLE_ADMIN, ROLE_SCANNER, ROLE_VIEWER, UserContext
from services.single_user_state import SingleUserConfig, SingleUserState
from tests._support import install_browser_session, start_live_server


def test_live_scan_page_redirects_to_login_without_session():
    import app_server as srv

    server, thread = start_live_server(srv)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/scan")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 303
        assert resp.getheader("Location") == "/login"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_live_api_scan_start_completes_and_updates_status():
    import app_server as srv

    orig_state = srv._operator_state
    orig_session = srv._current_session()
    original_sessions = install_browser_session(srv, csrf_token="csrf-demo")
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Scanner",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Scanner",
                roles=(ROLE_VIEWER, ROLE_SCANNER, ROLE_ADMIN),
                allowed_projects=("*",),
            ),
        )
    )
    server, thread = start_live_server(srv)
    try:
        def fake_start_scan(**kwargs):
            session = srv.ScanSession()
            session.scan_id = "20260319_101010"
            session.project_key = "COGI"
            session.repo_slugs = ["repo1"]
            session.total = 1
            session.state = "running"
            return session

        def fake_run_scan(session):
            with session.state_lock:
                session.state = "done"
                session.report_paths = {"__all__": {"html_name": "demo.html"}}

        with patch.object(srv, "start_scan", side_effect=fake_start_scan), \
             patch.object(srv, "_run_scan", side_effect=fake_run_scan), \
             patch.object(srv, "_is_connected", return_value=True):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            body = urllib.parse.urlencode({
                "project_key": "COGI",
                "repo_slugs": "repo1",
                "csrf_token": "csrf-demo",
            })
            conn.request(
                "POST",
                "/api/scan/start",
                body=body,
                headers={
                    "Cookie": "ai_scanner_session=valid-session",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert payload["ok"] is True
            time.sleep(0.1)

            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            conn.request("GET", "/api/scan/status", headers={"Cookie": "ai_scanner_session=valid-session"})
            resp = conn.getresponse()
            status_payload = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert status_payload["state"] == "done"
            assert status_payload["report"]["html_name"] == "demo.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state
        srv._replace_current_session(orig_session)


def test_live_results_navigation_renders_report_frame_for_completed_scan():
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    report_path = d / "demo.html"
    report_path.write_text("<html><body>demo report</body></html>", encoding="utf-8")
    orig_output = srv.OUTPUT_DIR
    orig_state = srv._operator_state
    orig_session = srv._current_session()
    original_sessions = install_browser_session(srv, csrf_token="csrf-demo")
    srv.OUTPUT_DIR = str(d)
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Viewer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Viewer",
                roles=(ROLE_VIEWER,),
                allowed_projects=("*",),
            ),
        )
    )
    session = srv.ScanSession()
    session.scan_id = "20260319_111111"
    session.project_key = "COGI"
    session.repo_slugs = ["repo1"]
    session.state = "done"
    session.report_paths = {"__all__": {"html": str(report_path), "html_name": report_path.name}}
    srv._replace_current_session(session)

    server, thread = start_live_server(srv)
    try:
        with patch.object(srv, "_is_connected", return_value=True):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            conn.request(
                "GET",
                "/scan/20260319_111111?tab=results",
                headers={"Cookie": "ai_scanner_session=valid-session"},
            )
            resp = conn.getresponse()
            html = resp.read().decode("utf-8")
            assert resp.status == 200
            assert 'class="results-frame"' in html
            assert '/reports/demo.html' in html
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        srv.OUTPUT_DIR = orig_output
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state
        srv._replace_current_session(orig_session)
