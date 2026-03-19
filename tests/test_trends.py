import http.client
import tempfile
from pathlib import Path
from unittest.mock import patch

from services.access_control import ROLE_VIEWER, UserContext
from services.single_user_state import SingleUserConfig, SingleUserState
from services.trends import compute_history_trends
from tests._support import install_browser_session, start_live_server


def test_compute_history_trends_aggregates_rule_and_model_metrics():
    d = Path(tempfile.mkdtemp())
    log_path = d / "scan1.txt"
    log_path.write_text(
        "[10:00:00] [LLM] Reviewing 4 finding(s) via qwen\n"
        "[10:00:01] [LLM] Batch 1/2 (2 finding(s))...\n"
        "[10:00:02] [LLM] Batch 1 failed — keeping as-is\n"
        "[10:00:03] [LLM] Batch 2/2 (2 finding(s))...\n"
        "[10:00:04] [LLM] Done — dismissed:1  reinstated:0  downgraded:2  kept:1\n",
        encoding="utf-8",
    )
    records = [
        {
            "scan_id": "20260319_100000",
            "started_at_utc": "2026-03-19T10:00:00Z",
            "project_key": "COGI",
            "repo_slugs": ["repo1"],
            "state": "done",
            "total": 12,
            "critical_prod": 3,
            "high_prod": 1,
            "sev": {"critical": 3, "high": 2, "medium": 4, "low": 3},
            "delta": {"new_count": 5, "fixed_count": 2},
            "llm_model": "qwen2.5-coder:7b-instruct",
            "log_file": str(log_path),
            "trend": {
                "rules": {
                    "active": {"openai": 5, "langchain": 2},
                    "suppressed": {"openai": 2},
                }
            },
        }
    ]

    trends = compute_history_trends(records)

    assert trends["summary"]["scan_count"] == 1
    assert trends["findings_over_time"][0]["value"] == 12
    assert trends["critical_over_time"][0]["value"] == 3
    assert trends["top_noisy_rules"][0]["rule"] == "openai"
    assert trends["top_noisy_rules"][0]["hits"] == 7
    assert trends["suppression_rate_by_rule"][0]["rate_pct"] == 29
    assert trends["llm_review_failure_rate_by_model"][0]["failed_batches"] == 1
    assert trends["llm_review_failure_rate_by_model"][0]["failure_rate_pct"] == 100


def test_live_trends_page_renders_aggregated_sections():
    import app_server as srv

    orig_state = srv._operator_state
    original_sessions = install_browser_session(srv, csrf_token="csrf-demo")
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
    history = [
        {
            "scan_id": "20260319_100000",
            "started_at_utc": "2026-03-19T10:00:00Z",
            "project_key": "COGI",
            "repo_slugs": ["repo1"],
            "state": "done",
            "total": 7,
            "critical_prod": 1,
            "high_prod": 1,
            "sev": {"critical": 1, "high": 2, "medium": 2, "low": 2},
            "delta": {"new_count": 3, "fixed_count": 1},
            "llm_model": "qwen2.5-coder:7b-instruct",
            "trend": {
                "rules": {"active": {"openai": 4}, "suppressed": {"openai": 1}},
                "llm": {"failed_batches": 0, "failed_scan": False, "reviewed": 4, "downgraded": 1},
            },
        }
    ]

    server, thread = start_live_server(srv)
    try:
        with patch.object(srv, "_is_connected", return_value=True), \
             patch.object(srv, "_load_history", return_value=history):
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            conn.request("GET", "/trends", headers={"Cookie": "ai_scanner_session=valid-session"})
            resp = conn.getresponse()
            html = resp.read().decode("utf-8")
            assert resp.status == 200
            assert '<a class="nav active" href="/trends">Trends</a>' in html
            assert "Findings Over Time" in html
            assert "Top Noisy Rules" in html
            assert "LLM Review Failure Rate by Model" in html
            assert "repo1" in html
            assert "openai" in html
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state
