import json
import tempfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from reports.html_report import HTMLReporter


def test_html_report_header_excludes_triage_summary_stats():
    reporter = HTMLReporter(
        output_dir=tempfile.mkdtemp(),
        scan_id="20260317_024619",
        meta={"suppressed_count": 2},
    )
    findings = [
        {
            "severity": 1,
            "ai_category": "Secrets",
            "repo": "cogi-rag",
            "project_key": "COGI",
            "file": "app.py",
            "line": 12,
            "policy_status": "BANNED",
            "provider_or_lib": "hardcoded_key",
            "capability": "api key",
            "description": "Hardcoded credential",
            "context": "production",
        }
    ]

    html = reporter._render(findings, policy={})

    assert "Reviewed" not in html
    assert "Accepted Risk" not in html
    assert "Suppressed" not in html


def test_html_report_excludes_threat_model_section():
    reporter = HTMLReporter(
        output_dir=tempfile.mkdtemp(),
        scan_id="20260319_140000",
        meta={
            "inventory": {
                "repos_total": 1,
                "repos_using_ai_count": 1,
                "provider_count": 4,
                "model_count": 2,
                "embeddings_vector_db_repos": 1,
                "prompt_handling_repos": 1,
                "model_serving_repos": 1,
                "agent_tool_use_repos": 1,
                "repo_profiles": [
                    {
                        "repo": "cogi-rag-agent",
                        "provider_labels": ["OpenAI", "LangChain"],
                        "embeddings_vector_db": True,
                        "prompt_handling": True,
                        "model_serving": True,
                        "agent_tool_use": True,
                    }
                ],
            }
        },
    )
    findings = [
        {
            "severity": 1,
            "ai_category": "Secrets",
            "repo": "cogi-rag-agent",
            "project_key": "COGI",
            "file": "app.py",
            "line": 12,
            "policy_status": "BANNED",
            "provider_or_lib": "secret_ai_correlation",
            "capability": "api key",
            "description": "Hardcoded credential near AI call",
            "context": "production",
        },
        {
            "severity": 2,
            "ai_category": "RAG/Vector DB",
            "repo": "cogi-rag-agent",
            "project_key": "COGI",
            "file": "rag.py",
            "line": 30,
            "policy_status": "REVIEW",
            "provider_or_lib": "rag_pattern",
            "capability": "retrieval",
            "description": "RAG pipeline",
            "context": "production",
        },
        {
            "severity": 2,
            "ai_category": "External AI API",
            "repo": "cogi-rag-agent",
            "project_key": "COGI",
            "file": "agent.py",
            "line": 41,
            "policy_status": "REVIEW",
            "provider_or_lib": "file_content_to_llm",
            "capability": "prompt",
            "description": "File content sent to model",
            "context": "production",
        },
    ]

    html = reporter._render(findings, policy={})

    assert "Threat Model" not in html
    assert "Threat Scenarios" not in html
    assert "Review Gaps / Open Questions" not in html
    assert "🧭 AI Inventory" not in html


def test_html_report_moves_approved_registry_to_end():
    reporter = HTMLReporter(
        output_dir=tempfile.mkdtemp(),
        scan_id="20260322_180000",
    )
    findings = [
        {
            "severity": 2,
            "ai_category": "External AI API",
            "repo": "repo1",
            "project_key": "COGI",
            "file": "app.py",
            "line": 10,
            "policy_status": "REVIEW",
            "provider_or_lib": "openai",
            "capability": "chat",
            "description": "Example finding",
            "context": "production",
            "remediation": "Fix it.",
        }
    ]
    policy = {
        "approved_providers": ["openai_enterprise"],
        "approved_provider_display_names": {"openai_enterprise": "OpenAI Enterprise"},
    }

    html = reporter._render(findings, policy=policy)

    assert html.index("🔧 Remediation Checklist") < html.index("✅ Approved AI Tools Registry")


def test_html_report_missing_llm_detail_message_points_to_detailed_html():
    reporter = HTMLReporter(
        output_dir=tempfile.mkdtemp(),
        scan_id="20260320_103000",
    )
    findings = [
        {
            "severity": 2,
            "repo": "repo1",
            "project_key": "COGI",
            "file": "app.py",
            "line": 10,
            "policy_status": "REVIEW",
            "provider_or_lib": "openai",
            "capability": "chat",
            "description": "Example finding",
            "context": "production",
        }
    ]

    html = reporter._render(findings, policy={}, llm_details={"app.py:10:openai": ""})

    assert "LLM detail was not embedded for this finding" in html
    assert "Generate a Detailed HTML report" in html
    assert "Re-run the scan with LLM enabled" not in html


def test_html_report_llm_enrichment_deduplicates_repeated_findings():
    import urllib.request

    reporter = HTMLReporter(output_dir=tempfile.mkdtemp(), scan_id="20260318_180000")
    findings = [
        {"file": "app.py", "line": 10, "provider_or_lib": "openai", "capability": "chat", "severity": 2},
        {"file": "app.py", "line": 10, "provider_or_lib": "openai", "capability": "chat", "severity": 2},
    ]

    class FakeResponse(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append((req.full_url, timeout))
        payload = json.dumps({"message": {"content": "## Why It's Problematic\nIssue.\n## How to Fix It\n- Fix\n- Test\n- Review\n## References\nhttps://owasp.org"}}).encode("utf-8")
        return FakeResponse(payload)

    with patch.object(urllib.request, "urlopen", side_effect=fake_urlopen):
        details = reporter._fetch_llm_details(findings, "http://localhost:11434", "qwen", timeout=180)

    assert len(calls) == 1
    assert len(details) == 1
    assert calls[0][1] == 180


def test_html_report_uses_stored_scan_time_llm_detail_before_fetching():
    import urllib.request

    reporter = HTMLReporter(output_dir=tempfile.mkdtemp(), scan_id="20260318_180025")
    findings = [
        {
            "file": "app.py",
            "line": 10,
            "provider_or_lib": "openai",
            "capability": "chat",
            "severity": 2,
            "llm_reason": "The key is embedded directly in code.",
            "remediation": "Move the key to an environment variable.",
            "llm_secure_example": "client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])",
        }
    ]

    with patch.object(urllib.request, "urlopen", side_effect=AssertionError("should not fetch")):
        details = reporter._fetch_llm_details(findings, "http://localhost:11434", "qwen", timeout=180)

    only_value = next(iter(details.values()))
    assert "Problematic" in only_value
    assert "Secure Code Example" in only_value
    assert "OPENAI_API_KEY" in only_value


def test_html_report_llm_enrichment_applies_budget_placeholder():
    import urllib.request
    from reports import html_report as report_mod

    reporter = HTMLReporter(output_dir=tempfile.mkdtemp(), scan_id="20260318_180100")
    findings = [
        {"file": f"app{i}.py", "line": i, "provider_or_lib": "openai", "capability": "chat", "severity": 2}
        for i in range(report_mod.REPORT_LLM_MAX_FINDINGS + 2)
    ]

    class FakeResponse(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(req.full_url)
        payload = json.dumps({"message": {"content": "## Why It's Problematic\nIssue.\n## How to Fix It\n- Fix\n- Test\n- Review\n## References\nhttps://owasp.org"}}).encode("utf-8")
        return FakeResponse(payload)

    with patch.object(urllib.request, "urlopen", side_effect=fake_urlopen):
        details = reporter._fetch_llm_details(findings, "http://localhost:11434", "qwen", timeout=180)

    assert len(calls) == report_mod.REPORT_LLM_MAX_FINDINGS
    skipped_key = f"app{report_mod.REPORT_LLM_MAX_FINDINGS}.py:{report_mod.REPORT_LLM_MAX_FINDINGS}:openai"
    assert "skipped for this finding" in details[skipped_key]


def test_html_report_llm_enrichment_timeout_returns_placeholder():
    import urllib.request

    reporter = HTMLReporter(output_dir=tempfile.mkdtemp(), scan_id="20260318_180150")
    findings = [
        {"file": "app.py", "line": 10, "provider_or_lib": "openai", "capability": "chat", "severity": 2}
    ]

    with patch.object(urllib.request, "urlopen", side_effect=TimeoutError("timed out")):
        details = reporter._fetch_llm_details(findings, "http://localhost:11434", "qwen", timeout=180)

    assert len(details) == 1
    only_value = next(iter(details.values()))
    assert "LLM unavailable (qwen): timed out" in only_value


def test_html_report_llm_enrichment_retries_once_after_timeout():
    import urllib.request

    reporter = HTMLReporter(output_dir=tempfile.mkdtemp(), scan_id="20260318_180151")
    findings = [
        {"file": "app.py", "line": 10, "provider_or_lib": "openai", "capability": "chat", "severity": 2}
    ]

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return self._payload

    payload = json.dumps({
        "message": {
            "content": "## Why It's Problematic\nIssue.\n## How to Fix It\n- Fix\n- Test\n- Review\n## References\nhttps://owasp.org"
        }
    }).encode("utf-8")

    with patch.object(urllib.request, "urlopen", side_effect=[TimeoutError("timed out"), FakeResponse(payload)]):
        details = reporter._fetch_llm_details(findings, "http://localhost:11434", "qwen", timeout=180)

    only_value = next(iter(details.values()))
    assert "LLM unavailable" not in only_value
    assert "Why It's Problematic" in only_value


def test_generate_html_report_builds_and_persists_html_artifact_on_demand():
    from services.scan_jobs import ScanJobPaths, ScanJobService

    temp_root = Path(tempfile.mkdtemp())
    output_dir = temp_root / "output"
    service = ScanJobService(
        app_version="test",
        paths=ScanJobPaths(
            output_dir=str(output_dir),
            temp_dir=str(temp_root / "tmp"),
            policy_file=str(temp_root / "policy.json"),
            owner_map_file=str(temp_root / "owner_map.json"),
            suppressions_file=str(temp_root / "ai_scanner_suppressions.json"),
            history_file=str(temp_root / "scan_history.json"),
            log_dir=str(temp_root / "logs"),
            db_file=str(temp_root / "scan_jobs.db"),
            llm_cfg_file=str(temp_root / "llm.json"),
        ),
        load_policy=lambda path: {},
        load_owner_map=lambda path: {},
        policy_version=lambda path: "test",
        utc_now_iso=lambda: "2026-03-19T12:00:00Z",
        git_head_commit=lambda repo_dir: "deadbeef",
        ollama_ping=lambda url, timeout=0.5: False,
    )

    record = {
        "scan_id": "20260319_120000",
        "project_key": "LOCAL",
        "repo_slugs": ["demo-repo"],
        "state": "done",
        "duration_s": 12,
        "started_at_utc": "2026-03-19T12:00:00Z",
        "completed_at_utc": "2026-03-19T12:00:12Z",
        "tool_version": "test",
        "policy_version": "test",
        "operator": "tester",
        "total": 1,
        "delta": {},
        "inventory": {"repos_total": 1},
        "llm_model": "qwen2.5-coder:7b-instruct",
        "llm_model_info": {"name": "qwen2.5-coder:7b-instruct"},
        "pre_llm_count": 1,
        "post_llm_count": 1,
        "repo_details": {"demo-repo": {"owner": "User", "branch": "main", "commit": "abc123"}},
        "reports": {"__all__": {"csv_name": "AI_Scan_Report_LOCAL_demo-repo_20260319_120000.csv"}},
        "findings": [
            {
                "severity": 2,
                "ai_category": "External AI API",
                "repo": "demo-repo",
                "project_key": "LOCAL",
                "file": "app.py",
                "line": 10,
                "policy_status": "REVIEW",
                "provider_or_lib": "openai",
                "capability": "chat",
                "description": "OpenAI usage",
                "context": "production",
            }
        ],
    }
    service._upsert_job_record(record)

    updated = service.generate_html_report("20260319_120000")

    html_name = updated["reports"]["__all__"]["html_name"]
    html_path = Path(updated["reports"]["__all__"]["html"])
    assert html_name.endswith(".html")
    assert html_path.exists()
    assert html_path.read_text("utf-8").startswith("<!DOCTYPE html>")


def test_save_llm_settings_persists_report_detail_timeout():
    from services.settings_service import SettingsService

    captured = {}
    service = SettingsService(
        load_llm_config=lambda: {"base_url": "http://localhost:11434", "model": "old", "report_detail_timeout_s": 180},
        save_llm_config=lambda cfg: captured.update(cfg),
        save_tls_config=lambda cfg: None,
        ensure_ollama_running=lambda url: {"ok": True},
        list_ollama_models=lambda url: ["m"],
        audit_event=lambda action, **details: None,
        sync_paths=lambda: None,
    )

    result = service.save_llm_settings(
        llm_url="http://localhost:11434",
        llm_model="gpt-oss:20b",
        report_detail_timeout_s="240",
    )

    assert result["ok"] is True
    assert captured["report_detail_timeout_s"] == 240


def test_save_tls_settings_validates_pem_bundle_content():
    import ssl
    from services.settings_service import SettingsService

    temp_root = Path(tempfile.mkdtemp())
    pem_path = temp_root / "corp-root.pem"
    pem_path.write_text("-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n", encoding="utf-8")

    captured = {}
    service = SettingsService(
        load_llm_config=lambda: {},
        save_llm_config=lambda cfg: None,
        save_tls_config=lambda cfg: captured.update(cfg),
        ensure_ollama_running=lambda url: {"ok": True},
        list_ollama_models=lambda url: [],
        audit_event=lambda action, **details: None,
        sync_paths=lambda: None,
    )

    fake_ctx = MagicMock()
    with patch.object(ssl, "create_default_context", return_value=fake_ctx):
        result = service.save_tls_settings(verify_ssl=True, ca_bundle=str(pem_path))

    assert result["ok"] is True
    assert captured["ca_bundle"] == str(pem_path.resolve())
    fake_ctx.load_verify_locations.assert_called_once_with(cafile=str(pem_path.resolve()))


def test_save_tls_settings_rejects_non_pem_bundle_with_clear_error():
    from services.settings_service import SettingsService

    temp_root = Path(tempfile.mkdtemp())
    der_like = temp_root / "corp_rootCA.cer"
    der_like.write_bytes(b"\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xff\x00\x01")

    service = SettingsService(
        load_llm_config=lambda: {},
        save_llm_config=lambda cfg: None,
        save_tls_config=lambda cfg: None,
        ensure_ollama_running=lambda url: {"ok": True},
        list_ollama_models=lambda url: [],
        audit_event=lambda action, **details: None,
        sync_paths=lambda: None,
    )

    try:
        service.save_tls_settings(verify_ssl=True, ca_bundle=str(der_like))
        raise AssertionError("Expected PEM validation failure")
    except ValueError as exc:
        assert "valid PEM certificate bundle" in str(exc)


def test_report_server_allows_only_its_local_origin():
    from reports.report_server import _allowed_origin

    assert _allowed_origin("http://127.0.0.1:8123", 8123) == "http://127.0.0.1:8123"
    assert _allowed_origin("http://localhost:8123", 8123) == "http://localhost:8123"
    assert _allowed_origin("http://127.0.0.1:5757", 8123) is None
    assert _allowed_origin("https://evil.example", 8123) is None
    assert _allowed_origin("", 8123) is None
