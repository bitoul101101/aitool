"""
Tests for AI Usage Scanner components.
Run: python -m pytest tests/ -v
"""

import sys
import os
import subprocess
import tempfile
import json
import base64
import http.client
import urllib.parse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.detector import AIUsageDetector
from scanner.suppressions import (
    TRIAGE_ACCEPTED_RISK,
    TRIAGE_FALSE_POSITIVE,
    TRIAGE_IN_REMEDIATION,
    TRIAGE_REVIEWED,
    TRIAGE_SENT_FOR_REVIEW,
    list_suppressions,
    list_triage,
    upsert_triage,
)
from analyzer.security import SecurityAnalyzer
from aggregator.aggregator import Aggregator
from reports.html_report import HTMLReporter
from reports.json_report import JSONReporter
from services.access_control import ROLE_ADMIN, ROLE_SCANNER, ROLE_TRIAGE, ROLE_VIEWER, UserContext
from services.single_user_state import SingleUserConfig, SingleUserState
from tests._support import install_browser_session as _install_browser_session


# ── Detector tests ────────────────────────────────────────────────

def make_test_file(content: str, suffix=".py") -> Path:
    """Write content to a temp file and return its path."""
    d = tempfile.mkdtemp()
    p = Path(d) / f"test{suffix}"
    p.write_text(content)
    return p.parent, p.name


def test_detects_openai_import():
    detector = AIUsageDetector()
    code = "import openai\nclient = openai.OpenAI()\n"
    tmpdir, fname = make_test_file(code)
    findings = detector.scan(tmpdir)
    providers = [f["provider_or_lib"] for f in findings]
    assert "openai" in providers, f"Expected openai, got: {providers}"


def test_detects_anthropic_import():
    detector = AIUsageDetector()
    code = "import anthropic\nclient = anthropic.Anthropic()\nresult = client.messages.create()\n"
    tmpdir, _ = make_test_file(code)
    findings = detector.scan(tmpdir)
    providers = [f["provider_or_lib"] for f in findings]
    assert "anthropic" in providers


def test_detects_hardcoded_key():
    detector = AIUsageDetector()
    code = 'OPENAI_API_KEY = "sk-abc123def456ghi789jkl012mno345"\n'
    tmpdir, _ = make_test_file(code)
    findings = detector.scan(tmpdir)
    cats = [f["category"] for f in findings]
    assert "Security" in cats


def test_secret_ai_correlation_fires_for_secret_plus_live_ai_usage():
    detector = AIUsageDetector()
    code = (
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'
        "from openai import OpenAI\n"
        "client = OpenAI(api_key=OPENAI_API_KEY)\n"
        'user_input = "hello"\n'
        'prompt = f"Answer: {user_input}"\n'
        'client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"user","content":prompt}])\n'
    )
    tmpdir, _ = make_test_file(code)
    findings = detector.scan(tmpdir, repo_name="repo1")

    correlated = [f for f in findings if f.get("provider_or_lib") == "secret_ai_correlation"]
    assert correlated, "Expected correlated secret-to-AI finding"
    finding = correlated[0]
    assert finding["severity"] == 1
    assert "correlated_evidence" in finding
    assert len(finding["correlated_evidence"]) >= 2
    assert "why_flagged" in finding


def test_secret_ai_correlation_does_not_fire_without_prompt_flow_signal():
    detector = AIUsageDetector()
    code = (
        'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'
        "from openai import OpenAI\n"
        "client = OpenAI(api_key=OPENAI_API_KEY)\n"
    )
    tmpdir, _ = make_test_file(code)
    findings = detector.scan(tmpdir, repo_name="repo1")

    correlated = [f for f in findings if f.get("provider_or_lib") == "secret_ai_correlation"]
    assert not correlated


def test_detects_openai_key_pattern():
    detector = AIUsageDetector()
    code = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'
    tmpdir, _ = make_test_file(code)
    findings = detector.scan(tmpdir)
    providers = [f["provider_or_lib"] for f in findings]
    assert "openai_key_pattern" in providers


def test_detects_rag_pattern():
    detector = AIUsageDetector()
    code = "from langchain.chains import RetrievalQA\nchain = RetrievalQA.from_chain_type()\n"
    tmpdir, _ = make_test_file(code)
    findings = detector.scan(tmpdir)
    cats = [f["category"] for f in findings]
    assert any(c in ("External AI API", "RAG/Vector DB") for c in cats)


def test_detects_notebook():
    detector = AIUsageDetector()
    nb = {
        "nbformat": 4,
        "cells": [
            {
                "cell_type": "code",
                "source": ["import openai\n", "client = openai.OpenAI()\n"],
                "outputs": []
            }
        ]
    }
    d = tempfile.mkdtemp()
    p = Path(d) / "analysis.ipynb"
    p.write_text(json.dumps(nb))
    findings = detector.scan(Path(d))
    assert any(f["is_notebook"] for f in findings), "Expected notebook finding"


def test_notebook_output_secret():
    detector = AIUsageDetector()
    nb = {
        "nbformat": 4,
        "cells": [
            {
                "cell_type": "code",
                "source": ["print(api_key)"],
                "outputs": [{"text": ["sk-secretkey12345678901234567890"]}]
            }
        ]
    }
    d = tempfile.mkdtemp()
    p = Path(d) / "notebook.ipynb"
    p.write_text(json.dumps(nb))
    findings = detector.scan(Path(d))
    providers = [f["provider_or_lib"] for f in findings]
    assert "notebook_output_secret" in providers


def test_deduplication():
    detector = AIUsageDetector()
    # Same exact code = same line numbers = same hashes = deduped
    code = "import openai\nclient = openai.OpenAI()\n"
    tmpdir, _ = make_test_file(code)
    findings1 = detector.scan(tmpdir)
    findings2 = detector.scan(tmpdir)
    # Running scan twice should not produce duplicates within each scan
    hashes1 = [f["_hash"] for f in findings1]
    assert len(hashes1) == len(set(hashes1)), "Duplicate hashes within single scan"


def test_skip_node_modules():
    detector = AIUsageDetector()
    d = Path(tempfile.mkdtemp())
    nm = d / "node_modules" / "openai"
    nm.mkdir(parents=True)
    (nm / "index.py").write_text("import openai\n")
    findings = detector.scan(d)
    assert len(findings) == 0, "node_modules should be skipped"


def test_detector_scan_excludes_explicit_paths():
    detector = AIUsageDetector()
    d = Path(tempfile.mkdtemp())
    (d / "keep.py").write_text("import openai\n", encoding="utf-8")
    excluded = d / "output"
    excluded.mkdir()
    (excluded / "skip.py").write_text("import openai\n", encoding="utf-8")

    findings = detector.scan(d, exclude_paths=["output"])

    files = {finding.get("file") for finding in findings}
    assert "keep.py" in files
    assert "output/skip.py" not in files


def test_self_scan_ignores_internal_pattern_catalog_findings():
    detector = AIUsageDetector()
    code = (
        '{\n'
        '    "pattern": r"exec\\(|eval\\(|subprocess\\.|os\\.system\\(|shell=True",\n'
        '    "category": "Security",\n'
        '    "provider_or_lib": "unsafe_code_exec",\n'
        '}\n'
    )

    findings = detector._scan_text_file_from_content(
        code,
        ".py",
        "scanner/patterns.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    assert findings == []


def test_file_content_to_llm_ignores_local_hashing_of_read_bytes():
    detector = AIUsageDetector()
    code = (
        "from pathlib import Path\n"
        "import hashlib\n"
        "def policy_version(path):\n"
        "    data = Path(path).read_bytes()\n"
        "    return hashlib.sha256(data).hexdigest()[:12]\n"
    )

    findings = detector._scan_text_file_from_content(
        code,
        ".py",
        "app_server.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    assert "file_content_to_llm" not in {f["provider_or_lib"] for f in findings}


def test_self_scan_ignores_internal_local_llm_plumbing_findings():
    detector = AIUsageDetector()

    report_server_code = (
        "class Handler:\n"
        '    ollama_base = "http://localhost:11434"\n'
        "    def proxy(self, body):\n"
        '        target = self.ollama_base.rstrip("/") + "/api/generate"\n'
        "        req = urllib.request.Request(target, data=body, headers={\"Content-Type\": \"application/json\"}, method=\"POST\")\n"
        "        return urllib.request.urlopen(req, timeout=120)\n"
    )
    report_findings = detector._scan_text_file_from_content(
        report_server_code,
        ".py",
        "reports/report_server.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )
    assert "ollama" not in {f["provider_or_lib"] for f in report_findings}
    assert "http_response_to_llm" not in {f["provider_or_lib"] for f in report_findings}

    settings_code = (
        "def save_settings(llm_url):\n"
        '    return {\"ok\": True, \"models\": list_ollama_models(llm_url or \"http://localhost:11434\")}\n'
    )
    settings_findings = detector._scan_text_file_from_content(
        settings_code,
        ".py",
        "services/settings_service.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )
    assert "ollama" not in {f["provider_or_lib"] for f in settings_findings}

    reviewer_code = (
        "def challenge(user_message):\n"
        "    body = {\n"
        '        \"messages\": [\n'
        '            {\"role\": \"system\", \"content\": _CHALLENGE_SYSTEM},\n'
        '            {\"role\": \"user\", \"content\": user_message},\n'
        "        ],\n"
        "        \"temperature\": 0.0,\n"
        "    }\n"
        "    return body\n"
    )
    reviewer_findings = detector._scan_text_file_from_content(
        reviewer_code,
        ".py",
        "scanner/llm_reviewer.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )
    assert "prompt_injection_risk" not in {f["provider_or_lib"] for f in reviewer_findings}


def test_self_scan_ignores_internal_cross_file_analysis_cache_reads():
    detector = AIUsageDetector()
    code = (
        "file_contents = {}\n"
        "if suffix in _CODE_EXTENSIONS and fpath.stat().st_size < 200_000:\n"
        "    try:\n"
        '        file_contents[rel] = fpath.read_text(encoding=\"utf-8\", errors=\"replace\")\n'
        "    except OSError:\n"
        "        pass\n"
    )

    findings = detector._scan_text_file_from_content(
        code,
        ".py",
        "scanner/detector.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    libs = {f["provider_or_lib"] for f in findings}
    assert "document_embedded_instruction" not in libs
    assert "file_content_to_llm" not in libs


def test_self_scan_ignores_internal_bitbucket_clone_and_security_advice_noise():
    detector = AIUsageDetector()

    bitbucket_code = (
        "import os, subprocess\n"
        "def clone(cmd, verify_ssl):\n"
        "    env = os.environ.copy()\n"
        "    if not verify_ssl:\n"
        '        env[\"GIT_SSL_NO_VERIFY\"] = \"1\"\n'
        "    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)\n"
    )
    bitbucket_findings = detector._scan_text_file_from_content(
        bitbucket_code,
        ".py",
        "scanner/bitbucket.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )
    bitbucket_libs = {f["provider_or_lib"] for f in bitbucket_findings}
    assert "unsafe_code_exec" not in bitbucket_libs
    assert "excessive_agent_autonomy" not in bitbucket_libs

    security_advice_code = (
        "SECURITY_GUIDANCE = {\n"
        '    \"unsafe_code_exec\": \"Never exec() model outputs directly in production.\",\n'
        '    \"sql_injection_risk\": \"Never pass LLM-generated SQL strings directly to execute().\",\n'
        "}\n"
    )
    guidance_findings = detector._scan_text_file_from_content(
        security_advice_code,
        ".py",
        "analyzer/security.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )
    guidance_libs = {f["provider_or_lib"] for f in guidance_findings}
    assert "unsafe_code_exec" not in guidance_libs
    assert "sql_injection_risk" not in guidance_libs


def test_self_scan_ignores_internal_detector_ui_and_test_fixture_noise():
    detector = AIUsageDetector()

    detector_code = (
        '_TOOL_MARKER_RE = re.compile(r"Tool\\\\s*\\\\(|BaseTool|StructuredTool|@tool\\\\b", re.IGNORECASE)\n'
        '_FIXED_ARGV_SUBPROCESS_RE = re.compile(r"^\\\\s*\\\\w+\\\\s*=\\\\s*subprocess\\\\.(?:run|call|Popen)")\n'
    )
    detector_findings = detector._scan_text_file_from_content(
        detector_code,
        ".py",
        "scanner/detector.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )
    detector_libs = {f["provider_or_lib"] for f in detector_findings}
    assert "llm_tool_no_authz" not in detector_libs
    assert "unsafe_code_exec" not in detector_libs

    ui_code = (
        'project_links = "".join(\n'
        '    f\'<a href="/scan?project={_esc(p.get("key",""))}">{_esc(p.get("key",""))}</a>\'\n'
        "    for p in projects\n"
        ")\n"
    )
    ui_findings = detector._scan_text_file_from_content(
        ui_code,
        ".py",
        "services/web_pages.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )
    assert "sql_injection_risk" not in {f["provider_or_lib"] for f in ui_findings}

    fixture_code = 'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'
    fixture_findings = detector._scan_text_file_from_content(
        fixture_code,
        ".py",
        "tests/test_scanner.py",
        "aitool",
        ctx_str="test",
        is_test=True,
    )
    fixture_libs = {f["provider_or_lib"] for f in fixture_findings}
    assert "openai_key_pattern" not in fixture_libs
    assert "entropy_secret" not in fixture_libs
    assert "hardcoded_key" not in fixture_libs


def test_shell_cmd_from_llm_ignores_fixed_argv_subprocess_calls():
    detector = AIUsageDetector()
    code = (
        "import subprocess\n"
        "def gpu_stats():\n"
        "    result = subprocess.run(\n"
        '        ["nvidia-smi", "--query-gpu=name"],\n'
        "        capture_output=True,\n"
        "        text=True,\n"
        "        timeout=2,\n"
        "    )\n"
        "    return result.stdout\n"
    )

    findings = detector._scan_text_file_from_content(
        code,
        ".py",
        "app_server.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    assert "shell_cmd_from_llm" not in {f["provider_or_lib"] for f in findings}
    assert "unsafe_code_exec" not in {f["provider_or_lib"] for f in findings}


def test_unsafe_code_exec_ignores_subprocess_exception_handling():
    detector = AIUsageDetector()
    code = (
        "import subprocess\n"
        "def gpu_stats():\n"
        "    try:\n"
        '        return subprocess.run(["nvidia-smi"], capture_output=True, text=True).stdout\n'
        "    except (OSError, subprocess.SubprocessError, ValueError):\n"
        '        return "Unavailable"\n'
    )

    findings = detector._scan_text_file_from_content(
        code,
        ".py",
        "app_server.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    assert "unsafe_code_exec" not in {f["provider_or_lib"] for f in findings}


def test_app_server_gpu_snapshot_does_not_trigger_shell_execution_rules():
    detector = AIUsageDetector()
    content = Path(r"C:\aitool\app_server.py").read_text(encoding="utf-8")

    findings = detector._scan_text_file_from_content(
        content,
        ".py",
        "app_server.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    risky = {
        (f["provider_or_lib"], int(f.get("line", 0) or 0))
        for f in findings
        if f.get("provider_or_lib") in {"shell_cmd_from_llm", "unsafe_code_exec"}
    }
    assert not risky


def test_app_server_policy_version_does_not_trigger_file_content_to_llm():
    detector = AIUsageDetector()
    content = Path(r"C:\aitool\app_server.py").read_text(encoding="utf-8")

    findings = detector._scan_text_file_from_content(
        content,
        ".py",
        "app_server.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    risky = {
        (f["provider_or_lib"], int(f.get("line", 0) or 0))
        for f in findings
        if f.get("provider_or_lib") == "file_content_to_llm"
    }
    assert not risky


def test_sql_in_tool_description_ignores_parameterized_sql_without_tool_context():
    detector = AIUsageDetector()
    code = (
        "import sqlite3\n"
        "def load_record(conn, scan_id):\n"
        "    return conn.execute(\n"
        '        "SELECT record_json FROM scan_jobs WHERE scan_id = ?",\n'
        "        (scan_id,),\n"
        "    ).fetchone()\n"
    )

    findings = detector._scan_text_file_from_content(
        code,
        ".py",
        "services/scan_jobs.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    assert "sql_in_tool_description" not in {f["provider_or_lib"] for f in findings}


def test_file_content_to_llm_requires_real_prompt_or_llm_sink_context():
    detector = AIUsageDetector()
    code = (
        "from pathlib import Path\n"
        "import hashlib\n"
        "def policy_version(path: str) -> str:\n"
        "    data = Path(path).read_bytes()\n"
        "    return hashlib.sha256(data).hexdigest()[:12]\n"
    )

    findings = detector._scan_text_file_from_content(
        code,
        ".py",
        "app_server.py",
        "aitool",
        ctx_str="production",
        is_test=False,
    )

    assert "file_content_to_llm" not in {f["provider_or_lib"] for f in findings}


# ── Security Analyzer tests ───────────────────────────────────────

POLICY = {
    "approved_providers": ["azure_openai"],
    "restricted_providers": ["openai", "anthropic"],
    "banned_providers": ["some_banned_lib"],
}


def make_finding(provider="openai", sev=2, cat="External AI API", context="production"):
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


def test_restricted_policy():
    analyzer = SecurityAnalyzer(policy=POLICY)
    f = make_finding(provider="openai", sev=2)
    results = analyzer.analyze([f])
    assert results[0]["policy_status"] == "RESTRICTED"
    assert results[0]["severity"] <= 2


def test_approved_policy():
    analyzer = SecurityAnalyzer(policy=POLICY)
    f = make_finding(provider="azure_openai", sev=2)
    results = analyzer.analyze([f])
    assert results[0]["policy_status"] == "APPROVED"


def test_banned_policy():
    analyzer = SecurityAnalyzer(policy=POLICY)
    f = make_finding(provider="some_banned_lib", sev=3)
    results = analyzer.analyze([f])
    assert results[0]["policy_status"] == "BANNED"
    assert results[0]["severity"] == 1


def test_security_category_critical():
    analyzer = SecurityAnalyzer(policy=POLICY)
    f = make_finding(provider="hardcoded_key", sev=2, cat="Security")
    results = analyzer.analyze([f])
    assert results[0]["policy_status"] == "CRITICAL"
    assert results[0]["severity"] == 1


def test_non_production_security_context_is_not_escalated_to_critical():
    analyzer = SecurityAnalyzer(policy=POLICY)
    f = make_finding(
        provider="unsafe_code_exec",
        sev=2,
        cat="Security",
        context="docs",
    )
    results = analyzer.analyze([f])
    assert results[0]["policy_status"] == "REVIEW"
    assert results[0]["severity"] >= 3


def test_real_secret_remains_critical_even_in_test_context():
    analyzer = SecurityAnalyzer(policy=POLICY)
    f = make_finding(
        provider="openai_key_pattern",
        sev=3,
        cat="Security",
        context="test",
    )
    results = analyzer.analyze([f])
    assert results[0]["policy_status"] == "CRITICAL"
    assert results[0]["severity"] == 1


def test_remediation_assigned():
    analyzer = SecurityAnalyzer(policy=POLICY)
    f = make_finding(provider="openai", sev=2)
    results = analyzer.analyze([f])
    assert results[0]["remediation"]
    assert len(results[0]["remediation"]) > 10


# ── Aggregator tests ──────────────────────────────────────────────

def test_aggregator_dedup():
    agg = Aggregator(min_severity=4)
    findings = [
        {**make_finding(), "product_house": "PH1", "owner": "A",
         "last_seen": "20250101", "_hash": "x1",
         "risk": "High", "severity_label": "Sev-2", "is_notebook": False,
         "match": "", "description": "test"},
        {**make_finding(), "product_house": "PH1", "owner": "A",
         "last_seen": "20250101", "_hash": "x1",  # same hash = duplicate
         "risk": "High", "severity_label": "Sev-2", "is_notebook": False,
         "match": "", "description": "test"},
    ]
    result = agg.process(findings)
    assert len(result) == 1, f"Expected 1 after dedup, got {len(result)}"


def test_aggregator_severity_filter():
    agg = Aggregator(min_severity=2)  # Only sev 1 and 2
    findings = []
    for sev in [1, 2, 3, 4]:
        f = {**make_finding(sev=sev), "product_house": "PH1", "owner": "A",
             "last_seen": "20250101", "_hash": f"h{sev}",
             "risk": "X", "severity_label": f"Sev-{sev}", "is_notebook": False,
             "match": "", "description": "test", "remediation": "fix"}
        findings.append(f)
    result = agg.process(findings)
    for r in result:
        assert r["severity"] <= 2, f"Expected sev ≤ 2, got {r['severity']}"


# ══════════════════════════════════════════════════════════════════
# New tests — added during architecture review
# Covers: path_context, placeholder suppression, multi-hit dedup,
#         challenge pass logic, delta baseline, history persistence,
#         pattern cache, _scan_text_file_from_content delegation.
# ══════════════════════════════════════════════════════════════════

import threading
import time
import re
from unittest.mock import patch, MagicMock

# ── path_context enforcement ──────────────────────────────────────

def test_helm_pattern_only_fires_in_helm_paths():
    """helm_ai_values must NOT fire on arbitrary YAML files."""
    detector = AIUsageDetector()
    # openai_key: matches helm_ai_values pattern
    code = "openai_key: some-model-name\n"
    d = Path(tempfile.mkdtemp())

    # Should fire in helm context
    helm_dir = d / "helm"
    helm_dir.mkdir()
    (helm_dir / "values.yaml").write_text(code)
    findings_helm = detector.scan(helm_dir)
    helm_hits = [f for f in findings_helm if f["provider_or_lib"] == "helm_ai_values"]
    assert helm_hits, "helm_ai_values should fire under helm/ directory"

    # Should NOT fire in unrelated YAML
    src_dir = d / "src"
    src_dir.mkdir()
    (src_dir / "config.yaml").write_text(code)
    findings_src = detector.scan(src_dir)
    src_hits = [f for f in findings_src if f["provider_or_lib"] == "helm_ai_values"]
    assert not src_hits, f"helm_ai_values should not fire in src/config.yaml, got {src_hits}"


def test_k8s_pattern_only_fires_in_k8s_paths():
    """k8s_ai_manifest must NOT fire outside k8s/manifests directories.

    Both files are placed under a common root so rel_path includes the
    parent directory — that is what path_context matches against.
    """
    detector = AIUsageDetector()
    code = "annotations:\n  kserve.io/enabled: \"true\"\n"
    d = Path(tempfile.mkdtemp())

    # Should fire under manifests/
    m_dir = d / "manifests"
    m_dir.mkdir()
    (m_dir / "deploy.yaml").write_text(code)
    findings_m = detector.scan(d)
    k8s_hits = [f for f in findings_m if f["provider_or_lib"] == "k8s_ai_manifest"]
    assert k8s_hits, "k8s_ai_manifest should fire under manifests/"

    # Should NOT fire under src/
    d2 = Path(tempfile.mkdtemp())
    src_dir = d2 / "src"
    src_dir.mkdir()
    (src_dir / "deploy.yaml").write_text(code)
    findings_src = detector.scan(d2)
    src_hits = [f for f in findings_src if f["provider_or_lib"] == "k8s_ai_manifest"]
    assert not src_hits, f"k8s_ai_manifest should not fire in src/, got {src_hits}"


def test_path_context_enforced_in_history_scanner():
    """path_context gate must apply in _scan_text_file_from_content too."""
    detector = AIUsageDetector()
    helm_code = "openai_key: my-model\n"

    # Deleted file from a helm path — should fire
    findings_helm = detector._scan_text_file_from_content(
        helm_code, ".yaml", "helm/values.yaml", "repo"
    )
    helm_hits = [f for f in findings_helm if f["provider_or_lib"] == "helm_ai_values"]
    assert helm_hits, "helm pattern should fire on helm/values.yaml in history scan"

    # Deleted file from unrelated path — should NOT fire
    findings_src = detector._scan_text_file_from_content(
        helm_code, ".yaml", "src/config.yaml", "repo"
    )
    src_hits = [f for f in findings_src if f["provider_or_lib"] == "helm_ai_values"]
    assert not src_hits, "helm pattern should not fire on src/config.yaml in history scan"


# ── _PLACEHOLDER_RE suppression ──────────────────────────────────

def test_placeholder_value_suppressed():
    """replace-with-* style values must not be reported as hardcoded keys."""
    detector = AIUsageDetector()
    placeholders = [
        'HF_TOKEN="replace-with-your-huggingface-token"',
        'OPENAI_API_KEY="your-api-key"',
        'OPENAI_API_KEY=YOUR_API_KEY',
        'OPENAI_API_KEY=changeme',
        'OPENAI_API_KEY=<INSERT_KEY_HERE>',
        'GROQ_API_KEY=placeholder-key',
        'OPENAI_API_KEY=example-key',
    ]
    for line in placeholders:
        d = Path(tempfile.mkdtemp())
        (d / "config.py").write_text(line + "\n")
        findings = detector.scan(d)
        sec = [f for f in findings if f["provider_or_lib"] == "hardcoded_key"]
        assert not sec, f"Placeholder should be suppressed: {line!r}"


def test_real_key_not_suppressed():
    """Real-looking keys must still be detected."""
    detector = AIUsageDetector()
    d = Path(tempfile.mkdtemp())
    (d / "config.py").write_text('OPENAI_API_KEY="sk-proj-xKj9mNpLqR2sT4uVwXyZ12"\n')
    findings = detector.scan(d)
    sec = [f for f in findings
           if f.get("provider_or_lib") in ("hardcoded_key", "openai_key_pattern")]
    assert sec, "Real API key should be detected"


# ── Multi-hit deduplication ───────────────────────────────────────

def test_multihit_deduplication():
    """Same credential matching multiple patterns → one finding, not two."""
    detector = AIUsageDetector()
    # OPENAI_API_KEY: fires both hardcoded_key and docker_compose_key
    d = Path(tempfile.mkdtemp())
    (d / "docker-compose.yml").write_text(
        'OPENAI_API_KEY: "sk-realkey12345678901234567890"\n'
    )
    findings = detector.scan(d)
    # All findings for the same file+match should have unique hashes
    hashes = [f["_hash"] for f in findings]
    assert len(hashes) == len(set(hashes)), (
        f"Duplicate hashes — multi-hit not deduped: "
        f"{[f['provider_or_lib'] for f in findings]}"
    )


def test_cross_repo_notebook_hashes_differ():
    """Same notebook path in two repos must produce different hashes."""
    detector = AIUsageDetector()
    nb = json.dumps({
        "nbformat": 4,
        "cells": [{
            "cell_type": "code",
            "source": ["print(key)"],
            "outputs": [{"text": ["sk-secretkey12345678901234"]}]
        }]
    })
    p = Path(tempfile.mkdtemp()) / "analysis.ipynb"
    p.write_text(nb)
    findings_a = detector._scan_notebook(p, "notebooks/analysis.ipynb", "repo-A")
    findings_b = detector._scan_notebook(p, "notebooks/analysis.ipynb", "repo-B")
    hashes_a = {f["_hash"] for f in findings_a}
    hashes_b = {f["_hash"] for f in findings_b}
    assert not hashes_a & hashes_b, (
        "Same notebook path in two repos produced identical hashes — "
        "would cause cross-repo deduplication"
    )


# ── Pattern cache ─────────────────────────────────────────────────

def test_pattern_cache_shared_across_instances():
    """Multiple AIUsageDetector instances must share the compiled pattern list."""
    from scanner.detector import _get_compiled_patterns
    d1 = AIUsageDetector()
    d2 = AIUsageDetector()
    assert d1._compiled is d2._compiled, (
        "Each instance has its own compiled list — cache not working"
    )
    assert len(d1._compiled) == len(_get_compiled_patterns())


def test_pattern_cache_is_populated():
    """Compiled cache must contain patterns with _re, _guard, _path_ctx keys."""
    from scanner.detector import _get_compiled_patterns
    compiled = _get_compiled_patterns()
    assert len(compiled) > 50, f"Expected >50 compiled patterns, got {len(compiled)}"
    for p in compiled:
        assert "_re" in p, f"Missing _re in pattern {p.get('provider_or_lib')}"
        assert "_guard" in p, f"Missing _guard in pattern {p.get('provider_or_lib')}"
        assert "_path_ctx" in p, f"Missing _path_ctx in pattern {p.get('provider_or_lib')}"


# ── _scan_text_file delegation ────────────────────────────────────

def test_scan_text_file_sets_docs_context():
    """Files in docs/ paths must get context=docs and sev_bump applied."""
    detector = AIUsageDetector()
    d = Path(tempfile.mkdtemp())
    docs = d / "docs"
    docs.mkdir()
    # Severity-1 finding in docs should become severity-3 (bump +2)
    (docs / "setup.md").write_text("import openai\nclient = openai.OpenAI()\n")
    findings = detector.scan(docs)
    for f in findings:
        assert f["context"] == "docs", f"Expected docs context, got {f['context']}"
        assert f["severity"] >= 3, (
            f"Docs finding severity {f['severity']} not bumped (expected ≥3)"
        )


def test_scan_text_file_from_content_deleted_file_default():
    """History scanner path must produce context=deleted_file by default."""
    detector = AIUsageDetector()
    findings = detector._scan_text_file_from_content(
        "import openai\nclient = openai.OpenAI()\n",
        ".py", "src/app.py", "my-repo"
    )
    assert findings, "Expected findings from history scan"
    for f in findings:
        assert f["context"] == "deleted_file", (
            f"Expected deleted_file, got {f['context']}"
        )


def test_scan_text_file_from_content_context_override():
    """Context override must flow through to all findings."""
    detector = AIUsageDetector()
    findings = detector._scan_text_file_from_content(
        "import openai\nclient = openai.OpenAI()\n",
        ".py", "tests/test_app.py", "my-repo",
        ctx_str="test", sev_bump=2, is_test=True
    )
    assert findings
    for f in findings:
        assert f["context"] == "test", f"Expected test, got {f['context']}"


# ── delta.py baseline comparison ─────────────────────────────────

def test_delta_no_baseline():
    """First scan: has_baseline=False, all findings counted as new."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from reports.delta import build_delta_meta

    findings = [
        {"_hash": "aaa", "provider_or_lib": "openai"},
        {"_hash": "bbb", "provider_or_lib": "anthropic"},
    ]
    d = Path(tempfile.mkdtemp())
    meta = build_delta_meta(findings, str(d), "PROJ", "my-repo")
    assert meta["has_baseline"] is False
    assert meta["new_count"] == 2


def test_delta_with_baseline():
    """Second scan: correctly identifies new, fixed, unchanged findings."""
    from reports.delta import build_delta_meta
    import csv

    findings_scan1 = [
        {"_hash": "aaa", "finding_id": "aaa", "provider_or_lib": "openai"},
        {"_hash": "bbb", "finding_id": "bbb", "provider_or_lib": "anthropic"},
    ]
    findings_scan2 = [
        {"_hash": "bbb", "finding_id": "bbb", "provider_or_lib": "anthropic"},  # unchanged
        {"_hash": "ccc", "finding_id": "ccc", "provider_or_lib": "langchain"},  # new
        # aaa is absent = fixed
    ]

    d = Path(tempfile.mkdtemp())
    # Write a baseline CSV (scan 1)
    baseline = d / "AI_Scan_Report_PROJ_my-repo_20250101_120000.csv"
    with open(baseline, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["finding_id", "repo", "file", "line"])
        writer.writeheader()
        for finding in findings_scan1:
            writer.writerow({
                "finding_id": finding["finding_id"],
                "repo": "my-repo",
                "file": "app.py",
                "line": "8",
            })

    meta = build_delta_meta(findings_scan2, str(d), "PROJ", "my-repo")
    assert meta["has_baseline"] is True
    assert meta["new_count"] == 1,       f"Expected 1 new, got {meta['new_count']}"
    assert meta["fixed_count"] == 1,     f"Expected 1 fixed, got {meta['fixed_count']}"
    assert meta["unchanged_count"] == 1, f"Expected 1 unchanged, got {meta['unchanged_count']}"
    assert meta["existing_count"] == 1
    assert "ccc" in meta["new_hashes"],  "ccc should be in new_hashes"
    assert "bbb" not in meta["new_hashes"], "bbb is unchanged, not new"
    assert meta["fixed_findings"][0]["finding_id"] == "aaa"
    assert meta["fixed_findings"][0]["file"] == "app.py"


def test_delta_with_baseline_scoped_to_changed_files():
    from reports.delta import build_delta_meta
    import csv

    findings_scan2 = [
        {"_hash": "bbb", "finding_id": "bbb", "provider_or_lib": "anthropic", "file": "app.py"},
    ]

    d = Path(tempfile.mkdtemp())
    baseline = d / "AI_Scan_Report_PROJ_my-repo_20250101_120000.csv"
    with open(baseline, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["finding_id", "repo", "file", "line"])
        writer.writeheader()
        writer.writerow({"finding_id": "bbb", "repo": "my-repo", "file": "app.py", "line": "8"})
        writer.writerow({"finding_id": "aaa", "repo": "my-repo", "file": "old.py", "line": "12"})

    meta = build_delta_meta(
        findings_scan2,
        str(d),
        "PROJ",
        "my-repo",
        scanned_files={"app.py"},
    )

    assert meta["has_baseline"] is True
    assert meta["scope_limited"] is True
    assert meta["scope_file_count"] == 1
    assert meta["new_count"] == 0
    assert meta["existing_count"] == 1
    assert meta["fixed_count"] == 0


def test_csv_reporter_writes_stable_finding_id_for_baselines():
    import csv
    from reports.csv_report import CSVReporter

    d = Path(tempfile.mkdtemp())
    reporter = CSVReporter(output_dir=str(d), scan_id="scan1")
    csv_path = Path(reporter.write_csv([{
        "_hash": "hash-123",
        "delta_status": "new",
        "repo": "repo1",
        "provider_or_lib": "openai",
        "capability": "Text generation",
        "policy_status": "REVIEW",
        "risk": "medium",
        "severity": 3,
        "file": "app.py",
        "line": 9,
        "snippet": "client.responses.create(...)",
        "owner": "alice",
        "last_seen": "20260318_100000",
        "remediation": "Review use",
    }]))

    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    assert rows[0]["finding_id"] == "hash-123"
    assert rows[0]["delta_status"] == "new"


def test_detector_scan_include_paths_limits_files():
    root = Path(tempfile.mkdtemp())
    (root / "keep.py").write_text("import openai\nclient = openai.OpenAI()\n", encoding="utf-8")
    (root / "skip.py").write_text("import openai\nclient = openai.OpenAI()\n", encoding="utf-8")

    detector = AIUsageDetector()
    findings, _ = detector.scan(root, repo_name="repo1", return_file_contents=True, include_paths=["keep.py"])

    files = {finding.get("file") for finding in findings}
    assert "keep.py" in files
    assert "skip.py" not in files


def test_local_scan_excludes_runtime_artifacts_under_repo_root():
    from services.scan_jobs import ScanJobPaths, ScanJobService

    temp_root = Path(tempfile.mkdtemp())
    service = ScanJobService(
        app_version="test",
        paths=ScanJobPaths(
            output_dir=str(temp_root / "output"),
            temp_dir=str(temp_root / "tmp"),
            policy_file=str(temp_root / "policy.json"),
            owner_map_file=str(temp_root / "owner_map.json"),
            suppressions_file=str(temp_root / "ai_scanner_suppressions.json"),
            history_file=str(temp_root / "scan_history.json"),
            log_dir=str(temp_root / "logs"),
            db_file=str(temp_root / "scan_jobs.db"),
        ),
        load_policy=lambda path: {},
        load_owner_map=lambda path: {},
        policy_version=lambda path: "test",
        utc_now_iso=lambda: "2026-03-19T11:30:00Z",
        git_head_commit=lambda repo_dir: "deadbeef",
        ollama_ping=lambda url, timeout=0.5: False,
    )

    excludes = service._local_scan_excludes(temp_root)

    assert "output" in excludes
    assert "tmp" in excludes
    assert "logs" in excludes
    assert "scan_history.json" in excludes
    assert "scan_jobs.db" in excludes


def test_start_scan_requires_compare_ref_for_branch_diff():
    from services.api_actions import start_scan
    from services.scan_jobs import ScanSession

    class DummyOperatorState:
        client = object()

        class Ctx:
            username = "tester"

        ctx = Ctx()

    try:
        start_scan(
            body={
                "project_key": "PROJ",
                "repo_slugs": ["repo1"],
                "scan_scope": "branch_diff",
            },
            session_factory=ScanSession,
            current_session=ScanSession(),
            operator_state=DummyOperatorState(),
            save_llm_config=lambda cfg: None,
            audit_event=lambda *args, **kwargs: None,
        )
    except ValueError as exc:
        assert "compare_ref required" in str(exc)
    else:
        raise AssertionError("branch_diff scans should require compare_ref")


def test_start_scan_accepts_local_repo_without_bitbucket_client():
    from services.api_actions import start_scan
    from services.scan_jobs import ScanSession

    repo_dir = Path(tempfile.mkdtemp())
    (repo_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")

    class DummyOperatorState:
        client = None

        class Ctx:
            username = "tester"

        ctx = Ctx()

    session = start_scan(
        body={
            "local_repo_path": str(repo_dir),
            "llm_model": "demo-model",
        },
        session_factory=ScanSession,
        current_session=ScanSession(),
        operator_state=DummyOperatorState(),
        save_llm_config=lambda cfg: None,
        audit_event=lambda *args, **kwargs: None,
    )

    assert session.scan_source == "local"
    assert session.local_repo_path == str(repo_dir.resolve())
    assert session.project_key == "LOCAL"
    assert session.repo_slugs == [repo_dir.name]


def test_start_scan_forces_local_project_key_even_when_form_posts_bitbucket_project():
    from services.api_actions import start_scan
    from services.scan_jobs import ScanSession

    class DummyOperatorState:
        client = None

        class Ctx:
            username = "tester"

        ctx = Ctx()

    repo_dir = Path(tempfile.mkdtemp())
    session = start_scan(
        body={
            "project_key": "COGI",
            "local_repo_path": str(repo_dir),
            "llm_model": "demo-model",
        },
        session_factory=ScanSession,
        current_session=ScanSession(),
        operator_state=DummyOperatorState(),
        save_llm_config=lambda cfg: None,
        audit_event=lambda *args, **kwargs: None,
    )

    assert session.scan_source == "local"
    assert session.project_key == "LOCAL"


def test_build_inventory_aggregates_ai_usage_profiles():
    from services.inventory import build_inventory

    inventory = build_inventory([
        {
            "repo": "repo1",
            "provider_or_lib": "openai",
            "ai_category": "External AI API",
            "capability": "LLM/Completion",
            "match": "gpt-4o",
            "snippet": "client.responses.create(model='gpt-4o')",
        },
        {
            "repo": "repo1",
            "provider_or_lib": "pinecone",
            "ai_category": "RAG/Vector DB",
            "capability": "Vector DB",
            "snippet": "pinecone.Index('docs')",
        },
        {
            "repo": "repo2",
            "provider_or_lib": "langchain",
            "ai_category": "External AI API",
            "capability": "LLM Orchestration",
            "snippet": "PromptTemplate.from_template(...)",
        },
        {
            "repo": "repo2",
            "provider_or_lib": "vllm",
            "ai_category": "Local LLM Runtime",
            "capability": "Local Inference Server",
        },
    ])

    assert inventory["repos_using_ai_count"] == 2
    assert inventory["provider_count"] >= 3
    assert "gpt-4o" in inventory["models"]
    assert inventory["embeddings_vector_db_repos"] == 1
    assert inventory["prompt_handling_repos"] >= 1
    assert inventory["model_serving_repos"] == 1
    assert inventory["agent_tool_use_repos"] >= 1


# ── History persistence (_save_history_record) ────────────────────

def test_save_history_record_creates_file():
    """_save_history_record must write a valid JSON file."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    # Temporarily redirect OUTPUT_DIR/HISTORY_FILE/LOG_DIR to a temp location
    import app_server as srv
    orig_out  = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log  = srv.LOG_DIR
    orig_db   = srv.DB_FILE

    d = Path(tempfile.mkdtemp())
    srv.OUTPUT_DIR   = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR      = str(d / "logs")
    srv.DB_FILE      = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        session = srv.ScanSession()
        session.scan_id      = "20250315_120000"
        session.project_key  = "TEST"
        session.repo_slugs   = ["my-repo"]
        session.state        = "done"
        session.scan_duration_s = 42
        session.llm_model    = "qwen2.5-coder:7b"
        session.llm_model_info = {"name": "qwen2.5-coder:7b"}
        session.operator = "Security Engineer"
        session.started_at_utc = "2025-03-15T12:00:00Z"
        session.completed_at_utc = "2025-03-15T12:00:42Z"
        session.policy_version = "abc123def456"
        session.tool_version = "19.1"
        session.repo_details = {
            "my-repo": {"owner": "alice", "branch": "main", "commit": "deadbeefcafebabe"}
        }
        session.inventory = {
            "repos_using_ai_count": 1,
            "repos_total": 1,
            "provider_count": 1,
            "model_count": 1,
            "repo_profiles": [{"repo": "my-repo", "provider_labels": ["Openai"], "models": ["gpt-4o"]}],
        }
        session.suppressed_findings = [
            {"_hash": "suppressed-1", "repo": "my-repo", "file": "docs.md"}
        ]
        session.log("Test log entry", "info")

        findings = [
            {"severity": 1, "context": "production", "provider_or_lib": "openai"},
            {"severity": 2, "context": "test",       "provider_or_lib": "anthropic"},
        ]
        srv._save_history_record(session, findings)

        hist_path = Path(srv.HISTORY_FILE)
        assert hist_path.exists(), "scan_history.json not created"

        records = json.loads(hist_path.read_text())
        assert len(records) == 1
        r = records[0]
        assert r["scan_id"]    == "20250315_120000"
        assert r["project_key"] == "TEST"
        assert "project" not in r
        assert r["total"]      == 2
        assert r["sev"]["critical"] == 1
        assert r["sev"]["high"]     == 1
        assert r["llm_model"]  == "qwen2.5-coder:7b"
        assert r["state"]      == "done"
        assert r["operator"]   == "Security Engineer"
        assert r["started_at_utc"] == "2025-03-15T12:00:00Z"
        assert r["completed_at_utc"] == "2025-03-15T12:00:42Z"
        assert r["policy_version"] == "abc123def456"
        assert r["tool_version"] == "19.1"
        assert r["repo_details"]["my-repo"]["branch"] == "main"
        assert r["suppressed_total"] == 1
        assert r["inventory"]["repos_using_ai_count"] == 1

        # Log file should exist
        log_path = Path(srv.LOG_DIR) / "20250315_120000.txt"
        assert log_path.exists(), "Log file not created"
        log_text = log_path.read_text()
        assert "Test log entry" in log_text

    finally:
        srv.OUTPUT_DIR   = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR      = orig_log
        srv.DB_FILE      = orig_db
        srv._invalidate_history_cache()


def test_history_cache_invalidated_after_write():
    """_load_history must return fresh data after _save_history_record."""
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_out  = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log  = srv.LOG_DIR
    orig_db   = srv.DB_FILE
    srv.OUTPUT_DIR   = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR      = str(d / "logs")
    srv.DB_FILE      = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        # First load: no file yet
        assert srv._load_history() == []

        # Write a record
        session = srv.ScanSession()
        session.scan_id = "20250315_130000"
        session.project_key = "PROJ"
        session.repo_slugs = ["r1"]
        session.state = "done"
        session.scan_duration_s = 10
        session.llm_model = "test-model"
        session.llm_model_info = {"name": "test-model"}
        srv._save_history_record(session, [])

        # Load should now return 1 record without manual invalidation
        hist = srv._load_history()
        assert len(hist) == 1, f"Expected 1 record, got {len(hist)}"

    finally:
        srv.OUTPUT_DIR   = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR      = orig_log
        srv.DB_FILE      = orig_db
        srv._invalidate_history_cache()


def test_save_history_record_skips_empty_repo_scans():
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    srv.OUTPUT_DIR = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR = str(d / "logs")
    srv.DB_FILE = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        session = srv.ScanSession()
        session.scan_id = "20250315_130100"
        session.project_key = "EMPTY"
        session.repo_slugs = []
        session.state = "done"
        srv._save_history_record(session, [])

        assert srv._load_history() == []
        assert not (Path(srv.LOG_DIR) / "20250315_130100.txt").exists()
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv._invalidate_history_cache()


def test_atomic_history_write():
    """History write must be atomic — no .tmp file left behind."""
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_hist = srv.HISTORY_FILE
    orig_db   = srv.DB_FILE
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.DB_FILE      = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        session = srv.ScanSession()
        session.scan_id = "20250315_140000"
        session.project_key = "EMPTY"
        session.repo_slugs = []
        session.state = "done"
        session.scan_duration_s = 1
        session.llm_model = "m"
        session.llm_model_info = {"name": "m"}
        srv.OUTPUT_DIR = str(d)
        srv.LOG_DIR    = str(d / "logs")
        srv._save_history_record(session, [])

        # Empty scans should not persist any history artifacts.
        tmp = Path(srv.HISTORY_FILE + ".tmp")
        assert not tmp.exists(), ".tmp file left behind after atomic write"
        assert not Path(srv.HISTORY_FILE).exists(), "scan_history.json should not be created"
    finally:
        srv.HISTORY_FILE = orig_hist
        srv.DB_FILE      = orig_db
        srv._invalidate_history_cache()


def test_history_normalizes_stale_running_records():
    import app_server as srv

    stale_record = {
        "scan_id": "20260317_010101",
        "project_key": "COGI",
        "repo_slugs": ["repo1"],
        "state": "running",
        "started_at_utc": "2026-03-17T01:01:01Z",
    }
    original_session = srv._session
    try:
        srv._session = srv.ScanSession()
        with patch.object(srv, "_load_history", return_value=[stale_record]):
            history = srv._history_records_for_user()
        assert history[0]["state"] == "stopped"
    finally:
        srv._session = original_session


def test_history_excludes_empty_repo_records():
    import app_server as srv

    valid_record = {
        "scan_id": "20260317_020202",
        "project_key": "COGI",
        "repo_slugs": ["repo1"],
        "state": "done",
        "started_at_utc": "2026-03-17T02:02:02Z",
    }
    empty_record = {
        "scan_id": "20260317_010101",
        "project_key": "EMPTY",
        "repo_slugs": [],
        "state": "done",
        "started_at_utc": "2026-03-17T01:01:01Z",
    }
    original_session = srv._session
    try:
        srv._session = srv.ScanSession()
        with patch.object(srv, "_load_history", return_value=[empty_record, valid_record]):
            history = srv._history_records_for_user()
        assert [record["scan_id"] for record in history] == ["20260317_020202"]
    finally:
        srv._session = original_session


def test_scan_page_selection_view_stays_pre_scan():
    import app_server as srv

    session = srv.ScanSession()
    session.findings = [
        {
            "_hash": "hash-0",
            "repo": "repo1",
            "file": "main.py",
            "line": 7,
            "severity": 1,
            "severity_label": "Critical",
            "capability": "API Key",
            "policy_status": "critical",
            "description": "Unsuppressed finding",
            "snippet": "client = OpenAI(api_key=token)",
        },
        {
            "_hash": "hash-1",
            "repo": "repo1",
            "file": "app.py",
            "line": 10,
            "severity": 2,
            "severity_label": "High",
            "capability": "OpenAI",
            "policy_status": "fail",
            "description": "Example finding",
        }
    ]
    html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="COGI",
        repos=[{"slug": "repo1"}, {"slug": "repo2"}],
        selected_repos=[],
        status=session.to_status(),
        llm_cfg=srv.load_llm_config(),
        llm_models=["m1", "m2"],
        log_text="line 1\nline 2",
        phase_timeline=[("init", "00:02")],
    ).decode("utf-8")

    assert 'id="repo-search"' in html
    assert 'id="llm-model-select"' in html
    assert "Start Scan" in html
    assert 'id="start-scan-btn" disabled' in html
    assert "New Scan" in html
    assert "AI Inventory" in html
    assert "Past Scans" in html
    assert "repo1" in html
    assert "Current Findings" not in html
    assert 'href="/assets/main.css"' in html
    assert 'src="/assets/scan_page.js"' in html
    assert 'current-findings-body' not in html
    assert 'id="inventory-summary"' not in html


def test_scan_page_shows_resume_scan_when_new_scan_is_blocked_by_running_scan():
    import app_server as srv

    session = srv.ScanSession()
    session.state = "running"
    session.scan_id = "20260320_101500"

    html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="COGI",
        repos=[{"slug": "repo1"}],
        selected_repos=[],
        status=session.to_status(),
        llm_cfg=srv.load_llm_config(),
        llm_models=["m1"],
        log_text="",
        phase_timeline=[("init", "00:02")],
        force_selection=True,
        scan_id="20260320_101500",
        current_scan={"scan_id": "20260320_101500", "state": "running", "label": "repo1"},
    ).decode("utf-8")

    assert 'id="resume-scan-btn"' in html
    assert 'href="/scan/20260320_101500?tab=activity"' in html
    assert '>Current Scan</a>' in html


def test_scan_page_renders_triage_and_suppression_actions_for_active_scan_view():
    import app_server as srv

    session = srv.ScanSession()
    session.state = "done"
    session.scan_id = "20260317_154037"
    session.report_paths = {
        "__all__": {
            "html_name": "scan.html",
            "csv_name": "scan.csv",
        }
    }
    session.delta = {
        "has_baseline": True,
        "baseline_file": "AI_Scan_Report_COGI_repo1_20260317_140000.csv",
        "new_count": 1,
        "existing_count": 1,
        "unchanged_count": 1,
        "fixed_count": 1,
        "fixed_findings": [
            {"finding_id": "fixed-1", "repo": "repo1", "file": "old.py", "line": "12"},
        ],
    }
    session.inventory = {
        "repos_using_ai_count": 1,
        "repos_total": 1,
        "provider_count": 2,
        "model_count": 1,
        "providers_by_count": [
            {"provider": "openai", "label": "Openai", "count": 1},
            {"provider": "langchain", "label": "Langchain", "count": 1},
        ],
        "models_by_count": [{"model": "gpt-4o", "count": 1}],
        "embeddings_vector_db_repos": 0,
        "prompt_handling_repos": 1,
        "model_serving_repos": 0,
        "agent_tool_use_repos": 1,
        "repo_profiles": [
            {
                "repo": "repo1",
                "provider_labels": ["Openai", "Langchain"],
                "embeddings_vector_db": False,
                "prompt_handling": True,
                "model_serving": False,
                "agent_tool_use": True,
            }
        ],
    }
    session.llm_model_info = {
        "name": "qwen2.5-coder:7b-instruct",
        "parameter_size": "7.6B",
        "quantization": "Q4_K_M",
    }
    session.log_lines = [
        {"msg": "[LLM] Evaluating 7 finding(s) for review...", "ts": 10.0},
        {"msg": "[LLM] Reviewing 4 finding(s) via qwen2.5-coder:7b-instruct (3 skipped — high-confidence) batch=3 vram=5.9GB", "ts": 11.0},
        {"msg": "[LLM] Batch 1/2 (3 finding(s))...", "ts": 12.0},
        {"msg": "[LLM] ↓ DOWNGRADE direct_http_ai → MEDIUM in system-config-tool.py — API call in production code, but no sensitive data visible.", "ts": 13.0},
        {"msg": "[LLM] Batch 2/2 (1 finding(s))...", "ts": 14.0},
        {"msg": "[LLM] Done — dismissed:1  reinstated:1  downgraded:1  kept:1", "ts": 20.0},
        {"msg": "[LLM] Review stage complete -> 6 finding(s)", "ts": 21.0},
    ]
    session.findings = [
        {
            "_hash": "hash-0",
            "repo": "repo1",
            "file": "main.py",
            "line": 7,
            "severity": 1,
            "severity_label": "Critical",
            "capability": "API Key",
            "policy_status": "critical",
            "description": "Unsuppressed finding",
            "snippet": "client = OpenAI(api_key=token)",
            "delta_status": "new",
            "detector_confidence_score": 88,
            "production_relevance_score": 97,
            "evidence_quality_score": 82,
            "llm_review_confidence_score": 79,
            "overall_signal_score": 88,
        },
        {
            "_hash": "hash-1",
            "repo": "repo1",
            "file": "app.py",
            "line": 10,
            "severity": 2,
            "severity_label": "High",
            "capability": "OpenAI",
            "policy_status": "fail",
            "description": "Example finding",
            "snippet": "response = llm.invoke(prompt)",
            "triage_status": "reviewed",
            "triage_by": "analyst",
            "triage_at": "2026-03-17T15:40:00Z",
            "triage_note": "",
            "delta_status": "existing",
            "detector_confidence_score": 63,
            "production_relevance_score": 31,
            "evidence_quality_score": 58,
            "llm_review_confidence_score": 66,
            "overall_signal_score": 53,
        }
    ]
    session.suppressed_findings = [
        {
            "_hash": "hash-2",
            "repo": "repo1",
            "file": "docs.md",
            "line": 3,
            "severity": 4,
            "severity_label": "Low",
            "capability": "Example",
            "description": "Documentation example",
            "snippet": "OPENAI_API_KEY=example",
            "triage_status": "false_positive",
            "triage_note": "Expected internal example",
            "triage_by": "analyst",
            "triage_at": "2026-03-17T15:41:00Z",
        }
    ]

    html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="COGI",
        repos=[{"slug": "repo1"}],
        selected_repos=["repo1"],
        status=session.to_status(),
        llm_cfg=srv.load_llm_config(),
        llm_models=["m1"],
        log_text="line 1\nline 2",
        phase_timeline=[("scan", "00:02")],
        scan_id="20260317_154037",
    ).decode("utf-8")

    assert "Current Findings" not in html
    assert '<div class="findings-panel">' not in html
    assert '<div class="mitigate-section">' not in html
    assert '<div class="suppressed-section">' not in html
    assert 'id="hardware-card"' in html
    assert "LLM Batch Timings" not in html
    assert "LLM Stats" not in html
    assert html.index("Phase Timeline") < html.index('id="hardware-card"')
    assert 'href="/scan/20260317_154037?tab=activity"' not in html
    assert '>Results</a>' not in html
    assert 'id="hardware-gpu"' in html
    assert 'id="hardware-disk-io"' in html
    assert 'id="hardware-cpu-graph"' in html
    assert 'id="hardware-ram-graph"' in html
    assert 'id="hardware-gpu-graph"' in html
    assert 'id="hardware-disk-bars"' in html
    assert 'id="hardware-disk-read-fill"' in html
    assert 'id="hardware-disk-write-fill"' in html
    assert 'id="perf-reviewed-skipped"' not in html
    assert 'id="perf-llm-outcomes"' not in html
    assert '<div class="workspace-header">' in html
    assert 'id="new-scan-btn"' not in html
    assert 'class="activity-main"' in html
    assert 'class="activity-side-stack"' in html
    assert 'class="terminal-log-text"' in html
    assert 'class="terminal-brand-inline"' in html
    assert "___ _             _             _    __  __" in html
    assert "Results Actions" not in html
    assert 'id="reports-card"' not in html
    assert 'id="hardware-process"' not in html
    assert 'id="hardware-workspace"' not in html
    assert 'id="hardware-disk"' not in html
    assert "Baseline" in html
    assert 'id="inventory-summary"' not in html
    assert "Compared to AI_Scan_Report_COGI_repo1_20260317_140000.csv" in html
    assert "old.py:12" in html
    assert "New" in html
    assert "Existing" in html
    assert 'src="/assets/scan_page.js"' in html
    assert "findingsBody" not in html
    assert "repairTimer" not in html


def test_scan_page_asset_refreshes_after_running_to_terminal_transition():
    script = Path("C:/aitool/assets/scan_page.js").read_text(encoding="utf-8")

    assert "let previousScanState = null;" in script
    assert 'const terminalState = ["done", "stopped", "skipped", "error"].includes(state);' in script
    assert 'const justFinished = previousScanState === "running" && terminalState;' in script
    assert "!redirectedToResults && justFinished" in script
    assert '?tab=activity' in script
    assert "function renderLlmStats(data)" not in script
    assert "function currentModelOptions()" in script
    assert "allowShrink = true" in script
    assert "const seemsPartial = models.length === 1 && beforeCount > 1;" in script
    assert "for (let attempt = 0; attempt < 3; attempt += 1)" in script


def test_scan_page_renders_incremental_scope_controls():
    import app_server as srv

    html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="COGI",
        repos=[{"slug": "repo1"}, {"slug": "repo2"}],
        selected_repos=["repo1"],
        llm_cfg=srv.load_llm_config(),
        llm_models=["qwen2.5-coder:7b-instruct"],
        status={"state": "idle", "delta": {}, "inventory": {}, "report": {}},
        log_text="",
        phase_timeline=[],
        force_selection=True,
        selected_scan_scope="branch_diff",
        selected_compare_ref="master",
    ).decode("utf-8")

    assert 'id="scan-scope-select"' in html
    assert 'value="branch_diff" selected' in html
    assert 'id="compare-ref-input"' in html
    assert 'value="master"' in html
    assert html.index('Search Repositories') < html.index('Scan Scope') < html.index('LLM Model')
    assert 'class="repo-toolbar repo-controls-row"' in html
    assert 'class="repo-toolbar repo-local-row"' in html
    assert 'id="local-repo-toggle-btn"' in html
    assert 'class="inline hidden" id="local-repo-row"' in html
    assert 'id="local-repo-path-input"' in html
    assert 'id="local-repo-browse-btn"' in html
    assert html.index('id="repo-search"') < html.index('id="scan-scope-select"') < html.index('id="llm-model-select"') < html.index('id="start-scan-btn"')
    assert html.index('id="start-scan-btn"') < html.index('id="local-repo-toggle-btn"') < html.index('id="local-repo-row"')
    assert "Baseline-Aware Rescan" in html
    assert "Changed-file and baseline-aware scans reduce traversal and LLM work on repeated runs." not in html


def test_new_scan_hides_repo_actions_until_project_is_selected():
    import app_server as srv

    html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="",
        repos=[],
        selected_repos=[],
        llm_cfg=srv.load_llm_config(),
        llm_models=["qwen2.5-coder:7b-instruct"],
        status={"state": "idle", "delta": {}, "inventory": {}, "report": {}},
        log_text="",
        phase_timeline=[],
        force_selection=True,
    ).decode("utf-8")

    assert 'class="repo-actions hidden" id="repo-actions"' in html
    assert 'class="muted hidden" id="no-repos-message"' in html


def test_llm_stats_are_derived_from_log_entries():
    import app_server as srv

    entries = [
        {"msg": "LLM      : qwen2.5-coder:7b-instruct | 7.6B | Q4_K_M", "ts": 5.0},
        {"msg": "[LLM] Evaluating 7 finding(s) for review...", "ts": 10.0},
        {"msg": "[LLM] Reviewing 4 finding(s) via qwen2.5-coder:7b-instruct (3 skipped — high-confidence) batch=3 vram=5.9GB", "ts": 11.0},
        {"msg": "[LLM] Batch 1/2 (3 finding(s))...", "ts": 12.0},
        {"msg": "[LLM] ↓ DOWNGRADE direct_http_ai → MEDIUM in app.py — context", "ts": 14.0},
        {"msg": "[LLM] Batch 2/2 (1 finding(s))...", "ts": 16.0},
        {"msg": "[LLM] Done — dismissed:1  reinstated:1  downgraded:1  kept:1", "ts": 20.0},
    ]

    stats = srv._llm_stats(entries, state="done")

    assert stats["model"] == "qwen2.5-coder:7b-instruct | 7.6B | Q4_K_M"
    assert stats["phase_elapsed"] == "00:10"
    assert stats["last_batch"] == "4.00s"
    assert stats["avg_batch"] == "4.00s"
    assert stats["avg_per_finding"] == "2.50s"
    assert stats["throughput"] == "24.0 findings/min"
    assert stats["reviewed"] == 4
    assert stats["skipped"] == 3
    assert stats["dismissed"] == 1
    assert stats["downgraded"] == 1
    assert stats["failed_batches"] == "0"


def test_scan_workspace_tabs_disable_results_until_scan_completes():
    from services.web_pages import _scan_workspace_tabs

    html = _scan_workspace_tabs("20260318_150000", "activity", results_enabled=False)

    assert 'href="/scan/20260318_150000?tab=activity"' in html
    assert 'aria-disabled="true"' in html
    assert '>Results</a>' in html


def test_scan_session_log_normalizes_blank_lines():
    import app_server as srv

    session = srv.ScanSession()
    session.log("\nGenerating reports...\n", "dim")
    session.log("\nOK repo1 -> 3 findings", "info")

    assert [entry["msg"] for entry in session.log_lines] == [
        "Generating reports...",
        "OK repo1 -> 3 findings",
    ]


def test_sse_log_formatter_matches_page_log_format():
    import app_server as srv
    from datetime import datetime
    from dateutil import tz

    line = srv._format_log_entry({"msg": "Scan complete.", "ts": 1773754860.0})
    expected = datetime.fromtimestamp(1773754860.0, tz.gettz("Asia/Jerusalem")).strftime("%H:%M:%S")

    assert line.startswith(f"[{expected}]")
    assert line.endswith("Scan complete.")


def test_help_page_can_hide_scan_results_navigation():
    import app_server as srv

    html = srv.render_help_page(show_scan_results=False).decode("utf-8")

    assert "New Scan" in html
    assert "AI Inventory" in html
    assert "Past Scans" in html
    assert 'href="/scan">Scan Results</a>' not in html


def test_has_scan_results_depends_on_current_session_only():
    import app_server as srv

    original_session = srv._session
    try:
        srv._session = srv.ScanSession()
        assert srv._has_scan_results() is False
        srv._session.scan_id = "20260318_120000"
        assert srv._has_scan_results() is True
    finally:
        srv._session = original_session


def test_history_records_are_normalized_to_project_key():
    from services.scan_jobs import ScanJobPaths, ScanJobService

    temp_root = Path(tempfile.mkdtemp())
    service = ScanJobService(
        app_version="test",
        paths=ScanJobPaths(
            output_dir=str(temp_root / "output"),
            temp_dir=str(temp_root / "tmp"),
            policy_file=str(temp_root / "policy.json"),
            owner_map_file=str(temp_root / "owner_map.json"),
            suppressions_file=str(temp_root / "suppressions.json"),
            history_file=str(temp_root / "scan_history.json"),
            log_dir=str(temp_root / "logs"),
            db_file=str(temp_root / "scan_jobs.db"),
        ),
        load_policy=lambda _: {},
        load_owner_map=lambda _: {},
        policy_version=lambda _: "test",
        utc_now_iso=lambda: "2026-03-18T10:00:00Z",
        git_head_commit=lambda _: "",
        ollama_ping=lambda _: False,
    )

    legacy_record = {"scan_id": "20260318_100000", "project": "COGI", "state": "done", "repos": ["repo1"]}

    with service._connect() as conn:
        conn.execute(
            "INSERT INTO scan_jobs(scan_id, state, updated_at, record_json) VALUES (?, ?, ?, ?)",
            ("20260318_100000", "done", 1.0, json.dumps(legacy_record)),
        )
        conn.commit()

    records = service.load_history()

    assert records[0]["project_key"] == "COGI"
    assert "project" not in records[0]


def test_history_records_without_repos_are_filtered_out():
    from services.scan_jobs import ScanJobPaths, ScanJobService

    temp_root = Path(tempfile.mkdtemp())
    service = ScanJobService(
        app_version="test",
        paths=ScanJobPaths(
            output_dir=str(temp_root / "output"),
            temp_dir=str(temp_root / "tmp"),
            policy_file=str(temp_root / "policy.json"),
            owner_map_file=str(temp_root / "owner_map.json"),
            suppressions_file=str(temp_root / "suppressions.json"),
            history_file=str(temp_root / "scan_history.json"),
            log_dir=str(temp_root / "logs"),
            db_file=str(temp_root / "scan_jobs.db"),
        ),
        load_policy=lambda _: {},
        load_owner_map=lambda _: {},
        policy_version=lambda _: "test",
        utc_now_iso=lambda: "2026-03-18T10:00:00Z",
        git_head_commit=lambda _: "",
        ollama_ping=lambda _: False,
    )

    bad_record = {"scan_id": "20260318_100000", "project_key": "EMPTY", "state": "done", "repos": []}
    good_record = {"scan_id": "20260318_100100", "project_key": "COGI", "state": "done", "repos": ["repo1"]}

    with service._connect() as conn:
        conn.execute(
            "INSERT INTO scan_jobs(scan_id, state, updated_at, record_json) VALUES (?, ?, ?, ?)",
            ("20260318_100000", "done", 1.0, json.dumps(bad_record)),
        )
        conn.execute(
            "INSERT INTO scan_jobs(scan_id, state, updated_at, record_json) VALUES (?, ?, ?, ?)",
            ("20260318_100100", "done", 2.0, json.dumps(good_record)),
        )
        conn.commit()

    records = service.load_history()

    assert len(records) == 1
    assert records[0]["scan_id"] == "20260318_100100"


def test_history_access_uses_project_key_only():
    from services.report_access import history_records_for_context

    ctx = UserContext(username="u", roles=[ROLE_VIEWER], allowed_projects=["COGI"])
    history = [
        {"scan_id": "1", "project_key": "COGI"},
        {"scan_id": "2", "project_key": "NOPE"},
    ]

    visible = history_records_for_context(history, ctx)

    assert [record["scan_id"] for record in visible] == ["1"]


def test_legacy_access_control_fails_closed_without_valid_config():
    from services.access_control import resolve_user_context

    d = Path(tempfile.mkdtemp())
    missing = d / "missing-access.json"

    ctx = resolve_user_context(str(missing), "analyst")

    assert ctx.username == "analyst"
    assert ctx.roles == ()
    assert ctx.allowed_projects == ()


def test_legacy_access_control_ignores_invalid_user_entry_and_uses_valid_defaults_only():
    from services.access_control import resolve_user_context

    d = Path(tempfile.mkdtemp())
    cfg = d / "access.json"
    cfg.write_text(
        json.dumps(
            {
                "default_roles": ["admin", "bogus"],
                "default_projects": ["", "COGI"],
                "users": {"alice": "invalid"},
            }
        ),
        encoding="utf-8",
    )

    ctx = resolve_user_context(str(cfg), "alice")

    assert ctx.roles == ("admin",)
    assert ctx.allowed_projects == ("COGI",)


def test_llm_fallback_parsing_does_not_emit_low_signal_operator_logs():
    from scanner import llm_reviewer as reviewer

    logs = []
    responses = [b"not-json", b'[{"verdict":"dismiss","reason":"docs","confidence":80}]']

    with patch.object(reviewer, "_post", side_effect=lambda *args, **kwargs: responses.pop(0)), \
         patch.object(reviewer, "_extract_json_array", side_effect=[None, [{"verdict": "dismiss", "reason": "docs", "confidence": 80}]]), \
         patch.object(reviewer, "_debug_log"):
        verdicts = reviewer._call_ollama(
            "http://localhost:11434",
            "demo-model",
            "[]",
            logs.append,
        )

    assert verdicts == [{"verdict": "dismiss", "reason": "docs", "confidence": 80}]
    assert logs == []


def test_llm_review_logs_explicit_warning_when_batches_fail():
    from scanner import llm_reviewer as reviewer

    logs = []
    findings = [
        {
            "_hash": "h1",
            "provider_or_lib": "openai",
            "confidence": 10,
            "context": "test",
            "severity": 2,
            "file": "app.py",
            "line": 4,
            "snippet": "import openai",
        }
    ]
    reviewer_obj = reviewer.LLMReviewer(model="demo-model", log_fn=logs.append)

    with patch.object(reviewer, "_available_vram_gb", return_value=0.0), \
         patch.object(reviewer, "compute_batch_size", return_value=1), \
         patch.object(reviewer, "_call_ollama", return_value=None):
        result = reviewer_obj.review(findings, {})

    assert result == findings
    assert any("Review failed for 1 finding(s); results kept without LLM refinement" in line for line in logs)


def test_security_analyzer_adds_explicit_scoring_fields():
    from analyzer.security import SecurityAnalyzer

    analyzer = SecurityAnalyzer(policy={})
    result = analyzer.analyze([{
        "_hash": "h1",
        "provider_or_lib": "openai",
        "category": "AI SDK",
        "severity": 2,
        "context": "production",
        "file": "src/app.py",
        "line": 8,
        "match": "OpenAI(api_key=token)",
        "snippet": "client = OpenAI(api_key=token)",
        "capability": "Chat Completion",
        "confidence": 77,
        "corroboration_count": 3,
    }])[0]

    assert result["detector_confidence_score"] == 77
    assert 0 <= result["production_relevance_score"] <= 100
    assert 0 <= result["evidence_quality_score"] <= 100
    assert 0 <= result["overall_signal_score"] <= 100
    assert result["llm_review_confidence_score"] is None


def test_apply_verdict_records_llm_review_confidence_score():
    from scanner.llm_reviewer import _apply_verdict

    finding = {"severity": 2}
    verdict = _apply_verdict(
        finding,
        {
            "verdict": "downgrade",
            "reason": "docs",
            "confidence": 83,
            "secure_example": "client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])",
        },
    )

    assert verdict == "downgrade"
    assert finding["llm_review_confidence_score"] == 83
    assert finding["llm_secure_example"] == "client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])"
    assert finding["severity"] == 3


def test_scan_page_can_force_new_scan_selection_after_completion():
    import app_server as srv

    session = srv.ScanSession()
    session.state = "done"
    session.findings = [{"_hash": "h1", "repo": "repo1", "file": "app.py", "line": 1, "severity": 2, "severity_label": "High", "capability": "OpenAI"}]

    html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="COGI",
        repos=[{"slug": "repo1"}],
        selected_repos=["repo1"],
        status=session.to_status(),
        llm_cfg=srv.load_llm_config(),
        llm_models=["m1"],
        log_text="line 1",
        phase_timeline=[("scan", "00:02")],
        force_selection=True,
    ).decode("utf-8")

    assert "Current Findings" not in html
    assert "Start Scan" in html
    assert '/scan?project=COGI&new=1' in html
    assert 'class="nav active"' in html
    assert 'value="repo1" checked' in html


def test_phase_timeline_hides_total_until_scan_finishes():
    import app_server as srv

    running_html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="COGI",
        repos=[{"slug": "repo1"}],
        selected_repos=["repo1"],
        status={"state": "running", "finding_details": [], "suppressed_details": []},
        llm_cfg=srv.load_llm_config(),
        llm_models=["m1"],
        log_text="line 1",
        phase_timeline=[("init", "00:02"), ("total", "00:20")],
    ).decode("utf-8")

    done_html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="COGI",
        repos=[{"slug": "repo1"}],
        selected_repos=["repo1"],
        status={"state": "done", "finding_details": [], "suppressed_details": []},
        llm_cfg=srv.load_llm_config(),
        llm_models=["m1"],
        log_text="line 1",
        phase_timeline=[("init", "00:02"), ("total", "00:20")],
    ).decode("utf-8")

    assert 'class="timeline-name">total<' not in running_html.lower()
    assert 'class="timeline-name">total<' in done_html.lower()


def test_phase_timeline_assigns_residual_seconds_to_last_started_phase():
    from services.scan_runtime_views import phase_timeline

    entries = [
        {"ts": 0.0, "msg": "Scan ID  : 1"},
        {"ts": 4.0, "msg": "repo  branch:main  owner:User"},
        {"ts": 4.0, "msg": "Starting scan (workers=1)..."},
        {"ts": 6.0, "msg": "[LLM] Evaluating 3 finding(s) for review..."},
        {"ts": 55.0, "msg": "Scan complete."},
    ]

    timeline = phase_timeline(entries, "done")
    durations = {item["name"]: item["duration"] for item in timeline}

    assert durations["init"] == "00:04"
    assert durations["clone"] == "00:00"
    assert durations["scan"] == "00:02"
    assert durations["llm review"] == "00:49"
    assert durations["total"] == "00:55"


def test_phase_timeline_total_matches_sum_of_displayed_finished_phases():
    from services.scan_runtime_views import phase_timeline

    entries = [
        {"ts": 0.0, "msg": "Scan ID  : 1"},
        {"ts": 3.0, "msg": "repo  branch:main  owner:User"},
        {"ts": 3.0, "msg": "Starting scan (workers=1)..."},
        {"ts": 3.0, "msg": "[LLM] Evaluating 2 finding(s) for review..."},
        {"ts": 10.0, "msg": "Scan complete."},
    ]

    timeline = phase_timeline(entries, "done")
    durations = {
        item["name"]: (int(item["duration"].split(":")[0]) * 60) + int(item["duration"].split(":")[1])
        for item in timeline
        if item["duration"] != "—"
    }

    phase_total = sum(value for key, value in durations.items() if key != "total")

    assert durations["total"] == phase_total


def test_structured_phase_timeline_prefers_persisted_phase_metrics():
    from services.scan_runtime_views import structured_phase_timeline

    timeline = structured_phase_timeline(
        {
            "init": 4,
            "clone": 0,
            "scan": 3,
            "llm review": 37,
            "report": 3,
            "total": 47,
        },
        duration_s=99,
        state="done",
    )
    durations = {item["name"]: item["duration"] for item in timeline}

    assert durations["init"] == "00:04"
    assert durations["clone"] == "00:00"
    assert durations["scan"] == "00:03"
    assert durations["llm review"] == "00:37"
    assert durations["report"] == "00:03"
    assert durations["total"] == "00:47"


def test_render_history_page_hides_phases_and_error_columns():
    import app_server as srv

    html = srv.render_history_page(
        history=[{
            "scan_id": "20260319_120000",
            "started_at_utc": "2026-03-19T12:00:00Z",
            "project_key": "LOCAL",
            "repo_slugs": ["aitool"],
            "state": "done",
            "total": 4,
            "delta": {"new_count": 1, "existing_count": 3, "fixed_count": 0},
            "critical_prod": 1,
            "high_prod": 1,
            "llm_model": "gpt-oss:20b",
            "duration_s": 55,
            "errors": [{"code": "LLM_REVIEW_FAILED", "stage": "llm_review", "message": "timed out"}],
        }],
        csrf_token="csrf-demo",
    ).decode("utf-8")

    assert ">Phases<" not in html
    assert ">Error<" not in html
    assert 'href="/findings?scan_id=20260319_120000"' in html


def test_build_findings_rollups_applies_triage_and_fixed_state():
    from services.findings import build_findings_rollups

    history = [
        {
            "scan_id": "scan-1",
            "started_at_utc": "2026-03-18T10:00:00Z",
            "delta": {"fixed_hashes": []},
            "findings": [
                {
                    "_hash": "hash-open",
                    "project_key": "COGI",
                    "repo": "repo1",
                    "file": "app.py",
                    "line": 14,
                    "severity": 1,
                    "severity_label": "Critical",
                    "provider_or_lib": "openai_key",
                    "description": "Hardcoded key",
                },
                {
                    "_hash": "hash-fixed",
                    "project_key": "COGI",
                    "repo": "repo1",
                    "file": "old.py",
                    "line": 22,
                    "severity": 2,
                    "severity_label": "High",
                    "provider_or_lib": "langchain",
                    "description": "Old issue",
                },
            ],
        },
        {
            "scan_id": "scan-2",
            "started_at_utc": "2026-03-19T10:00:00Z",
            "delta": {"fixed_hashes": ["hash-fixed"]},
            "findings": [
                {
                    "_hash": "hash-open",
                    "project_key": "COGI",
                    "repo": "repo1",
                    "file": "app.py",
                    "line": 16,
                    "severity": 1,
                    "severity_label": "Critical",
                    "provider_or_lib": "openai_key",
                    "description": "Hardcoded key",
                }
            ],
        },
    ]
    triage = {
        "hash-open": {"status": TRIAGE_ACCEPTED_RISK, "note": "Known exception", "marked_by": "analyst", "marked_at": "2026-03-19"},
        "hash-fixed": {"status": TRIAGE_SENT_FOR_REVIEW, "note": "Sent to owner", "marked_by": "analyst", "marked_at": "2026-03-18"},
    }

    rows = build_findings_rollups(history, triage)

    assert rows[0]["hash"] == "hash-open"
    assert rows[0]["status"] == "accepted_risk"
    assert rows[0]["triage_note"] == "Known exception"
    fixed = next(item for item in rows if item["hash"] == "hash-fixed")
    assert fixed["status"] == "fixed"
    assert fixed["status_label"] == "Fixed"


def test_build_scan_findings_returns_only_requested_scan_details():
    from services.findings import build_scan_findings

    record = {
        "scan_id": "scan-7",
        "started_at_utc": "2026-03-19T10:00:00Z",
        "project_key": "COGI",
        "findings": [
            {
                "_hash": "hash-a",
                "project_key": "COGI",
                "repo": "repo1",
                "file": "app.py",
                "line": 14,
                "severity": 1,
                "severity_label": "Critical",
                "provider_or_lib": "openai_key",
                "ai_category": "Security",
                "description": "Hardcoded key",
                "llm_reason": "Hardcoded credential in code.",
            }
        ],
    }

    rows = build_scan_findings(record, {"hash-a": {"status": "accepted_risk", "note": "known"}})

    assert len(rows) == 1
    assert rows[0]["last_seen_scan_id"] == "scan-7"
    assert rows[0]["scan_count"] == 1
    assert rows[0]["status"] == "accepted_risk"
    assert rows[0]["llm_reason"] == "Hardcoded credential in code."


def test_build_findings_rollups_normalizes_legacy_severity_labels():
    from services.findings import build_findings_rollups

    rows = build_findings_rollups(
        [
            {
                "scan_id": "scan-1",
                "started_at_utc": "2026-03-19T10:00:00Z",
                "findings": [
                    {
                        "_hash": "hash-1",
                        "repo": "repo1",
                        "file": "app.py",
                        "line": 12,
                        "severity": 1,
                        "severity_label": "sev-1",
                        "provider_or_lib": "debug_mode",
                        "capability": "Debug mode in production",
                        "description": "x",
                    }
                ],
            }
        ],
        {},
    )

    assert rows[0]["severity_label"] == "Critical"


def test_render_findings_page_shows_filters_and_bulk_actions():
    import app_server as srv

    html = srv.render_findings_page(
        findings=[
            {
                "hash": "hash-open",
                "project_key": "COGI",
                "repo": "repo1",
                "file": "app.py",
                "line": "14",
                "severity": 1,
                "severity_label": "Critical",
                "rule": "debug_mode",
                "capability": "Debug mode in production",
                "rule_label": "Debug mode in production",
                "ai_category": "Security",
                "description": "Hardcoded key next to AI client use",
                "match": "OpenAI(api_key='sk-test')",
                "llm_reason": "The code sends a hardcoded credential to an AI provider.",
                "remediation": "Move the credential to an environment variable and rotate it.",
                "llm_secure_example": "client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])",
                "llm_verdict": "kept",
                "llm_reviewed": True,
                "snippet": "client = OpenAI(api_key='sk-test')",
                "last_seen_at": "2026-03-19T10:00:00Z",
                "scan_count": 2,
                "status": "open",
                "status_label": "Open",
                "triage_note": "",
                "last_seen_scan_id": "scan-2",
            },
            {
                "hash": "hash-risk",
                "project_key": "COGI",
                "repo": "repo1",
                "file": "app.py",
                "line": "20",
                "severity": 2,
                "severity_label": "High",
                "rule": "hardcoded_credential",
                "capability": "Credential exposure",
                "rule_label": "Hardcoded credential",
                "ai_category": "Security",
                "description": "Credential cannot be rotated yet",
                "match": "password='legacy'",
                "llm_reason": "",
                "remediation": "",
                "llm_secure_example": "",
                "llm_verdict": "",
                "llm_reviewed": False,
                "snippet": "password='legacy'",
                "last_seen_at": "2026-03-19T11:00:00Z",
                "scan_count": 1,
                "status": "accepted_risk",
                "status_label": "Accepted Risk",
                "triage_note": "Approved temporary exception",
                "last_seen_scan_id": "scan-2",
            },
        ],
        csrf_token="csrf-demo",
        scan_label="scan-2",
        scan_actions_html='<form method="post" action="/findings/generate-html" class="triage-form inline-only" target="_blank"><input type="hidden" name="scan_id" value="scan-2" /><button type="submit" class="btn alt" name="export_type" value="csv">Generate CSV</button></form>',
    ).decode("utf-8")

    assert "Findings" in html
    assert 'href="/findings"' in html
    assert 'id="findings-table"' in html
    assert 'class="card findings-shell"' in html
    assert 'id="findings-form" class="findings-form"' in html
    assert 'class="table-shell findings-table-shell"' in html
    assert 'class="findings-summary-strip"' in html
    assert 'class="findings-summary-chip"' in html
    assert 'id="findings-filter-rule"' in html
    assert 'action="/findings/bulk"' in html
    assert 'formaction="/findings/generate-html"' in html
    assert 'id="generate-findings-html-btn"' in html
    assert 'id="generate-findings-csv-btn"' in html
    assert 'id="generate-findings-json-btn"' in html
    assert 'id="apply-findings-action-btn"' in html
    assert 'id="findings-export-hint"' in html
    assert "Select findings to change their status or to export them as HTML / CSV / JSON." in html
    assert 'id="findings-select-all"' in html
    assert 'id="findings-bulk-note"' not in html
    assert 'src="/assets/findings_page.js"' in html
    assert "Sent for Review" in html
    assert "In Remediation" in html
    assert "FP - Dismiss" in html
    assert "File : Line / Code" in html
    assert "<th>Note</th>" not in html
    assert 'sev-chip sev-critical' in html
    assert "Potential Risk" in html
    assert "Category" in html
    assert "Debug mode in production" in html
    assert "Security" in html
    assert "Showing findings for scan scan-2." in html
    assert "Generate CSV" in html
    assert 'class="finding-row"' in html
    assert 'data-match="OpenAI(api_key=' in html
    assert 'data-llm-secure-example="client = OpenAI(api_key=os.environ[' in html
    assert 'class="pill status-stopped has-tooltip"' in html
    assert 'data-tooltip-title="Justification"' in html
    assert 'data-tooltip-text="Approved temporary exception"' in html
    assert 'class="snippet-hit"' in html
    assert 'data-llm-reason="The code sends a hardcoded credential to an AI provider."' in html


def test_generate_selected_findings_html_report_registers_runtime_report(monkeypatch, tmp_path):
    import app_server as srv

    monkeypatch.setattr(srv, "OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(srv, "POLICY_FILE", str(tmp_path / "policy.json"))
    monkeypatch.setattr(srv, "load_llm_config", lambda: {"base_url": "http://localhost:11434", "model": "qwen", "report_detail_timeout_s": 120})

    class _StubScanService:
        def _load_policy(self, _path):
            return {}

    monkeypatch.setattr(srv, "_scan_service", _StubScanService())

    written = {}

    class _StubReporter:
        def __init__(self, output_dir, scan_id, include_snippets=True, meta=None):
            written["output_dir"] = output_dir
            written["scan_id"] = scan_id
            written["meta"] = meta or {}

        def write(self, findings, policy=None, ollama_url="", ollama_model="", detail_mode="detailed"):
            written["findings"] = findings
            written["policy"] = policy
            written["ollama_url"] = ollama_url
            written["ollama_model"] = ollama_model
            written["detail_mode"] = detail_mode
            path = Path(tmp_path) / "selected_findings_demo.html"
            path.write_text("<html></html>", encoding="utf-8")
            return str(path)

    monkeypatch.setattr(srv, "HTMLReporter", _StubReporter)

    report_name = srv._generate_selected_findings_html_report(
        [{"hash": "h1", "repo": "repo1", "project_key": "COGI", "llm_reason": "stored"}],
        scan_id="scan-7",
    )

    assert report_name == "selected_findings_demo.html"
    assert written["detail_mode"] == "detailed"
    assert written["ollama_model"] == "qwen"
    assert written["findings"][0]["hash"] == "h1"
    assert srv._runtime_report_allowed(report_name) is True


def test_generate_selected_findings_artifact_supports_json(monkeypatch, tmp_path):
    import app_server as srv

    monkeypatch.setattr(srv, "OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(srv, "load_llm_config", lambda: {"base_url": "http://localhost:11434", "model": "qwen", "report_detail_timeout_s": 120})

    class _StubReporter:
        def __init__(self, output_dir, scan_id):
            self.output_dir = output_dir
            self.scan_id = scan_id

        def write_json(self, findings, meta=None, replay_instructions=""):
            path = Path(tmp_path) / "selected_findings_demo.json"
            path.write_text("{}", encoding="utf-8")
            assert findings[0]["hash"] == "h1"
            assert meta["tool_version"] == srv.APP_VERSION
            return str(path)

    monkeypatch.setattr(srv, "JSONReporter", _StubReporter)

    report_name = srv._generate_selected_findings_artifact(
        [{"hash": "h1", "repo": "repo1", "project_key": "COGI", "llm_reason": "stored"}],
        export_type="json",
        scan_id="scan-8",
    )

    assert report_name == "selected_findings_demo.json"
    assert srv._runtime_report_allowed(report_name) is True


def test_findings_history_notice_reports_summary_only_scans():
    from services.findings import findings_history_notice

    notice = findings_history_notice([
        {"scan_id": "scan-1", "total": 6, "findings": [{"_hash": "a"}]},
        {"scan_id": "scan-2", "total": 14, "findings": []},
        {"scan_id": "scan-3", "total": 0, "findings": []},
    ])

    assert "Detailed findings are available for 1 of 2 scans." in notice
    assert "up to 14 findings cannot be listed here." in notice


def test_render_scan_page_clears_previous_repo_selection_in_new_scan_mode():
    import app_server as srv

    orig_session = srv._session
    try:
        session = srv.ScanSession()
        session.state = "done"
        session.project_key = "COGI"
        session.repo_slugs = ["repo1"]
        srv._session = session

        class DummyHandler:
            path = "/scan?project=COGI&new=1"
            headers = {}

            def __init__(self):
                self.sent = None

            def _send(self, status, ct, body):
                self.sent = (status, ct, body)

        handler = DummyHandler()
        with patch.object(srv, "_require_role", return_value=False), \
             patch.object(srv, "_require_project_access", return_value=False), \
             patch.object(srv, "_is_connected", return_value=True), \
             patch.object(srv, "_repos_for_project", return_value=[{"slug": "repo1"}, {"slug": "repo2"}]), \
             patch.object(srv, "filter_projects", return_value=[{"key": "COGI"}]), \
             patch.object(srv, "load_llm_config", return_value={"base_url": "http://localhost:11434", "model": "m1"}), \
             patch.object(srv, "_ollama_list_models", return_value=["m1"]):
            srv._Handler._render_scan_page(handler)

        html = handler.sent[2].decode("utf-8")
        assert 'value="repo1" checked' not in html
        assert 'value="repo2" checked' not in html
    finally:
        srv._session = orig_session


def test_new_scan_view_blocks_start_while_another_scan_is_running():
    import app_server as srv

    html = srv.render_scan_page(
        projects=[{"key": "COGI"}],
        selected_project="COGI",
        repos=[{"slug": "repo1"}],
        selected_repos=[],
        status={"state": "running"},
        llm_cfg={"base_url": "http://localhost:11434", "model": "gemma3:270m"},
        llm_models=["gemma3:270m"],
        log_text="",
        phase_timeline=[],
        force_selection=True,
    ).decode("utf-8")

    assert 'id="start-scan-btn" disabled' in html
    assert "A scan is in progress. Wait until it finishes before starting a new scan." in html
    assert "Selected model is below 4B and may be unreliable for LLM review." in html


def test_history_page_is_server_rendered():
    import app_server as srv

    html = srv.render_history_page(
        history=[
            {
                "scan_id": "20260317_120000",
                "project_key": "COGI",
                "repo_slugs": ["repo1"],
                "state": "done",
                "total": 3,
                "delta": {"new_count": 1, "existing_count": 2, "fixed_count": 4},
                "suppressed_total": 1,
                "critical_prod": 1,
                "high_prod": 2,
                "llm_model": "m",
                "duration_s": 14,
                "started_at_utc": "2026-03-17T12:00:00Z",
                "reports": {"__all__": {"html_name": "r.html", "csv_name": "r.csv"}},
                "log_file": "x.log",
            }
        ]
    ).decode("utf-8")

    assert 'action="/history/delete"' in html
    assert "Delete Selected Scans" in html
    assert 'id="history-search"' in html
    assert 'id="history-prev-btn"' in html
    assert 'id="history-next-btn"' in html
    assert 'id="history-select-page"' in html
    assert 'href="/assets/main.css"' in html
    assert 'src="/assets/history_page.js"' in html
    assert "function sortHistory" not in html
    assert "Page 1 of 1" in html
    assert "New" in html
    assert "Existing" in html
    assert "Fixed" in html
    assert ">Phases<" not in html
    assert ">1</td>" in html
    assert ">2</td>" in html


def test_iter_files_includes_high_value_supported_file_types(tmp_path):
    from scanner.detector import AIUsageDetector

    included = [
        "Dockerfile",
        "pom.xml",
        "application.properties",
        "build.gradle",
        "settings.kts",
        "query.sql",
        "tool.pyw",
        "model.swift",
        "service.kt",
        "pipeline.scala",
        "job.groovy",
        "script.pl",
        "analysis.r",
        "component.vue",
        "widget.svelte",
        "runtime.mjs",
        "legacy.cjs",
        "requirements.txt",
        "package.json",
        "pyproject.toml",
    ]
    skipped = [
        "archive.zip",
        "image.png",
        "binary.exe",
        "library.jar",
        "document.pdf",
    ]

    for name in included + skipped:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")

    found = {
        path.name
        for path in AIUsageDetector(verbose=False)._iter_files(tmp_path)
    }

    for name in included:
        assert name in found
    for name in skipped:
        assert name not in found


def test_gradle_files_get_comment_stripping_and_config_rule_handling():
    detector = AIUsageDetector()
    code = (
        "// openai.api_key = 'sk-comment-only'\n"
        "openai>=1.0\n"
    )

    findings = detector._scan_text_file_from_content(
        code,
        ".gradle",
        "build.gradle",
        "repo",
    )

    libs = {f["provider_or_lib"] for f in findings}
    assert "dependency_declaration" in libs
    assert "openai" not in libs


def test_properties_files_are_treated_as_config_for_entropy_secrets():
    detector = AIUsageDetector()
    code = 'API_TOKEN="abcdefghijklmnopqrstuvwxyzABCDEFG1234567890"\n'

    findings = detector._scan_text_file_from_content(
        code,
        ".properties",
        "application.properties",
        "repo",
    )

    assert "entropy_secret" in {f["provider_or_lib"] for f in findings}


def test_results_page_is_server_rendered():
    import app_server as srv

    html = srv.render_results_page(
        scan_id="20260318_140208",
        project_key="COGI",
        repo_label="repo1",
        state="done",
        html_name="scan.html",
        html_detail_mode="detailed",
        csv_name="scan.csv",
        json_name="scan.json",
        log_url="/api/history/log/20260318_140208",
        csrf_token="csrf-demo",
    ).decode("utf-8")

    assert '<iframe class="results-frame" src="/reports/scan.html"' in html
    assert 'Open Raw HTML' not in html
    assert 'Download CSV File' not in html
    assert 'Download JSON' not in html
    assert 'Download SARIF' not in html
    assert 'Download Threat Dragon' not in html
    assert 'Download Logs' not in html
    assert 'Replay Threat Model' not in html
    assert 'href="/scan/20260318_140208?tab=activity"' in html
    assert 'href="/scan/20260318_140208?tab=results"' in html
    assert '<h2>Results</h2>' not in html
    assert "Review the completed scan and download the generated artifacts." not in html
    assert 'repo1' not in html


def test_results_page_keeps_detailed_generation_available_after_fast_html():
    import app_server as srv

    html = srv.render_results_page(
        scan_id="20260318_140208",
        project_key="COGI",
        repo_label="repo1",
        state="done",
        html_name="scan_fast.html",
        html_detail_mode="fast",
        csv_name="scan.csv",
        json_name="scan.json",
        log_url="/api/history/log/20260318_140208",
        can_generate_html=True,
        csrf_token="csrf-demo",
    ).decode("utf-8")

    assert 'Open Raw HTML' not in html
    assert 'name="html_detail_mode" value="detailed"' not in html
    assert "Generate Detailed HTML" not in html
    assert "Generate Fast HTML" not in html


def test_results_page_handles_missing_html_report():
    import app_server as srv

    html = srv.render_results_page(
        scan_id="20260318_140208",
        project_key="COGI",
        repo_label="repo1",
        state="done",
        html_name="",
        csv_name="",
        log_url="/api/history/log/20260318_140208",
    ).decode("utf-8")

    assert "No report was generated for this scan." in html
    assert '<iframe class="results-frame"' not in html


def test_results_page_offers_on_demand_html_generation_when_findings_exist():
    import app_server as srv

    html = srv.render_results_page(
        scan_id="20260318_140208",
        project_key="COGI",
        repo_label="repo1",
        state="done",
        html_name="",
        csv_name="scan.csv",
        json_name="scan.json",
        log_url="/api/history/log/20260318_140208",
        can_generate_html=True,
        csrf_token="csrf-demo",
    ).decode("utf-8")

    assert "HTML report has not been generated yet." in html
    assert 'action="/scan/20260318_140208/generate-html"' not in html
    assert 'name="html_detail_mode" value="fast"' not in html
    assert 'name="html_detail_mode" value="detailed"' not in html
    assert "Generate Fast HTML" not in html
    assert "Generate Detailed HTML" not in html
    assert "Download CSV File" not in html
    assert "Download Threat Dragon" not in html
    assert "Replay Threat Model" not in html
    assert '<iframe class="results-frame"' not in html


def test_results_page_shows_html_generation_progress_card():
    import app_server as srv

    html = srv.render_results_page(
        scan_id="20260318_140208",
        project_key="COGI",
        repo_label="repo1",
        state="done",
        html_name="",
        csv_name="scan.csv",
        log_url="/api/history/log/20260318_140208",
        can_generate_html=True,
        html_generation={"state": "running", "message": "Generating LLM analysis 3/12...", "current": 3, "total": 12, "detail_mode": "detailed"},
        csrf_token="csrf-demo",
    ).decode("utf-8")

    assert "Detailed HTML Report Generation" in html
    assert "Generating LLM analysis 3/12..." in html
    assert 'data-report-generation-active="1"' in html
    assert 'src="/assets/results_page.js"' in html


def test_generate_html_report_for_scan_uses_stored_scan_record(monkeypatch):
    import app_server as srv

    record = {
        "scan_id": "20260322_100000",
        "reports": {"__all__": {}},
        "findings": [{"file": "stored.py", "llm_reason": "stored detail"}],
    }
    called = {}

    monkeypatch.setattr(srv, "_scan_record_for_id", lambda scan_id: record if scan_id == "20260322_100000" else None)
    monkeypatch.setattr(
        srv,
        "_current_session_snapshot",
        lambda: {"scan_id": "20260322_100000", "findings": [{"file": "live.py", "llm_reason": "live detail"}]},
    )

    class _StubService:
        def generate_html_report(self, scan_id, findings=None, **kwargs):
            called["scan_id"] = scan_id
            called["findings"] = findings
            return {"reports": {"__all__": {"html": "scan.html"}}}

    monkeypatch.setattr(srv, "_scan_service", _StubService())

    class _DummyCurrent:
        report_paths = {}

    monkeypatch.setattr(srv, "_current_session", lambda: _DummyCurrent())

    updated = srv._generate_html_report_for_scan("20260322_100000")

    assert updated["reports"]["__all__"]["html"] == "scan.html"
    assert called["scan_id"] == "20260322_100000"
    assert called["findings"] is None


def test_page_generate_html_report_redirects_back_to_scan_findings(monkeypatch):
    import app_server as srv

    record = {
        "scan_id": "20260322_120000",
        "project_key": "LOCAL",
        "reports": {"__all__": {}},
        "findings": [{"file": "stored.py"}],
    }
    redirects = []

    class DummyHandler:
        def _redirect(self, location):
            redirects.append(location)

        def _err(self, status, msg):
            raise AssertionError(f"{status}: {msg}")

    monkeypatch.setattr(srv, "_require_role", lambda handler, role: False)
    monkeypatch.setattr(srv, "_scan_record_for_id", lambda scan_id: record if scan_id == "20260322_120000" else None)
    monkeypatch.setattr(srv, "_require_project_access", lambda handler, project_key: False)
    monkeypatch.setattr(srv, "_start_html_report_generation", lambda scan_id, detail_mode="detailed": {"state": "queued"})

    srv._Handler._page_generate_html_report(DummyHandler(), "20260322_120000", {"html_detail_mode": "detailed"})

    assert redirects == ["/findings?scan_id=20260322_120000&notice=Detailed+HTML+report+generation+started"]


def test_html_report_fast_mode_skips_llm_detail_fetch(tmp_path):
    reporter = HTMLReporter(str(tmp_path), "demo")
    called = {"fetch": False}
    original_fetch = reporter._fetch_llm_details
    original_render = reporter._render
    try:
        def _fake_fetch(*args, **kwargs):
            called["fetch"] = True
            return {}
        reporter._render = lambda findings, policy, llm_details: "<html></html>"
        reporter._fetch_llm_details = _fake_fetch
        out = reporter.write(
            [{"file": "a.py", "line": 1, "provider_or_lib": "openai", "severity": 4}],
            policy={},
            ollama_url="http://localhost:11434",
            ollama_model="demo",
            detail_mode="fast",
        )
    finally:
        reporter._fetch_llm_details = original_fetch
        reporter._render = original_render
    assert Path(out).exists()
    assert called["fetch"] is False


def test_html_report_detail_cache_reuses_saved_llm_response(tmp_path):
    reporter = HTMLReporter(str(tmp_path), "demo")
    original_render = reporter._render
    findings = [{
        "file": "a.py",
        "line": 1,
        "provider_or_lib": "openai",
        "capability": "chat",
        "ai_category": "provider",
        "severity": 2,
        "description": "demo",
        "snippet": "client.chat()",
    }]
    calls = {"count": 0}
    original_urlopen = __import__("urllib.request").request.urlopen

    class _Resp:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def read(self):
            return json.dumps({"message": {"content": "## Why\nTest\n## How\n- Fix\n## Secure\n```python\npass\n```\n## References\nhttps://owasp.org"}}).encode("utf-8")

    try:
        reporter._render = lambda findings, policy, llm_details: "<html></html>"
        def _fake_urlopen(req, timeout=0):
            calls["count"] += 1
            return _Resp()
        __import__("urllib.request").request.urlopen = _fake_urlopen
        reporter.write(findings, policy={}, ollama_url="http://localhost:11434", ollama_model="demo", detail_mode="detailed")
        reporter.write(findings, policy={}, ollama_url="http://localhost:11434", ollama_model="demo", detail_mode="detailed")
    finally:
        __import__("urllib.request").request.urlopen = original_urlopen
        reporter._render = original_render
    assert calls["count"] == 1


def test_json_report_includes_structured_threat_model(tmp_path):
    findings = [{
        "provider_or_lib": "secret_ai_correlation",
        "description": "Credential-like data appears near AI usage.",
        "file": "app.py",
        "line": 12,
        "severity": 1,
        "context": "production",
    }]
    reporter = JSONReporter(str(tmp_path), "scan_demo")
    path = reporter.write_json(findings, meta={"project_key": "LOCAL", "repo": "repo1"})
    payload = json.loads(Path(path).read_text(encoding="utf-8"))

    assert "threat_model" in payload
    assert payload["threat_model"]["stages"]["threats"]
    assert payload["threat_model"]["stages"]["attack_trees"]


def test_html_report_header_uses_png_logo_and_centered_band(tmp_path):
    reporter = HTMLReporter(str(tmp_path), "demo")
    html = reporter._render([], {}, {})
    assert "data:image/png;base64," in html
    assert "flex-direction:column" in html
    assert "text-align:center" in html


def test_render_results_page_resolves_current_session_report():
    import app_server as srv

    orig_session = srv._session
    try:
        session = srv.ScanSession()
        session.scan_id = "20260318_150000"
        session.project_key = "COGI"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.started_at_utc = "2026-03-18T15:00:00Z"
        session.report_paths = {
            "__all__": {
                "html_name": "current.html",
                "csv_name": "current.csv",
            }
        }
        srv._session = session

        class DummyHandler:
            def __init__(self):
                self.sent = None
                self.redirected = None

            def _send(self, status, ct, body):
                self.sent = (status, ct, body)

            def _err(self, status, msg):
                raise AssertionError(f"{status}: {msg}")

            def _redirect(self, location):
                self.redirected = location

        handler = DummyHandler()
        with patch.object(srv, "_require_role", return_value=False):
            srv._Handler._render_results_page(handler, "20260318_150000")

        assert handler.redirected == "/scan/20260318_150000?tab=results"
    finally:
        srv._session = orig_session


def test_report_access_matches_json_exports():
    from services.report_access import find_history_record_by_report_name

    record = {
        "scan_id": "20260319_191549",
        "reports": {
            "__all__": {
                "json": r"C:\aitool\output\ai_scan_demo.json",
                "json_name": "ai_scan_demo.json",
            }
        },
    }

    assert find_history_record_by_report_name([record], "ai_scan_demo.json") == record


def test_asset_route_serves_main_css():
    import app_server as srv

    class DummyHandler:
        path = "/assets/main.css"

        def __init__(self):
            self.payload = None

        def _send(self, status, content_type, body):
            self.payload = (status, content_type, body)

        def _404(self):
            self.payload = ("404", None, None)

    handler = DummyHandler()
    srv._Handler.do_GET(handler)

    assert handler.payload[0] == 200
    assert handler.payload[1] == "text/css; charset=utf-8"
    assert b".header-nav" in handler.payload[2]


def test_asset_route_serves_layout_js():
    import app_server as srv

    class DummyHandler:
        path = "/assets/layout.js"

        def __init__(self):
            self.payload = None

        def _send(self, status, content_type, body):
            self.payload = (status, content_type, body)

        def _404(self):
            self.payload = ("404", None, None)

    handler = DummyHandler()
    srv._Handler.do_GET(handler)

    assert handler.payload[0] == 200
    assert handler.payload[1] == "application/javascript; charset=utf-8"
    assert b"history.replaceState" in handler.payload[2]
    assert b"phantomlm.triage.updated" in handler.payload[2]
    assert b"phantomlm.settings.updated" in handler.payload[2]


def test_asset_route_serves_history_page_js():
    import app_server as srv

    class DummyHandler:
        path = "/assets/history_page.js"

        def __init__(self):
            self.payload = None

        def _send(self, status, content_type, body):
            self.payload = (status, content_type, body)

        def _404(self):
            self.payload = ("404", None, None)

    handler = DummyHandler()
    srv._Handler.do_GET(handler)

    assert handler.payload[0] == 200
    assert handler.payload[1] == "application/javascript; charset=utf-8"
    assert b"sortHistory" in handler.payload[2]
    assert b"phantomlm.history.updated" not in handler.payload[2]


def test_asset_route_serves_findings_page_js():
    import app_server as srv

    class DummyHandler:
        path = "/assets/findings_page.js"

        def __init__(self):
            self.payload = None

        def _send(self, status, content_type, body):
            self.payload = (status, content_type, body)

        def _404(self):
            self.payload = ("404", None, None)

    handler = DummyHandler()
    srv._Handler.do_GET(handler)

    assert handler.payload[0] == 200
    assert handler.payload[1] == "application/javascript; charset=utf-8"
    assert b"box.checked = false;" in handler.payload[2]


def test_asset_route_serves_scan_page_js_with_settings_sync_refresh():
    import app_server as srv

    class DummyHandler:
        path = "/assets/scan_page.js"

        def __init__(self):
            self.payload = None

        def _send(self, status, content_type, body):
            self.payload = (status, content_type, body)

        def _404(self):
            self.payload = ("404", None, None)

    handler = DummyHandler()
    srv._Handler.do_GET(handler)

    assert handler.payload[0] == 200
    assert handler.payload[1] == "application/javascript; charset=utf-8"
    assert b'event.key !== "phantomlm.settings.updated"' in handler.payload[2]
    assert b"refreshModels();" in handler.payload[2]


def test_scan_workspace_results_page_handles_missing_report():
    import app_server as srv

    orig_find = srv._find_history_record_by_scan_id
    try:
        record = {
            "scan_id": "20260318_150000",
            "project_key": "COGI",
            "repo_slugs": ["repo1"],
            "state": "done",
            "started_at_utc": "2026-03-18T15:00:00Z",
            "reports": {"__all__": {}},
            "delta": {},
            "inventory": {},
            "log_file": "",
        }
        srv._find_history_record_by_scan_id = lambda _scan_id: record

        class DummyHandler:
            def __init__(self):
                self.path = "/scan/20260318_150000?tab=results"
                self.sent = None

            def _send(self, status, ct, body):
                self.sent = (status, ct, body)

            def _err(self, status, msg):
                raise AssertionError(f"{status}: {msg}")

        handler = DummyHandler()
        with patch.object(srv, "_require_role", return_value=False), \
             patch.object(srv, "_require_project_access", return_value=False), \
             patch.object(srv, "_has_scan_results", return_value=False), \
             patch.object(srv, "_current_csrf_token", return_value="csrf-demo"):
            srv._Handler._render_scan_workspace_page(handler, "20260318_150000")

        html = handler.sent[2].decode("utf-8")
        assert "No report was generated for this scan." in html
    finally:
        srv._find_history_record_by_scan_id = orig_find


def test_scan_workspace_activity_renders_for_empty_scan_record_without_log_text():
    import app_server as srv

    orig_find = srv._find_history_record_by_scan_id
    orig_get_log = srv._get_log_text
    try:
        record = {
            "scan_id": "20260318_160000",
            "project_key": "EMPTY",
            "repo_slugs": [],
            "state": "done",
            "started_at_utc": "2026-03-18T16:00:00Z",
            "reports": {"__all__": {}},
            "delta": {},
            "inventory": {},
            "log_file": "",
            "total": 0,
            "suppressed_total": 0,
        }
        srv._find_history_record_by_scan_id = lambda _scan_id: record
        srv._get_log_text = lambda _scan_id: ""

        class DummyHandler:
            def __init__(self):
                self.path = "/scan/20260318_160000?tab=activity"
                self.sent = None

            def _send(self, status, ct, body):
                self.sent = (status, ct, body)

            def _err(self, status, msg):
                raise AssertionError(f"{status}: {msg}")

        handler = DummyHandler()
        with patch.object(srv, "_require_role", return_value=False), \
             patch.object(srv, "_require_project_access", return_value=False), \
             patch.object(srv, "_has_scan_results", return_value=False), \
             patch.object(srv, "_current_csrf_token", return_value="csrf-demo"), \
             patch.object(srv, "filter_projects", return_value=[]), \
             patch.object(srv, "load_llm_config", return_value={"base_url": "http://localhost:11434", "model": "m1"}), \
             patch.object(srv, "_ollama_snapshot", return_value={"models": ["m1"]}):
            srv._Handler._render_scan_workspace_page(handler, "20260318_160000")

        html = handler.sent[2].decode("utf-8")
        assert "Activity Log" in html
        assert "Start Scan" not in html
        assert "No activity yet." in html
    finally:
        srv._find_history_record_by_scan_id = orig_find
        srv._get_log_text = orig_get_log


def test_settings_page_is_server_rendered():
    import app_server as srv

    html = srv.render_settings_page(
        bitbucket_url=srv.BITBUCKET_URL,
        output_dir=srv.OUTPUT_DIR,
        llm_cfg={"base_url": "http://localhost:11434", "model": "m", "report_detail_timeout_s": 180},
        tls_cfg={"verify_ssl": True, "ca_bundle": "C:\\corp-ca.pem"},
        state_dir="C:\\Users\\demo\\AppData\\Local\\AI Scanner",
    ).decode("utf-8")

    assert 'action="/settings/save"' in html
    assert srv.BITBUCKET_URL in html
    assert 'name="bitbucket_ca_bundle"' in html
    assert 'value="C:\\corp-ca.pem"' in html
    assert 'name="bitbucket_verify_ssl"' in html
    assert 'name="report_detail_timeout_s"' in html


def test_settings_page_warns_about_legacy_repo_root_runtime_files():
    import app_server as srv

    html = srv.render_settings_page(
        bitbucket_url=srv.BITBUCKET_URL,
        output_dir=srv.OUTPUT_DIR,
        llm_cfg={"base_url": "http://localhost:11434", "model": "m", "report_detail_timeout_s": 180},
        tls_cfg={"verify_ssl": True, "ca_bundle": ""},
        state_dir="C:\\Users\\demo\\AppData\\Local\\AI Scanner",
        legacy_runtime_files=[
            {
                "label": "LLM Config",
                "legacy_path": "C:\\aitool\\ai_scanner_llm_config.json",
                "active_path": "C:\\Users\\demo\\AppData\\Local\\AI Scanner\\ai_scanner_llm_config.json",
            }
        ],
    ).decode("utf-8")

    assert "Legacy repo-root runtime files detected" in html
    assert "Editing the old repo-root files will not change live settings." in html
    assert "C:\\aitool\\ai_scanner_llm_config.json" in html


def test_legacy_runtime_artifacts_lists_existing_repo_root_runtime_files():
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_base = srv._BASE_DIR
    orig_state_dir = srv.STATE_DIR
    orig_legacy_runtime_files = srv._LEGACY_RUNTIME_FILES
    try:
        legacy_cfg = d / "ai_scanner_llm_config.json"
        legacy_cfg.write_text("{}", encoding="utf-8")
        active_cfg = d / "state" / "ai_scanner_llm_config.json"
        active_cfg.parent.mkdir(parents=True, exist_ok=True)
        active_cfg.write_text("{}", encoding="utf-8")
        srv._BASE_DIR = d
        srv.STATE_DIR = d / "state"
        srv._LEGACY_RUNTIME_FILES = (
            ("LLM Config", legacy_cfg, active_cfg),
        )

        result = srv._legacy_runtime_artifacts()
        assert result == [{
            "label": "LLM Config",
            "legacy_path": str(legacy_cfg.resolve()),
            "active_path": str(active_cfg.resolve()),
        }]
    finally:
        srv._BASE_DIR = orig_base
        srv.STATE_DIR = orig_state_dir
        srv._LEGACY_RUNTIME_FILES = orig_legacy_runtime_files


def test_help_page_is_server_rendered():
    import app_server as srv

    html = srv.render_help_page().decode("utf-8")

    assert 'href="/help"' in html
    assert 'href="/inventory"' in html
    assert '<a class="nav active" href="/help">Help</a>' in html
    assert "PhantomLM Wiki" in html
    assert "On This Page" in html
    assert 'href="#installation"' in html
    assert "Capabilities" in html
    assert "CLI Usage" in html
    assert "Import / Export" in html
    assert "Known Limitations" in html
    assert "AI Inventory" in html
    assert 'id="connection-banner"' in html
    assert "Trying to reconnect to the local PhantomLM server" in html


def test_trends_page_renders_dashboard_controls():
    import app_server as srv

    html = srv.render_trends_page(
        trends={
            "summary": {"scan_count": 1, "total_findings": 2, "critical_prod_total": 1, "models_used": 1},
            "findings_over_time": [{"label": "2026-03-20", "repo": "repo1", "value": 2}],
            "critical_over_time": [{"label": "2026-03-20", "repo": "repo1", "value": 1}],
            "new_fixed_over_time": [],
            "top_repos_by_risk": [],
            "top_noisy_rules": [],
            "suppression_rate_by_rule": [],
            "llm_review_failure_rate_by_model": [],
        }
    ).decode("utf-8")

    assert 'id="trend-dashboard"' in html
    assert 'id="trends-layout-select"' in html
    assert 'data-card-id="findings_over_time"' in html
    assert 'data-card-id="llm_review_failure_rate_by_model"' in html
    assert 'src="/assets/trends_page.js"' in html
    assert 'class="trend-timeseries"' in html
    assert 'class="trend-timeseries-svg"' in html


def test_top_repos_by_risk_uses_latest_repo_snapshot_not_cumulative_counts():
    from services.trends import compute_history_trends

    trends = compute_history_trends([
        {
            "scan_id": "20260319_100000",
            "started_at_utc": "2026-03-19T10:00:00Z",
            "repo_slugs": ["repo1"],
            "sev": {"critical": 2, "high": 1, "medium": 0, "low": 0},
            "critical_prod": 50,
            "high_prod": 10,
            "total": 60,
        },
        {
            "scan_id": "20260320_100000",
            "started_at_utc": "2026-03-20T10:00:00Z",
            "repo_slugs": ["repo1"],
            "sev": {"critical": 1, "high": 0, "medium": 1, "low": 0},
            "critical_prod": 2,
            "high_prod": 1,
            "total": 4,
        },
    ])

    top_repo = trends["top_repos_by_risk"][0]
    assert top_repo["repo"] == "repo1"
    assert top_repo["scans"] == 2
    assert top_repo["critical_prod"] == 2
    assert top_repo["risk_score"] == 22


def test_multi_repo_trends_expand_scan_history_into_separate_repo_rows():
    from services.trends import compute_history_trends

    trends = compute_history_trends([
        {
            "scan_id": "20260320_101500",
            "started_at_utc": "2026-03-20T10:15:00Z",
            "state": "done",
            "repo_slugs": ["repo1", "repo2"],
            "per_repo": {
                "repo1": {
                    "count": 3,
                    "sev": {1: 1, 2: 1, 3: 0, 4: 1},
                },
                "repo2": {
                    "count": 2,
                    "sev": {1: 0, 2: 1, 3: 1, 4: 0},
                },
            },
            "findings": [
                {"repo": "repo1", "delta_status": "new"},
                {"repo": "repo1", "delta_status": "existing"},
                {"repo": "repo1", "delta_status": "existing"},
                {"repo": "repo2", "delta_status": "new"},
                {"repo": "repo2", "delta_status": "existing"},
            ],
            "total": 5,
            "critical_prod": 99,
            "high_prod": 88,
        }
    ])

    repo_names = [item["repo"] for item in trends["top_repos_by_risk"]]
    assert "repo1" in repo_names
    assert "repo2" in repo_names
    assert "repo1, repo2" not in repo_names

    findings_rows = {(item["repo"], item["value"]) for item in trends["findings_over_time"]}
    assert ("repo1", 3) in findings_rows
    assert ("repo2", 2) in findings_rows

    critical_rows = {(item["repo"], item["value"], item["high_prod"]) for item in trends["critical_over_time"]}
    assert ("repo1", 1, 1) in critical_rows
    assert ("repo2", 0, 1) in critical_rows

    delta_rows = {(item["repo"], item["new_count"], item["fixed_count"]) for item in trends["new_fixed_over_time"]}
    assert ("repo1", 1, 0) in delta_rows
    assert ("repo2", 1, 0) in delta_rows


def test_trends_over_time_use_all_past_scans_not_only_recent_subset():
    from services.trends import compute_history_trends

    records = []
    for idx in range(15):
        records.append({
            "scan_id": f"20260320_10{idx:02d}00",
            "started_at_utc": f"2026-03-20T10:{idx:02d}:00Z",
            "repo_slugs": ["repo1"],
            "total": idx + 1,
            "sev": {"critical": 0, "high": 0, "medium": 0, "low": idx + 1},
            "critical_prod": 0,
            "high_prod": 0,
            "delta": {"new_count": idx, "fixed_count": 0},
        })

    trends = compute_history_trends(records)

    assert len(trends["findings_over_time"]) == 15
    assert trends["findings_over_time"][0]["value"] == 1
    assert trends["findings_over_time"][-1]["value"] == 15


def test_trends_apply_live_false_positive_triage_overlay_to_rule_metrics():
    from services.trends import compute_history_trends

    records = [{
        "scan_id": "20260322_150000",
        "started_at_utc": "2026-03-22T15:00:00Z",
        "repo_slugs": ["repo1"],
        "total": 2,
        "findings": [
            {"_hash": "hash-1", "repo": "repo1", "provider_or_lib": "debug_mode"},
            {"_hash": "hash-2", "repo": "repo1", "provider_or_lib": "debug_mode"},
        ],
        "trend": {
            "rules": {
                "active": {"debug_mode": 2},
                "suppressed": {},
            }
        },
    }]

    trends = compute_history_trends(records, {"hash-2": {"status": TRIAGE_FALSE_POSITIVE}})

    assert trends["top_noisy_rules"][0]["rule"] == "debug_mode"
    assert trends["top_noisy_rules"][0]["hits"] == 2
    assert trends["top_noisy_rules"][0]["suppressed"] == 1
    assert trends["suppression_rate_by_rule"][0]["rule"] == "debug_mode"
    assert trends["suppression_rate_by_rule"][0]["suppressed"] == 1
    assert trends["suppression_rate_by_rule"][0]["total"] == 2
    assert trends["suppression_rate_by_rule"][0]["rate_pct"] == 50


def test_inventory_page_is_server_rendered():
    import app_server as srv

    html = srv.render_inventory_page(
        repo_inventory=[
            {
                "repo": "repo1",
                "project_key": "COGI",
                "scan_id": "20260318_101500",
                "last_scan_at_utc": "2026-03-18T10:15:00Z",
                "finding_count": 4,
                "provider_labels": ["Openai", "Langchain"],
                "models": ["gpt-4o"],
                "embeddings_vector_db": True,
                "prompt_handling": True,
                "model_serving": False,
                "agent_tool_use": True,
                "usage_tags": ["embeddings", "prompt", "agent"],
                "reports": {"html_name": "demo.html"},
            }
        ],
        summary={
            "repos_using_ai_count": 1,
            "repos_total": 1,
            "provider_count": 2,
            "model_count": 1,
            "agent_tool_use_repos": 1,
        },
    ).decode("utf-8")

    assert '<a class="nav active" href="/inventory">AI Inventory</a>' in html
    assert "Latest known AI usage profile per repository from scan history." in html
    assert "repo1" in html
    assert "Openai, Langchain" in html
    assert "gpt-4o" in html
    assert 'id="inventory-search"' in html
    assert 'id="inventory-reset"' in html
    assert 'href="/reports/demo.html"' in html


def test_login_page_centers_login_action():
    import app_server as srv

    html = srv.render_login_page(bitbucket_url=srv.BITBUCKET_URL, has_saved_pat=False).decode("utf-8")

    assert 'href="/assets/main.css"' in html
    assert '<div class="login-actions"><button type="submit" autofocus>Login</button></div>' in html
    assert '<body class="login-page">' in html
    assert '<header>' not in html
    assert '<section class="login-brand">' in html


def test_allowed_origin_only_permits_local_app_hosts():
    import app_server as srv

    assert srv._allowed_origin(f"http://127.0.0.1:{srv.APP_PORT}") == f"http://127.0.0.1:{srv.APP_PORT}"
    assert srv._allowed_origin(f"http://localhost:{srv.APP_PORT}") == f"http://localhost:{srv.APP_PORT}"
    assert srv._allowed_origin("https://evil.example") is None


def test_api_projects_returns_cached_projects():
    import app_server as srv

    class DummyHandler:
        path = "/api/projects"

        def __init__(self):
            self.headers = {"Cookie": "ai_scanner_session=valid-session"}
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    orig_state = srv._operator_state
    original_sessions = _install_browser_session(srv)
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
    srv._operator_state.projects_cache = [{"key": "COGI"}, {"key": "APPSEC"}]
    srv._operator_state.connected_owner = "Security Engineer"

    try:
        handler = DummyHandler()
        srv._Handler.do_GET(handler)

        assert handler.payload[0] == 200
        assert handler.payload[1]["projects"] == [{"key": "COGI"}, {"key": "APPSEC"}]
        assert handler.payload[1]["owner"] == "Security Engineer"
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_api_projects_filters_by_user_scope():
    import app_server as srv

    class DummyHandler:
        path = "/api/projects"

        def __init__(self):
            self.headers = {"Cookie": "ai_scanner_session=valid-session"}
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    orig_state = srv._operator_state
    original_sessions = _install_browser_session(srv)
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Security Engineer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Security Engineer",
                roles=(ROLE_VIEWER,),
                allowed_projects=("COGI",),
            ),
        )
    )
    srv._operator_state.projects_cache = [{"key": "COGI"}, {"key": "APPSEC"}]
    srv._operator_state.connected_owner = "Security Engineer"

    try:
        handler = DummyHandler()
        srv._Handler.do_GET(handler)

        assert handler.payload[0] == 200
        assert handler.payload[1]["projects"] == [{"key": "COGI"}]
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_default_temp_dir_prefers_system_temp_on_windows():
    import app_server as srv

    temp_dir = srv._default_temp_dir(os_name="nt", temp_root=r"C:\Temp")

    assert temp_dir == Path(r"C:\Temp") / "ai_scanner_tmp"


def test_scan_session_status_includes_suppressed_details():
    from services.scan_jobs import ScanSession

    session = ScanSession()
    session.scan_id = "20250316_040404"
    session.findings = [
        {"_hash": "a1", "repo": "repo1", "file": "app.py", "line": 12, "severity": 2, "capability": "OpenAI API"}
    ]
    session.suppressed_findings = [
        {
            "_hash": "b2",
            "repo": "repo1",
            "file": "docs.md",
            "line": 3,
            "severity": 4,
            "capability": "Example",
            "suppressed_reason": "Documentation example",
            "suppressed_by": "analyst",
            "suppressed_at": "2026-03-17",
        }
    ]

    status = session.to_status()

    assert status["active_count"] == 1
    assert status["suppressed_count"] == 1
    assert status["finding_details"][0]["hash"] == "a1"
    assert status["suppressed_details"][0]["reason"] == "Documentation example"


def test_scan_session_status_includes_observability_fields():
    from services.scan_jobs import ScanSession

    session = ScanSession()
    session.phase_metrics = {"init": 2, "scan": 11, "total": 13}
    session.repo_metrics = {"repo1": {"clone_s": 1.2, "scan_s": 2.3, "llm_review_s": 0.0}}
    session.llm_batch_metrics = [{"batch": 1, "total_batches": 2, "duration_s": 4.2, "failed": False}]
    session.cache_metrics = {"hits": 3, "misses": 1}
    session.errors = [{"code": "LLM_REVIEW_FAILED", "stage": "llm_review", "message": "timed out"}]

    status = session.to_status()

    assert status["phase_metrics"]["scan"] == 11
    assert status["repo_metrics"]["repo1"]["clone_s"] == 1.2
    assert status["llm_batch_metrics"][0]["batch"] == 1
    assert status["cache_metrics"]["hits"] == 3
    assert status["errors"][0]["code"] == "LLM_REVIEW_FAILED"


def test_get_log_text_reads_from_sqlite_when_file_missing():
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    srv.OUTPUT_DIR = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR = str(d / "logs")
    srv.DB_FILE = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        session = srv.ScanSession()
        session.scan_id = "20250316_020202"
        session.project_key = "TEST"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.llm_model = "test-model"
        session.llm_model_info = {"name": "test-model"}
        session.log("SQLite-backed log entry", "info")
        srv._save_history_record(session, [])

        log_path = Path(srv.LOG_DIR) / "20250316_020202.txt"
        if log_path.exists():
            log_path.unlink()

        log_text = srv._get_log_text("20250316_020202")
        assert "SQLite-backed log entry" in log_text
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv._invalidate_history_cache()


def test_delete_history_removes_sqlite_record():
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    srv.OUTPUT_DIR = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR = str(d / "logs")
    srv.DB_FILE = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        session = srv.ScanSession()
        session.scan_id = "20250316_030303"
        session.project_key = "TEST"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.llm_model = "test-model"
        session.llm_model_info = {"name": "test-model"}
        session.log("To be deleted", "info")
        srv._save_history_record(session, [])

        assert any(r["scan_id"] == "20250316_030303" for r in srv._load_history())

        srv._delete_history(["20250316_030303"])

        assert all(r["scan_id"] != "20250316_030303" for r in srv._load_history())
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv._invalidate_history_cache()


def test_api_finding_suppress_moves_finding_and_preserves_reports():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    orig_sup = srv.SUPPRESSIONS_FILE
    orig_session = srv._session
    orig_state = srv._operator_state
    srv.OUTPUT_DIR = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR = str(d / "logs")
    srv.DB_FILE = str(d / "scan_jobs.db")
    srv.SUPPRESSIONS_FILE = str(d / "ai_scanner_suppressions.json")
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Security Engineer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Security Engineer",
                roles=(ROLE_VIEWER, ROLE_SCANNER, ROLE_TRIAGE, ROLE_ADMIN),
                allowed_projects=("*",),
            ),
        )
    )
    srv._invalidate_history_cache()

    try:
        html_path = d / "report.html"
        csv_path = d / "report.csv"
        html_path.write_text("html")
        csv_path.write_text("csv")

        session = srv.ScanSession()
        finding = {
            "_hash": "hash-1",
            "repo": "repo1",
            "file": "app.py",
            "line": 9,
            "severity": 2,
            "capability": "OpenAI API",
            "description": "Detected usage",
        }
        session.scan_id = "20250316_050505"
        session.project_key = "TEST"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.findings = [finding]
        session.per_repo = {"repo1": [finding]}
        session.report_paths = {
            "__all__": {
                "html": str(html_path),
                "csv": str(csv_path),
                "html_name": html_path.name,
                "csv_name": csv_path.name,
            }
        }
        srv._session = session

        handler = DummyHandler()
        srv._Handler._api_finding_suppress(handler, {"hash": "hash-1", "reason": "Expected internal example"})

        assert handler.payload[0] == 200
        assert handler.payload[1]["ok"] is True
        assert srv._session.findings == []
        assert len(srv._session.suppressed_findings) == 1
        assert srv._session.report_paths["__all__"]["html_name"] == html_path.name
        assert srv._session.report_paths["__all__"]["csv_name"] == csv_path.name
        assert html_path.exists()
        assert csv_path.exists()
        assert any(rec["hash"] == "hash-1" for rec in list_suppressions(srv.SUPPRESSIONS_FILE))
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv.SUPPRESSIONS_FILE = orig_sup
        srv._session = orig_session
        srv._operator_state = orig_state
        srv._invalidate_history_cache()


def test_api_scan_start_requires_scanner_role():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    orig_state = srv._operator_state
    try:
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
        handler = DummyHandler()
        srv._Handler._api_scan_start(
            handler,
            {"project_key": "COGI", "repo_slugs": ["repo1"]},
        )
        assert handler.payload[0] == 403
        assert "scanner role required" in handler.payload[1]["error"]
    finally:
        srv._operator_state = orig_state


def test_api_repos_rejects_project_outside_scope():
    import app_server as srv

    class DummyClient:
        def list_repos(self, project_key):
            return [{"slug": "repo1", "project": project_key}]

    class DummyHandler:
        path = "/api/repos?project=APPSEC"

        def __init__(self):
            self.headers = {"Cookie": "ai_scanner_session=valid-session"}
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    orig_state = srv._operator_state
    original_sessions = _install_browser_session(srv)
    try:
        srv._operator_state = SingleUserState(
            SingleUserConfig(
                name="Analyst",
                expected_bitbucket_owner="",
                ctx=UserContext(
                    username="Analyst",
                    roles=(ROLE_VIEWER, ROLE_SCANNER),
                    allowed_projects=("COGI",),
                ),
            )
        )
        srv._operator_state.client = DummyClient()
        handler = DummyHandler()
        srv._Handler.do_GET(handler)
        assert handler.payload[0] == 403
        assert "project access denied" in handler.payload[1]["error"]
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_api_connect_rotates_browser_sessions_and_invalidates_old_cookie():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.headers = {}
            self.payload = None
            self._response_cookies = []

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    original_sessions = dict(srv._browser_sessions)
    orig_state = srv._operator_state
    srv._browser_sessions.clear()
    srv._browser_sessions["old-session"] = {"csrf_token": "old-csrf", "issued_at": time.time()}
    try:
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
        handler = DummyHandler()
        with patch.object(srv, "connect_operator", return_value={"ok": True, "projects": [{"key": "COGI"}], "owner": "Security Engineer"}):
            srv._Handler._api_connect(handler, {"token": "demo"})

        assert handler.payload[0] == 200
        assert handler.payload[1]["ok"] is True
        assert "csrf_token" in handler.payload[1]
        assert len(srv._browser_sessions) == 1
        new_session_id = next(iter(srv._browser_sessions))
        assert new_session_id != "old-session"
        assert "old-session" not in srv._browser_sessions
        assert handler._response_cookies and f"ai_scanner_session={new_session_id};" in handler._response_cookies[0]
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_rotated_old_browser_session_redirects_page_requests_to_login():
    import app_server as srv
    from urllib.parse import urlparse

    class DummyHandler:
        def __init__(self):
            self.headers = {"Cookie": "ai_scanner_session=old-session"}
            self.redirect_to = None

        def _redirect(self, location):
            self.redirect_to = location

        def _require_browser_session(self):
            return srv._Handler._require_browser_session(self)

    original_sessions = dict(srv._browser_sessions)
    orig_state = srv._operator_state
    srv._browser_sessions.clear()
    srv._browser_sessions["old-session"] = {"csrf_token": "old-csrf", "issued_at": time.time()}
    try:
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
        new_session_id, _csrf = srv._rotate_browser_session()
        assert new_session_id != "old-session"

        handler = DummyHandler()
        handled = srv._Handler._handle_page_get(handler, urlparse("/scan"))

        assert handled is True
        assert handler.redirect_to == "/login"
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_rotated_old_browser_session_gets_401_on_api_requests():
    import app_server as srv

    class DummyHandler:
        path = "/api/projects"

        def __init__(self):
            self.headers = {"Cookie": "ai_scanner_session=old-session"}
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    original_sessions = dict(srv._browser_sessions)
    orig_state = srv._operator_state
    srv._browser_sessions.clear()
    srv._browser_sessions["old-session"] = {"csrf_token": "old-csrf", "issued_at": time.time()}
    try:
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
        srv._rotate_browser_session()

        handler = DummyHandler()
        srv._Handler.do_GET(handler)

        assert handler.payload == (401, {"error": "Authentication required"})
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_viewer_cannot_read_triage_or_suppressions_api():
    import app_server as srv

    class DummyHandler:
        def __init__(self, path):
            self.path = path
            self.headers = {"Cookie": "ai_scanner_session=valid-session"}
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    orig_state = srv._operator_state
    original_sessions = _install_browser_session(srv)
    try:
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
        for path in ("/api/suppressions", "/api/triage"):
            handler = DummyHandler(path)
            srv._Handler.do_GET(handler)
            assert handler.payload[0] == 403
            assert "triage role required" in handler.payload[1]["error"]
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_triage_role_can_read_triage_and_suppressions_api():
    import app_server as srv

    class DummyHandler:
        def __init__(self, path):
            self.path = path
            self.headers = {"Cookie": "ai_scanner_session=valid-session"}
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    orig_state = srv._operator_state
    original_sessions = _install_browser_session(srv)
    try:
        srv._operator_state = SingleUserState(
            SingleUserConfig(
                name="Analyst",
                expected_bitbucket_owner="",
                ctx=UserContext(
                    username="Analyst",
                    roles=(ROLE_VIEWER, ROLE_TRIAGE),
                    allowed_projects=("*",),
                ),
            )
        )
        with patch.object(srv, "list_suppressions", return_value=[{"hash": "h1"}]), \
             patch.object(srv, "list_triage", return_value=[{"hash": "h1", "status": "accepted_risk"}]):
            handler = DummyHandler("/api/suppressions")
            srv._Handler.do_GET(handler)
            assert handler.payload == (200, {"suppressions": [{"hash": "h1"}]})

            handler = DummyHandler("/api/triage")
            srv._Handler.do_GET(handler)
            assert handler.payload == (200, {"triage": [{"hash": "h1", "status": "accepted_risk"}]})
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_repos_for_project_skips_local_project_without_calling_bitbucket():
    import app_server as srv

    class DummyClient:
        def list_repos(self, project_key):
            raise AssertionError(f"should not query Bitbucket for {project_key}")

    orig_state = srv._operator_state
    try:
        srv._operator_state = SingleUserState(
            SingleUserConfig(
                name="Analyst",
                expected_bitbucket_owner="",
                ctx=UserContext(
                    username="Analyst",
                    roles=(ROLE_VIEWER, ROLE_SCANNER),
                    allowed_projects=("*",),
                ),
            )
        )
        srv._operator_state.client = DummyClient()
        assert srv._repos_for_project("LOCAL") == []
    finally:
        srv._operator_state = orig_state


def test_api_repos_returns_empty_for_local_project():
    import app_server as srv
    from urllib.parse import urlparse

    class DummyClient:
        def list_repos(self, project_key):
            raise AssertionError(f"should not query Bitbucket for {project_key}")

    class DummyHandler:
        def __init__(self):
            self.headers = {"Cookie": "ai_scanner_session=valid-session"}
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    orig_state = srv._operator_state
    original_sessions = _install_browser_session(srv)
    try:
        srv._operator_state = SingleUserState(
            SingleUserConfig(
                name="Analyst",
                expected_bitbucket_owner="",
                ctx=UserContext(
                    username="Analyst",
                    roles=(ROLE_VIEWER, ROLE_SCANNER),
                    allowed_projects=("*",),
                ),
            )
        )
        srv._operator_state.client = DummyClient()
        handler = DummyHandler()
        srv._Handler._api_repos_get(handler, urlparse("/api/repos?project=LOCAL"))
        assert handler.payload == (200, {"repos": []})
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_settings_save_writes_audit_record():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    orig_audit = srv.AUDIT_FILE
    orig_state = srv._operator_state
    orig_llm_cfg = Path(srv.LLM_CFG_FILE).read_text(encoding="utf-8")
    try:
        srv.OUTPUT_DIR = str(d)
        srv.HISTORY_FILE = str(d / "scan_history.json")
        srv.LOG_DIR = str(d / "logs")
        srv.DB_FILE = str(d / "scan_jobs.db")
        srv.AUDIT_FILE = str(d / "audit_events.jsonl")
        srv._sync_scan_service_paths()
        srv._operator_state = SingleUserState(
            SingleUserConfig(
                name="Admin",
                expected_bitbucket_owner="",
                ctx=UserContext(
                    username="Admin",
                    roles=(ROLE_ADMIN,),
                    allowed_projects=("*",),
                ),
            )
        )
        handler = DummyHandler()
        srv._Handler._api_settings_save(
            handler,
            {"llm_url": "http://localhost:11434", "llm_model": "demo-model"},
        )

        lines = Path(srv.AUDIT_FILE).read_text(encoding="utf-8").strip().splitlines()
        assert handler.payload[0] == 200
        assert any("settings_llm_update" in line for line in lines)
        assert any('"actor": "Admin"' in line for line in lines)
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv.AUDIT_FILE = orig_audit
        srv._operator_state = orig_state
        Path(srv.LLM_CFG_FILE).write_text(orig_llm_cfg, encoding="utf-8")
        srv._sync_scan_service_paths()


def test_api_finding_triage_marks_sent_for_review_and_reset_clears_it():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    orig_sup = srv.SUPPRESSIONS_FILE
    orig_session = srv._session
    orig_state = srv._operator_state
    srv.OUTPUT_DIR = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR = str(d / "logs")
    srv.DB_FILE = str(d / "scan_jobs.db")
    srv.SUPPRESSIONS_FILE = str(d / "ai_scanner_suppressions.json")
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Security Engineer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Security Engineer",
                roles=(ROLE_VIEWER, ROLE_SCANNER, ROLE_ADMIN, ROLE_TRIAGE),
                allowed_projects=("*",),
            ),
        )
    )
    srv._invalidate_history_cache()

    try:
        session = srv.ScanSession()
        finding = {
            "_hash": "hash-2",
            "repo": "repo1",
            "file": "service.py",
            "line": 21,
            "severity": 3,
            "capability": "LLM Orchestration",
            "description": "Detected orchestration usage",
        }
        session.scan_id = "20250316_060606"
        session.project_key = "TEST"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.findings = [finding]
        session.per_repo = {"repo1": [finding]}
        srv._session = session

        handler = DummyHandler()
        srv._Handler._api_finding_triage(
            handler,
            {"hash": "hash-2", "status": TRIAGE_SENT_FOR_REVIEW, "note": "Shared with repo owner"},
        )

        assert handler.payload[0] == 200
        assert srv._session.findings[0]["triage_status"] == TRIAGE_SENT_FOR_REVIEW
        assert srv._session.findings[0]["triage_note"] == "Shared with repo owner"
        assert any(rec["hash"] == "hash-2" and rec["status"] == TRIAGE_SENT_FOR_REVIEW for rec in list_triage(srv.SUPPRESSIONS_FILE))

        srv._Handler._api_finding_reset(handler, {"hash": "hash-2"})

        assert handler.payload[0] == 200
        assert "triage_status" not in srv._session.findings[0]
        assert all(rec["hash"] != "hash-2" for rec in list_triage(srv.SUPPRESSIONS_FILE))
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv.SUPPRESSIONS_FILE = orig_sup
        srv._session = orig_session
        srv._operator_state = orig_state
        srv._invalidate_history_cache()


def test_page_finding_triage_redirects_back_to_findings_and_ignores_none_scan_id():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.redirect_to = None
            self.headers = {"Referer": "http://127.0.0.1:5757/findings?scan_id=None"}

        def _redirect(self, location):
            self.redirect_to = location

        def _render_scan_page(self, error=""):
            raise AssertionError(f"unexpected render_scan_page: {error}")

    d = Path(tempfile.mkdtemp())
    orig_sup = srv.SUPPRESSIONS_FILE
    orig_session = srv._session
    orig_state = srv._operator_state
    srv.SUPPRESSIONS_FILE = str(d / "ai_scanner_suppressions.json")
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Security Engineer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Security Engineer",
                roles=(ROLE_VIEWER, ROLE_SCANNER, ROLE_ADMIN, ROLE_TRIAGE),
                allowed_projects=("*",),
            ),
        )
    )

    try:
        session = srv.ScanSession()
        finding = {
            "_hash": "hash-r1",
            "repo": "repo1",
            "file": "service.py",
            "line": 21,
            "severity": 3,
            "capability": "LLM Orchestration",
            "description": "Detected orchestration usage",
        }
        session.scan_id = "20250316_060606"
        session.project_key = "TEST"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.findings = [finding]
        session.per_repo = {"repo1": [finding]}
        srv._session = session

        handler = DummyHandler()
        srv._Handler._page_finding_triage(handler, {"hash": "hash-r1", "status": TRIAGE_SENT_FOR_REVIEW, "note": ""})

        assert handler.redirect_to == "/findings?notice=Finding+triage+updated"
    finally:
        srv.SUPPRESSIONS_FILE = orig_sup
        srv._session = orig_session
        srv._operator_state = orig_state


def test_page_finding_triage_redirects_back_to_findings_for_all_statuses():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.redirect_to = None
            self.headers = {"Referer": "http://127.0.0.1:5757/findings?scan_id=20250316_060606"}

        def _redirect(self, location):
            self.redirect_to = location

        def _render_scan_page(self, error=""):
            raise AssertionError(f"unexpected render_scan_page: {error}")

    d = Path(tempfile.mkdtemp())
    orig_sup = srv.SUPPRESSIONS_FILE
    orig_session = srv._session
    orig_state = srv._operator_state
    srv.SUPPRESSIONS_FILE = str(d / "ai_scanner_suppressions.json")
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Security Engineer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Security Engineer",
                roles=(ROLE_VIEWER, ROLE_SCANNER, ROLE_ADMIN, ROLE_TRIAGE),
                allowed_projects=("*",),
            ),
        )
    )

    try:
        session = srv.ScanSession()
        finding = {
            "_hash": "hash-r2",
            "repo": "repo1",
            "file": "service.py",
            "line": 22,
            "severity": 2,
            "capability": "LLM Orchestration",
            "description": "Detected orchestration usage",
        }
        session.scan_id = "20250316_060606"
        session.project_key = "TEST"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.findings = [finding]
        session.per_repo = {"repo1": [finding]}
        srv._session = session

        for status, note in [
            (TRIAGE_SENT_FOR_REVIEW, ""),
            (TRIAGE_IN_REMEDIATION, ""),
            (TRIAGE_ACCEPTED_RISK, "known limitation"),
            (TRIAGE_FALSE_POSITIVE, "test fixture"),
        ]:
            handler = DummyHandler()
            srv._Handler._page_finding_triage(handler, {"hash": "hash-r2", "status": status, "note": note})
            parsed = urllib.parse.urlparse(handler.redirect_to)
            params = urllib.parse.parse_qs(parsed.query)
            assert parsed.path == "/findings"
            assert params == {"scan_id": ["20250316_060606"], "notice": ["Finding triage updated"]}
    finally:
        srv.SUPPRESSIONS_FILE = orig_sup
        srv._session = orig_session
        srv._operator_state = orig_state


def test_page_finding_reset_redirects_back_to_findings():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.redirect_to = None
            self.headers = {"Referer": "http://127.0.0.1:5757/findings?scan_id=20250316_060606"}

        def _redirect(self, location):
            self.redirect_to = location

    d = Path(tempfile.mkdtemp())
    orig_sup = srv.SUPPRESSIONS_FILE
    orig_session = srv._session
    orig_state = srv._operator_state
    srv.SUPPRESSIONS_FILE = str(d / "ai_scanner_suppressions.json")
    srv._operator_state = SingleUserState(
        SingleUserConfig(
            name="Security Engineer",
            expected_bitbucket_owner="",
            ctx=UserContext(
                username="Security Engineer",
                roles=(ROLE_VIEWER, ROLE_SCANNER, ROLE_ADMIN, ROLE_TRIAGE),
                allowed_projects=("*",),
            ),
        )
    )

    try:
        session = srv.ScanSession()
        finding = {
            "_hash": "hash-r3",
            "repo": "repo1",
            "file": "service.py",
            "line": 23,
            "severity": 2,
            "provider_or_lib": "demo_rule",
            "description": "Detected issue",
        }
        session.scan_id = "20250316_060606"
        session.project_key = "TEST"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.findings = [finding]
        srv._session = session
        upsert_triage(srv.SUPPRESSIONS_FILE, finding, status=TRIAGE_IN_REMEDIATION, note="", marked_by="analyst")

        handler = DummyHandler()
        srv._Handler._page_finding_reset(handler, {"hash": "hash-r3"})

        parsed = urllib.parse.urlparse(handler.redirect_to)
        params = urllib.parse.parse_qs(parsed.query)
        assert parsed.path == "/findings"
        assert params == {"scan_id": ["20250316_060606"], "notice": ["Finding triage reset"]}
    finally:
        srv.SUPPRESSIONS_FILE = orig_sup
        srv._session = orig_session
        srv._operator_state = orig_state


def test_page_findings_generate_html_exports_whole_scan_when_scan_action_sends_no_hashes():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.redirect_to = None
            self.headers = {"Cookie": "ai_scanner_session=valid-session"}

        def _redirect(self, location):
            self.redirect_to = location

    orig_state = srv._operator_state
    original_sessions = _install_browser_session(srv)
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

    record = {
        "scan_id": "20250316_070707",
        "project_key": "COGI",
        "repo_slugs": ["repo1"],
        "findings": [{"_hash": "hash-a"}, {"_hash": "hash-b"}],
    }
    built_findings = [
        {"hash": "hash-a", "repo": "repo1", "project_key": "COGI"},
        {"hash": "hash-b", "repo": "repo1", "project_key": "COGI"},
    ]

    try:
        handler = DummyHandler()
        with patch.object(srv, "_scan_record_for_id", return_value=record), \
             patch.object(srv, "build_scan_findings", return_value=built_findings), \
             patch.object(srv, "_triage_by_hash", return_value={}), \
             patch.object(srv, "_require_role", return_value=False), \
             patch.object(srv, "_generate_selected_findings_artifact", return_value="selected.csv") as export_mock:
            srv._Handler._page_findings_generate_html(handler, {"scan_id": "20250316_070707", "export_type": "csv"})

        export_mock.assert_called_once()
        selected = export_mock.call_args.kwargs["findings"] if "findings" in export_mock.call_args.kwargs else export_mock.call_args.args[0]
        assert len(selected) == 2
        assert handler.redirect_to == "/reports/selected.csv"
    finally:
        srv._browser_sessions.clear()
        srv._browser_sessions.update(original_sessions)
        srv._operator_state = orig_state


def test_handle_page_get_redirects_legacy_findings_path_to_query_form():
    import app_server as srv
    from urllib.parse import urlparse

    class DummyHandler:
        def __init__(self):
            self.redirect_to = None

        def _require_browser_session(self):
            return False

        def _redirect(self, location):
            self.redirect_to = location

    orig_is_connected = srv._is_connected
    try:
        srv._is_connected = lambda: True

        handler = DummyHandler()
        parsed = urlparse("/findings/None")
        handled = srv._Handler._handle_page_get(handler, parsed)

        assert handled is True
        assert handler.redirect_to == "/findings"

        handler = DummyHandler()
        parsed = urlparse("/findings/20250316_060606")
        handled = srv._Handler._handle_page_get(handler, parsed)

        assert handled is True
        assert handler.redirect_to == "/findings?scan_id=20250316_060606"
    finally:
        srv._is_connected = orig_is_connected


def test_serve_report_uses_stored_history_artifact_path_when_output_dir_changes(tmp_path):
    import app_server as srv

    old_output = tmp_path / "old-output"
    new_output = tmp_path / "new-output"
    old_output.mkdir()
    new_output.mkdir()
    html_path = old_output / "scan.html"
    html_path.write_text("<html>old report</html>", encoding="utf-8")

    class DummyHandler:
        def __init__(self):
            self.sent = None
            self.errors = []

        def _send(self, status, content_type, body):
            self.sent = (status, content_type, body)

        def _err(self, status, msg):
            self.errors.append((status, msg))
            return None

        def _404(self):
            self.errors.append((404, "not found"))
            return None

    orig_out = srv.OUTPUT_DIR
    try:
        srv.OUTPUT_DIR = str(new_output)
        record = {
            "scan_id": "20260323_120000",
            "project_key": "COGI",
            "reports": {"__all__": {"html": str(html_path), "html_name": html_path.name}},
        }
        handler = DummyHandler()
        with patch.object(srv, "_find_history_record_by_report_name", return_value=record):
            srv._Handler._serve_report(handler, "scan.html")

        assert handler.sent[0] == 200
        assert handler.sent[1] == "text/html; charset=utf-8"
        assert b"old report" in handler.sent[2]
        assert handler.errors == []
    finally:
        srv.OUTPUT_DIR = orig_out


def test_cleanup_stale_temp_clones_removes_leftovers():
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_temp = srv.TEMP_DIR
    stale_dir = d / "scan_stale-run"
    stale_dir.mkdir(parents=True)
    (stale_dir / "keep.txt").write_text("leftover")
    active_dir = d / "scan_active-run"
    active_dir.mkdir(parents=True)
    (active_dir / "keep.txt").write_text("fresh")
    stale_age = time.time() - (7 * 60 * 60)
    os.utime(stale_dir, (stale_age, stale_age))
    os.utime(stale_dir / "keep.txt", (stale_age, stale_age))

    try:
        srv.TEMP_DIR = str(d)
        srv._cleanup_stale_temp_clones()

        assert not stale_dir.exists()
        assert active_dir.exists()
    finally:
        srv.TEMP_DIR = orig_temp


def test_shallow_clone_cleans_partial_destination_on_failure():
    from scanner.bitbucket import shallow_clone

    class FakeProc:
        def __init__(self, dest_path: Path):
            self.returncode = 128
            self.stdout = None
            self.stderr = MagicMock()
            self.stderr.read.return_value = "fatal: clone failed"
            dest_path.mkdir(parents=True, exist_ok=True)
            (dest_path / ".git").mkdir(exist_ok=True)

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            return None

    d = Path(tempfile.mkdtemp())
    dest = d / "partial-clone"

    with patch("scanner.bitbucket.subprocess.Popen", return_value=FakeProc(dest)):
        try:
            shallow_clone("https://example.invalid/repo.git", dest)
            assert False, "Expected shallow_clone to raise RuntimeError"
        except RuntimeError:
            pass

    assert not dest.exists(), "Partial clone directory should be cleaned up after failure"


def test_get_clone_url_does_not_embed_credentials():
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient("https://bitbucket.example", token="pat-123", username="alice")
    client._get = lambda *_args, **_kwargs: {
        "links": {
            "clone": [
                {"name": "http", "href": "https://bitbucket.example/scm/proj/repo.git"}
            ]
        }
    }

    clone_url = client.get_clone_url("PROJ", "repo")

    assert clone_url == "https://bitbucket.example/scm/proj/repo.git"
    assert "pat-123" not in clone_url
    assert "alice@" not in clone_url


def test_repo_metadata_cache_reuses_bitbucket_responses():
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient("https://bitbucket.example", token="pat-123")
    calls = []

    def fake_get(url, params=None):
        calls.append((url, tuple(sorted((params or {}).items()))))
        if url.endswith("/repos/repo1"):
            return {"links": {"clone": [{"name": "http", "href": "https://bitbucket.example/scm/proj/repo1.git"}]}}
        if url.endswith("/default-branch"):
            return {"displayId": "main"}
        if url.endswith("/commits"):
            return {"values": [{"author": {"displayName": "Owner"}}]}
        raise AssertionError(f"Unexpected URL: {url}")

    with patch.object(client, "_get", side_effect=fake_get):
        first = client.get_repo_metadata("PROJ", "repo1")
        second = client.get_repo_metadata("PROJ", "repo1")
        branch = client.get_default_branch("PROJ", "repo1")
        owner = client.get_repo_owner("PROJ", "repo1")
        clone_url = client.get_clone_url("PROJ", "repo1")

    assert first == second
    assert branch == "main"
    assert owner == "Owner"
    assert clone_url == "https://bitbucket.example/scm/proj/repo1.git"
    assert len(calls) == 3


def test_build_git_auth_env_uses_header_not_url():
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient("https://bitbucket.example", token="pat-123", username="alice")

    env = client.build_git_auth_env()

    expected = base64.b64encode(b"alice:pat-123").decode("ascii")
    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {expected}"


def test_bitbucket_owner_fallbacks_use_user_label():
    from requests import RequestException
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient("https://bitbucket.example", token="pat-123")
    with patch.object(client, "_get", side_effect=RequestException("offline")):
        assert client.get_pat_owner() == "User"
        assert client.get_repo_owner("COGI", "repo1") == "User"

    state = SingleUserState(
        SingleUserConfig(
            name="Demo User",
            expected_bitbucket_owner="",
            ctx=UserContext(username="Demo User", roles=(ROLE_VIEWER,), allowed_projects=("*",)),
        )
    )
    assert state.connected_owner == "User"
    state.connect(client=object(), owner="", projects=[])
    assert state.connected_owner == "User"


def test_get_pat_owner_falls_back_cleanly_when_myself_endpoint_returns_404():
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient("https://bitbucket.example", token="pat-123")

    class _Resp:
        def __init__(self, status_code, *, payload=None, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            if self._payload is None:
                raise ValueError("no json")
            return self._payload

    calls = []

    def fake_get(url, timeout=0, params=None):
        calls.append(url)
        if url.endswith("/rest/api/1.0/users/myself"):
            return _Resp(404)
        if url.endswith("/plugins/servlet/applinks/whoami"):
            return _Resp(200, text="Segal, Sarit")
        raise AssertionError(f"Unexpected URL: {url}")

    with patch.object(client.session, "get", side_effect=fake_get):
        assert client.get_pat_owner() == "Segal, Sarit"
    assert len(calls) == 2


def test_get_pat_owner_skips_non_json_myself_response_without_parsing_error():
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient("https://bitbucket.example", token="pat-123")

    class _Resp:
        def __init__(self, status_code, *, payload=None, text="", headers=None):
            self.status_code = status_code
            self._payload = payload
            self.text = text
            self.headers = headers or {}

        def json(self):
            if self._payload is None:
                raise AssertionError("json() should not be called for non-JSON owner response")
            return self._payload

    calls = []

    def fake_get(url, timeout=0, params=None):
        calls.append(url)
        if url.endswith("/rest/api/1.0/users/myself"):
            return _Resp(200, text="", headers={"Content-Type": "text/html"})
        if url.endswith("/plugins/servlet/applinks/whoami"):
            return _Resp(200, text="Segal, Sarit")
        raise AssertionError(f"Unexpected URL: {url}")

    with patch.object(client.session, "get", side_effect=fake_get):
        assert client.get_pat_owner() == "Segal, Sarit"
    assert len(calls) == 2


def test_get_pat_owner_swallows_requests_jsondecodeerror_and_falls_back():
    from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient("https://bitbucket.example", token="pat-123")

    class _Resp:
        def __init__(self, status_code, *, text="", headers=None):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}

        def json(self):
            raise RequestsJSONDecodeError("Expecting value", "", 0)

    calls = []

    def fake_get(url, timeout=0, params=None):
        calls.append(url)
        if url.endswith("/rest/api/1.0/users/myself"):
            return _Resp(200, text="{broken", headers={"Content-Type": "application/json"})
        if url.endswith("/plugins/servlet/applinks/whoami"):
            return type("WhoAmIResp", (), {"status_code": 200, "text": "Segal, Sarit", "headers": {}})()
        raise AssertionError(f"Unexpected URL: {url}")

    with patch.object(client.session, "get", side_effect=fake_get):
        assert client.get_pat_owner() == "Segal, Sarit"
    assert len(calls) == 2


def test_delete_pat_skips_delete_call_when_no_stored_value():
    from scanner import pat_store

    class FakeKeyring:
        def __init__(self):
            self.delete_calls = 0

        def get_password(self, service, username):
            return ""

        def delete_password(self, service, username):
            self.delete_calls += 1
            raise AssertionError("delete_password should not be called when nothing is stored")

    fake = FakeKeyring()
    with patch.object(pat_store, "_get_keyring", return_value=fake):
        assert pat_store.delete_pat() is True
    assert fake.delete_calls == 0


def test_load_owner_map_returns_empty_when_file_is_missing():
    import app_server as srv

    missing = Path(tempfile.mkdtemp()) / "owner_map.json"
    assert srv.load_owner_map(str(missing)) == {}


def test_bitbucket_client_uses_ca_bundle_for_tls_verification():
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient(
        "https://bitbucket.example",
        token="pat-123",
        verify_ssl=True,
        ca_bundle="C:\\corp-ca.pem",
    )

    assert client.verify_ssl is True
    assert client.ca_bundle == "C:\\corp-ca.pem"
    assert client.session.verify == "C:\\corp-ca.pem"


def test_shallow_clone_sets_git_cainfo_when_ca_bundle_is_provided():
    from scanner.bitbucket import shallow_clone

    captured = {}

    class FakeProc:
        def __init__(self):
            self.returncode = 0
            self.stdout = None
            self.stderr = None

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            return None

    def fake_popen(cmd, stdout=None, stderr=None, text=None, env=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return FakeProc()

    d = Path(tempfile.mkdtemp())
    dest = d / "clone-target"

    with patch("scanner.bitbucket.subprocess.Popen", side_effect=fake_popen):
        shallow_clone(
            "https://example.invalid/repo.git",
            dest,
            verify_ssl=True,
            ca_bundle="C:\\corp-ca.pem",
        )

    assert "http.sslVerify=false" not in " ".join(captured["cmd"])
    assert captured["env"]["GIT_SSL_CAINFO"] == "C:\\corp-ca.pem"
    assert "GIT_SSL_NO_VERIFY" not in captured["env"]


def test_shallow_clone_polls_without_timeoutexpired_control_flow():
    from scanner.bitbucket import shallow_clone

    dest = Path(tempfile.mkdtemp()) / "repo"

    class FakeProc:
        def __init__(self):
            self.returncode = 0
            self.stdout = None
            self.stderr = MagicMock()
            self.poll_calls = 0

        def poll(self):
            self.poll_calls += 1
            return 0 if self.poll_calls >= 3 else None

        def wait(self):
            return 0

    fake_proc = FakeProc()

    with patch("scanner.bitbucket.subprocess.Popen", return_value=fake_proc), \
         patch("scanner.bitbucket.time.sleep", return_value=None):
        shallow_clone("https://example.invalid/repo.git", dest)

    assert fake_proc.poll_calls >= 3


def test_load_history_merges_sqlite_and_legacy_records():
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    srv.OUTPUT_DIR = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR = str(d / "logs")
    srv.DB_FILE = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        legacy_record = {
            "scan_id": "20250315_000001",
            "project": "LEGACY",
            "state": "done",
            "repos": ["legacy-repo"],
            "reports": {},
        }
        Path(srv.HISTORY_FILE).write_text(json.dumps([legacy_record]), encoding="utf-8")

        session = srv.ScanSession()
        session.scan_id = "20250316_000002"
        session.project_key = "DB"
        session.repo_slugs = ["repo1"]
        session.state = "done"
        session.llm_model = "test-model"
        session.llm_model_info = {"name": "test-model"}
        srv._save_history_record(session, [])

        history = srv._load_history()

        assert {r["scan_id"] for r in history} == {"20250315_000001", "20250316_000002"}
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv._invalidate_history_cache()


def test_api_history_delete_refuses_unmanaged_paths():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    d = Path(tempfile.mkdtemp())
    outside = Path(tempfile.mkdtemp()) / "outside-report.html"
    outside.write_text("do not delete", encoding="utf-8")

    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    srv.OUTPUT_DIR = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR = str(d / "logs")
    srv.DB_FILE = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        handler = DummyHandler()
        record = {
            "scan_id": "20250317_000003",
            "project_key": "COGI",
            "repo_slugs": ["repo1"],
            "reports": {"__all__": {"html": str(outside)}},
            "log_file": "",
        }
        with patch.object(srv, "_load_history", return_value=[record]), patch.object(srv, "_delete_history") as delete_mock:
            srv._Handler._api_history_delete(handler, {"scan_ids": ["20250317_000003"]})

        assert handler.payload[0] == 200
        assert outside.exists()
        assert "refused to delete unmanaged path" in handler.payload[1]["errors"][0]
        delete_mock.assert_called_once_with(["20250317_000003"])
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv._invalidate_history_cache()


def test_api_history_delete_removes_all_generated_artifacts():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    d = Path(tempfile.mkdtemp())
    logs_dir = d / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    html = d / "ai_scan_report.html"
    csv = d / "ai_scan_report.csv"
    json_report = d / "ai_scan_report.json"
    log_file = logs_dir / "20250317_000004.txt"
    llm_debug_log = logs_dir / "20250317_000004_llm_debug.log"
    for path in (html, csv, json_report, log_file, llm_debug_log):
        path.write_text("artifact", encoding="utf-8")

    orig_out = srv.OUTPUT_DIR
    orig_hist = srv.HISTORY_FILE
    orig_log = srv.LOG_DIR
    orig_db = srv.DB_FILE
    srv.OUTPUT_DIR = str(d)
    srv.HISTORY_FILE = str(d / "scan_history.json")
    srv.LOG_DIR = str(logs_dir)
    srv.DB_FILE = str(d / "scan_jobs.db")
    srv._invalidate_history_cache()

    try:
        handler = DummyHandler()
        record = {
            "scan_id": "20250317_000004",
            "project_key": "COGI",
            "repo_slugs": ["repo1"],
            "reports": {
                "__all__": {
                    "html": str(html),
                    "csv": str(csv),
                    "json": str(json_report),
                }
            },
            "log_file": str(log_file),
            "llm_debug_log_file": str(llm_debug_log),
        }
        with patch.object(srv, "_load_history", return_value=[record]), patch.object(srv, "_delete_history") as delete_mock:
            srv._Handler._api_history_delete(handler, {"scan_ids": ["20250317_000004"]})

        assert handler.payload[0] == 200
        assert handler.payload[1]["errors"] == []
        assert not html.exists()
        assert not csv.exists()
        assert not json_report.exists()
        assert not log_file.exists()
        assert not llm_debug_log.exists()
        delete_mock.assert_called_once_with(["20250317_000004"])
    finally:
        srv.OUTPUT_DIR = orig_out
        srv.HISTORY_FILE = orig_hist
        srv.LOG_DIR = orig_log
        srv.DB_FILE = orig_db
        srv._invalidate_history_cache()


def test_stop_active_scan_kills_processes_and_marks_stopped():
    import app_server as srv

    class FakeProc:
        def __init__(self):
            self.killed = False

        def kill(self):
            self.killed = True

    class FakePool:
        def __init__(self):
            self.shutdown_calls = []

        def shutdown(self, wait=False, cancel_futures=False):
            self.shutdown_calls.append((wait, cancel_futures))

    orig_session = srv._session
    session = srv.ScanSession()
    session.state = "running"
    proc = FakeProc()
    pool = FakePool()
    session.proc_holder = [proc]
    session._active_pool = pool

    try:
        srv._session = session
        assert srv._stop_active_scan() is True
        assert session.state == "stopped"
        assert proc.killed is True
        assert pool.shutdown_calls == [(False, True)]
        assert session.proc_holder == []
    finally:
        srv._session = orig_session


def test_request_app_shutdown_sets_exit_event_and_stops_server():
    import app_server as srv

    class FakeServer:
        def __init__(self):
            self.shutdown_called = threading.Event()

        def shutdown(self):
            self.shutdown_called.set()

    orig_server = srv._server_instance
    srv._server_instance = FakeServer()
    srv._app_exit_event.clear()

    try:
        srv._request_app_shutdown()
        assert srv.wait_for_exit(0.5) is True
        assert srv._server_instance.shutdown_called.wait(0.5) is True
    finally:
        srv._server_instance = orig_server
        srv._app_exit_event.clear()


def test_api_history_delete_clears_matching_stopped_current_session():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

    handler = DummyHandler()
    orig_session = srv._session
    session = srv.ScanSession()
    session.scan_id = "20250317_999999"
    session.project_key = "LOCAL"
    session.repo_slugs = ["repo1"]
    session.state = "stopped"
    try:
        srv._replace_current_session(session)
        with patch.object(srv, "_load_history", return_value=[{
            "scan_id": "20250317_999999",
            "project_key": "LOCAL",
            "repo_slugs": ["repo1"],
            "state": "stopped",
            "reports": {"__all__": {}},
            "log_file": "",
        }]), patch.object(srv, "_delete_history") as delete_mock:
            srv._Handler._api_history_delete(handler, {"scan_ids": ["20250317_999999"]})

        assert handler.payload[0] == 200
        assert handler.payload[1]["deleted"] == ["20250317_999999"]
        delete_mock.assert_called_once_with(["20250317_999999"])
        assert srv._current_session().scan_id == ""
        assert srv._current_session().state == "idle"
    finally:
        srv._replace_current_session(orig_session)


def test_start_attempts_to_boot_ollama_before_opening_browser():
    import app_server as srv

    class FakeServer:
        def serve_forever(self):
            return None

    opened = []
    orig_server_instance = srv._server_instance
    try:
        with patch.object(srv.http.server, "ThreadingHTTPServer", return_value=FakeServer()), \
             patch.object(srv, "_cleanup_stale_temp_clones"), \
             patch.object(srv, "_legacy_runtime_artifacts", return_value=[]), \
             patch.object(srv, "_startup_ensure_ollama") as ollama_boot, \
             patch.object(srv.webbrowser, "open", side_effect=lambda url: opened.append(url)), \
             patch.object(srv.threading, "Timer", side_effect=lambda _delay, fn: type("ImmediateTimer", (), {"start": staticmethod(fn)})()):
            srv.start(open_browser=True)

        ollama_boot.assert_called_once_with()
        assert opened and opened[0].startswith("http://127.0.0.1:")
    finally:
        srv._server_instance = orig_server_instance


def test_page_app_exit_returns_shutdown_fallback_page():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.sent = None

        def _send(self, status, ct, body):
            self.sent = (status, ct, body)

    handler = DummyHandler()
    orig_request_shutdown = srv._request_app_shutdown
    orig_require_role = srv._require_role
    try:
        srv._request_app_shutdown = lambda: None
        srv._require_role = lambda _handler, _role: False
        srv._Handler._page_app_exit(handler)
        assert handler.sent[0] == 200
        html = handler.sent[2].decode("utf-8")
        assert "PhantomLM stopped" in html
        assert "Trying to close this tab..." in html
        assert "window.close()" in html
        assert "You can close this tab" in html
    finally:
        srv._request_app_shutdown = orig_request_shutdown
        srv._require_role = orig_require_role


def test_api_app_exit_returns_before_shutdown():
    import app_server as srv

    class DummyHandler:
        def __init__(self):
            self.calls = []

        def _json(self, data, status=200):
            self.calls.append(("json", status, data))

    handler = DummyHandler()
    orig_request_shutdown = srv._request_app_shutdown
    orig_require_role = srv._require_role
    try:
        srv._request_app_shutdown = lambda: handler.calls.append(("shutdown",))
        srv._require_role = lambda _handler, _role: False
        srv._Handler._api_app_exit(handler)
        assert handler.calls == [
            ("json", 200, {"ok": True, "message": "Shutting down"}),
            ("shutdown",),
        ]
    finally:
        srv._request_app_shutdown = orig_request_shutdown
        srv._require_role = orig_require_role


def test_json_reporter_writes_meta_and_findings(tmp_path):
    from reports.json_report import JSONReporter

    path = JSONReporter(str(tmp_path), "scan-demo").write_json(
        [{"_hash": "hash-1", "repo": "repo1", "description": "demo"}],
        meta={"scan_id": "scan-demo", "tool_version": "19.1"},
    )
    payload = json.loads(Path(path).read_text(encoding="utf-8"))

    assert payload["scan_id"] == "scan-demo"
    assert payload["finding_count"] == 1
    assert payload["meta"]["tool_version"] == "19.1"
    assert payload["findings"][0]["_hash"] == "hash-1"


def test_scan_cli_reports_json_and_csv_paths(tmp_path, capsys, monkeypatch):
    import scan_cli

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def fake_run_scan(self, session, client=None, save_history_record=None):
        session.state = "done"
        session.findings = [{"_hash": "hash-1"}]
        session.report_paths = {
            "__all__": {
                "csv": str(tmp_path / "scan.csv"),
                "json": str(tmp_path / "scan.json"),
            }
        }
        session.log("CLI run complete")

    monkeypatch.setattr(scan_cli.ScanJobService, "run_scan", fake_run_scan)
    monkeypatch.setattr(sys, "argv", ["scan_cli.py", str(repo_dir), "--output-dir", str(tmp_path)])

    rc = scan_cli.main()
    out = capsys.readouterr().out

    assert rc == 0
    assert "JSON report" in out
    assert (tmp_path / "logs").exists()


def test_scan_cli_supports_bitbucket_project_repo_mode(tmp_path, capsys, monkeypatch):
    import scan_cli

    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = dict(kwargs)

    def fake_run_scan(self, session, client=None, save_history_record=None):
        captured["project_key"] = session.project_key
        captured["repo_slugs"] = list(session.repo_slugs)
        captured["scan_source"] = session.scan_source
        captured["client_type"] = type(client).__name__
        session.state = "done"
        session.findings = []
        session.report_paths = {
            "__all__": {
                "csv": str(tmp_path / "scan.csv"),
                "json": str(tmp_path / "scan.json"),
            }
        }

    monkeypatch.setattr(scan_cli, "BitbucketClient", FakeClient)
    monkeypatch.setattr(scan_cli, "load_pat", lambda: "saved-token")
    monkeypatch.setattr(scan_cli.ScanJobService, "run_scan", fake_run_scan)
    monkeypatch.setattr(sys, "argv", ["scan_cli.py", "--project", "COGI", "--repo", "repo1", "--repo", "repo2", "--output-dir", str(tmp_path)])

    rc = scan_cli.main()
    out = capsys.readouterr().out

    assert rc == 0
    assert captured["project_key"] == "COGI"
    assert captured["repo_slugs"] == ["repo1", "repo2"]
    assert captured["scan_source"] == "bitbucket"
    assert captured["client_type"] == "FakeClient"
    assert captured["client_kwargs"]["token"] == "saved-token"
    assert "Scan mode    : bitbucket" in out


def test_sse_write_returns_false_on_client_disconnect():
    import app_server as srv

    class BrokenWriter:
        def write(self, _data):
            raise ConnectionAbortedError(10053, "connection aborted")

        def flush(self):
            raise AssertionError("flush should not run after write failure")

    handler = type("SSEHandler", (), {"wfile": BrokenWriter()})()

    assert srv._Handler._sse_write(handler, {"msg": "hello", "ts": 0, "level": "info"}) is False


def test_sse_stream_empty_queue_uses_keepalive_without_raising():
    import app_server as srv

    class Writer:
        def __init__(self):
            self.parts = []

        def write(self, data):
            self.parts.append(data)

        def flush(self):
            return None

    class DummyHandler:
        def __init__(self):
            self.wfile = Writer()

        def send_response(self, code):
            self.code = code

        def send_header(self, *_args):
            return None

        def end_headers(self):
            return None

        def _cors(self):
            return None

        _sse_write = srv._Handler._sse_write

    orig_snapshot = srv._current_session_snapshot
    try:
        session = srv.ScanSession()
        session.state = "done"
        session.log_lines = []
        srv._current_session_snapshot = lambda *args, **kwargs: {
            "session": session,
            "log_lines": [],
        }
        handler = DummyHandler()
        srv._Handler._sse_stream(handler)
        assert handler.code == 200
        assert any(part == b": keepalive\n\n" for part in handler.wfile.parts)
    finally:
        srv._current_session_snapshot = orig_snapshot


def test_sse_stream_swallows_client_disconnect_during_header_setup():
    import app_server as srv

    class DummyHandler:
        def send_response(self, _code):
            return None

        def send_header(self, _name, _value):
            raise ConnectionAbortedError(10053, "connection aborted")

        def _cors(self):
            return None

        def end_headers(self):
            raise AssertionError("end_headers should not run after send_header failure")

    srv._Handler._sse_stream(DummyHandler())


def test_sse_stream_swallows_client_disconnect_during_keepalive():
    import app_server as srv

    class BrokenWriter:
        def write(self, _data):
            raise ConnectionAbortedError(10053, "connection aborted")

        def flush(self):
            raise AssertionError("flush should not run after keepalive write failure")

    class DummyHandler:
        def __init__(self):
            self.wfile = BrokenWriter()

        def send_response(self, _code):
            return None

        def send_header(self, *_args):
            return None

        def end_headers(self):
            return None

        def _cors(self):
            return None

        _sse_write = srv._Handler._sse_write

    orig_snapshot = srv._current_session_snapshot
    try:
        session = srv.ScanSession()
        session.state = "running"
        session.log_lines = []
        srv._current_session_snapshot = lambda *args, **kwargs: {
            "session": session,
            "log_lines": [],
        }
        srv._Handler._sse_stream(DummyHandler())
    finally:
        srv._current_session_snapshot = orig_snapshot


def test_gpu_snapshot_returns_unavailable_when_nvidia_smi_hangs(monkeypatch):
    import app_server as srv

    class HangingProc:
        def __init__(self, *args, **kwargs):
            self.returncode = None
            self.killed = False

        def poll(self):
            return None if not self.killed else -9

        def kill(self):
            self.killed = True

        def communicate(self, timeout=None):
            return ("", "")

    monkeypatch.setattr(srv.os, "name", "nt")
    monkeypatch.setattr(srv.subprocess, "Popen", lambda *args, **kwargs: HangingProc())

    assert srv._gpu_snapshot() == "Unavailable"


def test_gpu_snapshot_returns_unavailable_when_communicate_times_out(monkeypatch):
    import app_server as srv

    class SlowCommunicateProc:
        def __init__(self, *args, **kwargs):
            self.returncode = 0

        def poll(self):
            return 0

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired(
                cmd=["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"],
                timeout=timeout or 0.2,
            )

    monkeypatch.setattr(srv.os, "name", "nt")
    monkeypatch.setattr(srv.subprocess, "Popen", lambda *args, **kwargs: SlowCommunicateProc())

    assert srv._gpu_snapshot() == "Unavailable"


def test_send_swallows_client_disconnects():
    import app_server as srv

    class BrokenWriter:
        def write(self, _data):
            raise ConnectionAbortedError(10053, "connection aborted")

    class DummyHandler:
        def __init__(self):
            self.wfile = BrokenWriter()

        def send_response(self, _status):
            pass

        def send_header(self, _name, _value):
            pass

        def _cors(self):
            pass

        def end_headers(self):
            pass

    handler = DummyHandler()

    srv._Handler._send(handler, 200, "text/plain", b"ok")
    assert handler.close_connection is True


def test_do_get_swallows_client_disconnect_from_api_json_write():
    import app_server as srv

    class DummyHandler:
        path = "/api/status"
        headers = {}

        def send_response(self, _status):
            return None

        def send_header(self, _name, _value):
            return None

        def _cors(self):
            return None

        def end_headers(self):
            return None

        @property
        def wfile(self):
            class BrokenWriter:
                def write(self, _data):
                    raise ConnectionAbortedError(10053, "connection aborted")
            return BrokenWriter()

        _send = srv._Handler._send
        _json = srv._Handler._json
        _404 = srv._Handler._404
        do_GET = srv._Handler.do_GET

    handler = DummyHandler()

    with patch.object(srv._Handler, "_handle_page_get", return_value=False), \
         patch.object(srv._Handler, "_handle_api_get", side_effect=lambda self, parsed: self._json({"ok": True}) or True):
        handler.do_GET()


def test_run_scan_with_no_repos_completes_cleanly():
    import app_server as srv

    session = srv.ScanSession()
    session.scan_id = "20250316_010101"
    session.project_key = "EMPTY"
    session.repo_slugs = []
    session.total = 0
    session.state = "running"

    with patch.object(srv, "_ollama_ping", return_value=False), \
         patch.object(srv._scan_service, "_ensure_ollama_running", return_value=(False, "unavailable")), \
         patch.object(srv, "_save_history_record", lambda session, findings: None):
        srv._run_scan(session)

    assert session.state == "done"
    assert session.findings == []
    assert session.repo_details == {}
    assert any(msg["msg"] == "  No findings - HTML report skipped." for msg in session.log_lines)
    report = dict((session.report_paths or {}).get("__all__", {}) or {})
    assert report.get("json_name", "").endswith(".json")
    assert all(ord(ch) < 128 for entry in session.log_lines for ch in entry["msg"])


def test_run_scan_logs_structured_metadata_fetch_errors():
    import app_server as srv
    from requests import RequestException

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_client = srv._operator_state.client
    try:
        srv.OUTPUT_DIR = str(d / "output")
        session = srv.ScanSession()
        session.scan_id = "20250316_020202"
        session.project_key = "COGI"
        session.repo_slugs = ["repo1"]
        session.total = 1
        session.state = "running"

        fake_client = MagicMock()
        fake_client.build_git_auth_env.return_value = {}
        fake_client.get_repo_metadata.side_effect = RequestException("bitbucket unavailable")
        srv._operator_state.client = fake_client

        def _fake_clone(_url, dest, **_kwargs):
            Path(dest).mkdir(parents=True, exist_ok=True)

        with patch.object(srv, "_ollama_ping", return_value=False), \
             patch.object(srv._scan_service, "_ensure_ollama_running", return_value=(False, "unavailable")), \
             patch.object(srv, "_save_history_record", lambda session, findings: None), \
             patch.object(srv._scan_service, "_git_head_commit", return_value="abc123"), \
             patch("scanner.bitbucket.shallow_clone", side_effect=_fake_clone), \
             patch("scanner.bitbucket.cleanup_clone", return_value=None), \
             patch("services.scan_jobs.AIUsageDetector.scan", return_value=[]):
            srv._run_scan(session)

        assert any("[META_FETCH] repo1: bitbucket unavailable" in entry["msg"] for entry in session.log_lines)
    finally:
        srv.OUTPUT_DIR = orig_out
        srv._operator_state.client = orig_client


def test_run_scan_defers_html_report_generation_until_requested():
    import app_server as srv

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_client = srv._operator_state.client
    try:
        srv.OUTPUT_DIR = str(d / "output")
        session = srv.ScanSession()
        session.scan_id = "20250316_030303"
        session.project_key = "COGI"
        session.repo_slugs = ["repo1"]
        session.total = 1
        session.state = "running"

        fake_client = MagicMock()
        fake_client.build_git_auth_env.return_value = {}
        fake_client.get_repo_metadata.return_value = {
            "branch": "main",
            "owner": "Owner",
            "clone_url": "https://example.invalid/repo1.git",
        }
        srv._operator_state.client = fake_client

        finding = {
            **make_finding(),
            "repo": "repo1",
            "file": "app.py",
            "line": 10,
            "_hash": "hash-report",
            "severity": 2,
            "severity_label": "High",
            "risk": "High",
            "context": "production",
            "product_house": "",
            "match": "import openai",
            "description": "Test finding",
            "last_seen": "20250316_030303",
            "is_notebook": False,
        }

        def _fake_clone(_url, dest, **_kwargs):
            dest_path = Path(dest)
            dest_path.mkdir(parents=True, exist_ok=True)
            (dest_path / "app.py").write_text("import openai\n", encoding="utf-8")

        with patch.object(srv, "_ollama_ping", return_value=False), \
             patch.object(srv._scan_service, "_ensure_ollama_running", return_value=(False, "unavailable")), \
             patch.object(srv, "_save_history_record", lambda session, findings: None), \
             patch.object(srv._scan_service, "_git_head_commit", return_value="abc123"), \
             patch("scanner.bitbucket.shallow_clone", side_effect=_fake_clone), \
             patch("scanner.bitbucket.cleanup_clone", return_value=None), \
             patch("services.scan_jobs.AIUsageDetector.scan", return_value=[finding]), \
             patch("services.scan_jobs.SecurityAnalyzer.analyze", side_effect=lambda self, rows: rows), \
             patch("services.scan_jobs.Aggregator.process", return_value=[finding]):
            srv._run_scan(session)

        assert any("HTML report deferred until requested from the Findings page." in entry["msg"] for entry in session.log_lines)
        assert not any("Writing CSV report..." in entry["msg"] for entry in session.log_lines)
        assert not any("Writing HTML report" in entry["msg"] for entry in session.log_lines)
    finally:
        srv.OUTPUT_DIR = orig_out
        srv._operator_state.client = orig_client


def test_run_scan_attempts_to_start_ollama_before_disabling_llm():
    import app_server as srv

    session = srv.ScanSession()
    session.scan_id = "20250316_040404"
    session.project_key = "EMPTY"
    session.repo_slugs = []
    session.total = 0
    session.state = "running"

    with patch.object(srv._scan_service, "_ollama_ping", side_effect=[False, True]), \
         patch.object(srv._scan_service, "_ensure_ollama_running", side_effect=lambda url, log_fn=None: (log_fn("  [LLM] Ollama not running - starting `ollama serve`..."), log_fn("  [LLM] Ollama started"), (True, "started"))[-1]) as ensure_mock, \
         patch("scanner.llm_reviewer.LLMReviewer.model_info", return_value={"name": session.llm_model}), \
         patch.object(srv, "_save_history_record", lambda session, findings: None):
        srv._run_scan(session)

    ensure_mock.assert_called_once()
    assert any("starting `ollama serve`" in entry["msg"] for entry in session.log_lines)
    assert any("LLM      :" in entry["msg"] for entry in session.log_lines)
    assert not any("running without LLM review" in entry["msg"] for entry in session.log_lines)


def test_run_scan_keeps_completed_findings_when_stop_is_requested_before_future_is_collected():
    import app_server as srv
    import concurrent.futures

    d = Path(tempfile.mkdtemp())
    orig_out = srv.OUTPUT_DIR
    orig_client = srv._operator_state.client
    try:
        srv.OUTPUT_DIR = str(d / "output")
        session = srv.ScanSession()
        session.scan_id = "20250316_050505"
        session.project_key = "COGI"
        session.repo_slugs = ["repo1"]
        session.total = 1
        session.state = "running"

        fake_client = MagicMock()
        fake_client.build_git_auth_env.return_value = {}
        fake_client.get_repo_metadata.return_value = {
            "branch": "main",
            "owner": "Owner",
            "clone_url": "https://example.invalid/repo1.git",
        }
        srv._operator_state.client = fake_client

        finding = {
            **make_finding(),
            "repo": "repo1",
            "file": "app.py",
            "line": 10,
            "_hash": "hash-stop-finished",
            "severity": 1,
            "severity_label": "Critical",
            "risk": "Critical",
            "context": "production",
            "match": "import openai",
            "description": "Test finding",
            "last_seen": session.scan_id,
            "is_notebook": False,
        }

        def _fake_clone(_url, dest, **_kwargs):
            dest_path = Path(dest)
            dest_path.mkdir(parents=True, exist_ok=True)
            (dest_path / "app.py").write_text("import openai\n", encoding="utf-8")

        wait_calls = {"count": 0}
        real_wait = concurrent.futures.wait

        def _stop_then_wait(fs, return_when=None, timeout=None):
            done, pending = real_wait(fs, return_when=return_when, timeout=timeout)
            if wait_calls["count"] == 0 and done:
                session.stop_event.set()
            wait_calls["count"] += 1
            return done, pending

        with patch.object(srv, "_ollama_ping", return_value=False), \
             patch.object(srv._scan_service, "_ensure_ollama_running", return_value=(False, "unavailable")), \
             patch.object(srv, "_save_history_record", lambda session, findings: None), \
             patch.object(srv._scan_service, "_git_head_commit", return_value="abc123"), \
             patch("scanner.bitbucket.shallow_clone", side_effect=_fake_clone), \
             patch("scanner.bitbucket.cleanup_clone", return_value=None), \
             patch("services.scan_jobs.wait", side_effect=_stop_then_wait), \
             patch("services.scan_jobs.AIUsageDetector.scan", return_value=([finding], {"app.py": "import openai\n"})), \
             patch("services.scan_jobs.SecurityAnalyzer.analyze", side_effect=lambda rows: rows), \
             patch("services.scan_jobs.Aggregator.process", side_effect=lambda rows: rows):
            srv._run_scan(session)

        assert session.state == "stopped"
        assert len(session.findings) == 1
        assert session.findings[0]["_hash"] == "hash-stop-finished"
        assert any("Total findings (deduped): 1" in entry["msg"] for entry in session.log_lines)
    finally:
        srv.OUTPUT_DIR = orig_out
        srv._operator_state.client = orig_client


def test_ensure_ollama_running_clears_stale_snapshot_cache_after_success():
    from services import runtime_support as rs

    base_url = "http://localhost:11434"
    with rs._OLLAMA_CACHE_LOCK:
        rs._OLLAMA_CACHE[base_url] = {
            "base_url": base_url,
            "reachable": False,
            "models": [],
            "fetched_at": 1.0,
            "stale": True,
        }

    ping_results = iter([False, True])
    with patch.object(rs, "ollama_ping", side_effect=lambda url, timeout=4: next(ping_results)), \
         patch.object(rs.subprocess, "Popen") as popen_mock, \
         patch.object(rs.time, "sleep", return_value=None):
        ok, status = rs.ensure_ollama_running(base_url, timeout_s=2)

    assert ok is True
    assert status == "started"
    popen_mock.assert_called_once()
    with rs._OLLAMA_CACHE_LOCK:
        assert base_url not in rs._OLLAMA_CACHE

if __name__ == "__main__":
    tests = [
        # Original tests
        test_detects_openai_import,
        test_detects_anthropic_import,
        test_detects_hardcoded_key,
        test_detects_openai_key_pattern,
        test_detects_rag_pattern,
        test_detects_notebook,
        test_notebook_output_secret,
        test_deduplication,
        test_skip_node_modules,
        test_restricted_policy,
        test_approved_policy,
        test_banned_policy,
        test_security_category_critical,
        test_remediation_assigned,
        test_aggregator_dedup,
        test_aggregator_severity_filter,
        # path_context
        test_helm_pattern_only_fires_in_helm_paths,
        test_k8s_pattern_only_fires_in_k8s_paths,
        test_path_context_enforced_in_history_scanner,
        # placeholder suppression
        test_placeholder_value_suppressed,
        test_real_key_not_suppressed,
        # multi-hit dedup
        test_multihit_deduplication,
        test_cross_repo_notebook_hashes_differ,
        # pattern cache
        test_pattern_cache_shared_across_instances,
        test_pattern_cache_is_populated,
        # _scan_text_file delegation
        test_scan_text_file_sets_docs_context,
        test_scan_text_file_from_content_deleted_file_default,
        test_scan_text_file_from_content_context_override,
        # delta baseline
        test_delta_no_baseline,
        test_delta_with_baseline,
        # history persistence
        test_save_history_record_creates_file,
        test_history_cache_invalidated_after_write,
        test_atomic_history_write,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed}/{len(tests)} tests passed")
    if failed:
        sys.exit(1)
