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
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.detector import AIUsageDetector
from scanner.suppressions import TRIAGE_REVIEWED, list_suppressions, list_triage
from analyzer.security import SecurityAnalyzer
from aggregator.aggregator import Aggregator
from reports.html_report import HTMLReporter
from services.access_control import ROLE_ADMIN, ROLE_SCANNER, ROLE_TRIAGE, ROLE_VIEWER, UserContext
from services.single_user_state import SingleUserConfig, SingleUserState


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
        session.project_key = "P"
        session.repo_slugs = []
        session.state = "done"
        session.scan_duration_s = 1
        session.llm_model = "m"
        session.llm_model_info = {"name": "m"}
        srv.OUTPUT_DIR = str(d)
        srv.LOG_DIR    = str(d / "logs")
        srv._save_history_record(session, [])

        # No .tmp file should remain after write
        tmp = Path(srv.HISTORY_FILE + ".tmp")
        assert not tmp.exists(), ".tmp file left behind after atomic write"
        assert Path(srv.HISTORY_FILE).exists(), "scan_history.json not created"
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

    original_session = srv._browser_session_id
    original_csrf = srv._browser_csrf_token
    try:
        srv._browser_session_id = "valid-session"
        srv._browser_csrf_token = "expected-csrf"
        handler = DummyHandler()
        srv._Handler.do_POST(handler)
        assert handler.error == (403, "CSRF validation failed")
    finally:
        srv._browser_session_id = original_session
        srv._browser_csrf_token = original_csrf


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

    original_session = srv._browser_session_id
    try:
        srv._browser_session_id = "valid-session"
        handler = DummyHandler()
        with patch.object(srv, "_is_connected", return_value=True):
            srv._Handler.do_GET(handler)
        assert handler.redirect == "/login"
    finally:
        srv._browser_session_id = original_session


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
    assert "Scan Results" in html
    assert "repo1" in html
    assert "Current Findings" not in html
    assert 'src="/assets/scan_page.js"' in html
    assert 'current-findings-body' not in html
    assert 'id="inventory-summary"' not in html


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
    ).decode("utf-8")

    assert "Current Findings" not in html
    assert '<div class="findings-panel">' not in html
    assert '<div class="mitigate-section">' not in html
    assert '<div class="suppressed-section">' not in html
    assert 'id="new-scan-btn"' in html
    assert html.index("Phase Timeline") < html.index("Open HTML Report")
    assert "Download CSV File" in html
    assert "Download Logs" in html
    assert 'href="/results/20260317_154037"' in html
    assert "Baseline" in html
    assert 'id="inventory-summary"' not in html
    assert "Compared to AI_Scan_Report_COGI_repo1_20260317_140000.csv" in html
    assert "old.py:12" in html
    assert "New" in html
    assert "Existing" in html
    assert 'src="/assets/scan_page.js"' in html
    assert "findingsBody" not in html
    assert "repairTimer" not in html


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

    legacy_record = {"scan_id": "20260318_100000", "project": "COGI", "state": "done"}

    with service._connect() as conn:
        conn.execute(
            "INSERT INTO scan_jobs(scan_id, state, updated_at, record_json) VALUES (?, ?, ?, ?)",
            ("20260318_100000", "done", 1.0, json.dumps(legacy_record)),
        )
        conn.commit()

    records = service.load_history()

    assert records[0]["project_key"] == "COGI"
    assert "project" not in records[0]


def test_history_access_uses_project_key_only():
    from services.report_access import history_records_for_context

    ctx = UserContext(username="u", roles=[ROLE_VIEWER], allowed_projects=["COGI"])
    history = [
        {"scan_id": "1", "project_key": "COGI"},
        {"scan_id": "2", "project_key": "NOPE"},
    ]

    visible = history_records_for_context(history, ctx)

    assert [record["scan_id"] for record in visible] == ["1"]


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
    verdict = _apply_verdict(finding, {"verdict": "downgrade", "reason": "docs", "confidence": 83})

    assert verdict == "downgrade"
    assert finding["llm_review_confidence_score"] == 83
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
    assert "Delete Selected Repos" in html
    assert 'id="history-search"' in html
    assert 'id="history-prev-btn"' in html
    assert 'id="history-next-btn"' in html
    assert "Page 1 of 1" in html
    assert "New" in html
    assert "Existing" in html
    assert "Fixed" in html
    assert ">1</td>" in html
    assert ">2</td>" in html
    assert ">4</td>" in html
    assert "/reports/r.html" in html
    assert ".table-shell tbody tr:hover" in html


def test_results_page_is_server_rendered():
    import app_server as srv

    html = srv.render_results_page(
        scan_id="20260318_140208",
        project_key="COGI",
        repo_label="repo1",
        state="done",
        html_name="scan.html",
        csv_name="scan.csv",
        log_url="/api/history/log/20260318_140208",
    ).decode("utf-8")

    assert '<iframe class="results-frame" src="/reports/scan.html"' in html
    assert 'Open Raw HTML' in html
    assert 'Download CSV File' in html
    assert 'Download Logs' in html
    assert 'Back to Scan' in html
    assert '<h2>Scan Results</h2>' in html
    assert "Review the completed scan and download the generated artifacts." in html
    assert 'repo1' not in html


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

            def _send(self, status, ct, body):
                self.sent = (status, ct, body)

            def _err(self, status, msg):
                raise AssertionError(f"{status}: {msg}")

        handler = DummyHandler()
        with patch.object(srv, "_require_role", return_value=False):
            srv._Handler._render_results_page(handler, "20260318_150000")

        html = handler.sent[2].decode("utf-8")
        assert 'src="/reports/current.html"' in html
        assert "<h2>Scan Results</h2>" in html
    finally:
        srv._session = orig_session


def test_settings_page_is_server_rendered():
    import app_server as srv

    html = srv.render_settings_page(
        bitbucket_url=srv.BITBUCKET_URL,
        output_dir=srv.OUTPUT_DIR,
        llm_cfg={"base_url": "http://localhost:11434", "model": "m"},
        tls_cfg={"verify_ssl": True, "ca_bundle": "C:\\corp-ca.pem"},
    ).decode("utf-8")

    assert 'action="/settings/save"' in html
    assert srv.BITBUCKET_URL in html
    assert 'name="bitbucket_ca_bundle"' in html
    assert 'value="C:\\corp-ca.pem"' in html
    assert 'name="bitbucket_verify_ssl"' in html


def test_help_page_is_server_rendered():
    import app_server as srv

    html = srv.render_help_page().decode("utf-8")

    assert 'href="/help"' in html
    assert 'href="/inventory"' in html
    assert '<a class="nav active" href="/help">Help</a>' in html
    assert "Reference documentation for the AI Security &amp; Compliance Scanner." in html
    assert "Main Components" in html
    assert "Known Limitations" in html
    assert "AI Inventory" in html


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

    assert ".login-actions{display:flex;justify-content:center}" in html


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
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

    orig_state = srv._operator_state
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
        srv._operator_state = orig_state


def test_api_projects_filters_by_user_scope():
    import app_server as srv

    class DummyHandler:
        path = "/api/projects"

        def __init__(self):
            self.payload = None

        def _json(self, data, status=200):
            self.payload = (status, data)

        def _err(self, status, msg):
            self.payload = (status, {"error": msg})
            return None

    orig_state = srv._operator_state
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


def test_api_finding_triage_marks_reviewed_and_reset_clears_it():
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
            {"hash": "hash-2", "status": TRIAGE_REVIEWED, "note": "Manually reviewed"},
        )

        assert handler.payload[0] == 200
        assert srv._session.findings[0]["triage_status"] == TRIAGE_REVIEWED
        assert srv._session.findings[0]["triage_note"] == "Manually reviewed"
        assert any(rec["hash"] == "hash-2" and rec["status"] == TRIAGE_REVIEWED for rec in list_triage(srv.SUPPRESSIONS_FILE))

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


def test_html_report_renders_suppressed_stat():
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

    assert "Suppressed" in html
    assert "suppressed by analyst workflow" in html


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


def test_build_git_auth_env_uses_header_not_url():
    from scanner.bitbucket import BitbucketClient

    client = BitbucketClient("https://bitbucket.example", token="pat-123", username="alice")

    env = client.build_git_auth_env()

    expected = base64.b64encode(b"alice:pat-123").decode("ascii")
    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {expected}"


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


def test_sse_write_returns_false_on_client_disconnect():
    import app_server as srv

    class BrokenWriter:
        def write(self, _data):
            raise ConnectionAbortedError(10053, "connection aborted")

        def flush(self):
            raise AssertionError("flush should not run after write failure")

    handler = type("SSEHandler", (), {"wfile": BrokenWriter()})()

    assert srv._Handler._sse_write(handler, {"msg": "hello", "ts": 0, "level": "info"}) is False


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


def test_run_scan_with_no_repos_completes_cleanly():
    import app_server as srv

    session = srv.ScanSession()
    session.scan_id = "20250316_010101"
    session.project_key = "EMPTY"
    session.repo_slugs = []
    session.total = 0
    session.state = "running"

    with patch.object(srv, "_ollama_ping", return_value=False), \
         patch.object(srv, "_save_history_record", lambda session, findings: None):
        srv._run_scan(session)

    assert session.state == "done"
    assert session.findings == []
    assert session.repo_details == {}
    assert any(msg["msg"] == "  No findings - no report generated." for msg in session.log_lines)
    assert all(ord(ch) < 128 for entry in session.log_lines for ch in entry["msg"])

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
