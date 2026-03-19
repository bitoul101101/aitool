"""
app_server.py
─────────────
Single-file web application server for the AI Security & Compliance Scanner.

Serves a simple server-rendered web UI with targeted dynamic endpoints.

Routes
──────
GET  /                → scan page (HTML)
GET  /scan            → scan page (HTML)
GET  /results/<id>    → compatibility redirect to /scan/<id>?tab=results
GET  /history         → history page (HTML)
GET  /settings        → settings page (HTML)
GET  /help            → help page (HTML)
GET  /api/status      → server health + config
POST /api/connect     → validate PAT, return projects
GET  /api/projects    → list projects (cached)
GET  /api/repos?project=KEY  → list repos for project
POST /api/scan/start  → start scan, return scan_id
GET  /api/scan/stream → SSE log stream
GET  /api/scan/status → current scan state + results
POST /api/scan/stop   → request cancellation
POST /api/ollama      → proxy to Ollama (for HTML report LLM panel)
GET  /reports/<file>  → serve a report file from OUTPUT_DIR
"""

from __future__ import annotations

import http.server
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import tempfile
import time
import tkinter
from tkinter import filedialog
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, urlencode, urlparse
from dateutil import tz

# ── Project imports ───────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent))

from scanner.pat_store import load_pat
from scanner.suppressions import (
    TRIAGE_FALSE_POSITIVE,
    list_suppressions,
    list_triage,
    remove_triage,
    triage_by_hash,
    upsert_triage,
)
from services.access_control import (
    ROLE_ADMIN,
    ROLE_SCANNER,
    ROLE_TRIAGE,
    ROLE_VIEWER,
    filter_projects,
)
from services.active_scan_state import ActiveScanStore
from services.audit_log import AuditLogService
from services.api_actions import (
    connect_operator,
    delete_history_records,
    reset_finding,
    start_scan,
    stop_scan,
    triage_finding,
)
from services.browser_sessions import BrowserSessionStore
from services.report_access import (
    find_history_record_by_report_name,
    find_history_record_by_scan_id,
    history_records_for_context,
)
from services.findings import build_findings_rollups
from services.scan_jobs import ScanJobPaths, ScanJobService, ScanSession
from services.settings_service import SettingsService
from services.single_user_state import SingleUserState, load_single_user_config
from services.scan_runtime_views import (
    format_log_entry as _runtime_format_log_entry,
    format_log_text as _format_log_text,
    llm_stats as _llm_stats,
    parse_log_text_entries as _parse_log_text_entries,
    phase_timeline as _phase_timeline,
    structured_phase_timeline as _structured_phase_timeline,
)
from services.trends import compute_history_trends
from services.web_pages import (
    render_findings_page,
    render_help_page,
    render_history_page,
    render_inventory_page,
    render_login_page,
    render_results_page,
    render_scan_page,
    render_settings_page,
    render_trends_page,
)
from services.runtime_support import (
    DEFAULT_LLM_CONFIG,
    DEFAULT_TLS_CONFIG,
    ensure_ollama_running,
    load_llm_config as load_llm_config_file,
    load_tls_config as load_tls_config_file,
    ollama_list_models,
    ollama_ping,
    ollama_snapshot,
    save_llm_config as save_llm_config_file,
    save_tls_config as save_tls_config_file,
)

# ── Constants ─────────────────────────────────────────────────────────────────
BITBUCKET_URL = "https://bitbucket.cognyte.local:8443"
_BASE_DIR     = Path(__file__).parent          # always relative to script
OUTPUT_DIR    = str(_BASE_DIR / "output")      # mutable at runtime via settings
POLICY_FILE   = str(_BASE_DIR / "policy.json")
OWNER_MAP_FILE = str(_BASE_DIR / "owner_map.json")
APP_PORT      = 5757   # fixed port for the app (report servers use random ports)
APP_VERSION   = "19.1"
ISRAEL_TZ = tz.gettz("Asia/Jerusalem")
_RESOURCE_LOCK = threading.RLock()
_CPU_TIMES_PREV: tuple[int, int, int] | None = None
_PROCESS_IO_PREV: tuple[float, int, int] | None = None
_WORKSPACE_USAGE_CACHE = {"scan_id": "", "ts": 0.0, "mb": 0.0}


def _default_temp_dir(os_name: Optional[str] = None,
                      temp_root: Optional[str] = None) -> Path:
    current_os = os_name or os.name
    if current_os == "nt":
        root = Path(temp_root or tempfile.gettempdir())
        return root / "ai_scanner_tmp"
    return _BASE_DIR / "tmp_clones"


TEMP_DIR      = str(_default_temp_dir())


def _default_state_dir() -> Path:
    override = os.environ.get("AI_SCANNER_STATE_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = (
            os.environ.get("LOCALAPPDATA")
            or os.environ.get("APPDATA")
            or str(Path.home() / "AppData" / "Local")
        )
        return Path(base) / "AI Scanner"
    return Path.home() / ".config" / "ai_scanner"


STATE_DIR = _default_state_dir()
SUPPRESSIONS_FILE = str(STATE_DIR / "ai_scanner_suppressions.json")
LLM_CFG_FILE  = str(STATE_DIR / "ai_scanner_llm_config.json")
TLS_CFG_FILE  = str(STATE_DIR / "ai_scanner_tls_config.json")
ACCESS_FILE   = str(STATE_DIR / "access_control.json")
_LEGACY_SUPPRESSIONS_FILE = _BASE_DIR / "ai_scanner_suppressions.json"
_LEGACY_LLM_CFG_FILE = _BASE_DIR / "ai_scanner_llm_config.json"
_LEGACY_TLS_CFG_FILE = _BASE_DIR / "ai_scanner_tls_config.json"
_LEGACY_ACCESS_FILE = _BASE_DIR / "access_control.json"
_LEGACY_RUNTIME_FILES = (
    ("Access Control", _LEGACY_ACCESS_FILE, Path(ACCESS_FILE)),
    ("LLM Config", _LEGACY_LLM_CFG_FILE, Path(LLM_CFG_FILE)),
    ("TLS Config", _LEGACY_TLS_CFG_FILE, Path(TLS_CFG_FILE)),
    ("Suppressions", _LEGACY_SUPPRESSIONS_FILE, Path(SUPPRESSIONS_FILE)),
)


def _prepare_runtime_file(target: Path, *, legacy: Path | None = None, default_json: dict | None = None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        return
    if legacy and legacy.exists():
        target.write_bytes(legacy.read_bytes())
        return
    if default_json is not None:
        target.write_text(json.dumps(default_json, indent=2), encoding="utf-8")


_prepare_runtime_file(Path(LLM_CFG_FILE), legacy=_LEGACY_LLM_CFG_FILE, default_json=DEFAULT_LLM_CONFIG)
_prepare_runtime_file(Path(TLS_CFG_FILE), legacy=_LEGACY_TLS_CFG_FILE, default_json=DEFAULT_TLS_CONFIG)
_prepare_runtime_file(Path(SUPPRESSIONS_FILE), legacy=_LEGACY_SUPPRESSIONS_FILE, default_json={"version": 2, "triage": []})
_prepare_runtime_file(Path(ACCESS_FILE), legacy=_LEGACY_ACCESS_FILE)


def _legacy_runtime_artifacts() -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for label, legacy_path, active_path in _LEGACY_RUNTIME_FILES:
        if not legacy_path.exists():
            continue
        items.append({
            "label": label,
            "legacy_path": str(legacy_path.resolve()),
            "active_path": str(active_path.resolve()),
        })
    return items


# ── Utility helpers (lifted from main.py) ─────────────────────────────────────

def load_policy(path):
    try:
        return json.loads(Path(path).read_text("utf-8"))
    except Exception:
        return {}

def load_owner_map(path):
    owner_map_path = Path(path)
    if not owner_map_path.exists() or not owner_map_path.is_file():
        return {}
    try:
        return json.loads(owner_map_path.read_text("utf-8"))
    except Exception:
        return {}

def load_llm_config() -> dict:
    return load_llm_config_file(LLM_CFG_FILE)

def save_llm_config(cfg: dict) -> None:
    merged = load_llm_config()
    merged.update(dict(cfg or {}))
    save_llm_config_file(LLM_CFG_FILE, merged)

def load_tls_config() -> dict:
    return load_tls_config_file(TLS_CFG_FILE)

def save_tls_config(cfg: dict) -> None:
    save_tls_config_file(TLS_CFG_FILE, cfg)


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _policy_version(path: str) -> str:
    try:
        data = Path(path).read_bytes()
    except Exception:
        return "unknown"
    return hashlib.sha256(data).hexdigest()[:12]


def _allowed_origin(origin: str) -> str | None:
    allowed = {
        f"http://127.0.0.1:{APP_PORT}",
        f"http://localhost:{APP_PORT}",
    }
    return origin if origin in allowed else None


def _pick_local_repo_path() -> str:
    if os.name != "nt":
        raise RuntimeError("Native folder picker is only supported on Windows")
    try:
        root = tkinter.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.update()
        selected = filedialog.askdirectory(
            parent=root,
            title="Select Local Repository",
            mustexist=True,
        )
        root.destroy()
        return str(selected or "").strip()
    except Exception as exc:
        raise RuntimeError("Unable to open the Windows folder picker") from exc


def _with_query(path: str, **params: str) -> str:
    clean = {key: value for key, value in params.items() if value}
    if not clean:
        return path
    return f"{path}?{urlencode(clean)}"


def _git_head_commit(repo_dir: Path) -> str:
    import subprocess as _sp

    try:
        result = _sp.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return result.stdout.strip()
    except Exception:
        return ""

def _ollama_ping(base_url: str) -> bool:
    return ollama_ping(base_url, timeout=3)

def _ollama_list_models(base_url: str) -> list:
    return ollama_list_models(base_url, timeout=5)


def _ollama_snapshot(base_url: str, *, refresh: bool = False) -> dict:
    return ollama_snapshot(base_url, timeout=5, refresh=refresh)


OLLAMA_START_TIMEOUT = 15   # seconds to wait for ollama serve to become ready


def _ollama_ensure_running(base_url: str) -> dict:
    ok, status = ensure_ollama_running(base_url, timeout_s=OLLAMA_START_TIMEOUT)
    if ok:
        return {"ok": True, "status": status}
    return {"ok": False, "error": status}


# ── Global app state ──────────────────────────────────────────────────────────

_operator_state = SingleUserState(load_single_user_config(ACCESS_FILE))
_active_scan_store = ActiveScanStore()
_state_lock = _active_scan_store.lock
_session: ScanSession = _active_scan_store.current()
_app_exit_event = threading.Event()
_server_instance: Optional[http.server.ThreadingHTTPServer] = None
_browser_session_store = BrowserSessionStore()
_browser_sessions = _browser_session_store.sessions


def _current_session() -> ScanSession:
    global _session
    if _session is not _active_scan_store.current():
        _active_scan_store.replace(_session)
    return _active_scan_store.current()


def _replace_current_session(session: ScanSession) -> ScanSession:
    global _session
    _session = _active_scan_store.replace(session)
    return _session


def _current_session_snapshot(*, include_status: bool = False, log_limit: int | None = None) -> dict[str, Any]:
    global _session
    if _session is not _active_scan_store.current():
        _active_scan_store.replace(_session)
    return _active_scan_store.snapshot(include_status=include_status, log_limit=log_limit)


# ── Scan job service ─────────────────────────────────────────────────────────

HISTORY_FILE = str(_BASE_DIR / "output" / "scan_history.json")
LOG_DIR = str(_BASE_DIR / "output" / "logs")
DB_FILE = str(_BASE_DIR / "output" / "scan_jobs.db")
AUDIT_FILE = str(_BASE_DIR / "output" / "audit_events.jsonl")
ASSETS_DIR = _BASE_DIR / "assets"
_audit_log = AuditLogService(AUDIT_FILE)
_report_generation_lock = threading.RLock()
_report_generation_jobs: dict[str, dict[str, Any]] = {}

_scan_service = ScanJobService(
    app_version=APP_VERSION,
    paths=ScanJobPaths(
        output_dir=OUTPUT_DIR,
        temp_dir=TEMP_DIR,
        policy_file=POLICY_FILE,
        owner_map_file=OWNER_MAP_FILE,
        suppressions_file=SUPPRESSIONS_FILE,
        history_file=HISTORY_FILE,
        log_dir=LOG_DIR,
        db_file=DB_FILE,
        llm_cfg_file=LLM_CFG_FILE,
    ),
    load_policy=load_policy,
    load_owner_map=load_owner_map,
    policy_version=_policy_version,
    utc_now_iso=_utc_now_iso,
    git_head_commit=_git_head_commit,
    ollama_ping=_ollama_ping,
)


def _sync_scan_service_paths() -> None:
    _scan_service.update_paths(
        output_dir=OUTPUT_DIR,
        temp_dir=TEMP_DIR,
        policy_file=POLICY_FILE,
        owner_map_file=OWNER_MAP_FILE,
        suppressions_file=SUPPRESSIONS_FILE,
        history_file=HISTORY_FILE,
        log_dir=LOG_DIR,
        db_file=DB_FILE,
        llm_cfg_file=LLM_CFG_FILE,
    )
    _audit_log.update_path(AUDIT_FILE)


def _set_output_paths(output_dir: Path) -> None:
    global OUTPUT_DIR, HISTORY_FILE, LOG_DIR, DB_FILE, AUDIT_FILE
    resolved = output_dir.resolve()
    OUTPUT_DIR = str(resolved)
    HISTORY_FILE = str(resolved / "scan_history.json")
    LOG_DIR = str(resolved / "logs")
    DB_FILE = str(resolved / "scan_jobs.db")
    AUDIT_FILE = str(resolved / "audit_events.jsonl")


def _audit_event(action: str, **details) -> None:
    _audit_log.record({
        "ts": _utc_now_iso(),
        "action": action,
        "actor": _operator_state.ctx.username,
        "roles": list(_operator_state.ctx.roles),
        **details,
    })


def _report_generation_status(scan_id: str) -> dict[str, Any]:
    with _report_generation_lock:
        return dict(_report_generation_jobs.get(scan_id, {}))


def _set_report_generation_status(scan_id: str, **status) -> dict[str, Any]:
    with _report_generation_lock:
        current = dict(_report_generation_jobs.get(scan_id, {}))
        current.update(status)
        _report_generation_jobs[scan_id] = current
        return dict(current)


def _clear_report_generation_status(scan_id: str) -> None:
    with _report_generation_lock:
        _report_generation_jobs.pop(scan_id, None)


def _require_role(handler, role: str):
    if not _operator_state.can(role):
        handler._err(403, f"{role} role required")
        return True
    return False


def _require_project_access(handler, project_key: str):
    if not _operator_state.can_access_project(project_key):
        handler._err(403, f"project access denied: {project_key}")
        return True
    return False


def _issue_browser_session() -> tuple[str, str]:
    return _browser_session_store.issue()


def _browser_cookie_value(handler) -> str:
    return _browser_session_store.extract_session_id(handler)


def _browser_session(handler) -> dict[str, Any] | None:
    return _browser_session_store.snapshot_for_handler(handler)


def _has_valid_browser_session(handler) -> bool:
    return _browser_session_store.has_valid_session(handler)


def _current_csrf_token(handler=None) -> str:
    return _browser_session_store.csrf_token_for_handler(handler)


def _csrf_matches(handler, body: dict) -> bool:
    return _browser_session_store.csrf_matches(handler, body)


def _queue_session_cookie(handler, session_id: str) -> None:
    _browser_session_store.queue_session_cookie(handler, session_id)


def _save_history_record(session, findings):
    _sync_scan_service_paths()
    _scan_service.save_history_record(session, findings)


def _apply_tls_settings_to_connected_client(tls_cfg: dict) -> None:
    client = _operator_state.client
    if not client:
        return
    verify_ssl = bool(tls_cfg.get("verify_ssl", True))
    ca_bundle = str(tls_cfg.get("ca_bundle", "") or "").strip()
    client.verify_ssl = verify_ssl
    client.ca_bundle = ca_bundle
    client.session.verify = ca_bundle if verify_ssl and ca_bundle else verify_ssl
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _load_history() -> list:
    _sync_scan_service_paths()
    return _scan_service.load_history()


def _invalidate_history_cache() -> None:
    _scan_service.invalidate_history_cache()


def _get_log_text(scan_id: str) -> str:
    _sync_scan_service_paths()
    return _scan_service.get_log_text(scan_id)


def _delete_history(scan_ids: List[str]) -> None:
    _sync_scan_service_paths()
    _scan_service.delete_history(scan_ids)


def _is_within_roots(path: Path, roots: List[Path]) -> bool:
    try:
        resolved = path.resolve()
    except Exception:
        return False
    for root in roots:
        try:
            if resolved.is_relative_to(root.resolve()):
                return True
        except Exception:
            continue
    return False


def _normalize_history_path(path_str: str) -> Path:
    raw = str(path_str or "").strip()
    if raw.startswith("\\\\?\\"):
        raw = raw[4:]
    return Path(raw)


def _is_tool_generated_legacy_file(path: Path, *, scan_id: str, artifact: str) -> bool:
    lowered = [part.lower() for part in path.parts]
    if "output" not in lowered:
        return False
    if artifact == "log":
        return path.name in {f"{scan_id}.txt", f"{scan_id}.log"} and path.parent.name.lower() == "logs"
    if artifact == "html":
        return path.suffix.lower() == ".html" and path.name.lower().startswith("ai_scan_")
    if artifact == "csv":
        return path.suffix.lower() == ".csv" and path.name.lower().startswith("ai_scan_")
    if artifact == "json":
        return path.suffix.lower() == ".json" and path.name.lower().startswith("ai_scan_")
    if artifact == "sarif":
        return path.suffix.lower() == ".sarif" and path.name.lower().startswith("ai_scan_")
    if artifact == "threat_dragon":
        return path.suffix.lower() == ".json" and path.name.lower().startswith("ai_scan_") and "threat_dragon" in path.name.lower()
    return False


def _delete_managed_history_file(path_str: str, scan_id: str, artifact: str, *, roots: List[Path]) -> str | None:
    path = _normalize_history_path(path_str)
    if not _is_within_roots(path, roots):
        if not _is_tool_generated_legacy_file(path, scan_id=scan_id, artifact=artifact):
            return f"refused to delete unmanaged path: {path}"
    if path.exists():
        path.unlink()
    return None


def _history_records_for_user() -> list[dict]:
    records = []
    for record in history_records_for_context(_load_history(), _operator_state.ctx):
        normalized = dict(record)
        repo_slugs = normalized.get("repo_slugs", normalized.get("repos", []))
        if not isinstance(repo_slugs, list) or not any(str(slug).strip() for slug in repo_slugs):
            continue
        if str(normalized.get("state", "")).lower() == "running":
            normalized["state"] = "stopped"
        records.append(normalized)
    current = _current_session_history_record()
    if current:
        records = [rec for rec in records if rec.get("scan_id") != current.get("scan_id")]
        records.append(current)
        records.sort(
            key=lambda record: (
                str(record.get("completed_at_utc") or record.get("started_at_utc") or ""),
                str(record.get("scan_id") or ""),
            )
        )
    return records


def _findings_for_user() -> list[dict]:
    return build_findings_rollups(_history_records_for_user(), _triage_by_hash())


def _inventory_snapshot_for_user() -> tuple[list[dict], dict]:
    latest_by_repo: dict[str, dict] = {}
    for record in _history_records_for_user():
        inventory = record.get("inventory") or {}
        profiles = inventory.get("repo_profiles") or []
        for profile in profiles:
            repo = str(profile.get("repo", "") or "").strip()
            if not repo:
                continue
            candidate = {
                "repo": repo,
                "project_key": str(record.get("project_key", "") or ""),
                "scan_id": str(record.get("scan_id", "") or ""),
                "last_scan_at_utc": str(record.get("completed_at_utc") or record.get("started_at_utc") or ""),
                "finding_count": int(profile.get("finding_count", 0) or 0),
                "providers": list(profile.get("providers", []) or []),
                "provider_labels": list(profile.get("provider_labels", []) or []),
                "models": list(profile.get("models", []) or []),
                "embeddings_vector_db": bool(profile.get("embeddings_vector_db")),
                "prompt_handling": bool(profile.get("prompt_handling")),
                "model_serving": bool(profile.get("model_serving")),
                "agent_tool_use": bool(profile.get("agent_tool_use")),
                "usage_tags": [
                    tag
                    for tag, enabled in (
                        ("embeddings", profile.get("embeddings_vector_db")),
                        ("prompt", profile.get("prompt_handling")),
                        ("serving", profile.get("model_serving")),
                        ("agent", profile.get("agent_tool_use")),
                    )
                    if enabled
                ],
                "reports": (record.get("reports") or {}).get("__all__", {}),
            }
            previous = latest_by_repo.get(repo)
            if not previous or candidate["last_scan_at_utc"] >= previous["last_scan_at_utc"]:
                latest_by_repo[repo] = candidate
    repo_inventory = sorted(
        latest_by_repo.values(),
        key=lambda item: (item.get("last_scan_at_utc", ""), item.get("repo", "")),
        reverse=True,
    )
    provider_labels = {label for item in repo_inventory for label in item.get("provider_labels", [])}
    models = {model for item in repo_inventory for model in item.get("models", [])}
    summary = {
        "repos_using_ai_count": sum(1 for item in repo_inventory if item.get("finding_count", 0) > 0),
        "repos_total": len(repo_inventory),
        "provider_count": len(provider_labels),
        "model_count": len(models),
        "agent_tool_use_repos": sum(1 for item in repo_inventory if item.get("agent_tool_use")),
    }
    return repo_inventory, summary


def _find_history_record_by_scan_id(scan_id: str) -> dict | None:
    return find_history_record_by_scan_id(_history_records_for_user(), scan_id)


def _find_history_record_by_report_name(filename: str) -> dict | None:
    return find_history_record_by_report_name(_history_records_for_user(), filename)


def _report_record_for_scan(scan_id: str) -> dict | None:
    snapshot = _current_session_snapshot()
    current_report = (snapshot["report_paths"] or {}).get("__all__", {})
    if snapshot["scan_id"] == scan_id and current_report.get("html_name"):
        return {
            "scan_id": snapshot["scan_id"],
            "project_key": snapshot["project_key"],
            "scan_source": snapshot["session"].scan_source,
            "local_repo_path": snapshot["session"].local_repo_path,
            "repo_slugs": list(snapshot["repo_slugs"]),
            "state": snapshot["state"],
            "started_at_utc": snapshot["started_at_utc"],
            "reports": {"__all__": dict(current_report)},
            "log_file": f"{scan_id}.txt" if scan_id else "",
        }
    return _find_history_record_by_scan_id(scan_id)


def _scan_record_for_id(scan_id: str) -> dict | None:
    snapshot = _current_session_snapshot()
    if snapshot["scan_id"] == scan_id:
        current_report = (snapshot["report_paths"] or {}).get("__all__", {})
        return {
            "scan_id": snapshot["scan_id"],
            "project_key": snapshot["project_key"],
            "scan_source": snapshot["session"].scan_source,
            "local_repo_path": snapshot["session"].local_repo_path,
            "repo_slugs": list(snapshot["repo_slugs"]),
            "state": snapshot["state"],
            "started_at_utc": snapshot["started_at_utc"],
            "completed_at_utc": snapshot["completed_at_utc"],
            "duration_s": snapshot["scan_duration_s"],
            "reports": {"__all__": dict(current_report)},
            "delta": dict(snapshot["delta"] or {}),
            "inventory": dict(snapshot["inventory"] or {}),
            "findings": list(snapshot["findings"]),
            "llm_model": str(snapshot.get("status", {}).get("llm_model", "") or ""),
            "llm_model_info": dict(snapshot.get("status", {}).get("llm_model_info") or {}),
            "pre_llm_count": int(snapshot["session"].pre_llm_count or 0),
            "post_llm_count": int(snapshot["session"].post_llm_count or 0),
            "repo_details": dict(snapshot["session"].repo_details or {}),
            "tool_version": snapshot["session"].tool_version,
            "policy_version": snapshot["session"].policy_version,
            "operator": snapshot["session"].operator,
            "finding_total": len(snapshot["findings"]),
            "suppressed_total": len(snapshot["suppressed_findings"]),
            "log_file": f"{scan_id}.txt" if scan_id else "",
        }
    return _find_history_record_by_scan_id(scan_id)


def _generate_html_report_for_scan(scan_id: str) -> dict:
    safe_scan_id = Path(scan_id).name
    record = _scan_record_for_id(safe_scan_id)
    if not record:
        raise RuntimeError("Scan results not found")
    report = dict((record.get("reports") or {}).get("__all__", {}) or {})
    html_path = str(report.get("html", "") or "")
    if html_path and Path(html_path).exists():
        return record

    snapshot = _current_session_snapshot()
    findings = None
    if snapshot["scan_id"] == safe_scan_id:
        findings = list(snapshot["findings"])
    updated = _scan_service.generate_html_report(safe_scan_id, findings=findings)
    if snapshot["scan_id"] == safe_scan_id:
        with _state_lock:
            current = _current_session()
            current.report_paths = dict(updated.get("reports") or {})
    return updated


def _start_html_report_generation(scan_id: str, detail_mode: str = "detailed") -> dict[str, Any]:
    safe_scan_id = Path(scan_id).name
    record = _scan_record_for_id(safe_scan_id)
    if not record:
        raise RuntimeError("Scan results not found")
    report = dict((record.get("reports") or {}).get("__all__", {}) or {})
    detail_mode = "fast" if str(detail_mode or "").strip().lower() == "fast" else "detailed"
    mode_label = "Fast" if detail_mode == "fast" else "Detailed"
    html_path = str(report.get("html", "") or "")
    existing_mode = str(report.get("html_detail_mode", "detailed") or "detailed").strip().lower()
    if html_path and Path(html_path).exists() and existing_mode == detail_mode:
        _clear_report_generation_status(safe_scan_id)
        return {"state": "done", "message": f"{mode_label} HTML report already generated.", "current": 1, "total": 1, "detail_mode": detail_mode}

    existing = _report_generation_status(safe_scan_id)
    if str(existing.get("state", "") or "").lower() in {"queued", "running"}:
        return existing

    _set_report_generation_status(
        safe_scan_id,
        state="queued",
        message=f"Queued {detail_mode} HTML report generation...",
        current=0,
        total=0,
        detail_mode=detail_mode,
    )

    def _worker():
        def _progress(i: int, n: int, _cap: str) -> None:
            _set_report_generation_status(
                safe_scan_id,
                state="running",
                message=f"Generating LLM analysis {i}/{n}...",
                current=i,
                total=n,
                detail_mode=detail_mode,
            )

        try:
            _set_report_generation_status(
                safe_scan_id,
                state="running",
                message=f"Building {detail_mode} HTML report...",
                current=0,
                total=0,
                detail_mode=detail_mode,
            )
            snapshot = _current_session_snapshot()
            findings = list(snapshot["findings"]) if snapshot["scan_id"] == safe_scan_id else None
            updated = _scan_service.generate_html_report(
                safe_scan_id,
                findings=findings,
                progress_fn=_progress,
                detail_mode=detail_mode,
            )
            if snapshot["scan_id"] == safe_scan_id:
                with _state_lock:
                    current = _current_session()
                    current.report_paths = dict(updated.get("reports") or {})
            _set_report_generation_status(
                safe_scan_id,
                state="done",
                message=f"{mode_label} HTML report generated.",
                current=1,
                total=1,
                detail_mode=detail_mode,
            )
        except Exception as exc:
            _set_report_generation_status(
                safe_scan_id,
                state="error",
                message=str(exc),
                current=0,
                total=0,
                detail_mode=detail_mode,
            )

    threading.Thread(target=_worker, daemon=True).start()
    return _report_generation_status(safe_scan_id)


def _triage_by_hash() -> Dict[str, dict]:
    return triage_by_hash(SUPPRESSIONS_FILE)


def _repos_for_project(project_key: str) -> list[dict]:
    if not project_key or not _operator_state.client:
        return []
    repos = _operator_state.repos_cache.get(project_key)
    if repos is None:
        repos = _operator_state.client.list_repos(project_key)
        _operator_state.repos_cache[project_key] = repos
    return repos


def _is_connected() -> bool:
    return _operator_state.client is not None


def _has_scan_results() -> bool:
    return bool(_current_session_snapshot().get("scan_id"))


def _current_session_history_record() -> dict | None:
    snapshot = _current_session_snapshot()
    if not snapshot["scan_id"] or snapshot["state"] not in {"running", "stopped"}:
        return None
    if not any(str(slug).strip() for slug in list(snapshot["repo_slugs"] or [])):
        return None
    findings = list(snapshot["findings"])
    suppressed = list(snapshot["suppressed_findings"])
    report_paths = dict(snapshot["report_paths"])
    inventory = dict(snapshot["inventory"])
    critical_prod = sum(
        1 for f in findings
        if f.get("severity") == 1 and str(f.get("context", "production")).lower() == "production"
    )
    high_prod = sum(
        1 for f in findings
        if f.get("severity") == 2 and str(f.get("context", "production")).lower() == "production"
    )
    return {
        "scan_id": snapshot["scan_id"],
        "project_key": snapshot["project_key"],
        "scan_source": snapshot["session"].scan_source,
        "local_repo_path": snapshot["session"].local_repo_path,
        "repo_slugs": list(snapshot["repo_slugs"]),
        "state": snapshot["state"],
        "started_at_utc": snapshot["started_at_utc"],
        "completed_at_utc": snapshot["completed_at_utc"],
        "total": len(findings),
        "active_total": len(findings),
        "suppressed_total": len(suppressed),
        "llm_model": snapshot["llm_model"],
        "duration_s": snapshot["scan_duration_s"],
        "critical_prod": critical_prod,
        "high_prod": high_prod,
        "reports": report_paths,
        "inventory": inventory,
        "log_file": "",
    }


def _format_log_entry(entry: dict) -> str:
    return _runtime_format_log_entry(entry)


def _format_mb(value_mb: float) -> str:
    if value_mb <= 0:
        return "0 MB"
    if value_mb >= 1024:
        return f"{value_mb / 1024:.1f} GB"
    return f"{int(round(value_mb))} MB"


def _format_percent(value: float) -> str:
    return f"{max(0.0, min(100.0, value)):.0f}%"


def _format_io_rate(bytes_per_second: float) -> str:
    value = max(0.0, float(bytes_per_second or 0.0))
    if value >= 1024 ** 2:
        return f"{value / (1024 ** 2):.1f} MB/s"
    if value >= 1024:
        return f"{value / 1024:.0f} KB/s"
    return f"{int(round(value))} B/s"


def _system_cpu_percent() -> float | None:
    if os.name != "nt":
        return None
    try:
        import ctypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]

        idle = FILETIME()
        kernel = FILETIME()
        user = FILETIME()
        if not ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return None
        idle_total = (idle.dwHighDateTime << 32) | idle.dwLowDateTime
        kernel_total = (kernel.dwHighDateTime << 32) | kernel.dwLowDateTime
        user_total = (user.dwHighDateTime << 32) | user.dwLowDateTime
        with _RESOURCE_LOCK:
            global _CPU_TIMES_PREV
            previous = _CPU_TIMES_PREV
            _CPU_TIMES_PREV = (idle_total, kernel_total, user_total)
        if previous is None:
            return None
        prev_idle, prev_kernel, prev_user = previous
        idle_delta = idle_total - prev_idle
        kernel_delta = kernel_total - prev_kernel
        user_delta = user_total - prev_user
        total_delta = kernel_delta + user_delta
        if total_delta <= 0:
            return None
        return max(0.0, min(100.0, (1.0 - (idle_delta / total_delta)) * 100.0))
    except Exception:
        return None


def _memory_snapshot() -> tuple[float | None, float | None]:
    if os.name != "nt":
        return None, None
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_uint32),
                ("dwMemoryLoad", ctypes.c_uint32),
                ("ullTotalPhys", ctypes.c_uint64),
                ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64),
                ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64),
                ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None, None
        used_mb = (status.ullTotalPhys - status.ullAvailPhys) / (1024 * 1024)
        total_mb = status.ullTotalPhys / (1024 * 1024)
        return used_mb, total_mb
    except Exception:
        return None, None


def _process_memory_mb() -> float | None:
    if os.name != "nt":
        return None
    try:
        import ctypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32),
                ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        proc = ctypes.windll.kernel32.GetCurrentProcess()
        if not ctypes.windll.psapi.GetProcessMemoryInfo(proc, ctypes.byref(counters), counters.cb):
            return None
        return counters.WorkingSetSize / (1024 * 1024)
    except Exception:
        return None


def _process_disk_io_text() -> str:
    if os.name != "nt":
        return "Unavailable"
    try:
        import ctypes
        from ctypes import wintypes

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(IO_COUNTERS)]
        kernel32.GetProcessIoCounters.restype = wintypes.BOOL

        counters = IO_COUNTERS()
        proc = kernel32.GetCurrentProcess()
        if not kernel32.GetProcessIoCounters(proc, ctypes.byref(counters)):
            return "Unavailable"
        now = time.time()
        with _RESOURCE_LOCK:
            global _PROCESS_IO_PREV
            previous = _PROCESS_IO_PREV
            _PROCESS_IO_PREV = (now, int(counters.ReadTransferCount), int(counters.WriteTransferCount))
        if previous is None:
            return "Sampling..."
        prev_ts, prev_read, prev_write = previous
        elapsed = max(now - prev_ts, 0.001)
        read_rate = (int(counters.ReadTransferCount) - prev_read) / elapsed
        write_rate = (int(counters.WriteTransferCount) - prev_write) / elapsed
        return f"R { _format_io_rate(read_rate) } | W { _format_io_rate(write_rate) }"
    except Exception:
        return "Unavailable"


def _workspace_size_mb(scan_id: str) -> float:
    if not scan_id:
        return 0.0
    now = time.time()
    with _RESOURCE_LOCK:
        if _WORKSPACE_USAGE_CACHE["scan_id"] == scan_id and (now - float(_WORKSPACE_USAGE_CACHE["ts"])) < 5.0:
            return float(_WORKSPACE_USAGE_CACHE["mb"])
    total_bytes = 0
    workspace = Path(TEMP_DIR) / f"scan_{scan_id}"
    try:
        if workspace.exists():
            for path in workspace.rglob("*"):
                if path.is_file():
                    try:
                        total_bytes += path.stat().st_size
                    except OSError:
                        continue
    except OSError:
        total_bytes = 0
    total_mb = total_bytes / (1024 * 1024)
    with _RESOURCE_LOCK:
        _WORKSPACE_USAGE_CACHE["scan_id"] = scan_id
        _WORKSPACE_USAGE_CACHE["ts"] = now
        _WORKSPACE_USAGE_CACHE["mb"] = total_mb
    return total_mb


def _hardware_snapshot(session: ScanSession | None) -> dict:
    cpu = _system_cpu_percent()
    ram_used_mb, ram_total_mb = _memory_snapshot()
    try:
        gpu_text = _gpu_snapshot()
    except (OSError, subprocess.SubprocessError, ValueError):
        gpu_text = "Unavailable"
    disk_io_text = _process_disk_io_text()
    ram_text = "Unavailable"
    if ram_used_mb is not None and ram_total_mb:
        ram_text = f"{_format_mb(ram_used_mb)} / {_format_mb(ram_total_mb)}"
    return {
        "cpu_percent": _format_percent(cpu) if cpu is not None else "Sampling...",
        "ram_text": ram_text,
        "gpu_text": gpu_text,
        "disk_io_text": disk_io_text,
    }


def _gpu_snapshot() -> str:
    if os.name != "nt":
        return "Unavailable"
    try:
        proc = subprocess.Popen(
            [
                "nvidia-smi",
                "--query-gpu=utilization.gpu,memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return "Unavailable"
    deadline = time.monotonic() + 2.0
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.communicate(timeout=0.2)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        return "Unavailable"
    try:
        stdout, _stderr = proc.communicate(timeout=0.2)
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return "Unavailable"
    if proc.returncode not in (0, None):
        return "Unavailable"
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        return "Unavailable"
    first = lines[0]
    parts = [part.strip() for part in first.split(",")]
    if len(parts) < 3:
        return "Unavailable"
    gpu_util, mem_used, mem_total = parts[:3]
    return f"{gpu_util}% | {mem_used} / {mem_total} MB"


_settings_service = SettingsService(
    load_llm_config=load_llm_config,
    save_llm_config=save_llm_config,
    save_tls_config=save_tls_config,
    ensure_ollama_running=_ollama_ensure_running,
    list_ollama_models=_ollama_list_models,
    audit_event=_audit_event,
    sync_paths=_sync_scan_service_paths,
)


def _clear_finding_triage(finding: dict) -> dict:
    updated = dict(finding)
    for key in (
        "triage_status",
        "triage_note",
        "triage_by",
        "triage_at",
        "suppressed_reason",
        "suppressed_by",
        "suppressed_at",
    ):
        updated.pop(key, None)
    return updated


def _apply_triage_metadata(finding: dict, meta: dict) -> dict:
    updated = dict(finding)
    status = meta.get("status", "")
    note = meta.get("note", "")
    marked_by = meta.get("marked_by", "")
    marked_at = meta.get("marked_at", "")
    updated["triage_status"] = status
    updated["triage_note"] = note
    updated["triage_by"] = marked_by
    updated["triage_at"] = marked_at
    if status == TRIAGE_FALSE_POSITIVE:
        updated["suppressed_reason"] = note
        updated["suppressed_by"] = marked_by
        updated["suppressed_at"] = marked_at
    return updated


def _rebuild_session_per_repo() -> None:
    session = _current_session()
    with _state_lock:
        rebuilt: Dict[str, Any] = {}
        for slug, data in session.per_repo.items():
            rebuilt[slug] = None if data is None else []
        for slug in session.repo_slugs:
            rebuilt.setdefault(slug, [])
        for finding in session.findings:
            slug = finding.get("repo", "")
            if rebuilt.get(slug) is not None:
                rebuilt.setdefault(slug, []).append(finding)
        session.per_repo = rebuilt


def _invalidate_session_reports() -> None:
    session = _current_session()
    with _state_lock:
        reports = list((session.report_paths or {}).values())
        session.report_paths = {}
    for report in reports:
        if not isinstance(report, dict):
            continue
        for key in ("html", "csv"):
            fpath = report.get(key, "")
            if not fpath:
                continue
            try:
                path = Path(fpath)
                if path.exists():
                    path.unlink()
            except Exception:
                pass


def _persist_session_state() -> None:
    _rebuild_session_per_repo()
    snapshot = _current_session_snapshot()
    session = snapshot["session"]
    findings = list(snapshot["findings"])
    scan_id = snapshot["scan_id"]
    if scan_id:
        _save_history_record(session, findings)


def _cleanup_stale_temp_clones() -> None:
    _sync_scan_service_paths()
    _scan_service.cleanup_stale_temp_clones()


def _stop_active_scan() -> bool:
    session = _current_session()
    with _state_lock:
        if session.state != "running":
            return False
        session.stop_event.set()
    with session.proc_lock:
        for proc in list(session.proc_holder):
            try:
                proc.kill()
            except Exception:
                pass
        session.proc_holder.clear()
    pool = getattr(session, "_active_pool", None)
    if pool:
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            try:
                pool.shutdown(wait=False)
            except Exception:
                pass
    with _state_lock:
        session.state = "stopped"
    return True


def _request_app_shutdown() -> None:
    _stop_active_scan()
    _app_exit_event.set()
    server = _server_instance
    if server is not None:
        threading.Thread(target=server.shutdown, daemon=True).start()


def _run_scan(session: ScanSession):
    _sync_scan_service_paths()
    _scan_service.run_scan(
        session,
        client=_operator_state.client,
        save_history_record=_save_history_record,
    )


# ── HTTP handler ──────────────────────────────────────────────────────────────


class _Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args): pass   # silence access log

    def _require_browser_session(self):
        if not _has_valid_browser_session(self):
            self._redirect("/login")
            return True
        return False

    def _require_browser_api_session(self):
        if not _has_valid_browser_session(self):
            self._err(401, "Authentication required")
            return True
        return False

    def _serve_asset(self, filename: str):
        safe = Path(filename).name
        asset_path = ASSETS_DIR / safe
        if not asset_path.exists():
            return self._404()
        content_types = {
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
        }
        self._send(200, content_types.get(asset_path.suffix.lower(), "application/octet-stream"), asset_path.read_bytes())

    def _api_projects_get(self):
        if _Handler._require_browser_api_session(self):
            return
        if _require_role(self, ROLE_VIEWER):
            return
        self._json({
            "projects": filter_projects(_operator_state.projects_cache, _operator_state.ctx),
            "owner": _operator_state.connected_owner,
            "auth": _operator_state.public_auth(),
        })

    def _api_repos_get(self, parsed):
        if _Handler._require_browser_api_session(self):
            return
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(parsed.query)
        key = qs.get("project", [""])[0]
        if not key or not _operator_state.client:
            return self._json({"repos": []})
        if _require_project_access(self, key):
            return
        try:
            repos = _operator_state.repos_cache.get(key)
            if repos is None:
                repos = _operator_state.client.list_repos(key)
                _operator_state.repos_cache[key] = repos
            self._json({"repos": repos})
        except Exception as e:
            self._err(500, str(e))

    def _handle_page_get(self, parsed) -> bool:
        p = parsed.path
        if p in ("/", "/index.html", "/login"):
            if _is_connected() and p in ("/", "/index.html"):
                self._redirect("/scan")
            else:
                self._render_login_page()
            return True
        if p == "/scan":
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            qs = parse_qs(parsed.query)
            fresh_scan = (qs.get("new", [""])[0] or "").lower() in {"1", "true", "yes"}
            current_scan_id = _current_session_snapshot().get("scan_id", "")
            if fresh_scan or not current_scan_id:
                self._render_scan_page()
            else:
                self._redirect("/scan/" + quote(current_scan_id) + "?tab=activity")
            return True
        if p.startswith("/scan/"):
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            self._render_scan_workspace_page(p[6:])
            return True
        if p.startswith("/results/"):
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            self._redirect("/scan/" + quote(Path(p[9:]).name) + "?tab=results")
            return True
        if p == "/history":
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            self._render_history_page()
            return True
        if p == "/findings":
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            self._render_findings_page()
            return True
        if p == "/inventory":
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            self._render_inventory_page()
            return True
        if p == "/trends":
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            self._render_trends_page()
            return True
        if p == "/settings":
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            self._render_settings_page()
            return True
        if p == "/help":
            if not _is_connected():
                self._redirect("/login")
                return True
            if self._require_browser_session():
                return True
            self._render_help_page()
            return True
        if p.startswith("/assets/"):
            _Handler._serve_asset(self, p[8:])
            return True
        return False

    def _handle_api_get(self, parsed) -> bool:
        p = parsed.path
        if p == "/api/status":
            if _Handler._require_browser_api_session(self):
                return True
            llm_cfg = load_llm_config()
            llm_info = _ollama_snapshot(llm_cfg.get("base_url", "http://localhost:11434"), refresh=False)
            self._json({
                "ok": True,
                "version": APP_VERSION,
                "llm": llm_cfg,
                "ollama": {
                    "base_url": llm_info.get("base_url", ""),
                    "reachable": bool(llm_info.get("reachable", False)),
                    "models": list(llm_info.get("models", [])),
                    "stale": bool(llm_info.get("stale", False)),
                    "fetched_at": llm_info.get("fetched_at", 0),
                },
                "has_saved_pat": bool(load_pat()),
                "auth": _operator_state.public_auth(),
                "connected": _is_connected(),
            })
            return True
        if p == "/api/projects":
            _Handler._api_projects_get(self)
            return True
        if p == "/api/repos":
            _Handler._api_repos_get(self, parsed)
            return True
        if p == "/api/scan/status":
            if _Handler._require_browser_api_session(self):
                return True
            if _require_role(self, ROLE_VIEWER):
                return True
            snapshot = _current_session_snapshot(include_status=True)
            session = snapshot["session"]
            log_lines = list(snapshot["log_lines"])
            state = snapshot["state"]
            scan_id = snapshot["scan_id"]
            status = dict(snapshot.get("status") or session.to_status())
            status["phase_timeline"] = (
                _structured_phase_timeline(status.get("phase_metrics"), status.get("duration_s"), state)
                or _phase_timeline(log_lines, state)
            )
            status["log_url"] = f"/api/history/log/{scan_id}" if scan_id else ""
            status["hardware"] = _hardware_snapshot(session)
            status["llm_stats"] = _llm_stats(
                log_lines,
                state=state,
                llm_model=str(status.get("llm_model", "") or ""),
                llm_model_info=status.get("llm_model_info") or {},
            )
            self._json(status)
            return True
        if p.startswith("/api/report-generation/status/"):
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_VIEWER):
                return True
            safe_scan_id = Path(p.rsplit("/", 1)[-1]).name
            record = _scan_record_for_id(safe_scan_id)
            if not record:
                return self._err(404, "Scan results not found")
            project_key = str(record.get("project_key", "") or "")
            if project_key and _require_project_access(self, project_key):
                return True
            reports = dict((record.get("reports") or {}).get("__all__", {}) or {})
            html_name = str(reports.get("html_name", "") or "")
            status = _report_generation_status(safe_scan_id)
            if html_name and not status:
                status = {"state": "done", "message": "HTML report generated.", "current": 1, "total": 1}
            self._json({"scan_id": safe_scan_id, "html_name": html_name, **status})
            return True
        if p == "/api/history":
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_VIEWER):
                return True
            self._json({"history": list(reversed(_history_records_for_user()))})
            return True
        if p == "/api/suppressions":
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_VIEWER):
                return True
            self._json({"suppressions": list_suppressions(SUPPRESSIONS_FILE)})
            return True
        if p == "/api/triage":
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_VIEWER):
                return True
            self._json({"triage": list_triage(SUPPRESSIONS_FILE)})
            return True
        if p.startswith("/api/history/log/"):
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_VIEWER):
                return True
            self._serve_log(p[17:])
            return True
        if p == "/api/settings":
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_ADMIN):
                return True
            self._json({
                "bitbucket_url": BITBUCKET_URL,
                "tls": load_tls_config(),
                "output_dir": str(Path(OUTPUT_DIR).resolve()),
                "llm": load_llm_config(),
            })
            return True
        if p == "/api/scan/stream":
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_VIEWER):
                return True
            self._sse_stream()
            return True
        if p == "/api/ollama/models":
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_VIEWER):
                return True
            qs = parse_qs(parsed.query)
            if "url" in qs:
                self._err(400, "Overriding the Ollama URL is not allowed")
                return True
            url = load_llm_config().get("base_url", "http://localhost:11434").strip()
            refresh = (qs.get("refresh", [""])[0] or "").lower() in {"1", "true", "yes"}
            snapshot = _ollama_snapshot(url, refresh=refresh)
            self._json({
                "models": list(snapshot.get("models", [])),
                "base_url": snapshot.get("base_url", url),
                "reachable": bool(snapshot.get("reachable", False)),
                "stale": bool(snapshot.get("stale", False)),
                "fetched_at": snapshot.get("fetched_at", 0),
            })
            return True
        if p.startswith("/reports/"):
            if _Handler._require_browser_api_session(self) or _require_role(self, ROLE_VIEWER):
                return True
            self._serve_report(p[9:])
            return True
        return False

    # ── Routing ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_client_disconnect(exc: BaseException) -> bool:
        if isinstance(exc, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError)):
            return True
        if isinstance(exc, OSError) and getattr(exc, "winerror", None) in {10053, 10054}:
            return True
        return False

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            if _Handler._handle_page_get(self, parsed):
                return
            if _Handler._handle_api_get(self, parsed):
                return
            self._404()
        except Exception as exc:
            if _Handler._is_client_disconnect(exc):
                return
            raise

    def do_POST(self):
        try:
            p = urlparse(self.path).path
            body = self._read_body()
            exempt_paths = {"/login", "/connect", "/api/connect"}
            if p not in exempt_paths:
                if not _has_valid_browser_session(self):
                    return self._err(401, "Authentication required")
                if not _csrf_matches(self, body):
                    return self._err(403, "CSRF validation failed")
            if p in ("/login", "/connect"):
                return self._page_connect(body)
            elif p == "/app/exit":
                return self._page_app_exit()
            elif p == "/scan/start":
                return self._page_scan_start(body)
            elif p == "/scan/stop":
                return self._page_scan_stop()
            elif p.startswith("/scan/") and p.endswith("/generate-html"):
                return self._page_generate_html_report(p[6:-14], body)
            elif p.startswith("/scan/") and p.endswith("/replay-threat-model"):
                return self._page_replay_threat_model(p[6:-20], body)
            elif p == "/history/delete":
                return self._page_history_delete(body)
            elif p == "/findings/bulk":
                return self._page_findings_bulk(body)
            elif p == "/settings/save":
                return self._page_settings_save(body)
            elif p == "/findings/triage":
                return self._page_finding_triage(body)
            elif p == "/findings/reset":
                return self._page_finding_reset(body)
            if p == "/api/connect":
                self._api_connect(body)
            elif p == "/api/scan/start":
                self._api_scan_start(body)
            elif p == "/api/local-repo/pick":
                self._api_local_repo_pick()
            elif p == "/api/scan/stop":
                self._api_scan_stop()
            elif p == "/api/ollama/start":
                self._api_ollama_start(body)
            elif p in ("/api/ollama", "/ollama"):
                self._proxy_ollama(body)
            elif p == "/api/llm/config":
                self._api_llm_config(body)
            elif p == "/api/settings/save":
                self._api_settings_save(body)
            elif p == "/api/history/delete":
                self._api_history_delete(body)
            elif p == "/api/findings/suppress":
                self._api_finding_suppress(body)
            elif p == "/api/findings/unsuppress":
                self._api_finding_unsuppress(body)
            elif p == "/api/findings/triage":
                self._api_finding_triage(body)
            elif p == "/api/findings/reset":
                self._api_finding_reset(body)
            elif p == "/api/app/shutdown":
                self._api_app_shutdown()
            else:
                self._404()
        except Exception as exc:
            if _Handler._is_client_disconnect(exc):
                return
            raise

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    # ── Page handlers ─────────────────────────────────────────────────────────

    def _render_login_page(self, *, notice: str = "", error: str = ""):
        qs = parse_qs(urlparse(self.path).query)
        html = render_login_page(
            bitbucket_url=BITBUCKET_URL,
            has_saved_pat=bool(load_pat()),
            csrf_token=_current_csrf_token(self),
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_scan_page(
        self,
        *,
        notice: str = "",
        error: str = "",
        selected_repos: list[str] | None = None,
        selected_scan_scope: str | None = None,
        selected_compare_ref: str | None = None,
        selected_local_repo_path: str | None = None,
    ):
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(urlparse(self.path).query)
        snapshot = _current_session_snapshot(include_status=_is_connected(), log_limit=500)
        session_project_key = snapshot["project_key"]
        session_repo_slugs = list(snapshot["repo_slugs"])
        session_log_lines = list(snapshot["log_lines"])
        session_state = snapshot["state"]
        status = dict(snapshot.get("status") or {})
        session_scan_scope = str(status.get("scan_scope", snapshot["session"].scan_scope) or "full")
        session_compare_ref = str(status.get("compare_ref", snapshot["session"].compare_ref) or "")
        session_local_repo_path = str(status.get("local_repo_path", snapshot["session"].local_repo_path) or "")
        if _is_connected():
            status["hardware"] = _hardware_snapshot(snapshot["session"])
            status["llm_stats"] = _llm_stats(
                session_log_lines,
                state=session_state,
                llm_model=str(status.get("llm_model", "") or ""),
                llm_model_info=status.get("llm_model_info") or {},
            )
        project_key = (qs.get("project", [""])[0] or session_project_key or "").strip()
        fresh_scan = (qs.get("new", [""])[0] or "").lower() in {"1", "true", "yes"}
        if project_key and _require_project_access(self, project_key):
            return
        repos = _repos_for_project(project_key) if project_key else []
        if selected_repos is not None:
            effective_selected_repos = selected_repos
        elif fresh_scan:
            effective_selected_repos = []
        else:
            effective_selected_repos = list(session_repo_slugs) if project_key and project_key == session_project_key else []
        effective_scan_scope = selected_scan_scope if selected_scan_scope is not None else session_scan_scope
        effective_compare_ref = selected_compare_ref if selected_compare_ref is not None else session_compare_ref
        effective_local_repo_path = (
            selected_local_repo_path if selected_local_repo_path is not None else session_local_repo_path
        )
        html = render_scan_page(
            projects=filter_projects(_operator_state.projects_cache, _operator_state.ctx),
            selected_project=project_key,
            repos=repos,
            selected_repos=effective_selected_repos,
            selected_scan_scope=effective_scan_scope,
            selected_compare_ref=effective_compare_ref,
            status=status,
            llm_cfg=load_llm_config(),
            llm_models=_ollama_snapshot(load_llm_config().get("base_url", "http://localhost:11434"), refresh=False).get("models", []),
            log_text=_format_log_text(session_log_lines),
            phase_timeline=(
                _structured_phase_timeline(snapshot.get("status", {}).get("phase_metrics"), snapshot.get("scan_duration_s"), session_state)
                or _phase_timeline(session_log_lines, session_state)
            ),
            force_selection=fresh_scan,
            selected_local_repo_path=effective_local_repo_path,
            show_scan_results=_has_scan_results(),
            csrf_token=_current_csrf_token(self),
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_scan_workspace_page(self, scan_id: str, *, notice: str = "", error: str = ""):
        if _require_role(self, ROLE_VIEWER):
            return
        safe_scan_id = Path(scan_id).name
        qs = parse_qs(urlparse(self.path).query)
        tab = (qs.get("tab", ["activity"])[0] or "activity").strip().lower()
        if tab not in {"activity", "results"}:
            tab = "activity"
        record = _scan_record_for_id(safe_scan_id)
        if not record:
            return self._err(404, "Scan results not found")
        project_key = str(record.get("project_key", "") or "")
        if project_key and _require_project_access(self, project_key):
            return
        repo_slugs = list(record.get("repo_slugs", record.get("repos", [])) or [])
        report = (record.get("reports") or {}).get("__all__", {})

        with _state_lock:
            is_current = _current_session().scan_id == safe_scan_id
            if is_current:
                snapshot = _current_session_snapshot(include_status=_is_connected(), log_limit=500)
                session_log_lines = list(snapshot["log_lines"])
                status = dict(snapshot.get("status") or {})
                if _is_connected():
                    status["hardware"] = _hardware_snapshot(snapshot["session"])
                    status["llm_stats"] = _llm_stats(
                        session_log_lines,
                        state=snapshot["state"],
                        llm_model=str(status.get("llm_model", "") or ""),
                        llm_model_info=status.get("llm_model_info") or {},
                    )
                session_state = snapshot["state"]
            else:
                session_log_lines = []
                status = {}
                session_state = str(record.get("state", "") or "")

        if is_current:
            log_text = _format_log_text(session_log_lines)
            phase_timeline = (
                _structured_phase_timeline(snapshot.get("status", {}).get("phase_metrics"), snapshot.get("scan_duration_s"), session_state)
                or _phase_timeline(session_log_lines, session_state)
            )
        else:
            log_text = _get_log_text(safe_scan_id)
            parsed_entries = _parse_log_text_entries(log_text)
            phase_timeline = (
                _structured_phase_timeline(record.get("phase_metrics"), record.get("duration_s"), session_state)
                or _phase_timeline(parsed_entries, session_state)
            )
            status = {
                "scan_id": safe_scan_id,
                "state": session_state,
                "report": report,
                "scan_scope": str(record.get("scan_scope", "full") or "full"),
                "compare_ref": str(record.get("compare_ref", "") or ""),
                "delta": record.get("delta") or {},
                "inventory": record.get("inventory") or {},
                "hardware": {},
                "llm_model": str(record.get("llm_model", "") or ""),
                "total": int(record.get("total", record.get("finding_total", 0)) or 0),
                "suppressed_total": int(record.get("suppressed_total", 0) or 0),
                "phase_metrics": dict(record.get("phase_metrics") or {}),
                "repo_metrics": dict(record.get("repo_metrics") or {}),
                "llm_batch_metrics": list(record.get("llm_batch_metrics") or []),
                "cache_metrics": dict(record.get("cache_metrics") or {}),
                "errors": list(record.get("errors") or []),
            }
            status["llm_stats"] = _llm_stats(
                parsed_entries,
                state=session_state,
                llm_model=str(record.get("llm_model", "") or ""),
            )
        scan_complete = str(session_state or record.get("state", "")).lower() in {"done", "stopped", "error"}

        if tab == "results":
            if not scan_complete:
                return self._redirect(f"/scan/{quote(safe_scan_id)}?tab=activity")
            html_name = report.get("html_name", "")
            can_generate_html = bool(
                len(snapshot["findings"]) if is_current else len(list(record.get("findings") or []))
            )
            html_generation = _report_generation_status(safe_scan_id)
            if html_name and html_generation:
                _clear_report_generation_status(safe_scan_id)
                html_generation = {}
            repo_label = ", ".join(repo_slugs)
            html = render_results_page(
                scan_id=safe_scan_id,
                project_key=project_key,
                repo_label=repo_label,
                state=session_state or str(record.get("state", "done")),
                html_name=html_name,
                html_detail_mode=report.get("html_detail_mode", ""),
                csv_name=report.get("csv_name", ""),
                json_name=report.get("json_name", ""),
                sarif_name=report.get("sarif_name", ""),
                threat_dragon_name=report.get("threat_dragon_name", ""),
                log_url=f"/api/history/log/{safe_scan_id}",
                started_at_utc=str(record.get("started_at_utc", "") or ""),
                can_generate_html=can_generate_html,
                html_generation=html_generation,
                show_scan_results=_has_scan_results(),
                csrf_token=_current_csrf_token(self),
                notice=notice or (qs.get("notice", [""])[0] or ""),
                error=error or (qs.get("error", [""])[0] or ""),
            )
        else:
            html = render_scan_page(
                projects=filter_projects(_operator_state.projects_cache, _operator_state.ctx),
                selected_project=project_key,
                repos=[],
                selected_repos=repo_slugs,
                selected_scan_scope=str(record.get("scan_scope", "full") or "full"),
                selected_compare_ref=str(record.get("compare_ref", "") or ""),
                selected_local_repo_path=str(record.get("local_repo_path", "") or ""),
                status=status,
                llm_cfg=load_llm_config(),
                llm_models=_ollama_snapshot(load_llm_config().get("base_url", "http://localhost:11434"), refresh=False).get("models", []),
                log_text=log_text,
                phase_timeline=phase_timeline,
                force_selection=False,
                scan_id=safe_scan_id,
                workspace_tab="activity",
                force_activity_view=True,
                include_live_script=is_current,
                show_scan_results=_has_scan_results(),
                csrf_token=_current_csrf_token(self),
                notice=notice or (qs.get("notice", [""])[0] or ""),
                error=error or (qs.get("error", [""])[0] or ""),
            )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_history_page(self, *, notice: str = "", error: str = ""):
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(urlparse(self.path).query)
        html = render_history_page(
            history=list(reversed(_history_records_for_user())),
            csrf_token=_current_csrf_token(self),
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
            show_scan_results=_has_scan_results(),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_findings_page(self, *, notice: str = "", error: str = ""):
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(urlparse(self.path).query)
        html = render_findings_page(
            findings=_findings_for_user(),
            csrf_token=_current_csrf_token(self),
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
            show_scan_results=_has_scan_results(),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_results_page(self, scan_id: str, *, notice: str = "", error: str = ""):
        self._redirect("/scan/" + quote(Path(scan_id).name) + "?tab=results")

    def _render_inventory_page(self, *, notice: str = "", error: str = ""):
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(urlparse(self.path).query)
        repo_inventory, summary = _inventory_snapshot_for_user()
        html = render_inventory_page(
            repo_inventory=repo_inventory,
            summary=summary,
            csrf_token=_current_csrf_token(self),
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
            show_scan_results=_has_scan_results(),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_trends_page(self, *, notice: str = "", error: str = ""):
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(urlparse(self.path).query)
        html = render_trends_page(
            trends=compute_history_trends(list(reversed(_history_records_for_user()))),
            csrf_token=_current_csrf_token(self),
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
            show_scan_results=_has_scan_results(),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_settings_page(self, *, notice: str = "", error: str = ""):
        if _require_role(self, ROLE_ADMIN):
            return
        qs = parse_qs(urlparse(self.path).query)
        html = render_settings_page(
            bitbucket_url=BITBUCKET_URL,
            output_dir=str(Path(OUTPUT_DIR).resolve()),
            llm_cfg=load_llm_config(),
            tls_cfg=load_tls_config(),
            state_dir=str(STATE_DIR.resolve()),
            legacy_runtime_files=_legacy_runtime_artifacts(),
            csrf_token=_current_csrf_token(self),
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
            show_scan_results=_has_scan_results(),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_help_page(self, *, notice: str = "", error: str = ""):
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(urlparse(self.path).query)
        html = render_help_page(
            csrf_token=_current_csrf_token(self),
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
            show_scan_results=_has_scan_results(),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _page_connect(self, body: dict):
        try:
            connect_operator(
                body=body,
                bitbucket_url=BITBUCKET_URL,
                tls_config=load_tls_config(),
                operator_state=_operator_state,
                audit_event=_audit_event,
            )
        except Exception as e:
            return self._render_login_page(error=str(e))
        session_id, _csrf = _issue_browser_session()
        _queue_session_cookie(self, session_id)
        self._redirect(_with_query("/scan", new="1", notice="Connected to Bitbucket"))

    def _page_app_exit(self):
        if _require_role(self, ROLE_ADMIN):
            return
        _audit_event("app_shutdown_requested")
        _request_app_shutdown()
        body = b"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AI Scanner Stopped</title>
  <style>
    body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f6efe6;color:#3b2412;display:grid;place-items:center;min-height:100vh}
    .card{max-width:480px;background:#fffaf4;border:1px solid #e3c9ad;border-radius:16px;padding:24px;box-shadow:0 18px 42px rgba(50,25,0,.08)}
    h1{margin:0 0 10px;font-size:22px}
    p{margin:0 0 10px;line-height:1.45}
    .muted{color:#7a5a3d}
  </style>
</head>
<body>
  <section class="card">
    <h1>AI Scanner stopped</h1>
    <p>The local server has been shut down.</p>
    <p class="muted" id="close-note">Trying to close this tab...</p>
  </section>
  <script>
    (function () {
      window.open('', '_self');
      window.close();
      setTimeout(function () {
        var note = document.getElementById('close-note');
        if (note) {
          note.textContent = 'The app has stopped. You can close this tab.';
        }
      }, 500);
    })();
  </script>
</body>
</html>"""
        self._send(
            200,
            "text/html; charset=utf-8",
            body,
        )

    def _page_scan_start(self, body: dict):
        if _require_role(self, ROLE_SCANNER):
            return
        repo_slugs = body.get("repo_slugs", [])
        if isinstance(repo_slugs, str):
            repo_slugs = [repo_slugs]
        project_key = body.get("project_key", "").strip()
        local_repo_path = str(body.get("local_repo_path", "") or "").strip()
        if not local_repo_path and _require_project_access(self, project_key):
            return
        page_body = dict(body)
        page_body["repo_slugs"] = repo_slugs
        page_body["scan_scope"] = str(body.get("scan_scope", "full") or "full")
        page_body["compare_ref"] = str(body.get("compare_ref", "") or "")
        current_session = _current_session()
        try:
            new_session = start_scan(
                body=page_body,
                session_factory=ScanSession,
                current_session=current_session,
                operator_state=_operator_state,
                save_llm_config=save_llm_config,
                audit_event=_audit_event,
            )
            _replace_current_session(new_session)
        except (ValueError, PermissionError, RuntimeError) as e:
            self.path = _with_query("/scan", project=project_key, new="1")
            return self._render_scan_page(
                error=str(e),
                selected_repos=repo_slugs,
                selected_scan_scope=page_body["scan_scope"],
                selected_compare_ref=page_body["compare_ref"],
                selected_local_repo_path=local_repo_path,
            )
        threading.Thread(target=_run_scan, args=(new_session,), daemon=True).start()
        self._redirect(_with_query(f"/scan/{new_session.scan_id}", tab="activity", notice="Scan started"))

    def _page_scan_stop(self):
        if _require_role(self, ROLE_SCANNER):
            return
        current_session = _current_session()
        stop_scan(current_session=current_session, stop_scan_fn=_stop_active_scan, audit_event=_audit_event)
        target = f"/scan/{current_session.scan_id}" if current_session.scan_id else "/scan"
        extra = {"tab": "activity"} if current_session.scan_id else {"new": "1"}
        self._redirect(_with_query(target, notice="Stop requested", **extra))

    def _page_generate_html_report(self, scan_id: str, body: dict):
        if _require_role(self, ROLE_VIEWER):
            return
        safe_scan_id = Path(scan_id).name
        record = _scan_record_for_id(safe_scan_id)
        if not record:
            return self._err(404, "Scan results not found")
        project_key = str(record.get("project_key", "") or "")
        if project_key and _require_project_access(self, project_key):
            return
        detail_mode = "fast" if str((body or {}).get("html_detail_mode", "") or "").strip().lower() == "fast" else "detailed"
        mode_label = "Fast" if detail_mode == "fast" else "Detailed"
        try:
            _start_html_report_generation(safe_scan_id, detail_mode=detail_mode)
        except Exception as e:
            self._redirect(_with_query(f"/scan/{safe_scan_id}", tab="results", error=str(e)))
            return
        self._redirect(_with_query(f"/scan/{safe_scan_id}", tab="results", notice=f"{mode_label} HTML report generation started"))

    def _page_replay_threat_model(self, scan_id: str, body: dict):
        if _require_role(self, ROLE_VIEWER):
            return
        safe_scan_id = Path(scan_id).name
        record = _scan_record_for_id(safe_scan_id)
        if not record:
            return self._err(404, "Scan results not found")
        project_key = str(record.get("project_key", "") or "")
        if project_key and _require_project_access(self, project_key):
            return
        replay_instructions = str(body.get("replay_instructions", "") or "").strip()
        try:
            snapshot = _current_session_snapshot()
            findings = list(snapshot["findings"]) if snapshot["scan_id"] == safe_scan_id else None
            updated = _scan_service.replay_threat_model(
                safe_scan_id,
                findings=findings,
                replay_instructions=replay_instructions,
            )
            if snapshot["scan_id"] == safe_scan_id:
                with _state_lock:
                    current = _current_session()
                    current.report_paths = dict(updated.get("reports") or {})
        except Exception as e:
            self._redirect(_with_query(f"/scan/{safe_scan_id}", tab="results", error=str(e)))
            return
        self._redirect(_with_query(f"/scan/{safe_scan_id}", tab="results", notice="Threat model replayed; regenerate HTML if you want the report refreshed"))

    def _page_history_delete(self, body: dict):
        if _require_role(self, ROLE_ADMIN):
            return
        scan_ids = body.get("scan_ids", [])
        if isinstance(scan_ids, str):
            scan_ids = [scan_ids]
        managed_roots = [Path(OUTPUT_DIR).resolve(), Path(LOG_DIR).resolve()]
        try:
            result = delete_history_records(
                body={"scan_ids": scan_ids},
                history_records=_history_records_for_user(),
                delete_managed_file=lambda path_str, sid, artifact: _delete_managed_history_file(path_str, sid, artifact, roots=managed_roots),
                delete_history=_delete_history,
                audit_event=_audit_event,
            )
        except Exception as e:
            return self._render_history_page(error=str(e))
        if result["errors"]:
            return self._render_history_page(error="; ".join(result["errors"]))
        self._redirect(_with_query("/history", notice=f"Deleted {len(result['deleted'])} scan record(s)"))

    def _page_findings_bulk(self, body: dict):
        if _require_role(self, ROLE_TRIAGE):
            return
        hashes = [str(value).strip() for value in list(body.get("hashes", [])) if str(value).strip()]
        action = str(body.get("action", "") or "").strip()
        note = str(body.get("note", "") or "").strip()
        if not hashes:
            return self._render_findings_page(error="Select at least one finding.")
        if action not in {"reviewed", "accepted_risk", "false_positive", "reset"}:
            return self._render_findings_page(error="Choose a valid bulk action.")
        if action in {"accepted_risk", "false_positive"} and not note:
            return self._render_findings_page(error="A note is required for Accept Risk and Suppress.")

        triage_lookup = _triage_by_hash()
        findings_by_hash = {item.get("hash", ""): item for item in _findings_for_user() if item.get("hash")}
        current_session = _current_session()

        for hash_ in hashes:
            finding = findings_by_hash.get(hash_)
            if action == "reset":
                remove_triage(SUPPRESSIONS_FILE, hash_)
                if current_session:
                    with current_session.state_lock:
                        active = next((f for f in current_session.findings if f.get("_hash") == hash_), None)
                        suppressed = next((f for f in current_session.suppressed_findings if f.get("_hash") == hash_), None)
                        current_session.findings = [f for f in current_session.findings if f.get("_hash") != hash_]
                        current_session.suppressed_findings = [f for f in current_session.suppressed_findings if f.get("_hash") != hash_]
                        if active:
                            current_session.findings.append(_clear_finding_triage(active))
                        elif suppressed:
                            current_session.findings.append(_clear_finding_triage(suppressed))
                        current_session.findings.sort(key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", "")))
                _audit_event("finding_reset", scan_id=_current_session_snapshot().get("scan_id", ""), finding_hash=hash_, removed=True)
                continue

            if not finding:
                continue
            payload = {
                "_hash": hash_,
                "repo": finding.get("repo", ""),
                "file": finding.get("file", ""),
                "line": finding.get("line", ""),
                "provider_or_lib": finding.get("rule", ""),
                "description": finding.get("description", ""),
            }
            upsert_triage(
                SUPPRESSIONS_FILE,
                payload,
                status=action,
                note=note if action in {"accepted_risk", "false_positive"} else "",
                marked_by=_operator_state.ctx.username,
            )
            triage_meta = triage_lookup.get(hash_, {})
            if current_session:
                with current_session.state_lock:
                    active = next((f for f in current_session.findings if f.get("_hash") == hash_), None)
                    suppressed = next((f for f in current_session.suppressed_findings if f.get("_hash") == hash_), None)
                    target = active or suppressed
                    if target:
                        updated = _apply_triage_metadata(target, triage_by_hash(SUPPRESSIONS_FILE).get(hash_, triage_meta))
                        current_session.findings = [f for f in current_session.findings if f.get("_hash") != hash_]
                        current_session.suppressed_findings = [f for f in current_session.suppressed_findings if f.get("_hash") != hash_]
                        if action == TRIAGE_FALSE_POSITIVE:
                            current_session.suppressed_findings.append(updated)
                        else:
                            current_session.findings.append(updated)
                            current_session.findings.sort(key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", "")))
            _audit_event("finding_triage", scan_id=_current_session_snapshot().get("scan_id", ""), finding_hash=hash_, triage_status=action, note=note)

        _persist_session_state()
        self._redirect(_with_query("/findings", notice=f"Updated {len(hashes)} finding(s)"))

    def _page_settings_save(self, body: dict):
        if _require_role(self, ROLE_ADMIN):
            return
        try:
            llm_url = body.get("llm_url", "").strip()
            llm_model = body.get("llm_model", "").strip()
            report_detail_timeout_s = body.get("report_detail_timeout_s", "").strip()
            output_dir = body.get("output_dir", "").strip()
            bitbucket_verify_ssl = bool(body.get("bitbucket_verify_ssl"))
            bitbucket_ca_bundle = body.get("bitbucket_ca_bundle", "").strip()
            tls_result = _settings_service.save_tls_settings(
                verify_ssl=bitbucket_verify_ssl,
                ca_bundle=bitbucket_ca_bundle,
            )
            _apply_tls_settings_to_connected_client(tls_result)
            if llm_url or llm_model:
                _settings_service.save_llm_settings(
                    llm_url=llm_url,
                    llm_model=llm_model,
                    report_detail_timeout_s=report_detail_timeout_s,
                )
            if output_dir:
                is_scan_running = _current_session_snapshot().get("state") == "running"
                _settings_service.save_output_dir(
                    output_dir=output_dir,
                    is_scan_running=is_scan_running,
                    set_paths=_set_output_paths,
                )
        except Exception as e:
            return self._render_settings_page(error=str(e))
        self._redirect(_with_query("/settings", notice="Settings saved"))

    def _page_finding_triage(self, body: dict):
        if _require_role(self, ROLE_TRIAGE):
            return
        try:
            triage_finding(
                body=body,
                session=_current_session(),
                suppressions_file=SUPPRESSIONS_FILE,
                triage_lookup=_triage_by_hash,
                apply_triage_metadata=_apply_triage_metadata,
                persist_session_state=_persist_session_state,
                marked_by=_operator_state.ctx.username,
                audit_event=_audit_event,
            )
        except Exception as e:
            return self._render_scan_page(error=str(e))
        current_scan_id = _current_session_snapshot().get("scan_id", "")
        target = f"/scan/{current_scan_id}" if current_scan_id else "/scan"
        extra = {"tab": "activity"} if current_scan_id else {"new": "1"}
        self._redirect(_with_query(target, notice="Finding triage updated", **extra))

    def _page_finding_reset(self, body: dict):
        if _require_role(self, ROLE_TRIAGE):
            return
        try:
            reset_finding(
                body=body,
                session=_current_session(),
                suppressions_file=SUPPRESSIONS_FILE,
                clear_finding_triage=_clear_finding_triage,
                persist_session_state=_persist_session_state,
                audit_event=_audit_event,
            )
        except Exception as e:
            return self._render_scan_page(error=str(e))
        current_scan_id = _current_session_snapshot().get("scan_id", "")
        target = f"/scan/{current_scan_id}" if current_scan_id else "/scan"
        extra = {"tab": "activity"} if current_scan_id else {"new": "1"}
        self._redirect(_with_query(target, notice="Finding triage reset", **extra))

    # ── API handlers ──────────────────────────────────────────────────────────

    def _api_connect(self, body: dict):
        try:
            response = connect_operator(
                body=body,
                bitbucket_url=BITBUCKET_URL,
                tls_config=load_tls_config(),
                operator_state=_operator_state,
                audit_event=_audit_event,
            )
            session_id, csrf_token = _issue_browser_session()
            _queue_session_cookie(self, session_id)
            payload = dict(response)
            payload["csrf_token"] = csrf_token
            self._json(payload)
        except ValueError as e:
            self._err(400, str(e))
        except Exception as e:
            _audit_event("connect", outcome="error", error=str(e))
            self._err(401, str(e))

    def _api_scan_start(self, body: dict):
        if _require_role(self, ROLE_SCANNER):
            return
        project_key = body.get("project_key", "").strip()
        local_repo_path = str(body.get("local_repo_path", "") or "").strip()
        if not local_repo_path and _require_project_access(self, project_key):
            return
        current_session = _current_session()
        try:
            new_session = start_scan(
                body=body,
                session_factory=ScanSession,
                current_session=current_session,
                operator_state=_operator_state,
                save_llm_config=save_llm_config,
                audit_event=_audit_event,
            )
            _replace_current_session(new_session)
        except ValueError as e:
            return self._err(400, str(e))
        except PermissionError as e:
            return self._err(401, str(e))
        except RuntimeError as e:
            return self._err(409, str(e))
        threading.Thread(target=_run_scan, args=(new_session,),
                         daemon=True).start()
        self._json({"ok": True, "scan_id": new_session.scan_id})

    def _api_scan_stop(self):
        if _require_role(self, ROLE_SCANNER):
            return
        current_session = _current_session()
        self._json(stop_scan(
            current_session=current_session,
            stop_scan_fn=_stop_active_scan,
            audit_event=_audit_event,
        ))

    def _api_local_repo_pick(self):
        if _require_role(self, ROLE_SCANNER):
            return
        try:
            selected = _pick_local_repo_path()
        except RuntimeError as e:
            self._err(500, str(e))
            return
        self._json({"ok": True, "path": selected})

    def _api_app_shutdown(self):
        if _require_role(self, ROLE_ADMIN):
            return
        _audit_event("app_shutdown_requested")
        _request_app_shutdown()
        self._json({"ok": True})


    def _api_llm_config(self, body: dict):
        if _require_role(self, ROLE_ADMIN):
            return
        url = body.get("base_url", "").strip()
        model = body.get("model", "").strip()
        report_detail_timeout_s = body.get("report_detail_timeout_s", "").strip()
        if not url or not model:
            return self._err(400, "base_url and model required")
        self._json(_settings_service.save_llm_settings(
            llm_url=url,
            llm_model=model,
            report_detail_timeout_s=report_detail_timeout_s,
        ))

    def _sse_stream(self):
        """Stream log lines as Server-Sent Events."""
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self._cors()
            self.end_headers()
        except Exception as exc:
            if _Handler._is_client_disconnect(exc):
                return
            raise

        # Snapshot the backlog and remember its length.
        # The queue may already contain some of these same entries —
        # we skip the first backlog_len items from the queue to avoid duplicates.
        snapshot = _current_session_snapshot()
        session = snapshot["session"]
        backlog = list(snapshot["log_lines"])
        backlog_len  = len(backlog)
        queue_skip   = backlog_len   # items to skip from queue (already sent)

        for entry in backlog:
            if not self._sse_write(entry):
                return

        # Stream new entries, skipping any that overlap with the backlog
        while True:
            if session.log_queue.empty():
                try:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                except Exception as exc:
                    if _Handler._is_client_disconnect(exc):
                        return
                    raise
                if session.state in ("done", "stopped", "error"):
                    break
                continue
            try:
                entry = session.log_queue.get(timeout=1.0)
                if queue_skip > 0:
                    queue_skip -= 1   # this entry was already in the backlog
                else:
                    if not self._sse_write(entry):
                        break
                if session.state in ("done", "stopped", "error"):
                    while not session.log_queue.empty():
                        try:
                            e2 = session.log_queue.get_nowait()
                            if queue_skip > 0:
                                queue_skip -= 1
                            else:
                                if not self._sse_write(e2):
                                    return
                        except queue.Empty:
                            break
                    break
            except queue.Empty:
                if session.state in ("done", "stopped", "error"):
                    break
                continue

    def _sse_write(self, entry: dict):
        line = _format_log_entry(entry)
        if not line:
            return True
        data = json.dumps(line)
        try:
            self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            return False

    def _serve_report(self, filename: str):
        """Serve a file from OUTPUT_DIR by name."""
        safe = Path(filename).name   # strip any path traversal
        if _find_history_record_by_report_name(safe) is None:
            return self._err(403, "Report access denied")
        path = Path(OUTPUT_DIR).resolve() / safe
        if not path.exists():
            return self._404()
        ct = "text/html; charset=utf-8" if safe.endswith(".html") else "text/csv"
        self._send(200, ct, path.read_bytes())

    def _serve_log(self, scan_id: str):
        """Serve a scan log file by scan_id."""
        safe = Path(scan_id.replace("/","").replace("\\","")).name
        if _find_history_record_by_scan_id(safe) is None:
            return self._err(403, "Log access denied")
        log_text = _get_log_text(safe)
        if not log_text:
            return self._err(404, "Log not found")
        body = log_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{safe}.txt"')
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            return

    def _api_settings_save(self, body: dict):
        global OUTPUT_DIR, HISTORY_FILE, LOG_DIR, DB_FILE, AUDIT_FILE
        if _require_role(self, ROLE_ADMIN):
            return
        llm_url    = body.get("llm_url", "").strip()
        llm_model  = body.get("llm_model", "").strip()
        report_detail_timeout_s = body.get("report_detail_timeout_s", "").strip()
        output_dir = body.get("output_dir", "").strip()
        bitbucket_verify_ssl = bool(body.get("bitbucket_verify_ssl"))
        bitbucket_ca_bundle = body.get("bitbucket_ca_bundle", "").strip()
        try:
            tls_result = _settings_service.save_tls_settings(
                verify_ssl=bitbucket_verify_ssl,
                ca_bundle=bitbucket_ca_bundle,
            )
            _apply_tls_settings_to_connected_client(tls_result)
        except Exception as e:
            return self._err(400, str(e))
        if llm_url and llm_model:
            _settings_service.save_llm_settings(
                llm_url=llm_url,
                llm_model=llm_model,
                report_detail_timeout_s=report_detail_timeout_s,
            )
        if output_dir:
            try:
                is_scan_running = _current_session_snapshot().get("state") == "running"
                result = _settings_service.save_output_dir(
                    output_dir=output_dir,
                    is_scan_running=is_scan_running,
                    set_paths=lambda p: _set_output_paths(p),
                )
            except Exception as e:
                return self._err(400, str(e))
            result.update({
                "verify_ssl": tls_result["verify_ssl"],
                "ca_bundle": tls_result["ca_bundle"],
            })
            return self._json(result)
        self._json({
            "ok": True,
            "output_dir": str(Path(OUTPUT_DIR).resolve()),
            "verify_ssl": tls_result["verify_ssl"],
            "ca_bundle": tls_result["ca_bundle"],
        })

    def _api_history_delete(self, body: dict):
        """Delete one or more history records plus their associated files."""
        if _require_role(self, ROLE_ADMIN):
            return
        managed_roots = [Path(OUTPUT_DIR).resolve(), Path(LOG_DIR).resolve()]
        try:
            self._json(delete_history_records(
                body=body,
                history_records=_history_records_for_user(),
                delete_managed_file=lambda path_str, sid, artifact: _delete_managed_history_file(path_str, sid, artifact, roots=managed_roots),
                delete_history=_delete_history,
                audit_event=_audit_event,
            ))
        except ValueError as e:
            return self._err(400, str(e))
        except Exception as e:
            return self._err(500, f"Failed to update stored history: {e}")

    def _api_finding_triage(self, body: dict):
        if _require_role(self, ROLE_TRIAGE):
            return
        try:
            self._json(triage_finding(
                body=body,
                session=_current_session(),
                suppressions_file=SUPPRESSIONS_FILE,
                triage_lookup=_triage_by_hash,
                apply_triage_metadata=_apply_triage_metadata,
                persist_session_state=_persist_session_state,
                marked_by=_operator_state.ctx.username,
                audit_event=_audit_event,
            ))
        except ValueError as e:
            return self._err(400, str(e))
        except LookupError as e:
            return self._err(404, str(e))

    def _api_finding_reset(self, body: dict):
        if _require_role(self, ROLE_TRIAGE):
            return
        try:
            self._json(reset_finding(
                body=body,
                session=_current_session(),
                suppressions_file=SUPPRESSIONS_FILE,
                clear_finding_triage=_clear_finding_triage,
                persist_session_state=_persist_session_state,
                audit_event=_audit_event,
            ))
        except ValueError as e:
            return self._err(400, str(e))

    def _api_finding_suppress(self, body: dict):
        body = dict(body)
        body["status"] = TRIAGE_FALSE_POSITIVE
        body["note"] = body.get("reason", body.get("note", ""))
        return _Handler._api_finding_triage(self, body)

    def _api_finding_unsuppress(self, body: dict):
        return _Handler._api_finding_reset(self, body)

    def _api_ollama_start(self, body: dict):
        """Start Ollama if not running, then return available models."""
        if _require_role(self, ROLE_ADMIN):
            return
        url = body.get("url", "").strip() or               load_llm_config().get("base_url", "http://localhost:11434")
        self._json(_settings_service.start_ollama(url=url))


    def _proxy_ollama(self, body: dict):
        if _require_role(self, ROLE_VIEWER):
            return
        status, ct, payload = _settings_service.proxy_ollama(body)
        self._send(status, ct, payload)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        raw = self.rfile.read(length)
        content_type = (self.headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
        if content_type == "application/x-www-form-urlencoded":
            parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            body = {}
            list_keys = {"repo_slugs", "scan_ids", "hashes"}
            for key, values in parsed.items():
                if key in list_keys:
                    body[key] = values
                else:
                    body[key] = values[0] if len(values) == 1 else values
            return body
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", body)

    def _err(self, status: int, msg: str):
        self._json({"error": msg}, status)

    def _send(self, status: int, ct: str, body: bytes):
        try:
            self.send_response(status)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            for cookie in getattr(self, "_response_cookies", []) or []:
                self.send_header("Set-Cookie", cookie)
            self._cors()
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            if _Handler._is_client_disconnect(exc):
                self.close_connection = True
                return
            raise
        finally:
            self._response_cookies = []

    def _redirect(self, location: str):
        body = b""
        try:
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            for cookie in getattr(self, "_response_cookies", []) or []:
                self.send_header("Set-Cookie", cookie)
            self._cors()
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            if _Handler._is_client_disconnect(exc):
                self.close_connection = True
                return
            raise
        finally:
            self._response_cookies = []

    def _404(self):
        self.send_response(404)
        self.end_headers()

    def _cors(self):
        origin = _allowed_origin(self.headers.get("Origin", ""))
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

# ── Server startup ────────────────────────────────────────────────────────────

def start(port: int = APP_PORT, open_browser: bool = True) -> http.server.ThreadingHTTPServer:
    global _server_instance
    _app_exit_event.clear()
    _cleanup_stale_temp_clones()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    _server_instance = server


    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    url = f"http://127.0.0.1:{port}/"
    print(f"  AI Scanner -> {url}")
    legacy_runtime_files = _legacy_runtime_artifacts()
    if legacy_runtime_files:
        print("  Warning: legacy repo-root runtime files were found. The app now uses the state directory below.")
        print(f"  Active state dir -> {Path(STATE_DIR).resolve()}")
        for item in legacy_runtime_files:
            print(f"  Legacy file     -> {item['legacy_path']}")

    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    return server


def wait_for_exit(timeout: Optional[float] = None) -> bool:
    return _app_exit_event.wait(timeout)


if __name__ == "__main__":
    srv = start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
        print("Server stopped.")


