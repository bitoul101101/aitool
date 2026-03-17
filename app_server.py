"""
app_server.py
─────────────
Single-file web application server for the AI Security & Compliance Scanner.

Serves a simple server-rendered web UI with targeted dynamic endpoints.

Routes
──────
GET  /                → scan page (HTML)
GET  /scan            → scan page (HTML)
GET  /history         → history page (HTML)
GET  /settings        → settings page (HTML)
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
import threading
import tempfile
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse
from dateutil import tz

# ── Project imports ───────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent))

from scanner.pat_store import load_pat
from scanner.suppressions import (
    TRIAGE_FALSE_POSITIVE,
    list_suppressions,
    list_triage,
    triage_by_hash,
)
from services.access_control import (
    ROLE_ADMIN,
    ROLE_SCANNER,
    ROLE_TRIAGE,
    ROLE_VIEWER,
    filter_projects,
)
from services.audit_log import AuditLogService
from services.api_actions import (
    connect_operator,
    delete_history_records,
    reset_finding,
    start_scan,
    stop_scan,
    triage_finding,
)
from services.report_access import (
    find_history_record_by_report_name,
    find_history_record_by_scan_id,
    history_records_for_context,
)
from services.scan_jobs import ScanJobPaths, ScanJobService, ScanSession
from services.settings_service import SettingsService
from services.single_user_state import SingleUserState, load_single_user_config
from services.web_pages import render_history_page, render_login_page, render_scan_page, render_settings_page
from services.runtime_support import (
    ensure_ollama_running,
    load_llm_config as load_llm_config_file,
    ollama_list_models,
    ollama_ping,
    save_llm_config as save_llm_config_file,
)

# ── Constants ─────────────────────────────────────────────────────────────────
BITBUCKET_URL = "https://bitbucket.cognyte.local:8443"
_BASE_DIR     = Path(__file__).parent          # always relative to script
OUTPUT_DIR    = str(_BASE_DIR / "output")      # mutable at runtime via settings
POLICY_FILE   = str(_BASE_DIR / "policy.json")
OWNER_MAP_FILE = str(_BASE_DIR / "owner_map.json")
SUPPRESSIONS_FILE = str(_BASE_DIR / "ai_scanner_suppressions.json")
LLM_CFG_FILE  = str(_BASE_DIR / "ai_scanner_llm_config.json")
ACCESS_FILE   = str(_BASE_DIR / "access_control.json")
APP_PORT      = 5757   # fixed port for the app (report servers use random ports)
APP_VERSION   = "19.1"
ISRAEL_TZ = tz.gettz("Asia/Jerusalem")


def _default_temp_dir(os_name: Optional[str] = None,
                      temp_root: Optional[str] = None) -> Path:
    current_os = os_name or os.name
    if current_os == "nt":
        root = Path(temp_root or tempfile.gettempdir())
        return root / "ai_scanner_tmp"
    return _BASE_DIR / "tmp_clones"


TEMP_DIR      = str(_default_temp_dir())


# ── Utility helpers (lifted from main.py) ─────────────────────────────────────

def load_policy(path):
    try:
        return json.loads(Path(path).read_text("utf-8"))
    except Exception:
        return {}

def load_owner_map(path):
    try:
        return json.loads(Path(path).read_text("utf-8"))
    except Exception:
        return {}

def load_llm_config() -> dict:
    return load_llm_config_file(LLM_CFG_FILE)

def save_llm_config(cfg: dict) -> None:
    save_llm_config_file(LLM_CFG_FILE, cfg)


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


OLLAMA_START_TIMEOUT = 15   # seconds to wait for ollama serve to become ready


def _ollama_ensure_running(base_url: str) -> dict:
    ok, status = ensure_ollama_running(base_url, timeout_s=OLLAMA_START_TIMEOUT)
    if ok:
        return {"ok": True, "status": status}
    return {"ok": False, "error": status}


# ── Global app state ──────────────────────────────────────────────────────────

_session: ScanSession = ScanSession()
_operator_state = SingleUserState(load_single_user_config(ACCESS_FILE))
_state_lock = threading.Lock()
_app_exit_event = threading.Event()
_server_instance: Optional[http.server.ThreadingHTTPServer] = None


# ── Scan job service ─────────────────────────────────────────────────────────

HISTORY_FILE = str(_BASE_DIR / "output" / "scan_history.json")
LOG_DIR = str(_BASE_DIR / "output" / "logs")
DB_FILE = str(_BASE_DIR / "output" / "scan_jobs.db")
AUDIT_FILE = str(_BASE_DIR / "output" / "audit_events.jsonl")
_audit_log = AuditLogService(AUDIT_FILE)

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


def _save_history_record(session, findings):
    _sync_scan_service_paths()
    _scan_service.save_history_record(session, findings)


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
        return path.name == f"{scan_id}.log" and path.parent.name.lower() == "logs"
    if artifact == "html":
        return path.suffix.lower() == ".html" and path.name.lower().startswith("ai_scan_")
    if artifact == "csv":
        return path.suffix.lower() == ".csv" and path.name.lower().startswith("ai_scan_")
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
    records = history_records_for_context(_load_history(), _operator_state.ctx)
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


def _find_history_record_by_scan_id(scan_id: str) -> dict | None:
    return find_history_record_by_scan_id(_history_records_for_user(), scan_id)


def _find_history_record_by_report_name(filename: str) -> dict | None:
    return find_history_record_by_report_name(_history_records_for_user(), filename)


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


def _current_session_history_record() -> dict | None:
    if not _session.scan_id or _session.state not in {"running", "stopped"}:
        return None
    findings = list(_session.findings)
    critical_prod = sum(
        1 for f in findings
        if f.get("severity") == 1 and str(f.get("context", "production")).lower() == "production"
    )
    high_prod = sum(
        1 for f in findings
        if f.get("severity") == 2 and str(f.get("context", "production")).lower() == "production"
    )
    return {
        "scan_id": _session.scan_id,
        "project_key": _session.project_key,
        "repo_slugs": list(_session.repo_slugs),
        "state": _session.state,
        "started_at_utc": _session.started_at_utc,
        "completed_at_utc": _session.completed_at_utc,
        "total": len(findings),
        "active_total": len(findings),
        "suppressed_total": len(_session.suppressed_findings),
        "llm_model": _session.llm_model,
        "duration_s": _session.scan_duration_s,
        "critical_prod": critical_prod,
        "high_prod": high_prod,
        "reports": _session.report_paths,
        "log_file": "",
    }


def _format_log_text(entries: list[dict]) -> str:
    return "\n".join(_format_log_entry(entry) for entry in entries if _format_log_entry(entry))


def _format_log_entry(entry: dict) -> str:
    ts = entry.get("ts")
    try:
        stamp = (
            datetime.fromtimestamp(float(ts), ISRAEL_TZ).strftime("%H:%M:%S")
            if ISRAEL_TZ
            else datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
        )
    except Exception:
        stamp = "--:--:--"
    msg = str(entry.get("msg", "")).strip()
    if not msg:
        return ""
    return f"[{stamp}] {msg}"


def _phase_timeline(entries: list[dict], state: str = "") -> list[dict]:
    if not entries:
        return []
    state = (state or "").lower()
    first_ts = float(entries[0].get("ts") or time.time())
    markers = {
        "init": first_ts,
        "clone": None,
        "scan": None,
        "llm review": None,
        "report": None,
        "end": float(entries[-1].get("ts") or first_ts),
    }
    for entry in entries:
        msg = str(entry.get("msg", ""))
        ts = float(entry.get("ts") or first_ts)
        if markers["clone"] is None and "branch:" in msg:
            markers["clone"] = ts
        if markers["scan"] is None and "Starting parallel scan" in msg:
            markers["scan"] = ts
        if markers["llm review"] is None and "[LLM]" in msg and ("Evaluating" in msg or "Reviewing" in msg):
            markers["llm review"] = ts
        if markers["report"] is None and "Generating reports" in msg:
            markers["report"] = ts
        if "Scan complete." in msg or "Scan stopped." in msg:
            markers["end"] = ts
    points = [
        ("init", markers["init"], markers["clone"] or markers["scan"] or markers["end"]),
        ("clone", markers["clone"], markers["scan"] or markers["llm review"] or markers["report"] or markers["end"]),
        ("scan", markers["scan"], markers["llm review"] or markers["report"] or markers["end"]),
        ("llm review", markers["llm review"], markers["report"] or markers["end"]),
        ("report", markers["report"], markers["end"]),
    ]
    timeline = []
    active_name = ""
    started_names = [name for name, start, _ in points if start is not None]
    if state == "running" and started_names:
        active_name = started_names[-1]
    for name, start, end in points:
        if start is None:
            timeline.append({"name": name, "duration": "—", "state": "pending"})
            continue
        seconds = max(int((end or start) - start), 0)
        phase_state = "done"
        if state in ("stopped", "error") and name == active_name:
            phase_state = "stopped"
        elif state == "running" and name == active_name:
            phase_state = "running"
        timeline.append({"name": name, "duration": f"{seconds // 60:02d}:{seconds % 60:02d}", "state": phase_state})
    total_seconds = max(int(markers["end"] - first_ts), 0)
    total_state = "running" if state == "running" else "stopped" if state in ("stopped", "error") else "done"
    timeline.append({"name": "total", "duration": f"{total_seconds // 60:02d}:{total_seconds % 60:02d}", "state": total_state})
    return timeline


_settings_service = SettingsService(
    load_llm_config=load_llm_config,
    save_llm_config=save_llm_config,
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
    rebuilt: Dict[str, Any] = {}
    for slug, data in _session.per_repo.items():
        rebuilt[slug] = None if data is None else []
    for slug in _session.repo_slugs:
        rebuilt.setdefault(slug, [])
    for finding in _session.findings:
        slug = finding.get("repo", "")
        if rebuilt.get(slug) is not None:
            rebuilt.setdefault(slug, []).append(finding)
    _session.per_repo = rebuilt


def _invalidate_session_reports() -> None:
    for report in (_session.report_paths or {}).values():
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
    _session.report_paths = {}


def _persist_session_state() -> None:
    _rebuild_session_per_repo()
    _invalidate_session_reports()
    if _session.scan_id:
        _save_history_record(_session, _session.findings)


def _cleanup_stale_temp_clones() -> None:
    _sync_scan_service_paths()
    _scan_service.cleanup_stale_temp_clones()


def _stop_active_scan() -> bool:
    if _session.state != "running":
        return False
    _session.stop_event.set()
    with _session.proc_lock:
        for proc in list(_session.proc_holder):
            try:
                proc.kill()
            except Exception:
                pass
        _session.proc_holder.clear()
    pool = getattr(_session, "_active_pool", None)
    if pool:
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            try:
                pool.shutdown(wait=False)
            except Exception:
                pass
    _session.state = "stopped"
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

    # ── Routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path
        if p in ("/", "/index.html", "/login"):
            if _is_connected() and p in ("/", "/index.html"):
                return self._redirect("/scan")
            self._render_login_page()
        elif p == "/scan":
            if not _is_connected():
                return self._redirect("/login")
            self._render_scan_page()
        elif p == "/history":
            if not _is_connected():
                return self._redirect("/login")
            self._render_history_page()
        elif p == "/settings":
            if not _is_connected():
                return self._redirect("/login")
            self._render_settings_page()
        elif p == "/api/status":
            self._json({
                "ok": True,
                "version": APP_VERSION,
                "llm": load_llm_config(),
                "has_saved_pat": bool(load_pat()),
                "auth": _operator_state.public_auth(),
                "connected": _is_connected(),
            })
        elif p == "/api/scan/status":
            if _require_role(self, ROLE_VIEWER):
                return
            status = _session.to_status()
            status["phase_timeline"] = _phase_timeline(_session.log_lines, _session.state)
            status["log_url"] = f"/api/history/log/{_session.scan_id}" if _session.scan_id else ""
            self._json(status)
        elif p == "/api/history":
            if _require_role(self, ROLE_VIEWER):
                return
            self._json({"history": list(reversed(_history_records_for_user()))})
        elif p == "/api/suppressions":
            if _require_role(self, ROLE_VIEWER):
                return
            self._json({"suppressions": list_suppressions(SUPPRESSIONS_FILE)})
        elif p == "/api/triage":
            if _require_role(self, ROLE_VIEWER):
                return
            self._json({"triage": list_triage(SUPPRESSIONS_FILE)})
        elif p.startswith("/api/history/log/"):
            if _require_role(self, ROLE_VIEWER):
                return
            self._serve_log(p[17:])
        elif p == "/api/settings":
            if _require_role(self, ROLE_ADMIN):
                return
            self._json({
                "bitbucket_url": BITBUCKET_URL,
                "output_dir":    str(Path(OUTPUT_DIR).resolve()),
                "llm":           load_llm_config(),
            })
        elif p == "/api/scan/stream":
            if _require_role(self, ROLE_VIEWER):
                return
            self._sse_stream()
        elif p == "/api/ollama/models":
            if _require_role(self, ROLE_ADMIN):
                return
            qs  = parse_qs(parsed.query)
            url = (qs.get("url", [None])[0] or
                   load_llm_config().get("base_url", "http://localhost:11434"))
            url = url.strip()
            self._json({"models": _ollama_list_models(url),
                        "base_url": url})
        elif p.startswith("/reports/"):
            if _require_role(self, ROLE_VIEWER):
                return
            self._serve_report(p[9:])
        else:
            self._404()

    def do_POST(self):
        p = urlparse(self.path).path
        body = self._read_body()
        if p in ("/login", "/connect"):
            return self._page_connect(body)
        elif p == "/app/exit":
            return self._page_app_exit()
        elif p == "/scan/start":
            return self._page_scan_start(body)
        elif p == "/scan/stop":
            return self._page_scan_stop()
        elif p == "/history/delete":
            return self._page_history_delete(body)
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
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _render_scan_page(self, *, notice: str = "", error: str = "", selected_repos: list[str] | None = None):
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(urlparse(self.path).query)
        project_key = (qs.get("project", [""])[0] or _session.project_key or "").strip()
        fresh_scan = (qs.get("new", [""])[0] or "").lower() in {"1", "true", "yes"}
        if project_key and _require_project_access(self, project_key):
            return
        repos = _repos_for_project(project_key) if project_key else []
        status = _session.to_status() if _is_connected() else {}
        effective_selected_repos = selected_repos if selected_repos is not None else (
            list(_session.repo_slugs) if project_key and project_key == _session.project_key else []
        )
        html = render_scan_page(
            projects=filter_projects(_operator_state.projects_cache, _operator_state.ctx),
            selected_project=project_key,
            repos=repos,
            selected_repos=effective_selected_repos,
            status=status,
            llm_cfg=load_llm_config(),
            llm_models=_ollama_list_models(load_llm_config().get("base_url", "http://localhost:11434")),
            log_text=_format_log_text(_session.log_lines[-500:]),
            phase_timeline=_phase_timeline(_session.log_lines, _session.state),
            force_selection=fresh_scan,
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
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
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
            notice=notice or (qs.get("notice", [""])[0] or ""),
            error=error or (qs.get("error", [""])[0] or ""),
        )
        self._send(200, "text/html; charset=utf-8", html)

    def _page_connect(self, body: dict):
        try:
            connect_operator(
                body=body,
                bitbucket_url=BITBUCKET_URL,
                operator_state=_operator_state,
                audit_event=_audit_event,
            )
        except Exception as e:
            return self._render_login_page(error=str(e))
        self._redirect(_with_query("/scan", notice="Connected to Bitbucket"))

    def _page_app_exit(self):
        if _require_role(self, ROLE_ADMIN):
            return
        _audit_event("app_shutdown_requested")
        _request_app_shutdown()
        self._send(
            200,
            "text/html; charset=utf-8",
            b"<html><body><script>window.open('','_self');window.close();setTimeout(()=>{document.body.innerHTML='';location.replace('about:blank');},250);</script></body></html>",
        )

    def _page_scan_start(self, body: dict):
        global _session
        if _require_role(self, ROLE_SCANNER):
            return
        repo_slugs = body.get("repo_slugs", [])
        if isinstance(repo_slugs, str):
            repo_slugs = [repo_slugs]
        project_key = body.get("project_key", "").strip()
        if _require_project_access(self, project_key):
            return
        page_body = dict(body)
        page_body["repo_slugs"] = repo_slugs
        try:
            _session = start_scan(
                body=page_body,
                session_factory=ScanSession,
                current_session=_session,
                operator_state=_operator_state,
                save_llm_config=save_llm_config,
                audit_event=_audit_event,
            )
        except (ValueError, PermissionError, RuntimeError) as e:
            return self._render_scan_page(error=str(e), selected_repos=repo_slugs)
        threading.Thread(target=_run_scan, args=(_session,), daemon=True).start()
        self._redirect(_with_query("/scan", project=project_key, notice="Scan started"))

    def _page_scan_stop(self):
        if _require_role(self, ROLE_SCANNER):
            return
        stop_scan(current_session=_session, stop_scan_fn=_stop_active_scan, audit_event=_audit_event)
        self._redirect(_with_query("/scan", notice="Stop requested"))

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

    def _page_settings_save(self, body: dict):
        if _require_role(self, ROLE_ADMIN):
            return
        try:
            llm_url = body.get("llm_url", "").strip()
            llm_model = body.get("llm_model", "").strip()
            output_dir = body.get("output_dir", "").strip()
            if llm_url or llm_model:
                _settings_service.save_llm_settings(llm_url=llm_url, llm_model=llm_model)
            if output_dir:
                _settings_service.save_output_dir(
                    output_dir=output_dir,
                    is_scan_running=_session.state == "running",
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
                session=_session,
                suppressions_file=SUPPRESSIONS_FILE,
                triage_lookup=_triage_by_hash,
                apply_triage_metadata=_apply_triage_metadata,
                persist_session_state=_persist_session_state,
                marked_by=_operator_state.ctx.username,
                audit_event=_audit_event,
            )
        except Exception as e:
            return self._render_scan_page(error=str(e))
        self._redirect(_with_query("/scan", notice="Finding triage updated"))

    def _page_finding_reset(self, body: dict):
        if _require_role(self, ROLE_TRIAGE):
            return
        try:
            reset_finding(
                body=body,
                session=_session,
                suppressions_file=SUPPRESSIONS_FILE,
                clear_finding_triage=_clear_finding_triage,
                persist_session_state=_persist_session_state,
                audit_event=_audit_event,
            )
        except Exception as e:
            return self._render_scan_page(error=str(e))
        self._redirect(_with_query("/scan", notice="Finding triage reset"))

    # ── API handlers ──────────────────────────────────────────────────────────

    def _api_connect(self, body: dict):
        try:
            self._json(connect_operator(
                body=body,
                bitbucket_url=BITBUCKET_URL,
                operator_state=_operator_state,
                audit_event=_audit_event,
            ))
        except ValueError as e:
            self._err(400, str(e))
        except Exception as e:
            _audit_event("connect", outcome="error", error=str(e))
            self._err(401, str(e))

    def _api_scan_start(self, body: dict):
        global _session
        if _require_role(self, ROLE_SCANNER):
            return
        project_key = body.get("project_key", "").strip()
        if _require_project_access(self, project_key):
            return
        try:
            _session = start_scan(
                body=body,
                session_factory=ScanSession,
                current_session=_session,
                operator_state=_operator_state,
                save_llm_config=save_llm_config,
                audit_event=_audit_event,
            )
        except ValueError as e:
            return self._err(400, str(e))
        except PermissionError as e:
            return self._err(401, str(e))
        except RuntimeError as e:
            return self._err(409, str(e))
        threading.Thread(target=_run_scan, args=(_session,),
                         daemon=True).start()
        self._json({"ok": True, "scan_id": _session.scan_id})

    def _api_scan_stop(self):
        if _require_role(self, ROLE_SCANNER):
            return
        self._json(stop_scan(
            current_session=_session,
            stop_scan_fn=_stop_active_scan,
            audit_event=_audit_event,
        ))

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
        if not url or not model:
            return self._err(400, "base_url and model required")
        self._json(_settings_service.save_llm_settings(llm_url=url, llm_model=model))

    def _sse_stream(self):
        """Stream log lines as Server-Sent Events."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self._cors()
        self.end_headers()

        # Snapshot the backlog and remember its length.
        # The queue may already contain some of these same entries —
        # we skip the first backlog_len items from the queue to avoid duplicates.
        backlog      = list(_session.log_lines)
        backlog_len  = len(backlog)
        queue_skip   = backlog_len   # items to skip from queue (already sent)

        for entry in backlog:
            self._sse_write(entry)

        # Stream new entries, skipping any that overlap with the backlog
        while True:
            try:
                entry = _session.log_queue.get(timeout=1.0)
                if queue_skip > 0:
                    queue_skip -= 1   # this entry was already in the backlog
                else:
                    self._sse_write(entry)
                if _session.state in ("done", "stopped", "error"):
                    while not _session.log_queue.empty():
                        try:
                            e2 = _session.log_queue.get_nowait()
                            if queue_skip > 0:
                                queue_skip -= 1
                            else:
                                self._sse_write(e2)
                        except queue.Empty:
                            break
                    break
            except queue.Empty:
                try:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                except Exception:
                    break
                if _session.state in ("done", "stopped", "error"):
                    break

    def _sse_write(self, entry: dict):
        line = _format_log_entry(entry)
        if not line:
            return
        data = json.dumps(line)
        self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
        self.wfile.flush()

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
        self._send(200, "text/plain; charset=utf-8", log_text.encode("utf-8"))

    def _api_settings_save(self, body: dict):
        global OUTPUT_DIR, HISTORY_FILE, LOG_DIR, DB_FILE, AUDIT_FILE
        if _require_role(self, ROLE_ADMIN):
            return
        llm_url    = body.get("llm_url", "").strip()
        llm_model  = body.get("llm_model", "").strip()
        output_dir = body.get("output_dir", "").strip()
        if llm_url and llm_model:
            _settings_service.save_llm_settings(llm_url=llm_url, llm_model=llm_model)
        if output_dir:
            try:
                result = _settings_service.save_output_dir(
                    output_dir=output_dir,
                    is_scan_running=_session.state == "running",
                    set_paths=lambda p: _set_output_paths(p),
                )
            except Exception as e:
                return self._err(400, str(e))
            return self._json(result)
        self._json({"ok": True, "output_dir": str(Path(OUTPUT_DIR).resolve())})

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
                session=_session,
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
                session=_session,
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
            list_keys = {"repo_slugs", "scan_ids"}
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
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str):
        body = b""
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

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

# ── Add GET /api/repos to handler ─────────────────────────────────────────────
# Patch _Handler to handle /api/repos

_orig_get = _Handler.do_GET
def _patched_get(self):
    p = self.path.split("?")[0]
    if p == "/api/projects":
        if _require_role(self, ROLE_VIEWER):
            return
        self._json({
            "projects": filter_projects(_operator_state.projects_cache, _operator_state.ctx),
            "owner": _operator_state.connected_owner,
            "auth": _operator_state.public_auth(),
        })
    elif p == "/api/repos":
        if _require_role(self, ROLE_VIEWER):
            return
        qs = parse_qs(urlparse(self.path).query)
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
    else:
        _orig_get(self)
_Handler.do_GET = _patched_get


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


