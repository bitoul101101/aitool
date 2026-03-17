"""
app_server.py
─────────────
Single-file web application server for the AI Security & Compliance Scanner.

Replaces the Tkinter GUI with a browser-based SPA.

Routes
──────
GET  /                → SPA shell (HTML)
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
from services.spa_ui import build_spa
from services.single_user_state import SingleUserState, load_single_user_config
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


def _delete_managed_history_file(path_str: str, *, roots: List[Path]) -> str | None:
    path = Path(path_str)
    if not _is_within_roots(path, roots):
        return f"refused to delete unmanaged path: {path}"
    if path.exists():
        path.unlink()
    return None


def _history_records_for_user() -> list[dict]:
    return history_records_for_context(_load_history(), _operator_state.ctx)


def _find_history_record_by_scan_id(scan_id: str) -> dict | None:
    return find_history_record_by_scan_id(_history_records_for_user(), scan_id)


def _find_history_record_by_report_name(filename: str) -> dict | None:
    return find_history_record_by_report_name(_history_records_for_user(), filename)


def _triage_by_hash() -> Dict[str, dict]:
    return triage_by_hash(SUPPRESSIONS_FILE)


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

_HTML: bytes = b""   # injected at startup


class _Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args): pass   # silence access log

    # ── Routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", _HTML)
        elif p == "/api/status":
            self._json({
                "ok": True,
                "version": APP_VERSION,
                "llm": load_llm_config(),
                "has_saved_pat": bool(load_pat()),
                "auth": _operator_state.public_auth(),
            })
        elif p == "/api/scan/status":
            if _require_role(self, ROLE_VIEWER):
                return
            self._json(_session.to_status())
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
            # Accept ?url=... so the UI can pass the current input value
            from urllib.parse import urlparse, parse_qs
            qs  = parse_qs(urlparse(self.path).query)
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
        p = self.path.split("?")[0]
        body = self._read_body()
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
        data = json.dumps(entry)
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
                delete_managed_file=lambda path_str: _delete_managed_history_file(path_str, roots=managed_roots),
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
        try:
            return json.loads(self.rfile.read(length))
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


def _build_spa() -> bytes:
    return build_spa(has_saved_pat=bool(load_pat()), llm_cfg=load_llm_config())


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
        from urllib.parse import urlparse, parse_qs
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
    global _HTML, _server_instance
    _HTML = _build_spa()
    _app_exit_event.clear()
    _cleanup_stale_temp_clones()

    # Inject into handler
    _Handler.html_bytes_app = _HTML  # not used directly; _HTML global is read

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


