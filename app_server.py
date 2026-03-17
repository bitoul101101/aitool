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
import urllib.error
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Project imports ───────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent))

from scanner.bitbucket import BitbucketClient
from scanner.pat_store import save_pat, load_pat, delete_pat, is_available
from scanner.suppressions import (
    TRIAGE_ACCEPTED_RISK,
    TRIAGE_FALSE_POSITIVE,
    TRIAGE_REVIEWED,
    list_suppressions,
    list_triage,
    remove_triage,
    triage_by_hash,
    upsert_triage,
)
from services.scan_jobs import ScanJobPaths, ScanJobService, ScanSession

# ── Constants ─────────────────────────────────────────────────────────────────
BITBUCKET_URL = "https://bitbucket.cognyte.local:8443"
_BASE_DIR     = Path(__file__).parent          # always relative to script
OUTPUT_DIR    = str(_BASE_DIR / "output")      # mutable at runtime via settings
POLICY_FILE   = str(_BASE_DIR / "policy.json")
OWNER_MAP_FILE = str(_BASE_DIR / "owner_map.json")
SUPPRESSIONS_FILE = str(_BASE_DIR / "ai_scanner_suppressions.json")
LLM_CFG_FILE  = str(_BASE_DIR / "ai_scanner_llm_config.json")
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
    try:
        return json.loads(Path(LLM_CFG_FILE).read_text("utf-8"))
    except Exception:
        return {"base_url": "http://localhost:11434",
                "model": "qwen2.5-coder:7b-instruct"}

def save_llm_config(cfg: dict) -> None:
    try:
        Path(LLM_CFG_FILE).write_text(json.dumps(cfg, indent=2), "utf-8")
    except Exception as e:
        print(f"[WARN] Could not save LLM config: {e}")


def _utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


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
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/api/tags")
        with urllib.request.urlopen(req, timeout=3):
            return True
    except Exception:
        return False

def _ollama_list_models(base_url: str) -> list:
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/api/tags")
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
            return [m.get("name", "") for m in data.get("models", [])]
    except Exception:
        return []


OLLAMA_START_TIMEOUT = 15   # seconds to wait for ollama serve to become ready


def _ollama_ensure_running(base_url: str) -> dict:
    """
    Ensure Ollama is reachable at base_url.
    If not, attempt to start it with `ollama serve` and wait up to
    OLLAMA_START_TIMEOUT seconds for it to become ready.
    Returns {"ok": True} or {"ok": False, "error": "<reason>"}.
    """
    import subprocess as _sp

    if _ollama_ping(base_url):
        return {"ok": True, "status": "already_running"}

    # Try to start
    try:
        _sp.Popen(
            ["ollama", "serve"],
            stdout=_sp.DEVNULL,
            stderr=_sp.DEVNULL,
            creationflags=_sp.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except FileNotFoundError:
        return {"ok": False,
                "error": "`ollama` not found in PATH - install from https://ollama.com"}
    except Exception as e:
        return {"ok": False, "error": f"Failed to start ollama: {e}"}

    # Poll until ready or timeout
    deadline = time.time() + OLLAMA_START_TIMEOUT
    while time.time() < deadline:
        time.sleep(1)
        if _ollama_ping(base_url):
            return {"ok": True, "status": "started"}

    return {"ok": False,
            "error": f"Ollama did not become ready within {OLLAMA_START_TIMEOUT}s"}


# ── Global app state ──────────────────────────────────────────────────────────

_client: Optional[BitbucketClient] = None
_session: ScanSession = ScanSession()
_projects_cache: List[dict] = []
_repos_cache: Dict[str, List[dict]] = {}
_connected_user: str = "Unknown"
_state_lock = threading.Lock()
_app_exit_event = threading.Event()
_server_instance: Optional[http.server.ThreadingHTTPServer] = None


# ── Scan job service ─────────────────────────────────────────────────────────

HISTORY_FILE = str(_BASE_DIR / "output" / "scan_history.json")
LOG_DIR = str(_BASE_DIR / "output" / "logs")
DB_FILE = str(_BASE_DIR / "output" / "scan_jobs.db")

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


def _triage_by_hash() -> Dict[str, dict]:
    return triage_by_hash(SUPPRESSIONS_FILE)


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
        client=_client,
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
            })
        elif p == "/api/scan/status":
            self._json(_session.to_status())
        elif p == "/api/history":
            self._json({"history": list(reversed(_load_history()))})
        elif p == "/api/suppressions":
            self._json({"suppressions": list_suppressions(SUPPRESSIONS_FILE)})
        elif p == "/api/triage":
            self._json({"triage": list_triage(SUPPRESSIONS_FILE)})
        elif p.startswith("/api/history/log/"):
            self._serve_log(p[17:])
        elif p == "/api/settings":
            self._json({
                "bitbucket_url": BITBUCKET_URL,
                "output_dir":    str(Path(OUTPUT_DIR).resolve()),
                "llm":           load_llm_config(),
            })
        elif p == "/api/scan/stream":
            self._sse_stream()
        elif p == "/api/ollama/models":
            # Accept ?url=... so the UI can pass the current input value
            from urllib.parse import urlparse, parse_qs
            qs  = parse_qs(urlparse(self.path).query)
            url = (qs.get("url", [None])[0] or
                   load_llm_config().get("base_url", "http://localhost:11434"))
            url = url.strip()
            self._json({"models": _ollama_list_models(url),
                        "base_url": url})
        elif p.startswith("/reports/"):
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
        global _client, _projects_cache, _connected_user
        token = body.get("token", "").strip()
        remember = body.get("remember", False)
        use_saved_token = bool(body.get("use_saved_token"))
        if not token and use_saved_token:
            token = load_pat() or ""
        if not token:
            return self._err(400, "Token required")
        try:
            client = BitbucketClient(
                base_url=BITBUCKET_URL, token=token,
                verify_ssl=False, verbose=False)
            owner    = client.get_pat_owner()
            projects = client.list_projects()
            _client         = client
            _projects_cache = projects
            _connected_user = owner or "Unknown"
            if remember:
                save_pat(token)
            else:
                delete_pat()
            self._json({"ok": True, "owner": owner,
                        "projects": projects})
        except Exception as e:
            self._err(401, str(e))

    def _api_scan_start(self, body: dict):
        global _session
        project_key = body.get("project_key", "").strip()
        repo_slugs  = body.get("repo_slugs", [])
        llm_url     = body.get("llm_url", "http://localhost:11434").strip()
        llm_model   = body.get("llm_model", "qwen2.5-coder:7b-instruct").strip()

        if not project_key or not repo_slugs:
            return self._err(400, "project_key and repo_slugs required")
        if not _client:
            return self._err(401, "Not connected")
        if _session.state == "running":
            return self._err(409, "Scan already running")

        save_llm_config({"base_url": llm_url, "model": llm_model})

        _session              = ScanSession()
        _session.scan_id      = datetime.now().strftime("%Y%m%d_%H%M%S")
        _session.project_key  = project_key
        _session.repo_slugs   = repo_slugs
        _session.total        = len(repo_slugs)
        _session.llm_url      = llm_url
        _session.llm_model    = llm_model
        _session.operator     = _connected_user or "Unknown"
        _session.state        = "running"

        threading.Thread(target=_run_scan, args=(_session,),
                         daemon=True).start()
        self._json({"ok": True, "scan_id": _session.scan_id})

    def _api_scan_stop(self):
        stopped = _stop_active_scan()
        self._json({"ok": True, "stopped": stopped})

    def _api_app_shutdown(self):
        _request_app_shutdown()
        self._json({"ok": True})


    def _api_llm_config(self, body: dict):
        url   = body.get("base_url", "").strip()
        model = body.get("model", "").strip()
        if url and model:
            save_llm_config({"base_url": url, "model": model})
        models = _ollama_list_models(url or "http://localhost:11434")
        self._json({"ok": True, "models": models})

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
        path = Path(OUTPUT_DIR).resolve() / safe
        if not path.exists():
            return self._404()
        ct = "text/html; charset=utf-8" if safe.endswith(".html") else "text/csv"
        self._send(200, ct, path.read_bytes())

    def _serve_log(self, scan_id: str):
        """Serve a scan log file by scan_id."""
        safe = Path(scan_id.replace("/","").replace("\\","")).name
        log_text = _get_log_text(safe)
        if not log_text:
            return self._err(404, "Log not found")
        self._send(200, "text/plain; charset=utf-8", log_text.encode("utf-8"))

    def _api_settings_save(self, body: dict):
        global OUTPUT_DIR, HISTORY_FILE, LOG_DIR, DB_FILE
        llm_url    = body.get("llm_url", "").strip()
        llm_model  = body.get("llm_model", "").strip()
        output_dir = body.get("output_dir", "").strip()
        if llm_url and llm_model:
            save_llm_config({"base_url": llm_url, "model": llm_model})
        if output_dir:
            if _session.state == "running":
                return self._err(409, "Cannot change output directory while a scan is running")
            try:
                p = Path(output_dir)
                p.mkdir(parents=True, exist_ok=True)
                OUTPUT_DIR   = str(p)
                HISTORY_FILE = str(p / "scan_history.json")
                LOG_DIR      = str(p / "logs")
                DB_FILE      = str(p / "scan_jobs.db")
                Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
                _sync_scan_service_paths()
            except Exception as e:
                return self._err(400, f"Invalid output directory: {e}")
        self._json({"ok": True, "output_dir": str(Path(OUTPUT_DIR).resolve())})

    def _api_history_delete(self, body: dict):
        """Delete one or more history records plus their associated files."""
        scan_ids = body.get("scan_ids", [])
        if not scan_ids or not isinstance(scan_ids, list):
            return self._err(400, "scan_ids list required")

        hist = _load_history()
        deleted, errors = [], []
        managed_roots = [Path(OUTPUT_DIR).resolve(), Path(LOG_DIR).resolve()]

        for sid in scan_ids:
            # Find matching record
            rec = next((r for r in hist if r.get("scan_id") == sid), None)
            if not rec:
                errors.append(f"{sid}: not found")
                continue

            # Delete associated files
            rp = (rec.get("reports") or {}).get("__all__", {})
            for key in ("html", "csv"):
                fpath = rp.get(key, "")
                if fpath:
                    try:
                        err = _delete_managed_history_file(fpath, roots=managed_roots)
                        if err:
                            errors.append(f"{sid} {key}: {err}")
                    except Exception as e:
                        errors.append(f"{sid} {key}: {e}")

            log_file = rec.get("log_file", "")
            if log_file:
                try:
                    err = _delete_managed_history_file(log_file, roots=managed_roots)
                    if err:
                        errors.append(f"{sid} log: {err}")
                except Exception as e:
                    errors.append(f"{sid} log: {e}")

            deleted.append(sid)

        if deleted:
            try:
                _delete_history(deleted)
            except Exception as e:
                return self._err(500, f"Failed to update stored history: {e}")

        self._json({"ok": True, "deleted": deleted, "errors": errors})

    def _api_finding_triage(self, body: dict):
        hash_ = body.get("hash", "").strip()
        status = body.get("status", "").strip()
        note = body.get("note", "").strip()
        if not hash_:
            return self._err(400, "hash required")
        if status not in {TRIAGE_REVIEWED, TRIAGE_ACCEPTED_RISK, TRIAGE_FALSE_POSITIVE}:
            return self._err(400, "invalid triage status")
        if status in {TRIAGE_ACCEPTED_RISK, TRIAGE_FALSE_POSITIVE} and not note:
            return self._err(400, "note required")

        target = next((f for f in _session.findings if f.get("_hash") == hash_), None)
        if target is None:
            target = next((f for f in _session.suppressed_findings if f.get("_hash") == hash_), None)
        if not target:
            return self._err(404, "Finding not found in current session")

        upsert_triage(
            SUPPRESSIONS_FILE,
            target,
            status=status,
            note=note,
            marked_by=_connected_user,
        )
        triage_meta = _triage_by_hash().get(hash_, {})
        updated = _apply_triage_metadata(target, triage_meta)

        _session.findings = [f for f in _session.findings if f.get("_hash") != hash_]
        _session.suppressed_findings = [
            f for f in _session.suppressed_findings if f.get("_hash") != hash_
        ]
        if status == TRIAGE_FALSE_POSITIVE:
            _session.suppressed_findings.append(updated)
        else:
            _session.findings.append(updated)
            _session.findings.sort(
                key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", ""))
            )
        _persist_session_state()
        self._json({"ok": True, "status": _session.to_status()})

    def _api_finding_reset(self, body: dict):
        hash_ = body.get("hash", "").strip()
        if not hash_:
            return self._err(400, "hash required")
        removed = remove_triage(SUPPRESSIONS_FILE, hash_)
        finding = next((f for f in _session.findings if f.get("_hash") == hash_), None)
        if finding is not None:
            updated = _clear_finding_triage(finding)
            _session.findings = [f for f in _session.findings if f.get("_hash") != hash_]
            _session.findings.append(updated)
            _session.findings.sort(
                key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", ""))
            )
            _persist_session_state()
            return self._json({"ok": True, "removed": removed, "status": _session.to_status()})

        finding = next((f for f in _session.suppressed_findings if f.get("_hash") == hash_), None)
        _session.suppressed_findings = [
            f for f in _session.suppressed_findings if f.get("_hash") != hash_
        ]
        if finding:
            _session.findings.append(_clear_finding_triage(finding))
            _session.findings.sort(
                key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", ""))
            )
            _persist_session_state()
        self._json({"ok": True, "removed": removed, "status": _session.to_status()})

    def _api_finding_suppress(self, body: dict):
        body = dict(body)
        body["status"] = TRIAGE_FALSE_POSITIVE
        body["note"] = body.get("reason", body.get("note", ""))
        return _Handler._api_finding_triage(self, body)

    def _api_finding_unsuppress(self, body: dict):
        return _Handler._api_finding_reset(self, body)

    def _api_ollama_start(self, body: dict):
        """Start Ollama if not running, then return available models."""
        url = body.get("url", "").strip() or               load_llm_config().get("base_url", "http://localhost:11434")
        result = _ollama_ensure_running(url)
        if result["ok"]:
            models = _ollama_list_models(url)
            self._json({"ok": True, "status": result.get("status","running"),
                        "models": models})
        else:
            self._json({"ok": False, "error": result["error"], "models": []})


    def _proxy_ollama(self, body: dict):
        cfg    = load_llm_config()
        target = cfg.get("base_url", "http://localhost:11434").rstrip("/") + "/api/generate"
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            target, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                self.send_response(resp.status)
                ct = resp.headers.get("Content-Type", "application/x-ndjson")
                self.send_header("Content-Type", ct)
                self._cors()
                self.end_headers()
                while True:
                    chunk = resp.read(4096)
                    if not chunk: break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except urllib.error.URLError as exc:
            err = json.dumps({"error": str(exc)}).encode()
            self._send(502, "application/json", err)

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


# ── SPA HTML ──────────────────────────────────────────────────────────────────

def _build_spa() -> bytes:
    """Return the full single-page application as UTF-8 bytes."""
    # Pre-load non-secret client state and LLM config
    llm_cfg   = load_llm_config()
    return _SPA_TEMPLATE.replace("__HAS_SAVED_PAT__", "true" if load_pat() else "false") \
                        .replace("__LLM_URL__",   llm_cfg.get("base_url","http://localhost:11434")) \
                        .replace("__LLM_MODEL__", llm_cfg.get("model","qwen2.5-coder:7b-instruct")) \
                        .encode("utf-8")


# ── SPA Template ──────────────────────────────────────────────────────────────

_SPA_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Security & Compliance Scanner</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --red:#C00000; --ora:#c45e00; --yel:#a06000; --grn:#2e6e2e; --lgrn:#3a7a3a;
  --pur:#5c2e0e; --pur2:#8b4513; --pur3:#f5e6d8;
  --bg:#f5ede0; --surface:#ede0ce; --card:#e8d5ba; --card2:#e0c9a8;
  --border:#c8aa88; --border2:#b89870;
  --text:#2c1a08; --text2:#5a3a1a; --dim:#8a6840;
  --mono:'Cascadia Code',Consolas,monospace;
  --sans:'Segoe UI',system-ui,sans-serif;
  --r:8px;
}
html,body{height:100%;background:var(--bg);color:var(--text);
  font-family:var(--sans);font-size:15px;line-height:1.55;
  overflow:hidden;-webkit-font-smoothing:antialiased}

/* ════ SHELL ════ */
#app{display:flex;flex-direction:column;height:100vh}
#topbar{
  display:flex;align-items:center;gap:16px;padding:0 20px;height:50px;flex-shrink:0;
  background:linear-gradient(135deg,#3b1a08 0%,#6b2d0a 45%,#4a1a4e 100%);
  border-bottom:1px solid rgba(255,200,120,.15);
  box-shadow:0 2px 14px rgba(60,20,5,.4);z-index:10;
}
.logo{font-size:15px;font-weight:700;color:#fff;display:flex;align-items:center;gap:10px}
.logo-icon{width:28px;height:28px;border-radius:6px;background:rgba(255,255,255,.15);
  display:flex;align-items:center;justify-content:center;font-size:15px}
.logo-sub{font-size:11px;font-weight:400;color:rgba(255,255,255,.45);margin-left:4px}
.top-actions{margin-left:auto;display:flex;align-items:center;gap:10px}
.top-actions .btn-xs{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.18);color:#fff}
.top-actions .btn-xs:hover{color:#fff;border-color:rgba(255,255,255,.38);background:rgba(255,255,255,.14)}
#conn-info{margin-left:auto;font-size:12px;color:rgba(255,255,255,.45);font-family:var(--mono)}

#body-wrap{flex:1;display:flex;overflow:hidden}

/* ════ SIDEBAR ════ */
#sidebar{
  width:184px;flex-shrink:0;
  background:var(--surface);border-right:1px solid var(--border);
  display:none;flex-direction:column;
  transition:width .2s ease;
}
#sidebar.visible{display:flex}
.nav-section{padding:12px 10px 6px;
  font-size:10px;font-weight:700;color:var(--dim);letter-spacing:.1em;text-transform:uppercase}
.nav-item{
  display:flex;align-items:center;gap:10px;
  padding:9px 14px;margin:1px 6px;border-radius:6px;
  font-size:13px;font-weight:500;color:var(--text2);
  cursor:pointer;transition:background .1s,color .1s;user-select:none;
}
.nav-item:hover{background:var(--card);color:var(--text)}
.nav-item.active{background:rgba(139,69,19,.18);color:#5c2e0e;font-weight:700}
.nav-spacer{flex:1}
.nav-version{padding:12px 14px;font-family:var(--mono);font-size:10px;color:var(--dim)}

/* ════ MAIN AREA ════ */
#main{flex:1;overflow:hidden;display:flex;flex-direction:column}
.view{display:none;overflow:hidden;flex:1;min-height:0}
.view.active{display:flex;flex-direction:column}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.view.active{animation:fadeIn .16s ease}

/* ════ LOGIN ════ */
#v-login{
  align-items:center;justify-content:center;
  background:linear-gradient(160deg,#f5ede0 0%,#e8d5ba 50%,#f0e0c8 100%);
}
.login-wrap{
  width:440px;
  background:#fff;
  border:1px solid var(--border);
  border-radius:16px;
  overflow:hidden;
  box-shadow:0 12px 48px rgba(60,20,5,.18);
}
.login-hero{
  background:linear-gradient(135deg,#3b1a08 0%,#6b2d0a 50%,#4a1a4e 100%);
  padding:36px 40px 28px;
  text-align:center;
}
.login-hero-icon{
  font-size:38px;margin-bottom:12px;display:block;
  filter:drop-shadow(0 2px 8px rgba(0,0,0,.3));
}
.login-hero h1{
  font-size:22px;font-weight:800;color:#fff;
  margin:0 0 4px;letter-spacing:-.3px;
}
.login-hero .subtitle{
  font-size:13px;font-weight:600;
  color:rgba(255,210,160,.75);
  text-transform:uppercase;letter-spacing:.1em;
  margin:0;
}
.login-body{padding:32px 40px 36px;}
.field{margin-bottom:18px}
.field label{display:block;font-size:12px;font-weight:700;color:var(--text2);
  text-transform:uppercase;letter-spacing:.06em;margin-bottom:7px}
.field input{
  width:100%;background:var(--bg);
  border:1.5px solid var(--border2);
  border-radius:var(--r);color:var(--text);
  font-size:14px;padding:11px 14px;outline:none;
  transition:border-color .15s,box-shadow .15s;
  box-sizing:border-box;
}
.field input:focus{
  border-color:var(--pur2);
  box-shadow:0 0 0 3px rgba(139,69,19,.15);
}
.field input::placeholder{color:var(--dim);font-family:var(--mono);font-size:13px}
.chk-row{display:flex;align-items:center;gap:9px;margin-bottom:24px;cursor:pointer}
.chk-row input{accent-color:var(--pur2);width:16px;height:16px;flex-shrink:0}
.chk-row span{font-size:13px;color:var(--text2)}
#login-status{min-height:20px;font-size:13px;margin-bottom:14px;font-family:var(--mono)}
.btn-primary{
  width:100%;padding:13px;border-radius:var(--r);
  background:linear-gradient(135deg,#5c2e0e,#8b4513);
  color:#fff;border:none;font-size:14px;font-weight:700;
  cursor:pointer;transition:opacity .15s,transform .1s;
  letter-spacing:.02em;
}
.btn-primary:hover{opacity:.9}
.btn-primary:active{transform:translateY(1px)}
.btn-primary:disabled{opacity:.4;cursor:not-allowed}
/* ════ SELECTOR ════ */
#v-selector{}
.sel-body{flex:1;display:grid;grid-template-columns:200px 1fr;overflow:hidden;min-height:0}
.sel-sidebar{background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow:hidden}
.panel-hdr{padding:12px 16px 10px;font-size:11px;font-weight:700;color:var(--dim);
  letter-spacing:.1em;text-transform:uppercase;border-bottom:1px solid var(--border);flex-shrink:0}
#proj-list{flex:1;overflow-y:auto}
.proj-item{padding:10px 16px;font-size:14px;color:var(--text2);cursor:pointer;
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;
  transition:background .1s,color .1s;user-select:none}
.proj-item:hover{background:var(--card);color:var(--text)}
.proj-item.active{background:var(--card2);color:#fff;font-weight:600;
  border-left:3px solid var(--pur2);padding-left:13px}
.sel-content{display:flex;flex-direction:column;overflow:hidden;min-height:0}
.sel-toolbar{display:flex;align-items:center;gap:10px;padding:10px 14px;
  border-bottom:1px solid var(--border);flex-shrink:0;background:var(--surface)}
.rh{font-size:13px;font-weight:600;color:var(--text2);white-space:nowrap}
.search-inp{flex:1;background:var(--card);border:1.5px solid var(--border2);border-radius:6px;
  color:var(--text);font-size:13px;padding:6px 12px;outline:none}
.search-inp:focus{border-color:var(--pur2)}
.search-inp::placeholder{color:var(--dim)}
.btn-xs{padding:5px 12px;border-radius:6px;background:var(--card2);border:1px solid var(--border2);
  color:var(--text2);font-size:12px;font-weight:600;cursor:pointer;transition:color .1s,border-color .1s;white-space:nowrap}
.btn-xs:hover{color:#fff;border-color:var(--pur2)}
#repo-list{flex:1;overflow-y:auto;min-height:0;padding:6px 8px}
.repo-grid{display:grid;gap:2px;}
.repo-grid.cols-1{grid-template-columns:1fr}
.repo-grid.cols-2{grid-template-columns:1fr 1fr}
.repo-grid.cols-3{grid-template-columns:1fr 1fr 1fr}
.repo-item{display:flex;align-items:center;gap:9px;padding:7px 10px;cursor:pointer;
  border:1px solid var(--border);border-radius:5px;transition:background .1s,border-color .1s}
.repo-item:hover{background:var(--card);border-color:var(--border2)}
.repo-item.checked{background:rgba(85,64,170,.12);border-color:var(--pur2)}
.repo-item input[type=checkbox]{accent-color:var(--pur2);width:14px;height:14px;flex-shrink:0}
.repo-item label{font-size:13px;color:var(--text);cursor:pointer;flex:1;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.llm-bar{display:flex;align-items:center;gap:12px;flex-wrap:nowrap;padding:9px 16px;
  background:var(--surface);border-top:1px solid var(--border);flex-shrink:0}
.lb{font-size:11px;font-weight:700;color:var(--dim);letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}
.llm-bar input,.llm-bar select{background:var(--card);border:1.5px solid var(--border2);
  border-radius:6px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 10px;outline:none}
.llm-bar input{width:185px}
.llm-bar select{flex:1;min-width:150px;max-width:240px}
.llm-bar input:focus,.llm-bar select:focus{border-color:var(--pur2)}
#llm-ind{font-family:var(--mono);font-size:11px;color:var(--dim);white-space:nowrap}
#llm-ind.ind-ok{color:#2787F5}
#llm-ind.ind-warn{color:#fcd34d}
#llm-ind.ind-err{color:#fca5a5}
.sel-footer{display:flex;align-items:center;gap:12px;padding:10px 16px;
  background:var(--surface);border-top:1px solid var(--border);flex-shrink:0}
.sel-count{font-size:13px;color:var(--dim);flex:1}
.sel-count.has{
  color:#fff;font-weight:700;font-size:14px;
  background:linear-gradient(135deg,#5c2e0e,#8b4513);
  padding:5px 14px;border-radius:20px;
  box-shadow:0 1px 6px rgba(60,20,5,.3);
}
.btn-go{padding:10px 26px;border-radius:var(--r);
  background:linear-gradient(135deg,var(--pur),var(--pur2));
  color:#fff;border:none;font-size:14px;font-weight:700;cursor:pointer;transition:opacity .15s}
.btn-go:hover{opacity:.88}
.btn-go:disabled{opacity:.35;cursor:not-allowed}

/* ════ SCAN TABS ════ */
#v-scan{flex-direction:column}
.tab-bar-wrap{
  display:none;align-items:stretch;flex-shrink:0;
  background:var(--card);border-bottom:2px solid var(--border);
}
.tab-scroll-btn{
  flex-shrink:0;width:24px;border:none;background:var(--surface);
  color:var(--dim);font-size:18px;line-height:1;cursor:pointer;
  border-right:1px solid var(--border);padding:0;
  transition:background .1s,color .1s;
}
.tab-scroll-btn:last-child{border-right:none;border-left:1px solid var(--border)}
.tab-scroll-btn:hover{background:var(--card);color:var(--text)}
.tab-bar{
  display:flex;align-items:stretch;gap:0;flex:1;
  overflow-x:auto;min-height:0;scroll-behavior:smooth;
  scrollbar-width:none;
}
.tab-bar::-webkit-scrollbar{display:none}
.scan-tab{
  display:flex;align-items:center;gap:8px;
  padding:0 14px;height:38px;flex-shrink:0;
  border-right:1px solid var(--border);
  cursor:pointer;user-select:none;
  font-size:12px;font-weight:500;color:var(--text2);
  position:relative;transition:background .1s,color .1s;
  max-width:240px;min-width:120px;
}
.scan-tab:hover{background:var(--card);color:var(--text)}
.scan-tab.active{
  background:var(--bg);color:var(--pur);font-weight:700;
  border-bottom:2px solid #a0522d;margin-bottom:-2px;
}
.tab-dot{
  width:7px;height:7px;border-radius:50%;
  background:var(--dim);flex-shrink:0;
}
.tab-dot.running{background:var(--lgrn);animation:pulse 1.2s ease-in-out infinite}
.tab-dot.done{background:var(--lgrn)}
.tab-dot.stopped{background:var(--ora)}
.tab-dot.error{background:var(--red)}
.tab-dot.skipped{background:var(--dim)}
.tab-label{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tab-close{
  font-size:14px;color:var(--dim);flex-shrink:0;
  width:16px;text-align:center;border-radius:3px;
  display:none;
}
.scan-tab:hover .tab-close,.scan-tab.active .tab-close{display:block}
.tab-close:hover{color:var(--text);background:var(--border2)}
#tab-panels{flex:1;overflow:hidden;position:relative;min-height:0}
.tab-panel{
  position:absolute;inset:0;display:none;
  flex-direction:column;overflow:hidden;
}
.tab-panel.active{display:flex}
.report-iframe{
  flex:1;width:100%;border:none;background:#fff;
  display:block;min-height:0;
}
.tab-dot.report{background:#a0522d}

/* ════ SCAN VIEW ════ */
.scan-body{
  flex:1;display:grid;
  grid-template-columns:minmax(0,1fr) 380px;
  grid-template-rows:minmax(0,1fr) auto;
  overflow:hidden;min-height:0
}
.log-panel{
  grid-column:1;grid-row:1;
  display:flex;flex-direction:column;overflow:hidden;border-right:1px solid var(--border)
}
.log-header{display:flex;align-items:center;gap:12px;padding:11px 18px;
  border-bottom:1px solid var(--border);flex-shrink:0;
  background:linear-gradient(135deg,#1a0545 0%,#2d0e7a 100%)}
.lh-icon{width:9px;height:9px;border-radius:50%;background:var(--pur3);flex-shrink:0}
.lh-icon.running{background:var(--lgrn);animation:pulse 1.2s ease-in-out infinite}
.lh-title{font-size:14px;font-weight:700;color:#fff;flex:1}
.lh-eta{font-family:var(--mono);font-size:11px;color:rgba(255,255,255,.4)}
.scan-action-btn{flex-shrink:0}
.prog-wrap{height:4px;background:rgba(255,255,255,.08);flex-shrink:0}
.prog-fill{height:100%;background:linear-gradient(90deg,#6b2d0a,#a0522d);
  transition:width .5s ease;width:0%}
#log-out,.log-out-pane{flex:1;overflow-y:auto;padding:8px 0;font-family:var(--mono);font-size:12.5px;line-height:1.7}
.log-entry{display:flex;gap:12px;padding:2px 18px;transition:background .1s}
.log-entry:hover{background:rgba(255,255,255,.03)}
.log-ts{color:var(--dim);flex-shrink:0;font-size:11px;padding-top:2px;user-select:none;min-width:64px}
.log-msg{flex:1;word-break:break-all}
.log-sep{margin:5px 18px;border:none;border-top:1px solid var(--border);opacity:.5}
.lv-hd   .log-msg{color:#b3a3f5;font-weight:700}
.lv-ok   .log-msg{color:#6ee7b7}
.lv-err  .log-msg{color:#fca5a5}
.lv-warn .log-msg{color:#fcd34d}
.lv-info .log-msg{color:var(--text)}
.lv-dim  .log-msg{color:var(--dim)}
.findings-panel{
  grid-column:2;grid-row:1 / span 2;
  display:grid;grid-template-rows:auto auto minmax(120px,1fr) auto;
  overflow:hidden;background:var(--surface);min-height:0
}
.fp-header{background:linear-gradient(135deg,#1a0545 0%,#2d0e7a 55%,#3d1599 100%);
  padding:8px 14px;border-bottom:2px solid rgba(255,255,255,.1);flex-shrink:0}
.fp-title{font-size:13px;font-weight:800;color:#fff;display:block;margin-bottom:1px}
.fp-subtitle{font-size:11px;color:rgba(255,255,255,.45);font-family:var(--mono)}
.kpi-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--border);border-bottom:1px solid var(--border);flex-shrink:0}
.kpi-cell{background:var(--card);padding:6px 4px;text-align:center;border-top:3px solid transparent}
.kpi-cell.k1{border-top-color:var(--red)} .kpi-cell.k2{border-top-color:var(--ora)}
.kpi-cell.k3{border-top-color:var(--yel)} .kpi-cell.k4{border-top-color:var(--lgrn)}
.kpi-n{font-size:18px;font-weight:800;line-height:1;font-family:var(--mono)}
.kpi-l{font-size:9px;font-weight:700;color:var(--dim);letter-spacing:.08em;text-transform:uppercase;margin-top:2px}
.k1 .kpi-n{color:var(--red)} .k2 .kpi-n{color:var(--ora)}
.k3 .kpi-n{color:var(--yel)} .k4 .kpi-n{color:var(--lgrn)}
#repo-cards,[id^="repo-cards-"]{min-height:0;overflow-y:auto;padding:10px}
.finding-drawer{
  grid-column:1;grid-row:2;
  border-top:1px solid var(--border);border-right:1px solid var(--border);
  background:var(--surface);display:flex;flex-direction:column;
  min-height:220px;max-height:300px;min-width:0;overflow:hidden
}
.finding-drawer-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 14px;background:rgba(0,0,0,.03);border-bottom:1px solid var(--border);flex-wrap:wrap}
.finding-drawer-title{font-size:12px;font-weight:800;color:var(--text);text-transform:uppercase;letter-spacing:.06em}
.finding-switches{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.finding-switch{display:inline-flex;align-items:center;gap:8px;padding:7px 10px;border-radius:999px;border:1px solid var(--border2);background:var(--card);color:var(--text2);font-size:11px;font-weight:700;cursor:pointer}
.finding-switch.active{background:#f1e7de;border-color:#a0522d;color:#6b2d0a}
.finding-switch-count{font-family:var(--mono);font-size:11px;color:inherit;opacity:.8}
.finding-panes{flex:1;min-height:0}
.finding-pane{display:none;height:100%}
.finding-pane.active{display:block}
.finding-list{height:100%;overflow-y:auto}
.finding-empty{padding:10px 12px;color:var(--dim);font-size:12px}
.finding-item{padding:10px 12px;border-top:1px solid rgba(0,0,0,.06)}
.finding-item:first-child{border-top:none}
.finding-main{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:flex-start;gap:10px}
.finding-badge{padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.04em;color:#fff;flex-shrink:0}
.finding-badge.sev-1{background:var(--red)} .finding-badge.sev-2{background:var(--ora)}
.finding-badge.sev-3{background:var(--yel);color:#1a1c24} .finding-badge.sev-4{background:var(--lgrn)}
.finding-body{flex:1;min-width:0}
.finding-title{font-size:12px;font-weight:700;color:var(--text)}
.finding-meta{font-size:11px;color:var(--dim);font-family:var(--mono);margin-top:2px}
.finding-tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.finding-chip{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.04em}
.finding-chip.delta-new{background:#e8f5e9;color:#1f6a3d}
.finding-chip.delta-unchanged{background:#f1f5f9;color:#475569}
.finding-chip.triage-reviewed{background:#e0f2fe;color:#0c4a6e}
.finding-chip.triage-accepted_risk{background:#fff7d6;color:#8a4b00}
.finding-chip.triage-false_positive{background:#f3e8ff;color:#6b21a8}
.finding-desc{font-size:11px;color:var(--text2);margin-top:4px}
.finding-actions{display:flex;gap:8px;align-self:flex-start;justify-self:end}
.finding-btn{padding:5px 10px;border-radius:6px;border:1px solid var(--border2);background:var(--card2);color:var(--text2);font-size:11px;font-weight:700;cursor:pointer}
.finding-btn:hover{border-color:var(--pur2);color:var(--text)}
.finding-btn.warn{background:#fff4d6;border-color:#e0b050}
.finding-btn.safe{background:#e7f6ea;border-color:#6fb07a}
.finding-btn.info{background:#e0f2fe;border-color:#7dd3fc}
.finding-btn.alt{background:#f8fafc;border-color:#cbd5e1}
.finding-note{font-size:11px;color:var(--dim);margin-top:4px}
/* ── Monitor panel (phase timeline + live log) ── */
.monitor-panel{display:block;overflow:visible;min-height:0}
.monitor-spacer{display:none}
.phase-timeline{padding:10px 14px 12px;background:var(--surface);border-top:1px solid var(--border);min-height:170px}
.phase-row{display:flex;align-items:center;gap:8px;padding:3px 0;font-size:11px;color:var(--dim);line-height:1.3}
.phase-row.ph-done{color:var(--text2)}
.phase-row.ph-active{color:var(--text);font-weight:600}
.phase-icon{width:16px;height:16px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:9px}
.ph-wait  .phase-icon{background:var(--border);color:var(--dim)}
.ph-done  .phase-icon{background:#22c55e;color:#fff}
.ph-active .phase-icon{background:var(--pur);color:#fff;animation:pulse 1.2s ease-in-out infinite}
.ph-skip  .phase-icon{background:var(--dim);color:#fff}
.phase-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-right:6px}
.phase-detail{font-family:var(--mono);font-size:10px;color:var(--dim);flex-shrink:0;opacity:.75}
.repo-card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
  margin-bottom:8px;overflow:hidden;transition:border-color .15s;
  box-shadow:0 1px 4px rgba(0,0,0,.2)}
.repo-card:hover{border-color:var(--border2)}
.repo-card-head{display:flex;align-items:center;gap:10px;padding:10px 14px}
.rc-icon{font-size:15px;flex-shrink:0}
.rc-name{font-size:13px;font-weight:700;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rc-name.skip{color:var(--dim);font-weight:400} .rc-name.clean{color:#4ade80;font-weight:600}
.rc-count{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--text2);flex-shrink:0}
.rc-bar{height:4px;display:flex;margin:0 14px 9px;border-radius:3px;overflow:hidden;gap:1px}
.rc-bar-c{background:var(--red)} .rc-bar-h{background:var(--ora)}
.rc-bar-m{background:var(--yel)} .rc-bar-l{background:var(--lgrn)}
.rc-badges{display:flex;align-items:center;gap:5px;padding:0 14px 9px;flex-wrap:wrap}
.rcb{display:inline-block;padding:3px 9px;border-radius:4px;
  font-size:11px;font-weight:700;letter-spacing:.2px;color:#fff}
.rcb-c{background:var(--red)} .rcb-h{background:var(--ora)}
.rcb-m{background:var(--yel);color:#1a1c24} .rcb-l{background:var(--lgrn)}
.rc-links{display:flex;gap:7px;padding:0 14px 10px}
.rc-lnk{font-size:12px;font-weight:600;padding:4px 12px;border-radius:5px;
  background:var(--pur);color:#fff;text-decoration:none;letter-spacing:.02em;
  border:1px solid var(--pur2);transition:background .1s}
.rc-lnk:hover{background:var(--pur2)}
.rc-lnk.csv{background:var(--card2);color:var(--text2);border-color:var(--border2)}
.rc-lnk.csv:hover{border-color:var(--pur2);color:var(--text)}


.btn-new{padding:8px 16px;border-radius:6px;background:transparent;
  border:1.5px solid var(--border2);color:var(--text2);font-size:12px;font-weight:700;
  cursor:pointer;transition:color .1s,border-color .1s}
.btn-new:hover{color:#fff;border-color:var(--pur2)}
.report-bar{
  display:none;align-items:center;gap:14px;
  padding:13px 20px;flex-shrink:0;
  background:linear-gradient(135deg,rgba(59,26,8,.08),rgba(107,45,10,.12));
  border-top:2px solid #8b4513;
}
.report-bar.visible{display:flex}
.report-bar-label{font-size:11px;font-weight:700;color:var(--text2);
  text-transform:uppercase;letter-spacing:.08em;flex-shrink:0}
.rpt-btn{
  display:inline-flex;align-items:center;gap:7px;
  padding:9px 22px;border-radius:var(--r);
  font-size:13px;font-weight:700;text-decoration:none;
  transition:opacity .15s,transform .1s;flex-shrink:0;
}
.rpt-btn:hover{opacity:.88;transform:translateY(-1px)}
.rpt-btn:active{transform:translateY(0)}
.rpt-btn.html{background:linear-gradient(135deg,#5c2e0e,#8b4513);color:#fff;
  box-shadow:0 2px 8px rgba(85,64,170,.4)}
.rpt-btn.csv{background:var(--card2);color:var(--text2);
  border:1.5px solid var(--border2)}
.rpt-btn.csv:hover{border-color:var(--pur2);color:var(--text)}

/* ════ PAGE HEADER (settings / history) ════ */
.page-hdr{
  background:linear-gradient(135deg,#3b1a08 0%,#6b2d0a 50%,#4a1a4e 100%);
  padding:16px 28px;border-bottom:2px solid rgba(255,200,120,.2);flex-shrink:0;
}
.page-hdr h1{font-size:18px;font-weight:800;color:#fff}
.page-hdr p{font-size:13px;color:rgba(255,255,255,.45);margin-top:2px}
.page-body{flex:1;overflow-y:auto;padding:24px 28px}

/* ════ SETTINGS ════ */
.settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;max-width:860px}
.setting-card{background:var(--card);border:1px solid var(--border);
  border-radius:var(--r);padding:20px 22px}
.setting-card h3{font-size:14px;font-weight:700;color:var(--text);margin-bottom:14px;
  padding-bottom:8px;border-bottom:1px solid var(--border)}
.setting-row{margin-bottom:14px}
.setting-row label{display:block;font-size:11px;font-weight:700;color:var(--dim);
  letter-spacing:.07em;text-transform:uppercase;margin-bottom:6px}
.setting-row input,.setting-row select{
  width:100%;background:var(--bg);border:1.5px solid var(--border2);border-radius:6px;
  color:var(--text);font-size:13px;padding:9px 12px;outline:none;
  font-family:var(--mono);
}
.setting-row input:focus,.setting-row select:focus{border-color:var(--pur2)}
.setting-row .readonly{opacity:.55;cursor:not-allowed}
.setting-save{
  margin-top:16px;padding:9px 22px;border-radius:6px;
  background:var(--pur2);color:#fff;border:none;font-size:13px;font-weight:600;
  cursor:pointer;transition:opacity .15s;
}
.setting-save:hover{opacity:.85}
#settings-msg{font-size:12px;margin-top:10px;font-family:var(--mono);min-height:18px}

/* ════ HISTORY ════ */
.hist-toolbar{position:sticky;top:0;z-index:3;background:var(--surface);display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;padding-bottom:8px}
.hist-toolbar input{
  flex:1;min-width:180px;background:var(--card);border:1.5px solid var(--border2);
  border-radius:6px;color:var(--text);font-size:13px;padding:7px 12px;outline:none;
}
.hist-toolbar input:focus{border-color:var(--pur2)}
.hist-toolbar select{
  background:var(--card);border:1.5px solid var(--border2);border-radius:6px;
  color:var(--text);font-size:13px;padding:7px 10px;outline:none;
}
.hist-empty{text-align:center;padding:60px 20px;color:var(--dim);font-size:14px}
.hist-table-wrap{overflow-x:auto;overflow-y:auto;max-height:calc(100vh - 290px)}
table.hist thead tr th{position:sticky;top:0;z-index:2;background:var(--card);}
table.hist{width:100%;border-collapse:collapse;font-size:13px}
table.hist th{
  background:var(--card);color:var(--text2);padding:9px 13px;text-align:left;
  font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;
  border-bottom:2px solid var(--border);
  cursor:pointer;user-select:none;white-space:nowrap;
}
table.hist th:hover{background:var(--pur);color:#fff}
table.hist th.sort-asc::after{content:' ▲';font-size:9px}
table.hist th.sort-desc::after{content:' ▼';font-size:9px}
table.hist td{
  padding:9px 13px;border-bottom:1px solid var(--border);
  vertical-align:middle;color:var(--text2);white-space:nowrap;
}
table.hist tr:hover td{background:rgba(85,64,170,.1)}
table.hist td.td-repo{color:var(--text);font-family:var(--mono);font-size:12px;max-width:200px;
  overflow:hidden;text-overflow:ellipsis}
table.hist td.td-num{text-align:right;font-family:var(--mono);font-weight:700}
table.hist td.td-llm{max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sev-pills{display:flex;gap:3px}
.sp{display:inline-flex;align-items:center;gap:3px;padding:2px 6px;border-radius:3px;
  font-family:var(--mono);font-size:10px;font-weight:700}
.sp-c{background:rgba(192,0,0,.1);color:var(--red);border:1px solid rgba(192,0,0,.25)}
.sp-h{background:rgba(196,94,0,.1);color:var(--ora);border:1px solid rgba(196,94,0,.25)}
.sp-m{background:rgba(160,96,0,.1);color:var(--yel);border:1px solid rgba(160,96,0,.2)}
.sp-l{background:rgba(58,122,58,.1);color:var(--lgrn);border:1px solid rgba(58,122,58,.2)}
.ctx-pills{display:flex;gap:3px;flex-wrap:wrap}
.cp{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600;
  background:var(--card2);color:var(--text2)}
.log-btn{
  padding:4px 10px;border-radius:4px;background:transparent;
  border:1px solid var(--border2);color:var(--dim);font-size:11px;
  cursor:pointer;transition:color .1s,border-color .1s;text-decoration:none;display:inline-block;
}
.log-btn:hover{color:var(--text);border-color:var(--pur2)}
.state-done{color:var(--lgrn);font-weight:600}
.state-stopped{color:var(--ora)}
.state-skipped{color:var(--dim);font-style:italic}
.state-running{color:var(--pur2);animation:pulse 1.4s ease-in-out infinite}

/* ════ SHARED ════ */
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--dim)}
</style>
<script>
// Browser-side UI logic
</script>
</head>
<body>
<div id="app">

<div id="topbar">
  <div class="logo">
    <div class="logo-icon">AI</div>
    AI Security &amp; Compliance Scanner
    <span class="logo-sub">Bitbucket Edition</span>
  </div>
  <div class="top-actions">
    <button class="btn-xs" id="exit-btn" onclick="exitTool()">Exit Tool</button>
  </div>
</div>

<div id="body-wrap">

<!-- SIDEBAR -->
<nav id="sidebar">
  <div class="nav-section">Navigation</div>
  <div class="nav-item active" id="nav-scan" onclick="navTo('scan')">Scan</div>
  <div class="nav-item" id="nav-history" onclick="navTo('history')">Scan History</div>
  <div class="nav-item" id="nav-settings" onclick="navTo('settings')">Settings</div>
  <div class="nav-spacer"></div>
  <div class="nav-version">v19.1</div>
</nav>

<div id="main">

<!-- GLOBAL TAB BAR — persists across all pages -->
<div class="tab-bar-wrap" id="tab-bar-wrap" style="display:none">
  <button class="tab-scroll-btn" id="tab-scroll-left" onclick="_tabScroll(-1)">&#8249;</button>
  <div class="tab-bar" id="tab-bar"></div>
  <button class="tab-scroll-btn" id="tab-scroll-right" onclick="_tabScroll(1)">&#8250;</button>
</div>

<!-- LOGIN -->
<div class="view active" id="v-login">
  <div class="login-wrap">
    <div class="login-hero">
      <span class="login-hero-icon">AI</span>
      <h1>AI Security &amp; Compliance Scanner</h1>
      <p class="subtitle">Bitbucket Edition</p>
    </div>
    <div class="login-body">
      <div class="field">
        <label>Personal Access Token (PAT)</label>
        <input type="password" id="pat-input" placeholder="Paste your token here..." autocomplete="off">
      </div>
      <label class="chk-row">
        <input type="checkbox" id="remember-chk" checked>
        <span>Remember token between sessions</span>
      </label>
      <div id="saved-token-note" style="display:none;font-size:12px;color:var(--dim)">
        A saved token is available on this machine. Leave the field blank to use it.
      </div>
      <div id="login-status"></div>
      <button class="btn-primary" id="connect-btn">Connect</button>
    </div>
  </div>
</div>

<!-- SCAN (contains selector panel + scan tab panels) -->
<div class="view" id="v-scan">
  <div class="page-hdr">
    <h1>Scan</h1>
    <p>Scan repositories for AI/LLM usage patterns and security risks</p>
  </div>
  <!-- Selector panel — shown when selecting a new scan -->
  <div id="v-selector" style="display:flex;flex-direction:column;flex:1;overflow:hidden;min-height:0">
    <div class="sel-body">
      <div class="sel-sidebar">
        <div class="panel-hdr">Projects</div>
        <div id="proj-list"></div>
      </div>
      <div class="sel-content">
        <div class="sel-toolbar">
          <span class="rh" id="repo-hdr">Repositories</span>
          <input class="search-inp" id="repo-search" placeholder="Filter repositories...">
          <button class="btn-xs" onclick="selAll()">All</button>
          <button class="btn-xs" onclick="selNone()">None</button>
        </div>
        <div id="repo-list"></div>
      </div>
    </div>
    <div class="llm-bar">
      <span class="lb">Ollama URL</span>
      <input id="llm-url-inp" value="__LLM_URL__" placeholder="http://localhost:11434">
      <span class="lb">Model</span>
      <select id="llm-model-sel"></select>
      <button class="btn-xs" onclick="refreshModels()">Refresh</button>
      <span id="llm-ind">checking...</span>
    </div>
    <div class="sel-footer">
      <span class="sel-count" id="sel-count">Select a project, then tick repositories</span>
      <button class="btn-go" id="go-btn" disabled onclick="startScan()">Start Scan</button>
    </div>
  </div>
  <!-- Tab panels — active when a scan/report tab is selected -->
  <div id="scan-tabs-area" style="display:none;flex:1;overflow:hidden;min-height:0;position:relative">
    <div id="tab-panels" style="position:absolute;inset:0"></div>
  </div>
</div>

<!-- SETTINGS -->
<div class="view" id="v-settings">
  <div class="page-hdr">
    <h1>Settings</h1>
    <p>Configure scanner connection and LLM review settings</p>
  </div>
  <div class="page-body">
    <div class="settings-grid">
      <div class="setting-card">
        <h3>Bitbucket Connection</h3>
        <div class="setting-row">
          <label>Server URL</label>
          <input id="s-bb-url" class="readonly" readonly>
        </div>
        <div class="setting-row">
          <label>Connected as</label>
          <input id="s-owner" class="readonly" readonly>
        </div>
      </div>
      <div class="setting-card">
        <h3>LLM Review (Ollama)</h3>
        <div class="setting-row">
          <label>Ollama Base URL</label>
          <input id="s-llm-url" placeholder="http://localhost:11434">
        </div>
        <div class="setting-row">
          <label>Model</label>
          <select id="s-llm-model"></select>
        </div>
        <button class="setting-save" onclick="saveSettings()">Save LLM Settings</button>
        <div id="settings-msg"></div>
      </div>
      <div class="setting-card">
        <h3>Output</h3>
        <div class="setting-row">
          <label>Reports Directory</label>
          <div style="display:flex;gap:8px;align-items:center">
            <input id="s-out-dir" placeholder="./output" style="flex:1"
              title="Type a path, e.g. C:\Users\you\scans or ./output">
            <button class="btn-xs" style="padding:7px 12px;flex-shrink:0"
              title="Browse for directory" onclick="browseOutputDir()">📂 Browse</button>
          </div>
          <div style="font-size:11px;color:var(--dim);margin-top:4px">
            Type a path directly or use Browse (requires Chrome/Edge).
          </div>
        </div>
        <button class="setting-save" onclick="saveOutputDir()">Apply Directory</button>
        <div id="outdir-msg" style="font-size:12px;margin-top:8px;font-family:var(--mono);min-height:18px"></div>
      </div>
    </div>
  </div>
</div>

<!-- HISTORY -->
<div class="view" id="v-history">
  <div class="page-hdr">
    <h1>Scan History</h1>
    <p>All completed scans, sortable and filterable</p>
  </div>
  <div class="page-body">
    <div class="hist-toolbar">
      <input id="hist-search" placeholder="Search..." oninput="_histPage=0;renderHistory()">
      <select id="hist-filter-project" onchange="_histPage=0;renderHistory()">
        <option value="">All Projects</option>
      </select>
      <select id="hist-filter-repo" onchange="_histPage=0;renderHistory()">
        <option value="">All Repos</option>
      </select>
      <select id="hist-state" onchange="_histPage=0;renderHistory()">
        <option value="">All States</option>
        <option value="done">Completed</option>
        <option value="stopped">Stopped</option>
        <option value="skipped">Skipped</option>
      </select>
      <select id="hist-filter-llm" onchange="_histPage=0;renderHistory()">
        <option value="">All Models</option>
      </select>
      <select id="hist-filter-triage" onchange="_histPage=0;renderHistory()">
        <option value="">All Triage</option>
        <option value="needs_attention">Needs Attention</option>
        <option value="reviewed">Reviewed</option>
        <option value="accepted_risk">Accepted Risk</option>
        <option value="false_positive">False Positive</option>
      </select>
      <select id="hist-filter-delta" onchange="_histPage=0;renderHistory()">
        <option value="">All Delta</option>
        <option value="new">Has New Findings</option>
        <option value="resolved">Has Resolved Findings</option>
        <option value="baseline">Has Baseline</option>
        <option value="first_scan">First Scan</option>
      </select>
      <button class="btn-xs" onclick="loadHistory()">Refresh</button>
      <button class="btn-xs" id="hist-del-btn" onclick="deleteSelectedHistory()"
        style="display:none;background:#b91c1c;color:#fff;border-color:#b91c1c"
        title="Delete selected rows and their files">Delete selected</button>
    </div>
    <div class="hist-table-wrap">
      <table class="hist" id="hist-table">
        <thead><tr>
          <th style="width:32px;text-align:center">
            <input type="checkbox" id="hist-sel-all" title="Select all"
              onchange="histToggleAll(this.checked)">
          </th>
          <th onclick="histSort('date')" id="hth-date" class="sortable" style="cursor:pointer">Date / Time</th>
          <th onclick="histSort('project')" id="hth-project" class="sortable" style="cursor:pointer">Project</th>
          <th onclick="histSort('repos')" id="hth-repos" class="sortable" style="cursor:pointer">Repositories</th>
          <th onclick="histSort('total')" id="hth-total" class="sortable" style="cursor:pointer">Total</th>
          <th onclick="histSort('attention')" id="hth-attention" class="sortable" style="cursor:pointer">Needs Attention</th>
          <th>Triage</th>
          <th>Delta</th>
          <th>Suppressed</th>
          <th onclick="histSort('critical')" id="hth-critical" class="sortable" style="cursor:pointer">Critical</th>
          <th>High</th>
          <th>By Context</th>
          <th onclick="histSort('llm_model')" id="hth-llm_model" class="sortable" style="cursor:pointer">LLM Model</th>
          <th onclick="histSort('duration')" id="hth-duration" class="sortable" style="cursor:pointer">Duration</th>
          <th>State</th>
          <th>HTML</th>
          <th>CSV</th>
          <th>Log</th>
        </tr></thead>
        <tbody id="hist-body"></tbody>
      </table>
      <div class="hist-empty" id="hist-empty" style="display:none">No scan history yet. Run a scan to see records here.</div>
    </div>
    <div style="display:flex;align-items:center;gap:10px;margin-top:10px;flex-wrap:wrap">
      <span id="hist-pg-info" style="font-size:12px;color:var(--dim);flex:1"></span>
      <div id="hist-pg-controls" style="display:flex;gap:4px;flex-wrap:wrap"></div>
    </div>
  </div>
</div>


</div><!-- #main -->
</div><!-- #body-wrap -->
</div><!-- #app -->

<script>
"use strict";
let _projects=[],_repos={},_selVars={},_curProj=null,_owner="";
let _sse=null,_pollTimer=null;
// scan state derived from _tabs array
let _histData=[],_histSortCol='date',_histSortDir='desc';
let _histPage=0;
const HIST_PAGE_SIZE=20;

// ── NAV ───────────────────────────────────────────────────────────
function show(id){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}
// Show the selector panel inside v-scan
function showSelector(){
  document.getElementById('v-selector').style.display='flex';
  document.getElementById('scan-tabs-area').style.display='none';
  const hdr=document.querySelector('#v-scan .page-hdr');
  if(hdr) hdr.style.display='';
}
function showTabsArea(){
  document.getElementById('v-selector').style.display='none';
  document.getElementById('scan-tabs-area').style.display='flex';
  // Hide the "🔍 Scan" page header — it obscures iframe/tab content
  const hdr=document.querySelector('#v-scan .page-hdr');
  if(hdr) hdr.style.display='none';
}
async function ensureProjectsLoaded(){
  if(_projects.length) return true;
  try{
    const r=await fetch('/api/projects');
    const d=await r.json();
    if(!r.ok) throw new Error(d.error||'Failed to load projects');
    _projects=d.projects||[];
    _owner=d.owner||_owner;
    return _projects.length>0;
  }catch(e){
    console.error('ensureProjectsLoaded:', e);
    return false;
  }
}
async function _openSelectorTab(){
  // If selector tab already exists, switch to it
  if(_selectorTabId && _getTab(_selectorTabId)){
    _switchTab(_selectorTabId);
    showSelector();
    await ensureProjectsLoaded();
    buildProjectList();
    refreshModels();
    return;
  }
  // Create a new "New Scan" tab
  const tid = ++_tabSeq;
  _selectorTabId = tid;
  const tabEl=document.createElement('div');
  tabEl.className='scan-tab';
  tabEl.id=`tab-${tid}`;
  tabEl.onclick=()=>{ _switchTab(tid); show('v-scan'); showSelector(); ensureProjectsLoaded().then(()=>buildProjectList()); };
  const lblEl=document.createElement('span');
  lblEl.className='tab-label';
  lblEl.textContent='＋ New Scan';
  const closeEl=document.createElement('span');
  closeEl.className='tab-close';
  closeEl.textContent='✕';
  closeEl.onclick=e=>{
    e.stopPropagation();
    tabEl.remove();
    _tabs=_tabs.filter(t=>t.id!==tid);
    _selectorTabId=null;
    _syncTabBar();
    if(_tabs.length) _switchTab(_tabs[0].id);
    else { show('v-scan'); showSelector(); }
  };
  tabEl.append(lblEl, closeEl);
  closeEl.style.display='block';
  document.getElementById('tab-bar').appendChild(tabEl);
  const tab={id:tid, label:'New Scan', state:'selector',
             sse:null, pollTimer:null,
             dotEl:{className:''},
             lblEl, closeEl, tabEl, panelEl:null,
             isSelector:true};
  _tabs.push(tab);
  _switchTab(tid);
  _syncTabBar();
  show('v-scan');
  showSelector();
  await ensureProjectsLoaded();
  buildProjectList();
  refreshModels();
}
function _syncTabBar(){
  // Show the global tab bar whenever tabs exist, regardless of active page
  const wrap=document.getElementById('tab-bar-wrap');
  if(wrap) wrap.style.display=_tabs.length>0?'flex':'none';
}
function navTo(page){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('nav-'+page).classList.add('active');
  if(page==='scan'){
    if(!_curProj){ show('v-login'); return; }
    show('v-scan');
    if(_anyRunning()){
      showTabsArea();  // running — keep focused on active scan
      return;
    }
    // Open selector as a tab (create once, reuse if already open)
    _openSelectorTab();
  }
  else if(page==='settings'){show('v-settings');loadSettings()}
  else if(page==='history'){show('v-history');loadHistory()}
}
function showSidebar(){document.getElementById('sidebar').classList.add('visible')}

// ── LOGIN ─────────────────────────────────────────────────────────
const HAS_SAVED_PAT = (__HAS_SAVED_PAT__ === true);
if(HAS_SAVED_PAT){
  document.getElementById('saved-token-note').style.display='block';
}
document.getElementById('pat-input').addEventListener('keydown',e=>{if(e.key==='Enter')connect()});
document.getElementById('connect-btn').addEventListener('click',connect);

// ── Page-load recovery ────────────────────────────────────────────
// If the server already has an active or recently completed scan session,
// restore the UI without requiring a new login (handles page reload + nav-away).
(async function _recoverSession(){
  try{
    const r = await fetch('/api/scan/status');
    const d = await r.json();
    const activeStates = ['running','done','stopped','skipped','error'];
    if(!activeStates.includes(d.state)) return;  // idle — nothing to recover
    const proj = d.project_key || '';
    // Restore client state
    _curProj = proj;
    showSidebar();
    show('v-scan');
    document.getElementById('nav-scan').classList.add('active');
    // Build a recovery tab that polls the existing session
    const repoList = Object.keys(d.per_repo||{});
    const repoLabel = repoList.length===1 ? repoList[0] : `${repoList.length} repos`;
    const label = `${proj} | ${repoLabel}`;
    const tab = _createTab(label);
    const tid = tab.id;
    tab.scan_id = d.scan_id;

    if(d.state==='running'){
      showTabsArea();
      _connectSSE(tab);
      _startPoll(tab);
    } else {
      // Already finished — restore final state immediately
      showTabsArea();
      _onTabFinished(tab, d);
      _updateScanUI(tid, d);
    }
  }catch(e){
    // Server unreachable or no session — stay on login
  }
})();
function setStatus(msg,color){
  const el=document.getElementById('login-status');
  el.textContent=msg;el.style.color=color||'var(--dim)';
}
async function connect(){
  const token=document.getElementById('pat-input').value.trim();
  const useSavedToken = !token && HAS_SAVED_PAT;
  if(!token && !useSavedToken){setStatus('Please enter your Personal Access Token.','var(--red)');return}
  const btn=document.getElementById('connect-btn');
  btn.disabled=true;setStatus(useSavedToken?'Connecting with saved token�':'Connecting�','var(--dim)');
  try{
    const r=await fetch('/api/connect',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        token,
        use_saved_token:useSavedToken,
        remember:document.getElementById('remember-chk').checked
      })});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error||'Connection failed');
    _owner=d.owner||'';_projects=d.projects||[];
    showSidebar();buildProjectList();show('v-scan');_openSelectorTab();
  }catch(e){setStatus(e.message,'var(--red)')}
  finally{btn.disabled=false}
}

// ── SELECTOR ──────────────────────────────────────────────────────
function buildProjectList(){
  const el=document.getElementById('proj-list');el.innerHTML='';
  _projects.forEach(p=>{
    const key=p.key||p.slug||'';
    const div=document.createElement('div');
    div.className='proj-item';div.textContent=key;div.dataset.key=key;
    div.addEventListener('click',()=>pickProject(key,div));el.appendChild(div);
  });
  if(_projects.length){
    const wanted=[...el.querySelectorAll('.proj-item')].find(item=>item.dataset.key===_curProj);
    const target=wanted||el.querySelector('.proj-item');
    if(target) target.click();
  }else{
    document.getElementById('repo-hdr').textContent='Repositories';
    document.getElementById('repo-list').innerHTML='';
    updateSelCount();
  }
}
async function pickProject(key,el){
  document.querySelectorAll('.proj-item').forEach(e=>e.classList.remove('active'));
  el.classList.add('active');_curProj=key;_selVars={};
  document.getElementById('repo-hdr').textContent=`${key} - Loading...`;
  document.getElementById('repo-list').innerHTML='';updateSelCount();
  if(_repos[key]){buildRepoList(_repos[key]);return}
  try{
    const r=await fetch(`/api/repos?project=${encodeURIComponent(key)}`);
    const d=await r.json();_repos[key]=d.repos||[];buildRepoList(_repos[key]);
  }catch(e){document.getElementById('repo-hdr').textContent=`${key} - Error: ${e.message}`}
}
function buildRepoList(repos,filter=''){
  const el=document.getElementById('repo-list');
  const hdr=document.getElementById('repo-hdr');
  const list=filter?repos.filter(r=>r.slug.toLowerCase().includes(filter.toLowerCase())):repos;
  hdr.textContent=`${_curProj} - ${repos.length} repo${repos.length===1?'':'s'}`;
  el.innerHTML='';
  // Choose column count: 1 for <=8, 2 for <=20, 3 for >20
  const cols=repos.length<=8?1:repos.length<=20?2:3;
  const grid=document.createElement('div');
  grid.className=`repo-grid cols-${cols}`;
  list.forEach(repo=>{
    const slug=repo.slug||'';
    const row=document.createElement('div');
    row.className='repo-item'+((_selVars[slug])?' checked':'');
    const chk=document.createElement('input');chk.type='checkbox';chk.id=`chk-${slug}`;
    chk.checked=!!_selVars[slug];
    chk.addEventListener('change',()=>{
      _selVars[slug]=chk.checked;
      row.classList.toggle('checked',chk.checked);
      updateSelCount();
    });
    const lbl=document.createElement('label');lbl.htmlFor=`chk-${slug}`;lbl.textContent=slug;
    row.append(chk,lbl);grid.appendChild(row);
  });
  el.appendChild(grid);
  updateSelCount();
}
document.getElementById('repo-search').addEventListener('input',e=>{
  if(_curProj&&_repos[_curProj]) buildRepoList(_repos[_curProj],e.target.value);
});
function selAll(){
  const q=document.getElementById('repo-search').value.trim().toLowerCase();
  (_repos[_curProj]||[]).forEach(r=>{if(!q||r.slug.toLowerCase().includes(q))_selVars[r.slug]=true});
  buildRepoList(_repos[_curProj]||[],document.getElementById('repo-search').value);
}
function selNone(){
  Object.keys(_selVars).forEach(k=>_selVars[k]=false);
  buildRepoList(_repos[_curProj]||[],document.getElementById('repo-search').value);
}
function updateSelCount(){
  const n=Object.values(_selVars).filter(Boolean).length;
  const el=document.getElementById('sel-count');const btn=document.getElementById('go-btn');
  if(n){el.textContent=`${n} repo${n===1?'':'s'} selected`;el.className='sel-count has';btn.disabled=false}
  else{el.textContent='Select a project, then tick repositories';el.className='sel-count';btn.disabled=true}
}

// ── OLLAMA ────────────────────────────────────────────────────────
async function _startOllamaAndReload(url){
  const ind=document.getElementById('llm-ind');
  ind.textContent='Starting Ollama...';ind.className='ind-ok';
  try{
    const r=await fetch('/api/ollama/start',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url})});
    const d=await r.json();
    if(d.ok&&d.models.length){
      _populateModelDropdown(d.models);
      ind.textContent=`${d.models.length} model${d.models.length===1?'':'s'}`;ind.className='ind-ok';
    }else if(d.ok&&!d.models.length){
      ind.textContent='Ollama running, no models - run: ollama pull qwen2.5-coder:7b-instruct';ind.className='ind-warn';
    }else{
      ind.textContent=`Warning: ${d.error||'Could not start Ollama'}`;ind.className='ind-err';
    }
  }catch(e){
    ind.textContent='Warning: Ollama unreachable - install from ollama.com';ind.className='ind-err';
  }
}
function _populateModelDropdown(models){
  const sel=document.getElementById('llm-model-sel');
  const prev=sel.value;
  const savedModel='__LLM_MODEL__';
  sel.innerHTML='';
  models.forEach(m=>{
    const o=document.createElement('option');o.value=o.textContent=m;
    if(m===prev||m===savedModel) o.selected=true;
    sel.appendChild(o);
  });
  if(!sel.value&&savedModel){
    for(const opt of sel.options) if(opt.value===savedModel){opt.selected=true;break}
  }
  if(!sel.value&&sel.options.length) sel.options[0].selected=true;
}

async function refreshModels(){
  // Single fast check. If Ollama is reachable and has models — done.
  // Otherwise hand off to _startOllamaAndReload which does the heavy lifting.
  const ind=document.getElementById('llm-ind');
  ind.textContent='checking...';ind.className='';
  const url=document.getElementById('llm-url-inp').value.trim()||'http://localhost:11434';
  try{
    const r=await fetch('/api/ollama/models?url='+encodeURIComponent(url));
    const d=await r.json();
    if(d.models&&d.models.length){
      _populateModelDropdown(d.models);
      ind.textContent=`${d.models.length} model${d.models.length===1?'':'s'}`;ind.className='ind-ok';
    }else{
      // Not running or no models — start it
      _startOllamaAndReload(url);
    }
  }catch(e){
    // Unreachable — start it
    _startOllamaAndReload(url);
  }
}

// Refresh models when Ollama URL input changes (with debounce)
let _urlDebounce=null;
document.getElementById('llm-url-inp').addEventListener('input',()=>{
  clearTimeout(_urlDebounce);
  _urlDebounce=setTimeout(()=>refreshModels(0), 800);
});

// ── SCAN ──────────────────────────────────────────────────────────
// ── SCAN TABS ─────────────────────────────────────────────────────
// Each tab is: { id, scan_id, label, state, sse, pollTimer, el, dotEl, panelEl, logs, statusData }
let _selectorTabId = null;  // ID of the "New Scan" selector tab (if open)
let _tabs = [];
let _activeTabId = null;
let _tabSeq = 0;

function _tabPanelHTML(tid){
  return `<div class="tab-panel" id="tp-${tid}">
  <div class="scan-body">
    <div class="log-panel">
      <div class="log-header">
        <div class="lh-icon" id="run-dot-${tid}"></div>
        <span class="lh-title" id="scan-title-${tid}">Scanning...</span>
        <span class="lh-eta" id="scan-eta-${tid}"></span>
        <button class="btn-xs scan-action-btn" id="scan-stop-${tid}" onclick="stopScan(${tid})">Cancel Scan</button>
      </div>
      <div class="prog-wrap"><div class="prog-fill" id="prog-bar-${tid}"></div></div>
      <div id="log-out-${tid}" class="log-out-pane"></div>
    </div>
    <div class="findings-panel">
      <div class="fp-header">
        <span class="fp-title">Scan Status</span>
        <span class="fp-subtitle" id="fp-total-${tid}">Waiting for scan results...</span>
      </div>
      <div class="kpi-strip">
        <div class="kpi-cell k1"><div class="kpi-n" id="k-crit-${tid}">-</div><div class="kpi-l">Critical</div></div>
        <div class="kpi-cell k2"><div class="kpi-n" id="k-high-${tid}">-</div><div class="kpi-l">High</div></div>
        <div class="kpi-cell k3"><div class="kpi-n" id="k-med-${tid}" >-</div><div class="kpi-l">Medium</div></div>
        <div class="kpi-cell k4"><div class="kpi-n" id="k-low-${tid}" >-</div><div class="kpi-l">Low</div></div>
      </div>
      <div id="repo-cards-${tid}"></div>
      <div class="monitor-panel">
        <div class="monitor-spacer"></div>
        <div class="phase-timeline" id="phase-tl-${tid}"></div>
      </div>
    </div>
    <div class="finding-drawer">
      <div class="finding-drawer-head">
        <span class="finding-drawer-title">Finding Details</span>
        <div class="finding-switches">
          <button class="finding-switch active" id="finding-switch-active-${tid}" onclick="showFindingPane(${tid},'active')">
            <span>Active</span>
            <span class="finding-switch-count" id="finding-count-${tid}">0</span>
          </button>
          <button class="finding-switch" id="finding-switch-suppressed-${tid}" onclick="showFindingPane(${tid},'suppressed')">
            <span>Suppressed</span>
            <span class="finding-switch-count" id="suppressed-count-${tid}">0</span>
          </button>
        </div>
      </div>
      <div class="finding-panes">
        <div class="finding-pane active" id="finding-pane-active-${tid}">
          <div class="finding-list" id="finding-list-${tid}"></div>
        </div>
        <div class="finding-pane" id="finding-pane-suppressed-${tid}">
          <div class="finding-list" id="suppressed-list-${tid}"></div>
        </div>
      </div>
    </div>
  </div>
  <div class="report-bar" id="report-bar-${tid}">
  </div>
</div>`;
}

function _createTab(label){
  const tid = ++_tabSeq;

  // Tab button
  const tabEl = document.createElement('div');
  tabEl.className = 'scan-tab';
  tabEl.id = `tab-${tid}`;
  tabEl.onclick = ()=>_switchTab(tid);
  const dotEl = document.createElement('div');dotEl.className='tab-dot running';
  const lblEl = document.createElement('span');lblEl.className='tab-label';lblEl.textContent=label;
  const closeEl = document.createElement('span');closeEl.className='tab-close';closeEl.textContent='✕';
  closeEl.onclick = e=>{e.stopPropagation();_closeTab(tid)};
  tabEl.append(dotEl, lblEl, closeEl);

  const bar = document.getElementById('tab-bar');
  bar.appendChild(tabEl);

  // Panel
  const panels = document.getElementById('tab-panels');
  panels.insertAdjacentHTML('beforeend', _tabPanelHTML(tid));
  const panelEl = document.getElementById(`tp-${tid}`);

  const tab = {id:tid, label, state:'running',
               sse:null, pollTimer:null,
               dotEl, lblEl, closeEl, tabEl, panelEl,
               logs:[], statusData:null};
  _tabs.push(tab);
  _switchTab(tid);
  _syncTabBar();
  return tab;
}

function _getTab(tid){ return _tabs.find(t=>t.id===tid) }

function _switchTab(tid){
  _activeTabId = tid;
  _tabs.forEach(t=>{
    if(t.panelEl) t.panelEl.classList.toggle('active', t.id===tid);
    t.tabEl.classList.toggle('active', t.id===tid);
  });
  // Navigate to v-scan if not already there
  const vscan = document.getElementById('v-scan');
  if(vscan && !vscan.classList.contains('active')){
    document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
    vscan.classList.add('active');
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    const ns=document.getElementById('nav-scan');if(ns)ns.classList.add('active');
  }
  // Show selector panel for selector tab, tabs area for scan/report tabs
  const tab=_getTab(tid);
  if(tab && tab.isSelector) showSelector();
  else showTabsArea();
}

async function _closeTab(tid){
  const tab = _getTab(tid);
  if(!tab) return;
  if(tab.state==='running'){
    // Stop the scan, then close the tab and open selector
    try{ await fetch('/api/scan/stop',{method:'POST'}); }catch(_){}
  }
  if(tab.sse) tab.sse.close();
  if(tab.pollTimer) clearInterval(tab.pollTimer);
  tab.tabEl.remove();
  if(tab.panelEl) tab.panelEl.remove();
  _tabs = _tabs.filter(t=>t.id!==tid);
  _syncTabBar();
  // Always open selector tab after closing any scan tab
  _openSelectorTab();
}

function _createReportTab(scanLabel, url){
  const tid = ++_tabSeq;

  // Tab button
  const tabEl = document.createElement('div');
  tabEl.className = 'scan-tab';
  tabEl.id = `tab-${tid}`;
  tabEl.onclick = ()=>_switchTab(tid);
  const dotEl = document.createElement('div');
  dotEl.className = 'tab-dot report';
  const lblEl = document.createElement('span');
  lblEl.className = 'tab-label';
  lblEl.textContent = 'Report: ' + scanLabel;
  const closeEl = document.createElement('span');
  closeEl.className = 'tab-close';
  closeEl.textContent = '✕';
  closeEl.onclick = e => { e.stopPropagation(); _closeReportTab(tid); };
  tabEl.append(dotEl, lblEl, closeEl);
  // Always show close on report tabs
  closeEl.style.display = 'block';

  document.getElementById('tab-bar').appendChild(tabEl);

  // Panel: just an iframe
  const panelEl = document.createElement('div');
  panelEl.className = 'tab-panel';
  panelEl.id = `tp-${tid}`;
  const iframe = document.createElement('iframe');
  iframe.className = 'report-iframe';
  iframe.src = url;
  iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
  panelEl.appendChild(iframe);
  document.getElementById('tab-panels').appendChild(panelEl);

  const tab = {id:tid, label:scanLabel, state:'done',
               sse:null, pollTimer:null,
               dotEl, lblEl, closeEl, tabEl, panelEl,
               isReport:true};
  _tabs.push(tab);
  _switchTab(tid);
  _syncTabBar();
  // Ensure the scan view is visible with tabs area
  document.getElementById('nav-scan').classList.add('active');
  document.querySelectorAll('.nav-item:not(#nav-scan)').forEach(n=>n.classList.remove('active'));
  show('v-scan');
  showTabsArea();
}

function _closeReportTab(tid){
  const tab = _getTab(tid);
  if(!tab) return;
  tab.tabEl.remove();
  tab.panelEl.remove();
  _tabs = _tabs.filter(t=>t.id!==tid);
  _syncTabBar();
  if(_activeTabId===tid){
    if(_tabs.length) _switchTab(_tabs[0].id);
    else { goToSelector(); }
  }
}

function _openLogTab(scanId, label){
  // Open scan log as a pre-formatted text page in an internal tab
  const url = '/api/history/log/' + encodeURIComponent(scanId);
  const tid  = ++_tabSeq;

  const tabEl   = document.createElement('div');
  tabEl.className = 'scan-tab';
  tabEl.id = `tab-${tid}`;
  tabEl.onclick = () => _switchTab(tid);
  const dotEl   = document.createElement('div');
  dotEl.className = 'tab-dot report';
  const lblEl   = document.createElement('span');
  lblEl.className  = 'tab-label';
  lblEl.textContent = 'Log: ' + (label || scanId);
  const closeEl = document.createElement('span');
  closeEl.className = 'tab-close';
  closeEl.textContent = '✕';
  closeEl.style.display = 'block';
  closeEl.onclick = e => { e.stopPropagation(); _closeReportTab(tid); };
  tabEl.append(dotEl, lblEl, closeEl);
  document.getElementById('tab-bar').appendChild(tabEl);

  // Panel: iframe styled for plain-text log viewing
  const panelEl = document.createElement('div');
  panelEl.className = 'tab-panel';
  panelEl.id = `tp-${tid}`;
  const iframe = document.createElement('iframe');
  iframe.className = 'report-iframe';
  iframe.src = url;
  iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
  panelEl.appendChild(iframe);
  document.getElementById('tab-panels').appendChild(panelEl);

  const tab = {id:tid, label, state:'done', sse:null, pollTimer:null,
               dotEl, lblEl, closeEl, tabEl, panelEl, isReport:true};
  _tabs.push(tab);
  _switchTab(tid);
  _syncTabBar();
  document.getElementById('nav-scan').classList.add('active');
  document.querySelectorAll('.nav-item:not(#nav-scan)').forEach(n=>n.classList.remove('active'));
  show('v-scan');
  showTabsArea();
}

function _setTabState(tid, state){
  const tab = _getTab(tid); if(!tab) return;
  tab.state = state;
  tab.dotEl.className = 'tab-dot ' + state;
  // Show close button once not running
  if(state !== 'running') tab.closeEl.style.display = '';
}

function _setTabLabel(tid, label){
  const tab = _getTab(tid); if(!tab) return;
  tab.lblEl.textContent = label;
}

function _tabScroll(dir){
  const bar=document.getElementById('tab-bar');
  if(bar) bar.scrollBy({left:dir*180,behavior:'smooth'});
}
// ── compat: _scanActive/_scanDone still used by navTo ─────────────
function _anyRunning(){ return _tabs.some(t=>t.state==='running') }
function _anyDone()   { return _tabs.some(t=>t.state!=='running') }

async function startScan(){
  const slugs=Object.entries(_selVars).filter(([,v])=>v).map(([k])=>k);
  if(!slugs.length||!_curProj) return;

  // Show v-scan immediately with tabs area
  document.getElementById('nav-scan').classList.add('active');
  document.querySelectorAll('.nav-item:not(#nav-scan)').forEach(n=>n.classList.remove('active'));
  show('v-scan');
  showTabsArea();

  const repoLabel = slugs.length===1 ? slugs[0] : `${slugs.length} repos`;
  const label = `${_curProj} | ${repoLabel}`;
  // Close selector tab if open
  if(_selectorTabId && _getTab(_selectorTabId)){
    const selTab=_getTab(_selectorTabId);
    selTab.tabEl.remove();
    _tabs=_tabs.filter(t=>t.id!==_selectorTabId);
    _selectorTabId=null;
  }
  const tab = _createTab(label);
  const tid = tab.id;

  document.getElementById(`run-dot-${tid}`).classList.add('running');


  try{
    const r=await fetch('/api/scan/start',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        project_key:_curProj, repo_slugs:slugs,
        llm_url:document.getElementById('llm-url-inp').value.trim(),
        llm_model:document.getElementById('llm-model-sel').value,
      })});
    const d=await r.json();
    if(!r.ok){ alert(d.error); _closeTab(tid); return }
    tab.scan_id = d.scan_id;
    _connectSSE(tab);
    _startPoll(tab);
  }catch(e){alert('Failed to start scan: '+e.message); _closeTab(tid)}
}

async function stopScan(tid){
  const btn=document.getElementById(`scan-stop-${tid}`);
  if(btn) btn.disabled=true;
  try{
    const r=await fetch('/api/scan/stop',{method:'POST'});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error||'Failed to stop scan');
  }catch(e){
    if(btn) btn.disabled=false;
    alert('Failed to stop scan: '+e.message);
  }
}

async function exitTool(){
  const running=_tabs.some(t=>t.state==='running');
  const msg=running
    ? 'A scan is still running. Exit the tool and stop all related processes?'
    : 'Exit the tool now?';
  if(!confirm(msg)) return;
  const btn=document.getElementById('exit-btn');
  if(btn) btn.disabled=true;
  try{
    await fetch('/api/app/shutdown',{method:'POST'});
  }catch(_){}
  document.body.innerHTML='<div style="padding:40px;font-family:Segoe UI,system-ui,sans-serif;color:#2c1a08;background:#f5ede0">Shutting down the scanner...</div>';
  setTimeout(()=>window.close(), 300);
}

function _fmtFindingLoc(f){
  const file=f.file||'';
  const line=f.line?`:${f.line}`:'';
  return `${f.repo||'-'} | ${file}${line}`;
}

function showFindingPane(tid, pane){
  ['active','suppressed'].forEach(name=>{
    const btn=document.getElementById(`finding-switch-${name}-${tid}`);
    const panel=document.getElementById(`finding-pane-${name}-${tid}`);
    if(btn) btn.classList.toggle('active', name===pane);
    if(panel) panel.classList.toggle('active', name===pane);
  });
}

function _triageLabel(status){
  return status==='reviewed' ? 'Reviewed'
    : status==='accepted_risk' ? 'Accepted Risk'
    : status==='false_positive' ? 'False Positive'
    : '';
}

function _renderFindingCard(f, suppressed, tid){
  const sev=f.severity||4;
  const title=_esc(f.capability||f.provider_or_lib||'Finding');
  const meta=_esc(_fmtFindingLoc(f));
  const desc=_esc(f.description||'');
  const triageStatus=f.triage_status||'';
  const triageLabel=_triageLabel(triageStatus);
  const policy=f.policy_status?`<div class="finding-note">Policy: ${_esc(f.policy_status)}</div>`:'';
  const tags=[
    f.delta_status ? `<span class="finding-chip delta-${_esc(f.delta_status)}">${_esc(f.delta_status==='new'?'New Since Baseline':'Unchanged')}</span>` : '',
    triageLabel ? `<span class="finding-chip triage-${_esc(triageStatus)}">${_esc(triageLabel)}</span>` : '',
  ].filter(Boolean).join('');
  const note=suppressed
    ? `<div class="finding-note">Reason: ${_esc(f.reason||'')} ${f.marked_by?`| By: ${_esc(f.marked_by)}`:''} ${f.marked_at?`| At: ${_esc(f.marked_at)}`:''}</div>`
    : (f.reason||f.marked_by||f.marked_at)
      ? `<div class="finding-note">Note: ${_esc(f.reason||'')} ${f.marked_by?`| By: ${_esc(f.marked_by)}`:''} ${f.marked_at?`| At: ${_esc(f.marked_at)}`:''}</div>`
      : '';
  const actions=suppressed
    ? `<button class="finding-btn safe" onclick="unsuppressFinding('${tid}','${_esc(f.hash)}')">Restore</button>`
    : [
        triageStatus!=='reviewed'
          ? `<button class="finding-btn info" onclick="triageFinding('${tid}','${_esc(f.hash)}','reviewed')">Review</button>`
          : '',
        triageStatus!=='accepted_risk'
          ? `<button class="finding-btn alt" onclick="triageFinding('${tid}','${_esc(f.hash)}','accepted_risk')">Accept Risk</button>`
          : '',
        `<button class="finding-btn warn" onclick="triageFinding('${tid}','${_esc(f.hash)}','false_positive')">False Positive</button>`,
        triageStatus
          ? `<button class="finding-btn safe" onclick="resetFinding('${tid}','${_esc(f.hash)}')">Reset</button>`
          : '',
      ].filter(Boolean).join('');
  return `<div class="finding-item">
    <div class="finding-main">
      <span class="finding-badge sev-${sev}">Sev-${sev}</span>
      <div class="finding-body">
        <div class="finding-title">${title}</div>
        <div class="finding-meta">${meta}</div>
        ${tags?`<div class="finding-tags">${tags}</div>`:''}
        ${desc?`<div class="finding-desc">${desc}</div>`:''}
        ${policy}
        ${note}
      </div>
      <div class="finding-actions">${actions}</div>
    </div>
  </div>`;
}

async function suppressFinding(tid, hash){
  return triageFinding(tid, hash, 'false_positive');
}

async function triageFinding(tid, hash, status){
  let note='';
  if(status==='false_positive'){
    note=prompt('Enter the false-positive rationale for this finding:');
    if(note==null) return;
    note=note.trim();
    if(!note){ alert('A note is required for false positive.'); return; }
  }else if(status==='accepted_risk'){
    note=prompt('Enter the accepted-risk rationale for this finding:');
    if(note==null) return;
    note=note.trim();
    if(!note){ alert('A note is required for accepted risk.'); return; }
  }else if(status==='reviewed'){
    const input=prompt('Optional review note:');
    if(input==null) return;
    note=input.trim();
  }
  try{
    const r=await fetch('/api/findings/triage',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({hash, status, note})});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error||'Failed to update finding triage');
    const tab=_getTab(Number(tid)); if(tab){ tab.statusData=d.status; _updateScanUI(Number(tid), d.status); }
  }catch(e){
    alert('Failed to update triage: '+e.message);
  }
}

async function unsuppressFinding(tid, hash){
  return resetFinding(tid, hash);
}

async function resetFinding(tid, hash){
  try{
    const r=await fetch('/api/findings/reset',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({hash})});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error||'Failed to reset finding triage');
    const tab=_getTab(Number(tid)); if(tab){ tab.statusData=d.status; _updateScanUI(Number(tid), d.status); }
  }catch(e){
    alert('Failed to reset triage: '+e.message);
  }
}

// ── SSE ────────────────────────────────────────────────────────────
// ── PHASE TIMELINE + MONITOR LOG ─────────────────────────────────

const _PHASES = ['Init','Clone','Detect','LLM Review','Aggregate','Report'];
const _phaseStartTs = {};  // tid → [startMs, ...]  set when phase goes active
const _phaseEndTs   = {};  // tid → [endMs, ...]    set when NEXT phase goes active

function _initPhaseTimeline(tid){
  const tl=document.getElementById(`phase-tl-${tid}`);
  if(!tl) return;
  _phaseStartTs[tid] = new Array(_PHASES.length).fill(null);
  _phaseEndTs[tid]   = new Array(_PHASES.length).fill(null);
  tl.innerHTML=_PHASES.map((p,i)=>
    `<div class="phase-row ph-wait" id="ph-row-${tid}-${i}" data-phase="${p}">
       <div class="phase-icon">.</div>
       <span class="phase-label">${p}</span>
       <span class="phase-detail" id="ph-det-${tid}-${i}"></span>
     </div>`
  ).join('');
}

function _fmtDurMs(ms){
  if(ms==null||ms<=0) return '';
  if(ms<1000) return '<1s';
  const s=Math.round(ms/1000);
  if(s<60) return s+'s';
  return Math.floor(s/60)+'m '+String(s%60).padStart(2,'0')+'s';
}

function _setPhase(tid, phaseIdx, state){
  const row=document.getElementById(`ph-row-${tid}-${phaseIdx}`);
  if(!row) return;
  const prevClass=row.className;
  row.className=`phase-row ph-${state}`;
  const icon=row.querySelector('.phase-icon');
  icon.textContent = state==='done'?'OK' : state==='active'?'>': state==='skip'?'-' : '.';

  const now=Date.now();
  if(!_phaseStartTs[tid]) _phaseStartTs[tid]=new Array(_PHASES.length).fill(null);
  if(!_phaseEndTs[tid])   _phaseEndTs[tid]  =new Array(_PHASES.length).fill(null);

  if(state==='active' && !prevClass.includes('ph-active')){
    _phaseStartTs[tid][phaseIdx]=now;
    // The previous phase ended right now (this phase just started)
    if(phaseIdx>0 && _phaseEndTs[tid][phaseIdx-1]===null){
      _phaseEndTs[tid][phaseIdx-1]=now;
    }
  }

  if(state==='done'){
    if(_phaseEndTs[tid][phaseIdx]===null) _phaseEndTs[tid][phaseIdx]=now;
    const start=_phaseStartTs[tid][phaseIdx];
    const end  =_phaseEndTs[tid][phaseIdx];
    const det=document.getElementById(`ph-det-${tid}-${phaseIdx}`);
    if(det && start!==null) det.textContent=_fmtDurMs(end-start);
  }
}

// Detect which phase a log message belongs to
function _detectPhaseFromMsg(msg){
  if(/Scan ID\s*:/.test(msg))                                     return 0; // Init
  if(/branch:|metadata|clone|Cloning/.test(msg))                  return 1; // Clone
  if(/Scanning:|files\)|patterns found/.test(msg))                return 2; // Detect
  if(/\[LLM\]/.test(msg))                                         return 3; // LLM Review
  if(/Total findings|deduped|Aggregat/.test(msg))                 return 4; // Aggregate
  if(/Generating reports|Writing CSV|Writing HTML|Report\]|OK Report/.test(msg)) return 5; // Report
  return -1;
}

function _updatePhasesFromLog(tid, msg, phaseState){
  const idx=_detectPhaseFromMsg(msg);
  if(idx<0) return;
  // Mark previous phases done only if not already done
  for(let i=0;i<idx;i++){
    const r=document.getElementById(`ph-row-${tid}-${i}`);
    if(r && !r.className.includes('ph-done')) _setPhase(tid,i,'done');
  }
  if(phaseState==='running') _setPhase(tid,idx,'active');
  else                       _setPhase(tid,idx,'done');
}

function _finalisePhases(tid){
  const now=Date.now();
  // Seal any phase still active before marking all done
  if(_phaseEndTs[tid]){
    _phaseEndTs[tid].forEach((v,i)=>{
      if(v===null && (_phaseStartTs[tid]||[])[i]!==null)
        _phaseEndTs[tid][i]=now;
    });
  }
  for(let i=0;i<_PHASES.length;i++) _setPhase(tid,i,'done');
}

function _connectSSE(tab){
  if(tab.sse) tab.sse.close();
  _initPhaseTimeline(tab.id);
  const sse = new EventSource('/api/scan/stream');
  tab.sse = sse;
  sse.onmessage = e=>{
    try{
      const entry=JSON.parse(e.data);
      tab.logs.push(entry);
      _appendLog(tab.id, entry);
      _updatePhasesFromLog(tab.id, entry.msg||'', 'running');
      const title=document.getElementById(`scan-title-${tab.id}`);
      const eta=document.getElementById(`scan-eta-${tab.id}`);
    }catch(_){}
  };
  sse.onerror = ()=>sse.close();
}

function _appendLog(tid, entry){
  const el=document.getElementById(`log-out-${tid}`); if(!el) return;
  const lvl=entry.level||'dim';
  if(lvl==='hd'&&el.children.length){
    const sep=document.createElement('hr');sep.className='log-sep';el.appendChild(sep);
  }
  const ts=new Date((entry.ts||0)*1000);
  const tStr=ts.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const row=document.createElement('div');row.className=`log-entry lv-${lvl}`;
  const tsEl=document.createElement('span');tsEl.className='log-ts';tsEl.textContent=tStr;
  const msgEl=document.createElement('span');msgEl.className='log-msg';msgEl.textContent=entry.msg||'';
  row.append(tsEl,msgEl);el.appendChild(row);el.scrollTop=el.scrollHeight;
}

// ── POLL ───────────────────────────────────────────────────────────
function _startPoll(tab){
  if(tab.pollTimer) clearInterval(tab.pollTimer);
  tab.pollTimer = setInterval(()=>_pollTab(tab), 600);
}

async function _pollTab(tab){
  try{
    const r=await fetch('/api/scan/status');const d=await r.json();
    tab.statusData = d;
    _updateScanUI(tab.id, d);
    if(d.state==='done'||d.state==='stopped'||d.state==='error'||d.state==='skipped'){
      clearInterval(tab.pollTimer); tab.pollTimer=null;
      if(tab.sse) tab.sse.close();
      _onTabFinished(tab, d);
    }
  }catch(_){}
}

function _updateScanUI(tid, d){
  const stopBtn=document.getElementById(`scan-stop-${tid}`);
  if(stopBtn) stopBtn.disabled = d.state !== 'running';
  const pct=d.total_files>0?Math.round(d.file_index/d.total_files*100)
           :(d.total>0?Math.round(d.progress/d.total*100):0);
  const pb=document.getElementById(`prog-bar-${tid}`); if(pb) pb.style.width=pct+'%';
  const eta=document.getElementById(`scan-eta-${tid}`);
  if(eta) eta.textContent=d.total_files>0?`${d.file_index} / ${d.total_files} files`:`${d.progress} / ${d.total} repos`;
  // Progress shown in log (see below)
  // Always compute a meaningful status text
  let statusText;
  if(d.current_file){
    const fname=d.current_file.split('/').pop();
    const cnt=d.total_files>0?`${d.file_index}/${d.total_files}`:'';
    statusText=`${pct}% | ${fname}${cnt?' ('+cnt+')':''}`;
  } else if(d.total_files>0){
    statusText=`Scanning... ${d.file_index}/${d.total_files} files (${pct}%)`;
  } else if(d.current_repo){
    statusText=`Scanning: ${d.current_repo}`;
  } else if(d.state==='running'){
    statusText='Scanning...';
  } else {
    statusText=d.state||'...';
  }
  const title=document.getElementById(`scan-title-${tid}`);
  if(title && d.state==='running') title.textContent=statusText;
  const s=d.sev||{};
  const total=(s.critical||0)+(s.high||0)+(s.medium||0)+(s.low||0);
  const _s=(id,v)=>{const e=document.getElementById(`${id}-${tid}`);if(e)e.textContent=v};
  _s('k-crit',s.critical!=null?s.critical:'-');
  _s('k-high',s.high!=null?s.high:'-');
  _s('k-med', s.medium!=null?s.medium:'-');
  _s('k-low', s.low!=null?s.low:'-');
  const fpt=document.getElementById(`fp-total-${tid}`);
  if(fpt){
    const repoCount=Object.keys(d.per_repo||{}).length;
    const sup=d.suppressed_count||0;
    const reviewed=d.reviewed_count||0;
    const accepted=d.accepted_risk_count||0;
    const delta=d.delta||{};
    const deltaText=delta.has_baseline?` | Delta +${delta.new_count||0} / -${delta.fixed_count||0}`:'';
    if(total){
      fpt.textContent=`${total} active finding${total===1?'':'s'} across ${repoCount} repo${repoCount===1?'':'s'}${reviewed?` | ${reviewed} reviewed`:''}${accepted?` | ${accepted} accepted risk`:''}${sup?` | ${sup} suppressed`:''}${deltaText}`;
    }else{
      fpt.textContent=sup?`${sup} suppressed finding${sup===1?'':'s'}${deltaText}`:`Scanning...${deltaText}`;
    }
  }
  _buildRepoCards(tid, d);
  _buildFindingLists(tid, d);
}

function _buildRepoCards(tid, d){
  const el=document.getElementById(`repo-cards-${tid}`); if(!el) return;
  el.innerHTML='';
  Object.entries(d.per_repo||{}).forEach(([slug,info])=>{
    const sv=info.sev||{};const total=info.count||0;
    const skipped=info.skipped;const clean=!skipped&&total===0;
    const card=document.createElement('div');card.className='repo-card';
    const head=document.createElement('div');head.className='repo-card-head';
    const icon=document.createElement('span');icon.className='rc-icon';
    icon.textContent=skipped?'SKIP':clean?'OK':'REP';
    const name=document.createElement('span');
    name.className='rc-name'+(skipped?' skip':clean?' clean':'');name.textContent=slug;
    const cnt=document.createElement('span');cnt.className='rc-count';
    cnt.textContent=skipped?'skipped':clean?'clean':`${total} finding${total===1?'':'s'}`;
    head.append(icon,name,cnt);card.appendChild(head);
    if(!skipped&&total>0){
      const bar=document.createElement('div');bar.className='rc-bar';
      [[sv[1],'c'],[sv[2],'h'],[sv[3],'m'],[sv[4],'l']].forEach(([n,c])=>{
        if(n){const s=document.createElement('div');s.className=`rc-bar-${c}`;
          s.style.flex=n;bar.appendChild(s);}});
      card.appendChild(bar);
      const badges=document.createElement('div');badges.className='rc-badges';
      [[sv[1],'c','Critical'],[sv[2],'h','High'],[sv[3],'m','Medium'],[sv[4],'l','Low']]
        .forEach(([n,c,lbl])=>{if(n){const b=document.createElement('span');
          b.className=`rcb rcb-${c}`;b.textContent=`${n} ${lbl}`;badges.appendChild(b);}});
      card.appendChild(badges);
    }
    const rp=info.reports||{};

    el.appendChild(card);
  });
}

function _buildFindingLists(tid, d){
  const activeEl=document.getElementById(`finding-list-${tid}`);
  const suppressedEl=document.getElementById(`suppressed-list-${tid}`);
  const activeCount=document.getElementById(`finding-count-${tid}`);
  const suppressedCount=document.getElementById(`suppressed-count-${tid}`);
  if(!activeEl || !suppressedEl) return;
  const active=d.finding_details||[];
  const suppressed=d.suppressed_details||[];
  if(activeCount) activeCount.textContent=String(d.active_count ?? active.length);
  if(suppressedCount) suppressedCount.textContent=String(d.suppressed_count ?? suppressed.length);
  activeEl.innerHTML=active.length
    ? active.map(f=>_renderFindingCard(f,false,tid)).join('')
    : '<div class="finding-empty">No active findings.</div>';
  suppressedEl.innerHTML=suppressed.length
    ? suppressed.map(f=>_renderFindingCard(f,true,tid)).join('')
    : '<div class="finding-empty">No suppressed findings.</div>';
  const activeBtn=document.getElementById(`finding-switch-active-${tid}`);
  const suppressedBtn=document.getElementById(`finding-switch-suppressed-${tid}`);
  const activeSelected=activeBtn ? activeBtn.classList.contains('active') : true;
  const suppressedSelected=suppressedBtn ? suppressedBtn.classList.contains('active') : false;
  if(!active.length && suppressed.length && !suppressedSelected){
    showFindingPane(tid, 'suppressed');
  }else if(active.length && !activeSelected && !suppressedSelected){
    showFindingPane(tid, 'active');
  }
}

function _onTabFinished(tab, d){
  _setTabState(tab.id, d.state||'done');
  _finalisePhases(tab.id);
  const stopBtn=document.getElementById(`scan-stop-${tab.id}`);
  if(stopBtn) stopBtn.disabled = true;
  const dotEl=document.getElementById(`run-dot-${tab.id}`);
  if(dotEl) dotEl.classList.remove('running');
  const titleMap={done:'Scan complete',stopped:'Scan stopped',skipped:'Scan skipped'};
  const titleEl=document.getElementById(`scan-title-${tab.id}`);
  if(titleEl) titleEl.textContent=titleMap[d.state]||'Scan finished';
  const pb=document.getElementById(`prog-bar-${tab.id}`);if(pb) pb.style.width='100%';

  // Update tab label with finding count
  const sev=d.sev||{};
  const total=(sev.critical||0)+(sev.high||0)+(sev.medium||0)+(sev.low||0);
  _setTabLabel(tab.id, `${tab.label} - ${total} finding${total===1?'':'s'}`);
  // Show prominent report bar
  const rb=document.getElementById(`report-bar-${tab.id}`);
  if(rb){
    const rp=d.report||{};
    if(rp.html_name||rp.csv_name){
      rb.innerHTML='';
      if(rp.html_name){
        const b=document.createElement('button');
        b.className='rpt-btn html';
        b.textContent='Open HTML Report';
        b.onclick=()=>_createReportTab(tab.label, `/reports/${encodeURIComponent(rp.html_name)}`);
        rb.appendChild(b);
      }
      if(rp.csv_name){
        const a=document.createElement('a');
        a.className='rpt-btn csv';
        a.href=`/reports/${encodeURIComponent(rp.csv_name)}`;
        a.textContent='Open CSV Report';
        a.target='_blank';
        rb.appendChild(a);
        // Download Log button (same log file path convention)
        const logName=rp.html_name?rp.html_name.replace(/\.html$/,'.log'):'';
        const logPath=logName?`/api/history/log/${encodeURIComponent(d.scan_id||'')}` :'';
        if(logPath&&d.scan_id){
          const lb=document.createElement('a');
          lb.className='rpt-btn csv';
          lb.href=`/api/history/log/${encodeURIComponent(d.scan_id)}`;
          lb.textContent='Download Log';
          lb.download=(d.scan_id||'scan')+'.log';
          rb.appendChild(lb);
        }
      }
      rb.classList.add('visible');
    }
  }
}



function goToSelector(){
  document.getElementById('nav-scan').classList.add('active');
  document.querySelectorAll('.nav-item:not(#nav-scan)').forEach(n=>n.classList.remove('active'));
  show('v-scan');
  _openSelectorTab();
}

// ── SETTINGS ──────────────────────────────────────────────────────
async function loadSettings(){
  try{
    const r=await fetch('/api/settings');const d=await r.json();
    document.getElementById('s-bb-url').value=d.bitbucket_url||'';
    document.getElementById('s-owner').value=_owner||'';
    document.getElementById('s-out-dir').value=d.output_dir||'';
    const llm=d.llm||{};
    document.getElementById('s-llm-url').value=llm.base_url||'http://localhost:11434';
    // Populate model dropdown
    const sel=document.getElementById('s-llm-model');sel.innerHTML='';
    try{
      const mr=await fetch('/api/ollama/models');const md=await mr.json();
      (md.models||[]).forEach(m=>{
        const o=document.createElement('option');o.value=o.textContent=m;
        if(m===llm.model) o.selected=true;sel.appendChild(o);
      });
      if(!sel.options.length){
        const o=document.createElement('option');o.value=llm.model||'';
        o.textContent=llm.model||'(no models found)';sel.appendChild(o);
      }
    }catch(_){}
  }catch(e){console.error('loadSettings:',e)}
}
async function saveSettings(){
  const url=document.getElementById('s-llm-url').value.trim();
  const model=document.getElementById('s-llm-model').value.trim();
  const msg=document.getElementById('settings-msg');
  try{
    const r=await fetch('/api/settings/save',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({llm_url:url,llm_model:model})});
    const d=await r.json();
    if(d.ok){
      msg.textContent='LLM settings saved';msg.style.color='#6ee7b7';
      document.getElementById('llm-url-inp').value=url;
      const scanSel=document.getElementById('llm-model-sel');
      for(const opt of scanSel.options) if(opt.value===model) opt.selected=true;
    }else{msg.textContent='Failed to save';msg.style.color='var(--red)'}
  }catch(e){msg.textContent=e.message;msg.style.color='var(--red)'}
  setTimeout(()=>msg.textContent='',3000);
}
async function browseOutputDir(){
  if(window.showDirectoryPicker){
    try{
      const dh = await window.showDirectoryPicker({mode:'readwrite'});
      document.getElementById('s-out-dir').value = dh.name;
    }catch(e){
      if(e.name!=='AbortError'){
        const msg=document.getElementById('outdir-msg');
        msg.textContent='Could not open picker: '+e.message;
        msg.style.color='var(--ora)';
        setTimeout(()=>msg.textContent='',4000);
      }
    }
  } else {
    document.getElementById('s-out-dir').focus();
    const msg=document.getElementById('outdir-msg');
    msg.textContent='Directory picker not supported - please type the path directly.';
    msg.style.color='var(--dim)';
    setTimeout(()=>msg.textContent='',4000);
  }
}
async function saveOutputDir(){
  if(_scanActive){
    document.getElementById('outdir-msg').textContent='Cannot change directory while scan is running';
    document.getElementById('outdir-msg').style.color='var(--ora)';
    setTimeout(()=>document.getElementById('outdir-msg').textContent='',3000);
    return;
  }
  const dir=document.getElementById('s-out-dir').value.trim();
  const msg=document.getElementById('outdir-msg');
  if(!dir){msg.textContent='Enter a directory path';msg.style.color='var(--red)';return}
  try{
    const r=await fetch('/api/settings/save',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({output_dir:dir})});
    const d=await r.json();
    if(d.ok){
      msg.textContent=`Reports will be saved to: ${d.output_dir}`;
      msg.style.color='#6ee7b7';
      document.getElementById('s-out-dir').value=d.output_dir;
    }else{msg.textContent=d.error||'Failed';msg.style.color='var(--red)'}
  }catch(e){msg.textContent=e.message;msg.style.color='var(--red)'}
  setTimeout(()=>msg.textContent='',5000);
}

// ── HISTORY ───────────────────────────────────────────────────────

function fmtDur(s){
  if(s==null||s==='') return '-';
  const m = Math.floor(s/60);
  const sec = Math.floor(s%60);
  return String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0');
}

async function loadHistory(){
  try{
    const r=await fetch('/api/history');const d=await r.json();
    _histData=d.history||[];
    _populateHistFilters();
    renderHistory();
  }catch(e){console.error('loadHistory:',e)}
}

function _populateHistFilters(){
  const projects=new Set(), repos=new Set(), models=new Set();
  _histData.forEach(r=>{
    if(r.project) projects.add(r.project);
    (r.repos||[]).forEach(s=>repos.add(s));
    if(r.llm_model) models.add(r.llm_model);
  });
  function _fill(id, vals){
    const sel=document.getElementById(id);
    const cur=sel.value;
    sel.innerHTML=`<option value="">${sel.options[0]?.text||'All'}</option>`;
    [...vals].sort().forEach(v=>{
      const o=document.createElement('option');
      o.value=v;o.textContent=v;
      if(v===cur) o.selected=true;
      sel.appendChild(o);
    });
  }
  _fill('hist-filter-project', projects);
  _fill('hist-filter-repo',    repos);
  _fill('hist-filter-llm',     models);
}

function _histDelta(rec){
  return rec.delta || {};
}

function _histNeedsAttention(rec){
  const active=rec.active_total ?? rec.total ?? 0;
  const reviewed=rec.reviewed_total ?? 0;
  const accepted=rec.accepted_risk_total ?? 0;
  return Math.max(0, active - reviewed - accepted);
}

function _histTriageHtml(rec){
  const reviewed=rec.reviewed_total ?? 0;
  const accepted=rec.accepted_risk_total ?? 0;
  const suppressed=rec.suppressed_total ?? 0;
  return `R ${reviewed} | A ${accepted} | FP ${suppressed}`;
}

function _histDeltaHtml(rec){
  const delta=_histDelta(rec);
  if(!delta.has_baseline) return 'First scan';
  return `+${delta.new_count||0} / -${delta.fixed_count||0}`;
}

function histSort(col){
  if(_histSortCol===col){
    _histSortDir=_histSortDir==='asc'?'desc':'asc';
  }else{
    _histSortCol=col;_histSortDir='desc';
  }
  _histPage=0;
  renderHistory();
}

function renderHistory(){
  const search    = document.getElementById('hist-search').value.toLowerCase();
  const stateF    = document.getElementById('hist-state').value;
  const projF     = document.getElementById('hist-filter-project').value;
  const repoF     = document.getElementById('hist-filter-repo').value;
  const llmF      = document.getElementById('hist-filter-llm').value;
  const triageF   = document.getElementById('hist-filter-triage').value;
  const deltaF    = document.getElementById('hist-filter-delta').value;
  const sortCol   = _histSortCol;
  const sortDir   = _histSortDir;

  // Only keep records with a valid scan_id (YYYYMMDD_HHMMSS format)
  const _validId = /^\d{8}_\d{6}/;
  let rows = _histData.filter(r => _validId.test(r.scan_id || ''));

  // Filters
  if(search) rows=rows.filter(r=>
    (r.project||'').toLowerCase().includes(search)||
    (r.scan_id||'').toLowerCase().includes(search)||
    (r.repos||[]).some(s=>s.toLowerCase().includes(search))
  );
  if(stateF) rows=rows.filter(r=>r.state===stateF);
  if(projF)  rows=rows.filter(r=>r.project===projF);
  if(repoF)  rows=rows.filter(r=>(r.repos||[]).includes(repoF));
  if(llmF)   rows=rows.filter(r=>r.llm_model===llmF);
  if(triageF){
    rows=rows.filter(r=>{
      if(triageF==='needs_attention') return _histNeedsAttention(r) > 0;
      if(triageF==='reviewed') return (r.reviewed_total ?? 0) > 0;
      if(triageF==='accepted_risk') return (r.accepted_risk_total ?? 0) > 0;
      if(triageF==='false_positive') return (r.suppressed_total ?? 0) > 0;
      return true;
    });
  }
  if(deltaF){
    rows=rows.filter(r=>{
      const delta=_histDelta(r);
      if(deltaF==='new') return (delta.new_count ?? 0) > 0;
      if(deltaF==='resolved') return (delta.fixed_count ?? 0) > 0;
      if(deltaF==='baseline') return !!delta.has_baseline;
      if(deltaF==='first_scan') return !delta.has_baseline;
      return true;
    });
  }

  // Sort
  rows.sort((a,b)=>{
    function _sortKey(rec,col){
      if(col==='date')      return rec.scan_id||'';
      if(col==='duration')  return rec.duration_s||0;
      if(col==='critical')  return (rec.sev||{}).critical||0;
      if(col==='high')      return (rec.sev||{}).high||0;
      if(col==='total')     return rec.total||0;
      if(col==='attention') return _histNeedsAttention(rec);
      if(col==='project')   return (rec.project||'').toLowerCase();
      if(col==='repos')     return ((rec.repos||[])[0]||'').toLowerCase();
      if(col==='llm_model') return (rec.llm_model||'').toLowerCase();
      return rec[col]||0;
    }
    let av=_sortKey(a,sortCol),bv=_sortKey(b,sortCol);
    if(typeof av==='string'){av=av.toLowerCase();bv=bv.toLowerCase();}
    return sortDir==='asc'?(av>bv?1:av<bv?-1:0):(av<bv?1:av>bv?-1:0);
  });

  // Update sort indicators on headers
  document.querySelectorAll('table.hist th[id]').forEach(th=>{
    th.classList.remove('sort-asc','sort-desc');
    const col=th.id.replace('hth-','');
    if(col===sortCol) th.classList.add(sortDir==='asc'?'sort-asc':'sort-desc');
  });

  const tbody=document.getElementById('hist-body');
  const empty=document.getElementById('hist-empty');
  tbody.innerHTML='';
  // Reset select-all and hide delete button when re-rendering
  const selAll=document.getElementById('hist-sel-all');
  if(selAll) selAll.checked=false;
  const delBtn=document.getElementById('hist-del-btn');
  if(delBtn) delBtn.style.display='none';

  if(!rows.length){
    empty.style.display='';
    document.getElementById('hist-pg-controls').innerHTML='';
    document.getElementById('hist-pg-info').textContent='';
    return;
  }
  empty.style.display='none';

  // ── Pagination ──────────────────────────────────────────────────
  const total  = rows.length;
  const pages  = Math.ceil(total / HIST_PAGE_SIZE);
  _histPage    = Math.max(0, Math.min(_histPage, pages - 1));
  const start  = _histPage * HIST_PAGE_SIZE;
  const end    = Math.min(start + HIST_PAGE_SIZE, total);
  const paged  = rows.slice(start, end);

  // Page info
  document.getElementById('hist-pg-info').textContent =
    `Showing ${start+1}–${end} of ${total} scan${total!==1?'s':''}`;

  // Pagination buttons
  const pgCtrl = document.getElementById('hist-pg-controls');
  pgCtrl.innerHTML = '';
  function _pgBtn(label, page, disabled){
    const b = document.createElement('button');
    b.className = 'btn-xs';
    b.textContent = label;
    b.disabled = disabled;
    b.style.minWidth = '30px';
    b.onclick = () => { _histPage = page; renderHistory(); };
    pgCtrl.appendChild(b);
  }
  _pgBtn('«', 0,          _histPage === 0);
  _pgBtn('‹', _histPage-1, _histPage === 0);
  // Page number buttons — show up to 5 around current
  const startP = Math.max(0, _histPage-2);
  const endP   = Math.min(pages-1, _histPage+2);
  for(let p=startP; p<=endP; p++){
    const b = document.createElement('button');
    b.className = 'btn-xs';
    b.textContent = p+1;
    b.style.minWidth = '30px';
    if(p===_histPage) b.style.cssText += ';background:var(--pur);color:#fff;border-color:var(--pur)';
    b.onclick = (()=>{ const _p=p; return ()=>{ _histPage=_p; renderHistory(); }; })();
    pgCtrl.appendChild(b);
  }
  _pgBtn('›', _histPage+1, _histPage >= pages-1);
  _pgBtn('»', pages-1,     _histPage >= pages-1);

  paged.forEach(rec=>{
    const tr=document.createElement('tr');
    const dt=rec.scan_id||'';
    const dateStr=dt.length>=8?`${dt.slice(0,4)}-${dt.slice(4,6)}-${dt.slice(6,8)}`:'-';
    const timeStr=dt.length>=15?`${dt.slice(9,11)}:${dt.slice(11,13)}:${dt.slice(13,15)}`:'';
    const repos=(rec.repos||[]).join(', ')||'-';
    const sv=rec.sev||{};
    const critHtml=sv.critical
      ?`<span class="sp sp-c" style="font-size:13px;padding:3px 10px">${sv.critical}</span>`
      :'<span style="color:var(--dim)">-</span>';
    const highHtml=sv.high
      ?`<span class="sp sp-h" style="font-size:13px;padding:3px 10px">${sv.high}</span>`
      :'<span style="color:var(--dim)">-</span>';
    const ctx=rec.ctx||{};
    const ctxHtml=Object.entries(ctx).map(([k,v])=>
      `<span class="cp">${k}: ${v}</span>`
    ).join('')||'<span style="color:var(--dim)">-</span>';
    const llmHtml=rec.llm_model
      ?`<span style="font-family:var(--mono);font-size:11px;color:var(--text2)">${_esc(rec.llm_model)}</span>`
      :'<span style="color:var(--dim)">-</span>';
    const stateCls=rec.state==='done'?'state-done'
      :rec.state==='stopped'?'state-stopped'
      :rec.state==='skipped'?'state-skipped':'';
    const stateIcon=rec.state==='done'?'OK':rec.state==='stopped'?'STOP':rec.state==='skipped'?'SKIP':'RUN';
    const stateLabel=rec.state==='done'?'Done'
      :rec.state==='stopped'?'Stopped'
      :rec.state==='skipped'?'Skipped':(rec.state||'-');

    const rp=(rec.reports||{})['__all__']||{};

    // Build row entirely via createElement to preserve checkbox event listeners
    function _td(html, style){
      const td=document.createElement('td');
      if(style) td.style.cssText=style;
      td.innerHTML=html;
      return td;
    }

    // Checkbox cell
    const chkTd=document.createElement('td');
    chkTd.style.cssText='text-align:center;width:32px';
    const chk=document.createElement('input');
    chk.type='checkbox';
    chk.dataset.scanId=rec.scan_id;
    chk.addEventListener('change', _histSelectionChanged);
    chkTd.appendChild(chk);
    tr.appendChild(chkTd);

    // Date/Time
    tr.appendChild(_td(
      `<div style="font-weight:600;color:var(--text)">${dateStr}</div>`+
      `<div style="font-family:var(--mono);font-size:11px;color:var(--dim)">${timeStr}</div>`));
    tr.appendChild(_td(_esc(rec.project||'-'),'font-weight:600;color:var(--text)'));
    tr.appendChild(_td(_esc(repos),`max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap`));
    tr.appendChild(_td(rec.total??'-','font-size:15px;color:var(--text);text-align:right'));
    tr.appendChild(_td(String(_histNeedsAttention(rec)),'font-size:15px;color:#8b4513;text-align:right;font-weight:700'));
    tr.appendChild(_td(_esc(_histTriageHtml(rec)),'font-size:12px;color:var(--text2);white-space:nowrap'));
    tr.appendChild(_td(_esc(_histDeltaHtml(rec)),'font-size:12px;color:var(--text2);white-space:nowrap'));
    tr.appendChild(_td(rec.suppressed_total??'0','font-size:15px;color:var(--text2);text-align:right'));
    tr.appendChild(_td(critHtml,'text-align:center'));
    tr.appendChild(_td(highHtml,'text-align:center'));
    tr.appendChild(_td(`<div class="ctx-pills">${ctxHtml}</div>`));
    tr.appendChild(_td(llmHtml,'max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'));
    tr.appendChild(_td(rec.duration_s!=null?fmtDur(rec.duration_s):'-','text-align:right;font-family:var(--mono);font-size:12px'));
    tr.appendChild(_td(`<span class="${stateCls}">${stateIcon} ${stateLabel}</span>`));

    // HTML report button
    const htmlTd=document.createElement('td');
    htmlTd.style.textAlign='center';
    if(rp.html_name){
      const btn=document.createElement('button');
      btn.className='log-btn';
      btn.title='Open HTML Report';
      btn.textContent='HTML';
      const _url=`/reports/${encodeURIComponent(rp.html_name)}`;
      const _lbl=rec.project||'Report';
      btn.addEventListener('click',function(){ _createReportTab(_lbl,_url); });
      htmlTd.appendChild(btn);
    } else {
      htmlTd.innerHTML='<span style="color:var(--dim)">-</span>';
    }
    tr.appendChild(htmlTd);

    // CSV
    const csvTd=document.createElement('td');
    csvTd.style.textAlign='center';
    if(rp.csv_name){
      const a=document.createElement('a');
      a.className='log-btn';
      a.href=`/reports/${encodeURIComponent(rp.csv_name)}`;
      a.download=rp.csv_name;
      a.title='Download CSV';
      a.textContent='CSV';
      csvTd.appendChild(a);
    } else {
      csvTd.innerHTML='<span style="color:var(--dim)">-</span>';
    }
    tr.appendChild(csvTd);

    // Log
    const logTd=document.createElement('td');
    logTd.style.textAlign='center';
    if(rec.log_file){
      const lb=document.createElement('button');
      lb.className='log-btn';
      lb.title='View Log';
      lb.textContent='LOG';
      lb.addEventListener('click',function(){
        _openLogTab(rec.scan_id, rec.project||rec.scan_id);
      });
      logTd.appendChild(lb);
    } else {
      logTd.innerHTML='<span style="color:var(--dim)">-</span>';
    }
    tr.appendChild(logTd);

    tbody.appendChild(tr);
  });
}

function _histSelectionChanged(){
  const anyChecked = !!document.querySelector('#hist-body input[type=checkbox]:checked');
  const delBtn = document.getElementById('hist-del-btn');
  if(delBtn) delBtn.style.display = anyChecked ? '' : 'none';
  // Update select-all indeterminate state
  const all  = document.querySelectorAll('#hist-body input[type=checkbox]');
  const chkd = document.querySelectorAll('#hist-body input[type=checkbox]:checked');
  const selAll = document.getElementById('hist-sel-all');
  if(selAll){
    selAll.checked = chkd.length > 0 && chkd.length === all.length;
    selAll.indeterminate = chkd.length > 0 && chkd.length < all.length;
  }
}

function histToggleAll(checked){
  document.querySelectorAll('#hist-body input[type=checkbox]')
    .forEach(c => { c.checked = checked; });
  _histSelectionChanged();
}

async function deleteSelectedHistory(){
  const checked = [...document.querySelectorAll('#hist-body input[type=checkbox]:checked')];
  if(!checked.length) return;
  const scan_ids = checked.map(c => c.dataset.scanId);
  const n = scan_ids.length;
  if(!confirm(`Delete ${n} scan record${n>1?'s':''} and their HTML, CSV, and log files? This cannot be undone.`)) return;
  try{
    const r = await fetch('/api/history/delete', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({scan_ids})
    });
    const d = await r.json();
    if(!d.ok) throw new Error(d.error||'Delete failed');
    if(d.errors && d.errors.length){
      console.warn('Delete warnings:', d.errors);
    }
    await loadHistory();
  }catch(e){
    alert(`Delete failed: ${e.message}`);
  }
}
function _esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body>
</html>"""


# ── Add GET /api/repos to handler ─────────────────────────────────────────────
# Patch _Handler to handle /api/repos

_orig_get = _Handler.do_GET
def _patched_get(self):
    p = self.path.split("?")[0]
    if p == "/api/projects":
        self._json({
            "projects": _projects_cache,
            "owner": _connected_user,
        })
    elif p == "/api/repos":
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        key = qs.get("project", [""])[0]
        if not key or not _client:
            return self._json({"repos": []})
        try:
            repos = _repos_cache.get(key)
            if repos is None:
                repos = _client.list_repos(key)
                _repos_cache[key] = repos
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


