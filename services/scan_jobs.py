from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from aggregator.aggregator import Aggregator
from analyzer.security import SecurityAnalyzer
from reports.csv_report import CSVReporter
from reports.delta import build_delta_meta
from reports.html_report import HTMLReporter
from scanner.detector import AIUsageDetector
from scanner.suppressions import (
    TRIAGE_ACCEPTED_RISK,
    TRIAGE_FALSE_POSITIVE,
    TRIAGE_REVIEWED,
    apply_suppressions,
    list_triage,
)


class ScanSession:
    """Holds mutable state for a single scan job."""

    def __init__(self):
        self.scan_id: str = ""
        self.project_key: str = ""
        self.repo_slugs: List[str] = []
        self.llm_url: str = "http://localhost:11434"
        self.llm_model: str = "qwen2.5-coder:7b-instruct"
        self.operator: str = "Unknown"
        self.started_at_utc: str = ""
        self.completed_at_utc: str = ""
        self.policy_version: str = ""
        self.tool_version: str = ""
        self.repo_details: Dict[str, dict] = {}

        self.state: str = "idle"
        self.progress: int = 0
        self.total: int = 0
        self.current_repo: str = ""
        self.current_file: str = ""
        self.file_index: int = 0
        self.total_files: int = 0

        self.log_queue: queue.Queue = queue.Queue()
        self.log_lines: List[dict] = []
        self.stop_event: threading.Event = threading.Event()
        self.proc_holder: list = []
        self.proc_lock: threading.Lock = threading.Lock()
        self._active_pool = None

        self.findings: List[dict] = []
        self.suppressed_findings: List[dict] = []
        self.per_repo: Dict[str, Any] = {}
        self.report_paths: Dict[str, dict] = {}
        self.scan_duration_s: int = 0
        self.llm_model_info: dict = {}
        self.delta: dict = {}

    @staticmethod
    def _finding_detail(finding: dict) -> dict:
        return {
            "hash": finding.get("_hash", ""),
            "repo": finding.get("repo", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line", ""),
            "severity": finding.get("severity", 4),
            "severity_label": finding.get("severity_label", ""),
            "policy_status": finding.get("policy_status", ""),
            "provider_or_lib": finding.get("provider_or_lib", ""),
            "capability": finding.get("capability", ""),
            "description": finding.get("description", ""),
            "triage_status": finding.get("triage_status", ""),
            "triage_note": finding.get("triage_note", ""),
            "triage_by": finding.get("triage_by", ""),
            "triage_at": finding.get("triage_at", ""),
            "reason": finding.get("triage_note", finding.get("suppressed_reason", "")),
            "marked_by": finding.get("triage_by", finding.get("suppressed_by", "")),
            "marked_at": finding.get("triage_at", finding.get("suppressed_at", "")),
            "delta_status": finding.get("delta_status", ""),
        }

    def log(self, msg: str, level: str = "info") -> None:
        entry = {"msg": msg, "level": level, "ts": time.time()}
        self.log_lines.append(entry)
        self.log_queue.put(entry)

    def to_status(self) -> dict:
        sev = Counter(f.get("severity", 4) for f in self.findings)
        triage_counts = Counter(f.get("triage_status", "") or "new" for f in self.findings)
        return {
            "state": self.state,
            "scan_id": self.scan_id,
            "project_key": self.project_key,
            "operator": self.operator,
            "started_at_utc": self.started_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "policy_version": self.policy_version,
            "tool_version": self.tool_version,
            "progress": self.progress,
            "total": self.total,
            "current_repo": self.current_repo,
            "current_file": self.current_file,
            "file_index": self.file_index,
            "total_files": self.total_files,
            "findings": len(self.findings),
            "active_count": len(self.findings),
            "suppressed_count": len(self.suppressed_findings),
            "reviewed_count": triage_counts.get(TRIAGE_REVIEWED, 0),
            "accepted_risk_count": triage_counts.get(TRIAGE_ACCEPTED_RISK, 0),
            "sev": {
                "critical": sev.get(1, 0),
                "high": sev.get(2, 0),
                "medium": sev.get(3, 0),
                "low": sev.get(4, 0),
            },
            "delta": self.delta,
            "per_repo": {
                slug: {
                    "skipped": data is None,
                    "count": len(data) if data else 0,
                    "sev": dict(Counter(f.get("severity", 4) for f in (data or []))),
                    "reports": {},
                }
                for slug, data in self.per_repo.items()
            },
            "report": self.report_paths.get("__all__", {}),
            "duration_s": self.scan_duration_s,
            "finding_details": [
                self._finding_detail(f)
                for f in sorted(
                    self.findings,
                    key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", "")),
                )[:60]
            ],
            "suppressed_details": [
                self._finding_detail(f)
                for f in sorted(
                    self.suppressed_findings,
                    key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", "")),
                )[:30]
            ],
        }


@dataclass
class ScanJobPaths:
    output_dir: str
    temp_dir: str
    policy_file: str
    owner_map_file: str
    suppressions_file: str
    history_file: str
    log_dir: str
    db_file: str


class ScanJobService:
    def __init__(
        self,
        *,
        app_version: str,
        paths: ScanJobPaths,
        load_policy: Callable[[str], dict],
        load_owner_map: Callable[[str], dict],
        policy_version: Callable[[str], str],
        utc_now_iso: Callable[[], str],
        git_head_commit: Callable[[Path], str],
        ollama_ping: Callable[[str], bool],
    ):
        self.app_version = app_version
        self.paths = paths
        self._load_policy = load_policy
        self._load_owner_map = load_owner_map
        self._policy_version = policy_version
        self._utc_now_iso = utc_now_iso
        self._git_head_commit = git_head_commit
        self._ollama_ping = ollama_ping
        self._ensure_db()

    def update_paths(
        self,
        *,
        output_dir: Optional[str] = None,
        temp_dir: Optional[str] = None,
        policy_file: Optional[str] = None,
        owner_map_file: Optional[str] = None,
        suppressions_file: Optional[str] = None,
        history_file: Optional[str] = None,
        log_dir: Optional[str] = None,
        db_file: Optional[str] = None,
    ) -> None:
        if output_dir is not None:
            self.paths.output_dir = output_dir
        if temp_dir is not None:
            self.paths.temp_dir = temp_dir
        if policy_file is not None:
            self.paths.policy_file = policy_file
        if owner_map_file is not None:
            self.paths.owner_map_file = owner_map_file
        if suppressions_file is not None:
            self.paths.suppressions_file = suppressions_file
        if history_file is not None:
            self.paths.history_file = history_file
        if log_dir is not None:
            self.paths.log_dir = log_dir
        if db_file is not None:
            self.paths.db_file = db_file
        self._ensure_db()

    def _connect(self) -> sqlite3.Connection:
        db_path = Path(self.paths.db_file)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    scan_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    record_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_logs (
                    scan_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    ts REAL NOT NULL,
                    level TEXT NOT NULL,
                    msg TEXT NOT NULL,
                    PRIMARY KEY (scan_id, seq)
                )
                """
            )
            conn.commit()

    def invalidate_history_cache(self) -> None:
        # DB-backed reads are already fresh; wrapper kept for compatibility.
        return None

    def _build_record(
        self,
        session: ScanSession,
        findings: list,
        *,
        log_file: str = "",
    ) -> dict:
        sev = Counter(f.get("severity", 4) for f in findings)
        ctx = Counter(f.get("context", "production") for f in findings)
        llm_name = (session.llm_model_info or {}).get("name", session.llm_model)
        return {
            "scan_id": session.scan_id,
            "date": session.scan_id[:8],
            "time": session.scan_id[9:] if len(session.scan_id) > 8 else "",
            "project": session.project_key,
            "repos": session.repo_slugs,
            "operator": session.operator,
            "state": session.state,
            "duration_s": session.scan_duration_s,
            "started_at_utc": session.started_at_utc,
            "completed_at_utc": session.completed_at_utc,
            "policy_version": session.policy_version,
            "tool_version": session.tool_version,
            "total": len(findings),
            "active_total": len(findings),
            "suppressed_total": len(session.suppressed_findings),
            "reviewed_total": sum(1 for f in findings if f.get("triage_status") == TRIAGE_REVIEWED),
            "accepted_risk_total": sum(1 for f in findings if f.get("triage_status") == TRIAGE_ACCEPTED_RISK),
            "delta": session.delta,
            "sev": {
                "critical": sev.get(1, 0),
                "high": sev.get(2, 0),
                "medium": sev.get(3, 0),
                "low": sev.get(4, 0),
            },
            "ctx": dict(ctx),
            "llm_model": llm_name,
            "repo_details": session.repo_details,
            "log_file": log_file,
            "reports": session.report_paths,
        }

    def _build_scan_delta(
        self,
        findings: list,
        *,
        project_key: str,
        repo_slugs: list[str],
    ) -> dict:
        def _serialise_delta(delta: dict) -> dict:
            return {
                **delta,
                "new_hashes": sorted(delta.get("new_hashes", set())),
                "fixed_hashes": sorted(delta.get("fixed_hashes", set())),
            }

        if not repo_slugs:
            return _serialise_delta({
                "has_baseline": False,
                "new_count": len(findings),
                "fixed_count": 0,
                "unchanged_count": 0,
                "new_hashes": {f.get("_hash", "") for f in findings},
                "fixed_hashes": set(),
            })

        if len(repo_slugs) == 1:
            return _serialise_delta(
                build_delta_meta(findings, self.paths.output_dir, project_key, repo_slugs[0])
            )

        new_hashes = set()
        fixed_hashes = set()
        new_count = 0
        fixed_count = 0
        unchanged_count = 0
        has_baseline = False

        for slug in repo_slugs:
            repo_findings = [f for f in findings if f.get("repo") == slug]
            repo_delta = build_delta_meta(repo_findings, self.paths.output_dir, project_key, slug)
            if repo_delta.get("has_baseline"):
                has_baseline = True
            new_count += repo_delta.get("new_count", 0)
            fixed_count += repo_delta.get("fixed_count", 0)
            unchanged_count += repo_delta.get("unchanged_count", 0)
            new_hashes.update(repo_delta.get("new_hashes", set()))
            fixed_hashes.update(repo_delta.get("fixed_hashes", set()))

        return _serialise_delta({
            "has_baseline": has_baseline,
            "baseline_file": "multiple baselines",
            "new_count": new_count,
            "fixed_count": fixed_count,
            "unchanged_count": unchanged_count,
            "new_hashes": new_hashes,
            "fixed_hashes": fixed_hashes,
        })

    def _upsert_job_record(self, record: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs(scan_id, state, updated_at, record_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    state=excluded.state,
                    updated_at=excluded.updated_at,
                    record_json=excluded.record_json
                """,
                (
                    record["scan_id"],
                    record.get("state", "unknown"),
                    time.time(),
                    json.dumps(record, ensure_ascii=False),
                ),
            )
            conn.commit()

    def _replace_scan_logs(self, scan_id: str, log_lines: list[dict]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_logs WHERE scan_id = ?", (scan_id,))
            if log_lines:
                conn.executemany(
                    """
                    INSERT INTO scan_logs(scan_id, seq, ts, level, msg)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            scan_id,
                            idx,
                            float(entry.get("ts", 0.0)),
                            str(entry.get("level", "info")),
                            str(entry.get("msg", "")),
                        )
                        for idx, entry in enumerate(log_lines)
                    ],
                )
            conn.commit()

    def _read_legacy_history(self) -> list:
        try:
            path = Path(self.paths.history_file)
            if not path.exists():
                return []
            return json.loads(path.read_text("utf-8"))
        except Exception:
            return []

    def _write_legacy_history(self, record: dict) -> None:
        history = [r for r in self._read_legacy_history() if r.get("scan_id") != record["scan_id"]]
        history.append(record)
        history = history[-500:]
        tmp_path = self.paths.history_file + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(history, fh, indent=2)
        os.replace(tmp_path, self.paths.history_file)

    def record_job_snapshot(self, session: ScanSession, findings: Optional[list] = None) -> None:
        snapshot = self._build_record(session, findings if findings is not None else session.findings)
        self._upsert_job_record(snapshot)

    @staticmethod
    def _history_sort_key(record: dict) -> tuple[str, str]:
        return (
            str(record.get("completed_at_utc") or record.get("started_at_utc") or ""),
            str(record.get("scan_id") or ""),
        )

    def load_history(self) -> list:
        records_by_scan_id: dict[str, dict] = {
            str(record.get("scan_id")): record
            for record in self._read_legacy_history()
            if record.get("scan_id")
        }
        try:
            self._ensure_db()
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT record_json FROM scan_jobs ORDER BY updated_at ASC, scan_id ASC"
                ).fetchall()
            for row in rows:
                record = json.loads(row["record_json"])
                scan_id = str(record.get("scan_id") or "")
                if scan_id:
                    records_by_scan_id[scan_id] = record
        except Exception:
            pass
        return sorted(records_by_scan_id.values(), key=self._history_sort_key)

    def get_log_text(self, scan_id: str) -> str:
        try:
            self._ensure_db()
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT ts, msg FROM scan_logs WHERE scan_id = ? ORDER BY seq ASC",
                    (scan_id,),
                ).fetchall()
            if rows:
                lines = []
                for row in rows:
                    ts = datetime.fromtimestamp(row["ts"]).strftime("%H:%M:%S")
                    lines.append(f"[{ts}] {row['msg']}")
                return "\n".join(lines) + "\n"
        except Exception:
            pass
        path = Path(self.paths.log_dir) / f"{scan_id}.log"
        if path.exists():
            return path.read_text("utf-8")
        return ""

    def delete_history(self, scan_ids: list[str]) -> None:
        if not scan_ids:
            return
        try:
            with self._connect() as conn:
                conn.executemany(
                    "DELETE FROM scan_logs WHERE scan_id = ?",
                    [(scan_id,) for scan_id in scan_ids],
                )
                conn.executemany(
                    "DELETE FROM scan_jobs WHERE scan_id = ?",
                    [(scan_id,) for scan_id in scan_ids],
                )
                conn.commit()
        except Exception:
            pass
        history = [r for r in self._read_legacy_history() if r.get("scan_id") not in set(scan_ids)]
        tmp_path = self.paths.history_file + ".tmp"
        Path(self.paths.history_file).parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(history, fh, indent=2)
        os.replace(tmp_path, self.paths.history_file)

    def cleanup_stale_temp_clones(self) -> None:
        from scanner.bitbucket import cleanup_clone

        temp_root = Path(self.paths.temp_dir)
        if not temp_root.exists():
            return
        for child in temp_root.iterdir():
            try:
                if child.is_dir():
                    cleanup_clone(child)
                else:
                    child.unlink()
            except Exception:
                pass

    def save_history_record(self, session: ScanSession, findings: list) -> None:
        try:
            Path(self.paths.output_dir).mkdir(parents=True, exist_ok=True)
            Path(self.paths.log_dir).mkdir(parents=True, exist_ok=True)
            log_path = Path(self.paths.log_dir) / f"{session.scan_id}.log"
            try:
                with open(log_path, "w", encoding="utf-8") as fh:
                    for entry in session.log_lines:
                        ts = datetime.fromtimestamp(entry["ts"]).strftime("%H:%M:%S")
                        fh.write(f"[{ts}] {entry.get('msg', '')}\n")
            except Exception:
                log_path = None

            record = self._build_record(session, findings, log_file=str(log_path) if log_path else "")
            self._upsert_job_record(record)
            self._replace_scan_logs(session.scan_id, session.log_lines)
            self._write_legacy_history(record)
        except Exception as exc:
            print(f"[WARN] Could not save history: {exc}")

    def run_scan(
        self,
        session: ScanSession,
        *,
        client,
        save_history_record: Optional[Callable[[ScanSession, list], None]] = None,
    ) -> None:
        from scanner.history import scan_history
        from scanner.llm_reviewer import LLMReviewer

        persist_record = save_history_record or self.save_history_record
        log = session.log
        stop = session.stop_event

        policy = self._load_policy(self.paths.policy_file)
        owner_map = self._load_owner_map(self.paths.owner_map_file)
        detector = AIUsageDetector(verbose=False)
        analyzer = SecurityAnalyzer(policy=policy, verbose=False)
        aggregator = Aggregator(owner_map=owner_map, min_severity=4)

        Path(self.paths.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.paths.temp_dir).mkdir(parents=True, exist_ok=True)
        self.cleanup_stale_temp_clones()

        t_start = time.time()
        session.started_at_utc = session.started_at_utc or self._utc_now_iso()
        session.completed_at_utc = ""
        session.policy_version = self._policy_version(self.paths.policy_file)
        session.tool_version = self.app_version
        session.suppressed_findings = []
        session.delta = {}
        all_findings: List[dict] = []
        per_repo: Dict[str, Any] = {}
        per_branch: Dict[str, str] = {}
        triage_records = {
            rec.get("hash", ""): rec
            for rec in list_triage(self.paths.suppressions_file)
            if rec.get("hash")
        }
        suppressed_hashes = {
            hash_
            for hash_, rec in triage_records.items()
            if rec.get("status") == TRIAGE_FALSE_POSITIVE
        }
        self.record_job_snapshot(session, [])

        log(f"Scan ID  : {session.scan_id}", "hd")
        log(f"Project  : {session.project_key}", "dim")
        log(f"Repos    : {session.total}", "dim")

        session.llm_model_info = {}
        llm_enabled = True

        if not self._ollama_ping(session.llm_url):
            log("  [LLM] Ollama not reachable - running without LLM review", "warn")
            llm_enabled = False
        else:
            try:
                session.llm_model_info = LLMReviewer(
                    base_url=session.llm_url, model=session.llm_model
                ).model_info()
                info = session.llm_model_info
                parts = [info["name"]]
                if info.get("parameter_size"):
                    parts.append(info["parameter_size"])
                if info.get("quantization"):
                    parts.append(info["quantization"])
                log(f"LLM      : {' | '.join(parts)}", "dim")
            except Exception:
                session.llm_model_info = {"name": session.llm_model}
                log(f"LLM      : {session.llm_model}", "dim")

        log("=" * 58, "dim")

        repo_meta: Dict[str, dict] = {}
        git_env = client.build_git_auth_env() if client is not None else {}
        for slug in session.repo_slugs:
            if stop.is_set():
                break
            try:
                if client is None:
                    raise RuntimeError("Bitbucket client unavailable")
                branch = client.get_default_branch(session.project_key, slug)
                owner = client.get_repo_owner(session.project_key, slug)
                url = client.get_clone_url(session.project_key, slug)
                per_branch[slug] = branch or "default"
                repo_meta[slug] = {"branch": branch, "owner": owner, "url": url}
                log(f"  {slug}  branch:{branch or '?'}  owner:{owner}", "dim")
            except Exception as exc:
                log(f"  {slug}  metadata error: {exc}", "err")
                repo_meta[slug] = {"branch": None, "owner": "Unknown", "url": ""}

        log("=" * 58, "dim")

        try:
            from scanner.llm_reviewer import _available_vram_gb, compute_worker_count

            vram_gb = _available_vram_gb()
            param_sz = (session.llm_model_info or {}).get("parameter_size", "")
            workers = compute_worker_count(
                param_sz, vram_gb=vram_gb, repo_count=len(session.repo_slugs)
            )
        except Exception:
            workers = 4

        log(f"Starting parallel scan (workers={workers})...", "info")

        from scanner.bitbucket import cleanup_clone, shallow_clone

        def _scan_one(slug: str) -> tuple:
            if stop.is_set():
                return slug, None, "", 0, "scan stopped"
            meta = repo_meta.get(slug, {})
            branch = meta.get("branch")
            owner = meta.get("owner", "Unknown")
            clone_url = meta.get("url", "")
            clone_dir = Path(self.paths.temp_dir) / slug
            try:
                shallow_clone(
                    clone_url,
                    clone_dir,
                    branch=branch,
                    verbose=False,
                    stop_event=stop,
                    proc_holder=session.proc_holder,
                    proc_lock=session.proc_lock,
                    git_env=git_env,
                )
                meta["commit"] = self._git_head_commit(clone_dir)
            except RuntimeError as exc:
                return slug, None, owner, 0, f"clone failed: {exc}"
            except Exception as exc:
                return slug, None, owner, 0, f"clone error: {exc}"

            if stop.is_set():
                cleanup_clone(clone_dir)
                return slug, None, owner, 0, "scan stopped"

            try:
                last_pct = [-1]

                def _on_file(rel, idx, total):
                    session.current_file = f"{slug}/{rel}"
                    session.file_index = idx + 1
                    session.total_files = max(session.total_files, total)
                    pct = int((idx + 1) / max(total, 1) * 100)
                    if pct % 5 == 0 and pct != last_pct[0]:
                        last_pct[0] = pct
                        log(f"  [{slug}] Scanning: {pct}% ({idx+1}/{total} files)", "dim")

                raw, file_contents = detector.scan(
                    clone_dir,
                    repo_name=slug,
                    stop_event=stop,
                    return_file_contents=True,
                    on_file=_on_file,
                )
                try:
                    history_findings = scan_history(clone_dir, detector, slug, stop_event=stop)
                    if history_findings:
                        raw.extend(history_findings)
                except Exception as hist_err:
                    log(f"  [history] {slug}: {hist_err}", "dim")

                analyzed = analyzer.analyze(raw)
                pre_llm_count = len(analyzed)

                if llm_enabled and analyzed:
                    try:
                        reviewer = LLMReviewer(
                            base_url=session.llm_url,
                            model=session.llm_model,
                            log_fn=log,
                            stop_event=stop,
                        )
                        log(f"  [LLM] Reviewing {len(analyzed)} finding(s)...", "dim")
                        analyzed = reviewer.review(analyzed, file_contents)
                        log(f"  [LLM] Review done -> {len(analyzed)} finding(s)", "dim")
                    except Exception as exc:
                        log(f"  [LLM] Review skipped: {exc}", "dim")

                return slug, analyzed, owner, pre_llm_count, None
            except Exception as exc:
                return slug, None, owner, 0, f"scan error: {exc}"
            finally:
                cleanup_clone(clone_dir)

        total_pre_llm = 0
        total_post_llm = 0
        completed = 0

        session._active_pool = None
        with ThreadPoolExecutor(max_workers=workers) as pool:
            session._active_pool = pool
            futures = {pool.submit(_scan_one, slug): slug for slug in session.repo_slugs}
            for fut in as_completed(futures):
                if stop.is_set():
                    for future in futures:
                        future.cancel()
                    break

                slug, analyzed, bb_owner, pre_llm, skip_reason = fut.result()
                completed += 1
                session.progress = completed
                session.current_repo = slug

                if analyzed is None:
                    reason_str = f": {skip_reason}" if skip_reason else ""
                    log(f"  SKIP {slug}: skipped{reason_str}", "err")
                    per_repo[slug] = None
                    session.per_repo = dict(per_repo)
                    self.record_job_snapshot(session, session.findings)
                    continue

                sev_critical = sum(1 for f in analyzed if f.get("severity") == 1)
                sev_high = sum(1 for f in analyzed if f.get("severity") == 2)
                log(
                    f"\nOK {slug} -> {len(analyzed)} findings  (Crit:{sev_critical} High:{sev_high})",
                    "info",
                )
                if sev_critical:
                    log(f"  WARN {sev_critical} Critical finding(s)!", "err")

                total_pre_llm += pre_llm
                active_findings, suppressed_findings = apply_suppressions(
                    analyzed, suppressed_hashes
                )
                for finding in suppressed_findings:
                    meta = triage_records.get(finding.get("_hash", ""), {})
                    if meta:
                        finding["triage_status"] = meta.get("status", TRIAGE_FALSE_POSITIVE)
                        finding["triage_note"] = meta.get("note", "")
                        finding["triage_by"] = meta.get("marked_by", "")
                        finding["triage_at"] = meta.get("marked_at", "")
                        finding["suppressed_reason"] = meta.get("note", "")
                        finding["suppressed_by"] = meta.get("marked_by", "")
                        finding["suppressed_at"] = meta.get("marked_at", "")
                for finding in active_findings:
                    meta = triage_records.get(finding.get("_hash", ""), {})
                    if meta and meta.get("status") != TRIAGE_FALSE_POSITIVE:
                        finding["triage_status"] = meta.get("status", "")
                        finding["triage_note"] = meta.get("note", "")
                        finding["triage_by"] = meta.get("marked_by", "")
                        finding["triage_at"] = meta.get("marked_at", "")
                if suppressed_findings:
                    session.suppressed_findings.extend(suppressed_findings)
                    log(f"  [FP] Suppressed {len(suppressed_findings)} finding(s)", "dim")
                total_post_llm += len(active_findings)

                for finding in active_findings:
                    finding["project_key"] = session.project_key
                    finding["owner"] = bb_owner
                    finding["last_seen"] = session.scan_id
                all_findings.extend(active_findings)
                per_repo[slug] = active_findings
                session.per_repo = dict(per_repo)
                session.findings = list(all_findings)
                self.record_job_snapshot(session, session.findings)

        log("\n" + "=" * 58, "dim")
        final = aggregator.process(all_findings)
        session.findings = final
        scanned_slugs = [slug for slug in session.repo_slugs if per_repo.get(slug) is not None]
        session.delta = self._build_scan_delta(
            final,
            project_key=session.project_key,
            repo_slugs=scanned_slugs,
        )
        new_hashes = session.delta.get("new_hashes", set())
        for finding in final:
            finding["delta_status"] = "new" if finding.get("_hash", "") in new_hashes else "unchanged"
        log(f"Total findings (deduped): {len(final)}", "hd")

        session.scan_duration_s = int(time.time() - t_start)
        log("\nGenerating reports...", "dim")
        report_paths: Dict[str, dict] = {}

        for slug in session.repo_slugs:
            if per_repo.get(slug) is None:
                log(f"  {slug}: skipped (no findings recorded)", "dim")
            elif not [f for f in final if f.get("repo") == slug]:
                log(f"  {slug}: clean - no findings", "ok")

        if not final:
            log("  No findings - no report generated.", "dim")
        else:
            try:
                dt_date = datetime.now().strftime("%Y%m%d")
                dt_time = datetime.now().strftime("%H%M%S")
                report_generated_at_utc = self._utc_now_iso()
                is_multi = len(scanned_slugs) > 1
                label = "ALL" if is_multi else (scanned_slugs[0] if scanned_slugs else session.repo_slugs[0])
                safe_name = f"AI_Scan_Report_{session.project_key}_{label}_{dt_date}_{dt_time}"

                log("  Writing CSV report...", "dim")
                csv_reporter = CSVReporter(output_dir=self.paths.output_dir, scan_id=safe_name)
                csv_path = csv_reporter.write_csv(final)
                log(f"  Writing HTML report ({len(final)} finding(s))...", "dim")
                if session.llm_url and session.llm_model:
                    log(f"  [Report] Generating LLM analysis for {len(final)} finding(s)...", "dim")

                if is_multi:
                    repos_meta_list = [
                        {
                            "slug": slug,
                            "owner": repo_meta.get(slug, {}).get("owner", "Unknown"),
                            "branch": repo_meta.get(slug, {}).get("branch") or "default",
                            "commit": repo_meta.get(slug, {}).get("commit", ""),
                        }
                        for slug in session.repo_slugs
                    ]
                    report_meta = {
                        "repo": f"{len(session.repo_slugs)} repositories",
                        "project_key": session.project_key,
                        "owner": "",
                        "branch": "",
                        "operator": session.operator,
                        "started_at_utc": session.started_at_utc,
                        "completed_at_utc": report_generated_at_utc,
                        "policy_version": session.policy_version,
                        "tool_version": session.tool_version,
                        "repos_meta": repos_meta_list,
                        "scan_id": session.scan_id,
                        "delta": session.delta,
                        "llm_model_info": session.llm_model_info,
                        "scan_duration_s": session.scan_duration_s,
                        "pre_llm_count": total_pre_llm,
                        "post_llm_count": total_post_llm,
                        "suppressed_count": len(session.suppressed_findings),
                        "reviewed_count": sum(1 for f in final if f.get("triage_status") == TRIAGE_REVIEWED),
                        "accepted_risk_count": sum(1 for f in final if f.get("triage_status") == TRIAGE_ACCEPTED_RISK),
                    }
                else:
                    single_slug = label
                    single_owner = next((finding.get("owner", "") for finding in final), "Unknown")
                    report_meta = {
                        "repo": single_slug,
                        "project_key": session.project_key,
                        "owner": single_owner,
                        "branch": per_branch.get(single_slug, ""),
                        "commit": repo_meta.get(single_slug, {}).get("commit", ""),
                        "operator": session.operator,
                        "started_at_utc": session.started_at_utc,
                        "completed_at_utc": report_generated_at_utc,
                        "policy_version": session.policy_version,
                        "tool_version": session.tool_version,
                        "scan_id": session.scan_id,
                        "delta": session.delta,
                        "llm_model_info": session.llm_model_info,
                        "scan_duration_s": session.scan_duration_s,
                        "pre_llm_count": total_pre_llm,
                        "post_llm_count": total_post_llm,
                        "suppressed_count": len(session.suppressed_findings),
                        "reviewed_count": sum(1 for f in final if f.get("triage_status") == TRIAGE_REVIEWED),
                        "accepted_risk_count": sum(1 for f in final if f.get("triage_status") == TRIAGE_ACCEPTED_RISK),
                    }

                html_reporter = HTMLReporter(
                    output_dir=self.paths.output_dir,
                    scan_id=safe_name,
                    include_snippets=True,
                    meta=report_meta,
                )
                html_path = html_reporter.write(
                    final,
                    policy=policy,
                    ollama_url=session.llm_url,
                    ollama_model=session.llm_model,
                    progress_fn=lambda i, n, cap: log(
                        f"  [Report] LLM analysis {i}/{n}: {cap[:50]}...",
                        "dim",
                    ),
                )
                report_paths["__all__"] = {
                    "csv": str(Path(csv_path).resolve()),
                    "html": str(Path(html_path).resolve()),
                    "csv_name": Path(csv_path).name,
                    "html_name": Path(html_path).name,
                }
                session.report_paths = dict(report_paths)
                log(f"  OK Report: {Path(html_path).name}", "ok")
            except Exception as exc:
                log(f"  Report error: {exc}", "err")

        session.completed_at_utc = self._utc_now_iso()
        session.repo_details = {
            slug: {
                "owner": repo_meta.get(slug, {}).get("owner", "Unknown"),
                "branch": repo_meta.get(slug, {}).get("branch") or "default",
                "commit": repo_meta.get(slug, {}).get("commit", ""),
            }
            for slug in session.repo_slugs
        }

        skipped_all = all(value is None for value in per_repo.values()) and len(per_repo) > 0
        if stop.is_set():
            session.state = "stopped"
        elif skipped_all:
            session.state = "skipped"
        else:
            session.state = "done"
        self.record_job_snapshot(session, final)

        if stop.is_set():
            log("\nScan stopped.", "hd")
        elif skipped_all:
            log("\nAll repositories were skipped.", "warn")
        else:
            log("\nScan complete.", "hd")
        log(f"Duration: {session.scan_duration_s}s  |  Findings: {len(final)}", "info")

        session.completed_at_utc = self._utc_now_iso()
        persist_record(session, final)
