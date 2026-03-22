from __future__ import annotations

import json
import os
import queue
import sqlite3
import subprocess
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import urllib.error

from requests import RequestException

from aggregator.aggregator import Aggregator
from analyzer.security import SecurityAnalyzer
from reports.csv_report import CSVReporter
from reports.delta import build_delta_meta
from reports.html_report import HTMLReporter
from reports.json_report import JSONReporter
from scanner.detector import AIUsageDetector
from scanner.suppressions import (
    TRIAGE_ACCEPTED_RISK,
    TRIAGE_FALSE_POSITIVE,
    TRIAGE_REVIEWED,
    apply_suppressions,
    list_triage,
)
from services.inventory import build_inventory
from services.error_codes import make_error
from services.runtime_support import load_llm_config
from services.scan_runtime_views import llm_stats


EXPECTED_LLM_ERRORS = (
    urllib.error.HTTPError,
    urllib.error.URLError,
    JSONDecodeError,
    OSError,
    ValueError,
    TypeError,
    KeyError,
)

EXPECTED_REPORT_ERRORS = (
    urllib.error.HTTPError,
    urllib.error.URLError,
    JSONDecodeError,
    OSError,
    ValueError,
    TypeError,
    KeyError,
)

EXPECTED_METADATA_ERRORS = (
    RequestException,
    OSError,
    ValueError,
    TypeError,
    KeyError,
)


class ScanSession:
    """Holds mutable state for a single scan job."""

    def __init__(self):
        self.state_lock: threading.RLock = threading.RLock()
        self.scan_id: str = ""
        self.project_key: str = ""
        self.repo_slugs: List[str] = []
        self.scan_source: str = "bitbucket"
        self.local_repo_path: str = ""
        self.scan_scope: str = "full"
        self.compare_ref: str = ""
        self.llm_url: str = "http://localhost:11434"
        self.llm_model: str = "qwen2.5-coder:7b-instruct"
        self.operator: str = "User"
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
        self.inventory: dict = {}
        self.scoped_files_by_repo: Dict[str, List[str]] = {}
        self.pre_llm_count: int = 0
        self.post_llm_count: int = 0
        self.phase_metrics: Dict[str, int] = {}
        self.repo_metrics: Dict[str, dict] = {}
        self.llm_batch_metrics: List[dict] = []
        self.cache_metrics: Dict[str, int] = {}
        self.errors: List[dict] = []

    @staticmethod
    def _finding_detail(finding: dict) -> dict:
        delta_status = str(finding.get("delta_status", "") or "")
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
            "snippet": finding.get("snippet", ""),
            "triage_status": finding.get("triage_status", ""),
            "triage_note": finding.get("triage_note", ""),
            "triage_by": finding.get("triage_by", ""),
            "triage_at": finding.get("triage_at", ""),
            "reason": finding.get("triage_note", finding.get("suppressed_reason", "")),
            "marked_by": finding.get("triage_by", finding.get("suppressed_by", "")),
            "marked_at": finding.get("triage_at", finding.get("suppressed_at", "")),
            "delta_status": delta_status,
            "delta_label": delta_status.replace("_", " ").title() if delta_status else "",
            "detector_confidence_score": finding.get("detector_confidence_score", finding.get("confidence", 0)),
            "production_relevance_score": finding.get("production_relevance_score", 0),
            "evidence_quality_score": finding.get("evidence_quality_score", 0),
            "llm_review_confidence_score": finding.get("llm_review_confidence_score"),
            "overall_signal_score": finding.get("overall_signal_score", 0),
        }

    def log(self, msg: str, level: str = "info") -> None:
        text = "" if msg is None else str(msg)
        parts = []
        for part in text.splitlines():
            cleaned = part.rstrip("\r")
            if cleaned.strip():
                parts.append(cleaned)
        if not parts:
            return
        with self.state_lock:
            for part in parts:
                entry = {"msg": part, "level": level, "ts": time.time()}
                self.log_lines.append(entry)
                self.log_queue.put(entry)

    def add_phase_time(self, phase_name: str, seconds: float) -> None:
        phase = str(phase_name or "").strip().lower()
        if not phase:
            return
        value = max(int(round(float(seconds or 0.0))), 0)
        with self.state_lock:
            self.phase_metrics[phase] = int(self.phase_metrics.get(phase, 0) or 0) + value

    def set_phase_time(self, phase_name: str, seconds: float) -> None:
        phase = str(phase_name or "").strip().lower()
        if not phase:
            return
        value = max(int(round(float(seconds or 0.0))), 0)
        with self.state_lock:
            self.phase_metrics[phase] = value

    def record_repo_metric(self, repo_slug: str, **metrics: Any) -> None:
        slug = str(repo_slug or "").strip()
        if not slug:
            return
        with self.state_lock:
            current = dict(self.repo_metrics.get(slug) or {})
            current.update(metrics)
            self.repo_metrics[slug] = current

    def record_llm_batch(self, batch_data: dict) -> None:
        if not isinstance(batch_data, dict):
            return
        with self.state_lock:
            self.llm_batch_metrics.append(dict(batch_data))

    def record_error(self, code: str, stage: str, message: str, **details: Any) -> None:
        error = make_error(code, stage, message, **details)
        with self.state_lock:
            self.errors.append(error)

    def to_status(self) -> dict:
        with self.state_lock:
            findings = list(self.findings)
            suppressed_findings = list(self.suppressed_findings)
            per_repo = dict(self.per_repo)
            report_paths = dict(self.report_paths)
            delta = dict(self.delta)
            inventory = dict(self.inventory)
            sev = Counter(f.get("severity", 4) for f in findings)
            triage_counts = Counter(f.get("triage_status", "") or "new" for f in findings)
            return {
                "state": self.state,
                "scan_id": self.scan_id,
                "project_key": self.project_key,
                "scan_source": self.scan_source,
                "local_repo_path": self.local_repo_path,
                "scan_scope": self.scan_scope,
                "compare_ref": self.compare_ref,
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
                "findings": len(findings),
                "active_count": len(findings),
                "suppressed_count": len(suppressed_findings),
                "reviewed_count": triage_counts.get(TRIAGE_REVIEWED, 0),
                "accepted_risk_count": triage_counts.get(TRIAGE_ACCEPTED_RISK, 0),
                "sev": {
                    "critical": sev.get(1, 0),
                    "high": sev.get(2, 0),
                    "medium": sev.get(3, 0),
                    "low": sev.get(4, 0),
                },
                "delta": delta,
                "inventory": inventory,
                "scoped_files_by_repo": dict(self.scoped_files_by_repo),
                "per_repo": {
                    slug: {
                        "skipped": data is None,
                        "count": len(data) if data else 0,
                        "sev": dict(Counter(f.get("severity", 4) for f in (data or []))),
                        "reports": {},
                    }
                    for slug, data in per_repo.items()
                },
                "report": report_paths.get("__all__", {}),
                "duration_s": self.scan_duration_s,
                "llm_model": (self.llm_model_info or {}).get("name", self.llm_model),
                "llm_model_info": dict(self.llm_model_info),
                "pre_llm_count": self.pre_llm_count,
                "post_llm_count": self.post_llm_count,
                "phase_metrics": dict(self.phase_metrics),
                "repo_metrics": dict(self.repo_metrics),
                "llm_batch_metrics": list(self.llm_batch_metrics),
                "cache_metrics": dict(self.cache_metrics),
                "errors": list(self.errors[-10:]),
                "finding_details": [
                    self._finding_detail(f)
                    for f in sorted(
                        findings,
                        key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", "")),
                    )[:60]
                ],
                "suppressed_details": [
                    self._finding_detail(f)
                    for f in sorted(
                        suppressed_findings,
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
    llm_cfg_file: str = ""


class ScanJobService:
    _STALE_SCAN_ROOT_SECONDS = 6 * 60 * 60

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

    @staticmethod
    def _git_branch_name(repo_dir: Path) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            return result.stdout.strip()
        except (OSError, subprocess.SubprocessError, ValueError):
            return ""

    @staticmethod
    def _scan_workspace_name(scan_id: str) -> str:
        return f"scan_{scan_id}" if scan_id else "scan_unknown"

    def _scan_temp_root(self, session: ScanSession) -> Path:
        return Path(self.paths.temp_dir) / self._scan_workspace_name(session.scan_id)

    def _local_scan_excludes(self, repo_root: Path) -> list[str]:
        repo_root = Path(repo_root).resolve()
        candidates = [
            Path(self.paths.output_dir),
            Path(self.paths.temp_dir),
            Path(self.paths.log_dir),
            Path(self.paths.history_file),
            Path(self.paths.db_file),
            Path(self.paths.suppressions_file),
        ]
        excludes: list[str] = []
        for candidate in candidates:
            try:
                rel = candidate.resolve().relative_to(repo_root)
            except (OSError, RuntimeError, ValueError):
                continue
            rel_text = str(rel).replace("\\", "/").strip("/")
            if rel_text:
                excludes.append(rel_text)
        return sorted(set(excludes))

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
        llm_cfg_file: Optional[str] = None,
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
        if llm_cfg_file is not None:
            self.paths.llm_cfg_file = llm_cfg_file
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
        log_lines: list[dict] | None = None,
    ) -> dict:
        sev = Counter(f.get("severity", 4) for f in findings)
        ctx = Counter(f.get("context", "production") for f in findings)
        llm_name = (session.llm_model_info or {}).get("name", session.llm_model)
        active_rules = Counter(str(f.get("provider_or_lib", "") or f.get("category", "") or "unknown") for f in findings)
        suppressed_rules = Counter(
            str(f.get("provider_or_lib", "") or f.get("category", "") or "unknown")
            for f in list(session.suppressed_findings or [])
        )
        llm_summary = llm_stats(
            list(log_lines or []),
            state=session.state,
            llm_model=session.llm_model,
            llm_model_info=session.llm_model_info,
        )
        critical_prod = sum(
            1 for f in findings
            if f.get("severity") == 1 and str(f.get("context", "production")).lower() == "production"
        )
        high_prod = sum(
            1 for f in findings
            if f.get("severity") == 2 and str(f.get("context", "production")).lower() == "production"
        )
        return {
            "scan_id": session.scan_id,
            "date": session.scan_id[:8],
            "time": session.scan_id[9:] if len(session.scan_id) > 8 else "",
            "project_key": session.project_key,
            "scan_source": session.scan_source,
            "local_repo_path": session.local_repo_path,
            "repos": session.repo_slugs,
            "scan_scope": session.scan_scope,
            "compare_ref": session.compare_ref,
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
            "delta": session.delta,
            "inventory": session.inventory,
            "sev": {
                "critical": sev.get(1, 0),
                "high": sev.get(2, 0),
                "medium": sev.get(3, 0),
                "low": sev.get(4, 0),
            },
            "ctx": dict(ctx),
            "llm_model": llm_name,
            "llm_model_info": dict(session.llm_model_info or {}),
            "pre_llm_count": int(session.pre_llm_count or 0),
            "post_llm_count": int(session.post_llm_count or 0),
            "phase_metrics": dict(session.phase_metrics),
            "repo_metrics": dict(session.repo_metrics),
            "llm_batch_metrics": list(session.llm_batch_metrics),
            "cache_metrics": dict(session.cache_metrics),
            "errors": list(session.errors[-10:]),
            "critical_prod": critical_prod,
            "high_prod": high_prod,
            "repo_details": session.repo_details,
            "scoped_files_by_repo": dict(session.scoped_files_by_repo),
            "log_file": log_file,
            "reports": session.report_paths,
            "findings": list(findings),
            "trend": {
                "rules": {
                    "active": dict(active_rules),
                    "suppressed": dict(suppressed_rules),
                },
                "llm": {
                    "reviewed": int(llm_summary.get("reviewed", 0) or 0),
                    "skipped": int(llm_summary.get("skipped", 0) or 0),
                    "dismissed": int(llm_summary.get("dismissed", 0) or 0),
                    "downgraded": int(llm_summary.get("downgraded", 0) or 0),
                    "failed_batches": int(llm_summary.get("failed_batches", 0) or 0),
                    "failed_scan": int(llm_summary.get("failed_batches", 0) or 0) > 0,
                },
            },
        }

    def _build_scan_delta(
        self,
        findings: list,
        *,
        project_key: str,
        repo_slugs: list[str],
        scoped_files_by_repo: dict[str, list[str]] | None = None,
    ) -> dict:
        def _serialise_delta(delta: dict) -> dict:
            return {
                **delta,
                "existing_count": delta.get("existing_count", delta.get("unchanged_count", 0)),
                "new_hashes": sorted(delta.get("new_hashes", set())),
                "fixed_hashes": sorted(delta.get("fixed_hashes", set())),
                "fixed_findings": list(delta.get("fixed_findings", [])),
            }

        if not repo_slugs:
            return _serialise_delta({
                "has_baseline": False,
                "new_count": len(findings),
                "fixed_count": 0,
                "unchanged_count": 0,
                "existing_count": 0,
                "new_hashes": {f.get("_hash", "") for f in findings},
                "fixed_hashes": set(),
                "fixed_findings": [],
            })

        if len(repo_slugs) == 1:
            return _serialise_delta(
                build_delta_meta(
                    findings,
                    self.paths.output_dir,
                    project_key,
                    repo_slugs[0],
                    scanned_files=set((scoped_files_by_repo or {}).get(repo_slugs[0], []) or []),
                )
            )

        new_hashes = set()
        fixed_hashes = set()
        new_count = 0
        fixed_count = 0
        unchanged_count = 0
        existing_count = 0
        has_baseline = False
        fixed_findings: list[dict] = []

        for slug in repo_slugs:
            repo_findings = [f for f in findings if f.get("repo") == slug]
            repo_delta = build_delta_meta(
                repo_findings,
                self.paths.output_dir,
                project_key,
                slug,
                scanned_files=set((scoped_files_by_repo or {}).get(slug, []) or []),
            )
            if repo_delta.get("has_baseline"):
                has_baseline = True
            new_count += repo_delta.get("new_count", 0)
            fixed_count += repo_delta.get("fixed_count", 0)
            unchanged_count += repo_delta.get("unchanged_count", 0)
            existing_count += repo_delta.get("existing_count", repo_delta.get("unchanged_count", 0))
            new_hashes.update(repo_delta.get("new_hashes", set()))
            fixed_hashes.update(repo_delta.get("fixed_hashes", set()))
            fixed_findings.extend(repo_delta.get("fixed_findings", []))

        return _serialise_delta({
            "has_baseline": has_baseline,
            "baseline_file": "multiple baselines",
            "new_count": new_count,
            "fixed_count": fixed_count,
            "unchanged_count": unchanged_count,
            "existing_count": existing_count,
            "new_hashes": new_hashes,
            "fixed_hashes": fixed_hashes,
            "fixed_findings": fixed_findings,
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

    def _load_db_history_record(self, scan_id: str) -> dict | None:
        self._ensure_db()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT record_json FROM scan_jobs WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if not row:
            return None
        try:
            record = json.loads(row["record_json"])
        except (TypeError, ValueError, JSONDecodeError):
            return None
        if not isinstance(record, dict):
            return None
        return self._normalize_history_record(record)

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

    def _load_db_history_records(self) -> list[dict]:
        self._ensure_db()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT record_json FROM scan_jobs ORDER BY updated_at ASC, scan_id ASC"
            ).fetchall()
        records: list[dict] = []
        for row in rows:
            try:
                record = json.loads(row["record_json"])
            except Exception:
                continue
            if isinstance(record, dict) and record.get("scan_id"):
                records.append(self._normalize_history_record(record))
        return records

    @staticmethod
    def _normalize_history_record(record: dict) -> dict:
        normalized = dict(record)
        project_key = str(normalized.get("project_key", "") or normalized.get("project", "") or "")
        normalized["project_key"] = project_key
        normalized.pop("project", None)
        repo_slugs = normalized.get("repo_slugs", normalized.get("repos", []))
        if not isinstance(repo_slugs, list):
            repo_slugs = []
        normalized["repo_slugs"] = [str(slug).strip() for slug in repo_slugs if str(slug).strip()]
        normalized["repos"] = list(normalized["repo_slugs"])
        findings = normalized.get("findings", [])
        normalized["findings"] = findings if isinstance(findings, list) else []
        return normalized

    @staticmethod
    def _report_base_name(record: dict) -> str:
        reports = (record.get("reports") or {}).get("__all__", {})
        csv_name = str(reports.get("csv_name", "") or "").strip()
        if csv_name:
            return Path(csv_name).stem
        project_key = str(record.get("project_key", "") or "LOCAL")
        repo_slugs = [str(slug).strip() for slug in list(record.get("repo_slugs", record.get("repos", [])) or []) if str(slug).strip()]
        label = "ALL" if len(repo_slugs) > 1 else (repo_slugs[0] if repo_slugs else "results")
        scan_id = str(record.get("scan_id", "") or datetime.now().strftime("%Y%m%d_%H%M%S"))
        date_part = scan_id[:8] if len(scan_id) >= 8 else datetime.now().strftime("%Y%m%d")
        time_part = scan_id[9:15] if len(scan_id) >= 15 else datetime.now().strftime("%H%M%S")
        return f"AI_Scan_Report_{project_key}_{label}_{date_part}_{time_part}"

    def _report_meta_from_record(self, record: dict) -> dict:
        repo_slugs = [str(slug).strip() for slug in list(record.get("repo_slugs", record.get("repos", [])) or []) if str(slug).strip()]
        repo_details = dict(record.get("repo_details") or {})
        llm_cfg = load_llm_config(self.paths.llm_cfg_file) if self.paths.llm_cfg_file else {}
        if len(repo_slugs) > 1:
            repos_meta = [
                {
                    "slug": slug,
                    "owner": str((repo_details.get(slug) or {}).get("owner", "User") or "User"),
                    "branch": str((repo_details.get(slug) or {}).get("branch", "default") or "default"),
                    "commit": str((repo_details.get(slug) or {}).get("commit", "") or ""),
                }
                for slug in repo_slugs
            ]
            return {
                "repo": f"{len(repo_slugs)} repositories",
                "project_key": str(record.get("project_key", "") or ""),
                "owner": "",
                "branch": "",
                "operator": str(record.get("operator", "") or ""),
                "started_at_utc": str(record.get("started_at_utc", "") or ""),
                "completed_at_utc": str(record.get("completed_at_utc", "") or ""),
                "policy_version": str(record.get("policy_version", "") or ""),
                "tool_version": str(record.get("tool_version", "") or ""),
                "repos_meta": repos_meta,
                "scan_id": str(record.get("scan_id", "") or ""),
                "delta": dict(record.get("delta") or {}),
                "inventory": dict(record.get("inventory") or {}),
                "llm_model_info": dict(record.get("llm_model_info") or {}),
                "report_detail_timeout_s": int(record.get("report_detail_timeout_s", llm_cfg.get("report_detail_timeout_s", 180)) or 180),
                "scan_duration_s": int(record.get("duration_s", 0) or 0),
                "pre_llm_count": int(record.get("pre_llm_count", 0) or 0),
                "post_llm_count": int(record.get("post_llm_count", record.get("total", 0)) or 0),
                "suppressed_count": int(record.get("suppressed_total", 0) or 0),
                "reviewed_count": int(record.get("reviewed_count", 0) or 0),
                "accepted_risk_count": int(record.get("accepted_risk_count", 0) or 0),
            }
        single_slug = repo_slugs[0] if repo_slugs else Path(str(record.get("local_repo_path", "") or "")).name or "results"
        detail = dict(repo_details.get(single_slug) or {})
        return {
            "repo": single_slug,
            "project_key": str(record.get("project_key", "") or ""),
            "owner": str(detail.get("owner", "User") or "User"),
            "branch": str(detail.get("branch", "") or ""),
            "commit": str(detail.get("commit", "") or ""),
            "operator": str(record.get("operator", "") or ""),
            "started_at_utc": str(record.get("started_at_utc", "") or ""),
            "completed_at_utc": str(record.get("completed_at_utc", "") or ""),
            "policy_version": str(record.get("policy_version", "") or ""),
            "tool_version": str(record.get("tool_version", "") or ""),
            "scan_id": str(record.get("scan_id", "") or ""),
            "delta": dict(record.get("delta") or {}),
            "inventory": dict(record.get("inventory") or {}),
            "llm_model_info": dict(record.get("llm_model_info") or {}),
            "report_detail_timeout_s": int(record.get("report_detail_timeout_s", llm_cfg.get("report_detail_timeout_s", 180)) or 180),
            "scan_duration_s": int(record.get("duration_s", 0) or 0),
            "pre_llm_count": int(record.get("pre_llm_count", 0) or 0),
            "post_llm_count": int(record.get("post_llm_count", record.get("total", 0)) or 0),
            "suppressed_count": int(record.get("suppressed_total", 0) or 0),
            "reviewed_count": int(record.get("reviewed_count", 0) or 0),
            "accepted_risk_count": int(record.get("accepted_risk_count", 0) or 0),
        }

    def _report_meta_from_session(self, session: ScanSession, findings: list[dict]) -> dict:
        repo_slugs = [str(slug).strip() for slug in list(session.repo_slugs or []) if str(slug).strip()]
        record = {
            "scan_id": session.scan_id,
            "project_key": session.project_key,
            "repo_slugs": repo_slugs,
            "repos": repo_slugs,
            "repo_details": dict(session.repo_details or {}),
            "operator": session.operator,
            "started_at_utc": session.started_at_utc,
            "completed_at_utc": session.completed_at_utc,
            "policy_version": session.policy_version,
            "tool_version": session.tool_version,
            "delta": dict(session.delta or {}),
            "inventory": dict(session.inventory or {}),
            "llm_model_info": dict(session.llm_model_info or {}),
            "duration_s": session.scan_duration_s,
            "pre_llm_count": session.pre_llm_count,
            "post_llm_count": session.post_llm_count or len(findings),
            "suppressed_total": len(session.suppressed_findings),
            "reviewed_count": sum(1 for f in findings if str(f.get("triage_status", "") or "") == TRIAGE_REVIEWED),
            "accepted_risk_count": sum(1 for f in findings if str(f.get("triage_status", "") or "") == TRIAGE_ACCEPTED_RISK),
            "report_detail_timeout_s": int((session.llm_model_info or {}).get("report_detail_timeout_s", 180) or 180),
            "total": len(findings),
            "llm_model": (session.llm_model_info or {}).get("name", session.llm_model),
        }
        return self._report_meta_from_record(record)

    def _write_structured_reports(
        self,
        *,
        findings: list[dict],
        base_name: str,
        report_meta: dict,
        write_csv: bool,
        existing_reports: dict[str, Any] | None = None,
        replay_instructions: str = "",
    ) -> dict[str, Any]:
        reports = dict(existing_reports or {})
        if write_csv:
            csv_reporter = CSVReporter(output_dir=self.paths.output_dir, scan_id=base_name)
            csv_path = csv_reporter.write_csv(findings)
            reports["csv"] = str(Path(csv_path).resolve())
            reports["csv_name"] = Path(csv_path).name
        json_reporter = JSONReporter(output_dir=self.paths.output_dir, scan_id=base_name)
        json_path = json_reporter.write_json(findings, meta=report_meta, replay_instructions=replay_instructions)
        reports["json"] = str(Path(json_path).resolve())
        reports["json_name"] = Path(json_path).name
        return reports

    def generate_html_report(
        self,
        scan_id: str,
        findings: list[dict] | None = None,
        *,
        progress_fn: Callable[[int, int, str], None] | None = None,
        detail_mode: str = "detailed",
    ) -> dict:
        record = self._load_db_history_record(scan_id)
        if not record:
            raise RuntimeError("Stored scan record not found")
        findings = list(findings if findings is not None else record.get("findings") or [])
        if not findings:
            raise RuntimeError("This scan does not have stored findings to build an HTML report")
        reports = dict((record.get("reports") or {}).get("__all__", {}) or {})
        detail_mode = "fast" if str(detail_mode or "").strip().lower() == "fast" else "detailed"
        existing_html = str(reports.get("html", "") or "")
        existing_mode = str(reports.get("html_detail_mode", "detailed") or "detailed").strip().lower()
        if existing_html and Path(existing_html).exists() and existing_mode == detail_mode:
            return record

        base_name = self._report_base_name(record)
        Path(self.paths.output_dir).mkdir(parents=True, exist_ok=True)
        html_reporter = HTMLReporter(
            output_dir=self.paths.output_dir,
            scan_id=base_name,
            include_snippets=True,
            meta=self._report_meta_from_record(record),
        )
        llm_cfg = load_llm_config(self.paths.llm_cfg_file) if self.paths.llm_cfg_file else load_llm_config()
        ollama_url = str(llm_cfg.get("base_url", "") or "").strip()
        ollama_model = str(record.get("llm_model", "") or llm_cfg.get("model", "") or "").strip()
        html_path = html_reporter.write(
            findings,
            policy=self._load_policy(self.paths.policy_file),
            ollama_url=ollama_url,
            ollama_model=ollama_model,
            progress_fn=progress_fn,
            detail_mode=detail_mode,
        )
        reports["html"] = str(Path(html_path).resolve())
        reports["html_name"] = Path(html_path).name
        reports["html_detail_mode"] = detail_mode
        updated = dict(record)
        updated["reports"] = {"__all__": reports}
        self._upsert_job_record(updated)
        self._sync_legacy_history_export()
        return self._normalize_history_record(updated)

    @staticmethod
    def _is_meaningful_history_record(record: dict) -> bool:
        repo_slugs = record.get("repo_slugs", record.get("repos", []))
        if not isinstance(repo_slugs, list):
            return False
        return any(str(slug).strip() for slug in repo_slugs)

    def _latest_repo_record(self, project_key: str, repo_slug: str, *, exclude_scan_id: str = "") -> dict | None:
        for record in reversed(self.load_history()):
            if str(record.get("scan_id", "")) == str(exclude_scan_id or ""):
                continue
            if str(record.get("project_key", "") or "") != str(project_key or ""):
                continue
            repo_slugs = list(record.get("repo_slugs", record.get("repos", [])) or [])
            if repo_slug in repo_slugs:
                return record
        return None

    def _read_legacy_history(self) -> list:
        try:
            path = Path(self.paths.history_file)
            if not path.exists():
                return []
            return json.loads(path.read_text("utf-8"))
        except Exception:
            return []

    def _db_history_count(self) -> int:
        self._ensure_db()
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM scan_jobs").fetchone()
        return int(row["count"] if row is not None else 0)

    def _migrate_legacy_history_if_needed(self) -> None:
        if not self.paths.history_file:
            return
        if self._db_history_count() > 0:
            return
        legacy_records = self._read_legacy_history()
        if not legacy_records:
            return
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO scan_jobs(scan_id, state, updated_at, record_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    state=excluded.state,
                    updated_at=excluded.updated_at,
                    record_json=excluded.record_json
                """,
                [
                    (
                        str(record.get("scan_id", "")),
                        str(record.get("state", "unknown")),
                        time.time(),
                        json.dumps(self._normalize_history_record(record), ensure_ascii=False),
                    )
                    for record in legacy_records
                    if isinstance(record, dict) and record.get("scan_id")
                ],
            )
            conn.commit()

    def _sync_legacy_history_export(self) -> None:
        if not self.paths.history_file:
            return
        history = self._load_db_history_records()[-500:]
        tmp_path = self.paths.history_file + ".tmp"
        Path(self.paths.history_file).parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(history, fh, indent=2)
        os.replace(tmp_path, self.paths.history_file)

    def record_job_snapshot(self, session: ScanSession, findings: Optional[list] = None) -> None:
        with session.state_lock:
            snapshot = self._build_record(session, findings if findings is not None else list(session.findings))
        self._upsert_job_record(snapshot)

    @staticmethod
    def _history_sort_key(record: dict) -> tuple[str, str]:
        return (
            str(record.get("completed_at_utc") or record.get("started_at_utc") or ""),
            str(record.get("scan_id") or ""),
        )

    def load_history(self) -> list:
        self._migrate_legacy_history_if_needed()
        try:
            records = self._load_db_history_records()
        except sqlite3.Error:
            records = []
        records = [record for record in records if self._is_meaningful_history_record(record)]
        return sorted(records, key=self._history_sort_key)

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
        except sqlite3.Error:
            pass
        for suffix in (".txt", ".log"):
            path = Path(self.paths.log_dir) / f"{scan_id}{suffix}"
            if path.exists():
                try:
                    return path.read_text("utf-8")
                except (OSError, UnicodeDecodeError):
                    return ""
        return ""

    def delete_history(self, scan_ids: list[str]) -> None:
        if not scan_ids:
            return
        self._migrate_legacy_history_if_needed()
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
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to delete stored history: {exc}") from exc
        try:
            self._sync_legacy_history_export()
        except OSError as exc:
            raise RuntimeError(f"Failed to update history export: {exc}") from exc

    def cleanup_stale_temp_clones(self, *, current_scan_id: str = "") -> None:
        from scanner.bitbucket import cleanup_clone

        temp_root = Path(self.paths.temp_dir)
        if not temp_root.exists():
            return
        now = time.time()
        current_workspace = self._scan_workspace_name(current_scan_id)
        for child in temp_root.iterdir():
            try:
                if child.name == current_workspace:
                    continue
                age_s = now - child.stat().st_mtime
                if age_s < self._STALE_SCAN_ROOT_SECONDS:
                    continue
                if child.is_dir() and child.name.startswith("scan_"):
                    cleanup_clone(child)
                elif child.is_file() and child.name.startswith("scan_"):
                    child.unlink()
            except OSError:
                pass

    def save_history_record(self, session: ScanSession, findings: list) -> None:
        if not any(str(slug).strip() for slug in list(session.repo_slugs or [])):
            return
        self._migrate_legacy_history_if_needed()
        Path(self.paths.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.paths.log_dir).mkdir(parents=True, exist_ok=True)
        log_path = Path(self.paths.log_dir) / f"{session.scan_id}.txt"
        with session.state_lock:
            log_lines = list(session.log_lines)
        with open(log_path, "w", encoding="utf-8") as fh:
            for entry in log_lines:
                ts = datetime.fromtimestamp(entry["ts"]).strftime("%H:%M:%S")
                fh.write(f"[{ts}] {entry.get('msg', '')}\n")

        with session.state_lock:
            record = self._build_record(session, findings, log_file=str(log_path), log_lines=log_lines)
        try:
            self._upsert_job_record(record)
            self._replace_scan_logs(session.scan_id, log_lines)
            self._sync_legacy_history_export()
        except (sqlite3.Error, OSError, TypeError, ValueError, JSONDecodeError) as exc:
            raise RuntimeError(f"Could not save history: {exc}") from exc

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
        scan_temp_root = self._scan_temp_root(session)
        scan_temp_root.mkdir(parents=True, exist_ok=True)
        self.cleanup_stale_temp_clones(current_scan_id=session.scan_id)

        t_start = time.time()
        with session.state_lock:
            session.started_at_utc = session.started_at_utc or self._utc_now_iso()
            session.completed_at_utc = ""
            session.policy_version = self._policy_version(self.paths.policy_file)
            session.tool_version = self.app_version
            session.suppressed_findings = []
            session.delta = {}
            session.inventory = {}
            session.scoped_files_by_repo = {}
            session.phase_metrics = {}
            session.repo_metrics = {}
            session.llm_batch_metrics = []
            session.cache_metrics = {}
            session.errors = []
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
        if session.scan_source == "local" and session.local_repo_path:
            log(f"Local Path: {session.local_repo_path}", "dim")
        scope_labels = {
            "full": "full scan",
            "changed_files": "changed-files scan",
            "branch_diff": f"branch-diff scan vs {session.compare_ref}",
            "baseline_rescan": "baseline-aware rescan",
        }
        log(f"Scope    : {scope_labels.get(session.scan_scope, 'full scan')}", "dim")

        with session.state_lock:
            session.llm_model_info = {}
        llm_enabled = True

        if not self._ollama_ping(session.llm_url):
            session.record_error("OLLAMA_UNREACHABLE", "llm_setup", session.llm_url)
            log("  [LLM] Ollama not reachable - running without LLM review", "warn")
            llm_enabled = False
        else:
            try:
                info = LLMReviewer(
                    base_url=session.llm_url, model=session.llm_model
                ).model_info()
                with session.state_lock:
                    session.llm_model_info = dict(info)
                parts = [info["name"]]
                if info.get("parameter_size"):
                    parts.append(info["parameter_size"])
                if info.get("quantization"):
                    parts.append(info["quantization"])
                log(f"LLM      : {' | '.join(parts)}", "dim")
            except EXPECTED_LLM_ERRORS as exc:
                with session.state_lock:
                    session.llm_model_info = {"name": session.llm_model}
                session.record_error("LLM_INFO_FALLBACK", "llm_setup", str(exc), model=session.llm_model)
                log(f"LLM      : {session.llm_model}  [LLM_INFO_FALLBACK: {exc}]", "dim")

        log("=" * 58, "dim")
        session.set_phase_time("init", time.time() - t_start)

        repo_meta: Dict[str, dict] = {}
        git_env = client.build_git_auth_env() if client is not None else {}
        local_root = Path(session.local_repo_path).expanduser() if session.local_repo_path else None
        for slug in session.repo_slugs:
            if stop.is_set():
                break
            if session.scan_source == "local" and local_root is not None:
                branch = self._git_branch_name(local_root) or "local"
                owner = session.operator or "User"
                per_branch[slug] = branch
                repo_meta[slug] = {
                    "branch": branch,
                    "owner": owner,
                    "url": str(local_root),
                }
                log(f"  {slug}  branch:{branch}  owner:{owner}  source:local", "dim")
                continue
            try:
                if client is None:
                    raise RuntimeError("Bitbucket client unavailable")
                metadata = client.get_repo_metadata(session.project_key, slug)
                branch = metadata.get("branch")
                owner = metadata.get("owner", "User")
                url = metadata.get("clone_url")
                per_branch[slug] = branch or "default"
                repo_meta[slug] = {"branch": branch, "owner": owner, "url": url}
                log(f"  {slug}  branch:{branch or '?'}  owner:{owner}", "dim")
            except EXPECTED_METADATA_ERRORS as exc:
                session.record_error("META_FETCH_FAILED", "metadata", f"{slug}: {exc}", repo=slug)
                log(f"  [META_FETCH] {slug}: {exc}", "err")
                repo_meta[slug] = {"branch": None, "owner": "User", "url": ""}

        log("=" * 58, "dim")

        try:
            from scanner.llm_reviewer import _available_vram_gb, compute_worker_count

            vram_gb = _available_vram_gb()
            param_sz = (session.llm_model_info or {}).get("parameter_size", "")
            workers = compute_worker_count(
                param_sz, vram_gb=vram_gb, repo_count=len(session.repo_slugs)
            )
        except EXPECTED_LLM_ERRORS as exc:
            workers = 4
            session.record_error("WORKER_PLAN_FALLBACK", "planning", str(exc))
            log(f"  [WORKER_PLAN] fallback=4 reason={exc}", "dim")

        log(f"Starting parallel scan (workers={workers})...", "info")

        from scanner.bitbucket import (
            cleanup_clone,
            git_changed_files_against_ref,
            git_changed_files_since_previous_commit,
            shallow_clone,
        )

        def _resolve_scoped_files(slug: str, clone_dir: Path) -> list[str] | None:
            scope = str(session.scan_scope or "full").strip().lower()
            compare_ref = str(session.compare_ref or "").strip()
            verify_ssl = bool(getattr(client, "verify_ssl", True))
            ca_bundle = str(getattr(client, "ca_bundle", "") or "")
            if scope == "full":
                return None
            if scope == "changed_files":
                try:
                    changed = git_changed_files_since_previous_commit(
                        clone_dir,
                        git_env=git_env,
                        verify_ssl=verify_ssl,
                        ca_bundle=ca_bundle,
                    )
                    log(f"  [{slug}] Scope: {len(changed)} file(s) changed since previous commit", "dim")
                    return changed
                except RuntimeError as exc:
                    log(f"  [{slug}] Scope fallback to full scan [changed-files]: {exc}", "warn")
                    return None
            if scope == "branch_diff":
                if not compare_ref:
                    log(f"  [{slug}] Scope fallback to full scan [branch-diff]: compare branch missing", "warn")
                    return None
                try:
                    changed = git_changed_files_against_ref(
                        clone_dir,
                        compare_ref,
                        git_env=git_env,
                        verify_ssl=verify_ssl,
                        ca_bundle=ca_bundle,
                    )
                    log(f"  [{slug}] Scope: {len(changed)} file(s) changed vs {compare_ref}", "dim")
                    return changed
                except RuntimeError as exc:
                    log(f"  [{slug}] Scope fallback to full scan [branch-diff]: {exc}", "warn")
                    return None
            if scope == "baseline_rescan":
                baseline_record = self._latest_repo_record(
                    session.project_key,
                    slug,
                    exclude_scan_id=session.scan_id,
                )
                baseline_commit = str(
                    ((baseline_record or {}).get("repo_details") or {}).get(slug, {}).get("commit", "")
                    or ""
                ).strip()
                if not baseline_commit:
                    log(f"  [{slug}] Scope fallback to full scan [baseline]: no previous commit baseline", "warn")
                    return None
                try:
                    changed = git_changed_files_against_ref(
                        clone_dir,
                        baseline_commit,
                        git_env=git_env,
                        verify_ssl=verify_ssl,
                        ca_bundle=ca_bundle,
                    )
                    log(f"  [{slug}] Scope: {len(changed)} file(s) changed since baseline commit {baseline_commit[:12]}", "dim")
                    return changed
                except RuntimeError as exc:
                    log(f"  [{slug}] Scope fallback to full scan [baseline]: {exc}", "warn")
                    return None
            log(f"  [{slug}] Scope fallback to full scan [unknown scope: {scope}]", "warn")
            return None

        def _scan_one(slug: str) -> tuple:
            if stop.is_set():
                return slug, None, "", 0, "scan stopped"
            meta = repo_meta.get(slug, {})
            branch = meta.get("branch")
            owner = meta.get("owner", "User")
            clone_url = meta.get("url", "")
            clone_dir = scan_temp_root / slug
            repo_root = clone_dir
            cleanup_required = True
            repo_started = time.perf_counter()
            clone_started = time.perf_counter()
            clone_duration = 0.0
            scan_duration = 0.0
            llm_duration = 0.0
            try:
                if session.scan_source == "local":
                    if not local_root or not local_root.exists() or not local_root.is_dir():
                        session.record_error("LOCAL_REPO_NOT_FOUND", "clone", session.local_repo_path, repo=slug)
                        return slug, None, owner, 0, f"local repo path not found: {session.local_repo_path}"
                    repo_root = local_root
                    cleanup_required = False
                else:
                    shallow_clone(
                        clone_url,
                        clone_dir,
                        depth=2 if str(session.scan_scope or "full").lower() == "changed_files" else 1,
                        branch=branch,
                        verbose=False,
                        stop_event=stop,
                        proc_holder=session.proc_holder,
                        proc_lock=session.proc_lock,
                        git_env=git_env,
                        verify_ssl=bool(getattr(client, "verify_ssl", True)),
                        ca_bundle=str(getattr(client, "ca_bundle", "") or ""),
                    )
                clone_duration = max(time.perf_counter() - clone_started, 0.0)
                session.add_phase_time("clone", clone_duration)
                meta["commit"] = self._git_head_commit(repo_root)
            except RuntimeError as exc:
                session.record_error("CLONE_FAILED", "clone", str(exc), repo=slug)
                return slug, None, owner, 0, f"clone failed: {exc}"
            except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
                session.record_error("CLONE_ERROR", "clone", str(exc), repo=slug)
                return slug, None, owner, 0, f"clone error: {exc}"

            if stop.is_set():
                if cleanup_required:
                    cleanup_clone(clone_dir)
                return slug, None, owner, 0, "scan stopped"

            try:
                last_pct = [-1]
                scoped_files = _resolve_scoped_files(slug, repo_root)
                excluded_paths = self._local_scan_excludes(repo_root) if session.scan_source == "local" else []
                with session.state_lock:
                    session.scoped_files_by_repo[slug] = list(scoped_files or [])

                if scoped_files == []:
                    session.record_repo_metric(
                        slug,
                        clone_s=round(clone_duration, 2),
                        scan_s=0.0,
                        llm_review_s=0.0,
                        total_s=round(time.perf_counter() - repo_started, 2),
                    )
                    log(f"  [{slug}] No files matched the selected scan scope", "dim")
                    return slug, [], owner, 0, None
                if excluded_paths:
                    log(f"  [{slug}] Local scan excludes: {', '.join(excluded_paths)}", "dim")

                def _on_file(rel, idx, total):
                    with session.state_lock:
                        session.current_file = f"{slug}/{rel}"
                        session.file_index = idx + 1
                        session.total_files = max(session.total_files, total)
                    pct = int((idx + 1) / max(total, 1) * 100)
                    if pct % 5 == 0 and pct != last_pct[0]:
                        last_pct[0] = pct
                        log(f"  [{slug}] Scanning: {pct}% ({idx+1}/{total} files)", "dim")

                scan_started = time.perf_counter()
                raw, file_contents = detector.scan(
                    repo_root,
                    repo_name=slug,
                    stop_event=stop,
                    return_file_contents=True,
                    on_file=_on_file,
                    include_paths=scoped_files,
                    exclude_paths=excluded_paths,
                )
                scan_duration = max(time.perf_counter() - scan_started, 0.0)
                session.add_phase_time("scan", scan_duration)
                if not scoped_files:
                    try:
                        history_findings = scan_history(repo_root, detector, slug, stop_event=stop)
                        if history_findings:
                            raw.extend(history_findings)
                    except Exception as hist_err:
                        session.record_error("HISTORY_SCAN_FAILED", "history", str(hist_err), repo=slug)
                        log(f"  [history] {slug}: {hist_err}", "dim")

                analyzed = analyzer.analyze(raw)
                pre_llm_count = len(analyzed)

                if llm_enabled and analyzed:
                    try:
                        def _llm_batch_metric(batch_data: dict) -> None:
                            session.record_llm_batch({
                                **dict(batch_data),
                                "repo": slug,
                                "model": session.llm_model,
                            })

                        reviewer = LLMReviewer(
                            base_url=session.llm_url,
                            model=session.llm_model,
                            log_fn=log,
                            stop_event=stop,
                            batch_callback=_llm_batch_metric,
                        )
                        log(f"  [LLM] Evaluating {len(analyzed)} finding(s) for review...", "dim")
                        llm_started = time.perf_counter()
                        analyzed = reviewer.review(analyzed, file_contents)
                        llm_duration = max(time.perf_counter() - llm_started, 0.0)
                        session.add_phase_time("llm review", llm_duration)
                        analyzed = analyzer.refresh_scores(analyzed)
                        log(f"  [LLM] Review stage complete -> {len(analyzed)} finding(s)", "dim")
                    except EXPECTED_LLM_ERRORS as exc:
                        session.record_error("LLM_REVIEW_FAILED", "llm_review", str(exc), repo=slug, model=session.llm_model)
                        log(f"  [LLM_REVIEW] skipped: {exc}", "dim")

                session.record_repo_metric(
                    slug,
                    clone_s=round(clone_duration, 2),
                    scan_s=round(scan_duration, 2),
                    llm_review_s=round(llm_duration, 2),
                    total_s=round(time.perf_counter() - repo_started, 2),
                )
                return slug, analyzed, owner, pre_llm_count, None
            except (OSError, ValueError, TypeError, KeyError, JSONDecodeError) as exc:
                session.record_error("REPO_SCAN_FAILED", "scan", str(exc), repo=slug)
                return slug, None, owner, 0, f"scan error: {exc}"
            finally:
                if slug not in session.repo_metrics:
                    session.record_repo_metric(
                        slug,
                        clone_s=round(clone_duration, 2),
                        scan_s=round(scan_duration, 2),
                        llm_review_s=round(llm_duration, 2),
                        total_s=round(time.perf_counter() - repo_started, 2),
                    )
                if cleanup_required:
                    cleanup_clone(clone_dir)

        total_pre_llm = 0
        total_post_llm = 0
        completed = 0

        with session.state_lock:
            session._active_pool = None
        with ThreadPoolExecutor(max_workers=workers) as pool:
            with session.state_lock:
                session._active_pool = pool
            futures = {pool.submit(_scan_one, slug): slug for slug in session.repo_slugs}
            for fut in as_completed(futures):
                if stop.is_set():
                    for future in futures:
                        future.cancel()
                    break

                slug, analyzed, bb_owner, pre_llm, skip_reason = fut.result()
                completed += 1
                with session.state_lock:
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
                    with session.state_lock:
                        session.suppressed_findings.extend(suppressed_findings)
                    log(f"  [FP] Suppressed {len(suppressed_findings)} finding(s)", "dim")
                total_post_llm += len(active_findings)

                for finding in active_findings:
                    finding["project_key"] = session.project_key
                    finding["owner"] = bb_owner
                    finding["last_seen"] = session.scan_id
                all_findings.extend(active_findings)
                per_repo[slug] = active_findings
                with session.state_lock:
                    session.per_repo = dict(per_repo)
                    session.findings = list(all_findings)
                self.record_job_snapshot(session, session.findings)

        log("\n" + "=" * 58, "dim")
        final = aggregator.process(all_findings)
        with session.state_lock:
            session.findings = final
            session.pre_llm_count = int(total_pre_llm or 0)
            session.post_llm_count = int(total_post_llm or 0)
        scanned_slugs = [slug for slug in session.repo_slugs if per_repo.get(slug) is not None]
        delta_meta = self._build_scan_delta(
            final,
            project_key=session.project_key,
            repo_slugs=scanned_slugs,
            scoped_files_by_repo=dict(session.scoped_files_by_repo),
        )
        inventory_meta = build_inventory(final, repo_slugs=scanned_slugs)
        with session.state_lock:
            session.delta = delta_meta
            session.inventory = inventory_meta
        new_hashes = delta_meta.get("new_hashes", set())
        for finding in final:
            finding["delta_status"] = "new" if finding.get("_hash", "") in new_hashes else "existing"
        if delta_meta.get("has_baseline"):
            log(
                "Baseline compare: "
                f"{delta_meta.get('new_count', 0)} new, "
                f"{delta_meta.get('existing_count', delta_meta.get('unchanged_count', 0))} existing, "
                f"{delta_meta.get('fixed_count', 0)} fixed since last scan",
                "dim",
            )
        if inventory_meta.get("repos_using_ai_count", 0):
            log(
                "Inventory: "
                f"{inventory_meta.get('repos_using_ai_count', 0)}/{inventory_meta.get('repos_total', 0)} repos with AI, "
                f"{inventory_meta.get('provider_count', 0)} providers, "
                f"{inventory_meta.get('model_count', 0)} models",
                "dim",
            )
        log(f"Total findings (deduped): {len(final)}", "hd")

        log("\nGenerating reports...", "dim")
        report_paths: Dict[str, dict] = {}

        for slug in session.repo_slugs:
            if per_repo.get(slug) is None:
                log(f"  {slug}: skipped (no findings recorded)", "dim")
            elif not [f for f in final if f.get("repo") == slug]:
                log(f"  {slug}: clean - no findings", "ok")

        try:
            report_started = time.perf_counter()
            dt_date = datetime.now().strftime("%Y%m%d")
            dt_time = datetime.now().strftime("%H%M%S")
            is_multi = len(scanned_slugs) > 1
            label = "ALL" if is_multi else (scanned_slugs[0] if scanned_slugs else (session.repo_slugs[0] if session.repo_slugs else "results"))
            safe_name = f"AI_Scan_Report_{session.project_key}_{label}_{dt_date}_{dt_time}"
            report_meta = self._report_meta_from_session(session, final)

            log("  Writing CSV report...", "dim")
            log("  Writing JSON report...", "dim")
            structured_reports = self._write_structured_reports(
                findings=final,
                base_name=safe_name,
                report_meta=report_meta,
                write_csv=True,
            )
            if final:
                log("  HTML report deferred until requested from the Results tab.", "dim")
            else:
                log("  No findings - HTML report skipped.", "dim")
            report_paths["__all__"] = structured_reports
            with session.state_lock:
                session.report_paths = dict(report_paths)
            session.add_phase_time("report", time.perf_counter() - report_started)
            log(
                "  OK Reports: "
                f"{Path(structured_reports['csv']).name}, "
                f"{Path(structured_reports['json']).name}",
                "ok",
            )
        except EXPECTED_REPORT_ERRORS as exc:
            session.record_error("REPORT_GEN_FAILED", "report", str(exc))
            log(f"  [REPORT_GEN] error: {exc}", "err")

        with session.state_lock:
            session.scan_duration_s = int(time.time() - t_start)
            session.cache_metrics = dict(getattr(client, "cache_stats", lambda: {})() if client is not None else {})
            session.set_phase_time("total", session.scan_duration_s)
            session.completed_at_utc = self._utc_now_iso()
            session.repo_details = {
                slug: {
                    "owner": repo_meta.get(slug, {}).get("owner", "User"),
                    "branch": repo_meta.get(slug, {}).get("branch") or "default",
                    "commit": repo_meta.get(slug, {}).get("commit", ""),
                }
                for slug in session.repo_slugs
            }

        skipped_all = all(value is None for value in per_repo.values()) and len(per_repo) > 0
        if stop.is_set():
            with session.state_lock:
                session.state = "stopped"
        elif skipped_all:
            with session.state_lock:
                session.state = "skipped"
        else:
            with session.state_lock:
                session.state = "done"
        self.record_job_snapshot(session, final)

        if stop.is_set():
            log("\nScan stopped.", "hd")
        elif skipped_all:
            log("\nAll repositories were skipped.", "warn")
        else:
            log("\nScan complete.", "hd")
        log(f"Duration: {session.scan_duration_s}s  |  Findings: {len(final)}", "info")

        with session.state_lock:
            session.completed_at_utc = self._utc_now_iso()
        persist_record(session, final)
        try:
            from scanner.bitbucket import cleanup_clone

            cleanup_clone(scan_temp_root)
        except OSError:
            pass
