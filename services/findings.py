from __future__ import annotations

from collections import Counter
from datetime import datetime

from services.rule_labels import format_rule_label
from scanner.suppressions import (
    TRIAGE_ACCEPTED_RISK,
    TRIAGE_FALSE_POSITIVE,
    TRIAGE_REVIEWED,
)


def _safe_dt(value: str) -> tuple[int, str]:
    if not value:
        return 0, ""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return int(dt.timestamp()), value
    except Exception:
        return 0, str(value)


def _status_label(status: str) -> str:
    return {
        TRIAGE_FALSE_POSITIVE: "Suppressed",
        TRIAGE_ACCEPTED_RISK: "Accepted Risk",
        TRIAGE_REVIEWED: "Reviewed",
        "fixed": "Fixed",
        "open": "Open",
    }.get(status, "Open")


def _severity_label(value: object, raw_label: str = "") -> str:
    raw = str(raw_label or "").strip()
    lowered = raw.lower()
    if lowered in {"critical", "high", "medium", "low"}:
        return raw.title()
    mapping = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
    try:
        sev = int(value or 4)
    except Exception:
        sev = 4
    if lowered.startswith("sev-"):
        return mapping.get(sev, "Low")
    return raw or mapping.get(sev, "Low")


def build_findings_rollups(history: list[dict], triage: dict[str, dict]) -> list[dict]:
    fixed_marks: dict[str, tuple[int, str]] = {}
    for record in history:
        delta = dict(record.get("delta") or {})
        completed_at = str(record.get("completed_at_utc") or record.get("started_at_utc") or "")
        fixed_at = _safe_dt(completed_at)
        for hash_ in delta.get("fixed_hashes", []) or []:
            if hash_ and fixed_at > fixed_marks.get(str(hash_), (0, "")):
                fixed_marks[str(hash_)] = fixed_at

    rollups: dict[str, dict] = {}
    for record in history:
        scan_id = str(record.get("scan_id", "") or "")
        started_at = str(record.get("started_at_utc", "") or "")
        started_ts = _safe_dt(started_at)
        for finding in list(record.get("findings") or []):
            hash_ = str(finding.get("_hash", "") or "")
            if not hash_:
                continue
            row = rollups.setdefault(hash_, {
                "hash": hash_,
                "project_key": str(finding.get("project_key", record.get("project_key", "")) or ""),
                "repo": str(finding.get("repo", "") or ""),
                "file": str(finding.get("file", "") or ""),
                "line": str(finding.get("line", "") or ""),
                "severity": int(finding.get("severity", 4) or 4),
                "severity_label": _severity_label(
                    finding.get("severity", 4),
                    str(finding.get("severity_label", "") or ""),
                ),
                "rule": str(finding.get("provider_or_lib", "") or finding.get("category", "") or "unknown"),
                "capability": str(finding.get("capability", "") or ""),
                "rule_label": format_rule_label(
                    str(finding.get("provider_or_lib", "") or finding.get("category", "") or "unknown"),
                    str(finding.get("capability", "") or ""),
                ),
                "ai_category": str(finding.get("ai_category", "") or ""),
                "description": str(finding.get("description", "") or ""),
                "match": str(finding.get("match", "") or ""),
                "snippet": str(finding.get("snippet", "") or ""),
                "llm_reason": str(finding.get("llm_reason", "") or ""),
                "remediation": str(finding.get("remediation", "") or ""),
                "llm_secure_example": str(finding.get("llm_secure_example", "") or ""),
                "llm_verdict": str(finding.get("llm_verdict", "") or ""),
                "llm_reviewed": bool(finding.get("llm_reviewed", False)),
                "policy_status": str(finding.get("policy_status", "") or ""),
                "context": str(finding.get("context", "production") or "production"),
                "first_seen_at": started_at,
                "last_seen_at": started_at,
                "first_seen_scan_id": scan_id,
                "last_seen_scan_id": scan_id,
                "scan_count": 0,
                "status": "open",
                "status_label": "Open",
                "triage_note": "",
                "triage_by": "",
                "triage_at": "",
                "suppression_hits": 0,
            })
            row["scan_count"] += 1
            if started_ts < _safe_dt(row.get("first_seen_at", "")):
                row["first_seen_at"] = started_at
                row["first_seen_scan_id"] = scan_id
            if started_ts >= _safe_dt(row.get("last_seen_at", "")):
                row["last_seen_at"] = started_at
                row["last_seen_scan_id"] = scan_id
                row["severity"] = int(finding.get("severity", row["severity"]) or row["severity"])
                row["severity_label"] = _severity_label(
                    finding.get("severity", row["severity"]),
                    str(finding.get("severity_label", row.get("severity_label", "")) or row.get("severity_label", "")),
                )
                row["capability"] = str(finding.get("capability", row.get("capability", "")) or row.get("capability", ""))
                row["rule_label"] = format_rule_label(
                    str(finding.get("provider_or_lib", row.get("rule", "")) or row.get("rule", "")),
                    str(finding.get("capability", row.get("capability", "")) or row.get("capability", "")),
                )
                row["ai_category"] = str(finding.get("ai_category", row.get("ai_category", "")) or row.get("ai_category", ""))
                row["description"] = str(finding.get("description", row["description"]) or row["description"])
                row["match"] = str(finding.get("match", row.get("match", "")) or row.get("match", ""))
                row["snippet"] = str(finding.get("snippet", row.get("snippet", "")) or row.get("snippet", ""))
                row["llm_reason"] = str(finding.get("llm_reason", row.get("llm_reason", "")) or row.get("llm_reason", ""))
                row["remediation"] = str(finding.get("remediation", row.get("remediation", "")) or row.get("remediation", ""))
                row["llm_secure_example"] = str(finding.get("llm_secure_example", row.get("llm_secure_example", "")) or row.get("llm_secure_example", ""))
                row["llm_verdict"] = str(finding.get("llm_verdict", row.get("llm_verdict", "")) or row.get("llm_verdict", ""))
                row["llm_reviewed"] = bool(finding.get("llm_reviewed", row.get("llm_reviewed", False)))
                row["policy_status"] = str(finding.get("policy_status", row["policy_status"]) or row["policy_status"])
                row["file"] = str(finding.get("file", row["file"]) or row["file"])
                row["line"] = str(finding.get("line", row["line"]) or row["line"])
            if str(finding.get("triage_status", "") or "") == TRIAGE_FALSE_POSITIVE:
                row["suppression_hits"] += 1

    for hash_, row in rollups.items():
        triage_meta = dict(triage.get(hash_, {}) or {})
        fixed_at = fixed_marks.get(hash_, (0, ""))
        last_seen_ts = _safe_dt(str(row.get("last_seen_at", "") or ""))
        status = "open"
        if triage_meta.get("status"):
            status = str(triage_meta.get("status"))
            row["triage_note"] = str(triage_meta.get("note", "") or "")
            row["triage_by"] = str(triage_meta.get("marked_by", "") or "")
            row["triage_at"] = str(triage_meta.get("marked_at", "") or "")
        elif fixed_at[0] and fixed_at[0] >= last_seen_ts[0]:
            status = "fixed"
        row["status"] = status
        row["status_label"] = _status_label(status)

    return sorted(
        rollups.values(),
        key=lambda item: (
            item.get("status") == "fixed",
            int(item.get("severity", 4) or 4),
            -int(item.get("scan_count", 0) or 0),
            str(item.get("repo", "")),
            str(item.get("file", "")),
        ),
    )


def findings_filter_options(findings: list[dict]) -> dict[str, list[str]]:
    return {
        "projects": sorted({str(item.get("project_key", "")) for item in findings if item.get("project_key")}),
        "repos": sorted({str(item.get("repo", "")) for item in findings if item.get("repo")}),
        "rules": sorted({str(item.get("rule_label", "")) for item in findings if item.get("rule_label")}),
        "statuses": sorted({_status_label(str(item.get("status", "open"))) for item in findings}),
        "severities": sorted({str(item.get("severity_label", "")) for item in findings if item.get("severity_label")}),
    }


def findings_summary(findings: list[dict]) -> dict[str, int]:
    counts = Counter(str(item.get("status", "open")) for item in findings)
    return {
        "total": len(findings),
        "open": counts.get("open", 0),
        "reviewed": counts.get(TRIAGE_REVIEWED, 0),
        "accepted_risk": counts.get(TRIAGE_ACCEPTED_RISK, 0),
        "suppressed": counts.get(TRIAGE_FALSE_POSITIVE, 0),
        "fixed": counts.get("fixed", 0),
    }


def findings_history_notice(history: list[dict]) -> str:
    total_scans = 0
    detailed_scans = 0
    omitted_findings = 0
    for record in history:
        total = int(record.get("total", 0) or 0)
        findings = list(record.get("findings") or [])
        if total <= 0 and not findings:
            continue
        total_scans += 1
        if findings:
            detailed_scans += 1
        else:
            omitted_findings += total
    if total_scans and detailed_scans < total_scans:
        return (
            f"Detailed findings are available for {detailed_scans} of {total_scans} scans. "
            f"Older scans only stored summary counts, so up to {omitted_findings} findings cannot be listed here."
        )
    return ""
