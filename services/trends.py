from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from services.scan_runtime_views import llm_stats, parse_log_text_entries


def _record_datetime(record: dict) -> tuple[datetime | None, str]:
    raw = str(record.get("started_at_utc", "") or record.get("completed_at_utc", "") or "")
    if raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")), raw
        except ValueError:
            pass
    scan_id = str(record.get("scan_id", "") or "")
    if len(scan_id) >= 15 and "_" in scan_id:
        try:
            return datetime.strptime(scan_id, "%Y%m%d_%H%M%S"), scan_id
        except ValueError:
            pass
    return None, raw


def _repo_label(record: dict) -> str:
    repos = [str(item).strip() for item in list(record.get("repo_slugs", record.get("repos", [])) or []) if str(item).strip()]
    if repos:
        return ", ".join(repos)
    local_path = str(record.get("local_repo_path", "") or "").strip()
    if local_path:
        return Path(local_path).name or local_path
    return "Unknown"


def _risk_score(record: dict) -> int:
    sev = dict(record.get("sev") or {})
    critical = int(sev.get("critical", 0) or 0)
    high = int(sev.get("high", 0) or 0)
    medium = int(sev.get("medium", 0) or 0)
    low = int(sev.get("low", 0) or 0)
    critical_prod = int(record.get("critical_prod", 0) or 0)
    high_prod = int(record.get("high_prod", 0) or 0)
    return (critical * 10) + (high * 5) + (medium * 2) + low + (critical_prod * 4) + (high_prod * 2)


def _load_llm_metrics_from_log(record: dict) -> dict:
    log_file = str(record.get("log_file", "") or "").strip()
    if not log_file:
        return {}
    path = Path(log_file)
    if not path.exists() or not path.is_file():
        return {}
    try:
        log_text = path.read_text("utf-8")
    except OSError:
        return {}
    stats = llm_stats(
        parse_log_text_entries(log_text),
        state=str(record.get("state", "") or ""),
        llm_model=str(record.get("llm_model", "") or ""),
        llm_model_info=record.get("llm_model_info") or {},
    )
    try:
        failed_batches = int(stats.get("failed_batches", 0) or 0)
    except (TypeError, ValueError):
        failed_batches = 0
    return {
        "reviewed": int(stats.get("reviewed", 0) or 0),
        "skipped": int(stats.get("skipped", 0) or 0),
        "dismissed": int(stats.get("dismissed", 0) or 0),
        "downgraded": int(stats.get("downgraded", 0) or 0),
        "failed_batches": failed_batches,
        "failed_scan": failed_batches > 0,
    }


def compute_history_trends(records: list[dict]) -> dict:
    prepared: list[dict] = []
    for raw in records or []:
        record = dict(raw or {})
        dt, _ = _record_datetime(record)
        record["_dt"] = dt
        record["_repo_label"] = _repo_label(record)
        trend = dict(record.get("trend") or {})
        if not trend.get("llm") and record.get("llm_model"):
            log_metrics = _load_llm_metrics_from_log(record)
            if log_metrics:
                trend["llm"] = log_metrics
        record["trend"] = trend
        prepared.append(record)

    prepared.sort(key=lambda item: (item.get("_dt") or datetime.min, str(item.get("scan_id", ""))))
    recent = prepared[-12:]

    findings_over_time = []
    critical_over_time = []
    new_fixed_over_time = []

    repo_agg: dict[str, dict] = defaultdict(lambda: {
        "repo": "",
        "scans": 0,
        "risk_score": 0,
        "critical_prod": 0,
        "high_prod": 0,
        "last_seen": "",
        "_last_dt": None,
    })
    noisy_rules = Counter()
    suppressed_rules = Counter()
    llm_model_agg: dict[str, dict] = defaultdict(lambda: {
        "model": "",
        "scans": 0,
        "failed_scans": 0,
        "failed_batches": 0,
        "reviewed": 0,
        "skipped": 0,
        "dismissed": 0,
        "downgraded": 0,
    })

    for record in prepared:
        repo_label = record["_repo_label"]
        agg = repo_agg[repo_label]
        agg["repo"] = repo_label
        agg["scans"] += 1
        record_dt = record.get("_dt")
        last_dt = agg.get("_last_dt")
        if last_dt is None or (isinstance(record_dt, datetime) and record_dt >= last_dt):
            agg["risk_score"] = _risk_score(record)
            agg["critical_prod"] = int(record.get("critical_prod", 0) or 0)
            agg["high_prod"] = int(record.get("high_prod", 0) or 0)
            agg["last_seen"] = str(record.get("completed_at_utc", "") or record.get("started_at_utc", "") or "")
            agg["_last_dt"] = record_dt

        rules = dict((record.get("trend") or {}).get("rules") or {})
        for rule, count in dict(rules.get("active") or {}).items():
            noisy_rules[str(rule)] += int(count or 0)
        for rule, count in dict(rules.get("suppressed") or {}).items():
            suppressed_rules[str(rule)] += int(count or 0)
            noisy_rules[str(rule)] += int(count or 0)

        model = str(record.get("llm_model", "") or "Unavailable").strip() or "Unavailable"
        llm_metrics = dict((record.get("trend") or {}).get("llm") or {})
        model_agg = llm_model_agg[model]
        model_agg["model"] = model
        model_agg["scans"] += 1
        model_agg["failed_batches"] += int(llm_metrics.get("failed_batches", 0) or 0)
        model_agg["reviewed"] += int(llm_metrics.get("reviewed", 0) or 0)
        model_agg["skipped"] += int(llm_metrics.get("skipped", 0) or 0)
        model_agg["dismissed"] += int(llm_metrics.get("dismissed", 0) or 0)
        model_agg["downgraded"] += int(llm_metrics.get("downgraded", 0) or 0)
        if llm_metrics.get("failed_scan"):
            model_agg["failed_scans"] += 1

    for record in recent:
        dt = record.get("_dt")
        stamp = dt.strftime("%d/%m") if isinstance(dt, datetime) else str(record.get("scan_id", "") or "")[:8]
        repo_label = record["_repo_label"]
        total = int(record.get("total", record.get("active_total", 0)) or 0)
        critical_prod = int(record.get("critical_prod", 0) or 0)
        high_prod = int(record.get("high_prod", 0) or 0)
        delta = dict(record.get("delta") or {})
        new_count = int(delta.get("new_count", 0) or 0)
        fixed_count = int(delta.get("fixed_count", 0) or 0)
        findings_over_time.append({
            "label": stamp,
            "repo": repo_label,
            "value": total,
            "state": str(record.get("state", "") or ""),
        })
        critical_over_time.append({
            "label": stamp,
            "repo": repo_label,
            "value": critical_prod,
            "high_prod": high_prod,
        })
        new_fixed_over_time.append({
            "label": stamp,
            "repo": repo_label,
            "new_count": new_count,
            "fixed_count": fixed_count,
        })

    top_repos = sorted(repo_agg.values(), key=lambda item: (-int(item["risk_score"]), -int(item["critical_prod"]), item["repo"]))[:8]
    for item in top_repos:
        item.pop("_last_dt", None)
    top_noisy_rules = [
        {
            "rule": rule,
            "hits": int(hits),
            "suppressed": int(suppressed_rules.get(rule, 0) or 0),
        }
        for rule, hits in noisy_rules.most_common(8)
    ]

    suppression_rate_by_rule = []
    for rule, suppressed in suppressed_rules.items():
        total_hits = int(noisy_rules.get(rule, 0) or 0)
        if total_hits <= 0:
            continue
        suppression_rate_by_rule.append({
            "rule": rule,
            "suppressed": int(suppressed or 0),
            "total": total_hits,
            "rate_pct": round((int(suppressed or 0) / total_hits) * 100),
        })
    suppression_rate_by_rule.sort(key=lambda item: (-item["rate_pct"], -item["suppressed"], item["rule"]))
    suppression_rate_by_rule = suppression_rate_by_rule[:8]

    llm_review_failure_rate_by_model = []
    for item in llm_model_agg.values():
        scans = int(item["scans"] or 0)
        failed_scans = int(item["failed_scans"] or 0)
        llm_review_failure_rate_by_model.append({
            **item,
            "failure_rate_pct": round((failed_scans / scans) * 100) if scans else 0,
        })
    llm_review_failure_rate_by_model.sort(key=lambda item: (-item["failure_rate_pct"], -item["failed_batches"], item["model"]))

    summary = {
        "scan_count": len(prepared),
        "total_findings": sum(int(rec.get("total", rec.get("active_total", 0)) or 0) for rec in prepared),
        "critical_prod_total": sum(int(rec.get("critical_prod", 0) or 0) for rec in prepared),
        "models_used": len({str(rec.get("llm_model", "") or "").strip() for rec in prepared if str(rec.get("llm_model", "") or "").strip()}),
    }

    return {
        "summary": summary,
        "findings_over_time": findings_over_time,
        "critical_over_time": critical_over_time,
        "new_fixed_over_time": new_fixed_over_time,
        "top_repos_by_risk": top_repos,
        "top_noisy_rules": top_noisy_rules,
        "suppression_rate_by_rule": suppression_rate_by_rule,
        "llm_review_failure_rate_by_model": llm_review_failure_rate_by_model,
    }
