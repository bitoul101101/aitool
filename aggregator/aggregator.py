"""
Aggregator: deduplicates findings across repos and produces
the final finding schema for reports.
"""

from typing import List, Dict, Any
from collections import defaultdict


FINAL_COLUMNS = [
    "repo", "ai_category", "provider_or_lib",
    "capability", "policy_status", "risk", "severity",
    "file", "line", "snippet", "owner", "last_seen", "remediation",
    # extras kept for HTML report
    "description", "severity_label", "is_notebook", "match",
    "confidence", "context", "corroboration_count", "finding_id",
]


class Aggregator:

    def __init__(self, owner_map: dict = None, min_severity: int = 4):
        self.owner_map    = owner_map or {}
        self.min_severity = min_severity

    def process(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate globally, filter by severity, normalize columns."""
        seen    = set()
        deduped = []
        for f in findings:
            h = f.get("_hash", "")
            if h and h not in seen:
                seen.add(h)
                deduped.append(f)
            elif not h:
                deduped.append(f)

        filtered   = [f for f in deduped if f.get("severity", 4) <= self.min_severity]
        normalized = [self._normalize(f) for f in filtered]
        normalized.sort(key=lambda x: (x["severity"], x["repo"]))
        return normalized

    def _normalize(self, f: Dict) -> Dict:
        repo       = f.get("repo", "unknown")
        owner_info = self.owner_map.get(repo, {})
        return {
            "repo":                repo,
            "ai_category":         f.get("category", ""),
            "provider_or_lib":     f.get("provider_or_lib", ""),
            "capability":          f.get("capability", ""),
            "policy_status":       f.get("policy_status", "REVIEW"),
            "risk":                f.get("risk", "Low"),
            "severity":            f.get("severity", 4),
            "file":                f.get("file", ""),
            "line":                f.get("line", 0),
            "snippet":             f.get("snippet", ""),
            "owner":               f.get("owner") or owner_info.get("owner", "Unknown"),
            "last_seen":           f.get("last_seen", ""),
            "remediation":         f.get("remediation", ""),
            "description":         f.get("description", ""),
            "severity_label":      f.get("severity_label", f"Sev-{f.get('severity',4)}"),
            "is_notebook":         f.get("is_notebook", False),
            "match":               f.get("match", ""),
            "confidence":          f.get("confidence", 50),
            "context":             f.get("context", "production"),
            "corroboration_count": f.get("corroboration_count", 1),
            "finding_id":          f.get("_hash", ""),
            "llm_verdict":         f.get("llm_verdict", ""),
            "llm_reason":          f.get("llm_reason", ""),
            "llm_reviewed":        f.get("llm_reviewed", False),
            "_hash":               f.get("_hash", ""),
            "project_key":         f.get("project_key", ""),
        }

    def summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_cat    = defaultdict(int)
        by_sev    = defaultdict(int)
        by_policy = defaultdict(int)
        by_repo   = defaultdict(int)

        for f in findings:
            by_cat[f["ai_category"]]      += 1
            by_sev[f["severity"]]          += 1
            by_policy[f["policy_status"]] += 1
            by_repo[f["repo"]]             += 1

        return {
            "total":            len(findings),
            "by_category":      dict(by_cat),
            "by_severity":      {f"Sev-{k}": v for k, v in sorted(by_sev.items())},
            "by_policy_status": dict(by_policy),
            "by_repo":          dict(by_repo),
            "critical_count":   by_sev.get(1, 0),
            "high_count":       by_sev.get(2, 0),
            "repos_scanned":    len(by_repo),
        }
