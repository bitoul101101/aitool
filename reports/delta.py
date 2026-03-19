"""
Delta reporter (Enhancement J).

Compares the current scan findings against a persisted baseline CSV
and produces three buckets:
  - new       findings not in baseline (hash not seen before)
  - fixed     findings in baseline but absent from current scan
  - unchanged findings present in both

The baseline is the most recent CSV in OUTPUT_DIR that matches the
same project+repo combination. Hash is the _hash / finding ID field.
"""

import csv
from pathlib import Path
from typing import List, Dict, Any, Tuple


BASELINE_ID_FIELD = "finding_id"   # column name in CSV
BASELINE_DETAIL_FIELDS = (
    "finding_id",
    "delta_status",
    "repo",
    "provider_or_lib",
    "capability",
    "policy_status",
    "severity",
    "file",
    "line",
    "snippet",
    "owner",
    "last_seen",
    "remediation",
)


def _load_baseline_rows(csv_path: Path) -> dict[str, dict]:
    """Return baseline finding rows keyed by stable finding ID."""
    rows: dict[str, dict] = {}
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                h = row.get(BASELINE_ID_FIELD, "").strip()
                if h:
                    rows[h] = {field: (row.get(field, "") or "").strip() for field in BASELINE_DETAIL_FIELDS}
    except Exception as e:
        import sys
        print(f"[WARN] delta: could not read baseline {csv_path}: {e}", file=sys.stderr)
    return rows


def find_baseline(output_dir: str, project_key: str, repo: str) -> Path | None:
    """
    Find the most recent CSV baseline for this project+repo combination.
    Pattern: AI_Scan_Report_<PROJECT>_<REPO>_<date>_<time>.csv
    """
    base = Path(output_dir)
    if not base.exists():
        return None
    prefix = f"AI_Scan_Report_{project_key}_{repo}_"
    candidates = sorted(
        [f for f in base.glob(f"{prefix}*.csv")],
        key=lambda p: p.stem,
        reverse=True,   # most recent first (lexicographic on YYYYMMDD_HHMMSS)
    )
    return candidates[0] if candidates else None


def compute_delta(
    current_findings: List[Dict[str, Any]],
    baseline_rows: Dict[str, Dict[str, str]],
) -> Tuple[List[Dict], List[Dict[str, str]], List[Dict]]:
    """
    Returns (new_findings, fixed_findings, unchanged_findings).
    """
    baseline_hashes = set(baseline_rows.keys())
    current_hashes = {f.get("_hash", f.get("finding_id", "")): f
                      for f in current_findings}

    new_findings   = [f for h, f in current_hashes.items() if h not in baseline_hashes]
    unchanged      = [f for h, f in current_hashes.items() if h in baseline_hashes]
    fixed_findings = [baseline_rows[h] for h in sorted(baseline_hashes - set(current_hashes.keys()))]

    return new_findings, fixed_findings, unchanged


def build_delta_meta(
    current_findings: List[Dict[str, Any]],
    output_dir: str,
    project_key: str,
    repo: str,
    scanned_files: set[str] | None = None,
) -> Dict[str, Any]:
    """
    Full pipeline: find baseline → compute delta → return meta dict
    that is passed into HTMLReporter.
    """
    baseline_path = find_baseline(output_dir, project_key, repo)
    if not baseline_path:
        return {
            "has_baseline":  False,
            "new_count":     len(current_findings),
            "fixed_count":   0,
            "unchanged_count": 0,
            "existing_count": 0,
            "new_hashes":    {f.get("_hash","") for f in current_findings},
            "fixed_hashes":  set(),
            "fixed_findings": [],
        }

    baseline_rows = _load_baseline_rows(baseline_path)
    scoped_files = {
        str(Path(path)).replace("\\", "/").lstrip("./")
        for path in (scanned_files or set())
        if str(path).strip()
    }
    if scoped_files:
        baseline_rows = {
            finding_id: row
            for finding_id, row in baseline_rows.items()
            if str(Path(row.get("file", ""))).replace("\\", "/").lstrip("./") in scoped_files
        }
    new_findings, fixed_findings, unchanged = compute_delta(
        current_findings, baseline_rows
    )
    new_hashes = {f.get("_hash", "") for f in new_findings}
    fixed_hashes = {row.get("finding_id", "") for row in fixed_findings if row.get("finding_id")}

    return {
        "has_baseline":    True,
        "baseline_file":   baseline_path.name,
        "new_count":       len(new_findings),
        "fixed_count":     len(fixed_findings),
        "unchanged_count": len(unchanged),
        "existing_count":  len(unchanged),
        "new_hashes":      new_hashes,
        "fixed_hashes":    fixed_hashes,
        "fixed_findings":  fixed_findings,
        "scope_limited":   bool(scoped_files),
        "scope_file_count": len(scoped_files),
    }
