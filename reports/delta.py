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


def _load_baseline_hashes(csv_path: Path) -> set:
    """Return the set of finding hashes stored in a baseline CSV."""
    hashes = set()
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                h = row.get(BASELINE_ID_FIELD, "").strip()
                if h:
                    hashes.add(h)
    except Exception as e:
        import sys
        print(f"[WARN] delta: could not read baseline {csv_path}: {e}", file=sys.stderr)
    return hashes


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
    baseline_hashes: set,
) -> Tuple[List[Dict], List[str], List[Dict]]:
    """
    Returns (new_findings, fixed_hashes, unchanged_findings).
    """
    current_hashes = {f.get("_hash", f.get("finding_id", "")): f
                      for f in current_findings}

    new_findings   = [f for h, f in current_hashes.items() if h not in baseline_hashes]
    unchanged      = [f for h, f in current_hashes.items() if h in baseline_hashes]
    fixed_hashes   = list(baseline_hashes - set(current_hashes.keys()))

    return new_findings, fixed_hashes, unchanged


def build_delta_meta(
    current_findings: List[Dict[str, Any]],
    output_dir: str,
    project_key: str,
    repo: str,
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
            "new_hashes":    {f.get("_hash","") for f in current_findings},
            "fixed_hashes":  set(),
        }

    baseline_hashes = _load_baseline_hashes(baseline_path)
    new_findings, fixed_hashes, unchanged = compute_delta(
        current_findings, baseline_hashes
    )
    new_hashes = {f.get("_hash", "") for f in new_findings}

    return {
        "has_baseline":    True,
        "baseline_file":   baseline_path.name,
        "new_count":       len(new_findings),
        "fixed_count":     len(fixed_hashes),
        "unchanged_count": len(unchanged),
        "new_hashes":      new_hashes,
        "fixed_hashes":    set(fixed_hashes),
    }
