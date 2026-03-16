"""
False-Positive Suppression Store
─────────────────────────────────
Manages a JSON file that records findings marked as false positives by
analysts.  The file can be committed to source control so suppressions
are shared across the team and survive re-scans.

File format (ai_scanner_suppressions.json):
{
  "version": 1,
  "suppressions": [
    {
      "hash":       "a3f9c12d...",          # content-stable _hash from _make_finding
      "file":       "docs/how-to/auth.md",  # informational only
      "capability": "Secret in Container Config",
      "repo":       "kubeai",
      "reason":     "Documentation example — not a real credential",
      "marked_by":  "analyst",              # free text, optional
      "marked_at":  "2026-03-11"            # ISO date
    },
    ...
  ]
}

Public API
──────────
load_suppressions(path)  → set[str]          hashes to suppress
add_suppression(path, finding, reason, marked_by) → None
remove_suppression(path, hash_)  → bool      True if found and removed
suppression_count(path)  → int
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Dict, Any, Set

_VERSION = 1
_DEFAULT_FILE = "ai_scanner_suppressions.json"


def _read(path: Path) -> dict:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "suppressions" in data:
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return {"version": _VERSION, "suppressions": []}


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_suppressions(path: str | Path) -> Set[str]:
    """Return the set of suppressed finding hashes from *path*."""
    data = _read(Path(path))
    return {s["hash"] for s in data["suppressions"] if s.get("hash")}


def add_suppression(
    path: str | Path,
    finding: Dict[str, Any],
    reason: str = "",
    marked_by: str = "",
) -> None:
    """
    Record *finding* as a false positive.
    Safe to call multiple times — duplicates are ignored.
    """
    path = Path(path)
    data = _read(path)
    existing = {s["hash"] for s in data["suppressions"]}
    h = finding.get("_hash", "")
    if not h or h in existing:
        return
    data["suppressions"].append({
        "hash":       h,
        "file":       finding.get("file", ""),
        "capability": finding.get("capability", ""),
        "repo":       finding.get("repo", ""),
        "reason":     reason,
        "marked_by":  marked_by,
        "marked_at":  date.today().isoformat(),
    })
    _write(path, data)


def remove_suppression(path: str | Path, hash_: str) -> bool:
    """Remove a suppression by hash.  Returns True if it existed."""
    path = Path(path)
    data = _read(path)
    before = len(data["suppressions"])
    data["suppressions"] = [
        s for s in data["suppressions"] if s.get("hash") != hash_
    ]
    if len(data["suppressions"]) < before:
        _write(path, data)
        return True
    return False


def suppression_count(path: str | Path) -> int:
    return len(_read(Path(path))["suppressions"])


def apply_suppressions(
    findings: list,
    suppressed_hashes: Set[str],
    verbose: bool = False,
) -> tuple[list, list]:
    """
    Split *findings* into (active, suppressed) lists.

    Returns
    -------
    active      : findings NOT in suppressed_hashes
    suppressed  : findings that were filtered out
    """
    active, suppressed = [], []
    for f in findings:
        if f.get("_hash", "") in suppressed_hashes:
            suppressed.append(f)
        else:
            active.append(f)
    if verbose and suppressed:
        print(f"  [FP] Suppressed {len(suppressed)} false-positive finding(s)")
    return active, suppressed