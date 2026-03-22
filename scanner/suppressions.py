"""
Finding triage store.

The original implementation only supported false-positive suppressions.
This module now supports general triage records while keeping the legacy
suppression helpers intact for compatibility.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Set

_VERSION = 3
_DEFAULT_FILE = "ai_scanner_suppressions.json"

TRIAGE_SENT_FOR_REVIEW = "sent_for_review"
TRIAGE_IN_REMEDIATION = "in_remediation"
TRIAGE_FALSE_POSITIVE = "false_positive"
TRIAGE_REVIEWED = "reviewed"
TRIAGE_ACCEPTED_RISK = "accepted_risk"
TRIAGE_STATUSES = {
    TRIAGE_SENT_FOR_REVIEW,
    TRIAGE_IN_REMEDIATION,
    TRIAGE_FALSE_POSITIVE,
    TRIAGE_REVIEWED,
    TRIAGE_ACCEPTED_RISK,
}


def normalize_triage_status(status: str) -> str:
    value = str(status or "").strip().lower()
    if value == TRIAGE_REVIEWED:
        return TRIAGE_IN_REMEDIATION
    return value


def _read(path: Path) -> dict:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                if "triage" in data and isinstance(data["triage"], list):
                    return data
                if "suppressions" in data and isinstance(data["suppressions"], list):
                    return {
                        "version": _VERSION,
                        "triage": [
                            {
                                "hash": rec.get("hash", ""),
                                "file": rec.get("file", ""),
                                "capability": rec.get("capability", ""),
                                "repo": rec.get("repo", ""),
                                "status": TRIAGE_FALSE_POSITIVE,
                                "note": rec.get("reason", ""),
                                "marked_by": rec.get("marked_by", ""),
                                "marked_at": rec.get("marked_at", ""),
                            }
                            for rec in data["suppressions"]
                            if rec.get("hash")
                        ],
                    }
        except (json.JSONDecodeError, OSError):
            pass
    return {"version": _VERSION, "triage": []}


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_suppressions(path: str | Path) -> Set[str]:
    """Return the set of suppressed finding hashes from *path*."""
    data = _read(Path(path))
    return {
        rec["hash"]
        for rec in data["triage"]
        if rec.get("hash") and rec.get("status") == TRIAGE_FALSE_POSITIVE
    }


def list_triage(path: str | Path) -> List[Dict[str, Any]]:
    """Return the stored triage records."""
    data = _read(Path(path))
    records: list[dict[str, Any]] = []
    for rec in list(data["triage"]):
        updated = dict(rec)
        updated["status"] = normalize_triage_status(str(rec.get("status", "") or ""))
        records.append(updated)
    return records


def triage_by_hash(path: str | Path) -> Dict[str, Dict[str, Any]]:
    return {
        rec["hash"]: rec
        for rec in list_triage(path)
        if rec.get("hash")
    }


def list_suppressions(path: str | Path) -> List[Dict[str, Any]]:
    """Return stored false-positive records in the legacy shape."""
    return [
        {
            "hash": rec.get("hash", ""),
            "file": rec.get("file", ""),
            "capability": rec.get("capability", ""),
            "repo": rec.get("repo", ""),
            "reason": rec.get("note", ""),
            "marked_by": rec.get("marked_by", ""),
            "marked_at": rec.get("marked_at", ""),
        }
        for rec in list_triage(path)
        if rec.get("status") == TRIAGE_FALSE_POSITIVE
    ]


def upsert_triage(
    path: str | Path,
    finding: Dict[str, Any],
    *,
    status: str,
    note: str = "",
    marked_by: str = "",
) -> None:
    """Create or update a triage record for *finding*."""
    status = normalize_triage_status(status)
    if status not in TRIAGE_STATUSES:
        raise ValueError(f"Unsupported triage status: {status}")

    path = Path(path)
    data = _read(path)
    h = finding.get("_hash", "") or finding.get("hash", "")
    if not h:
        return

    record = {
        "hash": h,
        "file": finding.get("file", ""),
        "capability": finding.get("capability", ""),
        "repo": finding.get("repo", ""),
        "status": status,
        "note": note,
        "marked_by": marked_by,
        "marked_at": date.today().isoformat(),
    }

    triage = data["triage"]
    for idx, existing in enumerate(triage):
        if existing.get("hash") == h:
            triage[idx] = record
            _write(path, data)
            return
    triage.append(record)
    _write(path, data)


def remove_triage(path: str | Path, hash_: str) -> bool:
    """Remove a triage record by hash. Returns True if it existed."""
    path = Path(path)
    data = _read(path)
    before = len(data["triage"])
    data["triage"] = [rec for rec in data["triage"] if rec.get("hash") != hash_]
    if len(data["triage"]) < before:
        _write(path, data)
        return True
    return False


def add_suppression(
    path: str | Path,
    finding: Dict[str, Any],
    reason: str = "",
    marked_by: str = "",
) -> None:
    """Record *finding* as a false positive."""
    upsert_triage(
        path,
        finding,
        status=TRIAGE_FALSE_POSITIVE,
        note=reason,
        marked_by=marked_by,
    )


def remove_suppression(path: str | Path, hash_: str) -> bool:
    """Remove a suppression by hash. Returns True if it existed."""
    return remove_triage(path, hash_)


def suppression_count(path: str | Path) -> int:
    return len(load_suppressions(path))


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
