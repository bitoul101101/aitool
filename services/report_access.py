from __future__ import annotations

from pathlib import Path

from services.access_control import UserContext


def history_records_for_context(history: list[dict], ctx: UserContext) -> list[dict]:
    return [
        record for record in history
        if ctx.can_access_project(str(record.get("project_key", "")))
    ]


def find_history_record_by_scan_id(history: list[dict], scan_id: str) -> dict | None:
    for record in history:
        if record.get("scan_id") == scan_id:
            return record
    return None


def find_history_record_by_report_name(history: list[dict], filename: str) -> dict | None:
    safe = Path(filename).name
    for record in history:
        reports = (record.get("reports") or {}).get("__all__", {})
        for key in ("html", "csv", "html_name", "csv_name"):
            value = str(reports.get(key, "") or "")
            if value and Path(value).name == safe:
                return record
    return None
