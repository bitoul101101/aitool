from __future__ import annotations

import re
import time
from datetime import datetime

from dateutil import tz


ISRAEL_TZ = tz.gettz("Asia/Jerusalem")


def _entry_ts(entry: dict | None, fallback: float) -> float:
    if not entry:
        return float(fallback)
    value = entry.get("ts")
    if value is None:
        return float(fallback)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(fallback)


def format_log_entry(entry: dict) -> str:
    ts = entry.get("ts")
    try:
        stamp = (
            datetime.fromtimestamp(float(ts), ISRAEL_TZ).strftime("%H:%M:%S")
            if ISRAEL_TZ
            else datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
        )
    except Exception:
        stamp = "--:--:--"
    msg = str(entry.get("msg", "")).strip()
    if not msg:
        return ""
    return f"[{stamp}] {msg}"


def format_log_text(entries: list[dict]) -> str:
    return "\n".join(text for text in (format_log_entry(entry) for entry in entries) if text)


def parse_log_text_entries(log_text: str) -> list[dict]:
    entries: list[dict] = []
    if not log_text:
        return entries
    time_re = re.compile(r"^\[(\d{2}):(\d{2}):(\d{2})\]\s*(.*)$")
    day_offset = 0
    previous_ts: float | None = None
    for raw_line in str(log_text).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = time_re.match(line)
        if not match:
            entries.append({"ts": previous_ts or 0.0, "msg": line})
            continue
        hours, minutes, seconds = (int(match.group(i)) for i in range(1, 4))
        message = match.group(4).strip()
        seconds_of_day = hours * 3600 + minutes * 60 + seconds
        ts = float(seconds_of_day + day_offset)
        if previous_ts is not None and ts < previous_ts:
            day_offset += 86400
            ts = float(seconds_of_day + day_offset)
        previous_ts = ts
        entries.append({"ts": ts, "msg": message})
    return entries


def phase_timeline(entries: list[dict], state: str = "") -> list[dict]:
    if not entries:
        return []
    state = (state or "").lower()
    first_ts = _entry_ts(entries[0], time.time())
    markers = {
        "init": first_ts,
        "clone": None,
        "scan": None,
        "llm review": None,
        "report": None,
        "end": _entry_ts(entries[-1], first_ts),
    }
    for entry in entries:
        msg = str(entry.get("msg", ""))
        ts = _entry_ts(entry, first_ts)
        if markers["clone"] is None and "branch:" in msg:
            markers["clone"] = ts
        if markers["scan"] is None and "Starting parallel scan" in msg:
            markers["scan"] = ts
        if markers["llm review"] is None and "[LLM]" in msg and ("Evaluating" in msg or "Reviewing" in msg):
            markers["llm review"] = ts
        if markers["report"] is None and "Generating reports" in msg:
            markers["report"] = ts
        if "Scan complete." in msg or "Scan stopped." in msg:
            markers["end"] = ts
    points = [
        ("init", markers["init"], markers["clone"] or markers["scan"] or markers["end"]),
        ("clone", markers["clone"], markers["scan"] or markers["llm review"] or markers["report"] or markers["end"]),
        ("scan", markers["scan"], markers["llm review"] or markers["report"] or markers["end"]),
        ("llm review", markers["llm review"], markers["report"] or markers["end"]),
        ("report", markers["report"], markers["end"]),
    ]
    timeline = []
    phase_seconds: list[tuple[str, int]] = []
    active_name = ""
    started_names = [name for name, start, _ in points if start is not None]
    if state == "running" and started_names:
        active_name = started_names[-1]
    for name, start, end in points:
        if start is None:
            timeline.append({"name": name, "duration": "—", "state": "pending"})
            continue
        seconds = max(int((end or start) - start), 0)
        phase_seconds.append((name, seconds))
        phase_state = "done"
        if state in ("stopped", "error") and name == active_name:
            phase_state = "stopped"
        elif state == "running" and name == active_name:
            phase_state = "running"
        timeline.append({"name": name, "duration": f"{seconds // 60:02d}:{seconds % 60:02d}", "state": phase_state})

    total_seconds = max(int(markers["end"] - first_ts), 0)
    phase_sum = sum(seconds for _, seconds in phase_seconds)
    residual = total_seconds - phase_sum
    if residual > 0 and phase_seconds:
        last_started_name = phase_seconds[-1][0]
        adjusted: list[dict] = []
        for row in timeline:
            if row.get("name") == last_started_name:
                current_duration = str(row.get("duration", "00:00"))
                minutes, seconds = current_duration.split(":")
                adjusted_seconds = (int(minutes) * 60) + int(seconds) + residual
                row = {
                    **row,
                    "duration": f"{adjusted_seconds // 60:02d}:{adjusted_seconds % 60:02d}",
                }
            adjusted.append(row)
        timeline = adjusted
        total_seconds = phase_sum + residual
    elif phase_sum > 0:
        total_seconds = phase_sum

    total_state = "running" if state == "running" else "stopped" if state in ("stopped", "error") else "done"
    timeline.append({"name": "total", "duration": f"{total_seconds // 60:02d}:{total_seconds % 60:02d}", "state": total_state})
    return timeline


def format_mmss(seconds: int) -> str:
    total = max(int(seconds or 0), 0)
    return f"{total // 60:02d}:{total % 60:02d}"


def format_seconds_compact(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    value = max(float(seconds or 0), 0.0)
    if value >= 60:
        return format_mmss(int(round(value)))
    if value >= 10:
        return f"{value:.1f}s"
    return f"{value:.2f}s"


def llm_stats(entries: list[dict], *, state: str = "", llm_model: str = "", llm_model_info: dict | None = None) -> dict:
    model_info = dict(llm_model_info or {})
    model_text = ""
    model_name = str(model_info.get("name", "") or llm_model or "").strip()
    model_parts = [model_name] if model_name else []
    for key in ("parameter_size", "quantization"):
        value = str(model_info.get(key, "") or "").strip()
        if value:
            model_parts.append(value)
    if model_parts:
        model_text = " | ".join(model_parts)

    reviewed = 0
    skipped = 0
    dismissed = 0
    downgraded = 0
    batch_markers: list[tuple[int, int, float]] = []
    llm_start: float | None = None
    llm_end: float | None = None
    failed_batches = 0

    reviewing_re = re.compile(r"\[LLM\]\s+Reviewing\s+(\d+)\s+finding\(s\).*?(?:\((\d+)\s+skipped)", re.IGNORECASE)
    batch_re = re.compile(r"\[LLM\]\s+Batch\s+(\d+)/(\d+)", re.IGNORECASE)
    done_re = re.compile(
        r"\[LLM\]\s+Done.*?dismissed:(\d+).*?reinstated:(\d+).*?downgraded:(\d+)",
        re.IGNORECASE,
    )

    for entry in entries:
        msg = str(entry.get("msg", "") or "").strip()
        if not msg:
            continue
        ts = float(entry.get("ts") or 0.0)
        if not model_text and msg.startswith("LLM      :"):
            model_text = msg.split(":", 1)[1].strip()
        if "[LLM]" in msg and llm_start is None and ("Evaluating" in msg or "Reviewing" in msg):
            llm_start = ts
        if "[LLM]" in msg:
            llm_end = ts
        match = reviewing_re.search(msg)
        if match:
            reviewed += int(match.group(1) or 0)
            skipped += int(match.group(2) or 0)
        match = batch_re.search(msg)
        if match:
            batch_markers.append((int(match.group(1) or 0), int(match.group(2) or 0), ts))
        match = done_re.search(msg)
        if match:
            dismissed = int(match.group(1) or 0)
            downgraded = int(match.group(3) or 0)
        if "[LLM] Batch" in msg and "failed" in msg.lower():
            failed_batches += 1

    elapsed_seconds = None
    if llm_start is not None:
        end_ts = llm_end if llm_end is not None else (float(entries[-1].get("ts") or llm_start) if entries else llm_start)
        elapsed_seconds = max(end_ts - llm_start, 0.0)

    batch_durations: list[float] = []
    for index, (_current, _total, ts) in enumerate(batch_markers):
        next_ts = batch_markers[index + 1][2] if index + 1 < len(batch_markers) else llm_end
        if next_ts is None:
            continue
        batch_durations.append(max(float(next_ts) - ts, 0.0))

    avg_batch = (sum(batch_durations) / len(batch_durations)) if batch_durations else None
    last_batch = batch_durations[-1] if batch_durations else None
    avg_per_finding = (elapsed_seconds / reviewed) if elapsed_seconds is not None and reviewed > 0 else None
    throughput = ((reviewed / elapsed_seconds) * 60.0) if elapsed_seconds and reviewed > 0 else None

    return {
        "model": model_text or model_name or "Unavailable",
        "elapsed": format_mmss(int(round(elapsed_seconds))) if elapsed_seconds is not None else "—",
        "phase_elapsed": format_mmss(int(round(elapsed_seconds))) if elapsed_seconds is not None else "—",
        "elapsed_seconds": elapsed_seconds,
        "last_batch": format_seconds_compact(last_batch),
        "avg_batch": format_seconds_compact(avg_batch),
        "avg_per_finding": format_seconds_compact(avg_per_finding),
        "throughput": (f"{throughput:.1f} findings/min" if throughput is not None else "—"),
        "failed_batches": str(failed_batches),
        "reviewed": reviewed,
        "skipped": skipped,
        "dismissed": dismissed,
        "downgraded": downgraded,
        "state": state,
    }
