from __future__ import annotations

from datetime import datetime
from html import escape
from urllib.parse import quote
from dateutil import tz


ISRAEL_TZ = tz.gettz("Asia/Jerusalem")


def _esc(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _fmt_dt(value: str) -> tuple[str, str, int]:
    if not value:
        return "-", "", 0
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo and ISRAEL_TZ:
            dt = dt.astimezone(ISRAEL_TZ)
        return dt.strftime("%d/%m/%y"), dt.strftime("%H:%M:%S"), int(dt.timestamp())
    except Exception:
        return value, "", 0


def _fmt_duration(seconds: object) -> str:
    try:
        total = int(seconds or 0)
    except Exception:
        total = 0
    minutes, secs = divmod(max(total, 0), 60)
    return f"{minutes:02d}:{secs:02d}"


def _fmt_phase_summary(phase_metrics: dict | None) -> str:
    metrics = dict(phase_metrics or {})
    order = [("init", "I"), ("clone", "C"), ("scan", "S"), ("llm review", "L"), ("report", "R")]
    parts = []
    for key, label in order:
        if key in metrics:
            parts.append(f"{label} {_fmt_duration(metrics.get(key, 0))}")
    return " · ".join(parts) or "—"


def _fmt_triage_time(value: str) -> str:
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo and ISRAEL_TZ:
            dt = dt.astimezone(ISRAEL_TZ)
        return dt.strftime("%d/%m/%y %H:%M")
    except Exception:
        return str(value)


def _icon_uri(label: str, color: str) -> str:
    svg = f"""
<svg xmlns='http://www.w3.org/2000/svg' width='54' height='54' viewBox='0 0 54 54'>
  <rect x='8' y='4' width='30' height='34' rx='3' fill='#eceff1'/>
  <polygon points='38,4 48,14 48,38 38,38' fill='#d2d9de'/>
  <rect x='6' y='31' width='42' height='17' rx='5' fill='{color}'/>
  <text x='27' y='43' text-anchor='middle' font-family='Segoe UI,Arial,sans-serif' font-size='13' fill='white'>{label}</text>
</svg>""".strip()
    return "data:image/svg+xml;utf8," + quote(svg)


HTML_ICON = _icon_uri("HTML", "#21b35b")
CSV_ICON = _icon_uri("CSV", "#21b35b")
LOG_ICON = _icon_uri("LOG", "#1f4f98")
DETAILS_ICON = _icon_uri("SCAN", "#6d3514")


def _flash(notice: str = "", error: str = "") -> str:
    items = []
    if notice:
        items.append(f'<div class="notice toast">{_esc(notice)}</div>')
    if error:
        items.append(f'<div class="error toast">{_esc(error)}</div>')
    return f'<div class="toast-wrap">{"".join(items)}</div>' if items else ""


def _csrf_field(csrf_token: str = "") -> str:
    return f'<input type="hidden" name="csrf_token" value="{_esc(csrf_token)}">' if csrf_token else ""


def _scan_workspace_tabs(scan_id: str, active_tab: str = "activity", *, results_enabled: bool = True) -> str:
    safe_scan_id = _esc(scan_id)
    results_link = (
        f'<a class="{"active" if active_tab == "results" else ""}" href="/scan/{safe_scan_id}?tab=results">Results</a>'
        if results_enabled
        else '<a class="disabled" aria-disabled="true">Results</a>'
    )
    return (
        '<nav class="subnav" aria-label="Scan workspace">'
        + f'<a class="{"active" if active_tab == "activity" else ""}" href="/scan/{safe_scan_id}?tab=activity">Activity</a>'
        + results_link
        + "</nav>"
    )


def _layout(*, title: str, body: str, active: str = "", show_nav: bool = True, show_scan_results: bool = True, csrf_token: str = "") -> bytes:
    nav = ""
    body_class = "login-page" if not show_nav else ""
    if show_nav:
        nav = (
            '<div class="header-nav">'
            + f'<a class="nav{" active" if active == "new_scan" else ""}" href="/scan?new=1">New Scan</a>'
            + f'<a class="nav{" active" if active == "history" else ""}" href="/history">Past Scans</a>'
            + f'<a class="nav{" active" if active == "trends" else ""}" href="/trends">Trends</a>'
            + f'<a class="nav{" active" if active == "inventory" else ""}" href="/inventory">AI Inventory</a>'
            + f'<a class="nav{" active" if active == "settings" else ""}" href="/settings">Settings</a>'
            + f'<a class="nav{" active" if active == "help" else ""}" href="/help">Help</a>'
            + '</div>'
            + '<div class="header-actions">'
            + f'<form class="exit-form" method="post" action="/app/exit">{_csrf_field(csrf_token)}<button type="submit" class="warn">Exit</button></form>'
            + "</div>"
        )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<link rel="stylesheet" href="/assets/main.css">
</head>
<body class="{body_class}">
<header><h1>AI Security & Compliance Scanner</h1>{nav if nav else ""}</header>
<main>{body}</main>
<script src="/assets/layout.js" defer></script>
</body>
</html>"""
    return html.encode("utf-8")


def render_login_page(*, bitbucket_url: str, has_saved_pat: bool, notice: str = "", error: str = "", csrf_token: str = "") -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="card login-shell">
  <h2 class="login-title">Login to Bitbucket</h2>
  <p class="muted" style="margin:10px 0 0;text-align:center">Scan Bitbucket repositories to detect AI usage, insecure AI patterns, and policy-relevant findings.</p>
  <form method="post" action="/login" class="login-grid" style="margin-top:18px">
    {_csrf_field(csrf_token)}
    <div>
      <label>Personal Access Token</label>
      <input type="password" name="token" value="">
    </div>
    <label class="checkline"><input type="checkbox" name="use_saved_token" value="true"><span>Use saved token</span></label>
    <label class="checkline"><input type="checkbox" name="remember" value="true"><span>Remember token locally</span></label>
    <div class="muted">Saved token available: {"Yes" if has_saved_pat else "No"}</div>
    <div class="login-actions"><button type="submit">Login</button></div>
  </form>
</section>"""
    return _layout(title="Login", body=body, show_nav=False, csrf_token=csrf_token)


def render_scan_page(
    *,
    projects: list[dict],
    selected_project: str,
    repos: list[dict],
    selected_repos: list[str],
    llm_cfg: dict,
    llm_models: list[str],
    status: dict,
    log_text: str,
    phase_timeline: list[tuple[str, str]],
    selected_scan_scope: str = "full",
    selected_compare_ref: str = "",
    selected_local_repo_path: str = "",
    force_selection: bool = False,
    scan_id: str = "",
    workspace_tab: str = "activity",
    force_activity_view: bool = False,
    include_live_script: bool = True,
    show_scan_results: bool = True,
    csrf_token: str = "",
    notice: str = "",
    error: str = "",
) -> bytes:
    project_query_suffix = "&new=1" if force_selection else ""
    def _model_size_billions(name: str) -> float:
        text = (name or "").strip().lower()
        import re
        match = re.search(r'(?<!\d)(\d+(?:\.\d+)?)\s*([bm])(?!\w)', text)
        if not match:
            return 0.0
        value = float(match.group(1))
        return value if match.group(2) == "b" else value / 1000.0

    def triage_badge(status_name: str) -> str:
        if not status_name:
            return ""
        label_map = {
            "reviewed": "To Mitigate",
            "accepted_risk": "Accepted Risk",
            "false_positive": "Suppressed",
        }
        label = label_map.get(status_name, status_name.replace("_", " "))
        return f'<span class="triage-state triage-{_esc(status_name)}">{_esc(label)}</span>'

    def triage_meta(detail: dict) -> str:
        status_name = detail.get("triage_status", "")
        reason = detail.get("reason", "")
        marked_by = detail.get("marked_by", "")
        marked_at = _fmt_triage_time(detail.get("marked_at", ""))
        bits = []
        if status_name:
            bits.append(triage_badge(status_name))
        info = " · ".join(part for part in (marked_by, marked_at) if part)
        if info:
            bits.append(f'<span class="finding-sub">{_esc(info)}</span>')
        if reason:
            bits.append(f'<div class="triage-note">{_esc(reason)}</div>')
        return "".join(bits)

    def triage_actions(detail: dict, *, suppressed: bool = False) -> str:
        hash_ = detail.get("hash", "")
        if not hash_:
            return ""
        reset_form = (
            f'<form class="triage-form inline-only" method="post" action="/findings/reset">'
            f'{_csrf_field(csrf_token)}'
            f'<input type="hidden" name="hash" value="{_esc(hash_)}">'
            '<button type="submit" class="ghost">Reset</button>'
            "</form>"
        )
        if suppressed:
            return reset_form
        status_name = detail.get("triage_status", "")
        if status_name in {"reviewed", "accepted_risk"}:
            return f'<div class="triage-actions">{reset_form}</div>'
        reviewed_form = (
            f'<form class="triage-form inline-only" method="post" action="/findings/triage">'
            f'{_csrf_field(csrf_token)}'
            f'<input type="hidden" name="hash" value="{_esc(hash_)}">'
            '<input type="hidden" name="status" value="reviewed">'
            '<input type="hidden" name="note" value="">'
            '<button type="submit" class="ghost" onclick="return triagePromptSubmit(this.form, \'To Mitigate\')">To Mitigate</button>'
            "</form>"
        )
        accepted_form = (
            f'<form class="triage-form inline-only" method="post" action="/findings/triage">'
            f'{_csrf_field(csrf_token)}'
            f'<input type="hidden" name="hash" value="{_esc(hash_)}">'
            '<input type="hidden" name="status" value="accepted_risk">'
            '<input type="hidden" name="note" value="">'
            '<button type="submit" class="alt" onclick="return triagePromptSubmit(this.form, \'Accept Risk\')">Accept Risk</button>'
            "</form>"
        )
        suppress_form = (
            f'<form class="triage-form inline-only" method="post" action="/findings/triage">'
            f'{_csrf_field(csrf_token)}'
            f'<input type="hidden" name="hash" value="{_esc(hash_)}">'
            '<input type="hidden" name="status" value="false_positive">'
            '<input type="hidden" name="note" value="">'
            '<button type="submit" class="warn" onclick="return triagePromptSubmit(this.form, \'Suppress\')">Suppress</button>'
            "</form>"
        )
        return f'<div class="triage-actions">{reviewed_form}{accepted_form}{suppress_form}</div>'

    def severity_chip(detail: dict) -> str:
        sev = int(detail.get("severity", 4) or 4)
        label = detail.get("severity_label", str(sev))
        return f'<span class="sev-chip sev-{sev}">{_esc(label)}</span>'

    def snippet_block(detail: dict) -> str:
        snippet = str(detail.get("snippet", "") or "").strip()
        if not snippet:
            return ""
        snippet = snippet[:220]
        return f'<div class="finding-snippet">{_esc(snippet)}</div>'

    def score_strip(detail: dict) -> str:
        values = [
            ("Det", detail.get("detector_confidence_score", 0)),
            ("Prod", detail.get("production_relevance_score", 0)),
            ("Evd", detail.get("evidence_quality_score", 0)),
            ("LLM", detail.get("llm_review_confidence_score") if detail.get("llm_review_confidence_score") is not None else "—"),
            ("Sig", detail.get("overall_signal_score", 0)),
        ]
        return '<div class="score-strip">' + "".join(
            f'<span class="score-pill">{_esc(label)} {_esc(value)}</span>'
            for label, value in values
        ) + '</div>'

    def finding_summary(detail: dict) -> str:
        location = f'{detail.get("file", "")}:{detail.get("line", "")}'
        return (
            '<div class="finding-meta">'
            f'<div class="finding-main">{severity_chip(detail)}<span>{_esc(detail.get("repo", ""))}</span>'
            f'<span class="finding-loc">{_esc(location)}</span></div>'
            f'<div class="finding-sub">{_esc(detail.get("description", ""))}</div>'
            f'{score_strip(detail)}'
            f'{snippet_block(detail)}'
            '</div>'
        )

    def finding_row(detail: dict) -> str:
        return (
            "<tr>"
            f"<td>{finding_summary(detail)}</td>"
            f'<td><div class="finding-meta"><div>{_esc(detail.get("capability", ""))}</div>'
            f'<div class="finding-sub">{_esc(detail.get("delta_label", detail.get("delta_status", "")))}</div></div></td>'
            f"<td>{triage_actions(detail)}</td>"
            "</tr>"
        )

    def suppressed_row(detail: dict) -> str:
        status_name = detail.get("triage_status", "false_positive") or "false_positive"
        return (
            "<tr>"
            f"<td>{finding_summary(detail)}</td>"
            f"<td>{triage_badge(status_name)}</td>"
            f"<td>{triage_meta(detail)}</td>"
            f"<td>{triage_actions(detail, suppressed=True)}</td>"
            "</tr>"
        )

    def mitigated_row(detail: dict) -> str:
        return (
            "<tr>"
            f"<td>{finding_summary(detail)}</td>"
            f"<td>{triage_badge(detail.get('triage_status', 'reviewed') or 'reviewed')}</td>"
            f"<td>{triage_meta(detail)}</td>"
            f"<td>{triage_actions(detail, suppressed=False)}</td>"
            "</tr>"
        )

    state = str(status.get("state", "")).lower()
    running = state == "running"
    scan_complete = state in {"done", "stopped", "error"}
    start_blocked = running and force_selection
    selected = set(selected_repos)
    scope_value = str(selected_scan_scope or "full").strip().lower() or "full"
    compare_ref_value = str(selected_compare_ref or "").strip()
    local_repo_path_value = str(selected_local_repo_path or "").strip()
    repo_count = len(repos)
    repo_cols = "cols-2" if repo_count <= 18 else "cols-3"
    project_links = "".join(
        f'<a class="project-link{" active" if p.get("key","") == selected_project else ""}" href="/scan?project={_esc(p.get("key",""))}{project_query_suffix}">{_esc(p.get("key",""))}</a>'
        for p in projects
    ) or '<div class="muted">No projects loaded.</div>'
    has_selected_project = bool(selected_project)
    repo_rows = "".join(
        f'<label class="repo-row" data-repo-name="{_esc(repo.get("slug","").lower())}"><input type="checkbox" class="repo-checkbox" name="repo_slugs" value="{_esc(repo.get("slug",""))}"{" checked" if repo.get("slug","") in selected else ""}><span>{_esc(repo.get("slug","").lower())}</span></label>'
        for repo in repos
    ) or (
        '<div class="muted hidden" id="no-repos-message">No repositories available for the selected project.</div>'
        if not has_selected_project
        else '<div class="muted" id="no-repos-message">No repositories available for the selected project.</div>'
    )
    models = list(dict.fromkeys([m for m in llm_models if m] + ([llm_cfg.get("model", "")] if llm_cfg.get("model") else [])))
    model_options = "".join(
        f'<option value="{_esc(model)}"{" selected" if model == llm_cfg.get("model", "") else ""}>{_esc(model)}</option>'
        for model in models
    )
    scope_options = "".join(
        f'<option value="{_esc(value)}"{" selected" if value == scope_value else ""}>{_esc(label)}</option>'
        for value, label in [
            ("full", "Full Scan"),
            ("changed_files", "Changed Files Only"),
            ("branch_diff", "Branch Diff"),
            ("baseline_rescan", "Baseline-Aware Rescan"),
        ]
    )
    all_findings = status.get("finding_details", [])
    current_findings = [f for f in all_findings if f.get("triage_status") not in {"reviewed", "accepted_risk"}][:20]
    mitigate_findings = [f for f in all_findings if f.get("triage_status") == "reviewed"][:20]
    accepted_or_suppressed = [f for f in all_findings if f.get("triage_status") == "accepted_risk"] + status.get("suppressed_details", [])
    accepted_or_suppressed = accepted_or_suppressed[:30]
    findings_rows = "".join(finding_row(f) for f in current_findings) or '<tr><td colspan="5">No current findings.</td></tr>'
    mitigate_rows = "".join(mitigated_row(f) for f in mitigate_findings) or '<tr><td colspan="5">No findings marked to mitigate.</td></tr>'
    suppressed_rows = "".join(suppressed_row(f) for f in accepted_or_suppressed) or '<tr><td colspan="5">No suppressed or accepted findings.</td></tr>'
    normalized_timeline = []
    for item in phase_timeline:
        if isinstance(item, dict):
            normalized_timeline.append(item)
        else:
            name, duration = item
            normalized_timeline.append({"name": name, "duration": duration, "state": "pending"})
    timeline_html = "".join(
        f'<div class="timeline-row{" total-row" if str(item.get("name","")).lower() == "total" else ""}">'
        f'<span class="state-icon {_esc(item.get("state","pending"))}"></span>'
        f'<span class="timeline-name">{_esc(item.get("name",""))}</span>'
        f'<strong>{_esc(item.get("duration","—"))}</strong>'
        f"</div>"
        for item in normalized_timeline
        if scan_complete or str(item.get("name", "")).lower() != "total"
    ) or '<div class="muted">Timeline will appear after the scan starts.</div>'
    stop_button = (
        '<button type="button" id="stop-scan-btn" class="warn" onclick="document.getElementById(\'stop-form\').submit()">Stop Scan</button>'
        if running
        else '<button type="button" id="stop-scan-btn" class="warn" disabled>Stop Scan</button>'
    )
    state_icon_class = "running" if running else "done" if state == "done" else "stopped" if state == "stopped" else ""
    state_text = "Running" if running else "Done" if state == "done" else "Stopped" if state == "stopped" else "Ready"
    report = status.get("report") or {}
    delta = status.get("delta") or {}
    inventory = status.get("inventory") or {}
    hardware = status.get("hardware") or {}
    llm_stats = status.get("llm_stats") or {}
    phase_metrics = status.get("phase_metrics") or {}
    repo_metrics = status.get("repo_metrics") or {}
    llm_batch_metrics = list(status.get("llm_batch_metrics") or [])
    cache_metrics = status.get("cache_metrics") or {}
    structured_errors = list(status.get("errors") or [])
    fixed_findings = list(delta.get("fixed_findings") or [])[:8]
    baseline_html = ""
    if scan_complete and delta.get("has_baseline"):
        fixed_list = "".join(
            f'<li><strong>{_esc(item.get("repo") or item.get("provider_or_lib") or "Finding")}</strong> '
            f'<span class="muted">{_esc(item.get("file", ""))}{":" + _esc(item.get("line", "")) if item.get("line") else ""}</span></li>'
            for item in fixed_findings
        ) or '<li>No fixed findings.</li>'
        baseline_html = f"""
    <section class="card">
      <h2 style="margin:0 0 8px;font-size:16px">Baseline</h2>
      <div class="baseline-summary" id="baseline-summary">
        <div class="baseline-grid">
          <div class="baseline-stat"><span class="baseline-label">New</span><strong id="baseline-new-count">{_esc(delta.get("new_count", 0))}</strong></div>
          <div class="baseline-stat"><span class="baseline-label">Existing</span><strong id="baseline-existing-count">{_esc(delta.get("existing_count", delta.get("unchanged_count", 0)))}</strong></div>
          <div class="baseline-stat"><span class="baseline-label">Fixed</span><strong id="baseline-fixed-count">{_esc(delta.get("fixed_count", 0))}</strong></div>
        </div>
        <div class="muted" id="baseline-source">Compared to {_esc(delta.get("baseline_file", "previous scan"))}</div>
        <ul class="baseline-fixed-list" id="baseline-fixed-list">{fixed_list}</ul>
      </div>
    </section>"""
    scan_id = status.get("scan_id", "")
    inventory_html = ""
    if inventory.get("repos_total", 0):
        provider_chips = "".join(
            f'<span class="inventory-chip">{_esc(item.get("label", ""))} {_esc(item.get("count", 0))}</span>'
            for item in list(inventory.get("providers_by_count") or [])[:6]
        ) or '<span class="muted">No providers detected.</span>'
        model_chips = "".join(
            f'<span class="inventory-chip">{_esc(item.get("model", ""))}</span>'
            for item in list(inventory.get("models_by_count") or [])[:6]
        ) or '<span class="muted">No models detected.</span>'
        repo_blocks = "".join(
            f'<div class="inventory-repo"><strong>{_esc(profile.get("repo", ""))}</strong>'
            f'<div class="inventory-meta">{", ".join(_esc(label) for label in profile.get("provider_labels", [])[:4]) or "No provider detail"}</div>'
            f'<div class="inventory-meta">'
            f'Embeddings/Vector DB: {"Yes" if profile.get("embeddings_vector_db") else "No"} · '
            f'Prompt Handling: {"Yes" if profile.get("prompt_handling") else "No"} · '
            f'Model Serving: {"Yes" if profile.get("model_serving") else "No"} · '
            f'Agent/Tool Use: {"Yes" if profile.get("agent_tool_use") else "No"}'
            f'</div></div>'
            for profile in list(inventory.get("repo_profiles") or [])[:8]
        )
        inventory_html = f"""
    <section class="card">
      <h2 style="margin:0 0 8px;font-size:16px">AI Inventory</h2>
      <div class="inventory-summary" id="inventory-summary">
        <div class="inventory-grid inventory-grid-wide">
          <div class="inventory-stat"><span class="baseline-label">Repos Using AI</span><strong id="inventory-repos-ai">{_esc(inventory.get("repos_using_ai_count", 0))}/{_esc(inventory.get("repos_total", 0))}</strong></div>
          <div class="inventory-stat"><span class="baseline-label">Providers</span><strong id="inventory-provider-count">{_esc(inventory.get("provider_count", 0))}</strong></div>
          <div class="inventory-stat"><span class="baseline-label">Models</span><strong id="inventory-model-count">{_esc(inventory.get("model_count", 0))}</strong></div>
          <div class="inventory-stat"><span class="baseline-label">Embeddings / Vector DB</span><strong id="inventory-embed-count">{_esc(inventory.get("embeddings_vector_db_repos", 0))}</strong></div>
          <div class="inventory-stat"><span class="baseline-label">Prompt Handling</span><strong id="inventory-prompt-count">{_esc(inventory.get("prompt_handling_repos", 0))}</strong></div>
          <div class="inventory-stat"><span class="baseline-label">Model Serving / Agent Use</span><strong id="inventory-serving-agent">{_esc(inventory.get("model_serving_repos", 0))}/{_esc(inventory.get("agent_tool_use_repos", 0))}</strong></div>
        </div>
        <div><div class="muted" style="margin-bottom:4px">Providers</div><div class="inventory-list" id="inventory-providers">{provider_chips}</div></div>
        <div><div class="muted" style="margin-bottom:4px">Models</div><div class="inventory-list" id="inventory-models">{model_chips}</div></div>
        <div class="inventory-repos" id="inventory-repos-list">{repo_blocks or '<div class="muted">No repo inventory available.</div>'}</div>
      </div>
    </section>"""
    inventory_html = ""
    hardware_html = f"""
    <section class="card" id="hardware-card">
      <h2 style="margin:0 0 8px;font-size:15px">Performance</h2>
      <div class="baseline-summary" id="hardware-summary">
        <div class="hardware-grid">
          <div class="hardware-stat"><span class="baseline-label">CPU</span><strong id="hardware-cpu">{_esc(hardware.get("cpu_percent", "Sampling..."))}</strong></div>
          <div class="hardware-stat"><span class="baseline-label">RAM</span><strong id="hardware-ram">{_esc(hardware.get("ram_text", "Unavailable"))}</strong></div>
          <div class="hardware-stat"><span class="baseline-label">GPU</span><strong id="hardware-gpu">{_esc(hardware.get("gpu_text", "Unavailable"))}</strong></div>
          <div class="hardware-stat"><span class="baseline-label">Disk I/O</span><strong id="hardware-disk-io">{_esc(hardware.get("disk_io_text", "Sampling..."))}</strong></div>
          <div class="hardware-stat"><span class="baseline-label">Findings Reviewed / Skipped</span><strong id="perf-reviewed-skipped">{_esc(llm_stats.get("reviewed", 0))} / {_esc(llm_stats.get("skipped", 0))}</strong></div>
          <div class="hardware-stat"><span class="baseline-label">Dismissed / Downgraded</span><strong id="perf-llm-outcomes">{_esc(llm_stats.get("dismissed", 0))} / {_esc(llm_stats.get("downgraded", 0))}</strong></div>
        </div>
      </div>
    </section>"""
    timings_html = (
        '<section class="card" id="timings-card">'
        '<h2 style="margin:0 0 8px;font-size:15px">Structured Timings</h2>'
        '<div class="baseline-summary"><div class="hardware-grid">'
        + "".join(
            f'<div class="hardware-stat"><span class="baseline-label">{_esc(label)}</span><strong>{_esc(_fmt_duration(phase_metrics.get(key, 0)))}</strong></div>'
            for key, label in (("init", "Init"), ("clone", "Clone"), ("scan", "Scan"), ("llm review", "LLM"), ("report", "Report"), ("total", "Total"))
            if key in phase_metrics
        )
        + (
            f'<div class="hardware-stat"><span class="baseline-label">Cache</span><strong>{_esc(str(cache_metrics.get("hits", 0)))} / {_esc(str(cache_metrics.get("misses", 0)))} </strong></div>'
            if cache_metrics else ""
        )
        + '</div></div></section>'
    )
    repo_metrics_rows = "".join(
        f'<div class="hardware-stat"><span class="baseline-label">{_esc(repo)}</span>'
        f'<strong>{_esc(_fmt_duration(data.get("clone_s", 0)))} / {_esc(_fmt_duration(data.get("scan_s", 0)))} / {_esc(_fmt_duration(data.get("llm_review_s", 0)))}</strong></div>'
        for repo, data in list(repo_metrics.items())[:6]
    )
    repo_metrics_body = repo_metrics_rows or '<div class="muted">No repo timing data yet.</div>'
    repo_metrics_html = (
        '<section class="card" id="repo-metrics-card">'
        '<h2 style="margin:0 0 8px;font-size:15px">Per-Repo Timings</h2>'
        '<div class="muted" style="font-size:11px;margin-bottom:6px">Clone / Scan / LLM review</div>'
        f'<div class="baseline-summary"><div class="hardware-grid">{repo_metrics_body}</div></div>'
        '</section>'
    )
    llm_batches_html = (
        '<section class="card" id="llm-batches-card">'
        '<h2 style="margin:0 0 8px;font-size:15px">LLM Batch Timings</h2>'
        '<div class="baseline-summary"><div class="hardware-grid">'
        + "".join(
            f'<div class="hardware-stat"><span class="baseline-label">Batch {int(item.get("batch", 0))}/{int(item.get("total_batches", 0))}</span>'
            f'<strong>{_esc(_fmt_duration(item.get("duration_s", 0)))}{" fail" if item.get("failed") else ""}</strong></div>'
            for item in llm_batch_metrics[-5:]
        )
        + '</div></div></section>'
        if llm_batch_metrics else ""
    )
    errors_html = (
        '<section class="card" id="scan-errors-card">'
        '<h2 style="margin:0 0 8px;font-size:15px">Errors</h2>'
        + "".join(
            f'<div class="triage-note"><strong>{_esc(item.get("code", ""))}</strong> · {_esc(item.get("stage", ""))}'
            f'<div class="finding-sub">{_esc(item.get("message", ""))}</div></div>'
            for item in structured_errors[-4:]
        )
        + '</section>'
        if structured_errors else ""
    )
    new_scan_button = ""
    if scan_complete:
        project_q = f"?project={quote(selected_project)}&new=1" if selected_project else "?new=1"
        new_scan_button = f'<a class="btn" id="new-scan-btn" href="/scan{project_q}">New Scan</a>'
    model_warning = ""
    if _model_size_billions(llm_cfg.get("model", "")) and _model_size_billions(llm_cfg.get("model", "")) < 4:
        model_warning = "Selected model is below 4B and may be unreliable for LLM review."
    running_notice = (
        'A scan is in progress. Wait until it finishes before starting a new scan.'
        if start_blocked
        else ""
    )
    selection_view = f"""
<section class="selection-grid">
  <aside class="card project-panel">
    <h2 style="margin:0 0 8px;font-size:16px">Projects</h2>
    <div class="project-list">{project_links}</div>
  </aside>
  <section class="card repo-panel">
    <form method="post" action="/scan/start" class="stack" id="new-scan-form">
      {_csrf_field(csrf_token)}
      <input type="hidden" name="project_key" value="{_esc(selected_project)}">
      <div class="repo-toolbar">
        <div><label>Search Repositories</label><input type="search" id="repo-search" placeholder="Search by repo name"></div>
        <div><label>Scan Scope</label><select name="scan_scope" id="scan-scope-select">{scope_options}</select></div>
        <div><label>LLM Model</label><select name="llm_model" id="llm-model-select">{model_options}</select></div>
        <div class="inline repo-action-bar" style="justify-content:flex-start;align-items:end;gap:8px">
          <div class="inline{" hidden" if not local_repo_path_value else ""}" id="local-repo-row" style="gap:8px;align-items:center;flex:1 1 auto">
            <input type="text" name="local_repo_path" id="local-repo-path-input" value="{_esc(local_repo_path_value)}" placeholder="Local Repository Path e.g. C:\\repo or /home/user/repo">
            <button type="button" class="ghost" id="local-repo-browse-btn">Browse...</button>
          </div>
          <button type="button" class="ghost" id="local-repo-toggle-btn">Local Repo</button>
          <button type="submit" id="start-scan-btn"{" disabled" if start_blocked or (not selected and not local_repo_path_value) else ""}>Start Scan</button>
        </div>
      </div>
      <div class="repo-toolbar">
        <div id="compare-ref-wrap"{" class=\"hidden\"" if scope_value != "branch_diff" else ""}><label>Compare Branch</label><input type="text" name="compare_ref" id="compare-ref-input" value="{_esc(compare_ref_value)}" placeholder="e.g. master"></div>
        <div></div>
        <div></div>
        <div></div>
      </div>
      <div class="repo-notices">
        <div class="warn-box{" hidden" if not running_notice else ""}" id="running-scan-notice">{_esc(running_notice)}</div>
        <div class="warn-box{" hidden" if not model_warning else ""}" id="model-size-warning">{_esc(model_warning)}</div>
      </div>
      <div class="repo-actions{" hidden" if not has_selected_project else ""}" id="repo-actions">
        <span class="muted" id="repo-selection-count"></span>
        <button type="button" class="ghost" id="select-all-repos-btn">All</button>
        <button type="button" class="ghost" id="select-none-repos-btn">None</button>
      </div>
      <div class="repo-shell"><div id="repo-grid" class="repo-grid {repo_cols}">{repo_rows}</div></div>
    </form>
  </section>
</section>
<form method="post" action="/scan/stop" id="stop-form">{_csrf_field(csrf_token)}</form>"""
    workspace_tabs = _scan_workspace_tabs(scan_id, workspace_tab, results_enabled=scan_complete) if scan_id else ""
    running_view = f"""
<section class="running-shell">
  <section class="card activity-panel">
    <div class="workspace-header">
      {workspace_tabs}
      <h2>Activity Log</h2>
      <div class="scan-actions">{stop_button if running else ""}{new_scan_button}</div>
    </div>
    <div class="terminal" id="scan-log">{_esc(log_text or "No activity yet.")}</div>
  </section>
  <aside class="stack">
    <section class="card timeline-card">
      <h2 style="margin:0 0 8px;font-size:16px">Phase Timeline</h2>
      <div class="timeline" id="phase-timeline">{timeline_html}</div>
    </section>
    {hardware_html}
    {timings_html}
    {repo_metrics_html}
    {llm_batches_html}
    {errors_html}
    {baseline_html}
    {inventory_html}
  </aside>
</section>
<form method="post" action="/scan/stop" id="stop-form">{_csrf_field(csrf_token)}</form>"""
    body = f"""
{_flash(notice, error)}
<section class="scan-shell">
  {running_view if (force_activity_view or (not force_selection and (running or state in ("done", "stopped") and log_text))) else selection_view}
</section>
{'<script src="/assets/scan_page.js" defer></script>' if include_live_script else ''}"""
    nav_active = "" if scan_id else "new_scan"
    return _layout(title="Scan", body=body, active=nav_active, show_scan_results=show_scan_results, csrf_token=csrf_token)


def render_history_page(*, history: list[dict], notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "") -> bytes:
    projects = sorted({str(rec.get("project_key", "")) for rec in history if rec.get("project_key")})
    repos = sorted({", ".join(rec.get("repo_slugs", rec.get("repos", []))) for rec in history if rec.get("repo_slugs") or rec.get("repos")})
    statuses = sorted({str(rec.get("state", "")) for rec in history if rec.get("state")})
    models = sorted({str(rec.get("llm_model", "")) for rec in history if rec.get("llm_model")})

    def _opts(values: list[str], label: str) -> str:
        return f'<option value="">{_esc(label)}</option>' + "".join(f'<option value="{_esc(v)}">{_esc(v)}</option>' for v in values)

    rows = []
    for rec in history:
        project = rec.get("project_key", "")
        repo_label = ", ".join(rec.get("repo_slugs", rec.get("repos", [])))
        scan_id = str(rec.get("scan_id", "") or "")
        details_link = (
            f'<a class="icon-link" href="/scan/{_esc(scan_id)}?tab=activity" title="Open scan details"><img src="{DETAILS_ICON}" alt="Details"></a>'
            if scan_id
            else ""
        )
        date_text, time_text, ts = _fmt_dt(rec.get("started_at_utc", ""))
        state = str(rec.get("state", ""))
        status_class = {"running": "status-running", "done": "status-done", "stopped": "status-stopped"}.get(state.lower(), "")
        total_findings = rec.get("total", rec.get("finding_total", rec.get("active_total", 0)))
        delta = rec.get("delta") or {}
        delta_new = delta.get("new_count", 0)
        delta_existing = delta.get("existing_count", delta.get("unchanged_count", 0))
        delta_fixed = delta.get("fixed_count", 0)
        phase_summary = _fmt_phase_summary(rec.get("phase_metrics") or {})
        last_error = ((rec.get("errors") or [])[-1] or {}).get("code", "") if rec.get("errors") else ""
        rows.append(
            f'<tr data-project="{_esc(project)}" data-repo="{_esc(repo_label)}" data-status="{_esc(state)}" data-model="{_esc(rec.get("llm_model",""))}" data-ts="{ts}">'
            f'<td><input type="checkbox" class="history-check" name="scan_ids" value="{_esc(rec.get("scan_id",""))}"></td>'
            f'<td><div>{_esc(date_text)}</div><div class="history-time">{_esc(time_text)}</div></td>'
            f'<td>{_esc(project)}</td>'
            f'<td>{_esc(repo_label)}</td>'
            f'<td>{_esc(total_findings)}</td>'
            f'<td>{_esc(delta_new)}</td>'
            f'<td>{_esc(delta_existing)}</td>'
            f'<td>{_esc(delta_fixed)}</td>'
            f'<td>{_esc(rec.get("critical_prod", 0))}</td>'
            f'<td>{_esc(rec.get("high_prod", 0))}</td>'
            f'<td>{_esc(rec.get("llm_model", ""))}</td>'
            f'<td>{_esc(_fmt_duration(rec.get("duration_s", 0)))}</td>'
            f'<td>{_esc(phase_summary)}</td>'
            f'<td><span class="pill {status_class}">{_esc(state.title())}</span></td>'
            f'<td>{_esc(last_error or "—")}</td>'
            f'<td>{details_link}</td></tr>'
        )
    body = f"""
{_flash(notice, error)}
<section class="card">
  <form method="post" action="/history/delete" id="history-form">
    {_csrf_field(csrf_token)}
    <div class="history-toolbar filters-row">
      <input type="search" id="history-search" placeholder="Search any column">
      <select id="filter-project">{_opts(projects, 'All Projects')}</select>
      <select id="filter-repo">{_opts(repos, 'All Repos')}</select>
      <select id="filter-status">{_opts(statuses, 'All Statuses')}</select>
      <select id="filter-model">{_opts(models, 'All Models')}</select>
      <button type="button" class="ghost" id="reset-history-filters">Reset</button>
      <button type="submit" class="warn hidden" id="delete-selected-btn">Delete Selected Scans</button>
    </div>
    <div class="table-shell">
      <table id="history-table">
        <thead>
          <tr>
            <th></th>
            <th data-sort="datetime">Date/<br>Time</th>
            <th data-sort="text">Project</th>
            <th data-sort="text">Repo</th>
            <th data-sort="number">Total<br>Findings</th>
            <th data-sort="number">New</th>
            <th data-sort="number">Existing</th>
            <th data-sort="number">Fixed</th>
            <th data-sort="number">Critical<br>in Prod</th>
            <th data-sort="number">High<br>in Prod</th>
            <th data-sort="text">LLM<br>Model</th>
            <th data-sort="number">Duration</th>
            <th>Phases</th>
            <th data-sort="text">Status</th>
            <th>Error</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>{''.join(rows) or '<tr><td colspan="16">No scan history available.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="history-pagination">
      <button type="button" class="ghost" id="history-prev-btn">Previous</button>
      <span class="page-info" id="history-page-info">Page 1 of 1</span>
      <button type="button" class="ghost" id="history-next-btn">Next</button>
    </div>
  </form>
</section>
<script src="/assets/history_page.js" defer></script>"""
    return _layout(title="Past Scans", body=body, active="history", show_scan_results=show_scan_results, csrf_token=csrf_token)


def render_results_page(
    *,
    scan_id: str,
    project_key: str,
    repo_label: str,
    state: str,
    html_name: str,
    csv_name: str = "",
    log_url: str = "",
    started_at_utc: str = "",
    can_generate_html: bool = False,
    html_generation: dict | None = None,
    show_scan_results: bool = True,
    csrf_token: str = "",
    notice: str = "",
    error: str = "",
) -> bytes:
    workspace_tabs = _scan_workspace_tabs(scan_id, "results")
    html_generation = dict(html_generation or {})
    generation_state = str(html_generation.get("state", "") or "").lower()
    generation_active = generation_state in {"queued", "running"}
    toolbar_actions = []
    if html_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(html_name)}" target="_blank">Open Raw HTML</a>')
    elif can_generate_html and not generation_active:
        toolbar_actions.append(
            f'<form method="post" action="/scan/{_esc(scan_id)}/generate-html" class="triage-form inline-only">'
            f'{_csrf_field(csrf_token)}'
            '<button type="submit" class="btn alt">Generate HTML Report</button>'
            '</form>'
        )
    elif generation_active:
        toolbar_actions.append('<button type="button" class="btn alt disabled" disabled>Generating HTML Report...</button>')
    if csv_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(csv_name)}" download>Download CSV File</a>')
    if log_url:
        toolbar_actions.append(f'<a class="btn ghost" href="{_esc(log_url)}" download>Download Logs</a>')
    progress_card = ""
    if generation_state:
        progress_text = str(html_generation.get("message", "") or "")
        current = int(html_generation.get("current", 0) or 0)
        total = int(html_generation.get("total", 0) or 0)
        pct = int(round((current / total) * 100)) if total > 0 else (100 if generation_state == "done" else 0)
        state_label = {
            "queued": "Queued",
            "running": "Running",
            "done": "Ready",
            "error": "Failed",
        }.get(generation_state, generation_state.title())
        meta_text = f"{current}/{total}" if total > 0 else ("Complete" if generation_state == "done" else "")
        progress_card = (
            f'<section class="card report-progress-card" id="report-progress-card" data-scan-id="{_esc(scan_id)}" '
            f'data-report-generation-active="{"1" if generation_active else "0"}">'
            f'<div class="report-progress-head"><strong>HTML Report Generation</strong><span class="pill">{_esc(state_label)}</span></div>'
            f'<div class="muted" id="report-progress-message">{_esc(progress_text or "Preparing report generation...")}</div>'
            f'<div class="report-progress-bar"><div class="report-progress-fill" id="report-progress-fill" style="width:{pct}%"></div></div>'
            f'<div class="report-progress-meta" id="report-progress-meta">{_esc(meta_text)}</div>'
            '</section>'
        )
    if html_name:
        results_body = f'<iframe class="results-frame" src="/reports/{_esc(html_name)}" title="Detailed Report"></iframe>'
    elif can_generate_html:
        results_body = (
            '<section class="card empty-state"><strong>Detailed HTML report has not been generated yet.</strong>'
            '<div class="muted" style="margin-top:6px">Generate it when you need the full exported report. CSV and log artifacts remain available immediately.</div>'
            '</section>'
        )
    else:
        results_body = (
            '<section class="card empty-state"><strong>No report was generated for this scan.</strong>'
            '<div class="muted" style="margin-top:6px">This usually means the scan completed without findings or stopped before report generation.</div></section>'
        )
    body = f"""
{_flash(notice, error)}
<section class="results-shell">
  <section class="card">
    <div class="results-toolbar">
      {workspace_tabs}
      <div class="results-actions">
        {''.join(toolbar_actions)}
      </div>
    </div>
  </section>
  {progress_card}
  {results_body}
</section>
{'<script src="/assets/results_page.js" defer></script>' if (generation_state or (can_generate_html and not html_name)) else ''}"""
    return _layout(title="Results", body=body, active="", show_scan_results=show_scan_results, csrf_token=csrf_token)


def render_inventory_page(*, repo_inventory: list[dict], summary: dict, notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "") -> bytes:
    projects = sorted({str(item.get("project_key", "")) for item in repo_inventory if item.get("project_key")})
    providers = sorted({label for item in repo_inventory for label in item.get("provider_labels", []) if label})
    models = sorted({model for item in repo_inventory for model in item.get("models", []) if model})

    def _opts(values: list[str], label: str) -> str:
        return f'<option value="">{_esc(label)}</option>' + "".join(f'<option value="{_esc(v)}">{_esc(v)}</option>' for v in values)

    rows = []
    for item in repo_inventory:
        provider_text = ", ".join(item.get("provider_labels", []))
        model_text = ", ".join(item.get("models", []))
        date_text, time_text, ts = _fmt_dt(item.get("last_scan_at_utc", ""))
        reports = item.get("reports") or {}
        html_link = (
            f'<a class="icon-link" href="/reports/{_esc(reports.get("html_name",""))}" target="_blank" title="Open HTML Report"><img src="{HTML_ICON}" alt="HTML"></a>'
            if reports.get("html_name")
            else ""
        )
        rows.append(
            f'<tr data-project="{_esc(item.get("project_key", ""))}" '
            f'data-provider="{_esc(provider_text.lower())}" '
            f'data-model="{_esc(model_text.lower())}" '
            f'data-flags="{_esc(" ".join(item.get("usage_tags", [])))}" '
            f'data-ts="{ts}">'
            f'<td><div>{_esc(date_text)}</div><div class="history-time">{_esc(time_text)}</div></td>'
            f'<td>{_esc(item.get("project_key", ""))}</td>'
            f'<td><strong>{_esc(item.get("repo", ""))}</strong><div class="inventory-sub">{_esc(item.get("scan_id", ""))}</div></td>'
            f'<td>{_esc(item.get("finding_count", 0))}</td>'
            f'<td>{_esc(provider_text or "-")}</td>'
            f'<td>{_esc(model_text or "-")}</td>'
            f'<td><span class="inventory-bool {"yes" if item.get("embeddings_vector_db") else "no"}">{"Yes" if item.get("embeddings_vector_db") else "No"}</span></td>'
            f'<td><span class="inventory-bool {"yes" if item.get("prompt_handling") else "no"}">{"Yes" if item.get("prompt_handling") else "No"}</span></td>'
            f'<td><span class="inventory-bool {"yes" if item.get("model_serving") else "no"}">{"Yes" if item.get("model_serving") else "No"}</span></td>'
            f'<td><span class="inventory-bool {"yes" if item.get("agent_tool_use") else "no"}">{"Yes" if item.get("agent_tool_use") else "No"}</span></td>'
            f'<td>{html_link}</td>'
            "</tr>"
        )

    body = f"""
{_flash(notice, error)}
<section class="inventory-page-grid">
  <section class="card">
    <h2 style="margin:0 0 8px">AI Inventory</h2>
    <p class="muted" style="margin:0 0 12px">Latest known AI usage profile per repository from scan history.</p>
    <div class="inventory-summary-cards">
      <div class="inventory-card-stat"><span class="baseline-label">Repos Using AI</span><strong>{_esc(summary.get("repos_using_ai_count", 0))}</strong></div>
      <div class="inventory-card-stat"><span class="baseline-label">Total Repos</span><strong>{_esc(summary.get("repos_total", 0))}</strong></div>
      <div class="inventory-card-stat"><span class="baseline-label">Providers</span><strong>{_esc(summary.get("provider_count", 0))}</strong></div>
      <div class="inventory-card-stat"><span class="baseline-label">Models</span><strong>{_esc(summary.get("model_count", 0))}</strong></div>
      <div class="inventory-card-stat"><span class="baseline-label">Agent / Tool Use</span><strong>{_esc(summary.get("agent_tool_use_repos", 0))}</strong></div>
    </div>
  </section>

  <section class="card">
    <div class="inventory-toolbar filters-row">
      <input type="search" id="inventory-search" placeholder="Search repo, provider, model, or scan">
      <select id="inventory-project">{_opts(projects, 'All Projects')}</select>
      <select id="inventory-provider">{_opts(providers, 'All Providers')}</select>
      <select id="inventory-model">{_opts(models, 'All Models')}</select>
      <select id="inventory-usage">
        <option value="">All Usage Types</option>
        <option value="embeddings">Embeddings / Vector DB</option>
        <option value="prompt">Prompt Handling</option>
        <option value="serving">Model Serving</option>
        <option value="agent">Agent / Tool Use</option>
      </select>
      <button type="button" class="ghost" id="inventory-reset">Reset</button>
    </div>
    <div class="table-shell">
      <table id="inventory-table">
        <thead>
          <tr>
            <th data-sort="datetime">Last Scan</th>
            <th data-sort="text">Project</th>
            <th data-sort="text">Repo</th>
            <th data-sort="number">Findings</th>
            <th data-sort="text">Providers</th>
            <th data-sort="text">Models</th>
            <th data-sort="text">Embeddings /<br>Vector DB</th>
            <th data-sort="text">Prompt<br>Handling</th>
            <th data-sort="text">Model<br>Serving</th>
            <th data-sort="text">Agent /<br>Tool Use</th>
            <th>HTML</th>
          </tr>
        </thead>
        <tbody>{''.join(rows) or '<tr><td colspan="11">No AI inventory available yet.</td></tr>'}</tbody>
      </table>
    </div>
  </section>
</section>
<script>
const iBody=document.querySelector('#inventory-table tbody');
const iSearch=document.getElementById('inventory-search');
const iProject=document.getElementById('inventory-project');
const iProvider=document.getElementById('inventory-provider');
const iModel=document.getElementById('inventory-model');
const iUsage=document.getElementById('inventory-usage');
function iRows(){{return Array.from(iBody.querySelectorAll('tr')).filter(r=>r.querySelectorAll('td').length>1);}}
function inventoryMatchesUsage(row){{
  if(!iUsage.value) return true;
  return (row.dataset.flags||'').split(' ').includes(iUsage.value);
}}
function applyInventoryFilters(){{
  const q=(iSearch.value||'').toLowerCase().trim();
  iRows().forEach(row=>{{
    const text=row.textContent.toLowerCase();
    const okQ=!q || text.includes(q);
    const okP=!iProject.value || row.dataset.project===iProject.value;
    const okProvider=!iProvider.value || (row.dataset.provider||'').includes(iProvider.value.toLowerCase());
    const okModel=!iModel.value || (row.dataset.model||'').includes(iModel.value.toLowerCase());
    row.style.display=(okQ && okP && okProvider && okModel && inventoryMatchesUsage(row)) ? '' : 'none';
  }});
}}
let inventorySort={{index:null,dir:-1,kind:'datetime'}};
function inventoryCellValue(row,index,kind){{
  if(kind==='datetime') return Number(row.dataset.ts)||0;
  const text=(row.children[index]?.innerText||'').trim();
  if(kind==='number') return Number(text)||0;
  return text.toLowerCase();
}}
function sortInventory(index,kind){{
  const rows=iRows();
  if(inventorySort.index===index) inventorySort.dir*=-1; else inventorySort={{index,dir:kind==='datetime'?-1:1,kind}};
  rows.sort((a,b)=>{{
    const av=inventoryCellValue(a,inventorySort.index,inventorySort.kind);
    const bv=inventoryCellValue(b,inventorySort.index,inventorySort.kind);
    if(av<bv) return -1*inventorySort.dir;
    if(av>bv) return 1*inventorySort.dir;
    return 0;
  }});
  rows.forEach(r=>iBody.appendChild(r));
  applyInventoryFilters();
}}
document.querySelectorAll('#inventory-table thead th[data-sort]').forEach((th,index)=>th.addEventListener('click',()=>sortInventory(index,th.dataset.sort)));
[iSearch,iProject,iProvider,iModel].forEach(el=>el?.addEventListener('input',applyInventoryFilters));
[iProject,iProvider,iModel,iUsage].forEach(el=>el?.addEventListener('change',applyInventoryFilters));
document.getElementById('inventory-reset')?.addEventListener('click',()=>{{
  iSearch.value=''; iProject.value=''; iProvider.value=''; iModel.value=''; iUsage.value=''; applyInventoryFilters();
}});
sortInventory(0,'datetime');
</script>"""
    return _layout(title="AI Inventory", body=body, active="inventory", show_scan_results=show_scan_results, csrf_token=csrf_token)


def render_trends_page(*, trends: dict, notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "") -> bytes:
    summary = dict(trends.get("summary") or {})

    def _bar_rows(items: list[dict], *, value_key: str, empty_text: str) -> str:
        if not items:
            return f'<div class="empty-state">{_esc(empty_text)}</div>'
        max_value = max(int(item.get(value_key, 0) or 0) for item in items) or 1
        rows = []
        for item in items:
            value = int(item.get(value_key, 0) or 0)
            width = max(6, round((value / max_value) * 100)) if value > 0 else 0
            rows.append(
                '<div class="trend-bar-row">'
                + f'<div class="trend-bar-meta"><strong>{_esc(item.get("label", ""))}</strong><span class="muted">{_esc(item.get("repo", ""))}</span></div>'
                + f'<div class="trend-bar-track"><div class="trend-bar-fill" style="width:{width}%"></div></div>'
                + f'<div class="trend-bar-value">{_esc(value)}</div>'
                + '</div>'
            )
        return "".join(rows)

    def _table_rows(items: list[dict], columns: list[tuple[str, str]], empty_text: str) -> str:
        if not items:
            return f'<tr><td colspan="{len(columns)}">{_esc(empty_text)}</td></tr>'
        rows = []
        for item in items:
            rows.append("<tr>" + "".join(f"<td>{_esc(item.get(key, ''))}</td>" for key, _label in columns) + "</tr>")
        return "".join(rows)

    body = f"""
{_flash(notice, error)}
<section class="trends-shell">
  <section class="trend-summary-grid">
    <div class="trend-summary-card"><span class="baseline-label">Scans in History</span><strong>{_esc(summary.get("scan_count", 0))}</strong></div>
    <div class="trend-summary-card"><span class="baseline-label">Findings Captured</span><strong>{_esc(summary.get("total_findings", 0))}</strong></div>
    <div class="trend-summary-card"><span class="baseline-label">Critical in Prod</span><strong>{_esc(summary.get("critical_prod_total", 0))}</strong></div>
    <div class="trend-summary-card"><span class="baseline-label">Models Used</span><strong>{_esc(summary.get("models_used", 0))}</strong></div>
  </section>
  <section class="trend-grid">
    <section class="card">
      <h2 style="margin:0 0 10px">Findings Over Time</h2>
      <div class="trend-bars">{_bar_rows(list(trends.get("findings_over_time") or []), value_key="value", empty_text="No scan history available for findings trend.")}</div>
    </section>
    <section class="card">
      <h2 style="margin:0 0 10px">Critical in Prod Over Time</h2>
      <div class="trend-bars">{_bar_rows(list(trends.get("critical_over_time") or []), value_key="value", empty_text="No critical-in-prod trend data available.")}</div>
    </section>
  </section>
  <section class="trend-grid">
    <section class="card">
      <h2 style="margin:0 0 10px">New vs Fixed Findings</h2>
      <div class="table-shell trend-table-shell">
        <table>
          <thead><tr><th>Date</th><th>Repo</th><th>New</th><th>Fixed</th></tr></thead>
          <tbody>{_table_rows(list(trends.get("new_fixed_over_time") or []), [("label","Date"),("repo","Repo"),("new_count","New"),("fixed_count","Fixed")], "No baseline-aware trend data available yet.")}</tbody>
        </table>
      </div>
    </section>
    <section class="card">
      <h2 style="margin:0 0 10px">Top Repos by Risk</h2>
      <div class="table-shell trend-table-shell">
        <table>
          <thead><tr><th>Repo</th><th>Scans</th><th>Risk Score</th><th>Critical in Prod</th><th>Last Findings</th></tr></thead>
          <tbody>{_table_rows(list(trends.get("top_repos_by_risk") or []), [("repo","Repo"),("scans","Scans"),("risk_score","Risk"),("critical_prod","Critical in Prod"),("latest_total","Last Findings")], "No repository trend data available.")}</tbody>
        </table>
      </div>
    </section>
  </section>
  <section class="trend-grid">
    <section class="card">
      <h2 style="margin:0 0 10px">Top Noisy Rules</h2>
      <div class="table-shell trend-table-shell">
        <table>
          <thead><tr><th>Rule</th><th>Hits</th><th>Suppressed</th></tr></thead>
          <tbody>{_table_rows(list(trends.get("top_noisy_rules") or []), [("rule","Rule"),("hits","Hits"),("suppressed","Suppressed")], "Rule-level trend data will appear after new scans are saved.")}</tbody>
        </table>
      </div>
    </section>
    <section class="card">
      <h2 style="margin:0 0 10px">Suppression Rate by Rule</h2>
      <div class="table-shell trend-table-shell">
        <table>
          <thead><tr><th>Rule</th><th>Suppressed</th><th>Total</th><th>Rate</th></tr></thead>
          <tbody>{_table_rows([{**item, "rate": f"{item.get('rate_pct', 0)}%"} for item in list(trends.get("suppression_rate_by_rule") or [])], [("rule","Rule"),("suppressed","Suppressed"),("total","Total"),("rate","Rate")], "Suppression-rate trends will appear after new scans are saved.")}</tbody>
        </table>
      </div>
    </section>
  </section>
  <section class="card">
    <h2 style="margin:0 0 10px">LLM Review Failure Rate by Model</h2>
    <div class="table-shell trend-table-shell">
      <table>
        <thead><tr><th>Model</th><th>Scans</th><th>Failed Scans</th><th>Failed Batches</th><th>Failure Rate</th><th>Reviewed</th><th>Downgraded</th></tr></thead>
        <tbody>{_table_rows([{**item, "failure_rate": f"{item.get('failure_rate_pct', 0)}%"} for item in list(trends.get("llm_review_failure_rate_by_model") or [])], [("model","Model"),("scans","Scans"),("failed_scans","Failed Scans"),("failed_batches","Failed Batches"),("failure_rate","Failure Rate"),("reviewed","Reviewed"),("downgraded","Downgraded")], "No LLM trend data available yet.")}</tbody>
      </table>
    </div>
  </section>
</section>"""
    return _layout(title="Trends", body=body, active="trends", show_scan_results=show_scan_results, csrf_token=csrf_token)


def render_settings_page(
    *,
    bitbucket_url: str,
    output_dir: str,
    llm_cfg: dict,
    tls_cfg: dict,
    state_dir: str = "",
    legacy_runtime_files: list[dict] | None = None,
    notice: str = "",
    error: str = "",
    show_scan_results: bool = True,
    csrf_token: str = "",
) -> bytes:
    legacy_runtime_files = legacy_runtime_files or []
    legacy_runtime_notice = ""
    if legacy_runtime_files:
        legacy_items = "".join(
            f'<li><strong>{_esc(item.get("label", ""))}</strong>: legacy file <code>{_esc(item.get("legacy_path", ""))}</code> is no longer authoritative. Active file: <code>{_esc(item.get("active_path", ""))}</code></li>'
            for item in legacy_runtime_files
        )
        legacy_runtime_notice = f"""
    <div class="warn-box stack" style="margin-bottom:12px">
      <strong>Legacy repo-root runtime files detected</strong>
      <div class="muted">The app now reads runtime state from <code>{_esc(state_dir)}</code>. Editing the old repo-root files will not change live settings.</div>
      <ul style="margin:0;padding-left:18px">{legacy_items}</ul>
    </div>"""
    body = f"""
{_flash(notice, error)}
  <section class="card" style="max-width:760px">
    <h2 style="margin:0 0 12px">Settings</h2>
    {legacy_runtime_notice}
    <form method="post" action="/settings/save" class="stack">
      {_csrf_field(csrf_token)}
      <div><label>Bitbucket URL</label><input type="text" value="{_esc(bitbucket_url)}" disabled></div>
    <div><label>Bitbucket CA Bundle</label><input type="text" name="bitbucket_ca_bundle" value="{_esc(tls_cfg.get('ca_bundle',''))}" placeholder="Path to corporate root CA PEM/CRT file"></div>
    <label class="checkline"><input type="checkbox" name="bitbucket_verify_ssl" value="true"{" checked" if tls_cfg.get("verify_ssl", True) else ""}><span>Verify Bitbucket TLS certificates</span></label>
    <div><label>Output Directory</label><input type="text" name="output_dir" value="{_esc(output_dir)}"></div>
    <div><label>LLM URL</label><input type="text" name="llm_url" value="{_esc(llm_cfg.get('base_url',''))}"></div>
    <div><label>LLM Model</label><input type="text" name="llm_model" value="{_esc(llm_cfg.get('model',''))}"></div>
    <div><label>Report LLM Detail Timeout (seconds)</label><input type="number" min="30" max="600" step="1" name="report_detail_timeout_s" value="{_esc(llm_cfg.get('report_detail_timeout_s', 180))}"></div>
    <div><button type="submit">Save Settings</button></div>
  </form>
</section>"""
    return _layout(title="Settings", body=body, active="settings", show_scan_results=show_scan_results, csrf_token=csrf_token)


def render_help_page(*, notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "") -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="card stack" style="max-width:1080px">
  <h2 style="margin:0">Help</h2>
  <p class="muted" style="margin:0">Reference documentation for the AI Security &amp; Compliance Scanner.</p>

  <section>
    <h3 style="margin:0 0 8px">Purpose</h3>
    <p>This tool scans Bitbucket repositories to identify AI usage, insecure AI patterns, policy-relevant findings, and related code or configuration risks. It is optimized for internal review workflows where signal quality matters more than broad coverage.</p>
  </section>

  <section>
    <h3 style="margin:0 0 8px">Main Components</h3>
    <table>
      <thead><tr><th>Component</th><th>Role</th></tr></thead>
      <tbody>
        <tr><td>Bitbucket Access</td><td>Connects to the on-prem Bitbucket server, validates the PAT, lists visible projects and repositories, fetches repository metadata, and clones the selected repositories into a temporary workspace for local analysis.</td></tr>
        <tr><td>Detector</td><td>Parses repository content and identifies AI-related patterns, secrets, local model usage, model-serving indicators, risky AI data flows, and context such as documentation, tests, deleted files, and production-relevant paths.</td></tr>
        <tr><td>Security Analyzer</td><td>Applies internal policy logic, context-aware severity adjustments, provider classification, and remediation mapping so raw detections become prioritized security findings with better precision.</td></tr>
        <tr><td>LLM Review</td><td>Uses a local model through Ollama to review eligible findings, attempt structured adjudication, and downgrade, dismiss, or keep them with model-assisted reasoning when the selected model is reliable enough.</td></tr>
        <tr><td>Triage Store</td><td>Persists To Mitigate, Accept Risk, and Suppress decisions with actor, timestamp, and reason so analyst decisions survive page refreshes, report review, and later scan sessions.</td></tr>
        <tr><td>Reporting</td><td>Generates CSV and HTML reports, records scan history, exposes logs for review and download, and provides a durable artifact for engineers, AppSec reviewers, and management summaries.</td></tr>
      </tbody>
    </table>
  </section>

  <section>
    <h3 style="margin:0 0 8px">Technology Stack</h3>
    <table>
      <thead><tr><th>Area</th><th>Technology</th><th>Usage</th></tr></thead>
      <tbody>
        <tr><td>Backend</td><td>Python 3</td><td>Core scan orchestration, report generation, persistence, and HTTP server behavior.</td></tr>
        <tr><td>Web Server</td><td>Built-in `http.server`</td><td>Serves the local internal web UI, APIs, and SSE activity-log stream.</td></tr>
        <tr><td>Frontend</td><td>Server-rendered HTML, CSS, and targeted JavaScript</td><td>Implements the local web interface without a full SPA framework.</td></tr>
        <tr><td>Source Control Access</td><td>Git + Bitbucket REST API</td><td>Lists repositories, resolves metadata, and performs local shallow clones for scanning.</td></tr>
        <tr><td>LLM Runtime</td><td>Ollama</td><td>Provides local LLM-based review and report enrichment without external cloud dependency.</td></tr>
        <tr><td>Persistence</td><td>SQLite + JSON files</td><td>Stores scan history, logs, triage state, configuration, and generated artifacts.</td></tr>
        <tr><td>Reports</td><td>HTML + CSV</td><td>Produces analyst-friendly and export-friendly scan outputs.</td></tr>
      </tbody>
    </table>
  </section>

  <section>
    <h3 style="margin:0 0 8px">Detection Engine</h3>
    <p>The detection engine is regex- and context-driven. It scans repository content for known AI usage patterns, secret exposure, risky AI integrations, model-serving indicators, and unsafe data flows, then applies context-aware filtering before policy analysis and optional LLM review.</p>
    <p><strong>Pattern categories:</strong> provider and SDK usage, secrets and tokens, prompt and output handling risks, local model and serving patterns, vector/RAG components, configuration exposure, CI/CD and infrastructure references, and agent or gateway frameworks.</p>
    <p><strong>Scanned file types:</strong> common source files, configuration files, notebooks, scripts, markup, manifests, dependency files, environment files, and selected structured text formats such as JSON, YAML, TOML, INI, Docker-related files, and CI definitions.</p>
  </section>

  <section>
    <h3 style="margin:0 0 8px">How It Works</h3>
    <ol style="margin:0;padding-left:18px">
      <li>Login with a Bitbucket Personal Access Token.</li>
      <li>Select a project and one or more repositories in <strong>New Scan</strong>.</li>
      <li>Choose the LLM model used for review, then start the scan.</li>
      <li>The tool clones repositories, scans files, optionally runs LLM review, then generates reports.</li>
      <li>During or after the scan, use <strong>To Mitigate</strong>, <strong>Accept Risk</strong>, or <strong>Suppress</strong> to triage findings.</li>
      <li>Use <strong>Past Scans</strong> to revisit prior scans, open reports, download CSV output, or inspect logs.</li>
    </ol>
  </section>

  <section>
    <h3 style="margin:0 0 8px">Pages</h3>
    <table>
      <thead><tr><th>Page</th><th>What It Is For</th></tr></thead>
      <tbody>
        <tr><td>New Scan</td><td>Select project, repositories, and LLM model for a new run.</td></tr>
        <tr><td>Scan Workspace</td><td>Open a specific scan and switch between the live activity view and the finished detailed report.</td></tr>
        <tr><td>AI Inventory</td><td>Review the latest known AI usage profile per repository, including providers, models, and usage patterns.</td></tr>
        <tr><td>Past Scans</td><td>Search, filter, sort, and open results from previous scans.</td></tr>
        <tr><td>Settings</td><td>Configure output directory and LLM connection settings.</td></tr>
        <tr><td>Help</td><td>Understand the tool architecture, workflow, and limitations.</td></tr>
      </tbody>
    </table>
  </section>

    <section>
      <h3 style="margin:0 0 8px">Outputs</h3>
      <ul style="margin:0;padding-left:18px">
        <li><strong>AI Inventory:</strong> summary of repos using AI, detected providers and models, and where embeddings, prompt handling, model serving, and agent/tool-use patterns appear.</li>
        <li><strong>HTML Report:</strong> analyst-friendly report with summary, findings, and remediation context.</li>
        <li><strong>CSV Report:</strong> flat export for filtering, tracking, and external review.</li>
        <li><strong>Scan Log:</strong> terminal-like execution log showing scan phases and processing activity.</li>
      <li><strong>History Record:</strong> persisted scan metadata including duration, status, model used, and report references.</li>
    </ul>
  </section>

  <section>
    <h3 style="margin:0 0 8px">Triage States</h3>
    <table>
      <thead><tr><th>State</th><th>Meaning</th></tr></thead>
      <tbody>
        <tr><td>To Mitigate</td><td>The finding remains relevant and should be tracked for remediation.</td></tr>
        <tr><td>Accept Risk</td><td>The finding is acknowledged but intentionally accepted with a reason.</td></tr>
        <tr><td>Suppress</td><td>The finding is considered noise or not actionable and is hidden from the active findings set.</td></tr>
        <tr><td>Reset</td><td>Removes the triage decision and returns the finding to the active findings flow.</td></tr>
      </tbody>
    </table>
  </section>

  <section>
    <h3 style="margin:0 0 8px">Known Limitations</h3>
    <ul style="margin:0;padding-left:18px">
      <li>LLM review quality depends heavily on the selected local model. Small models may fail structured review or produce weak decisions.</li>
      <li>The tool is currently optimized for a single trusted operator workflow, even though parts of the architecture already anticipate stronger access control.</li>
      <li>Static scanning can identify likely issues, but it cannot prove exploitability or runtime behavior on its own.</li>
      <li>Generated reports reflect the scan state at generation time. Triage actions performed after report generation do not automatically rewrite those files.</li>
      <li>Precision is intentionally prioritized over maximum coverage, so some low-signal or ambiguous patterns may be skipped.</li>
    </ul>
  </section>
</section>"""
    return _layout(title="Help", body=body, active="help", show_scan_results=show_scan_results, csrf_token=csrf_token)
