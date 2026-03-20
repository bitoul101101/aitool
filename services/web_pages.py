from __future__ import annotations

from datetime import datetime
from html import escape
from urllib.parse import quote

from services.rule_labels import format_rule_label
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


def _current_scan_nav_item(current_scan: dict | None, active: str) -> str:
    if not current_scan:
        return ""
    scan_id = str(current_scan.get("scan_id", "") or "").strip()
    if not scan_id:
        return ""
    return f'<a class="nav current-scan-nav{" active" if active == "current_scan" else ""}" href="/scan/{_esc(scan_id)}?tab=activity">Current Scan</a>'


def _layout(*, title: str, body: str, active: str = "", show_nav: bool = True, show_scan_results: bool = True, csrf_token: str = "", current_scan: dict | None = None) -> bytes:
    nav = ""
    body_class = "login-page" if not show_nav else ""
    header_html = ""
    if show_nav:
        current_scan_nav = _current_scan_nav_item(current_scan, active)
        nav = (
            '<div class="header-nav">'
            + f'<a class="nav{" active" if active == "new_scan" else ""}" href="/scan?new=1">New Scan</a>'
            + current_scan_nav
            + f'<a class="nav{" active" if active == "history" else ""}" href="/history">Past Scans</a>'
            + f'<a class="nav{" active" if active == "findings" else ""}" href="/findings">Findings</a>'
            + f'<a class="nav{" active" if active == "trends" else ""}" href="/trends">Trends</a>'
            + f'<a class="nav{" active" if active == "inventory" else ""}" href="/inventory">AI Inventory</a>'
            + f'<a class="nav{" active" if active == "settings" else ""}" href="/settings">Settings</a>'
            + f'<a class="nav{" active" if active == "help" else ""}" href="/help">Help</a>'
            + '</div>'
            + '<div class="header-actions">'
            + f'<form class="exit-form" method="post" action="/app/exit">{_csrf_field(csrf_token)}<button type="submit" class="warn">Exit</button></form>'
            + "</div>"
        )
        header_html = f'<header><a class="brand-lockup" href="/scan" aria-label="PhantomLM home"><img src="/assets/phantomlm_logo.png" alt="PhantomLM"></a>{nav}</header>'
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(f"PhantomLM | {title}")}</title>
<link rel="stylesheet" href="/assets/main.css">
</head>
<body class="{body_class}">
{header_html}
<div id="connection-banner" class="connection-banner hidden" role="status" aria-live="polite">
  <strong>Connection lost.</strong> Trying to reconnect to the local PhantomLM server...
</div>
<main>{body}</main>
<script src="/assets/layout.js" defer></script>
</body>
</html>"""
    return html.encode("utf-8")


def render_login_page(*, bitbucket_url: str, has_saved_pat: bool, notice: str = "", error: str = "", csrf_token: str = "") -> bytes:
    body = f"""
  {_flash(notice, error)}
  <section class="login-brand">
    <img src="/assets/phantomlm_logo.png" alt="PhantomLM">
  </section>
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
    <div class="login-actions"><button type="submit" autofocus>Login</button></div>
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
    current_scan: dict | None = None,
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
        sev_css = {
            1: "sev-critical",
            2: "sev-high",
            3: "sev-medium",
            4: "sev-low",
        }.get(sev, "sev-low")
        return f'<span class="sev-chip {sev_css}">{_esc(label)}</span>'

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
          <div class="hardware-stat"><span class="baseline-label">CPU</span><strong id="hardware-cpu">{_esc(hardware.get("cpu_percent", "Sampling..."))}</strong><div class="metric-sparkline" id="hardware-cpu-graph" aria-hidden="true"></div></div>
          <div class="hardware-stat"><span class="baseline-label">RAM</span><strong id="hardware-ram">{_esc(hardware.get("ram_text", "Unavailable"))}</strong><div class="metric-sparkline" id="hardware-ram-graph" aria-hidden="true"></div></div>
          <div class="hardware-stat"><span class="baseline-label">GPU</span><strong id="hardware-gpu">{_esc(hardware.get("gpu_text", "Unavailable"))}</strong><div class="metric-sparkline" id="hardware-gpu-graph" aria-hidden="true"></div></div>
          <div class="hardware-stat"><span class="baseline-label">Disk I/O</span><strong id="hardware-disk-io">{_esc(hardware.get("disk_io_text", "Sampling..."))}</strong><div class="disk-io-bars" id="hardware-disk-bars" aria-hidden="true"><div class="disk-io-row"><span class="disk-io-label">Read</span><div class="disk-io-track"><div class="disk-io-fill read" id="hardware-disk-read-fill"></div></div><span class="disk-io-value" id="hardware-disk-read-value">-</span></div><div class="disk-io-row"><span class="disk-io-label">Write</span><div class="disk-io-track"><div class="disk-io-fill write" id="hardware-disk-write-fill"></div></div><span class="disk-io-value" id="hardware-disk-write-value">-</span></div></div></div>
        </div>
      </div>
    </section>"""
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
    resume_scan_action = (
        f'<a class="btn alt" id="resume-scan-btn" href="/scan/{_esc(scan_id)}?tab=activity">Resume Scan</a>'
        if start_blocked and scan_id
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
      <div class="repo-toolbar repo-controls-row">
        <div><label>Search Repositories</label><input type="search" id="repo-search" placeholder="Search by repo name"></div>
        <div><label>Scan Scope</label><select name="scan_scope" id="scan-scope-select">{scope_options}</select></div>
        <div><label>LLM Model</label><select name="llm_model" id="llm-model-select">{model_options}</select></div>
        <div class="inline repo-action-bar" style="justify-content:flex-start;align-items:end;gap:8px">
          <button type="submit" id="start-scan-btn"{" disabled" if start_blocked or (not selected and not local_repo_path_value) else ""}>Start Scan</button>
        </div>
      </div>
      <div class="repo-toolbar repo-local-row">
        <div class="inline" style="gap:8px;align-items:center">
          <button type="button" class="ghost" id="local-repo-toggle-btn">Local Repo</button>
          <div class="inline{" hidden" if not local_repo_path_value else ""}" id="local-repo-row" style="gap:8px;align-items:center;flex:1 1 auto">
            <input type="text" name="local_repo_path" id="local-repo-path-input" value="{_esc(local_repo_path_value)}" placeholder="Local Repository Path e.g. C:\\repo or /home/user/repo">
            <button type="button" class="ghost" id="local-repo-browse-btn">Browse...</button>
          </div>
        </div>
      </div>
      <div class="repo-toolbar">
        <div id="compare-ref-wrap"{" class=\"hidden\"" if scope_value != "branch_diff" else ""}><label>Compare Branch</label><input type="text" name="compare_ref" id="compare-ref-input" value="{_esc(compare_ref_value)}" placeholder="e.g. master"></div>
        <div></div>
        <div></div>
        <div></div>
      </div>
      <div class="repo-notices">
        <div class="warn-box{" hidden" if not running_notice else ""}" id="running-scan-notice">{_esc(running_notice)}{f'<div class="resume-scan-inline">{resume_scan_action}</div>' if resume_scan_action else ''}</div>
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
    nav_active = "current_scan" if scan_id and current_scan and str(current_scan.get("scan_id", "")) == str(scan_id) else ("" if scan_id else "new_scan")
    return _layout(title="Scan", body=body, active=nav_active, show_scan_results=show_scan_results, csrf_token=csrf_token, current_scan=current_scan)


def render_history_page(*, history: list[dict], notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "", current_scan: dict | None = None) -> bytes:
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
            f'<td><span class="pill {status_class}">{_esc(state.title())}</span></td>'
            f'<td>{_esc(last_error or "—")}</td>'
            f'<td>{details_link}</td></tr>'
        )
    body = f"""
{_flash(notice, error)}
<section class="card history-shell">
  <form method="post" action="/history/delete" id="history-form" class="history-form">
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
            <th><input type="checkbox" id="history-select-page" aria-label="Select all displayed scans"></th>
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
            <th data-sort="text">Status</th>
            <th>Error</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>{''.join(rows) or '<tr><td colspan="15">No scan history available.</td></tr>'}</tbody>
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
    return _layout(title="Past Scans", body=body, active="history", show_scan_results=show_scan_results, csrf_token=csrf_token, current_scan=current_scan)


def render_findings_page(*, findings: list[dict], notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "", current_scan: dict | None = None) -> bytes:
    projects = sorted({str(item.get("project_key", "")) for item in findings if item.get("project_key")})
    repos = sorted({str(item.get("repo", "")) for item in findings if item.get("repo")})
    rules = sorted({
        str(item.get("rule_label", "") or format_rule_label(str(item.get("rule", "") or ""), str(item.get("capability", "") or "")))
        for item in findings
        if item.get("rule") or item.get("rule_label")
    })
    statuses = sorted({str(item.get("status_label", "")) for item in findings if item.get("status_label")})
    severities = sorted({str(item.get("severity_label", "")) for item in findings if item.get("severity_label")})

    def _opts(values: list[str], label: str) -> str:
        return f'<option value="">{_esc(label)}</option>' + "".join(f'<option value="{_esc(v)}">{_esc(v)}</option>' for v in values)

    def _pill(status: str) -> str:
        key = str(status or "").lower().replace(" ", "_")
        css = {
            "open": "status-running",
            "reviewed": "status-done",
            "accepted_risk": "status-stopped",
            "suppressed": "status-stopped",
            "fixed": "",
        }.get(key, "")
        return f'<span class="pill {css}">{_esc(status)}</span>'

    def _severity_chip(detail: dict) -> str:
        sev = int(detail.get("severity", 4) or 4)
        label = detail.get("severity_label", str(sev))
        sev_css = {
            1: "sev-critical",
            2: "sev-high",
            3: "sev-medium",
            4: "sev-low",
        }.get(sev, "sev-low")
        return f'<span class="sev-chip {sev_css}">{_esc(label)}</span>'

    rows = []
    for item in findings:
        date_text, time_text, ts = _fmt_dt(str(item.get("last_seen_at", "") or item.get("first_seen_at", "")))
        rule_label = str(item.get("rule_label", "") or format_rule_label(str(item.get("rule", "") or ""), str(item.get("capability", "") or "")))
        details_link = ""
        if item.get("last_seen_scan_id"):
            details_link = f'<a class="icon-link" href="/scan/{_esc(item.get("last_seen_scan_id", ""))}?tab=results" title="Open latest scan results"><img src="{DETAILS_ICON}" alt="Details"></a>'
        file_line = _esc(item.get("file", ""))
        line_value = str(item.get("line", "") or "").strip()
        if line_value:
            file_line += f":{_esc(line_value)}"
        rows.append(
            f'<tr data-project="{_esc(item.get("project_key", ""))}" data-repo="{_esc(item.get("repo", ""))}" data-rule="{_esc(rule_label)}" data-status="{_esc(item.get("status_label", ""))}" data-severity="{_esc(item.get("severity_label", ""))}" data-ts="{ts}">'
            f'<td><input type="checkbox" class="finding-check" name="hashes" value="{_esc(item.get("hash", ""))}"></td>'
            f'<td>{_pill(item.get("status_label", "Open"))}</td>'
            f'<td>{_severity_chip(item)}</td>'
            f'<td>{_esc(rule_label)}</td>'
            f'<td>{_esc(item.get("project_key", ""))}</td>'
            f'<td>{_esc(item.get("repo", ""))}</td>'
            f'<td>{file_line}</td>'
            f'<td>{_esc(item.get("description", ""))}</td>'
            f'<td><div>{_esc(date_text)}</div><div class="history-time">{_esc(time_text)}</div></td>'
            f'<td>{_esc(item.get("scan_count", 0))}</td>'
            f'<td>{details_link}</td>'
            '</tr>'
        )

    body = f"""
{_flash(notice, error)}
  <section class="card findings-shell">
    <form method="post" action="/findings/bulk" id="findings-form" class="findings-form">
    {_csrf_field(csrf_token)}
    <section class="trend-summary-grid" style="margin-bottom:12px">
      <div class="trend-summary-card"><span class="baseline-label">Total</span><strong>{_esc(len(findings))}</strong></div>
      <div class="trend-summary-card"><span class="baseline-label">Open</span><strong>{_esc(sum(1 for item in findings if item.get("status") == "open"))}</strong></div>
      <div class="trend-summary-card"><span class="baseline-label">Accepted Risk</span><strong>{_esc(sum(1 for item in findings if item.get("status") == "accepted_risk"))}</strong></div>
      <div class="trend-summary-card"><span class="baseline-label">Suppressed</span><strong>{_esc(sum(1 for item in findings if item.get("status") == "false_positive"))}</strong></div>
    </section>
    <div class="history-toolbar filters-row">
      <input type="search" id="findings-search" placeholder="Search findings">
      <select id="findings-filter-project">{_opts(projects, 'All Projects')}</select>
      <select id="findings-filter-repo">{_opts(repos, 'All Repos')}</select>
      <select id="findings-filter-status">{_opts(statuses, 'All Statuses')}</select>
      <select id="findings-filter-severity">{_opts(severities, 'All Severities')}</select>
      <select id="findings-filter-rule">{_opts(rules, 'All Rules')}</select>
      <button type="button" class="ghost" id="reset-findings-filters">Reset</button>
    </div>
    <div class="history-toolbar filters-row" style="margin-top:10px">
      <select name="action" id="findings-bulk-action">
        <option value="">Bulk Action</option>
        <option value="reviewed">Mark Reviewed</option>
        <option value="accepted_risk">Accept Risk</option>
        <option value="false_positive">Suppress</option>
        <option value="reset">Reset</option>
      </select>
      <input type="text" name="note" id="findings-bulk-note" placeholder="Note for Accept Risk / Suppress">
      <button type="submit" class="warn hidden" id="apply-findings-action-btn">Apply to Selected</button>
    </div>
      <div class="table-shell findings-table-shell">
        <table id="findings-table">
        <thead>
          <tr>
            <th><input type="checkbox" id="findings-select-all" aria-label="Select all displayed findings"></th>
            <th data-sort="text">Status</th>
            <th data-sort="text">Severity</th>
            <th data-sort="text">Rule</th>
            <th data-sort="text">Project</th>
            <th data-sort="text">Repo</th>
            <th data-sort="text">File:Line</th>
            <th data-sort="text">Why Flagged</th>
            <th data-sort="datetime">Last Seen</th>
            <th data-sort="number">Scans</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>{''.join(rows) or '<tr><td colspan="11">No findings available.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="history-pagination">
      <button type="button" class="ghost" id="findings-prev-btn">Previous</button>
      <span class="page-info" id="findings-page-info">Page 1 of 1</span>
      <button type="button" class="ghost" id="findings-next-btn">Next</button>
    </div>
  </form>
</section>
<script src="/assets/findings_page.js" defer></script>"""
    return _layout(title="Findings", body=body, active="findings", show_scan_results=show_scan_results, csrf_token=csrf_token, current_scan=current_scan)


def render_results_page(
    *,
    scan_id: str,
    project_key: str,
    repo_label: str,
    state: str,
    html_name: str,
    html_detail_mode: str = "",
    csv_name: str = "",
    json_name: str = "",
    sarif_name: str = "",
    threat_dragon_name: str = "",
    log_url: str = "",
    started_at_utc: str = "",
    can_generate_html: bool = False,
    html_generation: dict | None = None,
    show_scan_results: bool = True,
    csrf_token: str = "",
    notice: str = "",
    error: str = "",
    current_scan: dict | None = None,
) -> bytes:
    workspace_tabs = _scan_workspace_tabs(scan_id, "results")
    html_generation = dict(html_generation or {})
    generation_state = str(html_generation.get("state", "") or "").lower()
    generation_active = generation_state in {"queued", "running"}
    generation_mode = str(html_generation.get("detail_mode", "") or "").strip().lower()
    generation_mode_label = "Fast" if generation_mode == "fast" else "Detailed"
    html_detail_mode = str(html_detail_mode or "").strip().lower()
    toolbar_actions = []
    if html_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(html_name)}" target="_blank">Open Raw HTML</a>')
        if can_generate_html and not generation_active and html_detail_mode == "fast":
            toolbar_actions.append(
                f'<form method="post" action="/scan/{_esc(scan_id)}/generate-html" class="triage-form inline-only">'
                f'{_csrf_field(csrf_token)}'
                '<input type="hidden" name="html_detail_mode" value="detailed" />'
                '<button type="submit" class="btn alt">Generate Detailed HTML</button>'
                '</form>'
            )
    elif can_generate_html and not generation_active:
        toolbar_actions.append(
            f'<form method="post" action="/scan/{_esc(scan_id)}/generate-html" class="triage-form inline-only">'
            f'{_csrf_field(csrf_token)}'
            '<input type="hidden" name="html_detail_mode" value="fast" />'
            '<button type="submit" class="btn alt">Generate Fast HTML</button>'
            '</form>'
        )
        toolbar_actions.append(
            f'<form method="post" action="/scan/{_esc(scan_id)}/generate-html" class="triage-form inline-only">'
            f'{_csrf_field(csrf_token)}'
            '<input type="hidden" name="html_detail_mode" value="detailed" />'
            '<button type="submit" class="btn alt">Generate Detailed HTML</button>'
            '</form>'
        )
    elif generation_active:
        toolbar_actions.append(f'<button type="button" class="btn alt disabled" disabled>Generating {generation_mode_label} HTML...</button>')
    if csv_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(csv_name)}" download>Download CSV File</a>')
    if json_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(json_name)}" download>Download JSON</a>')
    if sarif_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(sarif_name)}" download>Download SARIF</a>')
    if threat_dragon_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(threat_dragon_name)}" download>Download Threat Dragon</a>')
    if log_url:
        toolbar_actions.append(f'<a class="btn ghost" href="{_esc(log_url)}" download>Download Logs</a>')
    toolbar_actions.append(
        f'<form method="post" action="/scan/{_esc(scan_id)}/replay-threat-model" class="triage-form inline-only">'
        f'{_csrf_field(csrf_token)}'
        '<button type="submit" class="btn ghost">Replay Threat Model</button>'
        '</form>'
    )
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
            f'<div class="report-progress-head"><strong>{_esc(generation_mode_label)} HTML Report Generation</strong><span class="pill">{_esc(state_label)}</span></div>'
            f'<div class="muted" id="report-progress-message">{_esc(progress_text or "Preparing report generation...")}</div>'
            f'<div class="report-progress-bar"><div class="report-progress-fill" id="report-progress-fill" style="width:{pct}%"></div></div>'
            f'<div class="report-progress-meta" id="report-progress-meta">{_esc(meta_text)}</div>'
            '</section>'
        )
    if html_name:
        results_body = f'<iframe class="results-frame" src="/reports/{_esc(html_name)}" title="Detailed Report"></iframe>'
    elif can_generate_html:
        results_body = (
            '<section class="card empty-state"><strong>HTML report has not been generated yet.</strong>'
            '<div class="muted" style="margin-top:6px">Generate a fast or detailed HTML report when you need it. CSV and log artifacts remain available immediately.</div>'
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
    nav_active = "current_scan" if current_scan and str(current_scan.get("scan_id", "")) == str(scan_id) else ""
    return _layout(title="Results", body=body, active=nav_active, show_scan_results=show_scan_results, csrf_token=csrf_token, current_scan=current_scan)


def render_inventory_page(*, repo_inventory: list[dict], summary: dict, notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "", current_scan: dict | None = None) -> bytes:
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
    <div class="table-shell history-table-shell">
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
    return _layout(title="AI Inventory", body=body, active="inventory", show_scan_results=show_scan_results, csrf_token=csrf_token, current_scan=current_scan)


def render_trends_page(*, trends: dict, notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "", current_scan: dict | None = None) -> bytes:
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

    def _time_series_chart(items: list[dict], *, value_key: str, empty_text: str, y_label: str) -> str:
        if not items:
            return f'<div class="empty-state">{_esc(empty_text)}</div>'
        points = []
        values = []
        labels = []
        for item in items:
            try:
                value = int(item.get(value_key, 0) or 0)
            except Exception:
                value = 0
            values.append(value)
            labels.append(str(item.get("label", "") or ""))
        max_value = max(values) or 1
        width = 560
        height = 180
        pad_left = 36
        pad_right = 16
        pad_top = 18
        pad_bottom = 28
        plot_w = max(1, width - pad_left - pad_right)
        plot_h = max(1, height - pad_top - pad_bottom)
        step = plot_w / max(1, len(values) - 1)
        for index, value in enumerate(values):
            x = pad_left + (step * index if len(values) > 1 else plot_w / 2)
            y = pad_top + plot_h - ((value / max_value) * plot_h)
            points.append((x, y, value, labels[index]))
        line_points = " ".join(f"{x:.1f},{y:.1f}" for x, y, _v, _l in points)
        area_points = f"{pad_left:.1f},{pad_top + plot_h:.1f} " + line_points + f" {points[-1][0]:.1f},{pad_top + plot_h:.1f}"
        y_ticks = []
        for idx in range(4):
            tick_value = round(max_value * (3 - idx) / 3) if max_value else 0
            y = pad_top + (plot_h * idx / 3)
            y_ticks.append(
                f'<line x1="{pad_left}" y1="{y:.1f}" x2="{width - pad_right}" y2="{y:.1f}" class="trend-ts-grid"></line>'
                f'<text x="{pad_left - 8}" y="{y + 4:.1f}" class="trend-ts-axis" text-anchor="end">{tick_value}</text>'
            )
        x_labels = []
        for x, _y, _v, label in points:
            short = label[5:] if len(label) >= 10 and label[4] == "-" else label
            x_labels.append(f'<text x="{x:.1f}" y="{height - 8}" class="trend-ts-axis" text-anchor="middle">{_esc(short)}</text>')
        dots = "".join(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" class="trend-ts-dot"><title>{_esc(label)}: {value}</title></circle>'
            for x, y, value, label in points
        )
        latest_value = values[-1] if values else 0
        return (
            '<div class="trend-timeseries">'
            f'<div class="trend-timeseries-meta"><span class="baseline-label">{_esc(y_label)}</span><strong>{latest_value}</strong></div>'
            f'<svg viewBox="0 0 {width} {height}" class="trend-timeseries-svg" aria-label="{_esc(y_label)} over time">'
            + "".join(y_ticks)
            + f'<polygon points="{area_points}" class="trend-ts-area"></polygon>'
            + f'<polyline points="{line_points}" class="trend-ts-line"></polyline>'
            + dots
            + "".join(x_labels)
            + '</svg></div>'
        )

    def _table_rows(items: list[dict], columns: list[tuple[str, str]], empty_text: str) -> str:
        if not items:
            return f'<tr><td colspan="{len(columns)}">{_esc(empty_text)}</td></tr>'
        rows = []
        for item in items:
            cells = []
            for key, _label in columns:
                value = item.get(key, "")
                if key == "rule":
                    value = format_rule_label(str(value or ""))
                cells.append(f"<td>{_esc(value)}</td>")
            rows.append("<tr>" + "".join(cells) + "</tr>")
        return "".join(rows)

    def _trend_panel(*, card_id: str, title: str, body_html: str, col_span: int, row_span: int) -> str:
        return (
            f'<section class="card trend-card trend-panel" data-card-id="{_esc(card_id)}" '
            f'data-col-span="{int(col_span)}" data-row-span="{int(row_span)}" '
            f'style="--col-span:{int(col_span)};--row-span:{int(row_span)}">'
            f'<div class="trend-card-head">'
            f'<h2 style="margin:0">{_esc(title)}</h2>'
            f'</div>'
            f'<div class="trend-card-body">{body_html}</div>'
            f'</section>'
        )

    body = f"""
  {_flash(notice, error)}
  <section class="trends-shell">
    <section class="trend-summary-grid">
      <div class="trend-summary-card"><span class="baseline-label">Scans in History</span><strong>{_esc(summary.get("scan_count", 0))}</strong></div>
      <div class="trend-summary-card"><span class="baseline-label">Findings Captured</span><strong>{_esc(summary.get("total_findings", 0))}</strong></div>
      <div class="trend-summary-card"><span class="baseline-label">Critical in Prod</span><strong>{_esc(summary.get("critical_prod_total", 0))}</strong></div>
      <div class="trend-summary-card"><span class="baseline-label">Models Used</span><strong>{_esc(summary.get("models_used", 0))}</strong></div>
    </section>
    <div class="trend-dashboard-tools">
      <div class="muted">Choose a fixed layout for the dashboard.</div>
      <label class="trend-layout-picker"><span>Layout</span><select id="trends-layout-select"><option value="balanced">Balanced</option><option value="compact">Compact</option></select></label>
    </div>
    <section class="trend-grid trend-dashboard" id="trend-dashboard">
      {_trend_panel(
        card_id="findings_over_time",
        title="Findings Over Time",
        body_html=_time_series_chart(list(trends.get("findings_over_time") or []), value_key="value", empty_text="No scan history available for findings trend.", y_label="Findings"),
        col_span=6,
        row_span=8,
      )}
      {_trend_panel(
        card_id="critical_over_time",
        title="Critical in Prod Over Time",
        body_html=_time_series_chart(list(trends.get("critical_over_time") or []), value_key="value", empty_text="No critical-in-prod trend data available.", y_label="Critical in Prod"),
        col_span=6,
        row_span=8,
      )}
      {_trend_panel(
        card_id="new_fixed_over_time",
        title="New vs Fixed Findings",
        body_html=(
          '<div class="table-shell trend-table-shell"><table>'
          '<thead><tr><th>Date</th><th>Repo</th><th>New</th><th>Fixed</th></tr></thead>'
          f'<tbody>{_table_rows(list(trends.get("new_fixed_over_time") or []), [("label","Date"),("repo","Repo"),("new_count","New"),("fixed_count","Fixed")], "No baseline-aware trend data available yet.")}</tbody>'
          '</table></div>'
        ),
        col_span=5,
        row_span=8,
      )}
        {_trend_panel(
          card_id="top_repos_by_risk",
          title="Top Repos by Risk",
          body_html=(
            '<div class="table-shell trend-table-shell"><table>'
            '<thead><tr><th>Repo</th><th>Scans</th><th>Risk Score</th><th>Critical in Prod</th></tr></thead>'
            f'<tbody>{_table_rows(list(trends.get("top_repos_by_risk") or []), [("repo","Repo"),("scans","Scans"),("risk_score","Risk"),("critical_prod","Critical in Prod")], "No repository trend data available.")}</tbody>'
            '</table></div>'
          ),
          col_span=7,
          row_span=14,
        )}
      {_trend_panel(
        card_id="top_noisy_rules",
        title="Top Noisy Rules",
        body_html=(
          '<div class="table-shell trend-table-shell"><table>'
          '<thead><tr><th>Rule</th><th>Hits</th><th>Suppressed</th></tr></thead>'
          f'<tbody>{_table_rows(list(trends.get("top_noisy_rules") or []), [("rule","Rule"),("hits","Hits"),("suppressed","Suppressed")], "Rule-level trend data will appear after new scans are saved.")}</tbody>'
          '</table></div>'
        ),
        col_span=5,
        row_span=6,
      )}
      {_trend_panel(
        card_id="suppression_rate_by_rule",
        title="Suppression Rate by Rule",
        body_html=(
          '<div class="table-shell trend-table-shell"><table>'
          '<thead><tr><th>Rule</th><th>Suppressed</th><th>Total</th><th>Rate</th></tr></thead>'
          f'<tbody>{_table_rows([{**item, "rate": f"{item.get("rate_pct", 0)}%"} for item in list(trends.get("suppression_rate_by_rule") or [])], [("rule","Rule"),("suppressed","Suppressed"),("total","Total"),("rate","Rate")], "Suppression-rate trends will appear after new scans are saved.")}</tbody>'
          '</table></div>'
        ),
        col_span=5,
        row_span=6,
      )}
      {_trend_panel(
        card_id="llm_review_failure_rate_by_model",
        title="LLM Review Failure Rate by Model",
        body_html=(
          '<div class="table-shell trend-table-shell"><table>'
          '<thead><tr><th>Model</th><th>Scans</th><th>Failed Scans</th><th>Failed Batches</th><th>Failure Rate</th><th>Reviewed</th><th>Downgraded</th></tr></thead>'
          f'<tbody>{_table_rows([{**item, "failure_rate": f"{item.get("failure_rate_pct", 0)}%"} for item in list(trends.get("llm_review_failure_rate_by_model") or [])], [("model","Model"),("scans","Scans"),("failed_scans","Failed Scans"),("failed_batches","Failed Batches"),("failure_rate","Failure Rate"),("reviewed","Reviewed"),("downgraded","Downgraded")], "No LLM trend data available yet.")}</tbody>'
          '</table></div>'
        ),
        col_span=12,
        row_span=8,
      )}
    </section>
  </section>"""
    body += '<script src="/assets/trends_page.js" defer></script>'
    return _layout(title="Trends", body=body, active="trends", show_scan_results=show_scan_results, csrf_token=csrf_token, current_scan=current_scan)


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
    current_scan: dict | None = None,
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
    return _layout(title="Settings", body=body, active="settings", show_scan_results=show_scan_results, csrf_token=csrf_token, current_scan=current_scan)


def render_help_page(*, notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "", current_scan: dict | None = None) -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="wiki-shell">
    <section class="card wiki-doc">
      <div class="wiki-header">
        <div class="wiki-title-lockup">
          <img src="/assets/phantomlm_logo.png" alt="PhantomLM">
          <h2 style="margin:0">PhantomLM Wiki</h2>
        </div>
      </div>

    <section id="overview" class="wiki-section">
      <h3>Tool Description</h3>
      <p>This tool scans Bitbucket and local repositories to identify AI usage, insecure AI implementation patterns, secrets, risky integrations, model-serving exposure, and policy-relevant findings. It combines deterministic detection, policy-aware analysis, optional local LLM review, history tracking, triage workflows, findings management, and export artifacts for engineering and AppSec teams.</p>
      <div class="wiki-callout">
        <strong>Primary use case:</strong> internal AI/security review workflows where explainability, triage, and repeatable evidence matter more than raw detection volume.
      </div>
    </section>

    <section id="capabilities" class="wiki-section">
      <h3>Capabilities</h3>
      <table>
        <thead><tr><th>Area</th><th>What the Tool Does</th></tr></thead>
        <tbody>
          <tr><td>Repository Scanning</td><td>Scans Bitbucket repositories and local folders, including full scans, changed-files scans, branch diffs, and baseline-aware rescans.</td></tr>
          <tr><td>Detection</td><td>Finds AI provider usage, prompt handling risks, model-serving exposure, RAG/vector patterns, secret-to-AI correlation, policy violations, and suspicious flows.</td></tr>
          <tr><td>Analysis</td><td>Applies context-aware severity scoring, production relevance, evidence quality scoring, and policy mapping before optional LLM review.</td></tr>
          <tr><td>Review Workflow</td><td>Supports finding triage, suppressions, accepted risk, reviewed state, central findings management, scan history, and trend analysis.</td></tr>
          <tr><td>Reporting</td><td>Produces CSV, JSON, SARIF, Threat Dragon JSON, and on-demand HTML reports, plus logs, inventory views, staged threat-model sections, attack trees, and trend summaries.</td></tr>
          <tr><td>Execution Modes</td><td>Supports browser-driven scans plus a minimal CLI for both local-repo and Bitbucket project/repo scans that writes machine-readable artifacts.</td></tr>
        </tbody>
      </table>
    </section>

    <section id="installation" class="wiki-section">
      <h3>Installation</h3>
      <table>
        <thead><tr><th>Step</th><th>Detail</th></tr></thead>
        <tbody>
          <tr><td>Python</td><td>Use Python 3.13 on Windows for the current desktop workflow.</td></tr>
          <tr><td>Install Dependencies</td><td>Preferred: <code>python -m pip install -r requirements.txt</code></td></tr>
          <tr><td>Launch Web App</td><td><code>python C:\\aitool\\main_web.py</code></td></tr>
          <tr><td>Launch CLI</td><td><code>python C:\\aitool\\scan_cli.py C:\\path\\to\\repo</code> or <code>python C:\\aitool\\scan_cli.py --project COGI --repo repo1</code></td></tr>
          <tr><td>Optional LLM Runtime</td><td>Install and run Ollama if you want LLM review and report enrichment.</td></tr>
          <tr><td>Enterprise TLS</td><td>Configure the Bitbucket CA bundle in Settings when using an internal PKI.</td></tr>
        </tbody>
      </table>
      <p class="muted" style="margin:8px 0 0">Runtime state is stored in the OS state directory, not in the repo root.</p>
    </section>

    <section id="architecture" class="wiki-section">
      <h3>Architecture</h3>
      <table>
        <thead><tr><th>Module</th><th>Responsibility</th></tr></thead>
        <tbody>
          <tr><td>Web Server</td><td>Local server-rendered HTTP app in <code>app_server.py</code> with pages, APIs, session handling, and static assets.</td></tr>
          <tr><td>Scan Orchestration</td><td><code>services.scan_jobs</code> owns scan lifecycle, telemetry, report generation, history persistence, and active-session state.</td></tr>
          <tr><td>Bitbucket Access</td><td><code>scanner.bitbucket</code> handles PAT-authenticated project/repo listing, metadata lookup, and cloning with TLS validation.</td></tr>
          <tr><td>Detector and Analyzer</td><td><code>scanner.detector</code> and <code>analyzer.security</code> produce findings, score them, and enrich them with policy context.</td></tr>
          <tr><td>Persistence</td><td>SQLite-backed scan history, scan logs, findings rollups, triage metadata, and exported artifacts.</td></tr>
          <tr><td>Reports and Exports</td><td>CSV, JSON, SARIF, Threat Dragon JSON, and HTML reports live under the output directory and can be reopened from the UI.</td></tr>
        </tbody>
      </table>
    </section>

    <section id="modules" class="wiki-section">
      <h3>Modules</h3>
      <table>
        <thead><tr><th>Module Group</th><th>Purpose</th></tr></thead>
        <tbody>
          <tr><td>Scanner</td><td>Repo access, clone helpers, detection, suppression logic, and LLM reviewer integration.</td></tr>
          <tr><td>Services</td><td>Active scan state, session/auth handling, API actions, runtime support, trends, findings rollups, and UI rendering helpers.</td></tr>
          <tr><td>Reports</td><td>CSV, JSON, SARIF, HTML, delta comparison, and threat-model report content.</td></tr>
          <tr><td>Assets</td><td>Static CSS and JavaScript for pages such as scan activity, history, findings, results, and general layout.</td></tr>
          <tr><td>Tests</td><td>Regression, security, smoke, and report/settings coverage for the desktop web app and scan services.</td></tr>
        </tbody>
      </table>
    </section>

    <section id="workflow" class="wiki-section">
      <h3>Workflow</h3>
      <ol style="margin:0;padding-left:18px">
        <li>Connect to Bitbucket with a PAT or run the CLI against a local repo.</li>
        <li>Select repositories or a local path, choose scan scope, and choose an LLM model if LLM review is enabled.</li>
        <li>The tool resolves repo metadata, clones or opens the repo, scans files, applies policy analysis, and optionally runs LLM review.</li>
        <li>Structured telemetry, history, inventory, findings, and staged threat-model data are persisted as the scan progresses.</li>
        <li>CSV, JSON, SARIF, and Threat Dragon exports are written automatically; HTML can be generated on demand from the Results page.</li>
        <li>Operators review findings through the Findings page, scan workspace, Past Scans, Trends, and report artifacts.</li>
      </ol>
    </section>

    <section id="findings" class="wiki-section">
      <h3>Findings and Triage</h3>
      <table>
        <thead><tr><th>State</th><th>Meaning</th></tr></thead>
        <tbody>
          <tr><td>Open</td><td>Active finding with no triage decision yet.</td></tr>
          <tr><td>Reviewed</td><td>Analyst reviewed the finding but did not suppress or accept risk.</td></tr>
          <tr><td>Accepted Risk</td><td>Finding remains acknowledged with a documented reason.</td></tr>
          <tr><td>Suppressed</td><td>Finding is intentionally hidden as noise or not actionable.</td></tr>
          <tr><td>Fixed</td><td>Finding existed in a prior full/baseline comparison but is absent from a later relevant scan.</td></tr>
        </tbody>
      </table>
      <p>The <strong>Findings</strong> page is the central management surface for filtering, bulk triage actions, and cross-scan finding review.</p>
    </section>

    <section id="pages" class="wiki-section">
      <h3>Pages</h3>
      <table>
        <thead><tr><th>Page</th><th>Purpose</th></tr></thead>
        <tbody>
          <tr><td>New Scan</td><td>Choose repositories or a local path, set scope, select model, and start a new scan.</td></tr>
          <tr><td>Past Scans</td><td>Review historical scan runs, durations, statuses, and links back to scan workspaces.</td></tr>
          <tr><td>Findings</td><td>Central findings management page with filters, bulk actions, status review, and drill-down into scan details.</td></tr>
          <tr><td>Trends</td><td>History-derived metrics for findings over time, repo risk, noisy rules, suppression rate, and LLM operational stability.</td></tr>
          <tr><td>AI Inventory</td><td>Repository-level inventory of providers, models, embeddings, prompt handling, and model-serving/agent patterns.</td></tr>
          <tr><td>Settings</td><td>Runtime configuration including Bitbucket TLS, output path, LLM URL/model, and report timeout settings.</td></tr>
        </tbody>
      </table>
    </section>

    <section id="exports" class="wiki-section">
      <h3>Import / Export</h3>
      <table>
        <thead><tr><th>Artifact</th><th>Behavior</th></tr></thead>
        <tbody>
          <tr><td>CSV</td><td>Written automatically at scan completion for spreadsheet-style analysis and operational review.</td></tr>
          <tr><td>JSON</td><td>Written automatically at scan completion for machine-readable integration and custom processing.</td></tr>
          <tr><td>SARIF</td><td>Written automatically at scan completion for interoperability with static-analysis and security tooling.</td></tr>
          <tr><td>Threat Dragon JSON</td><td>Written automatically at scan completion as a starter threat-model file with inferred actors, processes, stores, flows, and attached threats.</td></tr>
          <tr><td>HTML</td><td>Generated on demand from the Results page and cached after generation.</td></tr>
          <tr><td>History Export</td><td>SQLite is the source of truth; compatibility JSON export is maintained for legacy consumers.</td></tr>
          <tr><td>Local Repo Input</td><td>Can scan a local repo path directly from the UI or from the CLI without Bitbucket cloning.</td></tr>
        </tbody>
      </table>
    </section>

    <section id="integrations" class="wiki-section">
      <h3>Integration</h3>
      <table>
        <thead><tr><th>Integration Surface</th><th>Current Support</th></tr></thead>
        <tbody>
          <tr><td>Bitbucket</td><td>PAT-authenticated project/repo discovery and cloning over TLS with custom CA bundle support.</td></tr>
          <tr><td>Ollama</td><td>Optional local LLM review and report enrichment with model discovery, runtime checks, and timeout controls.</td></tr>
          <tr><td>CLI</td><td>Headless local-repo or Bitbucket scans via <code>scan_cli.py</code> producing CSV, JSON, SARIF, and logs.</td></tr>
          <tr><td>Downstream Tools</td><td>JSON, SARIF, and Threat Dragon exports are the first integration layer for pipelines, security tooling, and external threat-model refinement.</td></tr>
        </tbody>
      </table>
    </section>

    <section id="cli" class="wiki-section">
      <h3>CLI Usage</h3>
      <pre><code>python C:\\aitool\\scan_cli.py C:\\path\\to\\repo
python C:\\aitool\\scan_cli.py C:\\path\\to\\repo --output-dir C:\\tmp\\scan-out
python C:\\aitool\\scan_cli.py --project COGI --repo repo1
python C:\\aitool\\scan_cli.py --project COGI --repo repo1 --repo repo2 --scope branch_diff --compare-ref master</code></pre>
      <p>The CLI is intentionally minimal but now supports both local-repo scans and Bitbucket project/repo scans. For Bitbucket mode, provide <code>--project</code> and one or more <code>--repo</code> values, plus a PAT through <code>--token</code>, <code>AI_SCANNER_PAT</code>, <code>BITBUCKET_PAT</code>, or the saved credential store.</p>
      <p class="muted" style="margin:8px 0 0">CLI scans write CSV, JSON, SARIF, and Threat Dragon exports automatically. HTML remains on-demand in the web UI.</p>
    </section>

    <section id="security" class="wiki-section">
      <h3>Security Model</h3>
      <ul style="margin:0;padding-left:18px">
        <li>The app is designed for localhost desktop use and uses browser session cookies plus CSRF protection for mutating actions.</li>
        <li>Bitbucket API traffic and clone operations verify TLS by default and support internal CA bundles.</li>
        <li>OS-backed keyring storage is preferred for PAT persistence; insecure fallback must be explicitly enabled.</li>
        <li>Mutable runtime state now lives outside the repo tree in the OS state directory.</li>
      </ul>
    </section>

    <section id="limitations" class="wiki-section">
      <h3>Known Limitations</h3>
      <ul style="margin:0;padding-left:18px">
        <li>LLM review quality and speed depend heavily on the selected local model and available hardware.</li>
        <li>This is still a single-operator desktop-oriented architecture, not a hardened multi-user service.</li>
        <li>Static scanning identifies likely issues and suspicious patterns but does not prove exploitability by itself.</li>
        <li>Generated HTML reports are cached snapshots of the finding state at generation time; later triage changes do not automatically rewrite an already generated report file.</li>
        <li>Threat-model outputs are evidence-backed drafts; flows, boundaries, and attack trees should still be validated by a human reviewer.</li>
        <li>JSON and SARIF exports are first-step integration outputs, not yet full issue-tracker or webhook pipelines.</li>
      </ul>
    </section>
  </section>

  <aside class="card wiki-toc">
    <h3 style="margin:0 0 10px">On This Page</h3>
    <nav class="wiki-toc-links">
      <a href="#overview">Tool Description</a>
      <a href="#capabilities">Capabilities</a>
      <a href="#installation">Installation</a>
      <a href="#architecture">Architecture</a>
      <a href="#modules">Modules</a>
      <a href="#workflow">Workflow</a>
      <a href="#findings">Findings and Triage</a>
      <a href="#pages">Pages</a>
      <a href="#exports">Import / Export</a>
      <a href="#integrations">Integration</a>
      <a href="#cli">CLI Usage</a>
      <a href="#security">Security Model</a>
      <a href="#limitations">Known Limitations</a>
    </nav>
  </aside>
</section>"""
    return _layout(title="Help", body=body, active="help", show_scan_results=show_scan_results, csrf_token=csrf_token, current_scan=current_scan)
