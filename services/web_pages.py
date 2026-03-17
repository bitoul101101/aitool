from __future__ import annotations

from datetime import datetime
from html import escape
from urllib.parse import quote


def _esc(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _fmt_dt(value: str) -> tuple[str, str, int]:
    if not value:
        return "-", "", 0
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
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


def _fmt_triage_time(value: str) -> str:
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
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


def _base_style() -> str:
    return """
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f6efe4;color:#261507}
header{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:14px;padding:12px 18px;background:#4a210c;color:#fff}
header h1{margin:0;font-size:18px}
.header-nav{display:flex;justify-content:center;gap:8px;align-items:center}
.header-actions{display:flex;justify-content:flex-end}
.nav{color:#f7e0c0;text-decoration:none;padding:7px 11px;border-radius:8px}
.nav.active,.nav:hover{background:#6d3514;color:#fff}
.exit-form{margin:0}
main{max-width:1340px;margin:0 auto;padding:16px 18px}
.card{background:#fffaf4;border:1px solid #d8b995;border-radius:14px;padding:14px}
.notice,.error{padding:10px 12px;border-radius:10px}
.notice{background:#e8f5e5;border:1px solid #b8d3b0;color:#224d22}
.error{background:#f8e5e2;border:1px solid #dfb1aa;color:#7d2a22}
.toast-wrap{position:fixed;top:14px;right:14px;display:grid;gap:8px;z-index:1000}
.toast{min-width:260px;max-width:420px;box-shadow:0 10px 24px rgba(0,0,0,.14);animation:fadein .2s ease}
.muted{color:#705333}
button,.btn{border:0;border-radius:8px;padding:9px 13px;background:#6d3514;color:#fff;font-weight:700;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;white-space:nowrap}
button.alt,.btn.alt{background:#8a6c50}
button.warn,.btn.warn{background:#a2392f}
button.ghost,.btn.ghost{background:#efe1cf;color:#5d3b15}
label{display:block;font-size:11px;font-weight:700;margin-bottom:5px;color:#6d4a21;text-transform:uppercase}
input,select,textarea{width:100%;padding:8px 10px;border:1px solid #cda983;border-radius:8px;background:#fff;box-sizing:border-box}
a{color:#7d3200}
table{width:100%;border-collapse:collapse;background:#fffaf4}
th,td{padding:8px 10px;border-bottom:1px solid #ead4ba;text-align:left;vertical-align:top}
th{background:#f0deca;font-size:11px;text-transform:uppercase;color:#67461f;white-space:normal;line-height:1.15}
.hidden{display:none!important}
.pill{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;background:#efe1cf;color:#5d3b15;font-size:12px;font-weight:700}
.status-running{background:#fff3d8;color:#8a5b00}
.status-done{background:#e3f3e3;color:#225522}
.status-stopped{background:#f6dddd;color:#7b1d1d}
.stack{display:grid;gap:10px}
.inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.checkline{display:flex;align-items:center;gap:8px;font-size:14px;text-transform:none;color:#261507}
.checkline input{width:auto;margin:0;flex:0 0 auto;transform:translateY(1px)}
.login-shell{max-width:540px;margin:48px auto 0}
.login-grid{display:grid;gap:14px}
.login-actions{display:flex;justify-content:flex-end}
.login-title{text-align:center;margin:0 0 6px}
.scan-shell{display:grid;grid-template-columns:minmax(0,1fr);gap:14px;align-items:start}
.selection-grid{display:grid;grid-template-columns:220px minmax(0,1fr);gap:14px;align-items:start}
.project-panel,.repo-panel,.activity-panel{min-height:calc(100vh - 132px)}
.project-list{display:grid;gap:2px;max-height:calc(100vh - 200px);overflow:auto;padding-right:4px}
.project-link{display:block;padding:4px 7px;border-radius:8px;text-decoration:none;background:#f6ebdc;color:#5e3b16;font-size:12px}
.project-link.active{background:#6d3514;color:#fff;font-weight:700}
.repo-toolbar{display:grid;grid-template-columns:minmax(180px,1fr) 240px auto;gap:8px;align-items:end;margin-bottom:8px}
.repo-actions{display:flex;align-items:center;gap:8px;margin:8px 0 10px}
.repo-shell{border:1px solid #ead4ba;border-radius:12px;background:#fcf6ee;padding:8px}
.repo-grid{display:grid;gap:2px 12px;max-height:calc(100vh - 285px);overflow:auto;padding-right:4px;align-content:start}
.repo-grid.cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}
.repo-grid.cols-3{grid-template-columns:repeat(3,minmax(0,1fr))}
.repo-row{display:flex;align-items:center;gap:6px;padding:1px 4px;border-radius:6px;font-size:12px;line-height:1.15}
.repo-row input{width:auto;margin:0;flex:0 0 auto;transform:translateY(1px)}
.repo-row span{display:block}
.running-shell{display:grid;grid-template-columns:minmax(0,1fr) 250px;gap:14px;align-items:start}
.scan-header{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:10px}
.scan-status{display:flex;align-items:center;gap:10px}
.state-icon{width:16px;height:16px;border-radius:50%;background:#2a7cff;display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:12px;font-weight:700}
.state-icon.pending{background:#bfa78c}
.state-icon.running{animation:blink 1s ease-in-out infinite}
.state-icon.done{background:#20a955}
.state-icon.done::before{content:"V"}
.state-icon.stopped{background:#a2392f}
.state-icon.stopped::before{content:"!"}
.timeline-row{display:grid;grid-template-columns:auto 1fr auto;gap:8px;padding:8px 10px;border-radius:10px;background:#f6ebdc;font-size:13px;align-items:center}
.timeline-name{text-transform:capitalize}
.terminal{background:#18120d;color:#f5debe;border:1px solid #3f2a19;border-radius:12px;padding:12px;height:420px;overflow:auto;font-family:Cascadia Code,Consolas,monospace;font-size:12px;line-height:1.45;white-space:pre-wrap}
.timeline{display:grid;gap:8px}
.timeline-row strong{justify-self:end}
.findings-panel{margin-top:12px}
.finding-table-wrap{max-height:240px;overflow:auto;border:1px solid #ead4ba;border-radius:12px}
.finding-meta{display:grid;gap:4px}
.finding-main{font-weight:600}
.finding-sub{font-size:12px;color:#705333}
.triage-state{display:inline-flex;align-items:center;padding:3px 7px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;background:#efe1cf;color:#5d3b15}
.triage-reviewed{background:#e3efff;color:#164a95}
.triage-accepted_risk{background:#fff1dc;color:#8a5b00}
.triage-false_positive{background:#e5f3e7;color:#1f6a35}
.triage-note{font-size:12px;color:#5f4527}
.triage-actions{display:grid;gap:6px}
.triage-form{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:0}
.triage-form.inline-only{display:inline-flex}
.triage-form input[type="text"]{min-width:170px;flex:1 1 180px}
.triage-form button{padding:6px 9px;font-size:12px}
.suppressed-section{margin-top:14px}
.suppressed-section h3{margin:0 0 8px;font-size:15px}
.suppressed-wrap{max-height:220px;overflow:auto;border:1px solid #ead4ba;border-radius:12px}
.report-actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 0}
button[disabled],.btn.disabled{opacity:.5;cursor:not-allowed}
.history-toolbar{display:grid;grid-template-columns:minmax(220px,1fr) repeat(4,170px) auto auto;gap:8px;align-items:end;position:sticky;top:0;background:#fffaf4;padding-bottom:10px;z-index:3}
.table-shell{max-height:calc(100vh - 220px);overflow:auto;border:1px solid #ead4ba;border-radius:12px}
.table-shell thead th{position:sticky;top:0;z-index:2}
.history-time{font-size:11px;color:#7a5d3e}
.icon-link img{display:block;width:34px;height:34px}
.filters-row{margin-bottom:12px}
@media (max-width:1220px){.selection-grid,.running-shell{grid-template-columns:1fr}.project-panel,.repo-panel,.activity-panel{min-height:auto}}
@media (max-width:900px){header{grid-template-columns:1fr}.header-nav,.header-actions{justify-content:flex-start}.selection-grid{grid-template-columns:1fr}.repo-grid.cols-3{grid-template-columns:repeat(2,minmax(0,1fr))}.history-toolbar{grid-template-columns:1fr 1fr}.table-shell{max-height:none}}
@keyframes fadein{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
@keyframes blink{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(42,124,255,.35)}50%{opacity:.35;box-shadow:0 0 0 5px rgba(42,124,255,0)}}
"""


def _flash(notice: str = "", error: str = "") -> str:
    items = []
    if notice:
        items.append(f'<div class="notice toast">{_esc(notice)}</div>')
    if error:
        items.append(f'<div class="error toast">{_esc(error)}</div>')
    return f'<div class="toast-wrap">{"".join(items)}</div>' if items else ""


def _layout(*, title: str, body: str, active: str = "", show_nav: bool = True) -> bytes:
    nav = ""
    if show_nav:
        nav = (
            '<div class="header-nav">'
            f'<a class="nav{" active" if active == "scan" else ""}" href="/scan">Scan</a>'
            f'<a class="nav{" active" if active == "history" else ""}" href="/history">History</a>'
            f'<a class="nav{" active" if active == "settings" else ""}" href="/settings">Settings</a>'
            '</div>'
            '<div class="header-actions">'
            '<form class="exit-form" method="post" action="/app/exit"><button type="submit" class="warn">Exit</button></form>'
            "</div>"
        )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>{_base_style()}</style>
</head>
<body>
<header><h1>AI Security & Compliance Scanner</h1>{nav if nav else ""}</header>
<main>{body}</main>
<script>
setTimeout(()=>document.querySelectorAll('.toast').forEach(el=>el.remove()),5000);
(function() {{
  const url=new URL(window.location.href);
  if(url.searchParams.has('notice')||url.searchParams.has('error')) {{
    url.searchParams.delete('notice');
    url.searchParams.delete('error');
    history.replaceState(null,'',url.pathname + (url.search ? url.search : ''));
  }}
}})();
</script>
</body>
</html>"""
    return html.encode("utf-8")


def render_login_page(*, bitbucket_url: str, has_saved_pat: bool, notice: str = "", error: str = "") -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="card login-shell">
  <h2 class="login-title">Login to Bitbucket</h2>
  <form method="post" action="/login" class="login-grid" style="margin-top:18px">
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
    return _layout(title="Login", body=body, show_nav=False)


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
    notice: str = "",
    error: str = "",
) -> bytes:
    def triage_badge(status_name: str) -> str:
        if not status_name:
            return ""
        label = status_name.replace("_", " ")
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
            f'<input type="hidden" name="hash" value="{_esc(hash_)}">'
            '<input type="hidden" name="status" value="reviewed">'
            '<button type="submit" class="ghost">Reviewed</button>'
            "</form>"
        )
        accepted_form = (
            f'<form class="triage-form" method="post" action="/findings/triage">'
            f'<input type="hidden" name="hash" value="{_esc(hash_)}">'
            '<input type="hidden" name="status" value="accepted_risk">'
            '<input type="text" name="note" placeholder="Accepted risk reason" required>'
            '<button type="submit" class="alt">Accept Risk</button>'
            "</form>"
        )
        suppress_form = (
            f'<form class="triage-form" method="post" action="/findings/triage">'
            f'<input type="hidden" name="hash" value="{_esc(hash_)}">'
            '<input type="hidden" name="status" value="false_positive">'
            '<input type="text" name="note" placeholder="Suppression reason" required>'
            '<button type="submit" class="warn">Suppress</button>'
            "</form>"
        )
        return f'<div class="triage-actions">{reviewed_form}{accepted_form}{suppress_form}</div>'

    def finding_row(detail: dict) -> str:
        location = f'{detail.get("file", "")}:{detail.get("line", "")}'
        return (
            "<tr>"
            f'<td><div class="finding-meta"><div class="finding-main">{_esc(detail.get("repo", ""))}</div>'
            f'<div class="finding-sub">{_esc(detail.get("description", ""))}</div></div></td>'
            f'<td><div class="finding-meta"><div>{_esc(location)}</div>{triage_meta(detail)}</div></td>'
            f"<td>{_esc(detail.get('severity_label', detail.get('severity', '')))}</td>"
            f'<td><div class="finding-meta"><div>{_esc(detail.get("capability", ""))}</div>'
            f'<div class="finding-sub">{_esc(detail.get("delta_status", ""))}</div></div></td>'
            f"<td>{triage_actions(detail)}</td>"
            "</tr>"
        )

    def suppressed_row(detail: dict) -> str:
        location = f'{detail.get("file", "")}:{detail.get("line", "")}'
        status_name = detail.get("triage_status", "false_positive") or "false_positive"
        return (
            "<tr>"
            f'<td><div class="finding-meta"><div class="finding-main">{_esc(detail.get("repo", ""))}</div>'
            f'<div class="finding-sub">{_esc(detail.get("description", ""))}</div></div></td>'
            f'<td><div class="finding-meta"><div>{_esc(location)}</div>{triage_meta(detail)}</div></td>'
            f"<td>{_esc(detail.get('severity_label', detail.get('severity', '')))}</td>"
            f"<td>{triage_badge(status_name)}</td>"
            f"<td>{triage_actions(detail, suppressed=True)}</td>"
            "</tr>"
        )

    state = str(status.get("state", "")).lower()
    running = state == "running"
    scan_complete = state in {"done", "stopped", "error"}
    selected = set(selected_repos)
    repo_count = len(repos)
    repo_cols = "cols-2" if repo_count <= 18 else "cols-3"
    project_links = "".join(
        f'<a class="project-link{" active" if p.get("key","") == selected_project else ""}" href="/scan?project={_esc(p.get("key",""))}">{_esc(p.get("key",""))}</a>'
        for p in projects
    ) or '<div class="muted">No projects loaded.</div>'
    repo_rows = "".join(
        f'<label class="repo-row" data-repo-name="{_esc(repo.get("slug","").lower())}"><input type="checkbox" class="repo-checkbox" name="repo_slugs" value="{_esc(repo.get("slug",""))}"{" checked" if repo.get("slug","") in selected else ""}><span>{_esc(repo.get("slug","").lower())}</span></label>'
        for repo in repos
    ) or '<div class="muted">No repositories available for the selected project.</div>'
    models = list(dict.fromkeys([m for m in llm_models if m] + ([llm_cfg.get("model", "")] if llm_cfg.get("model") else [])))
    model_options = "".join(
        f'<option value="{_esc(model)}"{" selected" if model == llm_cfg.get("model", "") else ""}>{_esc(model)}</option>'
        for model in models
    )
    findings = status.get("finding_details", [])[:20]
    suppressed = status.get("suppressed_details", [])[:30]
    findings_rows = "".join(finding_row(f) for f in findings) or '<tr><td colspan="5">No current findings.</td></tr>'
    suppressed_rows = "".join(suppressed_row(f) for f in suppressed) or '<tr><td colspan="5">No suppressed findings.</td></tr>'
    normalized_timeline = []
    for item in phase_timeline:
        if isinstance(item, dict):
            normalized_timeline.append(item)
        else:
            name, duration = item
            normalized_timeline.append({"name": name, "duration": duration, "state": "pending"})
    timeline_html = "".join(
        f'<div class="timeline-row">'
        f'<span class="state-icon {_esc(item.get("state","pending"))}"></span>'
        f'<span class="timeline-name">{_esc(item.get("name",""))}</span>'
        f'<strong>{_esc(item.get("duration","—"))}</strong>'
        f"</div>"
        for item in normalized_timeline
    ) or '<div class="muted">Timeline will appear after the scan starts.</div>'
    stop_button = (
        '<button type="button" id="stop-scan-btn" class="warn" onclick="document.getElementById(\'stop-form\').submit()">Stop Scan</button>'
        if running
        else '<button type="button" id="stop-scan-btn" class="warn" disabled>Stop Scan</button>'
    )
    state_icon_class = "running" if running else "done" if state == "done" else "stopped" if state == "stopped" else ""
    state_text = "Running" if running else "Done" if state == "done" else "Stopped" if state == "stopped" else "Ready"
    report = status.get("report") or {}
    scan_id = status.get("scan_id", "")
    report_actions = ""
    if scan_complete and findings:
        html_name = report.get("html_name", "")
        csv_name = report.get("csv_name", "")
        log_url = f"/api/history/log/{_esc(scan_id)}" if scan_id else ""
        buttons = []
        if html_name:
            buttons.append(f'<a class="btn" id="open-html-report" href="/reports/{_esc(html_name)}" target="_blank">Open HTML Report</a>')
        if csv_name:
            buttons.append(f'<a class="btn alt" id="download-csv-report" href="/reports/{_esc(csv_name)}" download>Download CSV File</a>')
        if log_url:
            buttons.append(f'<a class="btn ghost" id="download-log-report" href="{log_url}" download>Download Logs</a>')
        report_actions = f'<div class="report-actions" id="report-actions">{"".join(buttons)}</div>'
    selection_view = f"""
<section class="selection-grid">
  <aside class="card project-panel">
    <h2 style="margin:0 0 8px;font-size:16px">Projects</h2>
    <div class="project-list">{project_links}</div>
  </aside>
  <section class="card repo-panel">
    <form method="post" action="/scan/start" class="stack">
      <input type="hidden" name="project_key" value="{_esc(selected_project)}">
      <div class="repo-toolbar">
        <div><label>Search Repositories</label><input type="search" id="repo-search" placeholder="Search by repo name"></div>
        <div><label>LLM Model</label><select name="llm_model" id="llm-model-select">{model_options}</select></div>
        <div class="inline" style="justify-content:flex-start;align-items:end"><button type="submit">Start Scan</button></div>
      </div>
      <div class="repo-actions">
        <span class="muted" id="repo-selection-count"></span>
        <button type="button" class="ghost" id="select-all-repos-btn">All</button>
        <button type="button" class="ghost" id="select-none-repos-btn">None</button>
      </div>
      <div class="repo-shell"><div id="repo-grid" class="repo-grid {repo_cols}">{repo_rows}</div></div>
    </form>
  </section>
</section>
<form method="post" action="/scan/stop" id="stop-form"></form>"""
    running_view = f"""
<section class="running-shell">
  <section class="card activity-panel">
    <div class="scan-header">
      <div class="scan-status">
        <span id="scan-state-icon" class="state-icon {state_icon_class}"></span>
        <div>
          <div style="font-size:16px;font-weight:700">Scan</div>
          <div id="scan-state-text" class="muted">{_esc(state_text)}</div>
        </div>
      </div>
      <div class="inline">{stop_button if running else ""}</div>
    </div>
    <div>
      <h2 style="margin:0 0 8px;font-size:16px">Activity Log</h2>
      <div class="terminal" id="scan-log">{_esc(log_text or "No activity yet.")}</div>
    </div>
    <div class="findings-panel">
      <h2 style="margin:0 0 8px;font-size:16px">Current Findings</h2>
      <div class="finding-table-wrap">
        <table>
          <thead><tr><th>Repo</th><th>Location</th><th>Severity</th><th>Capability</th><th>Actions</th></tr></thead>
          <tbody id="current-findings-body">{findings_rows}</tbody>
        </table>
      </div>
    </div>
    <div class="suppressed-section">
      <h3>Suppressed / Triage</h3>
      <div class="suppressed-wrap">
        <table>
          <thead><tr><th>Repo</th><th>Location</th><th>Severity</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody id="suppressed-findings-body">{suppressed_rows}</tbody>
        </table>
      </div>
    </div>
    {report_actions}
  </section>
  <aside class="card">
    <h2 style="margin:0 0 8px;font-size:16px">Phase Timeline</h2>
    <div class="timeline" id="phase-timeline">{timeline_html}</div>
  </aside>
</section>
<form method="post" action="/scan/stop" id="stop-form"></form>"""
    body = f"""
{_flash(notice, error)}
<section class="scan-shell">
  {running_view if running or state in ("done", "stopped") and log_text else selection_view}
</section>
<script>
const repoSearch=document.getElementById('repo-search');
const repoCount=document.getElementById('repo-selection-count');
function repoCheckboxes(){{return Array.from(document.querySelectorAll('.repo-checkbox'));}}
function updateRepoCount(){{if(repoCount) repoCount.textContent=`${{repoCheckboxes().filter(cb=>cb.checked && cb.closest('.repo-row').style.display!=='none').length}} selected`;}}
function filterRepos(){{if(!repoSearch) return; const q=(repoSearch.value||'').toLowerCase().trim();document.querySelectorAll('.repo-row').forEach(row=>{{row.style.display=!q || (row.dataset.repoName||'').includes(q)?'flex':'none';}});updateRepoCount();}}
repoSearch?.addEventListener('input',filterRepos);
document.getElementById('select-all-repos-btn')?.addEventListener('click',()=>{{repoCheckboxes().forEach(cb=>{{if(cb.closest('.repo-row').style.display!=='none') cb.checked=true;}});updateRepoCount();}});
document.getElementById('select-none-repos-btn')?.addEventListener('click',()=>{{repoCheckboxes().forEach(cb=>cb.checked=false);updateRepoCount();}});
repoCheckboxes().forEach(cb=>cb.addEventListener('change',updateRepoCount));
filterRepos();
(function() {{
  const logEl=document.getElementById('scan-log');
  const iconEl=document.getElementById('scan-state-icon');
  const textEl=document.getElementById('scan-state-text');
  const findingsBody=document.getElementById('current-findings-body');
  const timelineEl=document.getElementById('phase-timeline');
  if(!logEl) return;
  function timelineRows(items){{
    if(!items || !items.length) return '<div class="muted">Timeline will appear after the scan starts.</div>';
    return items.map(item=>`<div class="timeline-row"><span class="state-icon ${{item.state||'pending'}}"></span><span class="timeline-name">${{item.name||''}}</span><strong>${{item.duration||'—'}}</strong></div>`).join('');
  }}
  function reportActions(data){{
    const shell=document.getElementById('report-actions');
    if(!shell) {{
      if(!data || !findingsBody) return;
    }}
    const report=data.report||{{}};
    const findings=data.finding_details||[];
    if(!findings.length || !(data.state==='done' || data.state==='stopped')) {{
      if(shell) shell.remove();
      return;
    }}
    const actions=[];
    if(report.html_name) actions.push(`<a class="btn" id="open-html-report" href="/reports/${{report.html_name}}" target="_blank">Open HTML Report</a>`);
    if(report.csv_name) actions.push(`<a class="btn alt" id="download-csv-report" href="/reports/${{report.csv_name}}" download>Download CSV File</a>`);
    if(data.scan_id) actions.push(`<a class="btn ghost" id="download-log-report" href="/api/history/log/${{data.scan_id}}" download>Download Logs</a>`);
    if(!actions.length) return;
    if(shell) {{ shell.innerHTML=actions.join(''); return; }}
    const mount=document.createElement('div');
    mount.id='report-actions';
    mount.className='report-actions';
    mount.innerHTML=actions.join('');
    findingsBody.closest('.findings-panel')?.insertAdjacentElement('afterend', mount);
  }}
  const stream=new EventSource('/api/scan/stream');
  stream.onmessage=(event)=>{{
    if(!event.data) return;
    let line=event.data;
    try {{ line=JSON.parse(event.data); }} catch (_err) {{}}
    logEl.textContent += (logEl.textContent.trim()? '\\n' : '') + line;
    logEl.scrollTop = logEl.scrollHeight;
  }};
  const timer=setInterval(async ()=>{{
    try {{
      const res=await fetch('/api/scan/status', {{headers:{{'Accept':'application/json'}}}});
      const data=await res.json();
      const state=(data.state||'').toLowerCase();
      if(timelineEl) timelineEl.innerHTML=timelineRows(data.phase_timeline||[]);
      reportActions(data);
      if(state==='running') return;
      clearInterval(timer);
      stream.close();
      if(iconEl) iconEl.className='state-icon ' + (state==='done' ? 'done' : state==='stopped' ? 'stopped' : '');
      if(textEl) textEl.textContent=state ? state.charAt(0).toUpperCase()+state.slice(1) : 'Ready';
      const stopBtn=document.getElementById('stop-scan-btn');
      if(stopBtn) stopBtn.disabled=true;
    }} catch (_err) {{}}
  }}, 3000);
}})();
</script>"""
    return _layout(title="Scan", body=body, active="scan")


def render_history_page(*, history: list[dict], notice: str = "", error: str = "") -> bytes:
    projects = sorted({str(rec.get("project_key", rec.get("project", ""))) for rec in history if rec.get("project_key") or rec.get("project")})
    repos = sorted({", ".join(rec.get("repo_slugs", rec.get("repos", []))) for rec in history if rec.get("repo_slugs") or rec.get("repos")})
    statuses = sorted({str(rec.get("state", "")) for rec in history if rec.get("state")})
    models = sorted({str(rec.get("llm_model", "")) for rec in history if rec.get("llm_model")})

    def _opts(values: list[str], label: str) -> str:
        return f'<option value="">{_esc(label)}</option>' + "".join(f'<option value="{_esc(v)}">{_esc(v)}</option>' for v in values)

    rows = []
    for rec in history:
        project = rec.get("project_key", rec.get("project", ""))
        repo_label = ", ".join(rec.get("repo_slugs", rec.get("repos", [])))
        date_text, time_text, ts = _fmt_dt(rec.get("started_at_utc", ""))
        state = str(rec.get("state", ""))
        status_class = {"running": "status-running", "done": "status-done", "stopped": "status-stopped"}.get(state.lower(), "")
        total_findings = rec.get("total", rec.get("finding_total", rec.get("active_total", 0)))
        reports = (rec.get("reports") or {}).get("__all__", {})
        html_link = f'<a class="icon-link" href="/reports/{_esc(reports.get("html_name",""))}" target="_blank" title="Open HTML Report"><img src="{HTML_ICON}" alt="HTML"></a>' if reports.get("html_name") else ""
        csv_link = f'<a class="icon-link" href="/reports/{_esc(reports.get("csv_name",""))}" download title="Download CVS Report"><img src="{CSV_ICON}" alt="CSV"></a>' if reports.get("csv_name") else ""
        log_link = f'<a class="icon-link" href="/api/history/log/{_esc(rec.get("scan_id",""))}" target="_blank" title="Open Log"><img src="{LOG_ICON}" alt="LOG"></a>' if rec.get("log_file") or state.lower() == "running" else ""
        rows.append(
            f'<tr data-project="{_esc(project)}" data-repo="{_esc(repo_label)}" data-status="{_esc(state)}" data-model="{_esc(rec.get("llm_model",""))}" data-ts="{ts}">'
            f'<td><input type="checkbox" class="history-check" name="scan_ids" value="{_esc(rec.get("scan_id",""))}"></td>'
            f'<td><div>{_esc(date_text)}</div><div class="history-time">{_esc(time_text)}</div></td>'
            f'<td>{_esc(project)}</td>'
            f'<td>{_esc(repo_label)}</td>'
            f'<td>{_esc(total_findings)}</td>'
            f'<td>{_esc(rec.get("critical_prod", 0))}</td>'
            f'<td>{_esc(rec.get("high_prod", 0))}</td>'
            f'<td>{_esc(rec.get("llm_model", ""))}</td>'
            f'<td>{_esc(_fmt_duration(rec.get("duration_s", 0)))}</td>'
            f'<td><span class="pill {status_class}">{_esc(state.title())}</span></td>'
            f'<td>{html_link}</td><td>{csv_link}</td><td>{log_link}</td></tr>'
        )
    body = f"""
{_flash(notice, error)}
<section class="card">
  <form method="post" action="/history/delete" id="history-form">
    <div class="history-toolbar filters-row">
      <input type="search" id="history-search" placeholder="Search any column">
      <select id="filter-project">{_opts(projects, 'All Projects')}</select>
      <select id="filter-repo">{_opts(repos, 'All Repos')}</select>
      <select id="filter-status">{_opts(statuses, 'All Statuses')}</select>
      <select id="filter-model">{_opts(models, 'All Models')}</select>
      <button type="button" class="ghost" id="reset-history-filters">Reset</button>
      <button type="submit" class="warn hidden" id="delete-selected-btn">Delete Selected Repos</button>
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
            <th data-sort="number">Critical<br>in Prod</th>
            <th data-sort="number">High<br>in Prod</th>
            <th data-sort="text">LLM<br>Model</th>
            <th data-sort="number">Duration</th>
            <th data-sort="text">Status</th>
            <th>HTML</th>
            <th>CSV</th>
            <th>LOG</th>
          </tr>
        </thead>
        <tbody>{''.join(rows) or '<tr><td colspan="13">No scan history available.</td></tr>'}</tbody>
      </table>
    </div>
  </form>
</section>
<script>
const hBody=document.querySelector('#history-table tbody');
const search=document.getElementById('history-search');
const fp=document.getElementById('filter-project');
const fr=document.getElementById('filter-repo');
const fs=document.getElementById('filter-status');
const fm=document.getElementById('filter-model');
const delBtn=document.getElementById('delete-selected-btn');
function rows(){{return Array.from(hBody.querySelectorAll('tr')).filter(r=>r.querySelectorAll('td').length>1);}}
function updateDelete(){{delBtn.classList.toggle('hidden',!rows().some(r=>r.querySelector('.history-check')?.checked));}}
function applyFilters(){{const q=(search.value||'').toLowerCase().trim();rows().forEach(row=>{{const text=row.textContent.toLowerCase();const ok=!q||text.includes(q);const okP=!fp.value||row.dataset.project===fp.value;const okR=!fr.value||row.dataset.repo===fr.value;const okS=!fs.value||row.dataset.status===fs.value;const okM=!fm.value||row.dataset.model===fm.value;row.style.display=(ok&&okP&&okR&&okS&&okM)?'':'none';}});updateDelete();}}
let sortState={{index:null,dir:-1,kind:'datetime'}};
function cellValue(row,index,kind){{if(kind==='datetime') return Number(row.dataset.ts)||0; const text=(row.children[index]?.innerText||'').trim(); if(kind==='number') return Number(text.replace(':','.'))||0; return text.toLowerCase();}}
function sortHistory(index,kind){{const rs=rows(); if(sortState.index===index) sortState.dir*=-1; else sortState={{index,dir:kind==='datetime'?-1:1,kind}}; rs.sort((a,b)=>{{const av=cellValue(a,sortState.index,sortState.kind); const bv=cellValue(b,sortState.index,sortState.kind); if(av<bv) return -1*sortState.dir; if(av>bv) return 1*sortState.dir; return 0;}}); rs.forEach(r=>hBody.appendChild(r)); applyFilters();}}
document.querySelectorAll('#history-table thead th[data-sort]').forEach((th,index)=>th.addEventListener('click',()=>sortHistory(index+1,th.dataset.sort)));
[search,fp,fr,fs,fm].forEach(el=>el?.addEventListener('input',applyFilters));
[fp,fr,fs,fm].forEach(el=>el?.addEventListener('change',applyFilters));
document.getElementById('reset-history-filters')?.addEventListener('click',()=>{{search.value='';fp.value='';fr.value='';fs.value='';fm.value='';applyFilters();}});
rows().forEach(r=>r.querySelector('.history-check')?.addEventListener('change',updateDelete));
sortHistory(1,'datetime');
</script>"""
    return _layout(title="History", body=body, active="history")


def render_settings_page(*, bitbucket_url: str, output_dir: str, llm_cfg: dict, notice: str = "", error: str = "") -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="card" style="max-width:760px">
  <h2 style="margin:0 0 12px">Settings</h2>
  <form method="post" action="/settings/save" class="stack">
    <div><label>Bitbucket URL</label><input type="text" value="{_esc(bitbucket_url)}" disabled></div>
    <div><label>Output Directory</label><input type="text" name="output_dir" value="{_esc(output_dir)}"></div>
    <div><label>LLM URL</label><input type="text" name="llm_url" value="{_esc(llm_cfg.get('base_url',''))}"></div>
    <div><label>LLM Model</label><input type="text" name="llm_model" value="{_esc(llm_cfg.get('model',''))}"></div>
    <div><button type="submit">Save Settings</button></div>
  </form>
</section>"""
    return _layout(title="Settings", body=body, active="settings")
