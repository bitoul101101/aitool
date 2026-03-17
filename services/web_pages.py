from __future__ import annotations

from html import escape
from typing import Iterable


def _esc(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _layout(*, title: str, active: str, body: str, auto_refresh: int | None = None) -> bytes:
    refresh = f'<meta http-equiv="refresh" content="{auto_refresh}">' if auto_refresh else ""
    nav = "".join(
        (
            f'<a class="nav{" active" if active == "scan" else ""}" href="/scan">Scan</a>',
            f'<a class="nav{" active" if active == "history" else ""}" href="/history">History</a>',
            f'<a class="nav{" active" if active == "settings" else ""}" href="/settings">Settings</a>',
        )
    )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{refresh}
<title>{_esc(title)}</title>
<style>
body{{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f4ecdf;color:#241406}}
header{{display:flex;align-items:center;gap:16px;padding:14px 20px;background:#4c210c;color:#fff}}
header h1{{margin:0;font-size:18px}}
nav{{display:flex;gap:10px;margin-left:auto}}
.nav{{color:#f6dec0;text-decoration:none;padding:8px 12px;border-radius:8px}}
.nav.active,.nav:hover{{background:#6e3514;color:#fff}}
main{{max-width:1200px;margin:0 auto;padding:24px}}
.grid{{display:grid;gap:16px}}
.grid.two{{grid-template-columns:repeat(2,minmax(0,1fr))}}
.card{{background:#fffaf3;border:1px solid #d5b692;border-radius:12px;padding:16px}}
.card h2{{margin:0 0 12px;font-size:18px}}
.muted{{color:#6f5332}}
.notice,.error{{padding:12px 14px;border-radius:10px;margin-bottom:16px}}
.notice{{background:#ecf6e8;border:1px solid #b5d2ad;color:#274d26}}
.error{{background:#f9e7e5;border:1px solid #e0b1ac;color:#772a24}}
.stats{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}}
.stat{{padding:12px;border:1px solid #ddc0a0;border-radius:10px;background:#fbf4ea}}
.stat strong{{display:block;font-size:24px}}
label{{display:block;font-size:12px;font-weight:700;margin-bottom:6px;color:#6b4a24;text-transform:uppercase}}
input,select,textarea{{width:100%;padding:10px 12px;border:1px solid #c9a985;border-radius:8px;background:#fff}}
textarea{{min-height:76px}}
button{{border:0;border-radius:8px;padding:10px 14px;background:#6e3514;color:#fff;font-weight:700;cursor:pointer}}
button.alt{{background:#82654a}}
button.warn{{background:#9a3a2f}}
.actions{{display:flex;gap:10px;flex-wrap:wrap}}
.repo-list,.finding-list{{display:grid;gap:10px}}
.repo-item,.finding{{padding:12px;border:1px solid #dfc3a3;border-radius:10px;background:#fcf6ee}}
.meta{{font-size:13px;color:#694c2a}}
table{{width:100%;border-collapse:collapse;background:#fffaf3}}
th,td{{padding:10px;border-bottom:1px solid #e4ccb0;text-align:left;vertical-align:top}}
th{{background:#f0dfca;font-size:12px;text-transform:uppercase;color:#6b4a24}}
a{{color:#7a3200}}
code,pre{{font-family:Cascadia Code,Consolas,monospace}}
pre{{background:#21160f;color:#f5debe;padding:12px;border-radius:10px;overflow:auto}}
.inline-form{{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}}
.inline-form > *{{flex:1 1 160px}}
.inline-form button{{flex:0 0 auto}}
@media (max-width:900px){{.grid.two,.stats{{grid-template-columns:1fr}} header{{flex-wrap:wrap}} nav{{margin-left:0}}}}
</style>
</head>
<body>
<header><h1>AI Security & Compliance Scanner</h1><nav>{nav}</nav></header>
<main>{body}</main>
</body>
</html>"""
    return html.encode("utf-8")


def _flash(notice: str = "", error: str = "") -> str:
    parts = []
    if notice:
        parts.append(f'<div class="notice">{_esc(notice)}</div>')
    if error:
        parts.append(f'<div class="error">{_esc(error)}</div>')
    return "".join(parts)


def _render_repo_options(repos: Iterable[dict], selected_repos: Iterable[str]) -> str:
    selected = set(selected_repos)
    items = []
    for repo in repos:
        slug = repo.get("slug", "")
        checked = " checked" if slug in selected else ""
        items.append(
            f'<label class="repo-item"><input type="checkbox" name="repo_slugs" value="{_esc(slug)}"{checked}> '
            f'<strong>{_esc(slug)}</strong> <span class="muted">{_esc(repo.get("name", ""))}</span></label>'
        )
    return "".join(items) or '<div class="muted">No repositories loaded for this project.</div>'


def _render_finding(finding: dict, *, action_path: str, reset_path: str) -> str:
    title = f'{_esc(finding.get("repo", ""))} / {_esc(finding.get("file", ""))}:{_esc(finding.get("line", ""))}'
    triage_status = finding.get("triage_status", "") or "new"
    note = finding.get("triage_note", finding.get("reason", ""))
    return f"""
<article class="finding" id="finding-{_esc(finding.get('hash', ''))}">
  <div><strong>{title}</strong></div>
  <div class="meta">Severity {_esc(finding.get("severity_label", finding.get("severity", "")))} | {_esc(finding.get("capability", ""))} | {_esc(finding.get("policy_status", ""))}</div>
  <p>{_esc(finding.get("description", ""))}</p>
  <form class="inline-form" method="post" action="{_esc(action_path)}">
    <input type="hidden" name="hash" value="{_esc(finding.get("hash", ""))}">
    <div>
      <label>Status</label>
      <select name="status">
        <option value="reviewed"{" selected" if triage_status == "reviewed" else ""}>Reviewed</option>
        <option value="accepted_risk"{" selected" if triage_status == "accepted_risk" else ""}>Accepted Risk</option>
        <option value="false_positive"{" selected" if triage_status == "false_positive" else ""}>False Positive</option>
      </select>
    </div>
    <div>
      <label>Note</label>
      <input type="text" name="note" value="{_esc(note)}">
    </div>
    <button type="submit">Save Triage</button>
  </form>
  <form class="actions" method="post" action="{_esc(reset_path)}">
    <input type="hidden" name="hash" value="{_esc(finding.get("hash", ""))}">
    <button type="submit" class="alt">Reset</button>
  </form>
</article>"""


def render_scan_page(
    *,
    bitbucket_url: str,
    connected_owner: str,
    has_saved_pat: bool,
    projects: list[dict],
    selected_project: str,
    repos: list[dict],
    selected_repos: list[str],
    status: dict,
    llm_cfg: dict,
    notice: str = "",
    error: str = "",
    log_text: str = "",
) -> bytes:
    options = ['<option value="">Select a project</option>']
    for project in projects:
        key = project.get("key", "")
        selected = " selected" if key == selected_project else ""
        options.append(f'<option value="{_esc(key)}"{selected}>{_esc(key)} - {_esc(project.get("name", ""))}</option>')
    report = status.get("report", {}) or {}
    summary = f"""
{_flash(notice, error)}
<section class="grid two">
  <article class="card">
    <h2>Bitbucket Connection</h2>
    <p class="muted">Server: {_esc(bitbucket_url)}</p>
    <p class="muted">Connected owner: {_esc(connected_owner or "Not connected")}</p>
    <form method="post" action="/connect">
      <label>Personal Access Token</label>
      <input type="password" name="token" value="">
      <p class="muted">Saved token available: {"Yes" if has_saved_pat else "No"}</p>
      <div class="actions">
        <label><input type="checkbox" name="use_saved_token" value="true"> Use saved token</label>
        <label><input type="checkbox" name="remember" value="true"> Remember token locally</label>
      </div>
      <div class="actions" style="margin-top:12px"><button type="submit">Connect</button></div>
    </form>
  </article>
  <article class="card">
    <h2>Current Scan</h2>
    <div class="stats">
      <div class="stat"><span class="muted">State</span><strong>{_esc(status.get("state", "idle"))}</strong></div>
      <div class="stat"><span class="muted">Active</span><strong>{_esc(status.get("active_count", 0))}</strong></div>
      <div class="stat"><span class="muted">Suppressed</span><strong>{_esc(status.get("suppressed_count", 0))}</strong></div>
      <div class="stat"><span class="muted">Progress</span><strong>{_esc(status.get("progress", 0))}/{_esc(status.get("total", 0))}</strong></div>
    </div>
    <p class="meta" style="margin-top:12px">Repo: {_esc(status.get("current_repo", "-"))} | File: {_esc(status.get("current_file", "-"))}</p>
    <div class="actions" style="margin-top:12px">
      <form method="post" action="/scan/stop"><button type="submit" class="warn">Stop Scan</button></form>
      <a href="/scan">Refresh</a>
      {f'<a href="/reports/{_esc(report.get("html_name", ""))}">Latest HTML Report</a>' if report.get("html_name") else ""}
      {f'<a href="/reports/{_esc(report.get("csv_name", ""))}">Latest CSV Report</a>' if report.get("csv_name") else ""}
      {f'<a href="/api/history/log/{_esc(status.get("scan_id", ""))}">Current Log</a>' if status.get("scan_id") else ""}
    </div>
  </article>
</section>
<section class="grid two" style="margin-top:16px">
  <article class="card">
    <h2>Start Scan</h2>
    <form method="get" action="/scan">
      <label>Project</label>
      <select name="project">{''.join(options)}</select>
      <div class="actions" style="margin-top:12px"><button type="submit" class="alt">Load Repositories</button></div>
    </form>
    <form method="post" action="/scan/start" style="margin-top:16px">
      <input type="hidden" name="project_key" value="{_esc(selected_project)}">
      <label>LLM URL</label>
      <input type="text" name="llm_url" value="{_esc(llm_cfg.get("base_url", ""))}">
      <label style="margin-top:12px">LLM Model</label>
      <input type="text" name="llm_model" value="{_esc(llm_cfg.get("model", ""))}">
      <label style="margin-top:12px">Repositories</label>
      <div class="repo-list">{_render_repo_options(repos, selected_repos)}</div>
      <div class="actions" style="margin-top:12px"><button type="submit">Start Scan</button></div>
    </form>
  </article>
  <article class="card">
    <h2>Recent Log Lines</h2>
    <pre>{_esc(log_text or "No log output yet.")}</pre>
  </article>
</section>"""
    active_findings = "".join(
        _render_finding(finding, action_path="/findings/triage", reset_path="/findings/reset")
        for finding in status.get("finding_details", [])
    ) or '<div class="muted">No active findings in the current session.</div>'
    suppressed_findings = "".join(
        _render_finding(finding, action_path="/findings/triage", reset_path="/findings/reset")
        for finding in status.get("suppressed_details", [])
    ) or '<div class="muted">No suppressed findings in the current session.</div>'
    body = (
        summary
        + f'<section class="card" style="margin-top:16px"><h2>Active Findings</h2><div class="finding-list">{active_findings}</div></section>'
        + f'<section class="card" style="margin-top:16px"><h2>Suppressed Findings</h2><div class="finding-list">{suppressed_findings}</div></section>'
    )
    auto_refresh = 5 if status.get("state") == "running" else None
    return _layout(title="Scan", active="scan", body=body, auto_refresh=auto_refresh)


def render_history_page(*, history: list[dict], notice: str = "", error: str = "") -> bytes:
    rows = []
    for rec in history:
        reports = (rec.get("reports") or {}).get("__all__", {})
        delta = rec.get("delta") or {}
        html_link = f'<a href="/reports/{_esc(reports.get("html_name", ""))}">HTML</a> ' if reports.get("html_name") else ""
        csv_link = f'<a href="/reports/{_esc(reports.get("csv_name", ""))}">CSV</a> ' if reports.get("csv_name") else ""
        log_link = f'<a href="/api/history/log/{_esc(rec.get("scan_id", ""))}">Log</a>' if rec.get("log_file") else ""
        rows.append(
            "<tr>"
            f'<td><input type="checkbox" name="scan_ids" value="{_esc(rec.get("scan_id", ""))}"></td>'
            f"<td>{_esc(rec.get('scan_id', ''))}</td>"
            f"<td>{_esc(rec.get('project_key', ''))}</td>"
            f"<td>{_esc(', '.join(rec.get('repo_slugs', [])))}</td>"
            f"<td>{_esc(rec.get('state', ''))}</td>"
            f"<td>{_esc(rec.get('finding_total', 0))}</td>"
            f"<td>{_esc(rec.get('suppressed_total', 0))}</td>"
            f"<td>{_esc(delta.get('new_count', 0))}/{_esc(delta.get('fixed_count', 0))}</td>"
            f"<td>{html_link}{csv_link}{log_link}</td>"
            "</tr>"
        )
    table = "".join(rows) or '<tr><td colspan="9">No scan history available.</td></tr>'
    body = f"""
{_flash(notice, error)}
<section class="card">
  <h2>Scan History</h2>
  <form method="post" action="/history/delete">
    <div class="actions" style="margin-bottom:12px"><button type="submit" class="warn">Delete Selected</button></div>
    <table>
      <thead>
        <tr><th></th><th>Scan ID</th><th>Project</th><th>Repositories</th><th>State</th><th>Findings</th><th>Suppressed</th><th>Delta</th><th>Artifacts</th></tr>
      </thead>
      <tbody>{table}</tbody>
    </table>
  </form>
</section>"""
    return _layout(title="History", active="history", body=body)


def render_settings_page(
    *,
    bitbucket_url: str,
    output_dir: str,
    llm_cfg: dict,
    notice: str = "",
    error: str = "",
) -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="grid two">
  <article class="card">
    <h2>Application Settings</h2>
    <form method="post" action="/settings/save">
      <label>Bitbucket URL</label>
      <input type="text" value="{_esc(bitbucket_url)}" disabled>
      <label style="margin-top:12px">Output Directory</label>
      <input type="text" name="output_dir" value="{_esc(output_dir)}">
      <label style="margin-top:12px">LLM URL</label>
      <input type="text" name="llm_url" value="{_esc(llm_cfg.get('base_url', ''))}">
      <label style="margin-top:12px">LLM Model</label>
      <input type="text" name="llm_model" value="{_esc(llm_cfg.get('model', ''))}">
      <div class="actions" style="margin-top:12px"><button type="submit">Save Settings</button></div>
    </form>
  </article>
  <article class="card">
    <h2>Migration Note</h2>
    <p class="muted">This UI is now server-rendered. Dynamic behavior should be added only where it clearly earns the complexity.</p>
  </article>
</section>"""
    return _layout(title="Settings", active="settings", body=body)
