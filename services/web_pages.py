from __future__ import annotations

from datetime import datetime
from html import escape
from urllib.parse import quote


def _esc(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _fmt_dt(value: str) -> tuple[str, str, int]:
    if not value:
        return "—", "", 0
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
header{display:flex;align-items:center;gap:14px;padding:12px 18px;background:#4a210c;color:#fff}
header h1{margin:0;font-size:18px}
nav{display:flex;gap:8px;margin-left:auto;align-items:center}
.nav{color:#f7e0c0;text-decoration:none;padding:7px 11px;border-radius:8px}
.nav.active,.nav:hover{background:#6d3514;color:#fff}
.exit-form{margin:0}
main{max-width:1340px;margin:0 auto;padding:16px 18px}
.card{background:#fffaf4;border:1px solid #d8b995;border-radius:14px;padding:14px}
.notice,.error{padding:10px 12px;border-radius:10px;margin-bottom:12px}
.notice{background:#e8f5e5;border:1px solid #b8d3b0;color:#224d22}
.error{background:#f8e5e2;border:1px solid #dfb1aa;color:#7d2a22}
.muted{color:#705333}
button,.btn{border:0;border-radius:8px;padding:9px 13px;background:#6d3514;color:#fff;font-weight:700;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}
button.alt,.btn.alt{background:#8a6c50}
button.warn,.btn.warn{background:#a2392f}
button.ghost,.btn.ghost{background:#efe1cf;color:#5d3b15}
label{display:block;font-size:11px;font-weight:700;margin-bottom:5px;color:#6d4a21;text-transform:uppercase}
input,select,textarea{width:100%;padding:8px 10px;border:1px solid #cda983;border-radius:8px;background:#fff}
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
.scan-shell{display:grid;grid-template-columns:220px minmax(0,1fr) 380px;gap:14px;align-items:start}
.project-panel,.repo-panel,.sidebar-panel{min-height:calc(100vh - 132px)}
.project-list{display:grid;gap:3px;max-height:calc(100vh - 190px);overflow:auto;padding-right:4px}
.project-link{display:block;padding:5px 8px;border-radius:8px;text-decoration:none;background:#f6ebdc;color:#5e3b16;font-size:13px}
.project-link.active{background:#6d3514;color:#fff;font-weight:700}
.repo-toolbar{display:grid;grid-template-columns:minmax(180px,1fr) 220px auto auto auto;gap:8px;align-items:end;margin-bottom:10px}
.repo-shell{border:1px solid #ead4ba;border-radius:12px;background:#fcf6ee;padding:8px}
.repo-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:4px 10px;max-height:300px;overflow:auto;padding-right:4px}
.repo-row{display:flex;align-items:center;gap:8px;padding:2px 4px;border-radius:6px;font-size:13px;line-height:1.2}
.repo-row input{width:auto;margin:0;flex:0 0 auto}
.repo-row span{display:block}
.scan-banner{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px}
.terminal{background:#18120d;color:#f5debe;border:1px solid #3f2a19;border-radius:12px;padding:12px;height:340px;overflow:auto;font-family:Cascadia Code,Consolas,monospace;font-size:12px;line-height:1.45;white-space:pre-wrap}
.finding-shell{position:sticky;top:16px}
.finding-table-wrap{max-height:calc(100vh - 170px);overflow:auto;border:1px solid #ead4ba;border-radius:12px}
.history-toolbar{display:grid;grid-template-columns:minmax(220px,1fr) repeat(4,170px) auto auto;gap:8px;align-items:end;position:sticky;top:0;background:#fffaf4;padding-bottom:10px;z-index:3}
.table-shell{max-height:calc(100vh - 220px);overflow:auto;border:1px solid #ead4ba;border-radius:12px}
.table-shell thead th{position:sticky;top:0;z-index:2}
.history-time{font-size:11px;color:#7a5d3e}
.icon-link img{display:block;width:34px;height:34px}
.filters-row{margin-bottom:12px}
@media (max-width:1220px){.scan-shell{grid-template-columns:200px 1fr}.sidebar-panel{grid-column:1 / -1}.finding-shell{position:static}.repo-toolbar{grid-template-columns:1fr 1fr auto auto auto}}
@media (max-width:900px){header{flex-wrap:wrap}nav{margin-left:0}.scan-shell{grid-template-columns:1fr}.project-panel,.repo-panel,.sidebar-panel{min-height:auto}.repo-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.history-toolbar{grid-template-columns:1fr 1fr}.table-shell{max-height:none}}
"""


def _flash(notice: str = "", error: str = "") -> str:
    parts = []
    if notice:
        parts.append(f'<div class="notice">{_esc(notice)}</div>')
    if error:
        parts.append(f'<div class="error">{_esc(error)}</div>')
    return "".join(parts)


def _layout(*, title: str, body: str, active: str = "", show_nav: bool = True, auto_refresh: int | None = None) -> bytes:
    refresh = f'<meta http-equiv="refresh" content="{auto_refresh}">' if auto_refresh else ""
    nav = ""
    if show_nav:
        nav = (
            f'<a class="nav{" active" if active == "scan" else ""}" href="/scan">Scan</a>'
            f'<a class="nav{" active" if active == "history" else ""}" href="/history">History</a>'
            f'<a class="nav{" active" if active == "settings" else ""}" href="/settings">Settings</a>'
            '<form class="exit-form" method="post" action="/app/exit"><button type="submit" class="warn">Exit</button></form>'
        )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{refresh}
<title>{_esc(title)}</title>
<style>{_base_style()}</style>
</head>
<body>
<header><h1>AI Security & Compliance Scanner</h1>{f"<nav>{nav}</nav>" if nav else ""}</header>
<main>{body}</main>
</body>
</html>"""
    return html.encode("utf-8")


def render_login_page(*, bitbucket_url: str, has_saved_pat: bool, notice: str = "", error: str = "") -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="card" style="max-width:540px;margin:48px auto 0">
  <h2 style="margin:0 0 12px">Login</h2>
  <p class="muted">Connect to {_esc(bitbucket_url)} with a Personal Access Token.</p>
  <form method="post" action="/login" class="stack" style="margin-top:16px">
    <div><label>Personal Access Token</label><input type="password" name="token" value=""></div>
    <label><input type="checkbox" name="use_saved_token" value="true"> Use saved token</label>
    <label><input type="checkbox" name="remember" value="true"> Remember token locally</label>
    <div class="muted">Saved token available: {"Yes" if has_saved_pat else "No"}</div>
    <div><button type="submit">Login</button></div>
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
    notice: str = "",
    error: str = "",
) -> bytes:
    running = status.get("state") == "running"
    project_links = "".join(
        f'<a class="project-link{" active" if p.get("key","") == selected_project else ""}" href="/scan?project={_esc(p.get("key",""))}">{_esc(p.get("key",""))}</a>'
        for p in projects
    ) or '<div class="muted">No projects loaded.</div>'
    selected = set(selected_repos)
    repo_rows = "".join(
        f'<label class="repo-row" data-repo-name="{_esc(repo.get("slug","").lower())}"><input type="checkbox" class="repo-checkbox" name="repo_slugs" value="{_esc(repo.get("slug",""))}"{" checked" if repo.get("slug","") in selected else ""}><span>{_esc(repo.get("slug",""))}</span></label>'
        for repo in repos
    ) or '<div class="muted">No repositories available for the selected project.</div>'
    models = list(dict.fromkeys([m for m in llm_models if m] + ([llm_cfg.get("model", "")] if llm_cfg.get("model") else [])))
    model_options = "".join(
        f'<option value="{_esc(model)}"{" selected" if model == llm_cfg.get("model", "") else ""}>{_esc(model)}</option>'
        for model in models
    )
    findings_rows = "".join(
        f"<tr><td>{_esc(f.get('repo',''))}</td><td>{_esc(f.get('file',''))}:{_esc(f.get('line',''))}</td><td>{_esc(f.get('severity_label', f.get('severity','')))}</td><td>{_esc(f.get('capability',''))}</td></tr>"
        for f in status.get("finding_details", [])[:20]
    ) or '<tr><td colspan="4">No current findings.</td></tr>'
    stop_button = '<button type="button" class="warn" onclick="document.getElementById(\'stop-form\').submit()">Stop Scan</button>' if running else ""
    banner = ""
    if running:
        banner = (
            f'<div class="notice scan-banner"><span>Scan running for {_esc(status.get("project_key") or selected_project)} '
            f'({int(status.get("progress",0))}/{int(status.get("total",0))} repos). '
            f'Current repo: {_esc(status.get("current_repo","-"))}</span>{stop_button}</div>'
        )
    body = f"""
{_flash(notice, error)}
{banner}
<section class="scan-shell">
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
        <button type="submit">Start Scan</button>
        <button type="button" class="ghost" id="refresh-models-btn">Refresh Models</button>
        <div class="inline" style="justify-content:flex-end">
          <button type="button" class="ghost" id="select-all-repos-btn">All</button>
          <button type="button" class="ghost" id="select-none-repos-btn">None</button>
        </div>
      </div>
      <div class="inline" style="justify-content:space-between">
        <div class="muted" id="repo-selection-count"></div>
        <div class="muted" id="model-refresh-status"></div>
      </div>
      <div class="repo-shell"><div id="repo-grid" class="repo-grid">{repo_rows}</div></div>
    </form>
    <form method="post" action="/scan/stop" id="stop-form"></form>
    <div style="margin-top:12px">
      <h2 style="margin:0 0 8px;font-size:16px">Activity Log</h2>
      <div class="terminal">{_esc(log_text or "No activity yet.")}</div>
    </div>
  </section>
  <aside class="card sidebar-panel">
    <div class="finding-shell">
      <h2 style="margin:0 0 8px;font-size:16px">Current Findings</h2>
      <div class="finding-table-wrap">
        <table>
          <thead><tr><th>Repo</th><th>Location</th><th>Severity</th><th>Capability</th></tr></thead>
          <tbody>{findings_rows}</tbody>
        </table>
      </div>
    </div>
  </aside>
</section>
<script>
const repoSearch=document.getElementById('repo-search');
const repoCount=document.getElementById('repo-selection-count');
function repoCheckboxes(){{return Array.from(document.querySelectorAll('.repo-checkbox'));}}
function updateRepoCount(){{repoCount.textContent=`${{repoCheckboxes().filter(cb=>cb.checked && cb.closest('.repo-row').style.display!=='none').length}} selected`;}}
function filterRepos(){{const q=(repoSearch.value||'').toLowerCase().trim();document.querySelectorAll('.repo-row').forEach(row=>{{row.style.display=!q || (row.dataset.repoName||'').includes(q)?'flex':'none';}});updateRepoCount();}}
repoSearch?.addEventListener('input',filterRepos);
document.getElementById('select-all-repos-btn')?.addEventListener('click',()=>{{repoCheckboxes().forEach(cb=>{{if(cb.closest('.repo-row').style.display!=='none') cb.checked=true;}});updateRepoCount();}});
document.getElementById('select-none-repos-btn')?.addEventListener('click',()=>{{repoCheckboxes().forEach(cb=>cb.checked=false);updateRepoCount();}});
repoCheckboxes().forEach(cb=>cb.addEventListener('change',updateRepoCount));
document.getElementById('refresh-models-btn')?.addEventListener('click',async()=>{{
 const status=document.getElementById('model-refresh-status');
 const select=document.getElementById('llm-model-select');
 status.textContent='Refreshing model list...';
 try {{
   const resp=await fetch('/api/ollama/models');
   const data=await resp.json();
   const current=select.value;
   const models=(data.models||[]);
   select.innerHTML='';
   models.forEach(model=>{{const opt=document.createElement('option');opt.value=model;opt.textContent=model;if(model===current) opt.selected=true;select.appendChild(opt);}});
   if(current && !models.includes(current)) {{const opt=document.createElement('option');opt.value=current;opt.textContent=current+' (current)';opt.selected=true;select.appendChild(opt);}}
   status.textContent='Model list refreshed.';
 }} catch (err) {{
   status.textContent='Failed to refresh models.';
 }}
}});
filterRepos();
</script>"""
    return _layout(title="Scan", body=body, active="scan", auto_refresh=5 if running else None)


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
let sortState={{index:1,dir:-1,kind:'datetime'}};
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
