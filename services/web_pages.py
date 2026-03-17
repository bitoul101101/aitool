from __future__ import annotations

from html import escape
from typing import Iterable


def _esc(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _base_style() -> str:
    return """
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f6efe4;color:#261507}
header{display:flex;align-items:center;gap:18px;padding:14px 20px;background:#4a210c;color:#fff}
header h1{margin:0;font-size:18px}
nav{display:flex;gap:10px;margin-left:auto}
.nav{color:#f7e0c0;text-decoration:none;padding:8px 12px;border-radius:8px}
.nav.active,.nav:hover{background:#6d3514;color:#fff}
main{max-width:1280px;margin:0 auto;padding:24px}
.card{background:#fffaf4;border:1px solid #d8b995;border-radius:14px;padding:18px}
.notice,.error{padding:12px 14px;border-radius:10px;margin-bottom:16px}
.notice{background:#e8f5e5;border:1px solid #b8d3b0;color:#224d22}
.error{background:#f8e5e2;border:1px solid #dfb1aa;color:#7d2a22}
.muted{color:#705333}
button,.btn{border:0;border-radius:8px;padding:10px 14px;background:#6d3514;color:#fff;font-weight:700;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}
button.alt,.btn.alt{background:#8a6c50}
button.warn,.btn.warn{background:#a2392f}
button.ghost,.btn.ghost{background:#efe1cf;color:#5d3b15}
label{display:block;font-size:12px;font-weight:700;margin-bottom:6px;color:#6d4a21;text-transform:uppercase}
input,select,textarea{width:100%;padding:10px 12px;border:1px solid #cda983;border-radius:8px;background:#fff}
a{color:#7d3200}
table{width:100%;border-collapse:collapse;background:#fffaf4}
th,td{padding:10px 12px;border-bottom:1px solid #ead4ba;text-align:left;vertical-align:top}
th{background:#f0deca;font-size:12px;text-transform:uppercase;color:#67461f;white-space:nowrap}
.grid{display:grid;gap:16px}
.grid.two{grid-template-columns:280px 1fr}
.inline{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.stack{display:grid;gap:12px}
.hidden{display:none!important}
.pill{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;background:#efe1cf;color:#5d3b15;font-size:12px;font-weight:700}
.status-running{background:#fff3d8;color:#8a5b00}
.status-done{background:#e3f3e3;color:#225522}
.status-stopped{background:#f6dddd;color:#7b1d1d}
.link-btn{background:none;border:0;padding:0;color:#7d3200;text-decoration:underline;cursor:pointer}
@media (max-width:980px){.grid.two{grid-template-columns:1fr}header{flex-wrap:wrap}nav{margin-left:0}}
"""


def _flash(notice: str = "", error: str = "") -> str:
    items = []
    if notice:
        items.append(f'<div class="notice">{_esc(notice)}</div>')
    if error:
        items.append(f'<div class="error">{_esc(error)}</div>')
    return "".join(items)


def _layout(*, title: str, body: str, active: str = "", show_nav: bool = True, auto_refresh: int | None = None) -> bytes:
    refresh = f'<meta http-equiv="refresh" content="{auto_refresh}">' if auto_refresh else ""
    nav = ""
    if show_nav:
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
    <div>
      <label>Personal Access Token</label>
      <input type="password" name="token" value="">
    </div>
    <label><input type="checkbox" name="use_saved_token" value="true"> Use saved token</label>
    <label><input type="checkbox" name="remember" value="true"> Remember token locally</label>
    <div class="muted">Saved token available: {"Yes" if has_saved_pat else "No"}</div>
    <div><button type="submit">Login</button></div>
  </form>
</section>"""
    return _layout(title="Login", body=body, show_nav=False)


def _repo_grid_items(repos: Iterable[dict], selected_repos: Iterable[str]) -> str:
    selected = set(selected_repos)
    items = []
    for repo in repos:
        slug = repo.get("slug", "")
        checked = " checked" if slug in selected else ""
        items.append(
            f'<label class="repo-item" data-repo-name="{_esc(slug.lower())}">'
            f'<input type="checkbox" class="repo-checkbox" name="repo_slugs" value="{_esc(slug)}"{checked}> '
            f'<span>{_esc(slug)}</span></label>'
        )
    return "".join(items) or '<div class="muted">No repositories available for the selected project.</div>'


def render_scan_page(
    *,
    connected_owner: str,
    projects: list[dict],
    selected_project: str,
    repos: list[dict],
    selected_repos: list[str],
    llm_cfg: dict,
    llm_models: list[str],
    status: dict,
    notice: str = "",
    error: str = "",
) -> bytes:
    project_items = []
    for project in projects:
        key = project.get("key", "")
        active = " style=\"font-weight:800;text-decoration:underline\"" if key == selected_project else ""
        project_items.append(f'<a href="/scan?project={_esc(key)}"{active}>{_esc(key)}</a>')
    models = list(dict.fromkeys([m for m in llm_models if m] + [llm_cfg.get("model", "")]))
    model_options = []
    for model in models:
        selected = " selected" if model == llm_cfg.get("model", "") else ""
        model_options.append(f'<option value="{_esc(model)}"{selected}>{_esc(model)}</option>')
    running = status.get("state") == "running"
    stop_button = '<a class="btn warn" href="#" onclick="document.getElementById(\'stop-form\').submit();return false;">Stop Scan</a>' if running else ""
    banner = ""
    if running:
        banner = (
            f'<div class="notice">Scan running for {_esc(status.get("project_key") or selected_project)}. '
            f'Current repo: {_esc(status.get("current_repo", "-"))}. You can move to History or Settings without stopping it.</div>'
        )
    findings = status.get("finding_details", [])
    findings_html = "".join(
        f'<tr><td>{_esc(f.get("repo", ""))}</td><td>{_esc(f.get("file", ""))}:{_esc(f.get("line", ""))}</td><td>{_esc(f.get("severity_label", f.get("severity", "")))}</td><td>{_esc(f.get("capability", ""))}</td><td>{_esc(f.get("description", ""))}</td></tr>'
        for f in findings[:20]
    ) or '<tr><td colspan="5">No current findings to display.</td></tr>'
    body = f"""
{_flash(notice, error)}
{banner}
<section class="grid two">
  <aside class="card">
    <h2 style="margin:0 0 12px">Projects</h2>
    <div class="stack">{''.join(project_items) or '<div class="muted">No projects loaded yet.</div>'}</div>
  </aside>
  <section class="card">
    <div class="inline" style="justify-content:space-between;margin-bottom:12px">
      <h2 style="margin:0">Repositories</h2>
      <span class="pill">Connected as {_esc(connected_owner or "Unknown")}</span>
    </div>
    <form method="post" action="/scan/start" class="stack" id="scan-form">
      <input type="hidden" name="project_key" value="{_esc(selected_project)}">
      <div class="inline">
        <div style="flex:1 1 280px">
          <label>Search Repositories</label>
          <input type="search" id="repo-search" placeholder="Search by repo name">
        </div>
        <div style="flex:1 1 220px">
          <label>LLM Model</label>
          <select name="llm_model" id="llm-model-select">{''.join(model_options)}</select>
        </div>
        <div style="flex:1 1 220px">
          <label>LLM URL</label>
          <input type="text" name="llm_url" id="llm-url-input" value="{_esc(llm_cfg.get("base_url", ""))}">
        </div>
      </div>
      <div class="inline">
        <button type="button" class="ghost" id="refresh-models-btn">Refresh Models</button>
        <button type="button" class="ghost" id="select-all-repos-btn">Select All</button>
        <button type="button" class="ghost" id="select-none-repos-btn">Select None</button>
        <span class="muted" id="repo-selection-count"></span>
      </div>
      <div id="model-refresh-status" class="muted"></div>
      <div id="repo-grid" style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px">{_repo_grid_items(repos, selected_repos)}</div>
      <div class="inline">
        <button type="submit">Start Scan</button>
        {stop_button}
      </div>
    </form>
    <form method="post" action="/scan/stop" id="stop-form"></form>
  </section>
</section>
<section class="card" style="margin-top:18px">
  <div class="inline" style="justify-content:space-between">
    <h2 style="margin:0">Current Findings</h2>
    <span class="muted">Showing up to 20 findings from the current session</span>
  </div>
  <table style="margin-top:12px">
    <thead><tr><th>Repo</th><th>Location</th><th>Severity</th><th>Capability</th><th>Description</th></tr></thead>
    <tbody>{findings_html}</tbody>
  </table>
</section>
<script>
const repoSearch=document.getElementById('repo-search');
const repoGrid=document.getElementById('repo-grid');
const repoCount=document.getElementById('repo-selection-count');
function repoCheckboxes(){{return Array.from(document.querySelectorAll('.repo-checkbox'));}}
function updateRepoCount(){{const checked=repoCheckboxes().filter(cb=>cb.checked && cb.closest('.repo-item') && cb.closest('.repo-item').style.display!=='none').length;repoCount.textContent=`${{checked}} selected`;}}
function filterRepos(){{const q=(repoSearch.value||'').toLowerCase().trim();Array.from(document.querySelectorAll('.repo-item')).forEach(item=>{{const name=item.dataset.repoName||'';item.style.display=!q||name.includes(q)?'':'none';}});updateRepoCount();}}
repoSearch?.addEventListener('input',filterRepos);
document.getElementById('select-all-repos-btn')?.addEventListener('click',()=>{{repoCheckboxes().forEach(cb=>{{if(cb.closest('.repo-item').style.display!=='none') cb.checked=true;}});updateRepoCount();}});
document.getElementById('select-none-repos-btn')?.addEventListener('click',()=>{{repoCheckboxes().forEach(cb=>cb.checked=false);updateRepoCount();}});
repoCheckboxes().forEach(cb=>cb.addEventListener('change',updateRepoCount));
document.getElementById('refresh-models-btn')?.addEventListener('click',async()=>{{
 const url=(document.getElementById('llm-url-input').value||'').trim();
 const status=document.getElementById('model-refresh-status');
 const select=document.getElementById('llm-model-select');
 status.textContent='Refreshing model list...';
 try {{
   const resp=await fetch('/api/ollama/models?url='+encodeURIComponent(url));
   const data=await resp.json();
   const current=select.value;
   const models=(data.models||[]);
   select.innerHTML='';
   if(!models.length) {{
     const opt=document.createElement('option'); opt.value=current; opt.textContent=current || 'No models found'; select.appendChild(opt);
   }} else {{
     models.forEach(model=>{{const opt=document.createElement('option'); opt.value=model; opt.textContent=model; if(model===current) opt.selected=true; select.appendChild(opt);}});
     if(current && !models.includes(current)) {{const opt=document.createElement('option'); opt.value=current; opt.textContent=current+' (current)'; opt.selected=true; select.appendChild(opt);}}
   }}
   status.textContent='Model list refreshed.';
 }} catch(err) {{
   status.textContent='Failed to refresh models.';
 }}
}});
filterRepos();
</script>"""
    auto_refresh = 5 if running else None
    return _layout(title="Scan", body=body, active="scan", auto_refresh=auto_refresh)


def render_history_page(*, history: list[dict], notice: str = "", error: str = "") -> bytes:
    rows = []
    for rec in history:
        reports = (rec.get("reports") or {}).get("__all__", {})
        repo_label = ", ".join(rec.get("repo_slugs", rec.get("repos", [])))
        state = rec.get("state", "")
        status_class = {
            "running": "status-running",
            "done": "status-done",
            "stopped": "status-stopped",
        }.get(str(state).lower(), "")
        started = rec.get("started_at_utc") or ""
        total_findings = rec.get("total", rec.get("finding_total", rec.get("active_total", 0)))
        critical_prod = rec.get("critical_prod", 0)
        high_prod = rec.get("high_prod", 0)
        llm_model = rec.get("llm_model", "")
        duration = rec.get("duration_s", 0)
        project = rec.get("project_key", rec.get("project", ""))
        html_link = f'<a href="/reports/{_esc(reports.get("html_name", ""))}" target="_blank" title="Open HTML report">&#128196;</a>' if reports.get("html_name") else ""
        csv_link = f'<a href="/reports/{_esc(reports.get("csv_name", ""))}" download title="Download CSV">&#11015;</a>' if reports.get("csv_name") else ""
        log_link = f'<a href="/api/history/log/{_esc(rec.get("scan_id", ""))}" target="_blank" title="Open log">&#128221;</a>' if rec.get("log_file") else ""
        rows.append(
            f'<tr data-project="{_esc(project)}" data-repo="{_esc(repo_label)}" data-status="{_esc(state)}" data-model="{_esc(llm_model)}">'
            f'<td><input type="checkbox" class="history-check" name="scan_ids" value="{_esc(rec.get("scan_id", ""))}"></td>'
            f'<td>{_esc(started)}</td>'
            f'<td>{_esc(project)}</td>'
            f'<td>{_esc(repo_label)}</td>'
            f'<td>{_esc(total_findings)}</td>'
            f'<td>{_esc(critical_prod)}</td>'
            f'<td>{_esc(high_prod)}</td>'
            f'<td>{_esc(llm_model)}</td>'
            f'<td>{_esc(duration)}</td>'
            f'<td><span class="pill {status_class}">{_esc(state.title())}</span></td>'
            f'<td>{html_link}</td><td>{csv_link}</td><td>{log_link}</td></tr>'
        )
    projects = sorted({str(rec.get("project_key", rec.get("project", ""))) for rec in history if rec.get("project_key") or rec.get("project")})
    repos = sorted({", ".join(rec.get("repo_slugs", rec.get("repos", []))) for rec in history if rec.get("repo_slugs") or rec.get("repos")})
    statuses = sorted({str(rec.get("state", "")) for rec in history if rec.get("state")})
    models = sorted({str(rec.get("llm_model", "")) for rec in history if rec.get("llm_model")})
    def opts(values: list[str], label: str) -> str:
        return f'<option value="">{_esc(label)}</option>' + "".join(f'<option value="{_esc(v)}">{_esc(v)}</option>' for v in values)
    body = f"""
{_flash(notice, error)}
<section class="card">
  <div class="inline" style="justify-content:space-between;margin-bottom:14px">
    <h2 style="margin:0">History</h2>
    <div class="inline">
      <input type="search" id="history-search" placeholder="Search any column" style="width:240px">
      <select id="filter-project">{opts(projects, 'All Projects')}</select>
      <select id="filter-repo">{opts(repos, 'All Repos')}</select>
      <select id="filter-status">{opts(statuses, 'All Statuses')}</select>
      <select id="filter-model">{opts(models, 'All Models')}</select>
      <button type="button" class="ghost" id="reset-history-filters">Reset</button>
    </div>
  </div>
  <form method="post" action="/history/delete" id="history-form">
    <div class="inline" style="margin-bottom:12px">
      <button type="submit" class="warn hidden" id="delete-selected-btn">Delete Selected Repos</button>
    </div>
    <table id="history-table">
      <thead>
        <tr>
          <th></th>
          <th data-sort="datetime">Date/Time</th>
          <th data-sort="text">Project</th>
          <th data-sort="text">Repo</th>
          <th data-sort="number">Total Findings</th>
          <th data-sort="number">Critical in Prod</th>
          <th data-sort="number">High in Prod</th>
          <th data-sort="text">LLM Model</th>
          <th data-sort="number">Duration</th>
          <th data-sort="text">Status</th>
          <th data-sort="none">HTML</th>
          <th data-sort="none">CSV</th>
          <th data-sort="none">LOG</th>
        </tr>
      </thead>
      <tbody>{''.join(rows) or '<tr><td colspan="13">No scan history available.</td></tr>'}</tbody>
    </table>
  </form>
</section>
<script>
const hTable=document.getElementById('history-table');
const hTbody=hTable?.querySelector('tbody');
const searchBox=document.getElementById('history-search');
const filterProject=document.getElementById('filter-project');
const filterRepo=document.getElementById('filter-repo');
const filterStatus=document.getElementById('filter-status');
const filterModel=document.getElementById('filter-model');
const deleteBtn=document.getElementById('delete-selected-btn');
function historyRows(){{return Array.from(hTbody.querySelectorAll('tr')).filter(r=>r.querySelectorAll('td').length>1);}}
function updateDeleteButton(){{const anyChecked=historyRows().some(r=>r.querySelector('.history-check')?.checked);deleteBtn.classList.toggle('hidden',!anyChecked);}}
function applyHistoryFilters(){{
 const q=(searchBox.value||'').toLowerCase().trim();
 historyRows().forEach(row=>{{
   const text=row.textContent.toLowerCase();
   const matchesSearch=!q || text.includes(q);
   const matchesProject=!filterProject.value || row.dataset.project===filterProject.value;
   const matchesRepo=!filterRepo.value || row.dataset.repo===filterRepo.value;
   const matchesStatus=!filterStatus.value || row.dataset.status===filterStatus.value;
   const matchesModel=!filterModel.value || row.dataset.model===filterModel.value;
   row.style.display=(matchesSearch && matchesProject && matchesRepo && matchesStatus && matchesModel)?'':'none';
 }});
 updateDeleteButton();
}}
function cellValue(row,index,kind){{
 const text=(row.children[index]?.innerText||'').trim();
 if(kind==='number') return Number(text)||0;
 if(kind==='datetime') return Date.parse(text)||0;
 return text.toLowerCase();
}}
let currentSort={{index:1,dir:-1,kind:'datetime'}};
function sortHistory(index,kind){{
 const rows=historyRows();
 if(currentSort.index===index) currentSort.dir*=-1; else currentSort={{index,dir:kind==='datetime'?-1:1,kind}};
 rows.sort((a,b)=>{{
   const av=cellValue(a,currentSort.index,currentSort.kind);
   const bv=cellValue(b,currentSort.index,currentSort.kind);
   if(av<bv) return -1*currentSort.dir;
   if(av>bv) return 1*currentSort.dir;
   return 0;
 }});
 rows.forEach(row=>hTbody.appendChild(row));
 applyHistoryFilters();
}}
Array.from(document.querySelectorAll('#history-table thead th')).forEach((th,index)=>{{
 const kind=th.dataset.sort;
 if(kind && kind!=='none') th.style.cursor='pointer';
 if(kind && kind!=='none') th.addEventListener('click',()=>sortHistory(index,kind));
}});
document.getElementById('reset-history-filters')?.addEventListener('click',()=>{{searchBox.value='';filterProject.value='';filterRepo.value='';filterStatus.value='';filterModel.value='';applyHistoryFilters();}});
[searchBox,filterProject,filterRepo,filterStatus,filterModel].forEach(el=>el?.addEventListener('input',applyHistoryFilters));
[filterProject,filterRepo,filterStatus,filterModel].forEach(el=>el?.addEventListener('change',applyHistoryFilters));
historyRows().forEach(row=>row.querySelector('.history-check')?.addEventListener('change',updateDeleteButton));
sortHistory(1,'datetime');
</script>"""
    return _layout(title="History", body=body, active="history")


def render_settings_page(*, bitbucket_url: str, output_dir: str, llm_cfg: dict, notice: str = "", error: str = "") -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="card" style="max-width:760px">
  <h2 style="margin:0 0 12px">Settings</h2>
  <form method="post" action="/settings/save" class="stack">
    <div>
      <label>Bitbucket URL</label>
      <input type="text" value="{_esc(bitbucket_url)}" disabled>
    </div>
    <div>
      <label>Output Directory</label>
      <input type="text" name="output_dir" value="{_esc(output_dir)}">
    </div>
    <div>
      <label>LLM URL</label>
      <input type="text" name="llm_url" value="{_esc(llm_cfg.get('base_url', ''))}">
    </div>
    <div>
      <label>LLM Model</label>
      <input type="text" name="llm_model" value="{_esc(llm_cfg.get('model', ''))}">
    </div>
    <div><button type="submit">Save Settings</button></div>
  </form>
</section>"""
    return _layout(title="Settings", body=body, active="settings")
