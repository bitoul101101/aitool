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


def _base_style() -> str:
    return """
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f6efe4;color:#261507}
header{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:14px;padding:12px 18px;background:#4a210c;color:#fff;position:sticky;top:0;z-index:20;box-shadow:0 2px 10px rgba(0,0,0,.18)}
header h1{margin:0;font-size:18px}
.header-nav{display:flex;justify-content:center;gap:8px;align-items:center}
.header-actions{display:flex;justify-content:flex-end}
.nav{color:#f7e0c0;text-decoration:none;padding:7px 11px;border-radius:8px}
.nav.active,.nav:hover{background:#6d3514;color:#fff}
.exit-form{margin:0}
main{max-width:1340px;margin:0 auto;padding:16px 18px}
.login-page main{min-height:calc(100vh - 70px);display:flex;align-items:center;justify-content:center}
.card{background:#fffaf4;border:1px solid #d8b995;border-radius:14px;padding:14px}
.notice,.error{padding:10px 12px;border-radius:10px}
.notice{background:#e8f5e5;border:1px solid #b8d3b0;color:#224d22}
.error{background:#f8e5e2;border:1px solid #dfb1aa;color:#7d2a22}
.warn-box{padding:10px 12px;border-radius:10px;background:#fff3d8;border:1px solid #e1bf77;color:#7a5310}
.toast-wrap{position:fixed;left:14px;bottom:14px;display:grid;gap:8px;z-index:1000}
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
.login-shell{width:min(100%,420px);margin:0 auto}
.login-grid{display:grid;gap:14px}
.login-actions{display:flex;justify-content:center}
.login-title{text-align:center;margin:0 0 6px}
.scan-shell{display:grid;grid-template-columns:minmax(0,1fr);gap:14px;align-items:start}
.selection-grid{display:grid;grid-template-columns:220px minmax(0,1fr);gap:14px;align-items:start}
.project-panel,.repo-panel,.activity-panel{min-height:calc(100vh - 132px)}
.project-list{display:grid;gap:2px;max-height:calc(100vh - 200px);overflow:auto;padding-right:4px}
.project-link{display:block;padding:4px 7px;border-radius:8px;text-decoration:none;background:#f6ebdc;color:#5e3b16;font-size:12px}
.project-link.active{background:#6d3514;color:#fff;font-weight:700}
.repo-toolbar{display:grid;grid-template-columns:minmax(180px,1fr) 240px auto;gap:8px;align-items:end;margin-bottom:8px}
.repo-actions{display:flex;align-items:center;gap:8px;margin:8px 0 10px}
.repo-notices{display:grid;gap:8px;margin-bottom:8px}
.repo-shell{border:1px solid #ead4ba;border-radius:12px;background:#fcf6ee;padding:8px}
.repo-grid{display:grid;gap:2px 12px;max-height:calc(100vh - 285px);overflow:auto;padding-right:4px;align-content:start}
.repo-grid.cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}
.repo-grid.cols-3{grid-template-columns:repeat(3,minmax(0,1fr))}
.repo-row{display:flex;align-items:center;gap:6px;padding:1px 4px;border-radius:6px;font-size:12px;line-height:1.15}
.repo-row input{width:auto;margin:0;flex:0 0 auto;transform:translateY(1px)}
.repo-row span{display:block}
.running-shell{display:grid;grid-template-columns:minmax(0,1fr) 220px;gap:14px;align-items:start}
.scan-sidebar-head{display:grid;gap:8px}
.scan-status{display:flex;justify-content:space-between;align-items:center;gap:8px}
.scan-status strong{font-size:16px}
.scan-status .muted{font-size:13px}
.scan-actions{display:flex;gap:8px;flex-wrap:wrap}
.scan-actions .warn,.scan-actions .btn{padding:7px 10px;font-size:12px}
.state-icon{width:16px;height:16px;border-radius:50%;background:#2a7cff;display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:12px;font-weight:700}
.state-icon.pending{background:#bfa78c}
.state-icon.running{animation:blink 1s ease-in-out infinite}
.state-icon.done{background:#20a955;box-shadow:0 0 0 2px rgba(255,255,255,.18) inset}
.state-icon.stopped{background:#a2392f}
.state-icon.stopped::before{content:"!"}
.timeline-row{display:grid;grid-template-columns:auto 1fr auto;gap:8px;padding:8px 10px;border-radius:10px;background:#f6ebdc;font-size:13px;align-items:center}
.timeline-row.total-row,.timeline .timeline-row:last-child{margin-top:8px;padding-top:12px;border-top:2px solid #cfae8a;border-radius:0 0 10px 10px}
.timeline-name{text-transform:capitalize}
.terminal{background:#18120d;color:#f5debe;border:1px solid #3f2a19;border-radius:12px;padding:12px;height:560px;overflow:auto;font-family:Cascadia Code,Consolas,monospace;font-size:12px;line-height:1.45;white-space:pre-wrap}
.timeline{display:grid;gap:8px}
.timeline-row strong{justify-self:end}
.findings-panel,.mitigate-section,.suppressed-section{margin-top:12px;padding:12px;border:2px solid #cda274;border-radius:14px;background:#fffdf8}
.finding-table-wrap{max-height:240px;overflow:auto;border:1px solid #ead4ba;border-radius:12px}
.finding-table-wrap table,.mitigate-wrap table,.suppressed-wrap table{font-size:12px}
.finding-meta{display:grid;gap:4px}
.finding-main{display:flex;align-items:center;gap:6px;font-weight:600;flex-wrap:wrap}
.finding-loc{font-size:11px;color:#7a5d3e;font-family:Cascadia Code,Consolas,monospace}
.finding-sub{font-size:11px;color:#705333}
.score-strip{display:flex;gap:6px;flex-wrap:wrap;margin-top:2px}
.score-pill{display:inline-flex;align-items:center;gap:4px;padding:2px 6px;border:1px solid #d8bf9f;border-radius:999px;background:#f6eee4;color:#5b3a16;font-size:10px;font-weight:600}
.sev-chip{display:inline-flex;align-items:center;padding:2px 7px;border-radius:999px;font-size:10px;font-weight:700;text-transform:uppercase;color:#fff}
.sev-1{background:#b42318}
.sev-2{background:#e05c00}
.sev-3{background:#b07a00}
.sev-4{background:#4f7b39}
.finding-snippet{margin-top:2px;padding:6px 8px;border-radius:8px;background:#f6ebdc;color:#5a4021;font-family:Cascadia Code,Consolas,monospace;font-size:10px;line-height:1.35;white-space:pre-wrap;overflow-wrap:anywhere}
.triage-state{display:inline-flex;align-items:center;padding:3px 7px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;background:#efe1cf;color:#5d3b15}
.triage-reviewed{background:#e3efff;color:#164a95}
.triage-accepted_risk{background:#fff1dc;color:#8a5b00}
.triage-false_positive{background:#e5f3e7;color:#1f6a35}
.triage-note{font-size:12px;color:#5f4527}
.triage-actions{display:flex;flex-direction:column;gap:4px;align-items:stretch}
.triage-form{display:flex;gap:6px;align-items:center;margin:0}
.triage-form.inline-only{display:inline-flex}
.triage-form button{padding:3px 6px;font-size:10px;width:100%}
.mitigate-section h3,.suppressed-section h3{margin:0 0 8px;font-size:15px}
.mitigate-wrap,.suppressed-wrap{max-height:220px;overflow:auto;border:1px solid #ead4ba;border-radius:12px}
  .report-actions{display:grid;gap:8px;margin:12px 0 0}
  .baseline-summary{display:grid;gap:8px}
  .baseline-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}
  .baseline-stat{padding:10px 12px;border:1px solid #ead4ba;border-radius:12px;background:#fffdf8}
  .baseline-stat strong{display:block;font-size:20px;line-height:1.1}
  .baseline-label{display:block;font-size:11px;color:#705333;text-transform:uppercase;letter-spacing:.04em}
  .baseline-fixed-list{margin:0;padding-left:18px;font-size:12px;color:#4b331b}
  .baseline-fixed-list li{margin:0 0 6px}
  .inventory-summary{display:grid;gap:8px}
  .inventory-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}
  .inventory-grid-wide{grid-template-columns:repeat(6,minmax(0,1fr))}
  .inventory-stat{padding:10px 12px;border:1px solid #ead4ba;border-radius:12px;background:#fffdf8}
  .inventory-stat strong{display:block;font-size:18px;line-height:1.1}
  .inventory-list{display:flex;flex-wrap:wrap;gap:6px}
  .inventory-chip{display:inline-flex;align-items:center;padding:3px 8px;border-radius:999px;background:#efe1cf;color:#5d3b15;font-size:11px;font-weight:700}
  .inventory-repos{display:grid;gap:8px}
  .inventory-repo{padding:8px 10px;border:1px solid #ead4ba;border-radius:10px;background:#fffdf8}
  .inventory-repo strong{display:block;margin-bottom:4px}
  .inventory-meta{font-size:11px;color:#705333}
  button[disabled],.btn.disabled{opacity:.5;cursor:not-allowed}
.history-toolbar{display:grid;grid-template-columns:minmax(220px,1fr) repeat(4,170px) auto auto;gap:8px;align-items:end;position:sticky;top:0;background:#fffaf4;padding-bottom:10px;z-index:3}
.inventory-toolbar{display:grid;grid-template-columns:minmax(220px,1fr) repeat(4,180px) auto;gap:8px;align-items:end;position:sticky;top:0;background:#fffaf4;padding-bottom:10px;z-index:3}
.inventory-page-grid{display:grid;gap:14px}
.inventory-summary-cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}
.inventory-card-stat{padding:10px 12px;border:1px solid #ead4ba;border-radius:12px;background:#fffdf8}
.inventory-card-stat strong{display:block;font-size:20px;line-height:1.1}
.inventory-bool{display:inline-flex;min-width:34px;justify-content:center;padding:3px 7px;border-radius:999px;font-size:11px;font-weight:700}
.inventory-bool.yes{background:#e3f3e3;color:#225522}
.inventory-bool.no{background:#efe1cf;color:#6f5234}
.inventory-sub{font-size:11px;color:#705333}
.table-shell{max-height:calc(100vh - 220px);overflow:auto;border:1px solid #ead4ba;border-radius:12px}
.table-shell thead th{position:sticky;top:0;z-index:2}
.table-shell tbody tr:hover{background:#f4eadb}
.history-time{font-size:11px;color:#7a5d3e}
.history-pagination{display:flex;justify-content:flex-end;align-items:center;gap:8px;margin-top:10px}
.history-pagination .page-info{font-size:12px;color:#705333}
.icon-link img{display:block;width:34px;height:34px}
.filters-row{margin-bottom:12px}
.results-shell{display:grid;gap:14px}
.results-toolbar{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap}
.results-title h2{margin:0 0 4px;font-size:22px}
.results-title p{margin:0;color:#705333}
.results-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.results-frame{width:100%;min-height:calc(100vh - 220px);border:1px solid #d8b995;border-radius:14px;background:#fff}
@media (max-width:1220px){.selection-grid,.running-shell{grid-template-columns:1fr}.project-panel,.repo-panel,.activity-panel{min-height:auto}.inventory-grid-wide{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:900px){header{grid-template-columns:1fr}.header-nav,.header-actions{justify-content:flex-start}.selection-grid{grid-template-columns:1fr}.repo-grid.cols-3{grid-template-columns:repeat(2,minmax(0,1fr))}.history-toolbar,.inventory-toolbar{grid-template-columns:1fr 1fr}.inventory-summary-cards{grid-template-columns:1fr 1fr}.table-shell{max-height:none}.inventory-grid-wide{grid-template-columns:repeat(2,minmax(0,1fr))}}
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


def _csrf_field(csrf_token: str = "") -> str:
    return f'<input type="hidden" name="csrf_token" value="{_esc(csrf_token)}">' if csrf_token else ""


def _layout(*, title: str, body: str, active: str = "", show_nav: bool = True, show_scan_results: bool = True, csrf_token: str = "") -> bytes:
    nav = ""
    body_class = "login-page" if not show_nav else ""
    if show_nav:
        nav = (
            '<div class="header-nav">'
            + f'<a class="nav{" active" if active == "new_scan" else ""}" href="/scan?new=1">New Scan</a>'
            + (f'<a class="nav{" active" if active == "scan" else ""}" href="/scan">Scan Results</a>' if show_scan_results else "")
            + f'<a class="nav{" active" if active == "inventory" else ""}" href="/inventory">AI Inventory</a>'
            + f'<a class="nav{" active" if active == "history" else ""}" href="/history">History</a>'
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
<style>{_base_style()}</style>
</head>
<body class="{body_class}">
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
    force_selection: bool = False,
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
    repo_count = len(repos)
    repo_cols = "cols-2" if repo_count <= 18 else "cols-3"
    project_links = "".join(
        f'<a class="project-link{" active" if p.get("key","") == selected_project else ""}" href="/scan?project={_esc(p.get("key",""))}{project_query_suffix}">{_esc(p.get("key",""))}</a>'
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
    report_actions = ""
    if scan_complete and all_findings:
        html_name = report.get("html_name", "")
        csv_name = report.get("csv_name", "")
        log_url = f"/api/history/log/{_esc(scan_id)}" if scan_id else ""
        buttons = []
        if html_name and scan_id:
            buttons.append(f'<a class="btn" id="open-results-page" href="/results/{_esc(scan_id)}">Open Results</a>')
        if html_name:
            buttons.append(f'<a class="btn alt" id="open-html-report" href="/reports/{_esc(html_name)}" target="_blank">Open HTML Report</a>')
        if csv_name:
            buttons.append(f'<a class="btn alt" id="download-csv-report" href="/reports/{_esc(csv_name)}" download>Download CSV File</a>')
        if log_url:
            buttons.append(f'<a class="btn ghost" id="download-log-report" href="{log_url}" download>Download Logs</a>')
        report_actions = f'<div class="report-actions" id="report-actions">{"".join(buttons)}</div>'
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
        <div><label>LLM Model</label><select name="llm_model" id="llm-model-select">{model_options}</select></div>
        <div class="inline" style="justify-content:flex-start;align-items:end"><button type="submit" id="start-scan-btn"{" disabled" if start_blocked or not selected else ""}>Start Scan</button></div>
      </div>
      <div class="repo-notices">
        <div class="warn-box{" hidden" if not running_notice else ""}" id="running-scan-notice">{_esc(running_notice)}</div>
        <div class="warn-box{" hidden" if not model_warning else ""}" id="model-size-warning">{_esc(model_warning)}</div>
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
<form method="post" action="/scan/stop" id="stop-form">{_csrf_field(csrf_token)}</form>"""
    running_view = f"""
<section class="running-shell">
  <section class="card activity-panel">
    <div>
      <h2 style="margin:0 0 8px;font-size:16px">Activity Log</h2>
      <div class="terminal" id="scan-log">{_esc(log_text or "No activity yet.")}</div>
    </div>
  </section>
  <aside class="stack">
    <section class="card scan-sidebar-head">
      <div class="scan-status">
        <strong>Scan</strong>
        <div id="scan-state-text" class="muted">{_esc(state_text)}</div>
      </div>
      <div class="scan-actions">{stop_button if running else ""}{new_scan_button}</div>
    </section>
    <section class="card">
      <h2 style="margin:0 0 8px;font-size:16px">Phase Timeline</h2>
      <div class="timeline" id="phase-timeline">{timeline_html}</div>
    </section>
    {baseline_html}
    {inventory_html}
    {f'<section class="card" id="reports-card"><h2 style="margin:0 0 8px;font-size:16px">Reports</h2>{report_actions}</section>' if report_actions else '<section class="card hidden" id="reports-card"><h2 style="margin:0 0 8px;font-size:16px">Reports</h2><div class="report-actions" id="report-actions"></div></section>'}
  </aside>
</section>
<form method="post" action="/scan/stop" id="stop-form">{_csrf_field(csrf_token)}</form>"""
    body = f"""
{_flash(notice, error)}
<section class="scan-shell">
  {running_view if (not force_selection and (running or state in ("done", "stopped") and log_text)) else selection_view}
</section>
<script src="/assets/scan_page.js" defer></script>"""
    return _layout(title="Scan", body=body, active="new_scan" if force_selection else "scan", show_scan_results=show_scan_results, csrf_token=csrf_token)


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
        date_text, time_text, ts = _fmt_dt(rec.get("started_at_utc", ""))
        state = str(rec.get("state", ""))
        status_class = {"running": "status-running", "done": "status-done", "stopped": "status-stopped"}.get(state.lower(), "")
        total_findings = rec.get("total", rec.get("finding_total", rec.get("active_total", 0)))
        delta = rec.get("delta") or {}
        delta_new = delta.get("new_count", 0)
        delta_existing = delta.get("existing_count", delta.get("unchanged_count", 0))
        delta_fixed = delta.get("fixed_count", 0)
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
            f'<td>{_esc(delta_new)}</td>'
            f'<td>{_esc(delta_existing)}</td>'
            f'<td>{_esc(delta_fixed)}</td>'
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
    {_csrf_field(csrf_token)}
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
            <th data-sort="number">New</th>
            <th data-sort="number">Existing</th>
            <th data-sort="number">Fixed</th>
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
<script>
const hBody=document.querySelector('#history-table tbody');
const search=document.getElementById('history-search');
const fp=document.getElementById('filter-project');
const fr=document.getElementById('filter-repo');
const fs=document.getElementById('filter-status');
const fm=document.getElementById('filter-model');
const delBtn=document.getElementById('delete-selected-btn');
const prevBtn=document.getElementById('history-prev-btn');
const nextBtn=document.getElementById('history-next-btn');
const pageInfo=document.getElementById('history-page-info');
const PAGE_SIZE=20;
let currentPage=1;
function rows(){{return Array.from(hBody.querySelectorAll('tr')).filter(r=>r.querySelectorAll('td').length>1);}}
function updateDelete(){{delBtn.classList.toggle('hidden',!rows().some(r=>r.querySelector('.history-check')?.checked));}}
function filteredRows(){{const q=(search.value||'').toLowerCase().trim();return rows().filter(row=>{{const text=row.textContent.toLowerCase();const ok=!q||text.includes(q);const okP=!fp.value||row.dataset.project===fp.value;const okR=!fr.value||row.dataset.repo===fr.value;const okS=!fs.value||row.dataset.status===fs.value;const okM=!fm.value||row.dataset.model===fm.value;return ok&&okP&&okR&&okS&&okM;}});}}
function renderPage(){{const visible=filteredRows();const totalPages=Math.max(1, Math.ceil(visible.length / PAGE_SIZE));currentPage=Math.min(currentPage,totalPages);const start=(currentPage-1)*PAGE_SIZE;const end=start+PAGE_SIZE;rows().forEach(row=>row.style.display='none');visible.slice(start,end).forEach(row=>row.style.display='');if(pageInfo) pageInfo.textContent=`Page ${{totalPages ? currentPage : 1}} of ${{totalPages}}`;if(prevBtn) prevBtn.disabled=currentPage<=1; if(nextBtn) nextBtn.disabled=currentPage>=totalPages; updateDelete();}}
function applyFilters(){{currentPage=1;renderPage();}}
let sortState={{index:null,dir:-1,kind:'datetime'}};
function cellValue(row,index,kind){{if(kind==='datetime') return Number(row.dataset.ts)||0; const text=(row.children[index]?.innerText||'').trim(); if(kind==='number') return Number(text.replace(':','.'))||0; return text.toLowerCase();}}
function sortHistory(index,kind){{const rs=rows(); if(sortState.index===index) sortState.dir*=-1; else sortState={{index,dir:kind==='datetime'?-1:1,kind}}; rs.sort((a,b)=>{{const av=cellValue(a,sortState.index,sortState.kind); const bv=cellValue(b,sortState.index,sortState.kind); if(av<bv) return -1*sortState.dir; if(av>bv) return 1*sortState.dir; return 0;}}); rs.forEach(r=>hBody.appendChild(r)); currentPage=1; renderPage();}}
document.querySelectorAll('#history-table thead th[data-sort]').forEach((th,index)=>th.addEventListener('click',()=>sortHistory(index+1,th.dataset.sort)));
[search,fp,fr,fs,fm].forEach(el=>el?.addEventListener('input',applyFilters));
[fp,fr,fs,fm].forEach(el=>el?.addEventListener('change',applyFilters));
document.getElementById('reset-history-filters')?.addEventListener('click',()=>{{search.value='';fp.value='';fr.value='';fs.value='';fm.value='';applyFilters();}});
rows().forEach(r=>r.querySelector('.history-check')?.addEventListener('change',updateDelete));
prevBtn?.addEventListener('click',()=>{{if(currentPage>1){{currentPage-=1;renderPage();}}}});
nextBtn?.addEventListener('click',()=>{{const totalPages=Math.max(1, Math.ceil(filteredRows().length / PAGE_SIZE)); if(currentPage<totalPages){{currentPage+=1;renderPage();}}}});
sortHistory(1,'datetime');
</script>"""
    return _layout(title="History", body=body, active="history", show_scan_results=show_scan_results, csrf_token=csrf_token)


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
    show_scan_results: bool = True,
    csrf_token: str = "",
    notice: str = "",
    error: str = "",
) -> bytes:
    toolbar_actions = []
    if html_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(html_name)}" target="_blank">Open Raw HTML</a>')
    if csv_name:
        toolbar_actions.append(f'<a class="btn alt" href="/reports/{_esc(csv_name)}" download>Download CSV File</a>')
    if log_url:
        toolbar_actions.append(f'<a class="btn ghost" href="{_esc(log_url)}" download>Download Logs</a>')
    body = f"""
{_flash(notice, error)}
<section class="results-shell">
  <section class="card">
    <div class="results-toolbar">
      <div class="results-title">
        <h2>Scan Results</h2>
        <p>Review the completed scan and download the generated artifacts.</p>
      </div>
      <div class="results-actions">
        <a class="btn ghost" href="/scan">Back to Scan</a>
        {''.join(toolbar_actions)}
      </div>
    </div>
  </section>
  <iframe class="results-frame" src="/reports/{_esc(html_name)}" title="Scan Results"></iframe>
</section>"""
    return _layout(title="Results", body=body, active="scan", show_scan_results=show_scan_results, csrf_token=csrf_token)


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


def render_settings_page(*, bitbucket_url: str, output_dir: str, llm_cfg: dict, notice: str = "", error: str = "", show_scan_results: bool = True, csrf_token: str = "") -> bytes:
    body = f"""
{_flash(notice, error)}
<section class="card" style="max-width:760px">
  <h2 style="margin:0 0 12px">Settings</h2>
  <form method="post" action="/settings/save" class="stack">
    {_csrf_field(csrf_token)}
    <div><label>Bitbucket URL</label><input type="text" value="{_esc(bitbucket_url)}" disabled></div>
    <div><label>Output Directory</label><input type="text" name="output_dir" value="{_esc(output_dir)}"></div>
    <div><label>LLM URL</label><input type="text" name="llm_url" value="{_esc(llm_cfg.get('base_url',''))}"></div>
    <div><label>LLM Model</label><input type="text" name="llm_model" value="{_esc(llm_cfg.get('model',''))}"></div>
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
      <li>Use <strong>History</strong> to revisit prior scans, open reports, download CSV output, or inspect logs.</li>
    </ol>
  </section>

  <section>
    <h3 style="margin:0 0 8px">Pages</h3>
    <table>
      <thead><tr><th>Page</th><th>What It Is For</th></tr></thead>
      <tbody>
        <tr><td>New Scan</td><td>Select project, repositories, and LLM model for a new run.</td></tr>
        <tr><td>Scan Results</td><td>Monitor the live activity log, phase timeline, findings sections, and report download buttons for the active or last run.</td></tr>
        <tr><td>AI Inventory</td><td>Review the latest known AI usage profile per repository, including providers, models, and usage patterns.</td></tr>
        <tr><td>History</td><td>Search, filter, sort, and open results from previous scans.</td></tr>
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
