#!/usr/bin/env python3
"""
AI Security & Compliance Scanner
PAT login → project/repo selection (checkboxes + search) → live scan → summary
"""

import sys
import json
import threading
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner.bitbucket import BitbucketClient
from scanner.detector import AIUsageDetector
from analyzer.security import SecurityAnalyzer
from aggregator.aggregator import Aggregator
from reports.csv_report import CSVReporter
from reports.html_report import HTMLReporter
from reports.delta import build_delta_meta
from reports.report_server import open_report, stop_all
from scanner.pat_store import save_pat, load_pat, delete_pat, backend_name, is_available
from services.runtime_support import (
    ensure_ollama_running,
    load_llm_config as load_llm_config_file,
    ollama_list_models,
    ollama_ping,
    save_llm_config as save_llm_config_file,
)

# ── Config ────────────────────────────────────────────────────────
BITBUCKET_URL    = "https://bitbucket.cognyte.local:8443"
OUTPUT_DIR       = "./output"
LOG_DIR          = "./logs"
TEMP_DIR         = "./tmp_clones"
POLICY_FILE      = "policy.json"
OWNER_MAP_FILE   = "owner_map.json"

# ── LLM reviewer config (persisted to JSON) ──────────────────────
# LLM review runs on every scan — it is not optional.
LLM_CONFIG_FILE     = "ai_scanner_llm_config.json"
OLLAMA_START_TIMEOUT = 12   # seconds to wait for ollama serve to become ready

def load_llm_config() -> dict:
    """Load LLM settings from JSON file, falling back to defaults."""
    return load_llm_config_file(LLM_CONFIG_FILE)

def save_llm_config(cfg: dict) -> None:
    """Persist LLM settings to JSON file."""
    save_llm_config_file(LLM_CONFIG_FILE, cfg)


def _ollama_ping(base_url: str) -> bool:
    """Return True if Ollama is reachable at base_url."""
    return ollama_ping(base_url, timeout=4)


def _ollama_ensure_running(base_url: str, log_fn=None) -> bool:
    """
    If Ollama is not reachable, attempt to start it with `ollama serve`.
    Waits up to OLLAMA_START_TIMEOUT seconds for it to become ready.
    Returns True when reachable, False if start failed.
    """
    ok, _status = ensure_ollama_running(
        base_url,
        timeout_s=OLLAMA_START_TIMEOUT,
        log_fn=log_fn,
    )
    return ok


def _ollama_list_models(base_url: str) -> list:
    """Return list of model name strings from Ollama /api/tags."""
    return ollama_list_models(base_url, timeout=6)

# ── Palette ───────────────────────────────────────────────────────
BG      = "#1e2130"
CARD    = "#262b3d"
ACCENT  = "#4f8ef7"
ACCENT2 = "#6c63ff"
TEXT    = "#e8eaf0"
DIM     = "#8b90a0"
SUCCESS = "#43d98d"
WARNING = "#ffa94d"
DANGER  = "#ff6b6b"
BORDER  = "#343a52"
IN_BG   = "#2d3348"
BTN_GO  = "#2ecc71"
BTN_GO2 = "#27ae60"
CHK_BG  = "#232840"   # checkbox list background


# ── Helpers ───────────────────────────────────────────────────────
def load_policy(path):
    if Path(path).exists():
        with open(path) as f:
            return json.load(f)
    return {"approved_providers": [], "banned_providers": []}


def load_owner_map(path):
    if Path(path).exists():
        with open(path) as f:
            return json.load(f)
    return {}


def fit_center(win, min_w=320, min_h=200, pad_x=80, pad_y=80):
    """Size window to content then center it, respecting a minimum."""
    win.update_idletasks()
    w = max(win.winfo_reqwidth()  + pad_x, min_w)
    h = max(win.winfo_reqheight() + pad_y, min_h)
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


def center_fixed(win, w, h):
    win.update_idletasks()
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


def lbl(parent, text, size=13, bold=False, color=TEXT, bg=BG, **kw):
    return tk.Label(parent, text=text, bg=bg, fg=color,
                    font=("Segoe UI", size, "bold" if bold else "normal"), **kw)


def inp(parent, show=None, width=32):
    return tk.Entry(parent, show=show, width=width,
                    bg=IN_BG, fg=TEXT, insertbackground=TEXT,
                    relief="flat", font=("Segoe UI", 13),
                    highlightthickness=1, highlightcolor=ACCENT,
                    highlightbackground=BORDER)


def make_btn(parent, text, cmd, color=ACCENT, hover=ACCENT2, fg="#fff",
             width=18, size=12):
    b = tk.Button(parent, text=text, command=cmd,
                  bg=color, fg=fg, activebackground=hover,
                  activeforeground=fg, relief="flat",
                  font=("Segoe UI", size, "bold"),
                  width=width, cursor="hand2", pady=9, padx=10)
    b.bind("<Enter>", lambda e: b.config(bg=hover))
    b.bind("<Leave>", lambda e: b.config(bg=color))
    return b


# ── Session-level PAT store (survives New Scan, cleared on exit) ──
_SESSION_PAT: str = ""


def open_file(path):
    p = str(Path(path).resolve())
    if sys.platform == "win32":
        os.startfile(p)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", p])
    else:
        subprocess.Popen(["xdg-open", p])


# ══════════════════════════════════════════════════════════════════
#  SCREEN 1 — Login (PAT only, no username field)
# ══════════════════════════════════════════════════════════════════
class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AI Security & Compliance Scanner")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)
        self._build()
        fit_center(self.root, min_w=420, min_h=280)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        stop_all()
        self.root.destroy()

    def _build(self):
        r = self.root
        global _SESSION_PAT

        hdr = tk.Frame(r, bg=CARD, pady=16)
        hdr.pack(fill="x")
        lbl(hdr, "🔍  AI Security & Compliance Scanner",
            15, bold=True, bg=CARD).pack()
        lbl(hdr, "Bitbucket Security Scan",
            9, color=DIM, bg=CARD).pack(pady=(3, 0))

        frm = tk.Frame(r, bg=BG, padx=44)
        frm.pack(fill="both", expand=True, pady=24)

        lbl(frm, "Personal Access Token (PAT)").pack(anchor="w", pady=(8, 2))
        self.t = inp(frm, show="●")
        self.t.pack(fill="x", ipady=5)

        # Task 13: Pre-fill from keyring first, fall back to session memory
        _saved = load_pat() or _SESSION_PAT
        if _saved:
            self.t.insert(0, _saved)

        # Explicit clipboard bindings — needed for password-style fields on Windows
        def _paste(e=None):
            try:
                text = self.t.clipboard_get()
                # Replace selection if any, otherwise insert at cursor
                try:
                    self.t.delete("sel.first", "sel.last")
                except tk.TclError:
                    pass
                self.t.insert(tk.INSERT, text.strip())
            except tk.TclError:
                pass
            return "break"

        def _copy(e=None):
            try:
                sel = self.t.selection_get()
                self.t.clipboard_clear()
                self.t.clipboard_append(sel)
            except tk.TclError:
                pass
            return "break"

        def _cut(e=None):
            _copy()
            try:
                self.t.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
            return "break"

        def _select_all(e=None):
            self.t.select_range(0, tk.END)
            self.t.icursor(tk.END)
            return "break"

        for seq in ("<Control-v>", "<Control-V>", "<Shift-Insert>"):
            self.t.bind(seq, _paste)
        for seq in ("<Control-c>", "<Control-C>"):
            self.t.bind(seq, _copy)
        for seq in ("<Control-x>", "<Control-X>"):
            self.t.bind(seq, _cut)
        for seq in ("<Control-a>", "<Control-A>"):
            self.t.bind(seq, _select_all)
        # Right-click context menu
        ctx = tk.Menu(self.t, tearoff=0, bg=CARD, fg=TEXT,
                      activebackground=ACCENT, activeforeground="#fff",
                      font=("Segoe UI", 10))
        ctx.add_command(label="Paste", command=_paste)
        ctx.add_command(label="Copy",  command=_copy)
        ctx.add_command(label="Cut",   command=_cut)
        ctx.add_separator()
        ctx.add_command(label="Select All", command=_select_all)
        self.t.bind("<Button-3>",
                    lambda e: ctx.tk_popup(e.x_root, e.y_root))

        # Task 13: "Remember PAT" checkbox + "Forget saved PAT" link
        opt_row = tk.Frame(frm, bg=BG)
        opt_row.pack(fill="x", pady=(8, 0))

        self._remember_var = tk.BooleanVar(value=bool(_saved))
        chk = tk.Checkbutton(
            opt_row,
            text="Remember PAT",
            variable=self._remember_var,
            bg=BG, fg=DIM,
            selectcolor=IN_BG,
            activebackground=BG,
            activeforeground=TEXT,
            font=("Segoe UI", 9),
            cursor="hand2",
        )
        chk.pack(side="left")

        # Show forget link only if a saved PAT exists in the keyring
        if is_available() and load_pat():
            def _forget():
                delete_pat()
                self.t.delete(0, tk.END)
                self._remember_var.set(False)
                self.st.config(text="Saved PAT removed.", fg=WARNING)
                # Hide the forget link after use
                forget_lk.pack_forget()

            forget_lk = tk.Label(
                opt_row,
                text="Forget saved PAT",
                bg=BG, fg=DANGER,
                font=("Segoe UI", 9, "underline"),
                cursor="hand2",
            )
            forget_lk.pack(side="right")
            forget_lk.bind("<Button-1>", lambda e: _forget())

        # Backend info — shown only when keyring is not available (so user knows why)
        if not is_available():
            be = backend_name()
            lbl(frm, f"ℹ PAT will not be saved between sessions ({be})",
                8, color=DIM).pack(anchor="w", pady=(2, 0))

        self.st = lbl(frm, "", 9, color=DIM)
        self.st.pack(pady=(12, 0))

        make_btn(frm, "Connect  →", self._login,
                 width=22, size=11).pack(pady=(12, 0))

        self.t.focus()
        r.bind("<Return>", lambda e: self._login())

    def _login(self):
        t = self.t.get().strip()
        if not t:
            self.st.config(text="Please enter your Personal Access Token.", fg=DANGER)
            return
        self.st.config(text="Connecting...", fg=DIM)
        self.root.update()
        threading.Thread(target=self._connect, args=(t,), daemon=True).start()

    def _connect(self, token):
        global _SESSION_PAT
        try:
            client = BitbucketClient(
                base_url=BITBUCKET_URL, token=token,
                verify_ssl=False, verbose=False)
            pat_owner = client.get_pat_owner()
            projects  = client.list_projects()
            _SESSION_PAT = token   # persist for New Scan (in-memory)

            # Task 13: save to OS keyring if "Remember PAT" is checked
            if getattr(self, "_remember_var", None) and self._remember_var.get():
                save_pat(token)   # no-op if keyring unavailable
            else:
                # If user unchecked "Remember", remove any previously saved PAT
                if not getattr(self, "_remember_var", None) or not self._remember_var.get():
                    delete_pat()

            self.root.after(0, lambda: self._ok(client, pat_owner, projects))
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda m=msg: self.st.config(
                text=f"Failed: {m}", fg=DANGER))

    def _ok(self, client, pat_owner, projects):
        self.st.config(
            text=f"✓ Connected — {len(projects)} project(s)", fg=SUCCESS)
        self.root.update()
        self.root.after(400, lambda: (
            self.root.destroy(),
            SelectorWindow(client, pat_owner, projects)))


# ══════════════════════════════════════════════════════════════════
#  SCREEN 2 — Select Targets  (checkboxes + search)
# ══════════════════════════════════════════════════════════════════
class SelectorWindow:
    def __init__(self, client, pat_owner, projects):
        self.client    = client
        self.pat_owner = pat_owner
        self.projects  = projects
        self.cache     = {}          # project_key → [repo dicts]
        self._proj     = None
        self._repos    = []          # full repo list for current project
        self._vars     = {}          # slug → BooleanVar

        self.root = tk.Tk()
        self.root.title("AI Security & Compliance Scanner — Select Targets")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self._build()
        center_fixed(self.root, 780, 580)
        self.root.mainloop()

    def _build(self):
        r = self.root

        # ── Header ──
        hdr = tk.Frame(r, bg=CARD, pady=10)
        hdr.pack(fill="x")
        lbl(hdr, "Select Scan Targets", 14, bold=True, bg=CARD).pack()
        if self.pat_owner and self.pat_owner != "Unknown":
            lbl(hdr, self.pat_owner, 9, color=DIM, bg=CARD).pack(pady=(2, 0))

        # ── Footer — MUST be packed before expanding body ──
        foot = tk.Frame(r, bg="#1a1f30", pady=12, padx=16)
        foot.pack(fill="x", side="bottom")
        self.sel_lbl = lbl(foot,
                           "← Select a project, then tick repos",
                           10, color=DIM, bg="#1a1f30")
        self.sel_lbl.pack(side="left")
        self.go = make_btn(foot, "▶  START SCAN", self._go,
                           color=BTN_GO, hover=BTN_GO2,
                           fg="#000000", width=18, size=11)
        self.go.pack(side="right")
        self.go.config(state="disabled")

        # ── LLM review panel (always-on) ─────────────────────────────
        _llm_cfg = load_llm_config()

        llm_outer = tk.Frame(r, bg=CARD, padx=16, pady=8)
        llm_outer.pack(fill="x", side="bottom")

        # Title row
        llm_hdr = tk.Frame(llm_outer, bg=CARD)
        llm_hdr.pack(fill="x")
        lbl(llm_hdr, "🧠  LLM Review", 10, bold=True, bg=CARD).pack(side="left")
        self._llm_status = lbl(llm_hdr, "starting…", 9, color=DIM, bg=CARD)
        self._llm_status.pack(side="left", padx=(12, 0))

        # Settings row
        llm_cfg_row = tk.Frame(llm_outer, bg=CARD)
        llm_cfg_row.pack(fill="x", pady=(6, 0))

        lbl(llm_cfg_row, "URL:", 9, color=DIM, bg=CARD).pack(side="left")
        self._llm_url = inp(llm_cfg_row, width=26)
        self._llm_url.insert(0, _llm_cfg.get("base_url", "http://localhost:11434"))
        self._llm_url.pack(side="left", ipady=3, padx=(4, 14))

        lbl(llm_cfg_row, "Model:", 9, color=DIM, bg=CARD).pack(side="left")

        # ttk.Combobox for model selection
        _combo_style = ttk.Style()
        _combo_style.theme_use("default")
        _combo_style.configure("LLM.TCombobox",
            fieldbackground=IN_BG, background=IN_BG,
            foreground=TEXT, selectbackground=IN_BG,
            selectforeground=TEXT,
            arrowcolor=TEXT, bordercolor=BORDER,
        )
        # In readonly state the entire field is "selected" — override so the
        # text colour stays readable instead of disappearing into the highlight.
        _combo_style.map("LLM.TCombobox",
            fieldbackground=[("readonly", IN_BG), ("focus", IN_BG)],
            foreground=[("readonly", TEXT), ("focus", TEXT)],
            selectbackground=[("readonly", IN_BG)],
            selectforeground=[("readonly", TEXT)],
            background=[("active", CARD), ("pressed", CARD)],
        )
        self._llm_model_var = tk.StringVar(
            value=_llm_cfg.get("model", "qwen2.5-coder:7b-instruct"))
        self._llm_combo = ttk.Combobox(
            llm_cfg_row,
            textvariable=self._llm_model_var,
            style="LLM.TCombobox",
            width=30, font=("Segoe UI", 9), state="readonly",
        )
        self._llm_combo.pack(side="left", ipady=3, padx=(4, 10))

        refresh_btn = make_btn(
            llm_cfg_row, "⟳", self._llm_refresh,
            color=CARD, hover=BORDER, fg=TEXT, width=3, size=11)
        refresh_btn.pack(side="left")

        # Kick off initial load: ensure Ollama running, then populate dropdown
        threading.Thread(target=self._llm_init, daemon=True).start()

        # ── Body: two columns (expand=True — must come last) ──
        body = tk.Frame(r, bg=BG, padx=16, pady=12)
        body.pack(fill="both", expand=True)

        # ─ Left: project list ─
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="y", padx=(0, 12))

        lbl(left, "Projects", bold=True).pack(anchor="w")
        lbl(left, "Click to load repos  →",
            8, color=DIM).pack(anchor="w", pady=(0, 5))

        pf = tk.Frame(left, bg=BORDER, bd=1)
        pf.pack(fill="y", expand=True)
        self.pbox = tk.Listbox(
            pf, width=22, height=22,
            bg=IN_BG, fg=TEXT,
            selectbackground=ACCENT, selectforeground="#fff",
            relief="flat", font=("Segoe UI", 10),
            activestyle="none", highlightthickness=0)
        ps = ttk.Scrollbar(pf, orient="vertical", command=self.pbox.yview)
        self.pbox.config(yscrollcommand=ps.set)
        self.pbox.pack(side="left", fill="both", expand=True)
        ps.pack(side="left", fill="y")
        for p in self.projects:
            self.pbox.insert("end", f"  {p.get('key','?')}")
        self.pbox.bind("<<ListboxSelect>>", self._pick_proj)

        # ─ Right: repo checkboxes + search ─
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        # Header row for repos
        rh = tk.Frame(right, bg=BG)
        rh.pack(fill="x", pady=(0, 4))
        lbl(rh, "Repositories", bold=True).pack(side="left")
        self.rcnt = lbl(rh, "", 9, color=DIM)
        self.rcnt.pack(side="left", padx=8)

        # Search box
        sch = tk.Frame(right, bg=BG)
        sch.pack(fill="x", pady=(0, 6))
        lbl(sch, "🔍", 10, bg=BG, color=DIM).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search)
        sch_entry = tk.Entry(sch, textvariable=self.search_var,
                             bg=IN_BG, fg=TEXT, insertbackground=TEXT,
                             relief="flat", font=("Segoe UI", 10),
                             highlightthickness=1, highlightcolor=ACCENT,
                             highlightbackground=BORDER)
        sch_entry.pack(side="left", fill="x", expand=True, ipady=4, padx=(4, 0))

        # Select-all / none row
        ctrl = tk.Frame(right, bg=BG)
        ctrl.pack(fill="x", pady=(0, 4))
        tk.Button(ctrl, text="Select All", command=self._select_all,
                  bg=CARD, fg=TEXT, relief="flat",
                  font=("Segoe UI", 9), cursor="hand2",
                  padx=8, pady=2).pack(side="left", padx=(0, 6))
        tk.Button(ctrl, text="Select None", command=self._select_none,
                  bg=CARD, fg=TEXT, relief="flat",
                  font=("Segoe UI", 9), cursor="hand2",
                  padx=8, pady=2).pack(side="left")

        # Scrollable checkbox frame
        chk_outer = tk.Frame(right, bg=BORDER, bd=1)
        chk_outer.pack(fill="both", expand=True)

        self.chk_canvas = tk.Canvas(chk_outer, bg=CHK_BG,
                                    highlightthickness=0)
        chk_sb = ttk.Scrollbar(chk_outer, orient="vertical",
                                command=self.chk_canvas.yview)
        self.chk_canvas.configure(yscrollcommand=chk_sb.set)
        self.chk_canvas.pack(side="left", fill="both", expand=True)
        chk_sb.pack(side="right", fill="y")

        self.chk_inner = tk.Frame(self.chk_canvas, bg=CHK_BG)
        self._chk_win  = self.chk_canvas.create_window(
            (0, 0), window=self.chk_inner, anchor="nw")

        self.chk_canvas.bind("<Configure>",
            lambda e: self.chk_canvas.itemconfig(
                self._chk_win, width=e.width))
        self.chk_inner.bind("<Configure>",
            lambda e: self.chk_canvas.configure(
                scrollregion=self.chk_canvas.bbox("all")))
        # Mouse-wheel scroll
        self.chk_canvas.bind_all("<MouseWheel>",
            lambda e: self.chk_canvas.yview_scroll(
                int(-1*(e.delta/120)), "units"))

    # ── Project selection ─────────────────────────────────────────
    def _pick_proj(self, _):
        sel = self.pbox.curselection()
        if not sel:
            return
        key = self.projects[sel[0]].get("key", "")
        if key == self._proj:
            return
        self._proj = key
        self._clear_checkboxes()
        self.rcnt.config(text="Loading...", fg=DIM)
        self.search_var.set("")
        if key in self.cache:
            self._fill(self.cache[key])
        else:
            threading.Thread(target=self._fetch,
                             args=(key,), daemon=True).start()

    def _fetch(self, key):
        try:
            repos = self.client.list_repos(key)
            self.cache[key] = repos
            self.root.after(0, lambda: self._fill(repos))
        except Exception as e:
            err = str(e)
            self.root.after(0, lambda m=err: self.rcnt.config(
                text=f"Error: {m}", fg=DANGER))

    def _fill(self, repos):
        self._repos = repos
        self.search_var.set("")
        self._rebuild_checkboxes(repos)
        total = len(repos)
        self.rcnt.config(text=f"{total} repo(s)", fg=DIM)

    def _clear_checkboxes(self):
        for w in self.chk_inner.winfo_children():
            w.destroy()
        self._vars = {}

    def _rebuild_checkboxes(self, repos_to_show):
        """Rebuild the visible checkboxes, preserving existing var states."""
        # Destroy only the checkbox widgets, keep vars
        for w in self.chk_inner.winfo_children():
            w.destroy()

        for repo in repos_to_show:
            slug = repo.get("slug", "")
            if slug not in self._vars:
                self._vars[slug] = tk.BooleanVar(value=False)
            var = self._vars[slug]
            cb = tk.Checkbutton(
                self.chk_inner,
                text=f"  {slug}",
                variable=var,
                command=self._update_count,
                bg=CHK_BG, fg=TEXT,
                selectcolor=IN_BG,
                activebackground=CHK_BG,
                activeforeground=TEXT,
                font=("Segoe UI", 10),
                anchor="w",
                relief="flat",
                cursor="hand2",
            )
            cb.pack(fill="x", padx=6, pady=1)

        self._update_count()

    def _on_search(self, *_):
        q = self.search_var.get().strip().lower()
        filtered = [r for r in self._repos
                    if q in r.get("slug", "").lower()] if q else self._repos
        self._rebuild_checkboxes(filtered)

    def _select_all(self):
        q = self.search_var.get().strip().lower()
        for repo in self._repos:
            slug = repo.get("slug", "")
            if not q or q in slug.lower():
                if slug in self._vars:
                    self._vars[slug].set(True)
        self._update_count()

    def _select_none(self):
        for v in self._vars.values():
            v.set(False)
        self._update_count()

    def _update_count(self):
        n = sum(1 for v in self._vars.values() if v.get())
        if n:
            self.sel_lbl.config(text=f"✓  {n} repo(s) selected", fg=SUCCESS)
            self.go.config(state="normal")
        else:
            self.sel_lbl.config(
                text="← Tick repos to scan", fg=DIM)
            self.go.config(state="disabled")

    def _llm_init(self):
        """Ensure Ollama is running then populate the model dropdown."""
        url = self._llm_url.get().strip() or "http://localhost:11434"
        self.root.after(0, lambda: self._llm_status.config(
            text="connecting to Ollama…", fg=DIM))

        ok = _ollama_ensure_running(url)
        if not ok:
            self.root.after(0, lambda: self._llm_status.config(
                text="⚠  Ollama not reachable — install from ollama.com", fg=WARNING))
            return

        models = _ollama_list_models(url)
        if not models:
            self.root.after(0, lambda: self._llm_status.config(
                text="⚠  No models found — run: ollama pull qwen2.5-coder:7b-instruct",
                fg=WARNING))
            return

        saved = self._llm_model_var.get()

        def _apply(models=models, saved=saved):
            self._llm_combo.config(values=models, state="readonly")
            # Keep saved selection if still available, else pick first
            if saved in models:
                self._llm_model_var.set(saved)
            else:
                self._llm_model_var.set(models[0])
            self._llm_status.config(
                text=f"✓  {len(models)} model(s) available", fg=SUCCESS)

        self.root.after(0, _apply)

    def _llm_refresh(self):
        """Re-fetch models when user clicks ⟳ (e.g. after pulling a new model)."""
        self._llm_status.config(text="refreshing…", fg=DIM)
        self._llm_combo.config(values=[], state="disabled")
        threading.Thread(target=self._llm_init, daemon=True).start()

    def _go(self):
        slugs = [slug for slug, v in self._vars.items() if v.get()]
        if not slugs:
            messagebox.showwarning("No selection",
                                   "Tick at least one repo.")
            return
        llm_url   = self._llm_url.get().strip()       or "http://localhost:11434"
        llm_model = self._llm_model_var.get().strip() or "qwen2.5-coder:7b-instruct"
        save_llm_config({"base_url": llm_url, "model": llm_model})
        self.root.destroy()
        ScanWindow(self.client, self.pat_owner,
                   self._proj, slugs,
                   llm_enabled=True,
                   llm_url=llm_url,
                   llm_model=llm_model)


# ══════════════════════════════════════════════════════════════════
#  SCREEN 3 — Live Scan + Summary
# ══════════════════════════════════════════════════════════════════
class ScanWindow:
    def __init__(self, client, pat_owner, project_key,
                 repo_slugs,
                 llm_enabled: bool = False,
                 llm_url: str = "http://localhost:11434",
                 llm_model: str = "qwen2.5-coder:7b-instruct"):
        self.client      = client
        self.pat_owner   = pat_owner
        self.project_key = project_key
        self.repo_slugs  = repo_slugs
        self.llm_enabled = llm_enabled
        self.llm_url     = llm_url
        self.llm_model   = llm_model
        self.scan_id       = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._report_paths = {}
        self._log_lines    = []
        self._stop_event   = threading.Event()   # set to request cancel
        self._proc_holder  = []                  # active git subprocess, if any
        self._proc_lock    = threading.Lock()    # guards _proc_holder (Task 9)

        self.root = tk.Tk()
        self.root.title("AI Security & Compliance Scanner — Scanning...")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        center_fixed(self.root, 1140, 580)
        self._build()
        self.root.after(300, lambda: threading.Thread(
            target=self._run, daemon=True).start())
        self.root.mainloop()

    def _build(self):
        r = self.root

        hdr = tk.Frame(r, bg=CARD, pady=10)
        hdr.pack(fill="x")
        lbl(hdr, "Scanning Repositories", 14, bold=True, bg=CARD).pack()
        sub_parts = [p for p in [
            self.project_key,
            f"{len(self.repo_slugs)} repo(s)" if self.repo_slugs else "",
        ] if p]
        if sub_parts:
            lbl(hdr, "  |  ".join(sub_parts),
                9, color=DIM, bg=CARD).pack(pady=(2, 0))

        # Progress
        pf = tk.Frame(r, bg=BG, padx=20, pady=8)
        pf.pack(fill="x")
        self.plbl = lbl(pf, "Initialising...")
        self.plbl.pack(anchor="w")
        sty = ttk.Style()
        sty.theme_use("default")
        sty.configure("S.Horizontal.TProgressbar",
                      troughcolor=IN_BG, background=ACCENT,
                      darkcolor=ACCENT, lightcolor=ACCENT,
                      bordercolor=BG, thickness=10)
        self.bar = ttk.Progressbar(
            pf, style="S.Horizontal.TProgressbar",
            mode="determinate", maximum=len(self.repo_slugs))
        self.bar.pack(fill="x", pady=5)

        # Footer — packed BEFORE notebook so it's always visible
        foot = tk.Frame(r, bg="#1a1f30", pady=12, padx=20)
        foot.pack(fill="x", side="bottom")
        foot.columnconfigure(0, weight=1)   # status label stretches

        self.stlbl = lbl(foot, "Scanning...", 10, color=DIM, bg="#1a1f30")
        self.stlbl.grid(row=0, column=0, sticky="w")

        self.exit_btn = make_btn(
            foot, "✕  Exit", self._on_exit,
            color=DANGER, hover="#cc3333", fg="#fff", width=12, size=11)
        self.exit_btn.grid(row=0, column=3, padx=(8, 0))

        self.stop_btn = make_btn(
            foot, "⏹  Stop Scan", self._on_stop,
            color="#8B4000", hover="#a84d00", fg="#fff", width=14, size=11)
        self.stop_btn.grid(row=0, column=2, padx=(8, 0))

        self.new_btn = make_btn(
            foot, "⟳  New Scan", self._new_scan,
            color=BTN_GO, hover=BTN_GO2, fg="#fff", width=14, size=11)
        self.new_btn.grid(row=0, column=1, padx=(8, 0))
        self.new_btn.config(state="disabled")

        # Notebook
        nb_frame = tk.Frame(r, bg=BG, padx=20)
        nb_frame.pack(fill="both", expand=True)

        sty.configure("Dark.TNotebook", background=BG, borderwidth=0)
        sty.configure("Dark.TNotebook.Tab",
                      background=IN_BG, foreground=DIM,
                      padding=[12, 5], font=("Segoe UI", 10))
        sty.map("Dark.TNotebook.Tab",
                background=[("selected", CARD)],
                foreground=[("selected", TEXT)])

        self.nb = ttk.Notebook(nb_frame, style="Dark.TNotebook")
        self.nb.pack(fill="both", expand=True)

        # ── Log tab ──
        log_tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(log_tab, text="  📋 Log  ")

        # Log toolbar (download button)
        log_toolbar = tk.Frame(log_tab, bg=BG, pady=4)
        log_toolbar.pack(fill="x", side="bottom")
        self.dl_btn = make_btn(
            log_toolbar, "⬇  Download Log", self._download_log,
            color=CARD, hover=BORDER, fg=TEXT, width=16, size=9)
        self.dl_btn.pack(side="right", padx=(0, 4))
        self.dl_btn.config(state="disabled")

        # Log text widget
        log_inner = tk.Frame(log_tab, bg=BG)
        log_inner.pack(fill="both", expand=True)
        self.log_widget = tk.Text(
            log_inner, bg="#0d1117", fg=TEXT,
            font=("Cascadia Code", 9), relief="flat",
            state="disabled", wrap="word", highlightthickness=0)
        ls = ttk.Scrollbar(log_inner, orient="vertical",
                           command=self.log_widget.yview)
        self.log_widget.config(yscrollcommand=ls.set)
        self.log_widget.pack(side="left", fill="both", expand=True)
        ls.pack(side="left", fill="y")
        self.log_widget.tag_config(
            "hd",   foreground=ACCENT,
            font=("Cascadia Code", 9, "bold"))
        self.log_widget.tag_config("ok",   foreground=SUCCESS)
        self.log_widget.tag_config("warn", foreground=WARNING)
        self.log_widget.tag_config("err",  foreground=DANGER)
        self.log_widget.tag_config("dim",  foreground=DIM)
        self.log_widget.tag_config("info", foreground=TEXT)

        # ── Summary tab ──
        self.sum_outer = tk.Frame(self.nb, bg=BG)
        self.nb.add(self.sum_outer, text="  📊 Summary  ")

    # ── Cancel / Exit helpers ────────────────────────────────────
    def _on_stop(self):
        """
        Request scan cancellation — designed to stop as fast as possible:
          1. Set stop_event first — all workers and LLM batches check this.
          2. Kill active git subprocesses under lock.
          3. Slash the global socket timeout so any in-flight urllib/Ollama
             request gets an error within 1 second instead of waiting up to
             REQUEST_TIMEOUT (180 s).
          4. Cancel unstarted futures.
        """
        self._stop_event.set()

        # Kill git clones
        with self._proc_lock:
            for proc in list(self._proc_holder):
                try:
                    proc.kill()
                except Exception:
                    pass

        # Shorten socket timeout so in-flight Ollama HTTP calls abort quickly
        try:
            import socket
            socket.setdefaulttimeout(1)
        except Exception:
            pass

        # Cancel unstarted futures
        _pool = getattr(self, "_active_pool", None)
        if _pool is not None:
            try:
                _pool.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                try:
                    _pool.shutdown(wait=False)
                except Exception:
                    pass
            except Exception:
                pass

        self.stop_btn.config(state="disabled", text="⏹  Stopping...")
        self.stlbl.config(text="Stopping scan — please wait...", fg=WARNING)

    def _on_exit(self):
        """Stop everything and close cleanly."""
        self._stop_event.set()
        with self._proc_lock:
            for proc in list(self._proc_holder):
                try:
                    proc.kill()
                except Exception:
                    pass
        self.root.destroy()

    # ── Log helpers ──────────────────────────────────────────────
    def _log(self, msg, tag="info"):
        self._log_lines.append(msg)
        self.log_widget.config(state="normal")
        self.log_widget.insert("end", msg + "\n", tag)
        self.log_widget.see("end")
        self.log_widget.config(state="disabled")

    def _save_log(self):
        """Write log to logs/ folder with same name pattern as reports."""
        try:
            log_dir = Path(LOG_DIR)
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / f"log_{self.project_key}-{self.scan_id}.txt"
            log_path.write_text(
                "\n".join(self._log_lines), encoding="utf-8")
            return str(log_path)
        except Exception as e:
            return None

    def _download_log(self):
        """Save log to a user-chosen location."""
        default_name = f"log_{self.project_key}-{self.scan_id}.txt"
        dest = filedialog.asksaveasfilename(
            title="Save Log",
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if dest:
            try:
                Path(dest).write_text(
                    "\n".join(self._log_lines), encoding="utf-8")
            except Exception as e:
                messagebox.showerror("Save failed", str(e))

    # ── Scan thread ──────────────────────────────────────────────
    def _run(self):
        from scanner.bitbucket import shallow_clone, cleanup_clone

        # Task 8: wire rate-limit callback so 429 backoffs appear in the log
        def _on_rate_limit(msg: str):
            self._log(f"⏳ {msg}", "warn")
            self.root.after(0, lambda m=msg: self.stlbl.config(
                text=m[:80], fg=WARNING))

        self.client._rate_cb = _on_rate_limit

        policy     = load_policy(POLICY_FILE)
        owner_map  = load_owner_map(OWNER_MAP_FILE)
        detector   = AIUsageDetector(verbose=False)
        analyzer   = SecurityAnalyzer(policy=policy, verbose=False)
        aggregator = Aggregator(owner_map=owner_map, min_severity=4)

        Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
        Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)

        import time as _time
        all_findings   = []
        per_repo       = {}
        per_branch     = {}
        total          = len(self.repo_slugs)
        _scan_start_ts = _time.time()

        self._log(f"Scan ID : {self.scan_id}", "hd")
        self._log(f"Project : {self.project_key}", "dim")
        self._log(f"Repos   : {total}", "dim")

        self.llm_model_info = {}   # populated below if LLM is enabled
        if self.llm_enabled:
            self._log(f"LLM     : {self.llm_model}  @  {self.llm_url}", "dim")
            # Guarantee Ollama is up before the first repo scan fires
            if not _ollama_ensure_running(self.llm_url, log_fn=self._log):
                self._log("  [LLM] Proceeding without LLM review (Ollama unavailable)", "err")
                self.llm_enabled = False
            else:
                # Fetch model details once — used in HTML report header
                try:
                    from scanner.llm_reviewer import LLMReviewer
                    self.llm_model_info = LLMReviewer(
                        base_url=self.llm_url, model=self.llm_model
                    ).model_info()
                    info = self.llm_model_info
                    parts = [info["name"]]
                    if info.get("parameter_size"):
                        parts.append(info["parameter_size"])
                    if info.get("quantization"):
                        parts.append(info["quantization"])
                    if info.get("digest"):
                        parts.append(f"#{info['digest']}")
                    self._log(f"LLM info: {' · '.join(parts)}", "dim")
                except Exception:
                    self.llm_model_info = {"name": self.llm_model}
        self._log("─" * 58, "dim")

        # ── L: Parallel clone + scan ──────────────────────────────
        # Prefetch metadata for all repos (sequential — fast API calls)
        repo_meta = {}
        git_env = self.client.build_git_auth_env()
        for slug in self.repo_slugs:
            if self._stop_event.is_set():
                break
            branch  = self.client.get_default_branch(self.project_key, slug)
            owner   = self.client.get_repo_owner(self.project_key, slug)
            url     = self.client.get_clone_url(self.project_key, slug)
            per_branch[slug] = branch or "default"
            repo_meta[slug]  = {"branch": branch, "owner": owner, "url": url}
            self._log(f"  {slug}  branch:{branch or '?'}  owner:{owner}", "dim")

        self._log("─" * 58, "dim")

        # ── Adaptive worker count ─────────────────────────────────
        try:
            from scanner.llm_reviewer import (
                compute_worker_count as _cwc, _available_vram_gb as _vram
            )
            _vram_gb  = _vram()
            _param_sz = (self.llm_model_info or {}).get("parameter_size", "")
            _workers  = _cwc(_param_sz, vram_gb=_vram_gb,
                             repo_count=len(self.repo_slugs))
        except Exception:
            _workers = 4

        self._log(
            f"Starting parallel scan (workers={_workers}"
            + (f", vram={_vram_gb:.1f}GB" if "_vram_gb" in dir() and _vram_gb > 0 else "")
            + ")...", "info"
        )

        completed_count = 0

        def _scan_one(slug: str) -> tuple:
            """Clone, scan, and return (slug, findings_or_None, owner, pre_llm, skip_reason)."""
            if self._stop_event.is_set():
                return slug, None, "", 0, "scan stopped"
            meta      = repo_meta.get(slug, {})
            branch    = meta.get("branch")
            owner     = meta.get("owner", "Unknown")
            clone_url = meta.get("url", "")
            clone_dir = Path(TEMP_DIR) / slug
            try:
                shallow_clone(clone_url, clone_dir,
                              branch=branch, verbose=False,
                              stop_event=self._stop_event,
                              proc_holder=self._proc_holder,
                              proc_lock=self._proc_lock,
                              git_env=git_env)
            except RuntimeError as e:
                return slug, None, owner, 0, f"clone failed: {e}"
            except Exception as e:
                return slug, None, owner, 0, f"clone error: {e}"

            if self._stop_event.is_set():
                cleanup_clone(clone_dir)
                return slug, None, owner, 0, "scan stopped"

            try:
                raw, file_contents = detector.scan(
                    clone_dir, repo_name=slug,
                    stop_event=self._stop_event,
                    return_file_contents=True,
                )
                # Task 4: scan git history for deleted files
                try:
                    from scanner.history import scan_history
                    history_findings = scan_history(
                        clone_dir, detector, slug,
                        stop_event=self._stop_event,
                    )
                    if history_findings:
                        raw.extend(history_findings)
                except Exception as _hist_err:
                    self._log(f"  [history] {slug}: {_hist_err}", "dim")

                analyzed = analyzer.analyze(raw)

                # LLM review: re-score uncertain findings locally via Ollama
                pre_llm_count = len(analyzed)
                if self.llm_enabled and analyzed:
                    try:
                        from scanner.llm_reviewer import LLMReviewer
                        reviewer = LLMReviewer(
                            base_url=self.llm_url,
                            model=self.llm_model,
                            log_fn=self._log,
                            stop_event=self._stop_event,
                        )
                        analyzed = reviewer.review(analyzed, file_contents)
                    except Exception as llm_err:
                        self._log(f"  [LLM] Review skipped: {llm_err}", "dim")

                return slug, analyzed, owner, pre_llm_count, None
            except Exception as e:
                return slug, None, owner, 0, f"scan error: {e}"
            finally:
                cleanup_clone(clone_dir)

        total_pre_llm  = 0
        total_post_llm = 0

        # Task 9: store pool reference so _on_stop can cancel_futures
        with ThreadPoolExecutor(max_workers=_workers) as pool:
            self._active_pool = pool
            futures = {pool.submit(_scan_one, slug): slug
                       for slug in self.repo_slugs}
            for fut in as_completed(futures):
                if self._stop_event.is_set():
                    # Drain remaining futures without blocking — they will
                    # self-terminate via stop_event check at top of _scan_one
                    for remaining in futures:
                        remaining.cancel()
                    break
                slug, analyzed, bb_owner, pre_llm, skip_reason = fut.result()
                completed_count += 1

                self.root.after(0, lambda s=slug, idx=completed_count: (
                    self.plbl.config(text=f"[{idx}/{total}]  {s}"),
                    self.bar.config(value=idx),
                    self.stlbl.config(text=f"Scanned {idx}/{total}: {s}", fg=DIM),
                ))

                if analyzed is None:
                    reason_str = f": {skip_reason}" if skip_reason else ""
                    self._log(f"  ✗ {slug}: skipped{reason_str}", "err")
                    per_repo[slug] = None
                    continue

                s1 = sum(1 for f in analyzed if f.get("severity") == 1)
                s2 = sum(1 for f in analyzed if f.get("severity") == 2)
                self._log(f"\n✓ {slug}  →  {len(analyzed)} findings  (Crit:{s1} High:{s2})", "info")
                if s1:
                    self._log(f"  ⚠  {s1} Critical finding(s)!", "err")

                total_pre_llm  += pre_llm
                total_post_llm += len(analyzed)

                for f in analyzed:
                    f["project_key"] = self.project_key
                    f["owner"]       = bb_owner
                    f["last_seen"]   = self.scan_id
                all_findings.extend(analyzed)
                per_repo[slug] = analyzed

        # Aggregate
        self._log("\n" + "─" * 58, "dim")
        final = aggregator.process(all_findings)
        self._log(f"Total findings (deduped): {len(final)}", "hd")
        self.root.after(0, lambda: self.bar.config(value=total))

        # ── Compute duration before writing reports ───────────────
        _scan_end_ts     = _time.time()
        self.scan_duration_s = int(_scan_end_ts - _scan_start_ts)

        # Reports
        self._log("\nGenerating reports...", "dim")
        report_paths = {}

        # Status summary per repo
        for slug in self.repo_slugs:
            if per_repo.get(slug) is None:
                self._log(f"  {slug}: skipped (no findings recorded)", "dim")
            elif not [f for f in final if f.get("repo") == slug]:
                self._log(f"  {slug}: ✓ clean — no findings", "ok")

        if not final:
            self._log("  No findings — no report generated.", "dim")
        else:
            try:
                dt_date   = datetime.now().strftime("%Y%m%d")
                dt_time   = datetime.now().strftime("%H%M%S")
                is_multi  = len(self.repo_slugs) > 1
                scanned_slugs = [s for s in self.repo_slugs
                                 if per_repo.get(s) is not None]
                label     = ("ALL" if is_multi
                             else (scanned_slugs[0] if scanned_slugs
                                   else self.repo_slugs[0]))
                safe_name = f"AI_Scan_Report_{self.project_key}_{label}_{dt_date}_{dt_time}"

                cr = CSVReporter(output_dir=OUTPUT_DIR, scan_id=safe_name)
                cp = cr.write_csv(final)

                if is_multi:
                    repos_meta_list = [
                        {
                            "slug":   s,
                            "owner":  repo_meta.get(s, {}).get("owner", "Unknown"),
                            "branch": repo_meta.get(s, {}).get("branch") or "default",
                        }
                        for s in self.repo_slugs
                    ]
                    report_meta = {
                        "repo":             f"{len(self.repo_slugs)} repositories",
                        "project_key":      self.project_key,
                        "owner":            "",
                        "branch":           "",
                        "repos_meta":       repos_meta_list,
                        "scan_id":          self.scan_id,
                        "delta":            {},
                        "llm_model_info":   self.llm_model_info,
                        "scan_duration_s":  getattr(self, "scan_duration_s", None),
                        "pre_llm_count":    total_pre_llm,
                        "post_llm_count":   total_post_llm,
                    }
                else:
                    single_slug  = label
                    single_owner = next((f.get("owner","") for f in final), "Unknown")
                    delta_meta   = build_delta_meta(
                        final, OUTPUT_DIR, self.project_key, single_slug)
                    report_meta = {
                        "repo":             single_slug,
                        "project_key":      self.project_key,
                        "owner":            single_owner,
                        "branch":           per_branch.get(single_slug, ""),
                        "scan_id":          self.scan_id,
                        "delta":            delta_meta,
                        "llm_model_info":   self.llm_model_info,
                        "scan_duration_s":  getattr(self, "scan_duration_s", None),
                        "pre_llm_count":    total_pre_llm,
                        "post_llm_count":   total_post_llm,
                    }

                hr = HTMLReporter(
                    output_dir=OUTPUT_DIR,
                    scan_id=safe_name,
                    include_snippets=True,
                    meta=report_meta,
                )
                hp = hr.write(final, policy=policy)
                report_paths["__all__"] = {"csv": cp, "html": hp}
                self._log(f"  ✓ Report: {Path(hp).name}", "ok")
            except Exception as e:
                self._log(f"  ✗ Report error: {e}", "err")

        _dur = self.scan_duration_s
        # Restore default socket timeout in case stop was pressed mid-scan
        try:
            import socket as _sock
            _sock.setdefaulttimeout(None)
        except Exception:
            pass
        _dur_str = (f"{_dur // 60}m {_dur % 60}s" if _dur >= 60 else f"{_dur}s")
        self._log(f"\n✓ Done in {_dur_str}. Reports in: {Path(OUTPUT_DIR).resolve()}", "ok")
        self._report_paths = report_paths

        # Cleanup tmp_clones contents — keep the folder, delete everything inside
        try:
            import shutil, stat

            def _force_remove(func, path, exc_info):
                """Clear read-only flag and retry — needed for .git pack files on Windows."""
                try:
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                except Exception:
                    pass

            tmp = Path(TEMP_DIR)
            if tmp.exists():
                removed = 0
                for item in tmp.iterdir():
                    try:
                        if item.is_dir():
                            shutil.rmtree(item, onerror=_force_remove)
                        else:
                            item.unlink()
                        removed += 1
                    except Exception as e:
                        self._log(f"⚠ Could not remove {item.name}: {e}", "warn")
                self._log(f"✓ Cleaned up {removed} item(s) in: {tmp.resolve()}", "dim")
        except Exception as e:
            self._log(f"⚠ Cleanup failed: {e}", "warn")

        # Auto-save log
        log_path = self._save_log()
        if log_path:
            self._log(f"✓ Log saved: {log_path}", "dim")

        self.root.after(0, lambda: self._finish(final, report_paths, per_repo))

    def _finish(self, final, report_paths, per_repo):
        stopped = self._stop_event.is_set()
        self.stop_btn.config(state="disabled", text="⏹  Stop Scan")
        self.new_btn.config(state="normal")
        self.dl_btn.config(state="normal")
        if stopped:
            self.plbl.config(text="Scan stopped ⏹")
            self.stlbl.config(
                text=f"{len(final)} findings collected before stop  |  "
                     f"{len(report_paths)} report(s) generated",
                fg=WARNING)
            self.root.title("AI Security & Compliance Scanner — Stopped")
        else:
            self.plbl.config(text="Scan complete ✓")
            self.stlbl.config(
                text=f"{len(final)} findings  |  "
                     f"{len(report_paths)} report(s) generated",
                fg=SUCCESS)
            self.root.title("AI Security & Compliance Scanner — Complete ✓")
        self.nb.select(1)
        self._build_summary(final, report_paths, per_repo)
        # Measure actual content and fit window tightly to it
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        content_h = self.root.winfo_reqheight()
        w = min(max(self.root.winfo_reqwidth() + 40, 900), int(sw * 0.92))
        h = min(max(content_h + 20, 480), int(sh * 0.88))
        self.root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    # ── Summary tab ──────────────────────────────────────────────
    def _build_summary(self, final, report_paths, per_repo):
        from collections import Counter

        outer = self.sum_outer
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        # Scrollbar shown only when content is taller than the canvas
        def _maybe_show_sb(event=None):
            canvas.update_idletasks()
            cr = canvas.bbox("all")
            if cr and cr[3] > canvas.winfo_height():
                sb.pack(side="right", fill="y")
            else:
                sb.pack_forget()
        canvas.bind("<Configure>", lambda e: _maybe_show_sb())

        inner = tk.Frame(canvas, bg=BG)
        cw = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(cw, width=e.width))
        inner.bind("<Configure>",
                   lambda e: canvas.configure(
                       scrollregion=canvas.bbox("all")))
        canvas.bind_all("<MouseWheel>",
            lambda e: canvas.yview_scroll(
                int(-1*(e.delta/120)), "units"))

        PAD = {"padx": 20, "pady": 5}

        # KPIs
        kpi_frame = tk.Frame(inner, bg=CARD, pady=14)
        kpi_frame.pack(fill="x", **PAD)
        sev_counts = Counter(f["severity"] for f in final)
        kpis = [
            ("Total",    len(final),              TEXT),
            ("🔴 Crit",  sev_counts.get(1, 0),    DANGER),
            ("🟠 High",  sev_counts.get(2, 0),    WARNING),
            ("🟡 Med",   sev_counts.get(3, 0),    "#FFC107"),
            ("🟢 Low",   sev_counts.get(4, 0),    SUCCESS),
        ]
        krow = tk.Frame(kpi_frame, bg=CARD)
        krow.pack()
        for klbl_txt, kval, kcol in kpis:
            box = tk.Frame(krow, bg=IN_BG, padx=16, pady=8)
            box.pack(side="left", padx=6)
            tk.Label(box, text=str(kval), bg=IN_BG, fg=kcol,
                     font=("Segoe UI", 24, "bold")).pack()
            tk.Label(box, text=klbl_txt, bg=IN_BG, fg=DIM,
                     font=("Segoe UI", 10)).pack()

        # ── Results per Repository — custom grid table ────────────
        lbl(inner, "Results per Repository", 13, bold=True).pack(
            anchor="w", padx=20, pady=(14, 6))

        # Col indices: 0=repo(stretch), 1=crit, 2=high, 3=med, 4=low, 5=reports
        # Fixed pixel minwidths for narrow cols; repo col stretches
        COL_MIN  = [0, 68, 68, 68, 68, 200]   # 0 = stretch
        COL_HDR  = ["Repository", "Crit", "High", "Med", "Low", "Reports"]
        HDR_BG   = "#2d1f6e"
        ROW_BG   = [IN_BG, "#232840"]
        ROW_H    = 34
        N_COLS   = len(COL_HDR)

        SEV_STYLE = {
            1: (DANGER,    "#fff"),
            2: (WARNING,   "#fff"),
            3: ("#d4a800", "#000"),
            4: (SUCCESS,   "#000"),
        }

        tbl_outer = tk.Frame(inner, bg=BG)
        tbl_outer.pack(fill="x", padx=20, pady=(0, 6))
        # col 0 stretches; rest fixed
        tbl_outer.columnconfigure(0, weight=1)
        for c in range(1, N_COLS):
            tbl_outer.columnconfigure(c, weight=0, minsize=COL_MIN[c])

        def _make_row(parent, row_idx, bg):
            """Configure grid row on parent frame."""
            parent.columnconfigure(0, weight=1)
            for c in range(1, N_COLS):
                parent.columnconfigure(c, weight=0, minsize=COL_MIN[c])

        # ── Header ──
        hdr = tk.Frame(tbl_outer, bg=HDR_BG)
        hdr.grid(row=0, column=0, columnspan=N_COLS, sticky="ew")
        hdr.columnconfigure(0, weight=1)
        for c in range(1, N_COLS):
            hdr.columnconfigure(c, weight=0, minsize=COL_MIN[c])
        for c, txt in enumerate(COL_HDR):
            anc = "w" if c in (0, 5) else "center"
            padx = (10, 4) if c == 0 else (0, 0)
            tk.Label(hdr, text=txt, bg=HDR_BG, fg="#fff",
                     font=("Segoe UI", 11, "bold"),
                     anchor=anc, pady=6,
                     padx=padx[0] if c == 0 else 0
                     ).grid(row=0, column=c, sticky="ew",
                            padx=(10,4) if c==0 else (0,0))

        # ── Data rows ──
        for idx, slug in enumerate(self.repo_slugs):
            skipped = per_repo.get(slug) is None
            repo_f  = [f for f in final if f.get("repo") == slug]
            sc      = Counter(f["severity"] for f in repo_f)
            rbg     = ROW_BG[idx % 2]
            grid_r  = idx + 1   # row 0 = header

            row_f = tk.Frame(tbl_outer, bg=rbg,
                             highlightthickness=1,
                             highlightbackground=BORDER,
                             height=ROW_H)
            row_f.grid(row=grid_r, column=0, columnspan=N_COLS,
                       sticky="ew")
            row_f.columnconfigure(0, weight=1)
            for c in range(1, N_COLS):
                row_f.columnconfigure(c, weight=0, minsize=COL_MIN[c])
            row_f.grid_propagate(False)

            # Col 0 — repo name
            if skipped:
                rtxt, rfg = f"⏭  {slug}", DIM
            elif not repo_f:
                rtxt, rfg = f"✓  {slug}", SUCCESS
            else:
                rtxt, rfg = slug, TEXT
            tk.Label(row_f, text=rtxt, bg=rbg, fg=rfg,
                     font=("Segoe UI", 11, "bold"),
                     anchor="w", padx=10, pady=0
                     ).grid(row=0, column=0, sticky="ew", ipady=5)

            # Cols 1-4 — severity badges
            for ci, sev_n in enumerate((1, 2, 3, 4), start=1):
                cnt = sc.get(sev_n, 0) if (not skipped and repo_f) else 0
                cell = tk.Frame(row_f, bg=rbg)
                cell.grid(row=0, column=ci, sticky="nsew")
                cell.columnconfigure(0, weight=1)
                cell.rowconfigure(0, weight=1)
                if cnt:
                    bbg, bfg = SEV_STYLE[sev_n]
                    tk.Label(cell, text=str(cnt),
                             bg=bbg, fg=bfg,
                             font=("Segoe UI", 10, "bold"),
                             padx=8, pady=2
                             ).place(relx=0.5, rely=0.5, anchor="center")
                else:
                    tk.Label(cell, text="—", bg=rbg, fg=DIM,
                             font=("Segoe UI", 10)
                             ).place(relx=0.5, rely=0.5, anchor="center")

            # Col 5 — placeholder (reports shown below the table)
            lnk = tk.Frame(row_f, bg=rbg)
            lnk.grid(row=0, column=5, sticky="nsew", padx=(8, 4))
            tk.Label(lnk, text="—", bg=rbg, fg=DIM,
                     font=("Segoe UI", 10)
                     ).place(relx=0.0, rely=0.5, anchor="w")

        # ── Combined report bar ───────────────────────────────────
        rpt = report_paths.get("__all__", {})
        if rpt:
            rpt_bar = tk.Frame(inner, bg=BG, pady=6)
            rpt_bar.pack(fill="x", padx=20)
            tk.Label(rpt_bar, text="Report:", bg=BG, fg=DIM,
                     font=("Segoe UI", 10)).pack(side="left", padx=(0, 8))
            for kind, icon in [("csv", "📄 CSV"), ("html", "🌐 HTML")]:
                p = rpt.get(kind, "")
                if p:
                    lk = tk.Label(rpt_bar, text=icon,
                                  bg=BG, fg=ACCENT,
                                  font=("Segoe UI", 10, "underline"),
                                  cursor="hand2")
                    lk.pack(side="left", padx=(0, 14))
                    if kind == "html":
                        lk.bind("<Button-1>",
                                lambda e, _p=p, _u=self.llm_url:
                                    open_report(_p, ollama_base=_u))
                    else:
                        lk.bind("<Button-1>",
                                lambda e, _p=p: open_file(_p))
                    lk.bind("<Enter>", lambda e, w=lk: w.config(fg=ACCENT2))
                    lk.bind("<Leave>", lambda e, w=lk: w.config(fg=ACCENT))

        # Output folder link
        of = tk.Frame(inner, bg=BG, pady=10)
        of.pack(fill="x", padx=20)
        flk = tk.Label(
            of,
            text=f"📂  Open output folder  →  "
                 f"{Path(OUTPUT_DIR).resolve()}",
            bg=BG, fg=DIM,
            font=("Segoe UI", 10, "underline"),
            cursor="hand2")
        flk.pack(anchor="w")
        flk.bind("<Button-1>",
                 lambda e: open_file(str(Path(OUTPUT_DIR).resolve())))
        flk.bind("<Enter>", lambda e: flk.config(fg=ACCENT))
        flk.bind("<Leave>", lambda e: flk.config(fg=DIM))

    def _new_scan(self):
        client     = self.client
        pat_owner  = self.pat_owner
        # Re-fetch project list (lightweight) so list is current
        try:
            projects = client.list_projects()
        except Exception:
            projects = []
        self.root.destroy()
        SelectorWindow(client, pat_owner, projects)


# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    from app_server import start

    print("Launching web UI on http://127.0.0.1:5757/")
    print("The desktop Tkinter flow is deprecated in favor of the local web app.")
    srv = start(open_browser=True)
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()

