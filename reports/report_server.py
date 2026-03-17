"""
reports/report_server.py
------------------------
Tiny stdlib-only HTTP server that:
  • Serves a single HTML report at  GET /
  • Proxies Ollama streaming at     POST /ollama  →  http://localhost:11434/api/generate

One server instance per report.  Runs in a daemon thread so it dies with the process.
Port is auto-selected from the OS (bind to :0).
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path


# ── Server ────────────────────────────────────────────────────────────────────

class _Handler(http.server.BaseHTTPRequestHandler):

    # injected by factory
    html_bytes: bytes = b""
    ollama_base: str  = "http://localhost:11434"

    # ── silence access log ────────────────────────────────────────────────────
    def log_message(self, fmt, *args):   # noqa: D401
        pass

    # ── routing ───────────────────────────────────────────────────────────────
    def do_GET(self):
        if self.path in ("/", "/report"):
            self._serve_html()
        else:
            self._404()

    def do_POST(self):
        if self.path == "/ollama":
            self._proxy_ollama()
        else:
            self._404()

    def do_OPTIONS(self):
        """CORS pre-flight — browser may send this before POST /ollama."""
        self.send_response(204)
        self._cors()
        self.end_headers()

    # ── handlers ─────────────────────────────────────────────────────────────
    def _serve_html(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.html_bytes)))
        self._cors()
        self.end_headers()
        self.wfile.write(self.html_bytes)

    def _proxy_ollama(self):
        length  = int(self.headers.get("Content-Length", 0))
        body    = self.rfile.read(length)
        target  = self.ollama_base.rstrip("/") + "/api/generate"

        req = urllib.request.Request(
            target,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                self.send_response(resp.status)
                # forward content-type (application/x-ndjson or similar)
                ct = resp.headers.get("Content-Type", "application/x-ndjson")
                self.send_header("Content-Type", ct)
                self._cors()
                self.end_headers()
                # stream chunks straight through
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except urllib.error.URLError as exc:
            err = json.dumps({"error": str(exc)}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(err)

    def _404(self):
        self.send_response(404)
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")


# ── Public API ────────────────────────────────────────────────────────────────

class ReportServer:
    """Serve one HTML report file over HTTP and proxy Ollama."""

    def __init__(self, html_path: str | Path,
                 ollama_base: str = "http://localhost:11434"):
        self._path       = Path(html_path).resolve()
        self._ollama_base = ollama_base
        self._server: http.server.HTTPServer | None = None
        self._port: int = 0

    # ── start ─────────────────────────────────────────────────────────────────
    def start(self) -> int:
        """Start the server in a daemon thread.  Returns the port number."""
        html_bytes   = self._path.read_bytes()
        ollama_base  = self._ollama_base

        # Build a handler class with the data baked in (avoid globals)
        class Handler(_Handler):
            pass
        Handler.html_bytes  = html_bytes
        Handler.ollama_base = ollama_base

        # Bind to any free port
        self._server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self._port   = self._server.server_address[1]

        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()
        return self._port

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None

    @property
    def port(self) -> int:
        return self._port

    def url(self) -> str:
        return f"http://127.0.0.1:{self._port}/"


# ── Convenience: open an HTML report in the browser via the server ────────────

# Registry so we don't spawn duplicate servers for the same file
_servers: dict[str, ReportServer] = {}
_lock = threading.Lock()


def open_report(html_path: str | Path,
                ollama_base: str = "http://localhost:11434") -> str:
    """
    Start (or reuse) a ReportServer for *html_path*, open it in the browser.
    Returns the URL.
    """
    key = str(Path(html_path).resolve())
    with _lock:
        if key not in _servers:
            srv = ReportServer(key, ollama_base=ollama_base)
            srv.start()
            _servers[key] = srv
        url = _servers[key].url()

    webbrowser.open(url)
    return url


def stop_all():
    """Call on app exit to cleanly shut down all servers."""
    with _lock:
        for srv in _servers.values():
            srv.stop()
        _servers.clear()
