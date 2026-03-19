from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable


class SettingsService:
    def __init__(
        self,
        *,
        load_llm_config: Callable[[], dict],
        save_llm_config: Callable[[dict], None],
        save_tls_config: Callable[[dict], None],
        ensure_ollama_running: Callable[[str], dict],
        list_ollama_models: Callable[[str], list],
        audit_event: Callable[[str], None],
        sync_paths: Callable[[], None],
    ):
        self._load_llm_config = load_llm_config
        self._save_llm_config = save_llm_config
        self._save_tls_config = save_tls_config
        self._ensure_ollama_running = ensure_ollama_running
        self._list_ollama_models = list_ollama_models
        self._audit_event = audit_event
        self._sync_paths = sync_paths

    def save_llm_settings(self, *, llm_url: str, llm_model: str, report_detail_timeout_s: int | str | None = None) -> dict:
        if not llm_url or not llm_model:
            raise ValueError("llm_url and llm_model required")
        existing = dict(self._load_llm_config() or {})
        if report_detail_timeout_s in (None, ""):
            timeout_value = int(existing.get("report_detail_timeout_s", 180) or 180)
        else:
            try:
                timeout_value = int(report_detail_timeout_s)
            except (TypeError, ValueError) as exc:
                raise ValueError("report_detail_timeout_s must be an integer") from exc
        timeout_value = max(30, min(600, timeout_value))
        self._save_llm_config({
            **existing,
            "base_url": llm_url,
            "model": llm_model,
            "report_detail_timeout_s": timeout_value,
        })
        self._audit_event("settings_llm_update", base_url=llm_url, model=llm_model, report_detail_timeout_s=timeout_value)
        return {"ok": True, "models": self._list_ollama_models(llm_url or "http://localhost:11434")}

    def save_output_dir(
        self,
        *,
        output_dir: str,
        is_scan_running: bool,
        set_paths: Callable[[Path], None],
    ) -> dict:
        if is_scan_running:
            raise ValueError("Cannot change output directory while a scan is running")
        p = Path(output_dir)
        p.mkdir(parents=True, exist_ok=True)
        set_paths(p)
        Path(p / "logs").mkdir(parents=True, exist_ok=True)
        self._sync_paths()
        self._audit_event("settings_output_dir_update", output_dir=str(p))
        return {"ok": True, "output_dir": str(p.resolve())}

    def save_tls_settings(self, *, verify_ssl: bool, ca_bundle: str) -> dict:
        ca_bundle = str(ca_bundle or "").strip()
        if ca_bundle:
            path = Path(ca_bundle)
            if not path.exists():
                raise ValueError("Bitbucket CA bundle file not found")
            if not path.is_file():
                raise ValueError("Bitbucket CA bundle must be a file")
            resolved = str(path.resolve())
            try:
                ctx = ssl.create_default_context()
                ctx.load_verify_locations(cafile=resolved)
            except ssl.SSLError as exc:
                msg = str(exc)
                if "NO_CERTIFICATE_OR_CRL_FOUND" in msg:
                    raise ValueError(
                        "Bitbucket CA bundle is not a valid PEM certificate bundle. "
                        "Convert DER/.cer certificates to PEM or provide a PEM bundle with the required CA chain."
                    ) from exc
                raise ValueError(f"Bitbucket CA bundle could not be parsed: {msg}") from exc
            except OSError as exc:
                raise ValueError(f"Bitbucket CA bundle could not be read: {exc}") from exc
            ca_bundle = resolved
        self._save_tls_config({"verify_ssl": bool(verify_ssl), "ca_bundle": ca_bundle})
        self._audit_event(
            "settings_tls_update",
            verify_ssl=bool(verify_ssl),
            ca_bundle=ca_bundle,
        )
        return {"ok": True, "verify_ssl": bool(verify_ssl), "ca_bundle": ca_bundle}

    def start_ollama(self, *, url: str) -> dict:
        result = self._ensure_ollama_running(url)
        self._audit_event("ollama_start", base_url=url, ok=bool(result["ok"]))
        if result["ok"]:
            return {
                "ok": True,
                "status": result.get("status", "running"),
                "models": self._list_ollama_models(url),
            }
        return {"ok": False, "error": result["error"], "models": []}

    def proxy_ollama(self, body: dict) -> tuple[int, str, bytes]:
        cfg = self._load_llm_config()
        target = cfg.get("base_url", "http://localhost:11434").rstrip("/") + "/api/generate"
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            target,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.status, resp.headers.get("Content-Type", "application/x-ndjson"), resp.read()
        except urllib.error.URLError as exc:
            return 502, "application/json", json.dumps({"error": str(exc)}).encode("utf-8")
