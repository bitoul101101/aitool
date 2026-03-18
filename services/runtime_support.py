from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable


DEFAULT_LLM_CONFIG = {
    "base_url": "http://localhost:11434",
    "model": "qwen2.5-coder:7b-instruct",
}
DEFAULT_TLS_CONFIG = {
    "verify_ssl": True,
    "ca_bundle": "",
}

_OLLAMA_CACHE_TTL_S = 30
_OLLAMA_CACHE_LOCK = threading.RLock()
_OLLAMA_CACHE: dict[str, dict] = {}


def load_llm_config(path: str) -> dict:
    """Load LLM settings from JSON file, falling back to defaults."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        cfg = dict(DEFAULT_LLM_CONFIG)
        cfg.update({k: v for k, v in data.items() if k in DEFAULT_LLM_CONFIG})
        return cfg
    except (FileNotFoundError, OSError, json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError):
        return dict(DEFAULT_LLM_CONFIG)


def save_llm_config(path: str, cfg: dict) -> None:
    """Persist LLM settings to JSON file."""
    Path(path).write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def load_tls_config(path: str) -> dict:
    """Load Bitbucket TLS settings from JSON file, falling back to defaults."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        cfg = dict(DEFAULT_TLS_CONFIG)
        cfg["verify_ssl"] = bool(data.get("verify_ssl", cfg["verify_ssl"]))
        cfg["ca_bundle"] = str(data.get("ca_bundle", "") or "").strip()
        return cfg
    except (FileNotFoundError, OSError, json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError):
        return dict(DEFAULT_TLS_CONFIG)


def save_tls_config(path: str, cfg: dict) -> None:
    """Persist Bitbucket TLS settings to JSON file."""
    payload = {
        "verify_ssl": bool(cfg.get("verify_ssl", True)),
        "ca_bundle": str(cfg.get("ca_bundle", "") or "").strip(),
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def ollama_ping(base_url: str, *, timeout: int = 4) -> bool:
    """Return True if Ollama is reachable at base_url."""
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/api/tags")
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


def ollama_snapshot(
    base_url: str,
    *,
    timeout: int = 6,
    refresh: bool = False,
    max_age_s: int = _OLLAMA_CACHE_TTL_S,
) -> dict:
    """Return cached Ollama reachability and models from /api/tags."""
    normalized = (base_url or DEFAULT_LLM_CONFIG["base_url"]).rstrip("/")
    now = time.time()
    with _OLLAMA_CACHE_LOCK:
        cached = dict(_OLLAMA_CACHE.get(normalized, {}))
    if (
        cached
        and not refresh
        and (now - float(cached.get("fetched_at", 0.0))) <= max_age_s
    ):
        return cached

    snapshot = {
        "base_url": normalized,
        "reachable": False,
        "models": [],
        "fetched_at": now,
        "stale": False,
    }
    try:
        req = urllib.request.Request(normalized + "/api/tags")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        models = sorted(m.get("name", "") for m in data.get("models", []) if m.get("name"))
        snapshot.update({"reachable": True, "models": models})
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        if cached:
            snapshot.update({
                "reachable": bool(cached.get("reachable", False)),
                "models": list(cached.get("models", [])),
                "stale": True,
            })
    with _OLLAMA_CACHE_LOCK:
        _OLLAMA_CACHE[normalized] = dict(snapshot)
    return snapshot


def ollama_list_models(base_url: str, *, timeout: int = 6) -> list[str]:
    """Return model names exposed by Ollama /api/tags."""
    return list(ollama_snapshot(base_url, timeout=timeout, refresh=True).get("models", []))


def ensure_ollama_running(
    base_url: str,
    *,
    timeout_s: int = 15,
    log_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    """
    Ensure Ollama is reachable at base_url.
    Returns (True, "already_running"/"started") or (False, "<error>").
    """
    if ollama_ping(base_url):
        return True, "already_running"

    if log_fn:
        log_fn("  [LLM] Ollama not running - starting `ollama serve`...")

    try:
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except FileNotFoundError:
        msg = "`ollama` not found in PATH - install from https://ollama.com"
        if log_fn:
            log_fn(f"  [LLM] {msg}")
        return False, msg
    except OSError as exc:
        msg = f"Failed to start ollama: {exc}"
        if log_fn:
            log_fn(f"  [LLM] {msg}")
        return False, msg

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(1)
        if ollama_ping(base_url):
            if log_fn:
                log_fn("  [LLM] Ollama started")
            return True, "started"

    msg = f"Ollama did not become ready within {timeout_s}s"
    if log_fn:
        log_fn(f"  [LLM] {msg}")
    return False, msg
