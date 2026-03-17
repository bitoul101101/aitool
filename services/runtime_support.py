from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Callable


DEFAULT_LLM_CONFIG = {
    "base_url": "http://localhost:11434",
    "model": "qwen2.5-coder:7b-instruct",
}


def load_llm_config(path: str) -> dict:
    """Load LLM settings from JSON file, falling back to defaults."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        cfg = dict(DEFAULT_LLM_CONFIG)
        cfg.update({k: v for k, v in data.items() if k in DEFAULT_LLM_CONFIG})
        return cfg
    except Exception:
        return dict(DEFAULT_LLM_CONFIG)


def save_llm_config(path: str, cfg: dict) -> None:
    """Persist LLM settings to JSON file."""
    try:
        Path(path).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"[WARN] Could not save LLM config: {exc}")


def ollama_ping(base_url: str, *, timeout: int = 4) -> bool:
    """Return True if Ollama is reachable at base_url."""
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/api/tags")
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception:
        return False


def ollama_list_models(base_url: str, *, timeout: int = 6) -> list[str]:
    """Return model names exposed by Ollama /api/tags."""
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/api/tags")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return sorted(m.get("name", "") for m in data.get("models", []) if m.get("name"))
    except Exception:
        return []


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
    except Exception as exc:
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
