from __future__ import annotations

from pathlib import Path


_DEFAULT_LLM_URL = "http://localhost:11434"
_DEFAULT_LLM_MODEL = "qwen2.5-coder:7b-instruct"
_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "web" / "spa_template.html"


def build_spa(*, has_saved_pat: bool, llm_cfg: dict) -> bytes:
    template = _TEMPLATE_PATH.read_text(encoding="utf-8")
    return (
        template.replace("__HAS_SAVED_PAT__", "true" if has_saved_pat else "false")
        .replace("__LLM_URL__", llm_cfg.get("base_url", _DEFAULT_LLM_URL))
        .replace("__LLM_MODEL__", llm_cfg.get("model", _DEFAULT_LLM_MODEL))
        .encode("utf-8")
    )
