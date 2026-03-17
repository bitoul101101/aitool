"""
LLM Reviewer — local false-positive reduction via Ollama.

Sends findings to a locally-running Ollama instance (default:
http://localhost:11434) for re-scoring.  No data leaves the machine.

Verdict meanings
----------------
keep      — genuine finding, severity stands
downgrade — real pattern but severity inflated; reduce by 1 level
dismiss   — false positive; remove from results

Eligibility filter — only sent for review if:
  confidence < CONFIDENCE_THRESH  OR  context in {"docs","test"}
  AND pattern not in _SKIP_PATTERNS

JSON reliability strategy
--------------------------
Ollama's `format` field accepts either the string "json" (valid JSON, any
schema) or a JSON Schema object (Ollama ≥ 0.5, constrained schema).

We attempt the constrained schema first (forces an array of verdict objects).
If that attempt fails or Ollama returns an error, we fall back to
format:"json" with aggressive client-side extraction.

All raw model responses are appended to LLM_DEBUG_LOG so failures can be
diagnosed without changing any code.
"""

from __future__ import annotations

import json
import re
import time
import textwrap
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

# ── Batch size tunables ───────────────────────────────────────────────
# compute_batch_size() overrides this at runtime based on model size + VRAM.
# This fallback is used when Ollama metadata is unavailable.
BATCH_SIZE_DEFAULT = 3

def _parse_param_billions(param_size: str) -> float:
    """Parse '15.7B', '7b', '0.5B' etc. → float in billions. Returns 0 on failure."""
    if not param_size:
        return 0.0
    s = param_size.strip().upper().rstrip("B").strip()
    try:
        return float(s)
    except ValueError:
        return 0.0


def _is_thinking_model(model_name: str) -> bool:
    """
    Return True for chain-of-thought / reasoning models that produce a long
    internal <think> block before answering.  These models need batch_size=1
    and a longer timeout regardless of VRAM.
    """
    low = (model_name or "").lower()
    return any(kw in low for kw in (
        "thinker", "thinking", "reasoner", "reason",
        "qwq", ":r1", "-r1", "_r1", "deepseek-r",
        "o1-", "o3-", "reflection",
    ))


def _request_timeout(model_name: str = "", param_size: str = "") -> int:
    """
    Return an appropriate HTTP timeout for a single LLM call.
    - Thinking/reasoning models : 600s (10 min) — CoT output is very long
    - Large model (>=14B)        : 360s
    - Default                    : REQUEST_TIMEOUT (180s)
    """
    if _is_thinking_model(model_name) or _is_thinking_model(param_size):
        return 600
    params = _parse_param_billions(param_size)
    if params >= 14:
        return 360
    return REQUEST_TIMEOUT


def _available_vram_gb() -> float:
    """
    Best-effort query for free GPU VRAM in GB.
    Tries nvidia-smi, then torch (if installed), falls back to 0.
    """
    # nvidia-smi
    try:
        import subprocess as _sp
        out = _sp.check_output(
            ["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
            timeout=4, stderr=_sp.DEVNULL
        ).decode()
        values = [int(x.strip()) for x in out.strip().splitlines() if x.strip().isdigit()]
        if values:
            return max(values) / 1024.0   # MiB → GiB
    except Exception:
        pass
    # torch
    try:
        import torch
        if torch.cuda.is_available():
            free, _total = torch.cuda.mem_get_info()
            return free / (1024 ** 3)
    except Exception:
        pass
    return 0.0


def compute_batch_size(param_size: str = "", vram_gb: float = 0.0) -> int:
    """
    Derive a safe batch size from model parameter count and available VRAM.

    Logic:
      - Larger models produce longer responses → smaller batches safer
      - More VRAM headroom → slightly larger batches tolerable
      - Hard floor = 1, hard ceiling = 8

    Tiers (parameters B):
      ≤ 3B  → base 6   (small/fast models — Phi-2, Qwen-1.8B, etc.)
      ≤ 8B  → base 4   (7B class — Mistral-7B, Llama-3-8B, Qwen2.5-7B)
      ≤ 16B → base 3   (14B/16B — DeepSeek-Coder-V2-Lite 15.7B)
      ≤ 34B → base 2   (33B class — CodeLlama-34B)
      > 34B → base 1   (70B+ — very slow, keep batches tiny)

    VRAM adjustment: +1 if free VRAM ≥ 10 GB, +1 more if ≥ 20 GB.
    """
    params = _parse_param_billions(param_size)

    if params <= 0:
        base = BATCH_SIZE_DEFAULT
    elif params <= 3:
        base = 6
    elif params <= 8:
        base = 4
    elif params <= 16:
        base = 3
    elif params <= 34:
        base = 2
    else:
        base = 1

    # Large model with no detected VRAM → likely CPU inference → cap at 1
    if vram_gb == 0 and params >= 14:
        return 1

    bonus = 0
    if vram_gb >= 20:
        bonus = 2
    elif vram_gb >= 10:
        bonus = 1

    return max(1, min(8, base + bonus))


def compute_worker_count(param_size: str = "", vram_gb: float = 0.0,
                         repo_count: int = 1) -> int:
    """
    Derive a safe parallel worker count for repo cloning + scanning.

    The LLM runs serially inside each worker so we cap workers to avoid
    multiple simultaneous Ollama inference calls starving the GPU.

    Logic:
      Each worker = 1 clone + 1 detector pass + potentially 1 LLM review.
      Workers are capped by:
        1. CPU cores (clone/scan is CPU + I/O bound)
        2. GPU VRAM headroom per concurrent LLM call
        3. Model size (larger models need more VRAM per call)

    CPU floor: always at least 2 workers (I/O latency hides well).
    CPU ceiling: os.cpu_count() or 8, whichever is less.

    VRAM-aware caps (param_size tiers):
      > 30B  → max 1 worker (70B+ models saturate any consumer GPU)
      > 13B  → max 2 workers if VRAM ≥ 16 GB, else 1
      > 6B   → max 3 workers if VRAM ≥ 12 GB, else 2
      ≤ 6B   → max 4 workers if VRAM ≥ 8 GB,  else 3
    No VRAM detected → use CPU-bound heuristic only (no penalty).

    Final value is also capped to repo_count (no point in excess workers).
    """
    import os as _os
    cpu_cap  = min(_os.cpu_count() or 4, 8)
    params   = _parse_param_billions(param_size)

    if vram_gb > 0:
        if params > 30:
            gpu_cap = 1
        elif params > 13:
            gpu_cap = 2 if vram_gb >= 16 else 1
        elif params > 6:
            gpu_cap = 3 if vram_gb >= 12 else 2
        else:
            gpu_cap = 4 if vram_gb >= 8 else 3
    else:
        # No GPU detected — pure CPU / RAM bound; stay conservative
        gpu_cap = cpu_cap

    workers = min(cpu_cap, gpu_cap, max(repo_count, 1))
    return max(1, workers)


# ── Other tunables ────────────────────────────────────────────────────
DEFAULT_BASE_URL   = "http://localhost:11434"
DEFAULT_MODEL      = "qwen2.5-coder:7b-instruct"
CONFIDENCE_THRESH  = 55        # findings below this score are candidates
CONTEXT_LINES      = 6         # source lines either side of the match
MAX_SNIPPET_CHARS  = 280       # hard cap on snippet per finding
MAX_RETRIES        = 1         # extra attempts after first failure
RETRY_DELAY        = 2.0       # seconds between retries
REQUEST_TIMEOUT    = 180       # seconds — local models can be slow
CHALLENGE_PASS     = True      # run a second defensive pass on dismissed findings
LLM_DEBUG_LOG      = "logs/llm_reviewer_debug.log"

# Patterns never sent for review — unambiguous high-signal rules
_SKIP_PATTERNS = {
    "entropy_secret",
    "openai_key_pattern",
    "anthropic_key_pattern",
    "js_hardcoded_key",
    "notebook_output_secret",
}

# ── Ollama structured format schema (Ollama ≥ 0.5) ───────────────────
# Requests an array where each element has verdict + reason + confidence.
_FORMAT_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["keep", "downgrade", "dismiss"]
            },
            "reason":     {"type": "string"},
            "confidence": {"type": "integer"}
        },
        "required": ["verdict", "reason", "confidence"]
    }
}

# ── Second-pass (challenge) schema — single object, not array ────────
_CHALLENGE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["keep", "downgrade", "dismiss"]
        },
        "reason":     {"type": "string"},
        "confidence": {"type": "integer"}
    },
    "required": ["verdict", "reason", "confidence"]
}

# ── Second-pass system prompt ─────────────────────────────────────────
_CHALLENGE_SYSTEM = textwrap.dedent("""\
    You are a senior security auditor providing a second opinion on a dismissed finding.
    A static analysis scanner flagged code. A first model dismissed it as a false positive.
    Your job: determine whether that dismissal was justified or whether the risk is real.

    IMPORTANT BIAS: false negatives (missing real risks) are more dangerous than false
    positives. Be actively sceptical of the first model's dismissal.

    INPUT: one finding with fields:
      pattern_name, capability, category, base_severity (1=Critical to 4=Low),
      context, file, file_ext, match, snippet, first_reason

    OUTPUT: a single JSON object with exactly three keys:
      "verdict":    "keep" | "downgrade" | "dismiss"
      "reason":     one sentence under 25 words — identify what was wrong or right
                    about the first model's reasoning
      "confidence": integer 0-100

    VERDICT MEANINGS:
      keep      = the first dismissal was wrong — this is a real risk at original severity
      downgrade = risk is real but first model was right that severity is inflated
      dismiss   = the first dismissal was correct

    THESE DISMISSAL REASONS ARE NEVER SUFFICIENT ON THEIR OWN:
      - "it's just an import"
      - "low confidence match"
      - "common pattern"
      - "no credentials visible in snippet"
      - "could be a false positive"
      For base_severity 1-2, these reasons alone → verdict must be "keep" or "downgrade".

    RULES BY SEVERITY:
      base_severity 1 (Critical): dismiss only if snippet is provably a placeholder,
                                   comment, or documentation file. Otherwise keep.
      base_severity 2 (High):     keep unless first_reason cites a specific concrete
                                   reason (placeholder value, docs file, test fixture).
      base_severity 3-4:          downgrade if first model cited reasonable context;
                                   dismiss only if clearly not security-relevant.

    SPECIFIC RULES:
      - Real token/key value (random chars, hf_*, sk-*, ghp_*, etc.) → always keep
      - SDK import with visible credential or PII in snippet → keep
      - LLM output passed to eval/exec/shell without sandboxing → always keep
      - User input flowing to prompt/tool/memory/vector store → keep
      - Placeholder, docs example, or test fixture with mock data → dismiss may be correct
      - Infrastructure YAML with no credential exposure → downgrade is acceptable
      - When genuinely unsure about a Critical/High finding → keep

    IMPORTANT: return ONLY the JSON object. No prose. No markdown fences.
    The first character must be { and the last must be }.
""")


# ── System prompt ─────────────────────────────────────────────────────
_SYSTEM = textwrap.dedent("""\
    You review static-analysis findings from an AI/LLM usage scanner.
    Your role: eliminate false positives while preserving real security risks.
    A missed real vulnerability (false negative) is worse than an extra finding.

    INPUT: a JSON array of findings. Each finding has:
      pattern_name, capability, category, base_severity (1=Critical to 4=Low),
      context, file, file_ext, match, snippet

    OUTPUT: a JSON array, same length and order as the input.
    Each element must have EXACTLY these three keys:
      "verdict":    "keep" | "downgrade" | "dismiss"
      "reason":     one sentence under 25 words, meaningful to a developer
      "confidence": integer 0-100 reflecting your certainty in this verdict

    VERDICT MEANINGS:
      keep      = genuine, actionable security risk in this specific context
      downgrade = real pattern but severity overstated for this context
      dismiss   = confirmed false positive — genuinely not a security risk

    SEVERITY-AWARE DEFAULT BIAS:
      base_severity 1 (Critical) → keep unless snippet is clearly a placeholder,
                                    comment, or documentation file
      base_severity 2 (High)     → keep when in doubt
      base_severity 3 (Medium)   → downgrade when in doubt
      base_severity 4 (Low)      → downgrade when in doubt

    BEFORE DECIDING, consider briefly:
      1. Is this production code, a test, or documentation?
      2. Does the snippet show real data (credentials, PII, user input) flowing?
      3. Is the matched text an actual value or just a variable name / comment?

    -- HARDCODED SECRETS & KEYS --
    keep      : real-looking token/key value (random chars, hf_*, sk-*, ghp_*, etc.)
    keep      : key assigned a value that is not an env-var reference
    downgrade : key name present but value is os.getenv / process.env / ${VAR}
    dismiss   : placeholder (replace-with-*, your-*-key, <INSERT_*>, YOUR_KEY,
                changeme, xxx*, example-*, fake-*, dummy-*, PLACEHOLDER)
    dismiss   : key appears only in a comment or docstring
    dismiss   : .env.example / .env.sample / .env.template files

    -- AI SDK USAGE (openai, langchain, anthropic, etc.) --
    keep      : direct API call with credentials or sensitive data visible in snippet
    downgrade : SDK imported/used but no credential or PII handling shown
    downgrade : appears in requirements.txt, package.json, pyproject.toml (dep only)
    dismiss   : SDK name in a comment, string literal, or log message only
    dismiss   : devDependencies / [dev] / [test] section of a config file
    dismiss   : file_ext is .md, .rst, .txt, .adoc (documentation)

    -- LOCAL LLM DEPLOYMENTS (ollama, vllm, triton, etc.) --
    keep      : inference endpoint exposed without auth, or sensitive data visible
    downgrade : serving stack config present but no obvious exposure risk
    dismiss   : manifest / helm / k8s YAML under manifests/, helm/, charts/, k8s/
    dismiss   : file_ext is .md or value is a URI scheme (ollama://)

    -- AGENTIC / LLM-SPECIFIC RISKS --
    keep      : user-controlled input flows into prompt, tool, memory, or vector store
    keep      : LLM output used in eval(), exec(), shell command, or file write
    keep      : system prompt concatenated with user input via string formatting
    keep      : trust_remote_code=True, auto_approve=True, or human approval disabled
    keep      : SQL query built with f-string and user-controlled variable
    keep      : jailbreak/override strings (SYSTEM OVERRIDE, ROOT_ADMIN, safety.*deprecated)
    keep      : prompt injection indicators in LLM output (🔒 🔓, multiple conflicting answers,
                "Absolutely! Here's", "/NoSkill", "DAN Mode enabled")
    downgrade : pattern present but data flow to dangerous sink not visible in snippet
    dismiss   : pattern appears in a test that explicitly validates the behaviour

    -- INSECURE CODE (PyRIT InsecureCodeScorer criteria) --
    keep      : eval() / exec() called with web request data or LLM output (Critical)
    keep      : stack trace or exception detail sent in HTTP response body (High)
    keep      : file encryption loop over directory traversal — ransomware pattern (Critical)
    keep      : unbounded network request loop — DoS pattern (High)
    keep      : deprecated or known-vulnerable library with active CVE (High)
    downgrade : debug mode active but file is clearly a local dev config
    downgrade : error handling exposes non-sensitive internal state only
    dismiss   : exception logged server-side only, not exposed to client

    -- PHISHING / SOCIAL ENGINEERING IN PROMPTS (PyRIT phishing.yaml) --
    keep      : urgency language in system prompt template (account suspended, verify now)
    keep      : impersonation of trusted entity in hardcoded prompt
    downgrade : generic sales/marketing copy that uses mild urgency
    dismiss   : urgency language in a test or documentation example

    -- LANGUAGE / FILE TYPE RULES --
    .md .rst .txt .adoc .mdx   : dismiss unless a real secret value is present
    .yaml .yml in infra dirs   : downgrade; dismiss if clearly example config
    .json devDependencies      : downgrade to LOW
    test / spec / fixture dirs : downgrade, not dismiss
    Jupyter .ipynb output cell : keep (executed, real output)
    Jupyter .ipynb source cell : treat as production code

    -- GENERAL RULES --
    - context=docs or context=test alone: downgrade, not dismiss
    - If snippet is "(source not available)": downgrade, do not dismiss
    - Match in a code comment that describes the pattern: dismiss
    - Monitoring / Grafana / OpenAPI spec files: dismiss
    - Same pattern repeated across files: apply consistent verdicts

    IMPORTANT: return ONLY the JSON array. No prose. No markdown fences.
    The first character of your response must be [ and the last must be ].
""")


# ── Debug logger ──────────────────────────────────────────────────────

def _debug_log(label: str, text: str) -> None:
    """Append raw model output to the debug log file for post-mortem inspection."""
    try:
        Path(LLM_DEBUG_LOG).parent.mkdir(parents=True, exist_ok=True)
        with open(LLM_DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*60}\n{label}\n{'='*60}\n{text}\n")
    except Exception:
        pass


# ── JSON extraction ───────────────────────────────────────────────────

def _unwrap_object(data: Any) -> Optional[List[Dict]]:
    """
    If model returned a JSON object instead of an array, try to find
    a list value inside it (e.g. {"verdicts": [...]}).
    """
    if not isinstance(data, dict):
        return None
    for v in data.values():
        if isinstance(v, list) and v:
            return v
    return None


def _has_verdict_fields(items: list) -> bool:
    """
    Return True if at least one item in the list looks like a verdict object
    (has a 'verdict' key). Rejects arrays where the model echoed back input
    fields (pattern_name, capability, etc.) instead of generating verdicts.
    """
    if not items:
        return False
    return any(isinstance(item, dict) and "verdict" in item for item in items)


def _extract_json_array(text: str) -> Optional[List[Dict]]:
    """
    Robustly extract a JSON array from model output that may contain:
      - markdown fences  (```json ... ```)
      - preamble text before the array
      - object wrapper   ({"verdicts": [...]})
      - truncated output (partial array)
      - trailing commentary after the array

    Strategy:
      1. Strip markdown fences
      2. Try direct parse
      3. Unwrap object wrapper
      4. Find outermost [...] by bracket-matching and parse that
      5. Salvage all complete {...} objects from a truncated array
    """
    if not text:
        return None

    # 1 — strip markdown fences
    text = re.sub(r"```[a-zA-Z]*\n?", "", text).strip()
    text = text.replace("```", "").strip()

    # 2 — try direct parse
    try:
        data = json.loads(text)
        if isinstance(data, list):
            if _has_verdict_fields(data):
                return data
        unwrapped = _unwrap_object(data)
        if unwrapped is not None and _has_verdict_fields(unwrapped):
            return unwrapped
    except json.JSONDecodeError:
        pass

    # 3 — find outermost [...] by bracket-matching
    start = text.find("[")
    if start == -1:
        # Maybe model returned an object at top level — try first {
        brace = text.find("{")
        if brace != -1:
            try:
                data = json.loads(text[brace:])
                unwrapped = _unwrap_object(data)
                if unwrapped is not None:
                    return unwrapped
            except json.JSONDecodeError:
                pass
        return None

    depth  = 0
    end    = -1
    in_str = False
    escape = False
    for i, ch in enumerate(text[start:], start=start):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                end = i
                break

    if end != -1:
        try:
            data = json.loads(text[start:end + 1])
            if isinstance(data, list) and _has_verdict_fields(data):
                return data
        except json.JSONDecodeError:
            pass

    # 4 — truncated array: salvage all complete top-level objects
    fragment  = text[start:]
    objects   = []
    obj_start = None
    obj_depth = 0
    in_str    = False
    escape    = False
    for i, ch in enumerate(fragment):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            if obj_depth == 0:
                obj_start = i
            obj_depth += 1
        elif ch == "}":
            obj_depth -= 1
            if obj_depth == 0 and obj_start is not None:
                try:
                    obj = json.loads(fragment[obj_start:i + 1])
                    objects.append(obj)
                except json.JSONDecodeError:
                    pass
                obj_start = None

    valid = [o for o in objects if _has_verdict_fields([o])]
    return valid if valid else None


# ── Snippet extraction ────────────────────────────────────────────────

def _extract_snippet(file_contents: Dict[str, str],
                     file_path: str,
                     line_number: int) -> str:
    """Return CONTEXT_LINES either side of line_number, marked with >>>."""
    content = file_contents.get(file_path, "")
    if not content:
        return "(source not available)"
    lines = content.splitlines()
    lo = max(0, line_number - CONTEXT_LINES - 1)
    hi = min(len(lines), line_number + CONTEXT_LINES)
    out = []
    for i, line in enumerate(lines[lo:hi], start=lo + 1):
        marker = ">>>" if i == line_number else "   "
        out.append(f"{marker} {i:4d} | {line[:100]}")
    snippet = "\n".join(out)
    if len(snippet) > MAX_SNIPPET_CHARS:
        snippet = snippet[:MAX_SNIPPET_CHARS] + "\n...(truncated)"
    return snippet


# ── Batch prompt builder ──────────────────────────────────────────────

def _build_user_message(batch: List[Dict[str, Any]],
                        file_contents: Dict[str, str]) -> str:
    """Serialise a batch of findings into the user message."""
    items = []
    for f in batch:
        file_path   = f.get("file", "")
        line_number = f.get("line", 0)
        snippet     = _extract_snippet(file_contents, file_path, line_number)
        items.append({
            "pattern_name":  f.get("provider_or_lib", ""),
            "capability":    f.get("capability", ""),
            "category":      f.get("category", ""),
            "base_severity": f.get("severity", f.get("base_severity", 4)),
            "context":       f.get("context", "production"),
            "file":          file_path,
            "file_ext":      Path(file_path).suffix.lower(),
            "match":         (f.get("match") or "")[:120],
            "snippet":       snippet,
        })
    return (
        f"Review these {len(items)} finding(s):\n"
        + json.dumps(items, separators=(",", ":"))
    )


# ── Challenge (second-pass) message builder ──────────────────────────

def _build_challenge_message(finding: Dict[str, Any],
                             file_contents: Dict[str, str],
                             first_reason: str) -> str:
    """Build a single-finding challenge message for the defensive second pass."""
    file_path   = finding.get("file", "")
    line_number = finding.get("line", 0)
    snippet     = _extract_snippet(file_contents, file_path, line_number)
    item = {
        "pattern_name":  finding.get("provider_or_lib", ""),
        "capability":    finding.get("capability", ""),
        "category":      finding.get("category", ""),
        "base_severity": finding.get("severity", finding.get("base_severity", 4)),
        "context":       finding.get("context", "production"),
        "file":          file_path,
        "file_ext":      Path(file_path).suffix.lower(),
        "match":         (finding.get("match") or "")[:120],
        "snippet":       snippet,
        "first_reason":  first_reason,
    }
    return "Challenge this dismissal:\n" + json.dumps(item, separators=(",", ":"))


def _call_ollama_single(base_url: str,
                        model: str,
                        user_message: str,
                        log_fn: Callable,
                        stop_event=None) -> Optional[Dict]:
    """
    Call Ollama for a single-object response (challenge pass).
    Returns a dict with verdict+reason, or None on failure.
    """
    # Try structured schema first (Ollama >= 0.5), fall back to json-mode
    for use_schema in (True, False):
        if stop_event and stop_event.is_set():
            return None
        body: Dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": _CHALLENGE_SYSTEM},
                {"role": "user",   "content": user_message},
            ],
            "temperature": 0.0,
            "stream": False,
        }
        if use_schema:
            body["format"] = _CHALLENGE_SCHEMA
        else:
            body["format"] = "json"
        payload = json.dumps(body).encode("utf-8")
        url = base_url.rstrip("/") + "/api/chat"
        try:
            # Use interruptible _post so stop_event aborts the call quickly.
            # _call_ollama_single uses /api/chat (Ollama native) — response shape
            # is {"message": {"content": "..."}} not OpenAI format, so we call
            # urlopen directly but still via the interruptible wrapper.
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            import threading as _th
            _rb, _eb = [], []
            def _do():
                try:
                    with urllib.request.urlopen(req, timeout=_request_timeout(model)) as r:
                        _rb.append(json.loads(r.read().decode("utf-8")))
                except Exception as e:
                    _eb.append(e)
            _t = _th.Thread(target=_do, daemon=True)
            _t.start()
            _sl, _el = 0.5, 0.0
            while _t.is_alive():
                _t.join(timeout=_sl); _el += _sl
                if stop_event and stop_event.is_set():
                    raise urllib.error.URLError("scan stopped by user")
                if _el >= _request_timeout(model) + 5:
                    raise urllib.error.URLError("challenge request timed out")
            if _eb: raise _eb[0]
            if not _rb: raise urllib.error.URLError("no response")
            raw_obj = _rb[0]
            text = raw_obj.get("message", {}).get("content", "")
            _debug_log(f"CHALLENGE use_schema={use_schema}", text)
            # Parse single object
            text = re.sub(r"```[a-zA-Z]*\n?", "", text).strip().replace("```", "").strip()
            try:
                obj = json.loads(text)
                if isinstance(obj, dict) and "verdict" in obj:
                    return obj
                # Model may have wrapped in array
                if isinstance(obj, list) and obj and isinstance(obj[0], dict):
                    return obj[0]
            except json.JSONDecodeError:
                pass
            # Fallback: find first {...}
            brace = text.find("{")
            if brace != -1:
                depth, end = 0, -1
                for ci, ch in enumerate(text[brace:], brace):
                    if ch == "{": depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0: end = ci; break
                if end != -1:
                    try:
                        obj = json.loads(text[brace:end+1])
                        if isinstance(obj, dict) and "verdict" in obj:
                            return obj
                    except json.JSONDecodeError:
                        pass
        except urllib.error.HTTPError as e:
            if use_schema and e.code == 400:
                continue   # schema not supported — try json-mode
            log_fn(f"  [LLM] challenge HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            log_fn(f"  [LLM] challenge connection error: {e.reason}")
            return None  # no point retrying if Ollama unreachable
        except Exception as e:
            log_fn(f"  [LLM] challenge unexpected error: {e}")
        if not use_schema:
            break
    return None


# ── Ollama HTTP call ──────────────────────────────────────────────────

def _build_payload(model: str,
                   user_message: str,
                   use_schema: bool) -> bytes:
    """Build the JSON request body. use_schema=True requires Ollama ≥ 0.5."""
    body: Dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user",   "content": user_message},
        ],
        "temperature": 0.0,
        "stream": False,
    }
    if use_schema:
        body["format"] = _FORMAT_SCHEMA   # constrained array schema
    else:
        body["format"] = "json"           # valid JSON, any shape
    return json.dumps(body).encode("utf-8")


def _post(url: str, payload: bytes, timeout: int,
          stop_event=None) -> str:
    """
    POST payload to url and return the model response text.

    If stop_event is provided the call runs in a daemon thread and is
    joined in 0.5 s increments so the caller unblocks within ~0.5 s of
    stop being requested rather than waiting up to REQUEST_TIMEOUT.
    """
    import threading as _threading

    result_box: list = []   # [response_str] on success
    error_box:  list = []   # [exception]    on failure

    def _do_post():
        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                result_box.append(body["choices"][0]["message"]["content"])
        except Exception as exc:
            error_box.append(exc)

    t = _threading.Thread(target=_do_post, daemon=True)
    t.start()

    # Join in short slices so we honour stop_event without blocking
    slice_s = 0.5
    elapsed = 0.0
    while t.is_alive():
        t.join(timeout=slice_s)
        elapsed += slice_s
        if stop_event and stop_event.is_set():
            # Thread is daemon — it will die with the process.
            # Raise so the caller knows the request was aborted.
            raise urllib.error.URLError("scan stopped by user")
        if elapsed >= timeout + 5:
            raise urllib.error.URLError("request timed out (interruptible)")

    if error_box:
        raise error_box[0]
    if result_box:
        return result_box[0]
    raise urllib.error.URLError("no response from Ollama")


def _call_ollama(base_url: str,
                 model: str,
                 user_message: str,
                 log_fn: Callable[[str], None],
                 stop_event=None) -> Optional[List[Dict]]:
    """
    Try two strategies in order:
      1. Structured schema (Ollama ≥ 0.5) — most reliable
      2. format:"json" with aggressive client-side extraction — fallback

    Each strategy gets MAX_RETRIES+1 attempts before moving on.
    Raw responses are always written to LLM_DEBUG_LOG.
    """
    url = base_url.rstrip("/") + "/v1/chat/completions"

    for use_schema in (True, False):
        mode = "schema" if use_schema else "json-mode"
        payload = _build_payload(model, user_message, use_schema)

        for attempt in range(1, MAX_RETRIES + 2):
            if stop_event and stop_event.is_set():
                return None   # propagate stop immediately
            try:
                raw = _post(url, payload, _request_timeout(model), stop_event=stop_event)
                _debug_log(
                    f"mode={mode} attempt={attempt} model={model}",
                    raw
                )

                verdicts = _extract_json_array(raw)
                if verdicts is not None:
                    if use_schema is False or attempt > 1:
                        # Only log fallback/retry usage — schema success is silent
                        log_fn(f"  [LLM] Response parsed via {mode} "
                               f"(attempt {attempt})")
                    return verdicts

                # Schema-mode failures are expected for small models and always
                # followed by the json-mode fallback — don't surface in the UI log.
                if not use_schema:
                    log_fn(
                        f"  [LLM] [{mode} attempt {attempt}] "
                        f"Could not parse response — retrying"
                    )
                if attempt <= MAX_RETRIES:
                    time.sleep(RETRY_DELAY)

            except urllib.error.HTTPError as e:
                # 400 from structured schema = Ollama too old — skip to fallback
                if use_schema and e.code == 400:
                    log_fn("  [LLM] Structured schema not supported "
                           "— falling back to json-mode")
                    break
                log_fn(f"  [LLM] [{mode}] HTTP {e.code} (attempt {attempt})")
                if attempt <= MAX_RETRIES:
                    time.sleep(RETRY_DELAY)

            except urllib.error.URLError as e:
                log_fn(f"  [LLM] [{mode}] Connection error: {e.reason}")
                return None   # No point retrying if Ollama is unreachable

            except Exception as e:
                log_fn(f"  [LLM] [{mode}] Error (attempt {attempt}): {e}")
                if attempt <= MAX_RETRIES:
                    time.sleep(RETRY_DELAY)

    return None


# ── Eligibility filter ────────────────────────────────────────────────

def _is_eligible(finding: Dict[str, Any]) -> bool:
    """Return True if this finding should be sent for LLM review."""
    if finding.get("provider_or_lib", "") in _SKIP_PATTERNS:
        return False
    confidence = finding.get("confidence", 50)
    context    = finding.get("context", "production")
    return confidence < CONFIDENCE_THRESH or context in {"docs", "test"}


# ── Apply verdict ─────────────────────────────────────────────────────

def _apply_verdict(finding: Dict[str, Any], verdict_obj: Any) -> str:
    """Mutate finding in-place with LLM verdict. Returns normalised verdict."""
    if not isinstance(verdict_obj, dict):
        verdict_obj = {}

    verdict = str(verdict_obj.get("verdict", "keep")).lower().strip()
    reason  = str(verdict_obj.get("reason", "")).strip()

    if verdict not in {"keep", "downgrade", "dismiss"}:
        verdict = "keep"

    finding["llm_verdict"]  = verdict
    finding["llm_reason"]   = reason
    finding["llm_reviewed"] = True

    if verdict == "downgrade":
        finding["severity"] = min(4, finding.get("severity", 3) + 1)

    return verdict


# ── Public interface ──────────────────────────────────────────────────

class LLMReviewer:
    """Post-scan LLM re-scorer using a local Ollama instance."""

    def __init__(self,
                 base_url: str = DEFAULT_BASE_URL,
                 model: str    = DEFAULT_MODEL,
                 log_fn: Callable[[str], None] = print,
                 stop_event=None):
        self.base_url           = base_url.rstrip("/")
        self.model              = model
        self.log_fn             = log_fn
        self._model_param_size  = ""   # populated by model_info()
        self._stop_event        = stop_event  # threading.Event or None

    def is_available(self) -> bool:
        """Return True if Ollama is reachable and the model is present."""
        try:
            url = self.base_url + "/api/tags"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data   = json.loads(resp.read())
                models = [m.get("name", "") for m in data.get("models", [])]
                base   = self.model.split(":")[0]
                return any(base in m for m in models)
        except Exception:
            return False

    def model_info(self) -> Dict[str, str]:
        """
        Query /api/show for model details.

        Returns a dict with keys (all may be empty string if unavailable):
          name            — full model tag as stored in Ollama
          family          — model family  (e.g. "deepseek2")
          parameter_size  — e.g. "15.7B"
          quantization    — e.g. "Q4_K_M"
          digest          — short commit-style hash (first 12 chars)

        On any error returns a dict with just name=self.model.
        """
        base = {"name": self.model, "family": "", "parameter_size": "",
                "quantization": "", "digest": ""}
        try:
            payload = json.dumps({"name": self.model}).encode("utf-8")
            req = urllib.request.Request(
                self.base_url + "/api/show",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data    = json.loads(resp.read())
                details = data.get("details", {})
                digest  = data.get("digest", "")
                base.update({
                    "family":         details.get("family", ""),
                    "parameter_size": details.get("parameter_size", ""),
                    "quantization":   details.get("quantization_level", ""),
                    "digest":         digest[:12] if digest else "",
                })
                self._model_param_size = base["parameter_size"]
        except Exception as e:
            base["_info_error"] = str(e)
        return base

    def review(self,
               findings: List[Dict[str, Any]],
               file_contents: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Review eligible findings. Returns filtered+annotated list.

        Dismissed findings are removed entirely.
        Downgraded findings have severity += 1 (capped at LOW).
        Reviewed findings gain: llm_verdict / llm_reason / llm_reviewed.

        If a batch returns fewer verdicts than expected (truncated response),
        salvaged verdicts are applied and the rest are kept unchanged.
        """
        eligible   = [f for f in findings if _is_eligible(f)]
        ineligible = [f for f in findings if not _is_eligible(f)]

        if not eligible:
            self.log_fn(f"  [LLM] 0 findings eligible for review ({len(ineligible)} skipped)")
            return findings

        # Compute adaptive batch size from model parameter count + free VRAM
        vram   = _available_vram_gb()
        b_size = compute_batch_size(
            self._model_param_size, vram_gb=vram
        )
        # Thinking/reasoning models override batch size to 1 regardless of param detection
        if _is_thinking_model(self.model):
            b_size = 1
        self.log_fn(
            f"  [LLM] Reviewing {len(eligible)} finding(s) via {self.model} "
            f"({len(ineligible)} skipped — high-confidence) "
            f"batch={b_size}"
            + (f" vram={vram:.1f}GB" if vram > 0 else "")
            + (" [thinking model — batch=1, timeout=600s]" if b_size == 1 and _is_thinking_model(self.model) else "")
        )

        kept              = []
        dismissed_findings = []   # (finding, first_reason) — for challenge pass
        dismissed_count   = 0
        downgraded_count  = 0
        error_count       = 0
        salvaged_count    = 0
        sev_labels       = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
        total_batches    = (len(eligible) + b_size - 1) // b_size

        for batch_start in range(0, len(eligible), b_size):
            batch     = eligible[batch_start: batch_start + b_size]
            batch_num = batch_start // b_size + 1

            self.log_fn(
                f"  [LLM] Batch {batch_num}/{total_batches} "
                f"({len(batch)} finding(s))..."
            )

            # Abort immediately if stop was requested
            if self._stop_event and self._stop_event.is_set():
                self.log_fn("  [LLM] Stopped by user — keeping remaining findings as-is")
                kept.extend(eligible[batch_start:])
                break

            user_msg = _build_user_message(batch, file_contents)
            verdicts = _call_ollama(
                self.base_url, self.model, user_msg, self.log_fn,
                stop_event=self._stop_event,
            )

            if verdicts is None:
                self.log_fn(
                    f"  [LLM] Batch {batch_num} failed — keeping as-is"
                )
                kept.extend(batch)
                error_count += len(batch)
                continue

            if len(verdicts) < len(batch):
                short = len(batch) - len(verdicts)
                salvaged_count += short
                self.log_fn(
                    f"  [LLM] Batch {batch_num}: {len(verdicts)}/{len(batch)} verdicts "
                    f"— {short} kept unreviewed"
                )

            for i, finding in enumerate(batch):
                if i < len(verdicts):
                    verdict = _apply_verdict(finding, verdicts[i])
                else:
                    finding["llm_verdict"]  = "keep"
                    finding["llm_reason"]   = "no verdict returned"
                    finding["llm_reviewed"] = True
                    verdict = "keep"

                fname  = Path(finding.get("file", "")).name
                lib    = finding.get("provider_or_lib", "")
                reason = finding.get("llm_reason", "")

                if verdict == "dismiss":
                    dismissed_count += 1
                    dismissed_findings.append((finding, reason))
                    self.log_fn(
                        f"  [LLM] ✗ DISMISS   {lib} in {fname} — {reason}"
                    )
                elif verdict == "downgrade":
                    downgraded_count += 1
                    sev = sev_labels.get(finding.get("severity", 3), "?")
                    self.log_fn(
                        f"  [LLM] ↓ DOWNGRADE {lib} → {sev} in {fname} — {reason}"
                    )
                    kept.append(finding)
                else:
                    kept.append(finding)

        # ── Second pass: challenge each dismissal ──────────────────────
        reinstated_count = 0
        if CHALLENGE_PASS and dismissed_findings and not (
            self._stop_event and self._stop_event.is_set()
        ):
            self.log_fn(
                f"  [LLM] Challenge pass: re-checking {len(dismissed_findings)} "
                f"dismissal(s) individually..."
            )
            for finding, first_reason in dismissed_findings:
                if self._stop_event and self._stop_event.is_set():
                    break
                fname = Path(finding.get("file", "")).name
                lib   = finding.get("provider_or_lib", "")
                msg   = _build_challenge_message(finding, file_contents, first_reason)
                result_obj = _call_ollama_single(
                    self.base_url, self.model, msg, self.log_fn,
                    stop_event=self._stop_event,
                )
                if result_obj is None:
                    # Call failed — safe default: reinstate the finding
                    finding["llm_verdict"]  = "keep"
                    finding["llm_reason"]   = "challenge call failed — reinstated"
                    finding["llm_reviewed"] = True
                    kept.append(finding)
                    reinstated_count += 1
                    self.log_fn(f"  [LLM] ⟳ REINSTATE {lib} in {fname} — challenge failed")
                    continue

                challenge_verdict = str(result_obj.get("verdict", "dismiss")).lower().strip()
                challenge_reason  = str(result_obj.get("reason", "")).strip()

                if challenge_verdict == "keep":
                    finding["llm_verdict"]  = "keep"
                    finding["llm_reason"]   = f"reinstated: {challenge_reason}"
                    finding["llm_reviewed"] = True
                    kept.append(finding)
                    reinstated_count += 1
                    self.log_fn(
                        f"  [LLM] ⟳ REINSTATE {lib} in {fname} — {challenge_reason}"
                    )
                else:
                    # Dismissal confirmed — stays dismissed (not added to kept)
                    self.log_fn(
                        f"  [LLM] ✓ CONFIRM   {lib} in {fname} — {challenge_reason}"
                    )

        result = kept + ineligible

        parts = [
            f"dismissed:{dismissed_count - reinstated_count}",
            f"reinstated:{reinstated_count}",
            f"downgraded:{downgraded_count}",
            f"kept:{len(kept) - downgraded_count - reinstated_count}",
        ]
        if error_count:
            parts.append(f"errors:{error_count}")
        if salvaged_count:
            parts.append(f"unreviewed:{salvaged_count}")

        self.log_fn(f"  [LLM] Done — " + "  ".join(parts))
        self.log_fn(f"  [LLM] Debug log: {LLM_DEBUG_LOG}")

        return result
