"""
AI Usage Detector v3 — Enhanced Detection Engine

Enhancements:
  A  Confidence scoring     — each finding gets a 0-100 score from signal accumulation
  B  Comment stripping      — Python/JS comments removed before regex matching
  C  Test file suppression  — findings in test paths downgraded by 2 severity levels
  D  Corroboration boost    — multiple patterns in same file raises confidence
  E  Entropy secrets        — high-entropy strings near cred vars flagged
  F  Dynamic imports        — importlib/__import__/dynamic require() detected
  G  Data exfiltration      — file/df/db/env content piped to LLM flagged
  H  Unsafe model loading   — torch.load / pickle / remote from_pretrained flagged
  I  Secret/AI correlation  — secret + live AI usage + prompt/data handling escalated
"""

import re
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Set

from scanner.patterns import (
    ALL_PATTERNS, SCAN_EXTENSIONS, SKIP_DIRS, SKIP_FILES, IMPORT_GUARDS
)
from scanner.aiignore import load_aiignore, is_suppressed
from scanner.entropy import scan_entropy_secrets, shannon_entropy

# ── Config-only pattern slugs ────────────────────────────────────
_CONFIG_LIBS = {
    "env_file_key", "docker_compose_key", "terraform_ai_resource",
    "k8s_model_serving", "dependency_declaration", "ci_secret_ref",
    "model_name_in_config",
    # Task 7: IaC patterns live in config/yaml files — must be in _CONFIG_LIBS
    # so the "skip non-config patterns on config files" guard doesn't drop them
    "helm_ai_values", "ansible_ai", "k8s_ai_manifest", "pulumi_ai",
}
_CONFIG_EXTENSIONS = {
    ".env", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".tf", ".hcl",
    "requirements.txt", "pyproject.toml", "package.json",
    "Dockerfile", ".Dockerfile",
}

_CODE_EXTENSIONS = {
    '.py', '.pyw',
    '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.vue', '.svelte',
    '.java', '.go', '.cs', '.c', '.cpp', '.h', '.hpp',
    '.rs', '.swift', '.kt', '.scala', '.groovy',
    '.rb', '.sh', '.bash', '.ps1', '.r', '.pl', '.sql',
}

_SECRET_FINDING_LIBS = {
    "hardcoded_key",
    "openai_key_pattern",
    "anthropic_key_pattern",
    "js_hardcoded_key",
    "entropy_secret",
    "notebook_output_secret",
    "minified_bundle_secret",
}

_AI_USAGE_CATEGORIES = {
    "External AI API",
    "AI Proxy/Gateway",
    "Agent Framework",
    "RAG/Vector DB",
}

_PROMPT_FLOW_RE = re.compile(
    r"(\bprompt\b|\bmessages\b|\buser[_\- ]?input\b|\brequest\b|\bresponse\b"
    r"|\boutput\b|\bcontent\b|\bchat_history\b|\bcontext\b|\bstream\b|\binput\s*\("
    r"|request\.(get_json|json|form|args)|flask\.request|fastapi|gradio|streamlit)",
    re.IGNORECASE,
)

_TOOL_MARKER_RE = re.compile(r"Tool\s*\(|BaseTool|StructuredTool|@tool\b", re.IGNORECASE)
_FIXED_ARGV_SUBPROCESS_RE = re.compile(
    r"^\s*\w+\s*=\s*subprocess\.(?:run|call|Popen|check_output|check_call)\s*\($"
)
_FIXED_ARGV_SUBPROCESS_WINDOW_RE = re.compile(
    r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[",
    re.IGNORECASE | re.DOTALL,
)
_LOCAL_FILE_HASH_RE = re.compile(
    r"hashlib\.(?:sha(?:1|224|256|384|512)|md5)\s*\(",
    re.IGNORECASE,
)
_REPORT_PROVIDER_MAP_RE = re.compile(r'^\s*"[^"]+"\s*:\s*"[^"]+"')
_SELF_SCAN_IGNORED_PATHS = {
    "scanner/patterns.py",
}
_SELF_SCAN_LOCAL_LLM_PLUMBING_PATHS = {
    "reports/report_server.py",
    "services/settings_service.py",
    "reports/html_report.py",
    "scanner/llm_reviewer.py",
}
_SELF_SCAN_ANALYSIS_INTERNAL_PATHS = {
    "scanner/detector.py",
    "scanner/cross_file.py",
}

# ── Entropy guard for credential patterns ────────────────────────
# Real secrets have high entropy (≥3.0 bits/char).  Documentation examples,
# placeholder values, and env-var references (e.g. $VAR, ${VAR}) are low-
# entropy and should be suppressed rather than reported as Critical findings.

_ENTROPY_GUARD_THRESHOLD = 3.0   # bits/char — below this → suppress

# Matches the value portion of   KEY = "value"  or  KEY: value
_CRED_VALUE_RE = re.compile(
    r'[:=]\s*["\']?([A-Za-z0-9+/=_\-]{4,})["\']?\s*$',
    re.MULTILINE,
)
# Env-var references that are not real secrets: $VAR, ${VAR}, $(cmd)
_ENVVAR_REF_RE = re.compile(r'^\$(\{[^}]+\}|[A-Z_][A-Z0-9_]*|\([^)]+\))$')

# Placeholder / instruction values common in docs — high entropy but not real secrets.
# Matches the START of the extracted value so replace-with-your-huggingface-token fires.
_PLACEHOLDER_RE = re.compile(
    r'^('
    r'replace[-_]?with'     # replace-with-your-key, replace_with_token
    r'|your[-_]'            # your-api-key, your_token
    r'|<[^>]+'              # <your-token>, <INSERT_KEY> (no closing > needed — _CRED_VALUE_RE strips quotes)
    r'|YOUR_'               # YOUR_API_KEY
    r'|INSERT[-_]'          # INSERT_KEY_HERE
    r'|change[-_]?me'       # changeme, change-me
    r'|xxx+'                # xxx, xxxxxxxx
    r'|placeholder'         # placeholder-key
    r'|example[-_]'         # example-key, example_token
    r'|fake[-_]'            # fake-key
    r'|dummy[-_]'           # dummy-token
    r'|test[-_]key'         # test-key (not test_ broadly — would suppress test tokens)
    r'|sample[-_]'          # sample-key
    r'|add[-_]your'         # add-your-key
    r'|put[-_]your'         # put-your-key-here
    r'|enter[-_]'           # enter-key-here
    r'|fill[-_]in'          # fill-in-key
    r'|paste[-_]'           # paste-your-token
    r'|todo'                # todo, TODO
    r')',
    re.IGNORECASE,
)


def _credential_value_is_low_entropy(match_text: str, line_in_file: str) -> bool:
    """
    Return True (suppress) when the credential value in a pattern match is
    clearly not a real secret:
      - it is an env-var reference ($VAR / ${VAR})
      - it is absent (KEY: with nothing after it — value will come from env)
      - it matches a known placeholder/instruction pattern
      - its Shannon entropy is below _ENTROPY_GUARD_THRESHOLD
    """
    # Prefer the full line (includes everything after the colon/equals)
    # so docker-compose  HF_TOKEN: $MY_TOKEN  is handled correctly.
    candidate_line = line_in_file.strip() if line_in_file else match_text

    # Extract the value portion
    vm = _CRED_VALUE_RE.search(candidate_line)
    if not vm:
        # No value on this line (bare  KEY:  with nothing after) → env reference
        return True
    value = vm.group(1).strip()

    # Env-var reference → not a hardcoded secret
    if _ENVVAR_REF_RE.match(value):
        return True
    # Also catch bare $ prefix or %VAR% (Windows)
    if value.startswith("$") or (value.startswith("%") and value.endswith("%")):
        return True

    # Placeholder / instruction value — high entropy but clearly not a real secret
    if _PLACEHOLDER_RE.match(value):
        return True

    ent = shannon_entropy(value)
    return ent < _ENTROPY_GUARD_THRESHOLD


# ── C: Test path detection ────────────────────────────────────────
_TEST_PATH_RE = re.compile(
    r"(^|[\\/])(test[s]?|__tests__|spec[s]?|fixtures?|mocks?|fakes?|benchmarks?)"
    r"[\\/]|test_[^/\\]+\.py$|[^/\\]+\.spec\.(ts|js|tsx|jsx)$"
    r"|[^/\\]+\.test\.(ts|js|tsx|jsx)$"
    r"|[^/\\]+_test\.go$",
    re.IGNORECASE,
)

def _is_test_path(rel_path: str) -> bool:
    return bool(_TEST_PATH_RE.search(rel_path))


# ── Docs path detection ───────────────────────────────────────────
# Matches documentation files by extension or by living inside a docs dir.
_DOCS_EXTENSIONS = {".md", ".rst", ".txt", ".adoc", ".asciidoc", ".mdx"}
_DOCS_DIR_RE = re.compile(
    r"(^|[\\/])(docs?|documentation|wiki|guides?|how[-_]?to|tutorials?|examples?|readme"
    r"|proposals?|reference|openapi|api[-_]?spec|spec[-_]?files?"
    r"|observabilit[y]?|monitoring|dashboards?|grafana|metrics?"
    r"|manifests?|helm|charts?|kustomize|overlays?|bases?|deploy(?:ment)?s?"
    r"|infra(?:structure)?|k8s|kubernetes|gitops|argocd|flux)[\\/]",
    re.IGNORECASE,
)
# OpenAPI/AsyncAPI spec files — always docs context regardless of location
_OPENAPI_RE = re.compile(
    r"(openapi|asyncapi|swagger).*\.(ya?ml|json)$"
    r"|.*\.(openapi|asyncapi|swagger)\.(ya?ml|json)$",
    re.IGNORECASE,
)

def _is_docs_path(rel_path: str) -> bool:
    suffix = Path(rel_path).suffix.lower()
    if suffix in _DOCS_EXTENSIONS:
        return True
    if bool(_DOCS_DIR_RE.search(rel_path)):
        return True
    if bool(_OPENAPI_RE.search(rel_path)):
        return True
    return False


# ── B: Comment stripping ─────────────────────────────────────────
# Replaces comment content with same-length spaces to preserve line numbers.
_PY_DOCSTRING_RE  = re.compile(r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')', re.MULTILINE)
_PY_COMMENT_RE    = re.compile(r'(#[^\n]*)')
_C_BLOCK_CMT_RE   = re.compile(r'(/\*[\s\S]*?\*/)', re.MULTILINE)
_C_LINE_CMT_RE    = re.compile(r'(//[^\n]*)')
_HASH_COMMENT_RE  = re.compile(r'(#[^\n]*)')          # Ruby, Shell, TOML (reuse)
_SQL_LINE_CMT_RE  = re.compile(r'(--[^\n]*)')

# Language families
_PY_SUFFIXES      = {'.py', '.pyw'}
_JS_SUFFIXES      = {'.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.vue', '.svelte'}
_C_FAMILY_SUFFIXES = {'.java', '.go', '.cs', '.c', '.cpp', '.h', '.hpp',
                      '.rs', '.swift', '.kt', '.scala', '.groovy'}
_HASH_CMT_SUFFIXES = {'.rb', '.sh', '.bash', '.ps1', '.r', '.pl'}
_SQL_SUFFIXES      = {'.sql'}


def _blank_match(m: re.Match) -> str:
    """Replace matched text with same-length whitespace (preserves line numbers)."""
    text = m.group(0)
    # Keep newlines intact so line numbers stay correct; blank everything else
    return ''.join('\n' if c == '\n' else ' ' for c in text)


def _strip_comments(content: str, suffix: str) -> str:
    """
    Strip comments for all supported languages, preserving line numbers
    by replacing comment characters with spaces (newlines are kept).

    Supported:
      Python      (.py .pyw)          — docstrings + # comments
      JS/TS       (.js .ts .jsx …)    — // and /* */
      C-family    (.java .go .cs .c   — // and /* */
                   .cpp .h .rs .swift
                   .kt .scala .groovy)
      Ruby/Shell  (.rb .sh .bash .ps1 .r .pl)  — # comments
      SQL         (.sql)              — -- comments
    """
    if suffix in _PY_SUFFIXES:
        content = _PY_DOCSTRING_RE.sub(_blank_match, content)
        content = _PY_COMMENT_RE.sub(_blank_match, content)
    elif suffix in _JS_SUFFIXES or suffix in _C_FAMILY_SUFFIXES:
        content = _C_BLOCK_CMT_RE.sub(_blank_match, content)
        content = _C_LINE_CMT_RE.sub(_blank_match, content)
    elif suffix in _HASH_CMT_SUFFIXES:
        content = _HASH_COMMENT_RE.sub(_blank_match, content)
    elif suffix in _SQL_SUFFIXES:
        content = _SQL_LINE_CMT_RE.sub(_blank_match, content)
    return content


# ── Symbol tracker ────────────────────────────────────────────────
_SYMBOL_PATTERNS: List[Dict[str, Any]] = [
    {"re": re.compile(r"(\w+)\s*=\s*OpenAI\s*\(",          re.I), "provider": "openai"},
    {"re": re.compile(r"(\w+)\s*=\s*AsyncOpenAI\s*\(",     re.I), "provider": "openai"},
    {"re": re.compile(r"(\w+)\s*=\s*AzureOpenAI\s*\(",     re.I), "provider": "azure_openai"},
    {"re": re.compile(r"(\w+)\s*=\s*anthropic\.Anthropic\s*\(", re.I), "provider": "anthropic"},
    {"re": re.compile(r"(\w+)\s*=\s*Anthropic\s*\(",       re.I), "provider": "anthropic"},
    {"re": re.compile(r"(\w+)\s*=\s*cohere\.Client\s*\(",  re.I), "provider": "cohere"},
    {"re": re.compile(r"(\w+)\s*=\s*MistralClient\s*\(",   re.I), "provider": "mistral_ai"},
    {"re": re.compile(r"(\w+)\s*=\s*Groq\s*\(",            re.I), "provider": "groq"},
    {"re": re.compile(r"(\w+)\s*=\s*genai\.GenerativeModel\s*\(", re.I), "provider": "google_gemini_vertexai"},
    {"re": re.compile(r"(\w+)\s*=\s*ChatOpenAI\s*\(",      re.I), "provider": "openai"},
    {"re": re.compile(r"(\w+)\s*=\s*ChatAnthropic\s*\(",   re.I), "provider": "anthropic"},
    {"re": re.compile(r"(\w+)\s*=\s*litellm\b",            re.I), "provider": "litellm"},
    {"re": re.compile(r"(\w+)\s*=\s*Portkey\s*\(",         re.I), "provider": "portkey"},
    {"re": re.compile(r"(\w+)\s*=\s*new\s+OpenAI\s*\(",    re.I), "provider": "openai_js"},
    {"re": re.compile(r"(\w+)\s*=\s*new\s+Anthropic\s*\(", re.I), "provider": "anthropic_js"},
]

_CALL_RE = re.compile(
    r"(\w+)\.(chat\.completions\.create|completions\.create|messages\.create"
    r"|generate|invoke|predict|stream|agenerate|ainvoke|astream"
    r"|achat|agenerate_text|complete)\s*\(",
    re.I,
)

def _build_symbol_table(content: str) -> Dict[str, str]:
    table: Dict[str, str] = {}
    for sp in _SYMBOL_PATTERNS:
        for m in sp["re"].finditer(content):
            table[m.group(1)] = sp["provider"]
    return table


# ── Task 1: Multi-line exfiltration scanner ───────────────────────
# Window size: how many lines before/after the data-source expression
# we search for an LLM sink signal.
EXFIL_WINDOW_LINES = 12

# LLM sink signals — any of these in the window confirms data is
# flowing toward an LLM call.
_EXFIL_SINK_RE = re.compile(
    r"(\.chat\.completions\.|\.messages\.create|\.completions\.create"
    r"|ChatCompletion\.|litellm\.completion|anthropic\."
    r"|langchain|llm\.invoke|llm\.predict|llm\.generate"
    r"|\bprompt\s*[\+=]|\bmessages\s*[\+=\[]"
    r"|\bsystem_prompt\b|\buser_message\b"
    r"|\bHumanMessage\b|\bSystemMessage\b|\bAIMessage\b"
    r"|\bPromptTemplate\b|\bChatPromptTemplate\b"
    r"|\bprompt\s*=\s*f[\"']|\bmessages\s*=\s*\[)",
    re.IGNORECASE,
)

# Collect exfil pattern rules at module load time (after ALL_PATTERNS is built)
# — populated lazily in AIUsageDetector.__init__
_EXFIL_COMPILED: List[Dict[str, Any]] = []   # filled by _init_exfil_patterns()

def _init_exfil_patterns():
    """Compile the multi-line exfil rules once. Called from AIUsageDetector.__init__."""
    global _EXFIL_COMPILED
    if _EXFIL_COMPILED:
        return
    from scanner.patterns import ALL_PATTERNS, IMPORT_GUARDS
    for p in ALL_PATTERNS:
        if not p.get("exfil_multiline"):
            continue
        try:
            guard_src = (p.get("import_context")
                         or IMPORT_GUARDS.get(p.get("provider_or_lib", "")))
            _EXFIL_COMPILED.append({
                **p,
                "_re":    re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE),
                "_guard": re.compile(guard_src, re.IGNORECASE | re.MULTILINE)
                          if guard_src else None,
            })
        except re.error as e:
            print(f"[WARN] Bad exfil regex for {p.get('description','?')}: {e}")


def _scan_exfil_multiline(
    content: str,
    lines: List[str],
    rel_path: str,
    repo_name: str,
    is_test: bool,
) -> List[Dict[str, Any]]:
    """
    For each data-source match, check whether an LLM sink expression
    appears within EXFIL_WINDOW_LINES lines.  If so, emit a finding.

    This catches multi-line prompt construction patterns like:

        data = pd.read_csv("customers.csv")        # line 10
        summary = data.to_string()                 # line 11
        prompt = f"Analyse this data:\\n{summary}" # line 12
        response = client.chat.completions.create( # line 13
            messages=[{"role":"user","content":prompt}]
        )
    """
    findings: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    total_lines = len(lines)

    for rule in _EXFIL_COMPILED:
        guard = rule.get("_guard")
        if guard and not guard.search(content):
            continue

        for m in rule["_re"].finditer(content):
            source_line = content[:m.start()].count("\n")   # 0-based
            win_start   = max(0, source_line - 2)           # small look-behind
            win_end     = min(total_lines, source_line + EXFIL_WINDOW_LINES + 1)
            window_text = "\n".join(lines[win_start:win_end])
            line_text = lines[source_line] if source_line < total_lines else ""

            if _should_ignore_internal_match(
                rel_path,
                rule.get("provider_or_lib", ""),
                line_text,
                local_window=window_text,
            ):
                continue

            if not _EXFIL_SINK_RE.search(window_text):
                continue

            # Confirmed: data source + LLM sink in the same window
            sev_bump = 2 if is_test else 0
            base_sev = rule.get("base_severity", 2)
            sev      = max(1, min(4, base_sev + sev_bump))

            match_text = m.group(0)
            norm_match = re.sub(r'\s+', ' ', match_text.strip())[:120]
            uid = hashlib.md5(
                f"{repo_name}::{rel_path}::ml::{norm_match}".encode()
            ).hexdigest()
            if uid in seen:
                continue
            seen.add(uid)

            snippet = "\n".join(l[:200] for l in lines[win_start:win_end])
            findings.append({
                "repo":            repo_name,
                "category":        rule["category"],
                "provider_or_lib": rule["provider_or_lib"],
                "capability":      rule["capability"] + " (multi-line)",
                "severity":        sev,
                "file":            rel_path,
                "line":            source_line + 1,
                "snippet":         snippet,
                "match":           match_text[:300],
                "policy_status":   "CRITICAL" if rule["category"] == "Security" else "REVIEW",
                "is_notebook":     False,
                "description":     rule["description"],
                "confidence":      70,
                "context":         "test" if is_test else "production",
                "corroboration_count": 1,
                "_hash":           uid,
            })

    return findings


def _normalize_evidence_label(finding: Dict[str, Any]) -> str:
    label = str(finding.get("provider_or_lib", "") or "").strip()
    capability = str(finding.get("capability", "") or "").strip()
    if capability:
        return f"{label}: {capability}"
    return label or "signal"


def _normalize_rel_path(rel_path: str) -> str:
    return str(rel_path or "").replace("\\", "/").lstrip("./")


def _should_ignore_internal_match(
    rel_path: str,
    provider_or_lib: str,
    line_text: str,
    *,
    local_window: str = "",
) -> bool:
    normalized = _normalize_rel_path(rel_path)
    lib = str(provider_or_lib or "")
    line = str(line_text or "")
    window = str(local_window or "")

    if normalized in _SELF_SCAN_IGNORED_PATHS:
        return True

    if normalized in _SELF_SCAN_LOCAL_LLM_PLUMBING_PATHS and lib in {
        "ollama",
        "vllm",
        "direct_http_ai",
        "http_response_to_llm",
        "prompt_injection_risk",
        "tool_output_injection",
        "cross_context_injection",
    }:
        return True

    if normalized in _SELF_SCAN_ANALYSIS_INTERNAL_PATHS and lib in {
        "document_embedded_instruction",
        "file_content_to_llm",
    }:
        return True

    if normalized == "reports/html_report.py" and _REPORT_PROVIDER_MAP_RE.match(line):
        return True

    if lib == "shell_cmd_from_llm":
        if (
            (_FIXED_ARGV_SUBPROCESS_RE.match(line) or _FIXED_ARGV_SUBPROCESS_WINDOW_RE.search(window))
            and "shell=True" not in window
        ):
            return True

    if lib == "unsafe_code_exec":
        if "except" in line and "subprocess." in line:
            return True
        if (
            (_FIXED_ARGV_SUBPROCESS_RE.match(line) or _FIXED_ARGV_SUBPROCESS_WINDOW_RE.search(window))
            and "shell=True" not in window
        ):
            return True

    if lib == "sql_in_tool_description":
        if "?" in window and "execute(" in window and not _TOOL_MARKER_RE.search(window):
            return True

    if lib == "file_content_to_llm":
        if ".read_bytes(" in line and _LOCAL_FILE_HASH_RE.search(window):
            return True

    return False


# ── Task 12: Calibrated Confidence Scoring ───────────────────────
#
# Design rationale
# ────────────────
# The old scorer used a flat additive scale starting at 40 with uncapped
# bonuses.  The new scorer uses a sceptical Bayesian framing:
#
#   • Base probability: 35 — we assume ~35 % of raw regex matches are real.
#   • Each positive/negative signal adjusts the probability up or down using
#     a log-odds update, then the result is projected back to [5, 98].
#
# This means:
#   - Two strong independent signals (import + direct assignment) → ~75 %
#   - A full house (import + assignment + call site + corroboration) → ~93 %
#   - A test-file match with no import → ~12 %
#   - A deleted-file history finding starts at a 10-point handicap
#
# Signals and weights (positive or negative log-odds deltas):
_CONF_SIGNALS = {
    # ── Positive signals ─────────────────────────────────────────
    "import_guard":       +1.20,  # known import present in same file
    "direct_assignment":  +0.90,  # var = Provider(api_key=...)
    "call_site":          +0.70,  # var.method(...) confirmed call site
    "security_category":  +0.65,  # pattern is in the Security category
    "entropy_key":        +0.85,  # match looks like a real API key (entropy)
    "config_native":      +0.40,  # pattern is designed for config files
    "notebook":           +0.20,  # jupyter notebook (exploratory, but real)
    "corroboration_3":    +0.60,  # ≥3 distinct libs in same file
    "corroboration_5":    +0.90,  # ≥5 distinct libs in same file
    "long_match":         +0.30,  # match is ≥20 chars (more specific regex hit)
    # ── Negative signals ─────────────────────────────────────────
    "test_file":          -1.40,  # path matches test heuristic
    "history_deleted":    -0.40,  # finding comes from deleted-file history
    "very_short_match":   -0.40,  # match is ≤6 chars (likely noisy pattern)
    "docs_file":          -0.80,  # documentation file — likely an example, not live code
    "no_guard_needed":     0.00,  # neutral — guard not applicable for this rule
}

# Minimum match lengths
_LONG_MATCH_THRESHOLD  = 20
_SHORT_MATCH_THRESHOLD = 6

# High-entropy character classes that suggest a real API key value
_KEY_VALUE_RE = re.compile(
    r'(?:api[_-]?key|token|secret|password|passwd|credential)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9+/=\-_.]{16,})["\']?',
    re.IGNORECASE,
)

# Secret pattern slugs — always trigger security_category signal
_SECURITY_CATEGORIES = {"Security"}


def _log_odds(p: float) -> float:
    """Convert probability p ∈ (0,1) to log-odds."""
    p = max(0.001, min(0.999, p))
    import math
    return math.log(p / (1.0 - p))


def _from_log_odds(lo: float) -> float:
    """Convert log-odds back to probability ∈ (0,1)."""
    import math
    return 1.0 / (1.0 + math.exp(-lo))


def _score_confidence(
    match_text: str,
    content: str,
    rel_path: str,
    rule: Dict,
    is_test: bool,
    *,
    context: str = "production",
    corroboration_count: int = 1,
    call_site_confirmed: bool = False,
) -> int:
    """
    Compute a calibrated confidence score (0–100) using a log-odds signal
    accumulation model.  Higher = more likely to be a real finding.

    Parameters
    ----------
    match_text          : The raw regex match string.
    content             : Full file content (for secondary signal detection).
    rel_path            : Relative path of the file (for test-path heuristic).
    rule                : The pattern rule dict.
    is_test             : True if the file is in a test directory/file.
    context             : "production" | "test" | "deleted_file" | "docs"
    corroboration_count : Number of distinct libs found in the same file.
    call_site_confirmed : True if a symbol-tracker call-site was matched.
    """
    import math

    BASE_P = 0.35          # sceptical prior: 35 % of raw matches are real
    lo = _log_odds(BASE_P)

    lib = rule.get("provider_or_lib", "")
    cat = rule.get("category", "")

    # ── Positive signals ─────────────────────────────────────────
    # 1. Import guard confirmed in same file
    guard_src = IMPORT_GUARDS.get(lib) or rule.get("import_context")
    if guard_src and re.search(guard_src, content, re.I):
        lo += _CONF_SIGNALS["import_guard"]

    # 2. Direct assignment: var = Provider(api_key="...", ...)
    if re.search(
        r'(?:api[_-]?key|token|secret|password)\s*=\s*["\'][^"\']{8,}["\']',
        match_text + content[:500],
        re.IGNORECASE,
    ):
        lo += _CONF_SIGNALS["direct_assignment"]

    # 3. Call site (symbol tracker confirmed this is an actual invocation)
    if call_site_confirmed:
        lo += _CONF_SIGNALS["call_site"]

    # 4. Security / Secret category
    if cat in _SECURITY_CATEGORIES:
        lo += _CONF_SIGNALS["security_category"]

    # 5. Match looks like a real API key value (key-value pair with sufficient entropy)
    if _KEY_VALUE_RE.search(match_text):
        lo += _CONF_SIGNALS["entropy_key"]

    # 6. Config-native pattern in a config file
    suffix = Path(rel_path).suffix.lower()
    if suffix in _CONFIG_EXTENSIONS and lib in _CONFIG_LIBS:
        lo += _CONF_SIGNALS["config_native"]

    # 7. Notebook context
    if ".ipynb" in rel_path:
        lo += _CONF_SIGNALS["notebook"]

    # 8. Corroboration (multiple distinct libs in the same file)
    if corroboration_count >= 5:
        lo += _CONF_SIGNALS["corroboration_5"]
    elif corroboration_count >= 3:
        lo += _CONF_SIGNALS["corroboration_3"]

    # 9. Long match → pattern is more specific, less likely to be a coincidence
    if len(match_text) >= _LONG_MATCH_THRESHOLD:
        lo += _CONF_SIGNALS["long_match"]

    # ── Negative signals ─────────────────────────────────────────
    # 10. Test file — strong downgrade
    if is_test:
        lo += _CONF_SIGNALS["test_file"]

    # 11. Deleted-file history finding — already resolved, lower urgency
    if context == "deleted_file":
        lo += _CONF_SIGNALS["history_deleted"]

    # 12. Docs file — examples and tutorials, lower urgency
    if context == "docs":
        lo += _CONF_SIGNALS["docs_file"]

    # 13. Very short match — likely a noisy single-token regex hit
    if len(match_text) <= _SHORT_MATCH_THRESHOLD:
        lo += _CONF_SIGNALS["very_short_match"]

    # ── Project to [5, 98] ────────────────────────────────────────
    probability = _from_log_odds(lo)
    score = int(round(probability * 100))
    return max(5, min(98, score))


# ── Module-level compiled pattern cache ──────────────────────────
# ALL_PATTERNS is a module-level constant that never changes at runtime.
# Compiling 99 regexes on every AIUsageDetector() instantiation is wasteful
# when multiple detectors are created (e.g. tests). Cache the result once.
_COMPILED_PATTERNS_CACHE: List[Dict[str, Any]] = []

def _get_compiled_patterns() -> List[Dict[str, Any]]:
    """Return the module-level compiled pattern list, building it once."""
    global _COMPILED_PATTERNS_CACHE
    if _COMPILED_PATTERNS_CACHE:
        return _COMPILED_PATTERNS_CACHE
    compiled = []
    for p in ALL_PATTERNS:
        if p.get("exfil_multiline"):
            continue
        try:
            guard_src    = (p.get("import_context")
                            or IMPORT_GUARDS.get(p.get("provider_or_lib", "")))
            path_ctx_src = p.get("path_context")
            compiled.append({
                **p,
                "_re":       re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE),
                "_guard":    re.compile(guard_src, re.IGNORECASE | re.MULTILINE)
                             if guard_src else None,
                "_path_ctx": re.compile(path_ctx_src, re.IGNORECASE)
                             if path_ctx_src else None,
            })
        except re.error as e:
            print(f"[WARN] Bad regex for {p.get('description','?')}: {e}")
    _COMPILED_PATTERNS_CACHE = compiled
    return compiled


class AIUsageDetector:

    def __init__(self, allowlist: List[str] = None, denylist: List[str] = None,
                 verbose: bool = False):
        self.allowlist = [re.compile(p, re.IGNORECASE) for p in (allowlist or [])]
        self.denylist  = [re.compile(p, re.IGNORECASE) for p in (denylist or [])]
        self.verbose   = verbose

        # Initialise multi-line exfil patterns (Task 1)
        _init_exfil_patterns()

        # Use the module-level compiled pattern cache — avoids re-compiling
        # 99 regexes on every instantiation (matters in tests and multi-scan runs)
        self._compiled: List[Dict[str, Any]] = _get_compiled_patterns()

    # ── Public entry point ────────────────────────────────────────
    def scan(self, root: Path, repo_name: str = "",
             stop_event=None,
             return_file_contents: bool = False,
             on_file=None,
             include_paths: List[str] | None = None,
             exclude_paths: List[str] | None = None):
        """
        Scan root and return findings.

        If return_file_contents=True, returns (findings, file_contents) so
        callers (e.g. LLM reviewer) can pass source to the reviewer without
        re-reading the disk.

        on_file(rel_path, file_index, total_files): optional callback called
        for each file scanned — used to update UI progress.
        """
        all_findings: List[Dict[str, Any]] = []
        root = Path(root)

        # Task 11: load .aiignore suppression rules from the repo root
        ignore_rules = load_aiignore(root)

        # Collect per-file findings + raw content (needed for cross-file analysis)
        file_findings: Dict[str, List[Dict]] = {}
        file_contents: Dict[str, str]        = {}

        all_files = list(self._iter_files(root))
        include_set = None
        if include_paths:
            include_set = {
                str(Path(path)).replace("\\", "/").lstrip("./")
                for path in include_paths
                if str(path).strip()
            }
            all_files = [
                fpath for fpath in all_files
                if str(fpath.relative_to(root)).replace("\\", "/") in include_set
            ]
        exclude_set = None
        if exclude_paths:
            exclude_set = {
                str(Path(path)).replace("\\", "/").strip("/").lstrip("./")
                for path in exclude_paths
                if str(path).strip()
            }
            filtered_files = []
            for fpath in all_files:
                rel = str(fpath.relative_to(root)).replace("\\", "/")
                if any(rel == prefix or rel.startswith(prefix + "/") for prefix in exclude_set):
                    continue
                filtered_files.append(fpath)
            all_files = filtered_files
        total_files = len(all_files)

        for file_index, fpath in enumerate(all_files):
            rel = str(fpath.relative_to(root))
            if stop_event and stop_event.is_set():
                break
            # Task 11: skip files covered by .aiignore before scanning
            if ignore_rules and is_suppressed(ignore_rules, rel):
                if self.verbose:
                    print(f"  [IGNORED] {rel}")
                continue
            if on_file:
                try:
                    on_file(rel, file_index, total_files)
                except Exception:
                    pass
            ff = self._scan_file(fpath, rel, repo_name)
            if ff:
                file_findings[rel] = ff
            all_findings.extend(ff)
            # Store raw content for cross-file analysis (code files only, ≤200 KB)
            suffix = fpath.suffix.lower()
            if suffix in _CODE_EXTENSIONS and fpath.stat().st_size < 200_000:
                try:
                    file_contents[rel] = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass

        # D: Corroboration boost
        self._apply_corroboration(file_findings)

        # Task 5: Cross-file analysis
        if file_contents:
            from scanner.cross_file import CrossFileAnalyzer
            xfa = CrossFileAnalyzer(repo_name=repo_name, verbose=self.verbose)
            xf_findings = xfa.analyze(file_contents)
            # Task 11: also suppress cross-file findings whose file path is ignored
            if ignore_rules:
                xf_findings = [
                    f for f in xf_findings
                    if not is_suppressed(ignore_rules, f.get("file", ""))
                ]
            all_findings.extend(xf_findings)

        # Task 11: final pass — suppress any findings whose file paths are covered
        if ignore_rules:
            all_findings = [
                f for f in all_findings
                if not is_suppressed(ignore_rules, f.get("file", ""))
            ]

        if return_file_contents:
            return all_findings, file_contents
        return all_findings

    # ── Public helper used by history scanner (Task 4) ───────────
    def _scan_text_file_from_content(
        self,
        content: str,
        suffix: str,
        rel_path: str,
        repo_name: str,
        *,
        ctx_str: str = "deleted_file",
        sev_bump: int = 0,
        is_test: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Scan an in-memory string as if it were a file with the given suffix
        and path.

        Used by two callers:
          - git history scanner: ctx_str="deleted_file" (default)
          - _scan_text_file:     passes computed ctx_str / sev_bump / is_test
            so docs/test context is handled identically in both paths.

        This is the single canonical implementation of the pattern-matching
        loop — _scan_text_file delegates here after reading the file from disk.
        """
        from pathlib import PurePosixPath
        name      = PurePosixPath(rel_path).name
        is_config = (suffix in _CONFIG_EXTENSIONS or name in _CONFIG_EXTENSIONS)
        is_code   = suffix in _CODE_EXTENSIONS

        stripped  = _strip_comments(content, suffix) if is_code else content
        lines     = content.splitlines()
        sym_table = _build_symbol_table(stripped) if is_code else {}

        findings: List[Dict[str, Any]] = []

        for rule in self._compiled:
            lib = rule.get("provider_or_lib", "")
            if lib in _CONFIG_LIBS and is_code:
                continue
            if lib not in _CONFIG_LIBS and is_config:
                continue
            guard = rule.get("_guard")
            if guard and not guard.search(stripped):
                continue
            # path_context: only fire if file path matches expected directory/name pattern
            path_ctx_re = rule.get("_path_ctx")
            if path_ctx_re and not path_ctx_re.search(rel_path.replace("\\", "/")):
                continue
            for m in rule["_re"].finditer(stripped):
                line_no    = stripped[:m.start()].count("\n") + 1
                match_text = m.group(0)
                raw_line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
                win_start = max(0, line_no - 8)
                win_end = min(len(lines), line_no + 4)
                local_window = "\n".join(lines[win_start:win_end])

                if _should_ignore_internal_match(
                    rel_path,
                    lib,
                    raw_line,
                    local_window=local_window,
                ):
                    continue

                # Entropy guard
                if rule.get("entropy_guard"):
                    if _credential_value_is_low_entropy(match_text, raw_line):
                        continue

                conf = _score_confidence(
                    match_text, content, rel_path, rule, is_test,
                    context=ctx_str,
                )
                f = self._make_finding(
                    rule=rule, repo_name=repo_name, file=rel_path,
                    line=line_no, snippet=self._get_snippet(lines, line_no - 1),
                    match=match_text,
                    policy_status=self._check_policy(match_text, rule),
                    is_notebook=False, severity_bump=sev_bump,
                )
                f["confidence"]          = conf
                f["context"]             = ctx_str
                f["corroboration_count"] = 1
                findings.append(f)

        if sym_table:
            for sf in self._track_symbol_calls(stripped, lines, rel_path, repo_name, sym_table):
                sf["confidence"] = _score_confidence(
                    sf["match"], content, rel_path, {}, is_test,
                    context=ctx_str,
                    call_site_confirmed=True,
                )
                sf["context"]             = ctx_str
                sf["corroboration_count"] = 1
                findings.append(sf)

        from scanner.entropy import scan_entropy_secrets
        if is_code or is_config:
            for ef in scan_entropy_secrets(content, lines, rel_path, repo_name):
                ef["confidence"]          = 75
                ef["context"]             = ctx_str
                ef["corroboration_count"] = 1
                findings.append(ef)

        if is_code:
            findings.extend(
                _scan_exfil_multiline(stripped, lines, rel_path, repo_name, is_test)
            )

        findings.extend(
            self._correlate_secret_to_ai_usage(
                findings=findings,
                content=content,
                rel_path=rel_path,
                repo_name=repo_name,
                context=ctx_str,
                is_test=is_test,
            )
        )

        return self._dedupe(findings)

    # ── D: Corroboration boost ────────────────────────────────────
    def _apply_corroboration(self, file_findings: Dict[str, List[Dict]]):
        """
        Task 12: Re-score confidence for files with 3+ distinct libs using
        the calibrated scorer's corroboration_count parameter, rather than
        additive arithmetic, so the result stays within the log-odds model.
        """
        for rel, findings in file_findings.items():
            distinct_libs = len({f.get("provider_or_lib","") for f in findings})
            if distinct_libs >= 3:
                for f in findings:
                    # Re-score in place with updated corroboration count
                    new_conf = _score_confidence(
                        f.get("match", ""),
                        "",         # content not available here; other signals already baked in
                        rel,
                        {},         # rule not available here; use context from finding
                        f.get("context", "production") == "test",
                        context=f.get("context", "production"),
                        corroboration_count=distinct_libs,
                    )
                    # Only boost, never reduce — corroboration is always positive evidence
                    f["confidence"]          = max(f.get("confidence", 35), new_conf)
                    f["corroboration_count"] = distinct_libs

    # ── File walker ───────────────────────────────────────────────
    def _correlate_secret_to_ai_usage(
        self,
        *,
        findings: List[Dict[str, Any]],
        content: str,
        rel_path: str,
        repo_name: str,
        context: str,
        is_test: bool,
    ) -> List[Dict[str, Any]]:
        secrets = [f for f in findings if str(f.get("provider_or_lib", "")) in _SECRET_FINDING_LIBS]
        ai_usage = [
            f for f in findings
            if (
                str(f.get("category", "")) in _AI_USAGE_CATEGORIES
                or (bool(f.get("_symbol_tracked")) and str(f.get("category", "")) == "External AI API")
            )
        ]
        if not secrets or not ai_usage:
            return []
        prompt_flow = _PROMPT_FLOW_RE.search(content or "")
        if not prompt_flow:
            return []

        evidence = secrets[:2] + ai_usage[:2]
        evidence_labels = [_normalize_evidence_label(item) for item in evidence]
        ai_libs = sorted({
            str(f.get("provider_or_lib", "") or "").strip()
            for f in ai_usage
            if f.get("provider_or_lib")
        })
        line_candidates = [
            int(f.get("line", 0) or 0)
            for f in evidence
            if int(f.get("line", 0) or 0) > 0
        ]
        line_no = min(line_candidates) if line_candidates else 1
        severity = 2 if context in {"docs", "test", "deleted_file"} or is_test else 1
        policy_status = "REVIEW" if severity > 1 else "CRITICAL"
        snippet = self._get_snippet((content or "").splitlines(), max(line_no - 1, 0))
        match_text = " | ".join(evidence_labels)[:300]
        provider_text = ", ".join(ai_libs) if ai_libs else "AI provider"
        prompt_signal = prompt_flow.group(0)
        uid = hashlib.md5(
            f"{repo_name}::{rel_path}::secret-ai-correlation::{provider_text}::{prompt_signal}".encode()
        ).hexdigest()
        return [{
            "repo": repo_name,
            "category": "Security",
            "provider_or_lib": "secret_ai_correlation",
            "capability": "Secret + AI Request Correlation",
            "severity": severity,
            "file": rel_path,
            "line": line_no,
            "snippet": snippet,
            "match": match_text,
            "policy_status": policy_status,
            "is_notebook": False,
            "description": (
                f"A committed secret appears in the same file as live AI usage ({provider_text}) "
                f"and prompt/input/output handling ('{prompt_signal}'). This combination is a much "
                "stronger indicator of an active credential exposure path than isolated pattern hits."
            ),
            "confidence": 95 if severity == 1 else 88,
            "context": context,
            "corroboration_count": len({
                item.get("provider_or_lib", "")
                for item in evidence
                if item.get("provider_or_lib")
            }),
            "correlated_evidence": evidence_labels,
            "why_flagged": [
                "secret-like credential detected in the file",
                f"live AI integration detected ({provider_text})",
                f"prompt/data handling signal detected ('{prompt_signal}')",
            ],
            "_hash": uid,
        }]

    def _iter_files(self, root: Path):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            parts = set(path.parts)
            if parts & SKIP_DIRS:
                continue
            if any(d in str(path) for d in SKIP_DIRS):
                continue
            if path.name in SKIP_FILES:
                continue
            suffix = path.suffix.lower()
            name   = path.name
            if name in SCAN_EXTENSIONS or suffix in SCAN_EXTENSIONS:
                yield path

    # ── File dispatcher ───────────────────────────────────────────
    def _scan_file(self, fpath: Path, rel_path: str,
                   repo_name: str) -> List[Dict[str, Any]]:
        try:
            if fpath.suffix == ".ipynb":
                return self._scan_notebook(fpath, rel_path, repo_name)
            # Task 6: minified JS gets its own fast scanner
            if self._is_minified(fpath):
                return self._scan_minified(fpath, rel_path, repo_name)
            return self._scan_text_file(fpath, rel_path, repo_name)
        except (UnicodeDecodeError, PermissionError, OSError) as e:
            if self.verbose:
                print(f"  [SKIP] {rel_path}: {e}")
            return []

    # ── Task 6: Minified file detection ──────────────────────────
    @staticmethod
    def _is_minified(fpath: Path) -> bool:
        """
        A file is considered minified if:
          - its name ends with .min.js / .min.ts, OR
          - its first non-empty line is longer than 1000 characters (typical
            bundle line), OR
          - average line length across the first 5 lines > 500 chars.
        """
        name = fpath.name.lower()
        if name.endswith(".min.js") or name.endswith(".min.ts"):
            return True
        try:
            with fpath.open(encoding="utf-8", errors="replace") as f:
                sample = []
                for _ in range(5):
                    line = f.readline()
                    if not line:
                        break
                    sample.append(len(line))
            if sample:
                if max(sample) > 1000:
                    return True
                if sum(sample) / len(sample) > 500:
                    return True
        except OSError:
            pass
        return False

    # ── Task 6: Minified file scanner ────────────────────────────
    # High-signal-only patterns applied on sliding 600-char windows
    _MINIFIED_KEY_RE = re.compile(
        r'(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9\-_]{30,}'
        r'|AIza[A-Za-z0-9\-_]{35}'           # Google AI key
        r'|Bearer\s+[A-Za-z0-9\-_.]{20,}'    # Bearer token
        r'|api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9\-_.]{16,}["\']'
        r'|openai\.com/v1|api\.anthropic\.com'
        r'|api\.cohere\.ai|api\.mistral\.ai'
        r'|generativelanguage\.googleapis\.com)',
        re.IGNORECASE,
    )

    def _scan_minified(self, fpath: Path, rel_path: str,
                       repo_name: str) -> List[Dict[str, Any]]:
        """
        Scan a minified/bundled JS file using a sliding-window approach.
        Only high-confidence patterns (hardcoded keys, AI API hostnames) are
        applied — we avoid the full rule set to prevent noise from minified
        variable names that happen to collide with our patterns.
        """
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        is_test = _is_test_path(rel_path)

        for m in self._MINIFIED_KEY_RE.finditer(content):
            match_text = m.group(0)
            # Approximate line number (count \n before match start)
            line_no = content[:m.start()].count("\n") + 1
            # Context window: 150 chars either side
            ctx_start = max(0, m.start() - 150)
            ctx_end   = min(len(content), m.end() + 150)
            snippet   = content[ctx_start:ctx_end]

            norm = re.sub(r'\s+', ' ', match_text.strip())[:120]
            uid  = hashlib.md5(
                f"{repo_name}::{rel_path}::minified::{norm}".encode()
            ).hexdigest()
            if uid in seen:
                continue
            seen.add(uid)

            sev = 1 if re.search(r'sk-|sk-ant-|Bearer\s', match_text, re.I) else 2
            if is_test:
                sev = min(4, sev + 2)

            findings.append({
                "repo":            repo_name,
                "category":        "Security",
                "provider_or_lib": "minified_bundle_secret",
                "capability":      "Hardcoded Key / AI Endpoint in Bundle",
                "severity":        sev,
                "file":            rel_path,
                "line":            line_no,
                "snippet":         snippet[:400],
                "match":           match_text[:300],
                "policy_status":   "CRITICAL",
                "is_notebook":     False,
                "confidence":      80,
                "context":         "test" if is_test else "production",
                "corroboration_count": 1,
                "description": (
                    "A hardcoded API key or AI service endpoint was found inside a "
                    "minified/bundled JavaScript file — bundled secrets are exposed "
                    "to all users of the application. Rotate the key immediately and "
                    "move it to a server-side environment variable."
                ),
                "_hash": uid,
            })

        return findings

    # ── Text file scanner ─────────────────────────────────────────
    def _scan_text_file(self, fpath: Path, rel_path: str,
                        repo_name: str) -> List[Dict[str, Any]]:
        """
        Read a file from disk and scan it.

        Derives context (production / test / docs) and severity bump from
        the file path, then delegates to _scan_text_file_from_content which
        is the single canonical implementation of the pattern-matching loop.
        """
        raw_content = fpath.read_text(encoding="utf-8", errors="replace")
        suffix      = fpath.suffix.lower()
        is_test     = _is_test_path(rel_path)
        is_docs     = _is_docs_path(rel_path)

        if is_test:
            ctx_str  = "test"
            sev_bump = 2
        elif is_docs:
            ctx_str  = "docs"
            sev_bump = 2
        else:
            ctx_str  = "production"
            sev_bump = 0

        return self._scan_text_file_from_content(
            raw_content, suffix, rel_path, repo_name,
            ctx_str=ctx_str, sev_bump=sev_bump, is_test=is_test,
        )

    # ── Symbol call tracker ───────────────────────────────────────
    def _track_symbol_calls(self, content: str, lines: List[str],
                             rel_path: str, repo_name: str,
                             sym_table: Dict[str, str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for m in _CALL_RE.finditer(content):
            var      = m.group(1)
            method   = m.group(2)
            provider = sym_table.get(var)
            if not provider:
                continue
            line_no = content[:m.start()].count("\n") + 1
            norm_call = re.sub(r'\s+', ' ', m.group(0).strip())[:80]
            uid = hashlib.md5(
                f"{repo_name}::{rel_path}::sym::{provider}::{norm_call}".encode()
            ).hexdigest()
            findings.append({
                "repo":            repo_name,
                "category":        "External AI API",
                "provider_or_lib": provider,
                "capability":      f"LLM Call via '{var}.{method}()'",
                "severity":        2,
                "file":            rel_path,
                "line":            line_no,
                "snippet":         self._get_snippet(lines, line_no - 1),
                "match":           m.group(0)[:300],
                "policy_status":   "REVIEW",
                "is_notebook":     False,
                "description": (
                    f"AI client '{var}' ({provider}) calls '{method}()' — "
                    f"confirm this call is intentional, input is sanitised, "
                    f"and the provider is approved."
                ),
                "_hash":           uid,
                "_symbol_tracked": True,
            })
        return findings

    # ── Notebook scanner ──────────────────────────────────────────
    def _scan_notebook(self, fpath: Path, rel_path: str,
                       repo_name: str) -> List[Dict[str, Any]]:
        try:
            nb = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []

        findings: List[Dict[str, Any]] = []
        is_test = _is_test_path(rel_path)   # C

        full_source = "\n".join(
            ("".join(c.get("source", [])) if isinstance(c.get("source"), list)
             else c.get("source", ""))
            for c in nb.get("cells", [])
            if c.get("cell_type") in ("code", "raw")
        )

        cell_idx = 0
        for cell in nb.get("cells", []):
            cell_idx += 1
            if cell.get("cell_type") not in ("code", "raw"):
                continue
            source = cell.get("source", "")
            if isinstance(source, list):
                source = "".join(source)
            if not source.strip():
                continue

            lines     = source.splitlines()
            sym_table = _build_symbol_table(source)
            cell_ref  = f"{rel_path}::cell[{cell_idx}]"
            stripped  = _strip_comments(source, ".py")

            for rule in self._compiled:
                lib = rule.get("provider_or_lib", "")
                if lib in _CONFIG_LIBS:
                    continue
                guard = rule.get("_guard")
                if guard and not guard.search(full_source):
                    continue
                for m in rule["_re"].finditer(stripped):
                    line_no    = stripped[:m.start()].count("\n") + 1
                    match_text = m.group(0)
                    extra_sev  = 1 if rule["category"] == "Security" else 0
                    sev_bump   = extra_sev + (2 if is_test else 0)
                    conf = _score_confidence(match_text, source, cell_ref, rule, is_test)
                    f = self._make_finding(
                        rule=rule, repo_name=repo_name, file=cell_ref,
                        line=line_no,
                        snippet=self._get_snippet(lines, line_no - 1),
                        match=match_text,
                        policy_status=self._check_policy(match_text, rule),
                        is_notebook=True,
                        severity_bump=sev_bump,
                    )
                    f["confidence"]          = conf
                    f["context"]             = "test" if is_test else "production"
                    f["corroboration_count"] = 1
                    findings.append(f)

            if sym_table:
                for sf in self._track_symbol_calls(stripped, lines, cell_ref, repo_name, sym_table):
                    sf["confidence"]          = 55
                    sf["context"]             = "test" if is_test else "production"
                    sf["corroboration_count"] = 1
                    findings.append(sf)

            # E: entropy in notebook cells
            for ef in scan_entropy_secrets(source, lines, cell_ref, repo_name):
                ef["is_notebook"]         = True
                ef["severity"]            = 1
                ef["confidence"]          = 80
                ef["context"]             = "test" if is_test else "production"
                ef["corroboration_count"] = 1
                findings.append(ef)

        # Scan cell outputs for accidentally printed secrets.
        # Uses word-boundary keyword matching to avoid firing on common LLM
        # benchmark/metric fields like input_tokens, tokens_per_second, etc.
        _OUTPUT_SECRET_RE = re.compile(
            r'\b(api[_\-]?key|auth[_\-]?token|access[_\-]?token'
            r'|bearer[_\-]?token|secret[_\-]?key|private[_\-]?key'
            r'|sk-[A-Za-z0-9]{10,}|sk-ant-[A-Za-z0-9\-_]{10,}'
            r'|Authorization\s*[=:]'
            r'|password\s*[=:]|passwd\s*[=:]'
            r'|api[_\-]?secret\s*[=:])\b',
            re.IGNORECASE,
        )
        for cell in nb.get("cells", []):
            for output in cell.get("outputs", []):
                raw      = output.get("text", [])
                out_text = "".join(raw) if isinstance(raw, list) else str(raw)
                if not _OUTPUT_SECRET_RE.search(out_text):
                    continue
                uid = hashlib.md5(
                    f"{repo_name}::{rel_path}::output::{out_text[:100]}".encode()
                ).hexdigest()
                findings.append({
                    "repo":              repo_name,
                    "category":          "Security",
                    "provider_or_lib":   "notebook_output_secret",
                    "capability":        "Secret in Notebook Output",
                    "base_severity":     1,
                    "severity":          1,
                    "file":              rel_path,
                    "line":              0,
                    "snippet":           out_text[:200],
                    "policy_status":     "CRITICAL",
                    "is_notebook":       True,
                    "confidence":        90,
                    "context":           "production",
                    "corroboration_count": 1,
                    "description": (
                        "Possible secret found in notebook cell output — "
                        "clear all outputs with nbstripout before committing "
                        "and rotate any exposed credentials immediately."
                    ),
                    "_hash": uid,
                })

        return self._dedupe(findings)

    # ── Helpers ───────────────────────────────────────────────────
    def _get_snippet(self, lines: List[str], line_idx: int,
                     context: int = 2) -> str:
        start = max(0, line_idx - context)
        end   = min(len(lines), line_idx + context + 1)
        return "\n".join(l[:200] for l in lines[start:end])

    def _check_policy(self, match_text: str, rule: Dict) -> str:
        for pattern in self.denylist:
            if pattern.search(match_text):
                return "DENIED"
        for pattern in self.allowlist:
            if pattern.search(match_text):
                return "ALLOWED"
        if rule["category"] == "Security":
            return "CRITICAL"
        return "REVIEW"

    def _make_finding(self, rule: Dict, repo_name: str, file: str,
                      line: int, snippet: str, match: str,
                      policy_status: str, is_notebook: bool,
                      severity_bump: int = 0) -> Dict[str, Any]:
        base = rule.get("base_severity", 4)
        sev  = max(1, min(4, base + severity_bump))

        # Task 3: Content-stable identity — survives line-number changes from refactoring.
        # Hash on: repo + file + provider + normalised match text (whitespace collapsed).
        # Line number is intentionally excluded so that moving code doesn't mark a
        # finding as "new" in the delta report.
        norm_match = re.sub(r'\s+', ' ', match.strip())[:120]
        uid = hashlib.md5(
            f"{repo_name}::{file}::{norm_match}".encode()
        ).hexdigest()

        return {
            "repo":            repo_name,
            "category":        rule["category"],
            "provider_or_lib": rule["provider_or_lib"],
            "capability":      rule["capability"],
            "severity":        sev,
            "file":            file,
            "line":            line,
            "snippet":         snippet,
            "match":           match[:300],
            "policy_status":   policy_status,
            "is_notebook":     is_notebook,
            "description":     rule["description"],
            "_hash":           uid,
        }

    def _dedupe(self, findings: List[Dict]) -> List[Dict]:
        seen:   Set[str]   = set()
        result: List[Dict] = []
        for f in findings:
            h = f["_hash"]
            if h not in seen:
                seen.add(h)
                result.append(f)
        return result
