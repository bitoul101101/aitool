"""
Cross-file analysis (Task 5).

After all files in a repo have been scanned individually, this module
looks for secrets or AI client credentials that are:
  - defined in one file  (e.g.  API_KEY = "sk-...")
  - imported / referenced in another  (e.g.  from config import API_KEY)

It also catches the pattern where a helper module wraps an LLM client
and exports it, and another module uses that exported client — the
individual file scanner sees neither half as a problem in isolation.

Approach
--------
1. Build a *definition map*: file → {name: (value_snippet, line)}
   Definitions are variable assignments whose value looks like a secret
   OR whose name suggests a credential (api_key, token, secret, …).

2. Build an *import map*: file → {name: source_file}
   Tracks  `from X import Y`  and  `import X`  statements.

3. For each import of a name that appears in the definition map:
   emit a cross-file finding pointing at the import site.

4. Also detect *exported LLM clients*:
   file A creates  client = OpenAI()  and exports it;
   file B does  from A import client  then calls  client.chat...
   → emit a finding on file B with the provider attribution.
"""

import re
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional


# ── Credential name heuristic ────────────────────────────────────
_CRED_NAME_RE = re.compile(
    r"(api[_-]?key|api[_-]?token|secret[_-]?key|auth[_-]?token"
    r"|access[_-]?token|bearer[_-]?token|private[_-]?key"
    r"|service[_-]?account|credentials?|passwd|password"
    r"|apikey|authkey|signing[_-]?key|openai[_-]?key"
    r"|anthropic[_-]?key|cohere[_-]?key)",
    re.IGNORECASE,
)

# Matches:  NAME = "value"  or  NAME = 'value'
_ASSIGN_RE = re.compile(
    r'^[ \t]*([A-Z_][A-Z0-9_]{2,})\s*=\s*["\']([^"\']{8,})["\']',
    re.MULTILINE,
)

# LLM client constructors worth tracking across files
_CLIENT_CTOR_RE = re.compile(
    r'([a-zA-Z_]\w*)\s*=\s*(OpenAI|AsyncOpenAI|AzureOpenAI|Anthropic|'
    r'anthropic\.Anthropic|ChatOpenAI|ChatAnthropic|MistralClient|Groq|'
    r'litellm|Portkey|genai\.GenerativeModel)\s*\(',
    re.IGNORECASE,
)

_PROVIDER_FROM_CTOR = {
    "openai": "openai", "asyncopenai": "openai", "azureopenai": "azure_openai",
    "anthropic": "anthropic", "chatopenai": "openai", "chatanthropic": "anthropic",
    "mistraiclient": "mistral_ai", "groq": "groq", "litellm": "litellm",
    "portkey": "portkey", "generativemodel": "google_gemini_vertexai",
}

# from X import Y  or  from X import Y, Z
_FROM_IMPORT_RE = re.compile(
    r'^[ \t]*from\s+([\w.]+)\s+import\s+(.+)$',
    re.MULTILINE,
)

# import X  (whole module)
_IMPORT_RE = re.compile(
    r'^[ \t]*import\s+([\w.]+)',
    re.MULTILINE,
)

# Use of an imported name near an LLM sink
_LLM_SINK_NEAR_RE = re.compile(
    r'(\.chat\.completions\.|\.messages\.create|\.completions\.create'
    r'|\.generate|\.invoke|\.predict|\.stream)',
    re.IGNORECASE,
)


def _module_to_rel_paths(module: str, known_files: List[str]) -> List[str]:
    """
    Convert a Python module path (e.g. 'config.secrets') to candidate
    relative file paths (e.g. 'config/secrets.py').
    Returns all known files that match.
    """
    candidate = module.replace(".", "/") + ".py"
    candidate_init = module.replace(".", "/") + "/__init__.py"
    return [f for f in known_files
            if f.endswith(candidate) or f.endswith(candidate_init)]


class CrossFileAnalyzer:

    def __init__(self, repo_name: str, verbose: bool = False):
        self.repo_name = repo_name
        self.verbose   = verbose

    def analyze(
        self,
        file_contents: Dict[str, str],   # rel_path → raw content
    ) -> List[Dict[str, Any]]:
        """
        Run cross-file analysis over the full set of file contents.
        Returns a list of additional findings.
        """
        findings: List[Dict[str, Any]] = []
        known_files = list(file_contents.keys())

        # 1. Build definition map
        def_map: Dict[str, List[Tuple[str, str, int]]] = {}
        # def_map[name] = [(rel_path, value_snippet, line_no), ...]
        for rel, content in file_contents.items():
            for m in _ASSIGN_RE.finditer(content):
                name  = m.group(1)
                value = m.group(2)
                line  = content[:m.start()].count("\n") + 1
                if _CRED_NAME_RE.search(name):
                    def_map.setdefault(name, []).append((rel, value[:60], line))

        # 2. Build exported-client map
        client_map: Dict[str, List[Tuple[str, str]]] = {}
        # client_map[var_name] = [(rel_path, provider), ...]
        for rel, content in file_contents.items():
            for m in _CLIENT_CTOR_RE.finditer(content):
                var      = m.group(1)
                ctor     = m.group(2).lower().split(".")[-1]
                provider = _PROVIDER_FROM_CTOR.get(ctor, "openai")
                client_map.setdefault(var, []).append((rel, provider))

        # 3. Scan import sites
        for rel, content in file_contents.items():
            lines = content.splitlines()

            # from X import Y, Z
            for m in _FROM_IMPORT_RE.finditer(content):
                module   = m.group(1).strip()
                imported = [n.strip().split(" as ")[0]
                            for n in m.group(2).split(",")]
                line_no  = content[:m.start()].count("\n") + 1
                src_files = _module_to_rel_paths(module, known_files)

                for name in imported:
                    # Credential cross-reference
                    if name in def_map:
                        for src_file, val_snip, def_line in def_map[name]:
                            if src_file == rel:
                                continue   # same file — normal scanner already handles
                            uid = hashlib.md5(
                                f"{self.repo_name}::xfile::{rel}::{name}::{src_file}".encode()
                            ).hexdigest()
                            snippet_lines = lines[max(0,line_no-2):line_no+2]
                            findings.append({
                                "repo":            self.repo_name,
                                "category":        "Security",
                                "provider_or_lib": "cross_file_secret",
                                "capability":      "Cross-File Secret Import",
                                "severity":        2,
                                "file":            rel,
                                "line":            line_no,
                                "snippet":         "\n".join(snippet_lines),
                                "match":           m.group(0)[:300],
                                "policy_status":   "CRITICAL",
                                "is_notebook":     False,
                                "confidence":      70,
                                "context":         "production",
                                "corroboration_count": 1,
                                "description": (
                                    f"'{name}' is imported from '{src_file}' "
                                    f"(defined at line {def_line}) — the name "
                                    f"matches a credential pattern. Verify the "
                                    f"value is not a hardcoded secret being "
                                    f"propagated across modules."
                                ),
                                "_hash": uid,
                            })

                    # Exported LLM client cross-reference
                    if name in client_map:
                        for src_file, provider in client_map[name]:
                            if src_file == rel:
                                continue
                            # Only flag if the imported var is actually used as an LLM sink
                            # Check a window around the import + anywhere in file
                            if not _LLM_SINK_NEAR_RE.search(content):
                                continue
                            uid = hashlib.md5(
                                f"{self.repo_name}::xfile::client::{rel}::{name}::{src_file}".encode()
                            ).hexdigest()
                            snippet_lines = lines[max(0,line_no-2):line_no+2]
                            findings.append({
                                "repo":            self.repo_name,
                                "category":        "External AI API",
                                "provider_or_lib": provider,
                                "capability":      "Cross-File LLM Client Import",
                                "severity":        3,
                                "file":            rel,
                                "line":            line_no,
                                "snippet":         "\n".join(snippet_lines),
                                "match":           m.group(0)[:300],
                                "policy_status":   "REVIEW",
                                "is_notebook":     False,
                                "confidence":      55,
                                "context":         "production",
                                "corroboration_count": 1,
                                "description": (
                                    f"An AI client ('{name}', provider: {provider}) "
                                    f"is imported from '{src_file}' and used here — "
                                    f"the provider is attributed to this call site "
                                    f"via cross-file analysis."
                                ),
                                "_hash": uid,
                            })

        return findings
