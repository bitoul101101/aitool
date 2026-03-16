"""
Entropy-based secret detection (Enhancement E).

Uses Shannon entropy to flag high-entropy string literals that are likely
credentials, even when they have no recognisable prefix (e.g. Replicate,
HuggingFace inference tokens, custom gateway keys).

Threshold: entropy >= 4.5 bits/char on strings of 20-120 chars that
appear next to a suspicious variable name (api_key, token, secret, auth…).
"""

import re
import math
import hashlib
from typing import List, Dict, Any

# Variable names that suggest a nearby string is a credential
_SUSPECT_VAR_RE = re.compile(
    r"(api[_-]?key|api[_-]?token|secret[_-]?key|auth[_-]?token|access[_-]?token"
    r"|bearer[_-]?token|private[_-]?key|service[_-]?account|credentials?"
    r"|passwd|password|apikey|authkey|signing[_-]?key)\s*[:=]",
    re.IGNORECASE,
)

# Strings that look like high-entropy literals (quoted, 20-120 chars)
_STRING_RE = re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,120})["\']')

# Known-safe values to suppress
_SAFE_VALUES = {
    "none", "null", "true", "false", "undefined",
    "your_api_key_here", "your-api-key", "placeholder",
    "changeme", "todo", "fixme", "example", "test",
}

ENTROPY_THRESHOLD = 4.5   # bits per character
WINDOW_CHARS      = 200   # chars before/after the string to check for var name


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def scan_entropy_secrets(
    content: str,
    lines: List[str],
    rel_path: str,
    repo_name: str,
) -> List[Dict[str, Any]]:
    """
    Scan file content for high-entropy string literals near credential
    variable names. Returns a list of findings.
    """
    findings: List[Dict[str, Any]] = []
    seen: set = set()

    for m in _STRING_RE.finditer(content):
        value = m.group(1)

        # Skip obviously safe/low-value strings
        if value.lower() in _SAFE_VALUES:
            continue
        # Skip strings that are all the same character
        if len(set(value)) < 6:
            continue

        ent = shannon_entropy(value)
        if ent < ENTROPY_THRESHOLD:
            continue

        # Check if a suspicious variable name appears nearby
        start = max(0, m.start() - WINDOW_CHARS)
        end   = min(len(content), m.end() + WINDOW_CHARS)
        window = content[start:end]
        if not _SUSPECT_VAR_RE.search(window):
            continue

        line_no = content[:m.start()].count("\n") + 1
        uid = hashlib.md5(
            f"{repo_name}::{rel_path}::{line_no}::entropy_secret".encode()
        ).hexdigest()
        if uid in seen:
            continue
        seen.add(uid)

        # Context snippet
        idx   = line_no - 1
        start_l = max(0, idx - 2)
        end_l   = min(len(lines), idx + 3)
        snippet = "\n".join(l[:200] for l in lines[start_l:end_l])

        findings.append({
            "repo":            repo_name,
            "category":        "Security",
            "provider_or_lib": "entropy_secret",
            "capability":      "High-Entropy Secret",
            "severity":        1,
            "file":            rel_path,
            "line":            line_no,
            "snippet":         snippet,
            "match":           f"{value[:12]}… (entropy={ent:.2f} bits/char)",
            "policy_status":   "CRITICAL",
            "is_notebook":     False,
            "description": (
                f"A high-entropy string (entropy={ent:.2f} bits/char) was found "
                f"near a credential variable name — this is likely a hardcoded "
                f"secret. Remove it immediately, rotate the credential, and store "
                f"it in a secrets manager or environment variable."
            ),
            "_hash": uid,
        })

    return findings
