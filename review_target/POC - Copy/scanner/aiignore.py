"""
.aiignore — suppression file for the AI Security & Compliance Scanner.

Syntax is a strict subset of .gitignore:
  - Blank lines and lines starting with '#' are ignored (comments).
  - A leading '/' anchors the pattern to the repo root.
  - A trailing '/' matches directories only (treated as a path-prefix).
  - '*' matches any sequence of characters except '/'.
  - '**' matches any path component (zero or more directories).
  - '?' matches a single character except '/'.
  - All other characters are literal.
  - A leading '!' negates a pattern (un-suppresses a previously suppressed path).

Example .aiignore:
    # Suppress all findings in generated or vendor code
    vendor/
    **/generated/**
    docs/

    # Suppress a specific known-false-positive file
    /src/legacy/old_openai_shim.py

    # Suppress findings in any test fixture file
    tests/fixtures/

Usage:
    from scanner.aiignore import load_aiignore, is_suppressed

    ignore = load_aiignore(Path("/path/to/repo"))
    if is_suppressed(ignore, "src/legacy/old_openai_shim.py"):
        # skip this finding
"""

import re
from pathlib import Path, PurePosixPath
from typing import List, Tuple

# A rule is (negated: bool, pattern_re: re.Pattern, original: str)
_Rule = Tuple[bool, re.Pattern, str]

AIIGNORE_FILENAME = ".aiignore"


def load_aiignore(repo_root: Path) -> List[_Rule]:
    """
    Parse the .aiignore file at `repo_root / .aiignore` and return a list
    of compiled rules.  Returns an empty list if the file does not exist.

    Each rule is a (negated, compiled_re, original_text) tuple.
    Rules are applied in order; the LAST matching rule wins (same as gitignore).
    """
    aiignore_path = repo_root / AIIGNORE_FILENAME
    if not aiignore_path.is_file():
        return []
    try:
        lines = aiignore_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    rules: List[_Rule] = []
    for raw_line in lines:
        line = raw_line.rstrip()
        stripped_line = line.lstrip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        # Work with the whitespace-stripped version for pattern parsing
        line = stripped_line

        negated = line.startswith("!")
        if negated:
            line = line[1:]
        if not line:
            continue

        # Trailing slash → directory prefix; we'll match as prefix
        dir_only = line.endswith("/")
        if dir_only:
            line = line.rstrip("/")

        # Leading slash → anchored to root; strip it and remember
        anchored = line.startswith("/")
        if anchored:
            line = line.lstrip("/")

        try:
            compiled = _compile_pattern(line, anchored, dir_only)
        except re.error:
            continue   # bad pattern — skip silently

        rules.append((negated, compiled, raw_line.rstrip()))

    return rules


def is_suppressed(rules: List[_Rule], rel_path: str) -> bool:
    """
    Return True if `rel_path` (relative to repo root, POSIX separators)
    is suppressed by the loaded .aiignore rules.

    Rules are evaluated in order; the last matching rule wins.
    If no rule matches, the path is not suppressed (returns False).
    """
    if not rules:
        return False

    # Normalise to POSIX separators regardless of OS
    norm = rel_path.replace("\\", "/").lstrip("/")

    suppressed = False
    for negated, pattern_re, _ in rules:
        if pattern_re.search(norm):
            suppressed = not negated   # negation flips the current state

    return suppressed


# ── Pattern compiler ──────────────────────────────────────────────

def _compile_pattern(pattern: str, anchored: bool, dir_only: bool) -> re.Pattern:
    """
    Translate a gitignore-style glob pattern into a compiled regex.

    Approach: convert the pattern to a regex that matches a POSIX-normalised
    relative path string.

      - '**' in the middle of a path  → matches zero or more path components
      - '**' at the start/end only    → same
      - '*'                           → matches any chars except '/'
      - '?'                           → matches any single char except '/'
      - All other characters          → literal (re-escaped)

    anchored: pattern starts with '/' — must match from the path root.
    dir_only: pattern ends with '/'  — matches the dir itself or anything inside.
    """
    # Tokenise into literal chars and globs
    # Replace '**/' and '/**' with a sentinel first to distinguish from '*'
    # Strategy: build the regex piece by piece from the pattern characters
    regex = _glob_to_regex(pattern)

    if anchored:
        # Must start at position 0 of the normalised path
        full = r"^" + regex
    else:
        # May start anywhere — at path start or after a directory separator
        full = r"(?:^|(?<=/))" + regex

    if dir_only:
        # Matches the directory itself or anything inside it
        full = full + r"(?:/|$)"
    else:
        # Must end at path boundary (file name end or followed by /)
        full = full + r"(?:/.*)?$"

    return re.compile(full, re.IGNORECASE)


def _glob_to_regex(pattern: str) -> str:
    """Convert a gitignore glob to a regex string (no anchoring/trailing)."""
    result: List[str] = []
    i = 0
    n = len(pattern)

    while i < n:
        c = pattern[i]

        if c == '*' and i + 1 < n and pattern[i + 1] == '*':
            # '**' — matches any path component sequence (including separators)
            # absorb optional surrounding slashes into the '**' token
            j = i + 2
            # skip trailing slash after **
            if j < n and pattern[j] == '/':
                j += 1
            # emit: zero or more path components with separator
            result.append(r"(?:[^/]+/)*(?:[^/]+)?")
            i = j
        elif c == '*':
            result.append(r"[^/]*")
            i += 1
        elif c == '?':
            result.append(r"[^/]")
            i += 1
        elif c == '/':
            result.append(re.escape('/'))
            i += 1
        else:
            result.append(re.escape(c))
            i += 1

    return "".join(result)


def _glob_seg_to_re(seg: str) -> str:
    """Convert a single glob segment (no '**') to a regex string."""
    result: List[str] = []
    for c in seg:
        if c == '*':
            result.append(r"[^/]*")
        elif c == '?':
            result.append(r"[^/]")
        else:
            result.append(re.escape(c))
    return "".join(result)
