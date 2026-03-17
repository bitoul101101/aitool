"""
Git history scanner (Task 4).

After a shallow clone, scans git history for files that were deleted
from HEAD but existed at some point — a common vector for leaked secrets
that were "cleaned up" but remain in history.

Strategy
--------
1. git log --all --diff-filter=D --name-only --format=%H
   → gives us commit hashes + deleted file paths

2. For each deleted file that matches SCAN_EXTENSIONS:
   git show <hash>:<path>  → retrieve the file content at deletion commit

3. Pass content through the same detector pipeline with:
   - context = "deleted_file"
   - severity bump = 0  (history findings are same severity — they ARE still
     reachable via git clone unless the repo is garbage-collected)
   - policy_status forced to CRITICAL for Security category

Limits
------
- MAX_DELETED_FILES: cap to avoid scanning huge repos with thousands of
  deleted files (churn repos).
- Timeouts per git-show call to avoid stalling on large blobs.
- Only scans files whose suffix is in SCAN_EXTENSIONS.
"""

import subprocess
import os
import re
from pathlib import Path
from typing import List, Optional, Set

from scanner.patterns import SCAN_EXTENSIONS, SKIP_DIRS

MAX_DELETED_FILES = 200    # per repo
GIT_SHOW_TIMEOUT  = 10     # seconds per git-show call


def _git(args: List[str], cwd: Path, timeout: int = 30) -> Optional[str]:
    """Run a git command, return stdout or None on failure."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if result.returncode == 0:
            return result.stdout
    except Exception as e:
        # Log at debug level — caller decides whether to surface this
        import sys
        print(f"[history] git {args[0] if args else '?'} failed: {e}", file=sys.stderr)
    return None


def list_deleted_files(clone_dir: Path) -> List[tuple]:
    """
    Return list of (commit_hash, file_path) for all files deleted in history.
    Capped at MAX_DELETED_FILES entries.
    """
    out = _git(
        ["log", "--all", "--diff-filter=D", "--name-only",
         "--format=COMMIT:%H", "--no-renames"],
        clone_dir,
    )
    if not out:
        return []

    results = []
    current_commit = None
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COMMIT:"):
            current_commit = line[7:]
        elif current_commit:
            # Filter by extension before we even try git-show
            suffix = Path(line).suffix.lower()
            name   = Path(line).name
            # Skip dirs we always skip
            parts = set(Path(line).parts)
            if parts & SKIP_DIRS:
                continue
            if name in SCAN_EXTENSIONS or suffix in SCAN_EXTENSIONS:
                results.append((current_commit, line))
                if len(results) >= MAX_DELETED_FILES:
                    break

    return results


def get_deleted_file_content(clone_dir: Path,
                              commit_hash: str,
                              file_path: str) -> Optional[str]:
    """Retrieve the content of a file at the commit it was deleted."""
    # The file existed in the parent commit, use <hash>~1 (parent)
    # to get the last version before deletion.
    # Fall back to <hash>^ if ~1 syntax unsupported.
    for ref in (f"{commit_hash}~1", f"{commit_hash}^"):
        content = _git(
            ["show", f"{ref}:{file_path}"],
            clone_dir,
            timeout=GIT_SHOW_TIMEOUT,
        )
        if content is not None:
            return content
    return None


def scan_history(
    clone_dir: Path,
    detector,          # AIUsageDetector instance
    repo_name: str,
    stop_event=None,
) -> List[dict]:
    """
    Full pipeline: find deleted files → retrieve content → scan → return findings.
    All findings are tagged context='deleted_file'.
    """
    deleted = list_deleted_files(clone_dir)
    if not deleted:
        return []

    all_findings: List[dict] = []
    seen_paths: Set[str] = set()

    for commit_hash, file_path in deleted:
        if stop_event and stop_event.is_set():
            break

        # Deduplicate: if the same file was deleted+re-added+deleted,
        # only scan the most recent deletion (first occurrence in log output).
        if file_path in seen_paths:
            continue
        seen_paths.add(file_path)

        content = get_deleted_file_content(clone_dir, commit_hash, file_path)
        if not content or len(content) > 500_000:   # skip >500 KB blobs
            continue

        # Write to a temp in-memory path label — no actual file needed
        fake_path = f"[DELETED]{file_path}"
        suffix    = Path(file_path).suffix.lower()

        # Use detector's internal text scanner directly
        findings = detector._scan_text_file_from_content(
            content=content,
            suffix=suffix,
            rel_path=fake_path,
            repo_name=repo_name,
        )

        # Tag all findings as deleted-file context + force CRITICAL for Security
        for f in findings:
            f["context"]     = "deleted_file"
            f["description"] = (
                f"[GIT HISTORY] {f.get('description','')} — "
                f"This finding is in a deleted file ({file_path}) reachable "
                f"via git history. The secret is still accessible to anyone "
                f"who can clone the repository."
            )
            if f.get("category") == "Security":
                f["policy_status"] = "CRITICAL"
                f["severity"]      = min(f.get("severity", 2), 1)  # always Critical

        all_findings.extend(findings)

    return all_findings
