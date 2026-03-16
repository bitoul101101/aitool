"""
Bitbucket client: list repos, get clone URLs, shallow clone, cleanup.
"""

import subprocess
import shutil
import stat
import os
import time
import threading
import requests
from pathlib import Path
from typing import List, Optional, Callable


# ── Rate-limiting defaults ────────────────────────────────────────
_DEFAULT_MIN_INTERVAL = 0.12   # seconds between requests (≈8 req/s)
_DEFAULT_MAX_RETRIES  = 3      # retries on 429 / 503
_DEFAULT_RETRY_AFTER  = 10     # fallback wait (s) if no Retry-After header


class BitbucketClient:
    """
    Supports Bitbucket Server (Data Center) and Bitbucket Cloud.
    Auto-detects based on URL pattern.

    Rate limiting (Task 8):
      - Enforces a minimum interval between requests (min_request_interval).
      - On HTTP 429 / 503: reads Retry-After header (or waits retry_after_fallback
        seconds), then retries up to max_retries times.
      - rate_limit_callback(msg) is called on every backoff event so callers can
        log/display it (e.g. update the GUI status label).
    """

    def __init__(self, base_url: str, token: str = None,
                 username: str = None, password: str = None,
                 verify_ssl: bool = True, verbose: bool = False,
                 min_request_interval: float = _DEFAULT_MIN_INTERVAL,
                 max_retries: int = _DEFAULT_MAX_RETRIES,
                 retry_after_fallback: float = _DEFAULT_RETRY_AFTER,
                 rate_limit_callback: Callable[[str], None] = None):
        self.base_url = base_url.rstrip("/")
        self.token    = token
        self.username = username
        self.password = password
        self.verbose  = verbose
        self.is_cloud = "bitbucket.org" in base_url

        self._min_interval    = min_request_interval
        self._max_retries     = max_retries
        self._retry_fallback  = retry_after_fallback
        self._rate_cb         = rate_limit_callback   # optional callback
        self._last_req_time   = 0.0                   # epoch seconds
        self._throttle_lock   = threading.Lock()      # guards _last_req_time

        self.session = requests.Session()
        self.session.verify = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        elif username and password:
            self.session.auth = (username, password)
        self.session.headers["Content-Type"] = "application/json"

    # ── Task 8: Rate-limited GET ──────────────────────────────────
    def _get(self, url: str, params: dict = None) -> dict:
        """
        GET with:
          1. Per-client throttle (min_request_interval between requests).
          2. Automatic retry on HTTP 429 / 503 with Retry-After respect.
        """
        for attempt in range(self._max_retries + 1):
            # Throttle: enforce minimum gap between requests
            with self._throttle_lock:
                now     = time.monotonic()
                elapsed = now - self._last_req_time
                gap     = self._min_interval - elapsed
                if gap > 0:
                    time.sleep(gap)
                self._last_req_time = time.monotonic()

            resp = self.session.get(url, params=params, timeout=30)

            if resp.status_code in (429, 503):
                # Parse Retry-After (seconds or HTTP-date)
                retry_after = self._parse_retry_after(
                    resp.headers.get("Retry-After"), self._retry_fallback)
                msg = (f"[Rate limit] HTTP {resp.status_code} — "
                       f"waiting {retry_after:.0f}s "
                       f"(attempt {attempt+1}/{self._max_retries+1})")
                if self.verbose:
                    print(msg)
                if self._rate_cb:
                    try:
                        self._rate_cb(msg)
                    except Exception:
                        pass
                if attempt < self._max_retries:
                    time.sleep(retry_after)
                    continue
                # Exhausted retries — raise so callers see the failure
                resp.raise_for_status()

            resp.raise_for_status()
            return resp.json()

        # Should never reach here
        raise RuntimeError(f"GET {url}: exhausted retries")

    @staticmethod
    def _parse_retry_after(header_value: Optional[str],
                            fallback: float) -> float:
        """
        Parse a Retry-After header.  Accepts:
          - integer/float seconds string: "30", "1.5"
          - HTTP-date:  "Wed, 11 Mar 2026 12:00:00 GMT"
        Falls back to `fallback` on any parse error.
        """
        if not header_value:
            return fallback
        header_value = header_value.strip()
        # Try numeric first (most common for Bitbucket)
        try:
            secs = float(header_value)
            return max(0.0, secs)
        except ValueError:
            pass
        # Try HTTP-date
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(header_value)
            secs = (dt.timestamp() - time.time())
            return max(0.0, secs)
        except Exception:
            pass
        return fallback

    def get_pat_owner(self) -> str:
        """
        Return the display name of the user who owns the PAT.
        Uses the Bitbucket Server /rest/api/1.0/application-properties
        and /rest/api/1.0/users/~/profile endpoints.
        Falls back to 'Unknown' if the endpoint is unavailable.
        """
        try:
            # Bitbucket Server: current user info
            data = self._get(f"{self.base_url}/rest/api/1.0/users/myself")
            return (data.get("displayName")
                    or data.get("name")
                    or data.get("slug")
                    or "Unknown")
        except Exception:
            pass
        try:
            # Alternative endpoint for some Bitbucket Server versions
            data = self._get(f"{self.base_url}/plugins/servlet/applinks/whoami")
            if isinstance(data, str):
                return data
        except Exception:
            pass
        return "Unknown"

    def list_repos(self, project_key: str) -> List[dict]:
        """List all repos in a Bitbucket Server project."""
        repos = []
        start = 0
        limit = 100
        while True:
            url = f"{self.base_url}/rest/api/1.0/projects/{project_key}/repos"
            data = self._get(url, params={"start": start, "limit": limit})
            repos.extend(data.get("values", []))
            if data.get("isLastPage", True):
                break
            start = data.get("nextPageStart", start + limit)
        return repos

    def get_clone_url(self, project_key: str, repo_slug: str,
                       protocol: str = "http") -> Optional[str]:
        """Get clone URL for a repo (prefers HTTP/HTTPS)."""
        if self.is_cloud:
            return f"{self.base_url}/{project_key}/{repo_slug}.git"

        url = f"{self.base_url}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}"
        data = self._get(url)
        for link in data.get("links", {}).get("clone", []):
            if link.get("name", "").lower() in (protocol, "https", "http"):
                href = link["href"]
                # Inject credentials — Bitbucket Server uses username:token
                if self.username and self.token:
                    href = href.replace("://", f"://{self.username}:{self.token}@", 1)
                elif self.username and self.password:
                    href = href.replace("://", f"://{self.username}:{self.password}@", 1)
                return href
        return None

    def get_repo_info(self, project_key: str, repo_slug: str) -> dict:
        """Get repo metadata."""
        url = f"{self.base_url}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}"
        return self._get(url)

    def get_default_branch(self, project_key: str, repo_slug: str) -> Optional[str]:
        """
        Return the default branch name as configured in Bitbucket Server.
        Falls back to None if the endpoint is unavailable.
        """
        try:
            url = (f"{self.base_url}/rest/api/1.0/projects/{project_key}"
                   f"/repos/{repo_slug}/default-branch")
            data = self._get(url)
            # Bitbucket Server returns {"id": "refs/heads/main", "displayId": "main", ...}
            return data.get("displayId") or data.get("id", "").replace("refs/heads/", "") or None
        except Exception:
            return None

    def get_repo_owner(self, project_key: str, repo_slug: str) -> str:
        """
        Return the display name / slug of the repo's last-modifier or project lead
        as surfaced by Bitbucket Server.  Falls back to 'Unknown'.
        """
        try:
            # Try repo-level: check the most recent commit author via commits API
            url = (f"{self.base_url}/rest/api/1.0/projects/{project_key}"
                   f"/repos/{repo_slug}/commits")
            data = self._get(url, params={"limit": 1})
            commits = data.get("values", [])
            if commits:
                author = commits[0].get("author", {})
                name = author.get("displayName") or author.get("name") or author.get("emailAddress", "")
                if name:
                    return name
        except Exception:
            pass
        try:
            # Fall back: project lead
            url = f"{self.base_url}/rest/api/1.0/projects/{project_key}"
            data = self._get(url)
            lead = data.get("lead", {})
            name = lead.get("displayName") or lead.get("slug") or lead.get("name", "")
            if name:
                return name
        except Exception:
            pass
        return "Unknown"

    def get_repo_size(self, project_key: str, repo_slug: str) -> Optional[int]:
        """
        Return the repo size in bytes as reported by Bitbucket Server.
        Returns None if unavailable.
        """
        try:
            url = (f"{self.base_url}/rest/api/1.0/projects/{project_key}"
                   f"/repos/{repo_slug}/sizes")
            data = self._get(url)
            # Bitbucket Server returns {"repository": <bytes>, "attachments": <bytes>}
            repo_bytes = data.get("repository") or data.get("size")
            if repo_bytes is not None:
                return int(repo_bytes)
        except Exception:
            pass
        # Fallback: try the main repo info endpoint
        try:
            url = (f"{self.base_url}/rest/api/1.0/projects/{project_key}"
                   f"/repos/{repo_slug}")
            data = self._get(url)
            size = data.get("size")
            if size is not None:
                return int(size)
        except Exception:
            pass
        return None

    def list_projects(self) -> List[dict]:
        """List all accessible projects."""
        projects = []
        start = 0
        limit = 100
        while True:
            url = f"{self.base_url}/rest/api/1.0/projects"
            data = self._get(url, params={"start": start, "limit": limit})
            projects.extend(data.get("values", []))
            if data.get("isLastPage", True):
                break
            start = data.get("nextPageStart", start + limit)
        return projects


def shallow_clone(clone_url: str, dest: Path, depth: int = 1,
                  branch: str = None, verbose: bool = False,
                  stop_event=None, proc_holder: list = None,
                  proc_lock=None) -> None:
    """
    Shallow clone a repo to dest.
    If branch is given, clones that specific branch (use for the default/main branch).
    Cleans dest first if it already exists.
    stop_event: threading.Event — if set before/during clone, raises RuntimeError.
    proc_holder: list — if provided, the subprocess is appended so the caller can kill it.
    proc_lock:   threading.Lock — guards proc_holder for thread-safe append/remove (Task 9).
    """
    if stop_event and stop_event.is_set():
        raise RuntimeError("Scan cancelled.")

    if dest.exists():
        shutil.rmtree(dest)

    cmd = ["git", "clone", "--depth", str(depth), "--single-branch", "--no-tags",
           "-c", "http.sslVerify=false",
           "-c", "filter.lfs.smudge=cat",
           "-c", "filter.lfs.process=cat",
           "-c", "filter.lfs.required=false",
           "-c", "lfs.fetchexclude=*",
           "-c", "core.longpaths=true"]   # Windows MAX_PATH (260 chars) workaround
    if branch:
        cmd += ["--branch", branch]
    cmd += [clone_url, str(dest)]

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"]  = "0"
    env["GIT_SSL_NO_VERIFY"]    = "1"
    env["GIT_LFS_SKIP_SMUDGE"]  = "1"   # skip LFS blob downloads entirely

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE if not verbose else None,
        stderr=subprocess.PIPE if not verbose else None,
        text=True, env=env
    )
    # Task 9: guard proc_holder with a lock so concurrent workers don't race
    if proc_holder is not None:
        if proc_lock is not None:
            with proc_lock:
                proc_holder.append(proc)
        else:
            proc_holder.append(proc)

    # Poll so we can honour stop_event mid-clone
    try:
        while True:
            if stop_event and stop_event.is_set():
                proc.kill()
                proc.wait()
                raise RuntimeError("Scan cancelled.")
            try:
                proc.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        if proc_holder is not None:
            if proc_lock is not None:
                with proc_lock:
                    if proc in proc_holder:
                        proc_holder.remove(proc)
            else:
                if proc in proc_holder:
                    proc_holder.remove(proc)

    if proc.returncode != 0:
        stderr_text = proc.stderr.read() if proc.stderr else ""
        # If a specific branch was requested and not found, retry without --branch
        # so git clones whatever the remote default branch is.
        if branch and ("not found in upstream" in stderr_text or
                       "Remote branch" in stderr_text or
                       "remote ref does not exist" in stderr_text.lower()):
            if dest.exists():
                shutil.rmtree(dest)
            cmd_retry = ["git", "clone", "--depth", str(depth), "--single-branch", "--no-tags",
                         "-c", "http.sslVerify=false",
                         "-c", "filter.lfs.smudge=cat",
                         "-c", "filter.lfs.process=cat",
                         "-c", "filter.lfs.required=false",
                         "-c", "lfs.fetchexclude=*",
                         "-c", "core.longpaths=true",
                         clone_url, str(dest)]
            proc2 = subprocess.Popen(
                cmd_retry,
                stdout=subprocess.PIPE if not verbose else None,
                stderr=subprocess.PIPE if not verbose else None,
                text=True, env=env
            )
            try:
                while True:
                    if stop_event and stop_event.is_set():
                        proc2.kill(); proc2.wait()
                        raise RuntimeError("Scan cancelled.")
                    try:
                        proc2.wait(timeout=0.5); break
                    except subprocess.TimeoutExpired:
                        continue
            finally:
                pass
            if proc2.returncode != 0:
                stderr2 = proc2.stderr.read() if proc2.stderr else ""
                raise RuntimeError(
                    f"Git clone failed (rc={proc2.returncode}): {stderr2.strip()}")
            return  # retry succeeded
        raise RuntimeError(
            f"Git clone failed (rc={proc.returncode}): {stderr_text.strip()}")


def cleanup_clone(path: Path) -> None:
    """
    Remove a cloned directory, handling read-only files on Windows
    (e.g. .git/objects/pack/*.idx and .git/lfs/objects/**).
    """
    if not path.exists():
        return

    def _force_remove(func, p, exc_info):
        """Clear read-only bit and retry."""
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    shutil.rmtree(path, onerror=_force_remove)