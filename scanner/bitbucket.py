"""
Bitbucket client: list repos, get clone URLs, shallow clone, cleanup.
"""

import base64
import subprocess
import shutil
import stat
import os
import time
import threading
import requests
from pathlib import Path
from typing import List, Optional, Callable

from requests import RequestException


# ── Rate-limiting defaults ────────────────────────────────────────
_DEFAULT_MIN_INTERVAL = 0.12   # seconds between requests (≈8 req/s)
_DEFAULT_MAX_RETRIES  = 3      # retries on 429 / 503
_DEFAULT_RETRY_AFTER  = 10     # fallback wait (s) if no Retry-After header
_DEFAULT_METADATA_CACHE_TTL = 300.0


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
                 verify_ssl: bool = True, ca_bundle: str = "",
                 verbose: bool = False,
                 min_request_interval: float = _DEFAULT_MIN_INTERVAL,
                 max_retries: int = _DEFAULT_MAX_RETRIES,
                 retry_after_fallback: float = _DEFAULT_RETRY_AFTER,
                 rate_limit_callback: Callable[[str], None] = None,
                 metadata_cache_ttl: float = _DEFAULT_METADATA_CACHE_TTL):
        self.base_url = base_url.rstrip("/")
        self.token    = token
        self.username = username
        self.password = password
        self.verbose  = verbose
        self.is_cloud = "bitbucket.org" in base_url
        self.verify_ssl = bool(verify_ssl)
        self.ca_bundle = str(ca_bundle or "").strip()

        self._min_interval    = min_request_interval
        self._max_retries     = max_retries
        self._retry_fallback  = retry_after_fallback
        self._rate_cb         = rate_limit_callback   # optional callback
        self._last_req_time   = 0.0                   # epoch seconds
        self._throttle_lock   = threading.Lock()      # guards _last_req_time
        self._metadata_cache_ttl = max(0.0, float(metadata_cache_ttl))
        self._metadata_cache: dict[tuple[str, str, str], tuple[float, object]] = {}
        self._metadata_lock = threading.Lock()
        self._cache_stats = {"hits": 0, "misses": 0}

        self.session = requests.Session()
        self.session.verify = self.ca_bundle if self.verify_ssl and self.ca_bundle else self.verify_ssl
        if not self.verify_ssl:
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
                    except (AttributeError, TypeError):
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
        except (TypeError, ValueError, OverflowError):
            pass
        return fallback

    def get_pat_owner(self) -> str:
        """
        Return the display name of the user who owns the PAT.
        Uses the Bitbucket Server /rest/api/1.0/application-properties
        and /rest/api/1.0/users/~/profile endpoints.
        Falls back to 'User' if the endpoint is unavailable.
        """
        try:
            # Bitbucket Server: current user info
            data = self._get(f"{self.base_url}/rest/api/1.0/users/myself")
            return (data.get("displayName")
                    or data.get("name")
                    or data.get("slug")
                    or "User")
        except (RequestException, ValueError, TypeError):
            pass
        try:
            # Alternative endpoint for some Bitbucket Server versions
            data = self._get(f"{self.base_url}/plugins/servlet/applinks/whoami")
            if isinstance(data, str):
                return data
        except (RequestException, ValueError, TypeError):
            pass
        return "User"

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

        data = self.get_repo_metadata(project_key, repo_slug, protocol=protocol)
        return data.get("clone_url")

    def _cache_key(self, kind: str, project_key: str, repo_slug: str = "") -> tuple[str, str, str]:
        return kind, str(project_key), str(repo_slug)

    def _cache_get(self, kind: str, project_key: str, repo_slug: str = ""):
        if self._metadata_cache_ttl <= 0:
            self._cache_stats["misses"] += 1
            return None
        key = self._cache_key(kind, project_key, repo_slug)
        with self._metadata_lock:
            cached = self._metadata_cache.get(key)
            if not cached:
                self._cache_stats["misses"] += 1
                return None
            stored_at, value = cached
            if (time.monotonic() - stored_at) > self._metadata_cache_ttl:
                self._metadata_cache.pop(key, None)
                self._cache_stats["misses"] += 1
                return None
            self._cache_stats["hits"] += 1
            return value

    def _cache_set(self, kind: str, project_key: str, repo_slug: str, value):
        if self._metadata_cache_ttl <= 0:
            return value
        key = self._cache_key(kind, project_key, repo_slug)
        with self._metadata_lock:
            self._metadata_cache[key] = (time.monotonic(), value)
        return value

    def _repo_info_cached(self, project_key: str, repo_slug: str) -> dict:
        cached = self._cache_get("repo_info", project_key, repo_slug)
        if cached is not None:
            return cached
        url = f"{self.base_url}/rest/api/1.0/projects/{project_key}/repos/{repo_slug}"
        return self._cache_set("repo_info", project_key, repo_slug, self._get(url))

    def _project_info_cached(self, project_key: str) -> dict:
        cached = self._cache_get("project_info", project_key)
        if cached is not None:
            return cached
        url = f"{self.base_url}/rest/api/1.0/projects/{project_key}"
        return self._cache_set("project_info", project_key, "", self._get(url))

    def _default_branch_cached(self, project_key: str, repo_slug: str) -> Optional[str]:
        cached = self._cache_get("default_branch", project_key, repo_slug)
        if cached is not None:
            return cached
        url = (f"{self.base_url}/rest/api/1.0/projects/{project_key}"
               f"/repos/{repo_slug}/default-branch")
        data = self._get(url)
        branch = data.get("displayId") or data.get("id", "").replace("refs/heads/", "") or None
        return self._cache_set("default_branch", project_key, repo_slug, branch)

    def get_repo_metadata(self, project_key: str, repo_slug: str, protocol: str = "http") -> dict:
        """Return branch, owner, and clone URL with a short-lived cache."""
        cached = self._cache_get("repo_metadata", project_key, repo_slug)
        if cached is not None:
            return dict(cached)

        repo_info = self._repo_info_cached(project_key, repo_slug)
        clone_url = None
        for link in repo_info.get("links", {}).get("clone", []):
            if link.get("name", "").lower() in (protocol, "https", "http"):
                clone_url = link["href"]
                break

        try:
            branch = self._default_branch_cached(project_key, repo_slug)
        except (RequestException, ValueError, TypeError):
            branch = None

        owner = "User"
        try:
            url = (f"{self.base_url}/rest/api/1.0/projects/{project_key}"
                   f"/repos/{repo_slug}/commits")
            data = self._get(url, params={"limit": 1})
            commits = data.get("values", [])
            if commits:
                author = commits[0].get("author", {})
                owner = author.get("displayName") or author.get("name") or author.get("emailAddress", "") or owner
        except (RequestException, ValueError, TypeError):
            try:
                data = self._project_info_cached(project_key)
                lead = data.get("lead", {})
                owner = lead.get("displayName") or lead.get("slug") or lead.get("name", "") or owner
            except (RequestException, ValueError, TypeError):
                pass

        metadata = {
            "branch": branch,
            "owner": owner,
            "clone_url": clone_url,
        }
        self._cache_set("repo_metadata", project_key, repo_slug, metadata)
        return dict(metadata)

    def cache_stats(self) -> dict[str, int]:
        return {
            "hits": int(self._cache_stats.get("hits", 0) or 0),
            "misses": int(self._cache_stats.get("misses", 0) or 0),
        }

    def build_git_auth_env(self) -> dict[str, str]:
        """
        Return git environment variables that inject HTTP auth without
        exposing credentials in the clone URL or process argv.
        """
        auth_value = ""
        if self.username and self.token:
            creds = f"{self.username}:{self.token}".encode("utf-8")
            auth_value = "Authorization: Basic " + base64.b64encode(creds).decode("ascii")
        elif self.username and self.password:
            creds = f"{self.username}:{self.password}".encode("utf-8")
            auth_value = "Authorization: Basic " + base64.b64encode(creds).decode("ascii")
        elif self.token:
            auth_value = f"Authorization: Bearer {self.token}"

        if not auth_value:
            return {}

        return _git_config_env("http.extraHeader", auth_value)

    def get_repo_info(self, project_key: str, repo_slug: str) -> dict:
        """Get repo metadata."""
        return self._repo_info_cached(project_key, repo_slug)

    def get_default_branch(self, project_key: str, repo_slug: str) -> Optional[str]:
        """
        Return the default branch name as configured in Bitbucket Server.
        Falls back to None if the endpoint is unavailable.
        """
        try:
            return self.get_repo_metadata(project_key, repo_slug).get("branch")
        except (RequestException, ValueError, TypeError):
            return None

    def get_repo_owner(self, project_key: str, repo_slug: str) -> str:
        """
        Return the display name / slug of the repo's last-modifier or project lead
        as surfaced by Bitbucket Server.  Falls back to 'User'.
        """
        try:
            return self.get_repo_metadata(project_key, repo_slug).get("owner") or "User"
        except (RequestException, ValueError, TypeError):
            pass
        return "User"

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
        except (RequestException, ValueError, TypeError):
            pass
        # Fallback: try the main repo info endpoint
        try:
            url = (f"{self.base_url}/rest/api/1.0/projects/{project_key}"
                   f"/repos/{repo_slug}")
            data = self._get(url)
            size = data.get("size")
            if size is not None:
                return int(size)
        except (RequestException, ValueError, TypeError):
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


def _git_config_env(key: str, value: str) -> dict[str, str]:
    """
    Encode transient git config via environment variables so secrets do not
    appear in command-line arguments.
    """
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": key,
        "GIT_CONFIG_VALUE_0": value,
    }


def shallow_clone(clone_url: str, dest: Path, depth: int = 1,
                  branch: str = None, verbose: bool = False,
                  stop_event=None, proc_holder: list = None,
                  proc_lock=None, git_env: dict | None = None,
                  verify_ssl: bool = True, ca_bundle: str | None = None) -> None:
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

    def _best_effort_cleanup() -> None:
        try:
            cleanup_clone(dest)
        except OSError:
            pass

    if dest.exists():
        shutil.rmtree(dest)

    def _clone_cmd(target_branch: str | None) -> list[str]:
        cmd = ["git", "clone", "--depth", str(depth), "--single-branch", "--no-tags",
               "-c", "filter.lfs.smudge=cat",
               "-c", "filter.lfs.process=cat",
               "-c", "filter.lfs.required=false",
               "-c", "lfs.fetchexclude=*",
               "-c", "core.longpaths=true"]   # Windows MAX_PATH (260 chars) workaround
        if not verify_ssl:
            cmd += ["-c", "http.sslVerify=false"]
        if target_branch:
            cmd += ["--branch", target_branch]
        cmd += [clone_url, str(dest)]
        return cmd

    cmd = _clone_cmd(branch)

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"]  = "0"
    env["GIT_LFS_SKIP_SMUDGE"]  = "1"   # skip LFS blob downloads entirely
    if not verify_ssl:
        env["GIT_SSL_NO_VERIFY"] = "1"
    elif ca_bundle:
        env["GIT_SSL_CAINFO"] = str(ca_bundle)
    if git_env:
        env.update(git_env)

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
                _best_effort_cleanup()
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
            cmd_retry = _clone_cmd(None)
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
                        _best_effort_cleanup()
                        raise RuntimeError("Scan cancelled.")
                    try:
                        proc2.wait(timeout=0.5); break
                    except subprocess.TimeoutExpired:
                        continue
            finally:
                pass
            if proc2.returncode != 0:
                stderr2 = proc2.stderr.read() if proc2.stderr else ""
                _best_effort_cleanup()
                raise RuntimeError(
                    f"Git clone failed (rc={proc2.returncode}): {stderr2.strip()}")
            return  # retry succeeded
        _best_effort_cleanup()
        raise RuntimeError(
            f"Git clone failed (rc={proc.returncode}): {stderr_text.strip()}")


def _git_env(*, git_env: dict | None = None, verify_ssl: bool = True, ca_bundle: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    if not verify_ssl:
        env["GIT_SSL_NO_VERIFY"] = "1"
    elif ca_bundle:
        env["GIT_SSL_CAINFO"] = str(ca_bundle)
    if git_env:
        env.update(git_env)
    return env


def _run_git(
    repo_dir: Path,
    args: list[str],
    *,
    git_env: dict | None = None,
    verify_ssl: bool = True,
    ca_bundle: str | None = None,
) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_dir),
        text=True,
        capture_output=True,
        env=_git_env(git_env=git_env, verify_ssl=verify_ssl, ca_bundle=ca_bundle),
        check=False,
    )
    if proc.returncode != 0:
        stderr_text = (proc.stderr or "").strip()
        stdout_text = (proc.stdout or "").strip()
        detail = stderr_text or stdout_text or "git command failed"
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout or ""


def git_changed_files_since_previous_commit(
    repo_dir: Path,
    *,
    git_env: dict | None = None,
    verify_ssl: bool = True,
    ca_bundle: str | None = None,
) -> list[str]:
    try:
        output = _run_git(
            repo_dir,
            ["diff", "--name-only", "HEAD~1", "HEAD"],
            git_env=git_env,
            verify_ssl=verify_ssl,
            ca_bundle=ca_bundle,
        )
    except RuntimeError as exc:
        raise RuntimeError("previous-commit diff is unavailable") from exc
    return [line.strip() for line in output.splitlines() if line.strip()]


def git_changed_files_against_ref(
    repo_dir: Path,
    ref: str,
    *,
    git_env: dict | None = None,
    verify_ssl: bool = True,
    ca_bundle: str | None = None,
) -> list[str]:
    ref = str(ref or "").strip()
    if not ref:
        raise RuntimeError("diff reference is required")
    _run_git(
        repo_dir,
        ["fetch", "--depth", "1", "origin", ref],
        git_env=git_env,
        verify_ssl=verify_ssl,
        ca_bundle=ca_bundle,
    )
    output = _run_git(
        repo_dir,
        ["diff", "--name-only", "FETCH_HEAD", "HEAD"],
        git_env=git_env,
        verify_ssl=verify_ssl,
        ca_bundle=ca_bundle,
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


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
        except OSError:
            pass

    shutil.rmtree(path, onerror=_force_remove)
