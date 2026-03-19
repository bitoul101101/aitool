from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable

from scanner.bitbucket import BitbucketClient
from scanner.pat_store import backend_name, delete_pat, load_pat, save_pat
from scanner.suppressions import (
    TRIAGE_ACCEPTED_RISK,
    TRIAGE_FALSE_POSITIVE,
    TRIAGE_REVIEWED,
    remove_triage,
    upsert_triage,
)


def connect_operator(
    *,
    body: dict,
    bitbucket_url: str,
    tls_config: dict,
    operator_state,
    audit_event: Callable[..., None],
) -> dict:
    token = body.get("token", "").strip()
    remember = body.get("remember", False)
    use_saved_token = bool(body.get("use_saved_token"))
    if not token and use_saved_token:
        token = load_pat() or ""
    if not token:
        raise ValueError("Token required")

    client = BitbucketClient(
        base_url=bitbucket_url,
        token=token,
        verify_ssl=bool(tls_config.get("verify_ssl", True)),
        ca_bundle=str(tls_config.get("ca_bundle", "") or "").strip(),
        verbose=False,
    )
    owner = client.get_pat_owner()
    projects = client.list_projects()
    visible_projects = operator_state.connect(client, owner, projects)
    if remember:
        try:
            persisted = save_pat(token)
        except RuntimeError as exc:
            raise ValueError(str(exc)) from exc
        if not persisted:
            raise ValueError(
                f"Could not persist the PAT with the active credential backend ({backend_name()})."
            )
    else:
        delete_pat()
    audit_event(
        "connect",
        outcome="success",
        project_count=len(visible_projects),
        connected_owner=operator_state.connected_owner,
    )
    return {
        "ok": True,
        "owner": owner,
        "projects": visible_projects,
        "auth": operator_state.public_auth(),
    }


def start_scan(
    *,
    body: dict,
    session_factory,
    current_session,
    operator_state,
    save_llm_config: Callable[[dict], None],
    audit_event: Callable[..., None],
):
    project_key = body.get("project_key", "").strip()
    repo_slugs = body.get("repo_slugs", [])
    local_repo_path = str(body.get("local_repo_path", "") or "").strip()
    llm_url = body.get("llm_url", "http://localhost:11434").strip()
    llm_model = body.get("llm_model", "qwen2.5-coder:7b-instruct").strip()
    scan_scope = str(body.get("scan_scope", "full") or "full").strip().lower()
    compare_ref = str(body.get("compare_ref", "") or "").strip()

    valid_scopes = {"full", "changed_files", "branch_diff", "baseline_rescan"}
    if scan_scope not in valid_scopes:
        raise ValueError("invalid scan_scope")
    if scan_scope == "branch_diff" and not compare_ref:
        raise ValueError("compare_ref required for branch diff scans")

    local_mode = bool(local_repo_path)
    if isinstance(repo_slugs, str):
        repo_slugs = [repo_slugs]
    if local_mode:
        repo_path = Path(local_repo_path).expanduser()
        if not repo_path.exists():
            raise ValueError("local_repo_path not found")
        if not repo_path.is_dir():
            raise ValueError("local_repo_path must be a directory")
        project_key = "LOCAL"
        repo_slugs = [repo_path.resolve().name or "local-repo"]
    elif not project_key or not repo_slugs:
        raise ValueError("project_key and repo_slugs required")

    if not local_mode and not operator_state.client:
        raise PermissionError("Not connected")
    if current_session.state == "running":
        raise RuntimeError("Scan already running")

    save_llm_config({"base_url": llm_url, "model": llm_model})

    session = session_factory()
    session.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    session.project_key = project_key
    session.repo_slugs = repo_slugs
    session.scan_source = "local" if local_mode else "bitbucket"
    session.local_repo_path = str(Path(local_repo_path).expanduser().resolve()) if local_mode else ""
    session.total = len(repo_slugs)
    session.scan_scope = scan_scope
    session.compare_ref = compare_ref
    session.llm_url = llm_url
    session.llm_model = llm_model
    session.operator = operator_state.ctx.username
    session.state = "running"
    audit_event(
        "scan_start",
        scan_id=session.scan_id,
        project_key=project_key,
        repo_slugs=list(repo_slugs),
    )
    return session


def stop_scan(*, current_session, stop_scan_fn: Callable[[], bool], audit_event: Callable[..., None]) -> dict:
    stopped = stop_scan_fn()
    audit_event("scan_stop", scan_id=current_session.scan_id, stopped=bool(stopped))
    return {"ok": True, "stopped": stopped}


def delete_history_records(
    *,
    body: dict,
    history_records: list[dict],
    delete_managed_file: Callable[[str, str, str], str | None],
    delete_history: Callable[[list[str]], None],
    audit_event: Callable[..., None],
) -> dict:
    scan_ids = body.get("scan_ids", [])
    if not scan_ids or not isinstance(scan_ids, list):
        raise ValueError("scan_ids list required")

    deleted, errors = [], []
    for sid in scan_ids:
        rec = next((r for r in history_records if r.get("scan_id") == sid), None)
        if not rec:
            errors.append(f"{sid}: not found")
            continue
        rp = (rec.get("reports") or {}).get("__all__", {})
        for key in ("html", "csv"):
            fpath = rp.get(key, "")
            if fpath:
                err = delete_managed_file(fpath, sid, key)
                if err:
                    errors.append(f"{sid} {key}: {err}")
        log_file = rec.get("log_file", "")
        if log_file:
            err = delete_managed_file(log_file, sid, "log")
            if err:
                errors.append(f"{sid} log: {err}")
        deleted.append(sid)

    if deleted:
        delete_history(deleted)
    audit_event("history_delete", scan_ids=list(deleted), errors=list(errors))
    return {"ok": True, "deleted": deleted, "errors": errors}


def triage_finding(
    *,
    body: dict,
    session,
    suppressions_file: str,
    triage_lookup: Callable[[], dict],
    apply_triage_metadata: Callable[[dict, dict], dict],
    persist_session_state: Callable[[], None],
    marked_by: str,
    audit_event: Callable[..., None],
) -> dict:
    hash_ = body.get("hash", "").strip()
    status = body.get("status", "").strip()
    note = body.get("note", "").strip()
    if not hash_:
        raise ValueError("hash required")
    if status not in {TRIAGE_REVIEWED, TRIAGE_ACCEPTED_RISK, TRIAGE_FALSE_POSITIVE}:
        raise ValueError("invalid triage status")
    if status in {TRIAGE_ACCEPTED_RISK, TRIAGE_FALSE_POSITIVE} and not note:
        raise ValueError("note required")

    with session.state_lock:
        target = next((f for f in session.findings if f.get("_hash") == hash_), None)
        if target is None:
            target = next((f for f in session.suppressed_findings if f.get("_hash") == hash_), None)
        if not target:
            raise LookupError("Finding not found in current session")

    upsert_triage(
        suppressions_file,
        target,
        status=status,
        note=note,
        marked_by=marked_by,
    )
    audit_event(
        "finding_triage",
        scan_id=session.scan_id,
        finding_hash=hash_,
        triage_status=status,
        note=note,
    )
    triage_meta = triage_lookup().get(hash_, {})
    updated = apply_triage_metadata(target, triage_meta)
    with session.state_lock:
        session.findings = [f for f in session.findings if f.get("_hash") != hash_]
        session.suppressed_findings = [f for f in session.suppressed_findings if f.get("_hash") != hash_]
        if status == TRIAGE_FALSE_POSITIVE:
            session.suppressed_findings.append(updated)
        else:
            session.findings.append(updated)
            session.findings.sort(key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", "")))
    persist_session_state()
    return {"ok": True, "status": session.to_status()}


def reset_finding(
    *,
    body: dict,
    session,
    suppressions_file: str,
    clear_finding_triage: Callable[[dict], dict],
    persist_session_state: Callable[[], None],
    audit_event: Callable[..., None],
) -> dict:
    hash_ = body.get("hash", "").strip()
    if not hash_:
        raise ValueError("hash required")
    removed = remove_triage(suppressions_file, hash_)
    audit_event("finding_reset", scan_id=session.scan_id, finding_hash=hash_, removed=bool(removed))
    with session.state_lock:
        finding = next((f for f in session.findings if f.get("_hash") == hash_), None)
        if finding is not None:
            updated = clear_finding_triage(finding)
            session.findings = [f for f in session.findings if f.get("_hash") != hash_]
            session.findings.append(updated)
            session.findings.sort(key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", "")))
            persist_session_state()
            return {"ok": True, "removed": removed, "status": session.to_status()}

        finding = next((f for f in session.suppressed_findings if f.get("_hash") == hash_), None)
        session.suppressed_findings = [f for f in session.suppressed_findings if f.get("_hash") != hash_]
        if finding:
            session.findings.append(clear_finding_triage(finding))
            session.findings.sort(key=lambda f: (f.get("severity", 4), f.get("repo", ""), f.get("file", "")))
            persist_session_state()
    return {"ok": True, "removed": removed, "status": session.to_status()}
