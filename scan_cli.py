from __future__ import annotations

import argparse
import sys
from datetime import datetime, UTC
from pathlib import Path

from app_server import _git_head_commit, _ollama_ping, _policy_version, load_owner_map, load_policy
from services.runtime_support import DEFAULT_LLM_CONFIG, load_llm_config
from services.scan_jobs import ScanJobPaths, ScanJobService, ScanSession


APP_VERSION = "19.1"
BASE_DIR = Path(__file__).parent


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local AI security scan and write JSON/SARIF/CSV artifacts.")
    parser.add_argument("repo_path", help="Local repository path to scan")
    parser.add_argument("--output-dir", default=str(BASE_DIR / "output"), help="Artifact output directory")
    parser.add_argument("--llm-url", default="", help="Ollama base URL")
    parser.add_argument("--llm-model", default="", help="Ollama model to use for review")
    parser.add_argument("--scope", choices=("full", "changed_files", "branch_diff", "baseline_rescan"), default="full")
    parser.add_argument("--compare-ref", default="", help="Compare branch/ref for branch_diff scans")
    args = parser.parse_args()

    repo_path = Path(args.repo_path).expanduser().resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        print(f"Local repository path not found: {repo_path}", file=sys.stderr)
        return 2
    if args.scope == "branch_diff" and not args.compare_ref.strip():
        print("--compare-ref is required for --scope branch_diff", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir).expanduser().resolve()
    llm_cfg = load_llm_config(str(output_dir / "cli_llm_config.json")) if (output_dir / "cli_llm_config.json").exists() else dict(DEFAULT_LLM_CONFIG)
    llm_url = args.llm_url.strip() or str(llm_cfg.get("base_url", "http://localhost:11434") or "http://localhost:11434")
    llm_model = args.llm_model.strip() or str(llm_cfg.get("model", "qwen2.5-coder:7b-instruct") or "qwen2.5-coder:7b-instruct")

    paths = ScanJobPaths(
        output_dir=str(output_dir),
        temp_dir=str(output_dir / "tmp_clones"),
        policy_file=str(BASE_DIR / "policy.json"),
        owner_map_file=str(BASE_DIR / "owner_map.json"),
        suppressions_file=str(output_dir / "cli_suppressions.json"),
        history_file=str(output_dir / "scan_history.json"),
        log_dir=str(output_dir / "logs"),
        db_file=str(output_dir / "scan_jobs.db"),
        llm_cfg_file=str(output_dir / "cli_llm_config.json"),
    )
    service = ScanJobService(
        app_version=APP_VERSION,
        paths=paths,
        load_policy=load_policy,
        load_owner_map=load_owner_map,
        policy_version=_policy_version,
        utc_now_iso=_utc_now_iso,
        git_head_commit=_git_head_commit,
        ollama_ping=_ollama_ping,
    )
    session = ScanSession()
    session.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    session.project_key = "LOCAL"
    session.repo_slugs = [repo_path.name or "local-repo"]
    session.scan_source = "local"
    session.local_repo_path = str(repo_path)
    session.total = 1
    session.scan_scope = args.scope
    session.compare_ref = args.compare_ref.strip()
    session.llm_url = llm_url
    session.llm_model = llm_model
    session.operator = "CLI"
    session.state = "running"
    session.started_at_utc = _utc_now_iso()

    service.run_scan(session, client=None, save_history_record=lambda _session, _findings: None)

    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{session.scan_id}.txt"
    log_path.write_text(
        "\n".join(f"[{datetime.fromtimestamp(entry['ts']).strftime('%H:%M:%S')}] {entry['msg']}" for entry in session.log_lines) + "\n",
        encoding="utf-8",
    )

    report = dict((session.report_paths or {}).get("__all__", {}) or {})
    print(f"Scan state   : {session.state}")
    print(f"Scan ID      : {session.scan_id}")
    print(f"Findings     : {len(session.findings)}")
    print(f"CSV report   : {report.get('csv', '')}")
    print(f"JSON report  : {report.get('json', '')}")
    print(f"SARIF report : {report.get('sarif', '')}")
    print(f"Log file     : {log_path}")
    return 0 if session.state in {"done", "stopped", "skipped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
