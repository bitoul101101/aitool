import importlib
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_app_server_storage(tmp_path):
    try:
        srv = importlib.import_module("app_server")
    except Exception:
        yield
        return

    orig_output = srv.OUTPUT_DIR
    orig_history = srv.HISTORY_FILE
    orig_log_dir = srv.LOG_DIR
    orig_db = srv.DB_FILE
    orig_audit = srv.AUDIT_FILE

    isolated_output = tmp_path / "output"
    isolated_output.mkdir(parents=True, exist_ok=True)
    srv._set_output_paths(isolated_output)
    srv._sync_scan_service_paths()
    try:
        yield
    finally:
        srv._set_output_paths(Path(orig_output))
        srv.HISTORY_FILE = orig_history
        srv.LOG_DIR = orig_log_dir
        srv.DB_FILE = orig_db
        srv.AUDIT_FILE = orig_audit
        srv._sync_scan_service_paths()
