"""
main_web.py — AI Security & Compliance Scanner (Web UI)
Launches the web UI server at http://127.0.0.1:5757 and keeps the process alive.
All scan logic, report generation, and the SPA are in app_server.py.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from app_server import start
except ImportError as _e:
    print(f"""
ERROR: Could not import 'start' from app_server.py.

  {_e}

This usually means your app_server.py is outdated.
Please replace it with the latest version from your download package.
""")
    sys.exit(1)

if __name__ == "__main__":
    srv = start(open_browser=True)
    print("  Press Ctrl+C to quit.")
    print("  Closing the browser tab will also stop the server.")
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        srv.shutdown()
        print("\nScanner stopped.")