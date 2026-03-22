"""
main_web.py - PhantomLM (Web UI)
Launches the local web application server at http://127.0.0.1:5757 and keeps the process alive.
The web UI is server-rendered from app_server.py and the services it imports.
This file is only the desktop-friendly launcher and shutdown wrapper.
"""
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from app_server import start, wait_for_exit
except ImportError as _e:
    print(f"""
ERROR: Could not import 'start' from app_server.py.

  {_e}

This usually means your app_server.py is outdated.
Please replace it with the latest version from your download package.
""")
    sys.exit(1)


def _browser_candidates() -> list[Path]:
    candidates = [
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    ]
    return [path for path in candidates if path.exists()]


def _launch_dedicated_browser_window(url: str) -> bool:
    for exe in _browser_candidates():
        try:
            subprocess.Popen(
                [
                    str(exe),
                    f"--app={url}",
                    "--new-window",
                    "--disable-session-crashed-bubble",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except OSError:
            continue
    try:
        webbrowser.open(url)
        return False
    except Exception:
        return False

if __name__ == "__main__":
    srv = start(open_browser=False)
    launched_dedicated = _launch_dedicated_browser_window("http://127.0.0.1:5757/")
    print("  Press Ctrl+C to quit.")
    print("  Use the Exit Tool button or Ctrl+C to stop the server.")
    if launched_dedicated:
        print("  Opened PhantomLM in a dedicated app window.")
    else:
        print("  Opened PhantomLM in the default browser.")
    try:
        wait_for_exit()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        srv.shutdown()
        srv.server_close()
        print("\nPhantomLM stopped.")
