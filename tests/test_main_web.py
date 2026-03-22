from pathlib import Path
from unittest.mock import patch

import main_web


def test_launch_dedicated_browser_window_uses_app_mode():
    fake_browser = Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")

    with patch.object(main_web, "_browser_candidates", return_value=[fake_browser]), \
         patch.object(main_web.subprocess, "Popen") as popen_mock:
        launched = main_web._launch_dedicated_browser_window("http://127.0.0.1:5757/")

    assert launched is True
    args = popen_mock.call_args[0][0]
    assert args[0] == str(fake_browser)
    assert "--new-window" in args
    assert "--start-maximized" in args
    assert any(arg.startswith("--app=http://127.0.0.1:5757/") for arg in args)


def test_launch_dedicated_browser_window_falls_back_to_webbrowser():
    with patch.object(main_web, "_browser_candidates", return_value=[]), \
         patch.object(main_web.webbrowser, "open", return_value=True) as open_mock:
        launched = main_web._launch_dedicated_browser_window("http://127.0.0.1:5757/")

    assert launched is False
    open_mock.assert_called_once_with("http://127.0.0.1:5757/")
