from services.browser_sessions import BrowserSessionStore, parse_cookie_header


def test_parse_cookie_header_extracts_named_values():
    cookies = parse_cookie_header("a=1; ai_scanner_session=demo; theme=light")
    assert cookies["a"] == "1"
    assert cookies["ai_scanner_session"] == "demo"
    assert cookies["theme"] == "light"


def test_browser_session_store_issues_and_validates_sessions():
    store = BrowserSessionStore()
    session_id, csrf_token = store.issue()

    class DummyHandler:
        headers = {"Cookie": f"ai_scanner_session={session_id}"}

    assert store.extract_session_id(DummyHandler()) == session_id
    assert store.has_valid_session(DummyHandler()) is True
    assert store.csrf_token_for_handler(DummyHandler()) == csrf_token
    assert store.csrf_matches(DummyHandler(), {"csrf_token": csrf_token}) is True
    assert store.csrf_matches(DummyHandler(), {"csrf_token": "wrong"}) is False


def test_browser_session_store_sets_cookie_header():
    store = BrowserSessionStore()

    class DummyHandler:
        _response_cookies = []

    handler = DummyHandler()
    store.queue_session_cookie(handler, "session-123")
    assert handler._response_cookies == [
        "ai_scanner_session=session-123; Path=/; HttpOnly; SameSite=Strict"
    ]
