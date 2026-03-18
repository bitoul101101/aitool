"""
pat_store.py — Cross-platform PAT persistence for the AI Scanner.

Strategy
--------
Uses the `keyring` library which delegates to the OS credential store:
  - Windows  : Windows Credential Manager (wincred)
  - macOS    : macOS Keychain
  - Linux    : libsecret (GNOME Keyring), KWallet, or SecretService
  - Fallback : If no backend is available (headless CI, minimal Docker), a
               local encrypted file (~/.ai_scanner_keyring) is used via the
               `keyrings.alt` package.  If even that is unavailable the module
               silently degrades to a session-only in-memory store (no disk I/O).

Install dependencies (all optional — graceful degradation if absent):
    pip install keyring
    pip install keyrings.alt   # for headless/minimal environments

Public API
----------
    save_pat(token: str) -> bool   — persist token; returns True on success
    load_pat() -> str | None       — retrieve token; None if not stored
    delete_pat() -> bool           — remove stored token; True on success
    backend_name() -> str          — human-readable backend description
"""

import os

_SERVICE  = "ai_scanner_cognyte"
_USERNAME = "bitbucket_pat"

# ── In-memory fallback (always available) ────────────────────────
_memory_store: str = ""


def _get_keyring():
    """Return the keyring module, or None if unavailable."""
    try:
        import keyring
        return keyring
    except ImportError:
        return None


def _allow_insecure_fallback() -> bool:
    return os.environ.get("AI_SCANNER_ALLOW_INSECURE_PAT_FALLBACK", "").strip().lower() in {"1", "true", "yes"}


def _backend_type_name() -> str:
    kr = _get_keyring()
    if kr is None:
        return "missing"
    try:
        return type(kr.get_keyring()).__name__
    except Exception:
        return "unknown"


def requires_persistent_backend() -> bool:
    return not _allow_insecure_fallback()


def save_pat(token: str) -> bool:
    """
    Persist `token` in the OS credential store.
    Returns True on success, False on any failure (caller can warn the user).
    """
    global _memory_store
    _memory_store = token   # always keep in-memory copy for this session

    kr = _get_keyring()
    if kr is None:
        if requires_persistent_backend():
            raise RuntimeError("Persistent credential storage is unavailable: keyring is not installed.")
        return False
    try:
        kr.set_password(_SERVICE, _USERNAME, token)
        if requires_persistent_backend() and not is_available():
            raise RuntimeError(
                f"Persistent credential storage is required, but the active backend is '{backend_name()}'."
            )
        return True
    except Exception:
        if requires_persistent_backend():
            raise RuntimeError(
                f"Persistent credential storage is required, but saving to '{backend_name()}' failed."
            )
        return False


def load_pat() -> str:
    """
    Retrieve a previously persisted PAT.
    Returns the token string, or an empty string if nothing is stored.
    """
    # Check in-memory first (survives New Scan within same process)
    if _memory_store:
        return _memory_store

    kr = _get_keyring()
    if kr is None:
        return ""
    try:
        value = kr.get_password(_SERVICE, _USERNAME)
        return value or ""
    except Exception:
        return ""


def delete_pat() -> bool:
    """
    Remove the stored PAT from the credential store.
    Returns True on success or if nothing was stored.
    """
    global _memory_store
    _memory_store = ""

    kr = _get_keyring()
    if kr is None:
        return True   # nothing was persisted anyway
    try:
        kr.delete_password(_SERVICE, _USERNAME)
        return True
    except Exception:
        # delete_password raises if key not found — treat as success
        return True


def backend_name() -> str:
    """Return a short human-readable description of the active backend."""
    kr = _get_keyring()
    if kr is None:
        return "in-memory only (keyring not installed)"
    try:
        be = kr.get_keyring()
        name = type(be).__name__
        # Map technical names to friendlier labels
        _LABELS = {
            "WinVaultKeyring":      "Windows Credential Manager",
            "Keyring":              "macOS Keychain",
            "SecretServiceKeyring": "Linux SecretService (GNOME Keyring)",
            "KWalletKeyring":       "Linux KWallet",
            "PlaintextKeyring":     "plaintext file (~/.local/share/python_keyring)",
            "EncryptedKeyring":     "encrypted file (keyrings.alt)",
            "CryptFileKeyring":     "encrypted file (keyrings.alt)",
            "NullKeyring":          "in-memory only (no OS backend)",
            "MemoryKeyring":        "in-memory only",
            "fail.Keyring":         "in-memory only (no backend available)",
        }
        return _LABELS.get(name, name)
    except Exception:
        return "unknown"


def is_available() -> bool:
    """Return True if a persistent (non-memory) backend is active."""
    kr = _get_keyring()
    if kr is None:
        return False
    try:
        be = kr.get_keyring()
        name = type(be).__name__
        return "Null" not in name and "Memory" not in name and "fail" not in name
    except Exception:
        return False
