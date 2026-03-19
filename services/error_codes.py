from __future__ import annotations

from typing import Any


def make_error(code: str, stage: str, message: str, **details: Any) -> dict[str, Any]:
    payload = {
        "code": str(code or "UNKNOWN_ERROR").strip() or "UNKNOWN_ERROR",
        "stage": str(stage or "unknown").strip() or "unknown",
        "message": str(message or "").strip(),
    }
    clean_details = {
        str(key): str(value)
        for key, value in details.items()
        if value not in (None, "", [], {}, ())
    }
    if clean_details:
        payload["details"] = clean_details
    return payload
