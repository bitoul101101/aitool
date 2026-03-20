from __future__ import annotations


def format_rule_label(raw: str, capability: str = "") -> str:
    cap = str(capability or "").strip()
    if cap:
        return cap
    value = str(raw or "").strip()
    if not value:
        return "Unknown"
    return value.replace("_", " ").replace("-", " ").title()
