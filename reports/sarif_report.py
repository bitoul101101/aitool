from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _level_for_severity(severity: object) -> str:
    try:
        value = int(severity or 4)
    except Exception:
        value = 4
    return {
        1: "error",
        2: "error",
        3: "warning",
        4: "note",
    }.get(value, "warning")


def _rule_id(finding: dict[str, Any]) -> str:
    return str(
        finding.get("provider_or_lib")
        or finding.get("category")
        or finding.get("policy_status")
        or "ai_finding"
    )


class SARIFReporter:
    def __init__(self, output_dir: str, scan_id: str):
        self.output_dir = Path(output_dir)
        self.scan_id = scan_id

    def write_sarif(self, findings: list[dict[str, Any]], *, meta: dict[str, Any] | None = None) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / f"ai_scan_{self.scan_id}.sarif"
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for finding in findings:
            rid = _rule_id(finding)
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": rid,
                    "shortDescription": {"text": str(finding.get("description", "") or rid)},
                    "properties": {
                        "severity_label": str(finding.get("severity_label", "") or ""),
                        "policy_status": str(finding.get("policy_status", "") or ""),
                    },
                }
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(finding.get("file", "") or "")},
                }
            }
            line = finding.get("line")
            try:
                line_no = int(line)
            except Exception:
                line_no = 0
            if line_no > 0:
                location["physicalLocation"]["region"] = {"startLine": line_no}
            results.append({
                "ruleId": rid,
                "level": _level_for_severity(finding.get("severity")),
                "message": {"text": str(finding.get("description", "") or rid)},
                "locations": [location],
                "properties": {
                    "repo": str(finding.get("repo", "") or ""),
                    "project_key": str(finding.get("project_key", "") or ""),
                    "finding_hash": str(finding.get("_hash", "") or finding.get("finding_id", "") or ""),
                    "delta_status": str(finding.get("delta_status", "") or ""),
                    "severity_label": str(finding.get("severity_label", "") or ""),
                },
            })

        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PhantomLM",
                            "version": str((meta or {}).get("tool_version", "") or ""),
                            "informationUri": "https://example.invalid/local-ai-scanner",
                            "rules": list(rules.values()),
                        }
                    },
                    "automationDetails": {
                        "id": str((meta or {}).get("scan_id", self.scan_id)),
                    },
                    "results": results,
                }
            ],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)
