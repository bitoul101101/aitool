from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from services.threat_modeling import build_threat_model


class JSONReporter:
    def __init__(self, output_dir: str, scan_id: str):
        self.output_dir = Path(output_dir)
        self.scan_id = scan_id

    def write_json(
        self,
        findings: list[dict[str, Any]],
        *,
        meta: dict[str, Any] | None = None,
        replay_instructions: str = "",
    ) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / f"ai_scan_{self.scan_id}.json"
        threat_model = build_threat_model(findings, meta=meta, replay_instructions=replay_instructions)
        payload = {
            "scan_id": self.scan_id,
            "generated_at": str((meta or {}).get("completed_at_utc", "") or (meta or {}).get("started_at_utc", "") or ""),
            "meta": dict(meta or {}),
            "finding_count": len(findings),
            "findings": list(findings),
            "threat_model": threat_model,
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)
