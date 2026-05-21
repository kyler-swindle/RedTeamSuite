from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from redteamsuite.core.models import utc_now_iso


class RunLogger:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.log_path = output_dir / "run_log.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, event_type: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        row = {
            "timestamp": utc_now_iso(),
            "event_type": event_type,
            "message": message,
            "data": data or {},
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
