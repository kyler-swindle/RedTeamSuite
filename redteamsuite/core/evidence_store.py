from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from redteamsuite.core.models import to_jsonable, utc_now_iso


class EvidenceStore:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.http_dir = output_dir / "evidence" / "http"
        self.upload_dir = output_dir / "evidence" / "uploads"
        self.http_dir.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0
        self.findings: List[Any] = []
        self.credentials: List[Any] = []
        self.sessions: List[Any] = []
        self.web_paths: List[Any] = []
        self.uploads: List[Any] = []

    def _next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"

    @staticmethod
    def _safe_name(text: str, max_len: int = 120) -> str:
        text = re.sub(r"^https?://", "", text)
        text = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")
        return text[:max_len] or "response"

    def save_http_response(self, method: str, url: str, status_code: int, headers: Dict[str, str], body: str) -> str:
        evidence_id = self._next_id("http")
        safe_url = self._safe_name(url)
        path = self.http_dir / f"{evidence_id}_{method}_{status_code}_{safe_url}.txt"
        content = [
            f"Evidence-ID: {evidence_id}",
            f"Timestamp: {utc_now_iso()}",
            f"Request: {method} {url}",
            f"Status: {status_code}",
            "Headers:",
            json.dumps(headers, indent=2, ensure_ascii=False),
            "",
            "Body:",
            body,
        ]
        path.write_text("\n".join(content), encoding="utf-8", errors="replace")
        return evidence_id

    def save_json(self, filename: str, data: Any) -> None:
        path = self.output_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(to_jsonable(data), indent=2, ensure_ascii=False), encoding="utf-8")

    def flush(self) -> None:
        self.save_json("credentials.json", self.credentials)
        self.save_json("sessions.json", self.sessions)
        self.save_json("web_paths.json", self.web_paths)
        self.save_json("uploads.json", self.uploads)
        self.save_json("findings.json", self.findings)
