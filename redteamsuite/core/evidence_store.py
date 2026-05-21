from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from redteamsuite.core.models import to_jsonable, utc_now_iso


class EvidenceStore:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.http_dir = output_dir / "evidence" / "http"
        self.upload_dir = output_dir / "evidence" / "uploads"
        self.network_dir = output_dir / "evidence" / "network"
        self.http_dir.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.network_dir.mkdir(parents=True, exist_ok=True)

        self._counter = self._load_next_http_counter()
        self.findings: List[Any] = self._load_json_list("findings.json")
        self.credentials: List[Any] = self._load_json_list("credentials.json")
        self.sessions: List[Any] = self._load_json_list("sessions.json")
        self.web_paths: List[Any] = self._load_json_list("web_paths.json")
        self.uploads: List[Any] = self._load_json_list("uploads.json")

    def _load_json_list(self, filename: str) -> List[Any]:
        path = self.output_dir / filename
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        return data if isinstance(data, list) else []

    def _load_next_http_counter(self) -> int:
        max_seen = 0
        if self.http_dir.exists():
            for path in self.http_dir.glob("http-*.txt"):
                match = re.match(r"http-(\d+)_", path.name)
                if match:
                    max_seen = max(max_seen, int(match.group(1)))
        return max_seen

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

    def save_text_evidence(self, subdir: str, filename: str, content: str) -> str:
        evidence_id = self._next_id(subdir)
        safe_file = self._safe_name(filename)
        path = self.output_dir / "evidence" / subdir / f"{evidence_id}_{safe_file}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", errors="replace")
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
