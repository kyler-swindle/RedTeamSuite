from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from redteamsuite.core.models import to_jsonable, utc_now_iso


class DedupeFindingList(list):
    """Append-compatible finding collection that merges repeat findings.

    Most modules currently do this:
        ctx.evidence.findings.append(Finding(...))

    Keeping this as a list subclass lets those modules remain unchanged while
    preserving append-only evidence references and preventing duplicate finding
    rows from taking over findings.json.
    """

    def __init__(self, values: Optional[Iterable[Any]] = None):
        super().__init__()
        for value in values or []:
            self.append(value)

    def append(self, item: Any) -> None:  # type: ignore[override]
        normalized = self._normalize(item)
        key = self._key(normalized)
        if key is None:
            super().append(item)
            return

        for idx, existing in enumerate(self):
            existing_norm = self._normalize(existing)
            if self._key(existing_norm) == key:
                self[idx] = self._merge(existing_norm, normalized)
                return

        # Ensure all finding rows have predictable dedupe metadata, even on first sighting.
        if isinstance(normalized, dict) and self._key(normalized) is not None:
            normalized = self._with_initial_metadata(normalized)
        super().append(normalized)

    def extend(self, values: Iterable[Any]) -> None:  # type: ignore[override]
        for value in values:
            self.append(value)

    @staticmethod
    def _normalize(item: Any) -> Dict[str, Any]:
        data = to_jsonable(item)
        return data if isinstance(data, dict) else {"value": data}

    @staticmethod
    def _key(item: Dict[str, Any]) -> Optional[tuple[str, str]]:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        finding_id = str(item.get("finding_type") or item.get("id") or "").strip()
        target = str(
            item.get("target")
            or item.get("affected_resource")
            or metadata.get("affected_resource")
            or ""
        ).strip()
        if not finding_id:
            return None
        return finding_id, target

    @staticmethod
    def _unique_preserve_order(values: Iterable[Any]) -> List[Any]:
        seen = set()
        out: List[Any] = []
        for value in values:
            marker = json.dumps(value, sort_keys=True, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
            if marker in seen:
                continue
            seen.add(marker)
            out.append(value)
        return out

    def _with_initial_metadata(self, item: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now_iso()
        metadata = dict(item.get("metadata") or {})
        first_seen = metadata.get("first_seen") or item.get("created_at") or now
        metadata.setdefault("dedupe_key", "|".join(self._key(item) or ("", "")))
        metadata.setdefault("affected_resource", item.get("target") or item.get("affected_resource"))
        metadata.setdefault("first_seen", first_seen)
        metadata.setdefault("last_seen", first_seen)
        metadata.setdefault("occurrence_count", 1)
        out = dict(item)
        out["metadata"] = metadata
        return out

    def _merge(self, existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now_iso()
        merged = dict(existing)

        existing_meta = dict(existing.get("metadata") or {})
        incoming_meta = dict(incoming.get("metadata") or {})
        first_seen = existing_meta.get("first_seen") or existing.get("created_at") or incoming.get("created_at") or now
        prev_count = int(existing_meta.get("occurrence_count") or existing.get("occurrence_count") or 1)

        merged["evidence_ids"] = self._unique_preserve_order(
            list(existing.get("evidence_ids") or []) + list(incoming.get("evidence_ids") or [])
        )
        merged["metadata"] = {
            **existing_meta,
            **incoming_meta,
            "dedupe_key": "|".join(self._key(incoming) or ("", "")),
            "first_seen": first_seen,
            "last_seen": now,
            "occurrence_count": prev_count + 1,
        }
        merged["finding_type"] = incoming.get("finding_type") or existing.get("finding_type") or incoming.get("id") or existing.get("id")

        # Preserve original created_at as first observation time, but allow fields
        # like severity/title/remediation to stay stable from the first finding.
        if "created_at" not in merged:
            merged["created_at"] = first_seen
        return merged


class EvidenceStore:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.http_dir = output_dir / "evidence" / "http"
        self.upload_dir = output_dir / "evidence" / "uploads"
        self.network_dir = output_dir / "evidence" / "network"
        self.http_dir.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.network_dir.mkdir(parents=True, exist_ok=True)

        self._counter = self._load_next_evidence_counter()
        self.findings: DedupeFindingList = DedupeFindingList(self._load_json_list("findings.json"))
        self.credentials: List[Any] = self._load_json_list("credentials.json")
        self.sessions: List[Any] = self._load_json_list("sessions.json")
        self.web_paths: List[Any] = self._load_json_list("web_paths.json")
        self.uploads: List[Any] = self._load_json_list("uploads.json")

    def load_json(self, filename: str, default: Any = None) -> Any:
        path = self.output_dir / filename
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

    def _load_json_list(self, filename: str) -> List[Any]:
        data = self.load_json(filename, [])
        return data if isinstance(data, list) else []

    def _load_next_evidence_counter(self) -> int:
        max_seen = 0
        evidence_root = self.output_dir / "evidence"
        if evidence_root.exists():
            for path in evidence_root.rglob("*.txt"):
                match = re.match(r"[A-Za-z_-]+-(\d+)_", path.name)
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

    def append_jsonl(self, filename: str, row: Dict[str, Any]) -> None:
        path = self.output_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(to_jsonable(row), ensure_ascii=False) + "\n")

    def upsert_run_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        existing = self.load_json("run_metadata.json", {})
        existing = existing if isinstance(existing, dict) else {}
        now = utc_now_iso()
        merged = {
            **existing,
            **data,
            "created_at": existing.get("created_at") or now,
            "last_updated_at": now,
        }
        self.save_json("run_metadata.json", merged)
        return merged

    def flush(self) -> None:
        self.save_json("credentials.json", self.credentials)
        self.save_json("sessions.json", self.sessions)
        self.save_json("web_paths.json", self.web_paths)
        self.save_json("uploads.json", self.uploads)
        # Rehydrate through DedupeFindingList to merge any duplicates loaded from older runs.
        self.findings = DedupeFindingList(self.findings)
        self.save_json("findings.json", self.findings)
