from __future__ import annotations

from typing import Iterable, List

from redteamsuite.core.context import TargetContext
from redteamsuite.core.models import Finding, WebPathRecord
from redteamsuite.core.utils import normalize_url


class WebEnumerator:
    def __init__(self, ctx: TargetContext):
        self.ctx = ctx

    def check_paths(self, base_url: str, paths: Iterable[str]) -> List[WebPathRecord]:
        records: List[WebPathRecord] = []
        for path in paths:
            url = normalize_url(base_url, path)
            self.ctx.logger.event("http.get", f"Fetching {url}")
            try:
                result = self.ctx.http.get(url, allow_redirects=False)
            except Exception as exc:
                self.ctx.logger.event("http.error", f"Failed to fetch {url}", {"error": str(exc)})
                continue
            record = WebPathRecord(
                url=url,
                status_code=result.status_code,
                content_type=result.content_type,
                length=len(result.text),
                title=result.title,
                evidence_id=result.evidence_id,
            )
            if "Index of" in result.text and result.status_code == 200:
                record.notes.append("Possible directory listing")
            self.ctx.evidence.web_paths.append(record)
            records.append(record)
        self._emit_directory_listing_findings(records)
        self.ctx.evidence.flush()
        return records

    def _emit_directory_listing_findings(self, records: List[WebPathRecord]) -> None:
        for rec in records:
            if "Possible directory listing" in rec.notes:
                self.ctx.evidence.findings.append(Finding(
                    id="WEB-DIRLIST-001",
                    title="Directory listing exposed",
                    severity="Medium",
                    target=rec.url,
                    description=f"The URL {rec.url} appears to expose an auto-generated directory listing.",
                    impact="Directory listings can reveal sensitive files, filenames, logs, credentials, and application structure.",
                    remediation="Disable directory indexing and move sensitive files outside the web root.",
                    evidence_ids=[rec.evidence_id] if rec.evidence_id else [],
                ))
