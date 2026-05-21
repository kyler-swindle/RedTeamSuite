from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from redteamsuite.core.context import TargetContext
from redteamsuite.core.models import Finding, UploadRecord
from redteamsuite.core.utils import normalize_url


class UploadTester:
    def __init__(self, ctx: TargetContext):
        self.ctx = ctx

    def upload_file(self, base_url: str, upload_path: str, local_path: Path, *, field_name: str = "file", mime_type: str = "text/plain") -> UploadRecord:
        url = normalize_url(base_url, upload_path)
        self.ctx.logger.event("upload.file", f"Uploading {local_path} to {url}")
        with local_path.open("rb") as f:
            result = self.ctx.http.post(url, files={field_name: (local_path.name, f, mime_type)}, allow_redirects=False)
        stored_name = self._extract_saved_as(result.text)
        record = UploadRecord(
            local_path=str(local_path),
            upload_url=url,
            stored_name=stored_name,
            upload_status_code=result.status_code,
            evidence_ids=[result.evidence_id],
        )
        self.ctx.evidence.uploads.append(record)
        self.ctx.evidence.flush()
        return record

    def verify_public_access(self, base_url: str, uploads_path: str, record: UploadRecord) -> UploadRecord:
        if not record.stored_name:
            record.notes.append("No stored filename was identified in upload response.")
            return record
        public_url = normalize_url(base_url, uploads_path.rstrip("/") + "/" + record.stored_name)
        result = self.ctx.http.get(public_url, allow_redirects=False)
        record.public_url = public_url
        record.accessible_status_code = result.status_code
        record.evidence_ids.append(result.evidence_id)
        self.ctx.evidence.flush()
        return record

    def safe_text_upload_test(self, base_url: str, upload_path: str, uploads_path: str) -> UploadRecord:
        local = self.ctx.evidence.upload_dir / "upload_test.txt"
        local.write_text("UPLOAD_TEST_REDTEAMSUITE_001\n", encoding="utf-8")
        record = self.upload_file(base_url, upload_path, local, mime_type="text/plain")
        self.verify_public_access(base_url, uploads_path, record)
        if record.accessible_status_code == 200:
            self.ctx.evidence.findings.append(Finding(
                id="WEB-UPLOAD-ACCESS-001",
                title="Uploaded files are directly web-accessible",
                severity="Medium",
                target=record.public_url or record.upload_url,
                description="The upload portal stores user-uploaded files in a web-accessible directory.",
                impact="If upload validation is weak, attackers may be able to host or execute malicious content from the web root.",
                remediation="Store uploads outside the web root, serve through controlled download handlers, and validate file content and extension.",
                evidence_ids=record.evidence_ids,
            ))
        self.ctx.evidence.flush()
        return record

    def php_double_extension_marker_test(self, base_url: str, upload_path: str, uploads_path: str) -> Optional[UploadRecord]:
        if not self.ctx.config.allow_upload_marker:
            self.ctx.logger.event("upload.skip", "Skipping PHP marker upload because allow_upload_marker is false")
            return None
        marker = "PHP_EXEC_TEST_REDTEAMSUITE"
        local = self.ctx.evidence.upload_dir / "rts_php_marker.php.png"
        local.write_text(f'<?php echo "{marker}"; ?>', encoding="utf-8")
        record = self.upload_file(base_url, upload_path, local, mime_type="image/png")
        self.verify_public_access(base_url, uploads_path, record)
        if record.public_url:
            result = self.ctx.http.get(record.public_url, allow_redirects=False)
            record.evidence_ids.append(result.evidence_id)
            record.executed_marker = marker in result.text and "<?php" not in result.text
            if record.executed_marker:
                self.ctx.evidence.findings.append(Finding(
                    id="WEB-UPLOAD-PHP-EXEC-001",
                    title="Double-extension upload leads to PHP execution",
                    severity="Critical",
                    target=record.public_url,
                    description="A file named with a .php.png double extension was accepted by the upload portal and executed as PHP when requested.",
                    impact="An authenticated user can execute arbitrary PHP code as the web server user.",
                    remediation="Reject dangerous multi-extension filenames, validate content server-side, disable PHP execution in upload directories, and store uploads outside the web root.",
                    evidence_ids=record.evidence_ids,
                    metadata={"marker": marker},
                ))
        self.ctx.evidence.flush()
        return record

    @staticmethod
    def _extract_saved_as(text: str) -> Optional[str]:
        match = re.search(r"Saved as:\s*<span[^>]*>([^<]+)</span>", text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
        match = re.search(r"Saved as:\s*([^\s<]+)", text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
