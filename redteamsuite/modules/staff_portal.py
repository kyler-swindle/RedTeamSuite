from __future__ import annotations

from typing import List

from redteamsuite.core.context import TargetContext
from redteamsuite.core.models import CredentialRecord, Finding
from redteamsuite.core.utils import normalize_url
from redteamsuite.modules.credential_parser import CredentialParser


class StaffPortalModule:
    def __init__(self, ctx: TargetContext):
        self.ctx = ctx

    def fetch_and_parse_users(self, base_url: str, users_path: str) -> List[CredentialRecord]:
        url = normalize_url(base_url, users_path)
        self.ctx.logger.event("portal.users", f"Fetching portal credential file {url}")
        result = self.ctx.http.get(url, allow_redirects=False)
        creds = CredentialParser.parse_colon_credentials(result.text, source=url)
        self.ctx.evidence.credentials.extend(creds)
        if creds:
            self.ctx.evidence.findings.append(Finding(
                id="WEB-DATA-CREDS-001",
                title="Exposed data file reveals portal credentials",
                severity="High",
                target=url,
                description="A publicly reachable data file contained username, password, and role values for the staff portal.",
                impact="Unauthenticated users can obtain valid portal credentials and access authenticated functionality.",
                remediation="Remove credential files from the web root, disable directory listing, rotate exposed credentials, and use secure password storage.",
                evidence_ids=[result.evidence_id],
                metadata={"credential_count": len(creds)},
            ))
        self.ctx.evidence.flush()
        return creds

    def fetch_upload_log(self, base_url: str, uploads_log_path: str) -> List[dict]:
        url = normalize_url(base_url, uploads_log_path)
        self.ctx.logger.event("portal.upload_log", f"Fetching upload log {url}")
        result = self.ctx.http.get(url, allow_redirects=False)
        rows: List[dict] = []
        for line in result.text.splitlines():
            parts = line.strip().split("|")
            if len(parts) == 4:
                rows.append({"timestamp": parts[0], "username": parts[1], "filename": parts[2], "size": parts[3]})
        self.ctx.evidence.save_json("parsed_upload_log.json", rows)
        if rows:
            suspicious = [r for r in rows if ".php" in r["filename"].lower() or "shell" in r["filename"].lower()]
            if suspicious:
                self.ctx.evidence.findings.append(Finding(
                    id="WEB-UPLOAD-LOG-001",
                    title="Upload log contains suspicious filenames",
                    severity="Medium",
                    target=url,
                    description="The exposed upload log contains filenames suggestive of shell or PHP payload upload attempts.",
                    impact="This may indicate that the upload functionality accepts risky filenames or has previously been used for code execution attempts.",
                    remediation="Restrict upload types using content validation, store uploads outside executable paths, and review upload logs for compromise indicators.",
                    evidence_ids=[result.evidence_id],
                    metadata={"suspicious_entries": suspicious},
                ))
        self.ctx.evidence.flush()
        return rows
