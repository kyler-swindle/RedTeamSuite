from __future__ import annotations

from typing import Optional

from redteamsuite.core.context import TargetContext
from redteamsuite.core.models import CredentialRecord, Finding, SessionRecord
from redteamsuite.core.utils import normalize_url


class AuthTester:
    def __init__(self, ctx: TargetContext):
        self.ctx = ctx

    def login_form(self, base_url: str, login_path: str, username_field: str, password_field: str, credential: CredentialRecord) -> SessionRecord:
        url = normalize_url(base_url, login_path)
        self.ctx.logger.event("auth.login", f"Testing login for {credential.username} at {url}")
        result = self.ctx.http.post(url, data={
            username_field: credential.username,
            password_field: credential.password,
        }, allow_redirects=False)

        valid = result.status_code in (301, 302, 303) and "Location" in result.headers
        if not valid and "Invalid username or password" not in result.text and result.status_code == 200:
            valid = "Dashboard" in result.text or "Logout" in result.text

        credential.valid_portal_login = valid
        cookie_path = self.ctx.evidence.output_dir / f"session_{credential.username}.json"
        self.ctx.evidence.save_json(cookie_path.name, {
            "username": credential.username,
            "cookies": self.ctx.http.cookie_dict(),
            "valid": valid,
            "login_url": url,
        })
        session = SessionRecord(
            username=credential.username,
            role=credential.role,
            cookie_file=str(cookie_path),
            login_url=url,
            valid=valid,
            evidence_id=result.evidence_id,
        )
        self.ctx.evidence.sessions.append(session)

        if valid:
            self.ctx.evidence.findings.append(Finding(
                id="AUTH-VALID-CREDS-001",
                title="Valid portal credentials identified",
                severity="High",
                target=url,
                description=f"Credential pair for {credential.username} successfully authenticated to the portal.",
                impact="An attacker with access to these credentials can access authenticated portal functionality.",
                remediation="Remove exposed credentials, rotate affected passwords, and store credentials using a secure password hashing scheme.",
                evidence_ids=[result.evidence_id],
                metadata={"username": credential.username, "role": credential.role},
            ))
        self.ctx.evidence.flush()
        return session
