from __future__ import annotations

from redteamsuite.core.context import TargetContext
from redteamsuite.modules.auth_tester import AuthTester
from redteamsuite.modules.staff_portal import StaffPortalModule
from redteamsuite.modules.upload_tester import UploadTester
from redteamsuite.modules.web_enum import WebEnumerator
from redteamsuite.profiles.project3_profile import Project3Profile
from redteamsuite.workflows.base_workflow import BaseWorkflow


class WebPortalWorkflow(BaseWorkflow):
    def __init__(self, ctx: TargetContext, profile: Project3Profile):
        super().__init__(ctx)
        self.profile = profile

    def run(self) -> None:
        base = self.ctx.config.base_http_url
        web = WebEnumerator(self.ctx)
        portal = StaffPortalModule(self.ctx)
        auth = AuthTester(self.ctx)
        upload = UploadTester(self.ctx)

        web.check_paths(base, self.profile.common_paths)
        creds = portal.fetch_and_parse_users(base, self.profile.data_users_path)
        portal.fetch_upload_log(base, self.profile.data_uploads_path)

        admin_cred = next((c for c in creds if (c.role or "").lower() == "admin"), creds[0] if creds else None)
        if admin_cred:
            session = auth.login_form(
                base,
                self.profile.login_path,
                self.profile.login_username_field,
                self.profile.login_password_field,
                admin_cred,
            )
            if session.valid:
                self.ctx.http.get(base + self.profile.dashboard_path, allow_redirects=False)
                self.ctx.http.get(base + self.profile.admin_path, allow_redirects=False)
                self.ctx.http.get(base + self.profile.upload_path, allow_redirects=False)
                upload.safe_text_upload_test(base, self.profile.upload_path, self.profile.uploads_path)
                upload.php_double_extension_marker_test(base, self.profile.upload_path, self.profile.uploads_path)
        self.ctx.evidence.flush()
