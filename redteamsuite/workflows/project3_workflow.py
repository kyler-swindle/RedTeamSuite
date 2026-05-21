from __future__ import annotations

from redteamsuite.core.context import TargetContext
from redteamsuite.profiles.project3_profile import Project3Profile
from redteamsuite.workflows.nextjs_health_workflow import NextJsHealthWorkflow
from redteamsuite.workflows.web_portal_workflow import WebPortalWorkflow


class Project3Workflow:
    def __init__(self, ctx: TargetContext, profile: Project3Profile):
        self.ctx = ctx
        self.profile = profile

    def run(self) -> None:
        self.ctx.logger.event("workflow.start", "Starting Project 3 profile workflow")
        WebPortalWorkflow(self.ctx, self.profile).run()
        NextJsHealthWorkflow(self.ctx, self.profile).run()
        self.ctx.logger.event("workflow.end", "Project 3 profile workflow complete")
        self.ctx.evidence.flush()
