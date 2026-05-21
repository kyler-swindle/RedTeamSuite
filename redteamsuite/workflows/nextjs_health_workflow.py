from __future__ import annotations

from redteamsuite.core.context import TargetContext
from redteamsuite.modules.nextjs_eval_tester import NextJsEvalTester
from redteamsuite.profiles.project3_profile import Project3Profile
from redteamsuite.workflows.base_workflow import BaseWorkflow


class NextJsHealthWorkflow(BaseWorkflow):
    def __init__(self, ctx: TargetContext, profile: Project3Profile):
        super().__init__(ctx)
        self.profile = profile

    def run(self) -> None:
        base = self.ctx.config.base_nextjs_url
        tester = NextJsEvalTester(self.ctx)
        tester.safe_eval_checks(base, self.profile.nextjs_dashboard_path)
        tester.command_execution_check(base, self.profile.nextjs_dashboard_path)
        self.ctx.evidence.flush()
