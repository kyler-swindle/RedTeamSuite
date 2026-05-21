from __future__ import annotations

from redteamsuite.core.context import TargetContext
from redteamsuite.profiles.project3_profile import get_profile
from redteamsuite.workflows.project3_workflow import Project3Workflow


def run_profile(ctx: TargetContext, profile_name: str) -> None:
    profile = get_profile(profile_name)
    if profile_name == "project3":
        Project3Workflow(ctx, profile).run()
        return
    raise ValueError(f"No workflow registered for profile: {profile_name}")
